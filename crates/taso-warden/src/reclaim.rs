//! The reclaimer: orphan reclamation (P4 spec §2.3, §2.4; review fix 2a).
//!
//! A content object (`<prefix>/obj/<kind>/<key>`: an artifact, a manifest,
//! a classification map, a vconf, a purge's inventory or local state, a
//! Template layer) that no record holds, older than `store.orphan_grace`,
//! is an orphan.  Reclaiming it is one deletion, as every deletion is: a
//! claim at the coordinator, the delete, the claim resolved.
//!
//! - **Claim**: `ReclaimClaimed { key, n }`, `n` the key's reclaims already
//!   completed, through this Warden's own Chronicle (D55).  The coordinator
//!   refuses it while the object is held, claimed or quarantined, or if
//!   `n` is not the key's next number; once it is accepted, no new hold on
//!   the object is accepted until the claim is resolved.
//! - **Delete**, only while that claim is still open: its `ReclaimClaimed`
//!   accepted, its `ReclaimComplete` not, and `n` still the key's next
//!   number.  A stale retry of an earlier reclaim finds it done and
//!   deletes nothing.
//! - **Resolve**: `ReclaimComplete { key, n, outcome }`, accepted only once
//!   the store says the object is gone; the key is then quarantined
//!   (`store.deleted_quarantine`).
//!
//! The grace period is the object's age in the store (its last write: a
//! put again makes it new), so an object being put and about to be held
//! is never claimed from under its writer within it.  It only limits how
//! soon reclaim is tried: the coordinator's log orders a claim and a hold,
//! and the second is refused (§2.4).
//!
//! A pass first finishes this Warden's own open claims, from its local log
//! (a claim accepted and a crash before its delete or its resolution:
//! otherwise the key could never be held again), then looks at every
//! content object.  Packs are never reclaimed: a pack is deleted only by
//! its purge's claim.  Last, under that claim, it deletes every file pack
//! of a Chronicle whose purge ended within the last week that no other
//! Chronicle holds: one put after the purge ended, by a Warden cut off
//! from the coordinator (generation 3, G5-2).  Tombstones are retained
//! history, never orphans.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use taso_core::contract::{logical_id, ContractRecord, LogicalKey, ObjectKind, ReclaimOutcome};
use taso_core::coordlog::ReclaimBlocker;
use taso_core::envelope::{ChronicleId, HashVal};
use taso_core::model::WardenId;

use crate::coordinator::Coord;
use crate::coordstore::{kind_dir, object_key_path, CONTENT_KINDS};
use crate::ship::SharedStore;
use crate::template::{TemplateError, WardenLog};

/// `store.orphan_grace`'s default: 24 h (spec §11.1).
pub const ORPHAN_GRACE: Duration = Duration::from_secs(24 * 3600);

/// The kinds a reclaim looks at: the content kinds but tombstones.
fn kinds() -> impl Iterator<Item = ObjectKind> {
    CONTENT_KINDS
        .into_iter()
        .filter(|k| *k != ObjectKind::Tombstone)
}

/// Why a delete under a claim stopped.
enum Halt {
    /// The claim is no longer open as this one: resolved meanwhile, or
    /// another number.  Nothing more is deleted.
    Stale,
    /// A store or coordinator error.
    Failed(String),
}
use Halt::{Failed, Stale};

/// One Warden's reclaimer.
pub struct Reclaimer {
    /// The coordinator.
    pub coord: Arc<dyn Coord>,
    /// The Wardens' store.
    pub store: SharedStore,
    /// Its key prefix.
    pub prefix: String,
    /// This Warden.
    pub warden: WardenId,
    /// The Warden's state directory (its own Chronicle is under it).
    pub state_dir: PathBuf,
    /// `store.orphan_grace`.
    pub grace: Duration,
}

/// How long after a purge's end the reclaimer looks for its file packs
/// (step 3, generation 3, G5-2): a week.  A Warden cut off from the
/// coordinator that long has stopped its Vessels long before.
pub const STRAY_PACK_WINDOW: Duration = Duration::from_secs(7 * 86_400);

/// What one pass did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Pass {
    /// Content objects looked at.
    pub looked: usize,
    /// Of those, younger than the grace period: not claimed.
    pub young: usize,
    /// Reclaimed (deleted and resolved), with whether it was still there.
    pub reclaimed: Vec<(HashVal, ReclaimOutcome)>,
    /// Claims refused: held, claimed, quarantined, or not the next number.
    pub refused: usize,
    /// File packs of a purged Chronicle deleted (step 3, generation 3,
    /// G5-2): (Chronicle, pack name).
    pub swept: Vec<(ChronicleId, String)>,
    /// What went wrong, by object; each is tried again at the next pass.
    pub failed: Vec<String>,
}

impl Reclaimer {
    /// One pass at `now`: this Warden's open claims finished, then every
    /// content object older than the grace period claimed, deleted and
    /// resolved.  `Err` only if the coordinator cannot be asked, the
    /// Warden's Chronicle cannot be opened or the store cannot be listed:
    /// nothing is guessed.
    pub fn pass(&self, now: SystemTime) -> Result<Pass, String> {
        let mut pass = Pass::default();
        // The Warden's Chronicle is opened only when there is something to
        // claim or finish: opening it takes a new epoch for it.
        let mut log: Option<WardenLog> = None;

        // 1. This Warden's own claims left open (a crash, a failed delete),
        //    if it ever claimed anything: its local log is here, or the
        //    coordinator knows its Chronicle (this node's state lost: the
        //    open rebuilds the log from its packs, which hold every
        //    accepted claim, shipped before it was accepted).  A claim
        //    whose object is already deleted is no longer listed, so step
        //    2 cannot find it (audit 2026-11-06, finding 5).
        let known = self
            .coord
            .query_chronicle(crate::template::warden_chronicle(self.warden))
            .map_err(|e| format!("the coordinator: {e}"))?
            .is_some();
        if self.warden_dir().exists() || known {
            let l = self.open_log(&mut log)?;
            let mut mine: Vec<(HashVal, u64)> = Vec::new();
            for r in l.records().map_err(|e| e.to_string())? {
                if let ContractRecord::ReclaimClaimed { object_key, n } = r {
                    mine.push((object_key, n));
                }
            }
            for (key, n) in mine {
                match self.open_claim(key) {
                    // The kind is not known here: each is tried in turn.
                    Ok(Some(open)) if open == n => self.finish(l, key, n, None, &mut pass),
                    Ok(_) => {}
                    Err(e) => pass.failed.push(format!("{key}: {e}")),
                }
            }
        }

        // 2. Every content object.
        for kind in kinds() {
            let dir = format!(
                "{}/obj/{}",
                self.prefix,
                kind_dir(kind).expect("a content kind")
            );
            let listed = self
                .store
                .list_times(&dir)
                .map_err(|e| format!("listing {dir}: {e}"))?;
            for (path, written) in listed {
                let Some(key) = key_of(&dir, &path) else {
                    continue; // not something put() of a content object made
                };
                pass.looked += 1;
                // An age in the future (clocks apart) is young.
                if now
                    .duration_since(written)
                    .map_or(true, |age| age < self.grace)
                {
                    pass.young += 1;
                    continue;
                }
                if pass.reclaimed.iter().any(|(k, _)| *k == key) {
                    continue; // finished in step 1
                }
                // Ask before claiming.  A claim is a record of this
                // Warden's Chronicle: announced, shipped in a pack and
                // put to the coordinator, to be refused if the object is
                // still needed, as nearly every old object is.  The
                // reclaimer used to claim every one of them at every
                // pass (audit 2026-11-09, the reclaimer claims every old
                // object; D&D R1 (b)).  The question changes nothing at
                // the coordinator, and the claim's acceptance still
                // decides: a hold accepted after this answer refuses it.
                match self.coord.reclaim_blocker(key) {
                    Ok(None) => {}
                    // Held by a record, or just deleted: not an orphan.
                    Ok(Some(ReclaimBlocker::Held | ReclaimBlocker::Quarantined)) => {
                        pass.refused += 1;
                        continue;
                    }
                    // Claimed.  A reclaim claim left open by a Warden
                    // that is gone is finished here, under that claim,
                    // as before; a purge's claim is the purge's.
                    Ok(Some(ReclaimBlocker::Claimed)) => match self.open_claim(key) {
                        Ok(Some(_)) => {}
                        Ok(None) => {
                            pass.refused += 1;
                            continue;
                        }
                        Err(e) => {
                            pass.failed.push(format!("{key}: {e}"));
                            continue;
                        }
                    },
                    Err(e) => {
                        pass.failed.push(format!("{key}: the coordinator: {e}"));
                        continue;
                    }
                }
                let l = self.open_log(&mut log)?;
                self.reclaim(l, key, kind, &mut pass);
            }
        }

        // 3. File packs that landed after a purge ended (generation 3,
        //    G5-2; finding 1.6): a Warden that reached the store but not
        //    the coordinator never learnt it was fenced, and each of its
        //    publishes puts a pack again.  Every file pack of a purged
        //    Chronicle that no other Chronicle holds is the purge's to
        //    delete, so no claim is made: the coordinator's purge
        //    projection names them, as it did for the purge's own end.
        //    Only purges that ended within the last week are looked at.
        let purged = self
            .coord
            .purged_within(STRAY_PACK_WINDOW.as_secs())
            .map_err(|e| format!("the coordinator: {e}"))?;
        for id in purged {
            if let Err(e) = self.sweep(id, &mut pass) {
                pass.failed.push(format!("{id:?}: {e}"));
            }
        }
        Ok(pass)
    }

    /// Step 3 for one purged Chronicle.
    fn sweep(&self, id: ChronicleId, pass: &mut Pass) -> Result<(), String> {
        let left = self.coord.purge_projection(id).map_err(|e| e.to_string())?;
        if left.is_empty() {
            return Ok(());
        }
        let packs =
            crate::pack::Packs::new(self.store.clone(), crate::ship::NoSend, &self.prefix, id)
                .map_err(|e| e.to_string())?;
        for it in left {
            if packs
                .delete_purged_file_pack(&it.pack.name)
                .map_err(|e| e.to_string())?
            {
                eprintln!(
                    "taso-warden: reclaim: deleted {} of purged {id:?}, put after its purge ended",
                    it.pack.name
                );
                pass.swept.push((id, it.pack.name));
            }
        }
        Ok(())
    }

    /// This Warden's Chronicle's local directory (as [`WardenLog::open`]
    /// keeps it).
    fn warden_dir(&self) -> PathBuf {
        let id = crate::template::warden_chronicle(self.warden);
        let hex: String = id.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
        self.state_dir.join("warden").join(hex)
    }

    /// The Warden's Chronicle, opened once per pass.
    fn open_log<'l>(&self, log: &'l mut Option<WardenLog>) -> Result<&'l mut WardenLog, String> {
        if log.is_none() {
            let mut notes = Vec::new();
            *log = Some(
                WardenLog::open(
                    &self.coord,
                    self.warden,
                    &self.store,
                    &self.prefix,
                    &self.state_dir,
                    &mut notes,
                )
                .map_err(|e| format!("this Warden's Chronicle: {e}"))?,
            );
        }
        Ok(log.as_mut().expect("opened"))
    }

    /// Claim `key` as its next reclaim, or take up the claim already open
    /// for it, then delete and resolve.
    fn reclaim(&self, log: &mut WardenLog, key: HashVal, kind: ObjectKind, pass: &mut Pass) {
        let n = match self.done(key) {
            Ok(n) => n,
            Err(e) => return pass.failed.push(format!("{key}: {e}")),
        };
        match log.submit(ContractRecord::ReclaimClaimed { object_key: key, n }) {
            // Accepted (ours, or a retry of ours, or another Warden's
            // identical claim): open, so it may be deleted under it.
            Ok(ContractRecord::ReclaimClaimed { object_key, n: m })
                if object_key == key && m == n =>
            {
                self.finish(log, key, n, Some(kind), pass)
            }
            Ok(other) => pass
                .failed
                .push(format!("{key}: the claim's logical id holds {other:?}")),
            Err(TemplateError::Refused(_)) => pass.refused += 1,
            Err(e) => pass.failed.push(format!("{key}: claiming it: {e}")),
        }
    }

    /// Delete `key` (where `kind` keeps it; every kind if not known)
    /// under its open claim `n`, then resolve the claim.  Round 3, R3-01
    /// (D&D a): the claim is checked open right before each delete call,
    /// so a stale reclaimer has at most one call in flight past the
    /// resolution, landing within the store's request timeout -- far
    /// inside the quarantine, during which nothing may hold the key.
    fn finish(
        &self,
        log: &mut WardenLog,
        key: HashVal,
        n: u64,
        kind: Option<ObjectKind>,
        pass: &mut Pass,
    ) {
        let prepared = match log.prepared(logical_id(&LogicalKey::ReclaimDone(key, n))) {
            Ok(p) => p,
            Err(e) => return pass.failed.push(format!("{key}: {e}")),
        };
        // Gone in the store, as the resolution's row checks; a resolution
        // prepared before a crash keeps the outcome it named.
        let outcome = match (self.delete(key, n, kind), prepared) {
            (Err(Stale), _) => return, // resolved meanwhile, or not ours
            (Err(Failed(e)), _) => return pass.failed.push(format!("{key}: deleting it: {e}")),
            (Ok(_), Some(ContractRecord::ReclaimComplete { outcome, .. })) => outcome,
            (Ok(true), _) => ReclaimOutcome::Deleted,
            (Ok(false), _) => ReclaimOutcome::Absent,
        };
        match log.submit(ContractRecord::ReclaimComplete {
            object_key: key,
            n,
            outcome,
        }) {
            Ok(ContractRecord::ReclaimComplete {
                object_key,
                n: m,
                outcome: o,
            }) if object_key == key && m == n => pass.reclaimed.push((key, o)),
            Ok(other) => pass.failed.push(format!(
                "{key}: the resolution's logical id holds {other:?}"
            )),
            Err(e) => pass.failed.push(format!("{key}: resolving its claim: {e}")),
        }
    }

    /// Delete `key` where `kind` keeps it, or wherever a content kind
    /// does: `true` if anything was there.  Each call only while claim `n`
    /// is open (R3-01).
    fn delete(&self, key: HashVal, n: u64, kind: Option<ObjectKind>) -> Result<bool, Halt> {
        let mut any = false;
        let all: Vec<ObjectKind> = match kind {
            Some(k) => vec![k],
            None => kinds().collect(),
        };
        for kind in all {
            match self.open_claim(key) {
                Ok(Some(open)) if open == n => {}
                Ok(_) => return Err(Stale),
                Err(e) => return Err(Failed(e)),
            }
            let path = object_key_path(&self.prefix, kind, key).expect("a content kind");
            any |= self
                .store
                .delete(&path)
                .map_err(|e| Failed(e.to_string()))?;
        }
        Ok(any)
    }

    /// How many reclaims of `key` completed: its next number.
    fn done(&self, key: HashVal) -> Result<u64, String> {
        let mut n = 0;
        while self
            .coord
            .query_logical(logical_id(&LogicalKey::ReclaimDone(key, n)))
            .map_err(|e| format!("the coordinator: {e}"))?
            .is_some()
        {
            n += 1;
        }
        Ok(n)
    }

    /// The number of `key`'s open claim, if one is open: claimed as its
    /// next reclaim, not yet resolved.
    fn open_claim(&self, key: HashVal) -> Result<Option<u64>, String> {
        let n = self.done(key)?;
        Ok(self
            .coord
            .query_logical(logical_id(&LogicalKey::Reclaim(key, n)))
            .map_err(|e| format!("the coordinator: {e}"))?
            .map(|_| n))
    }
}

/// The key of a content object at `path` under `dir`, if `path` is one:
/// `<dir>/<64 hex digits>`.
fn key_of(dir: &str, path: &str) -> Option<HashVal> {
    let hex = path.strip_prefix(dir)?.strip_prefix('/')?;
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    let mut b = [0u8; 32];
    for (i, out) in b.iter_mut().enumerate() {
        *out = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(HashVal::from_bytes(b))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    use crate::coordinator::{reading_store, Coordinator};
    use crate::ship::{LocalStore, ObjectStore};

    const PREFIX: &str = "taso";
    const QUARANTINE: u64 = 3600;
    const T0: u64 = 1_800_000_000;

    struct Env {
        _dir: tempfile::TempDir,
        root: PathBuf,
        store: SharedStore,
        coord: Arc<dyn Coord>,
        /// The coordinator's clock, seconds.
        clock: Arc<AtomicU64>,
    }

    fn env() -> Env {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let store: SharedStore = Arc::new(LocalStore::new(root.join("store")));
        let clock = Arc::new(AtomicU64::new(T0));
        let mut config = reading_store(store.clone(), PREFIX, QUARANTINE);
        let c = clock.clone();
        config.clock = Arc::new(move || c.load(Ordering::SeqCst));
        let coord: Arc<dyn Coord> =
            Arc::new(Coordinator::open_with(root.join("coord.redb"), config).unwrap());
        Env {
            _dir: dir,
            root,
            store,
            coord,
            clock,
        }
    }

    impl Env {
        fn reclaimer(&self) -> Reclaimer {
            Reclaimer {
                coord: self.coord.clone(),
                store: self.store.clone(),
                prefix: PREFIX.into(),
                warden: WardenId::new(1),
                state_dir: self.root.join("state"),
                grace: ORPHAN_GRACE,
            }
        }
        /// Put `bytes` as a manifest, last written `age` ago: its key.
        fn put(&self, bytes: &[u8], age: Duration) -> HashVal {
            let key = HashVal::from_bytes(blake3::derive_key(ObjectKind::Manifest.prefix(), bytes));
            let path = object_key_path(PREFIX, ObjectKind::Manifest, key).unwrap();
            self.store.put(&path, &mut &bytes[..]).unwrap();
            let f = std::fs::File::options()
                .write(true)
                .open(self.root.join("store").join(&path))
                .unwrap();
            f.set_modified(SystemTime::now() - age).unwrap();
            key
        }
        fn present(&self, key: HashVal) -> bool {
            let path = object_key_path(PREFIX, ObjectKind::Manifest, key).unwrap();
            self.store.exists(&path).unwrap()
        }
        fn done(&self, key: HashVal, n: u64) -> bool {
            self.coord
                .query_logical(logical_id(&LogicalKey::ReclaimDone(key, n)))
                .unwrap()
                .is_some()
        }
    }

    const DAY: Duration = Duration::from_secs(24 * 3600);
    const HOUR: Duration = Duration::from_secs(3600);

    /// Audit 2026-11-09, the reclaimer claimed every old object at every
    /// pass: a record of its Chronicle, shipped in a pack and put to the
    /// coordinator, to learn that the object is still needed.  Twenty
    /// objects are reclaimed and then put again, so each is quarantined.
    /// The next pass asks the coordinator first, claims none of them and
    /// puts nothing in the store; once the quarantine has ended it
    /// reclaims them as each key's second reclaim.
    #[test]
    fn a_pass_claims_nothing_the_coordinator_says_it_would_refuse() {
        const N: usize = 20;
        let e = env();
        let r = e.reclaimer();
        let put_all = || -> Vec<HashVal> {
            (0..N)
                .map(|i| e.put(format!("obj {i}").as_bytes(), 2 * DAY))
                .collect()
        };
        let keys = put_all();
        assert_eq!(r.coord.reclaim_blocker(keys[0]).unwrap(), None);
        let p = r.pass(SystemTime::now()).unwrap();
        assert_eq!(p.reclaimed.len(), N, "{:?}", p.failed);
        put_all();
        assert_eq!(
            r.coord.reclaim_blocker(keys[0]).unwrap(),
            Some(ReclaimBlocker::Quarantined)
        );
        let stored = || e.store.list(PREFIX).unwrap().len();
        let before = stored();
        let p = r.pass(SystemTime::now()).unwrap();
        assert_eq!((p.refused, p.reclaimed.len()), (N, 0), "{:?}", p.failed);
        assert!(p.failed.is_empty(), "{:?}", p.failed);
        assert_eq!(
            stored() - before,
            0,
            "packs the Warden shipped to claim {N} objects the coordinator would refuse"
        );
        // The quarantine over, they are orphans again.
        e.clock.fetch_add(QUARANTINE + 1, Ordering::SeqCst);
        assert_eq!(r.coord.reclaim_blocker(keys[0]).unwrap(), None);
        let p = r.pass(SystemTime::now()).unwrap();
        assert_eq!(p.reclaimed.len(), N, "{:?}", p.failed);
        assert!(e.done(keys[0], 1));
    }

    /// An orphan older than the grace period is claimed, deleted and
    /// resolved; a younger one, and what is not a content object, are
    /// left alone.
    #[test]
    fn an_old_orphan_is_reclaimed_and_a_young_one_is_not() {
        let e = env();
        let old = e.put(b"old", 2 * DAY);
        let young = e.put(b"young", HOUR);
        let pack = format!("{PREFIX}/0123/pack/00000000000000000001");
        e.store.put(&pack, &mut &b"a pack"[..]).unwrap();
        let p = e.reclaimer().pass(SystemTime::now()).unwrap();
        assert_eq!(p.reclaimed, vec![(old, ReclaimOutcome::Deleted)], "{p:?}");
        assert_eq!((p.looked, p.young, p.refused), (2, 1, 0));
        assert!(p.failed.is_empty(), "{:?}", p.failed);
        assert!(!e.present(old) && e.present(young));
        assert!(e.done(old, 0));
        assert!(e.store.exists(&pack).unwrap(), "a pack is never reclaimed");
        // Again: nothing more.
        let p = e.reclaimer().pass(SystemTime::now()).unwrap();
        assert!(p.reclaimed.is_empty() && p.failed.is_empty(), "{p:?}");
    }

    /// A pass with nothing to claim writes nothing at the coordinator: the
    /// Warden's Chronicle is not even registered (a pass at every start of
    /// a short-lived Warden, a test's, changes nothing).
    #[test]
    fn a_pass_with_nothing_old_writes_nothing() {
        let e = env();
        e.put(b"young", HOUR);
        let p = e.reclaimer().pass(SystemTime::now()).unwrap();
        assert_eq!((p.looked, p.young), (1, 1));
        let id = crate::template::warden_chronicle(WardenId::new(1));
        assert!(e.coord.query_chronicle(id).unwrap().is_none());
    }

    /// Review fixes 2a and R2a at the reclaimer: a key reclaimed, put
    /// again within the quarantine, is refused and kept; once the
    /// quarantine has passed it is reclaimed again as reclaim 1.  A stale
    /// finish of reclaim 0 deletes nothing.
    #[test]
    fn a_key_put_again_is_reclaimed_again_as_its_next_reclaim() {
        let e = env();
        let k = e.put(b"k", 2 * DAY);
        let r = e.reclaimer();
        assert_eq!(r.pass(SystemTime::now()).unwrap().reclaimed.len(), 1);
        assert!(e.done(k, 0) && !e.present(k));

        // Put again (old already, as a copy with an old time would be).
        e.put(b"k", 2 * DAY);
        let p = r.pass(SystemTime::now()).unwrap();
        assert_eq!((p.refused, p.reclaimed.len()), (1, 0), "quarantined: {p:?}");
        assert!(e.present(k));

        // A stale finish of reclaim 0: its claim is resolved, so nothing.
        let mut notes = Vec::new();
        let mut log = WardenLog::open(
            &e.coord,
            r.warden,
            &r.store,
            PREFIX,
            &r.state_dir,
            &mut notes,
        )
        .unwrap();
        let mut stale = Pass::default();
        r.finish(&mut log, k, 0, None, &mut stale);
        drop(log);
        assert_eq!(stale, Pass::default());
        assert!(e.present(k), "a stale reclaim deletes nothing");

        e.clock.fetch_add(QUARANTINE, Ordering::SeqCst);
        let p = r.pass(SystemTime::now()).unwrap();
        assert_eq!(p.reclaimed, vec![(k, ReclaimOutcome::Deleted)], "{p:?}");
        assert!(e.done(k, 1) && !e.present(k));
    }

    /// A claim accepted and then a crash, before its delete: the next pass
    /// finishes it from the Warden's local log, whatever the object's age
    /// (otherwise the key could never be held again).
    #[test]
    fn an_open_claim_left_by_a_crash_is_finished_at_the_next_pass() {
        let e = env();
        let k = e.put(b"k", HOUR);
        let r = e.reclaimer();
        let mut notes = Vec::new();
        let mut log = WardenLog::open(
            &e.coord,
            r.warden,
            &r.store,
            PREFIX,
            &r.state_dir,
            &mut notes,
        )
        .unwrap();
        log.submit(ContractRecord::ReclaimClaimed {
            object_key: k,
            n: 0,
        })
        .unwrap();
        drop(log);
        assert!(e.present(k));
        let p = r.pass(SystemTime::now()).unwrap();
        assert_eq!(p.reclaimed, vec![(k, ReclaimOutcome::Deleted)], "{p:?}");
        assert!(e.done(k, 0) && !e.present(k));
    }

    /// A store that counts its deletes and can run something during the
    /// first (another Warden, while this one's call is in flight).
    struct Gated {
        inner: SharedStore,
        deletes: std::sync::Mutex<Vec<String>>,
        during_first: std::sync::Mutex<Option<Box<dyn FnOnce() + Send>>>,
    }
    impl ObjectStore for Gated {
        fn put(&self, k: &str, d: &mut dyn std::io::Read) -> std::io::Result<u64> {
            self.inner.put(k, d)
        }
        fn get(&self, k: &str) -> std::io::Result<Option<crate::ship::ByteStream>> {
            self.inner.get(k)
        }
        fn exists(&self, k: &str) -> std::io::Result<bool> {
            self.inner.exists(k)
        }
        fn list(&self, p: &str) -> std::io::Result<Vec<String>> {
            self.inner.list(p)
        }
        fn list_times(&self, p: &str) -> std::io::Result<Vec<(String, SystemTime)>> {
            self.inner.list_times(p)
        }
        fn delete(&self, k: &str) -> std::io::Result<bool> {
            self.deletes.lock().unwrap().push(k.to_string());
            let r = self.inner.delete(k);
            if let Some(f) = self.during_first.lock().unwrap().take() {
                f();
            }
            r
        }
    }

    /// Round 3, R3-01 (Kimi; D&D a): a listed object is deleted by one call
    /// (its kind's), and a reclaimer whose claim another Warden resolves
    /// while its call is in flight makes no further call: the claim is
    /// checked before each.  So a stale delete is at most one call, within
    /// the store's timeout, far inside the quarantine (at least 600 s).
    #[test]
    fn a_stale_reclaimer_makes_at_most_one_call_after_the_claim_resolves() {
        let e = env();
        let gated = |e: &Env| {
            Arc::new(Gated {
                inner: e.store.clone(),
                deletes: Default::default(),
                during_first: Default::default(),
            })
        };
        // A listed orphan: one delete, of its own kind's path.
        let k = e.put(b"listed", 2 * DAY);
        let g = gated(&e);
        let r = Reclaimer {
            store: g.clone(),
            ..e.reclaimer()
        };
        assert_eq!(r.pass(SystemTime::now()).unwrap().reclaimed.len(), 1);
        assert_eq!(
            *g.deletes.lock().unwrap(),
            vec![object_key_path(PREFIX, ObjectKind::Manifest, k).unwrap()]
        );

        // A claim left open by a crash (its kind unknown: every kind is
        // tried), resolved by another Warden during this one's first call.
        let k = e.put(b"resumed", HOUR);
        let mut notes = Vec::new();
        let mut log = WardenLog::open(
            &e.coord,
            r.warden,
            &r.store,
            PREFIX,
            &r.state_dir,
            &mut notes,
        )
        .unwrap();
        log.submit(ContractRecord::ReclaimClaimed {
            object_key: k,
            n: 0,
        })
        .unwrap();
        drop(log);
        let g = gated(&e);
        let other = Reclaimer {
            warden: WardenId::new(2),
            state_dir: e.root.join("state-2"),
            ..e.reclaimer()
        };
        *g.during_first.lock().unwrap() = Some(Box::new(move || {
            let mut notes = Vec::new();
            let mut log = WardenLog::open(
                &other.coord,
                other.warden,
                &other.store,
                PREFIX,
                &other.state_dir,
                &mut notes,
            )
            .unwrap();
            let mut p = Pass::default();
            other.finish(&mut log, k, 0, Some(ObjectKind::Manifest), &mut p);
            assert_eq!(p.reclaimed.len(), 1, "the other Warden resolved it: {p:?}");
        }));
        let r = Reclaimer {
            store: g.clone(),
            ..e.reclaimer()
        };
        let p = r.pass(SystemTime::now()).unwrap();
        assert!(p.failed.is_empty(), "{:?}", p.failed);
        assert_eq!(
            g.deletes.lock().unwrap().len(),
            1,
            "one call in flight, then the claim was seen resolved: no more"
        );
        assert!(e.done(k, 0));
    }

    /// The shortest quarantine is 20 store-request timeouts (R3-01).
    #[test]
    fn the_quarantine_outlasts_a_delete_in_flight_by_far() {
        assert!(crate::coordinator::deleted_quarantine(599).is_err());
        assert_eq!(crate::coordinator::deleted_quarantine(600), Ok(600));
    }

    /// A store that cannot say an object's age stops the pass: nothing is
    /// claimed on a guess.
    #[test]
    fn a_listing_without_ages_claims_nothing() {
        let e = env();
        e.put(b"old", 2 * DAY);
        struct NoAges(SharedStore);
        impl ObjectStore for NoAges {
            fn put(&self, k: &str, d: &mut dyn std::io::Read) -> std::io::Result<u64> {
                self.0.put(k, d)
            }
            fn get(&self, k: &str) -> std::io::Result<Option<crate::ship::ByteStream>> {
                self.0.get(k)
            }
            fn exists(&self, k: &str) -> std::io::Result<bool> {
                self.0.exists(k)
            }
            fn list(&self, p: &str) -> std::io::Result<Vec<String>> {
                self.0.list(p)
            }
            fn list_times(&self, _: &str) -> std::io::Result<Vec<(String, SystemTime)>> {
                Err(std::io::Error::other("no LastModified"))
            }
            fn delete(&self, k: &str) -> std::io::Result<bool> {
                self.0.delete(k)
            }
        }
        let r = Reclaimer {
            store: Arc::new(NoAges(e.store.clone())),
            ..e.reclaimer()
        };
        let err = r.pass(SystemTime::now()).unwrap_err();
        assert!(err.contains("no LastModified"), "{err}");
        assert!(
            e.store
                .list(&format!("{PREFIX}/obj/manifest"))
                .unwrap()
                .len()
                == 1
        );
    }

    /// The reclaimer on a real Garage bucket (an ignored test, as
    /// s3.rs's): ages from Garage's own `LastModified`, the deletes and the
    /// coordinator's not-found checks through S3.  A young object is left,
    /// the same object later reclaimed; put again, refused within the
    /// quarantine, then reclaimed as reclaim 1.  Everything it put is
    /// deleted at the end.
    ///
    /// ```text
    /// TASO_S3_ENDPOINT=http://127.0.0.1:3900 TASO_S3_BUCKET=... TASO_S3_KEY_ID=... \
    ///   TASO_S3_SECRET=... cargo test -p taso-warden --lib reclaim_on_garage -- --ignored
    /// ```
    #[test]
    #[ignore = "needs a Garage bucket: set TASO_S3_*"]
    fn reclaim_on_garage() {
        use crate::s3::{S3Config, S3Store};
        let var = |k: &str| std::env::var(k).unwrap_or_else(|_| panic!("set {k}"));
        let s3 = S3Store::new(
            S3Config {
                endpoint: var("TASO_S3_ENDPOINT"),
                region: std::env::var("TASO_S3_REGION").unwrap_or_else(|_| "garage".into()),
                bucket: var("TASO_S3_BUCKET"),
                access_key_id: var("TASO_S3_KEY_ID"),
                secret_key: var("TASO_S3_SECRET"),
                ca_file: std::env::var_os("TASO_S3_CA").map(Into::into),
                plaintext: var("TASO_S3_ENDPOINT").starts_with("http://"),
            },
            Duration::from_secs(30),
        )
        .unwrap();
        let store: SharedStore = Arc::new(s3);
        let millis = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let prefix = format!("reclaim-{}-{millis}", std::process::id());
        // Everything under the prefix is deleted at the end, also on a
        // failure.
        struct Sweep(SharedStore, String);
        impl Drop for Sweep {
            fn drop(&mut self) {
                for k in self.0.list(&self.1).unwrap_or_default() {
                    let _ = self.0.delete(&k);
                }
            }
        }
        let _sweep = Sweep(store.clone(), prefix.clone());

        let dir = tempfile::tempdir().unwrap();
        let clock = Arc::new(AtomicU64::new(T0));
        let mut config = reading_store(store.clone(), &prefix, QUARANTINE);
        let c = clock.clone();
        config.clock = Arc::new(move || c.load(Ordering::SeqCst));
        let coord: Arc<dyn Coord> =
            Arc::new(Coordinator::open_with(dir.path().join("coord.redb"), config).unwrap());
        let r = Reclaimer {
            coord: coord.clone(),
            store: store.clone(),
            prefix: prefix.clone(),
            warden: WardenId::new(1),
            state_dir: dir.path().join("state"),
            grace: HOUR,
        };
        let bytes = b"reclaimed on garage";
        let k = HashVal::from_bytes(blake3::derive_key(ObjectKind::Manifest.prefix(), bytes));
        let path = object_key_path(&prefix, ObjectKind::Manifest, k).unwrap();
        let done = |n| {
            coord
                .query_logical(logical_id(&LogicalKey::ReclaimDone(k, n)))
                .unwrap()
                .is_some()
        };
        store.put(&path, &mut &bytes[..]).unwrap();

        // Just put: young by Garage's clock (a minute of skew allowed).
        let p = r.pass(SystemTime::now() + Duration::from_secs(60)).unwrap();
        assert_eq!((p.looked, p.young, p.reclaimed.len()), (1, 1, 0), "{p:?}");
        // Two hours on: old, reclaimed.
        let later = || SystemTime::now() + 2 * HOUR;
        let p = r.pass(later()).unwrap();
        assert_eq!(p.reclaimed, vec![(k, ReclaimOutcome::Deleted)], "{p:?}");
        assert!(p.failed.is_empty(), "{:?}", p.failed);
        assert!(!store.exists(&path).unwrap() && done(0));

        // Put again: within the quarantine, refused and kept.
        store.put(&path, &mut &bytes[..]).unwrap();
        let p = r.pass(later()).unwrap();
        assert_eq!((p.refused, p.reclaimed.len()), (1, 0), "{p:?}");
        assert!(store.exists(&path).unwrap());
        // After it: reclaim 1.
        clock.fetch_add(QUARANTINE, Ordering::SeqCst);
        let p = r.pass(later()).unwrap();
        assert_eq!(p.reclaimed, vec![(k, ReclaimOutcome::Deleted)], "{p:?}");
        assert!(!store.exists(&path).unwrap() && done(1));
    }

    #[test]
    fn content_paths_name_their_key() {
        let k = HashVal::from_bytes([0xAB; 32]);
        let dir = "p/obj/manifest";
        assert_eq!(key_of(dir, &format!("{dir}/{}", "ab".repeat(32))), Some(k));
        for bad in [
            format!("{dir}/{}", "AB".repeat(32)),
            format!("{dir}/{}", "ab".repeat(31)),
            format!("{dir}/x/{}", "ab".repeat(32)),
            format!("q/obj/manifest/{}", "ab".repeat(32)),
        ] {
            assert_eq!(key_of(dir, &bad), None, "{bad}");
        }
    }

    /// Audit 2026-11-06, finding 5: a claim accepted and its object
    /// deleted, then this node's state lost (the Warden's local log with
    /// it).  The object is no longer listed, so only the coordinator still
    /// knows the claim is open; the pass rebuilds the Warden's log from
    /// its packs (every accepted record was shipped before it was
    /// accepted) and resolves it.
    #[test]
    fn an_open_claim_is_resolved_after_the_warden_state_is_lost() {
        let e = env();
        let k = e.put(b"lost node", HOUR);
        let r = e.reclaimer();
        let mut notes = Vec::new();
        let mut log = WardenLog::open(
            &e.coord,
            r.warden,
            &r.store,
            PREFIX,
            &r.state_dir,
            &mut notes,
        )
        .unwrap();
        log.submit(ContractRecord::ReclaimClaimed {
            object_key: k,
            n: 0,
        })
        .unwrap();
        drop(log);
        assert!(
            matches!(r.delete(k, 0, None), Ok(true)),
            "a crash after the delete"
        );
        std::fs::remove_dir_all(&r.state_dir).unwrap();
        let p = r.pass(SystemTime::now()).unwrap();
        assert!(p.failed.is_empty(), "{p:?}");
        // Deleted before the loss, so gone when the pass looks.
        assert_eq!(p.reclaimed, vec![(k, ReclaimOutcome::Absent)], "{p:?}");
        assert!(e.done(k, 0), "the claim is resolved");
    }
}
