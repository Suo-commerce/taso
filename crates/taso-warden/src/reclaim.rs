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
//! its purge's claim.  Tombstones are retained history, never orphans.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use taso_core::contract::{logical_id, ContractRecord, LogicalKey, ObjectKind, ReclaimOutcome};
use taso_core::envelope::HashVal;
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
    /// What went wrong, by object; each is tried again at the next pass.
    pub failed: Vec<String>,
}

impl Reclaimer {
    /// One pass at `now`: this Warden's open claims finished, then every
    /// content object older than the grace period claimed, deleted and
    /// resolved.  `Err` only if the Warden's Chronicle cannot be opened or
    /// the store cannot be listed: nothing is guessed.
    pub fn pass(&self, now: SystemTime) -> Result<Pass, String> {
        let mut pass = Pass::default();
        // The Warden's Chronicle is opened only when there is something to
        // claim or finish: opening it takes a new epoch for it.
        let mut log: Option<WardenLog> = None;

        // 1. This Warden's own claims left open (a crash, a failed delete),
        //    if it ever claimed anything here.
        if self.warden_dir().exists() {
            let l = self.open_log(&mut log)?;
            let mut mine: Vec<(HashVal, u64)> = Vec::new();
            for r in l.records().map_err(|e| e.to_string())? {
                if let ContractRecord::ReclaimClaimed { object_key, n } = r {
                    mine.push((object_key, n));
                }
            }
            for (key, n) in mine {
                match self.open_claim(key) {
                    Ok(Some(open)) if open == n => self.finish(l, key, n, &mut pass),
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
                let l = self.open_log(&mut log)?;
                self.reclaim(l, key, &mut pass);
            }
        }
        Ok(pass)
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
    fn reclaim(&self, log: &mut WardenLog, key: HashVal, pass: &mut Pass) {
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
                self.finish(log, key, n, pass)
            }
            Ok(other) => pass
                .failed
                .push(format!("{key}: the claim's logical id holds {other:?}")),
            Err(TemplateError::Refused(_)) => pass.refused += 1,
            Err(e) => pass.failed.push(format!("{key}: claiming it: {e}")),
        }
    }

    /// Delete `key` under its open claim `n`, then resolve the claim.  The
    /// claim is checked open right before the delete: a stale `n` deletes
    /// nothing.
    fn finish(&self, log: &mut WardenLog, key: HashVal, n: u64, pass: &mut Pass) {
        match self.open_claim(key) {
            Ok(Some(open)) if open == n => {}
            Ok(_) => return, // resolved meanwhile, or not ours to finish
            Err(e) => return pass.failed.push(format!("{key}: {e}")),
        }
        let prepared = match log.prepared(logical_id(&LogicalKey::ReclaimDone(key, n))) {
            Ok(p) => p,
            Err(e) => return pass.failed.push(format!("{key}: {e}")),
        };
        // Gone in the store, as the resolution's row checks; a resolution
        // prepared before a crash keeps the outcome it named.
        let outcome = match (self.delete(key), prepared) {
            (Err(e), _) => return pass.failed.push(format!("{key}: deleting it: {e}")),
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

    /// Delete `key` wherever a content kind keeps it: `true` if anything
    /// was there.
    fn delete(&self, key: HashVal) -> std::io::Result<bool> {
        let mut any = false;
        for kind in kinds() {
            let path = object_key_path(&self.prefix, kind, key).expect("a content kind");
            any |= self.store.delete(&path)?;
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
        r.finish(&mut log, k, 0, &mut stale);
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
}
