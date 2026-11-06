//! What the coordinator reads from the store (P4 spec rev. 12 §0.4, §1.2
//! step 5, §2.1; D35, D36; file 1d-2).
//!
//! [`CoordStore`] is the coordinator log's [`StoreView`] over an object
//! store: Chronicle packs where P2 puts them, and content-addressed
//! objects under `<prefix>/obj/<kind>/<key>` ([`object_key_path`], D35).
//! The coordinator never takes a Warden's word for any of it:
//!
//! - **`carries`** reads the pack's header and log, verified against the
//!   log digest, on every accept, and looks for the record by digest.
//! - **`lookup`** verifies an object the first time it is asked about it
//!   — a content object read whole and its key recomputed under its
//!   kind's domain; a pack's header and log — and after that, until this
//!   process ends, only checks it is still there (D36).
//! - **`lookup_inventory`** reads the inventory object and checks its key.
//! - **`fs_packs`** reads every fs-bearing pack of the Chronicle whole,
//!   trailer included ([`Packs::inventory_item`]); purges are rare.
//! - **`seal_closure`** lists the packs restoring a Seal needs, with its
//!   parent's closure for a fork or a succession (§2.1), from pack names
//!   and the Lineage record.
//! - **`lookup_replacement`** is [`Packs::verify_replacement`].
//!
//! Every read has three answers (review fix 5a): found and verified, the
//! store's own not-found, or unreadable.  Unreadable is any other store
//! error (a timeout, a permission, an outage) or bytes that do not verify
//! (a store-integrity fault, logged as one).  It is never taken as an
//! absence: the coordinator refuses for now and the Warden retries.
//!
//! Normative reference: `Taso_spec_p4_contracts` rev. 12, BLAKE3
//! `37c75f30580bf3edd79674be38702d7893af413813bbfe6d4585231e9477144a`.

use std::collections::BTreeMap;
use std::fmt;
use std::io::Read;
use std::sync::{Arc, Mutex};

use taso_core::contract::{object_key, Inventory, InventoryItem, ObjectKind};
use taso_core::coordlog::{Lookup, ObjectId, StoreView, Submitted};
use taso_core::envelope::{ChronicleId, HashVal, Lsn};
use taso_core::record::{Origin, Payload};

use crate::pack::{name_bounds, PackError, Packs};
use crate::ship::{NoSend, ObjectStore};

/// The content-addressed kinds, in the order the coordinator looks for a
/// key whose kind it does not know (D35).
pub const CONTENT_KINDS: [ObjectKind; 8] = [
    ObjectKind::Artifact,
    ObjectKind::Manifest,
    ObjectKind::Classmap,
    ObjectKind::Vconf,
    ObjectKind::Inventory,
    ObjectKind::Local,
    ObjectKind::Tombstone,
    ObjectKind::Layer,
];

/// A content kind's directory name (D35); `None` for packs, which live
/// under their Chronicle.
pub fn kind_dir(kind: ObjectKind) -> Option<&'static str> {
    Some(match kind {
        ObjectKind::Artifact => "artifact",
        ObjectKind::Manifest => "manifest",
        ObjectKind::Classmap => "classmap",
        ObjectKind::Vconf => "vconf",
        ObjectKind::Inventory => "inventory",
        ObjectKind::Local => "local",
        ObjectKind::Tombstone => "tombstone",
        ObjectKind::Layer => "layer",
        ObjectKind::Pack => return None,
    })
}

/// Where a content object lives: `<prefix>/obj/<kind>/<key hex>` (D35).
pub fn object_key_path(prefix: &str, kind: ObjectKind, key: HashVal) -> Option<String> {
    let hex: String = key.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
    Some(format!("{prefix}/obj/{}/{hex}", kind_dir(kind)?))
}

/// How deep a closure follows parents before it gives up (fail closed).
const MAX_LINEAGE_DEPTH: usize = 64;

/// The coordinator's view of an object store.
pub struct CoordStore {
    store: Arc<dyn ObjectStore + Send + Sync>,
    prefix: String,
    /// Objects verified by this process: a content key and the kind it was
    /// found under, or a pack.
    verified: Mutex<BTreeMap<ObjectId, Option<ObjectKind>>>,
}

impl CoordStore {
    /// The objects under `prefix` in `store` (the Wardens' prefix).
    pub fn new(store: Arc<dyn ObjectStore + Send + Sync>, prefix: &str) -> Self {
        Self {
            store,
            prefix: prefix.to_string(),
            verified: Mutex::default(),
        }
    }

    fn packs(&self, c: ChronicleId) -> Option<Packs<Arc<dyn ObjectStore + Send + Sync>, NoSend>> {
        Packs::new(self.store.clone(), NoSend, &self.prefix, c).ok()
    }

    fn known(&self, o: &ObjectId) -> Option<Option<ObjectKind>> {
        self.verified
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(o)
            .copied()
    }

    fn remember(&self, o: ObjectId, kind: Option<ObjectKind>) {
        self.verified
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(o, kind);
    }

    /// Read a content object whole and check its key under `kind`.
    fn verify_content(&self, kind: ObjectKind, key: HashVal) -> Lookup<()> {
        let Some(path) = object_key_path(&self.prefix, kind, key) else {
            return Lookup::NotFound;
        };
        let mut r = match self.store.get(&path) {
            Ok(Some(r)) => r,
            Ok(None) => return Lookup::NotFound,
            Err(e) => return failed(&path, e, false),
        };
        let mut h = blake3::Hasher::new_derive_key(kind.prefix());
        if let Err(e) = std::io::copy(&mut r, &mut h) {
            return failed(&path, e, false);
        }
        if h.finalize().as_bytes() != key.as_bytes() {
            return failed(&path, "does not hash to its key", true);
        }
        Lookup::Found(())
    }

    fn content_lookup(&self, key: HashVal) -> Lookup<()> {
        let o = ObjectId::content(key);
        if let Some(Some(kind)) = self.known(&o) {
            let Some(path) = object_key_path(&self.prefix, kind, key) else {
                return Lookup::NotFound;
            };
            return match self.store.exists(&path) {
                Ok(true) => Lookup::Found(()),
                Ok(false) => Lookup::NotFound,
                Err(e) => failed(&path, e, false),
            };
        }
        // The kind is the key's domain: at most one kind holds it.  Gone
        // only if every kind answered not-found.
        let mut unreadable = false;
        for kind in CONTENT_KINDS {
            match self.verify_content(kind, key) {
                Lookup::Found(()) => {
                    self.remember(o, Some(kind));
                    return Lookup::Found(());
                }
                Lookup::NotFound => {}
                Lookup::Unreadable => unreadable = true,
            }
        }
        if unreadable {
            Lookup::Unreadable
        } else {
            Lookup::NotFound
        }
    }

    fn pack_lookup(&self, c: ChronicleId, name: &str) -> Lookup<()> {
        let o = ObjectId::pack(c, name);
        let Some(packs) = self.packs(c) else {
            return Lookup::Unreadable;
        };
        if self.known(&o).is_some() {
            return match packs.has_pack(name) {
                Ok(true) => Lookup::Found(()),
                Ok(false) => Lookup::NotFound,
                Err(e) => pack_failed(name, e),
            };
        }
        match packs.read_pack_log(name) {
            Ok(Some(_)) => {
                self.remember(o, None);
                Lookup::Found(())
            }
            Ok(None) => Lookup::NotFound,
            Err(e) => pack_failed(name, e),
        }
    }

    /// Push the closure of `c` at `seal` onto `out`: `Found` when it is
    /// complete.
    fn closure(
        &self,
        c: ChronicleId,
        seal: Lsn,
        depth: usize,
        out: &mut Vec<ObjectId>,
    ) -> Lookup<()> {
        if depth > MAX_LINEAGE_DEPTH {
            eprintln!("taso-coordd: the lineage of {c:?} is deeper than {MAX_LINEAGE_DEPTH}");
            return Lookup::NotFound;
        }
        let Some(packs) = self.packs(c) else {
            return Lookup::Unreadable;
        };
        let names = match packs.pack_names() {
            Ok(n) => n,
            Err(e) => return pack_failed(&format!("the packs of {c:?}"), e),
        };
        let mut first = None;
        for name in names {
            let Some((_, base, fs_to)) = name_bounds(&name) else {
                continue;
            };
            if base == Lsn::new(0) {
                first = Some(name.clone());
            }
            if base < seal || fs_to.is_some_and(|t| t <= seal) {
                out.push(ObjectId::pack(c, &name));
            }
        }
        // A parent is named by the Lineage record, lsn 1, in the pack that
        // starts at genesis.  A Chronicle whose lsn 1 is another record (a
        // Template's) has no parent.  No such pack: no such lineage.
        let Some(first) = first else {
            return Lookup::NotFound;
        };
        let frames = match packs.read_pack_log(&first) {
            Ok(Some((_, frames))) => frames,
            Ok(None) => return Lookup::NotFound,
            Err(e) => return pack_failed(&first, e),
        };
        match frames.first().map(|f| Payload::decode(&f.payload)) {
            Some(Ok(Payload::Lineage(l))) => match l.origin {
                Origin::Void => Lookup::Found(()),
                Origin::Fork { parent } | Origin::Succession { parent, .. } => {
                    self.closure(parent.chronicle, parent.seal, depth + 1, out)
                }
                // A Template-born Vessel's closure ends at its layer object
                // (P4 spec rev. 16 §2.1, D54).
                Origin::Template { layer_key, .. } => {
                    out.push(ObjectId::content(layer_key));
                    Lookup::Found(())
                }
            },
            Some(Ok(_)) => Lookup::Found(()),
            // A verified log whose lsn 1 does not decode.
            Some(Err(_)) | None => failed(&first, "its lsn 1 is no record", true),
        }
    }
}

/// A read that failed: logged, and never taken as an absence.  `integrity`
/// marks bytes that are there and do not verify (a store-integrity fault,
/// review fix 5a: refused for now, never "lost" or "deleted").
fn failed<T>(what: &str, why: impl fmt::Display, integrity: bool) -> Lookup<T> {
    if integrity {
        eprintln!("taso-coordd: store integrity: {what}: {why}");
    } else {
        eprintln!("taso-coordd: store read failed: {what}: {why}");
    }
    Lookup::Unreadable
}

/// A pack read's error, as a lookup answers it.  A name that is no pack
/// name names nothing the store can hold: not found.
fn pack_failed<T>(what: &str, e: PackError) -> Lookup<T> {
    match e {
        PackError::BadKey(_) => Lookup::NotFound,
        PackError::Corrupt { .. } | PackError::Conflict { .. } => failed(what, e, true),
        e => failed(what, e, false),
    }
}

impl StoreView for CoordStore {
    fn carries(&self, chronicle: ChronicleId, name: &str, digest: HashVal) -> bool {
        let Some(packs) = self.packs(chronicle) else {
            return false;
        };
        let Ok(Some((_, frames))) = packs.read_pack_log(name) else {
            return false;
        };
        self.remember(ObjectId::pack(chronicle, name), None);
        frames.iter().any(|f| match Payload::decode(&f.payload) {
            Ok(Payload::Contract(r)) => r.digest() == digest,
            Ok(Payload::Lineage(lineage)) => {
                Submitted::Birth { chronicle, lineage }.digest() == digest
            }
            _ => false,
        })
    }

    fn lookup(&self, object: &ObjectId) -> Lookup<()> {
        match object {
            ObjectId::Content(k) => self.content_lookup(HashVal::from_bytes(*k)),
            ObjectId::Pack(c, name) => self.pack_lookup(ChronicleId::from_bytes(*c), name),
        }
    }

    fn lookup_inventory(&self, key: HashVal) -> Lookup<Inventory> {
        let Some(path) = object_key_path(&self.prefix, ObjectKind::Inventory, key) else {
            return Lookup::NotFound;
        };
        let mut r = match self.store.get(&path) {
            Ok(Some(r)) => r,
            Ok(None) => return Lookup::NotFound,
            Err(e) => return failed(&path, e, false),
        };
        let mut bytes = Vec::new();
        if let Err(e) = r.read_to_end(&mut bytes) {
            return failed(&path, e, false);
        }
        if object_key(ObjectKind::Inventory, &bytes) != key {
            return failed(&path, "does not hash to its key", true);
        }
        match Inventory::decode(&bytes) {
            Ok(inv) => Lookup::Found(inv),
            // Verified bytes that are no inventory never become one.
            Err(_) => {
                eprintln!("taso-coordd: {path} is not an inventory");
                Lookup::NotFound
            }
        }
    }

    fn fs_packs(&self, chronicle: ChronicleId) -> Option<Vec<InventoryItem>> {
        let packs = self.packs(chronicle)?;
        let names = match packs.pack_names() {
            Ok(n) => n,
            Err(e) => {
                eprintln!("taso-coordd: listing the packs of {chronicle:?}: {e}");
                return None;
            }
        };
        let mut out = Vec::new();
        for n in names
            .into_iter()
            .filter(|n| name_bounds(n).is_some_and(|(_, _, fs)| fs.is_some()))
        {
            match packs.inventory_item(&n) {
                Ok(it) => out.push(it),
                Err(e) => {
                    eprintln!("taso-coordd: inspecting pack {n} of {chronicle:?}: {e}");
                    return None;
                }
            }
        }
        Some(out)
    }

    fn seal_closure(&self, chronicle: ChronicleId, seal: Lsn) -> Lookup<Vec<ObjectId>> {
        let mut out = Vec::new();
        match self.closure(chronicle, seal, 0, &mut out) {
            Lookup::Found(()) => Lookup::Found(out),
            Lookup::NotFound => Lookup::NotFound,
            Lookup::Unreadable => Lookup::Unreadable,
        }
    }

    fn lookup_replacement(&self, chronicle: ChronicleId, item: &InventoryItem) -> Lookup<HashVal> {
        let Some(packs) = self.packs(chronicle) else {
            return Lookup::Unreadable;
        };
        match packs.verify_replacement(item) {
            Ok(Some(h)) => Lookup::Found(h),
            Ok(None) => Lookup::NotFound,
            // No replacement can exist for this item (a tombstone form,
            // which no writer builds).
            Err(PackError::Refused(_)) => Lookup::NotFound,
            Err(e) => pack_failed(&item.pack.name, e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use taso_core::canon::Canonical;
    use taso_core::contract::{genesis_id, Consistency, ContractRecord, GenesisStarted, Peer};
    use taso_core::envelope::{BranchId, Epoch, Stream};
    use taso_core::record::{
        Authority, LayerRef, LineageRecord, Namespace, ParentSeal, Record, SealRecord, StreamCut,
        TurnId, Verdict,
    };

    use crate::segment::{Position, Segment};
    use crate::ship::{ByteStream, LocalStore, Sender};
    use crate::storage::{Dataset, Snapshot};
    use std::io;

    const PREFIX: &str = "taso";

    fn h(n: u8) -> HashVal {
        HashVal::from_bytes([n; 32])
    }

    struct FakeSend;
    impl Sender for FakeSend {
        fn send(&self, _: &Dataset, _: Option<&str>, to: Lsn) -> io::Result<ByteStream> {
            Ok(Box::new(io::Cursor::new(vec![to.get() as u8; 1000])))
        }
    }

    /// One Chronicle's local log, shipped with `Packs` into `store`.
    struct Log {
        _dir: tempfile::TempDir,
        id: ChronicleId,
        seg: Segment,
        tail: Position,
        packs: Packs<Arc<dyn ObjectStore + Send + Sync>, FakeSend>,
    }

    impl Log {
        fn new(
            store: &Arc<dyn ObjectStore + Send + Sync>,
            id: ChronicleId,
            origin: Origin,
        ) -> Self {
            Self::under(store, PREFIX, id, origin)
        }
        fn under(
            store: &Arc<dyn ObjectStore + Send + Sync>,
            prefix: &str,
            id: ChronicleId,
            origin: Origin,
        ) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let seg = Segment::create(dir.path().join("seg"), id, Position::GENESIS).unwrap();
            let packs = Packs::new(store.clone(), FakeSend, prefix, id).unwrap();
            let mut l = Self {
                _dir: dir,
                id,
                seg,
                tail: Position::GENESIS,
                packs,
            };
            l.push(
                Stream::Ctl,
                Payload::Lineage(LineageRecord {
                    origin,
                    namespace: Namespace::from_bytes([1; 16]),
                    ledger_pos: Lsn::new(0),
                }),
            );
            l
        }
        fn push(&mut self, stream: Stream, p: Payload) -> Position {
            let r = Record::new(
                self.id,
                BranchId::TRUNK,
                Epoch::FIRST,
                stream,
                self.tail.lsn.next(),
                self.tail.hash,
                p,
            );
            self.seg
                .append(&r.envelope, &r.payload.canon_bytes())
                .unwrap();
            self.tail = Position {
                lsn: r.envelope.lsn,
                hash: r.envelope.hash,
            };
            self.tail
        }
        /// A Seal, shipped with its `fs` section and named.
        fn seal(&mut self) -> Lsn {
            let p = self.push(
                Stream::Ctl,
                Payload::Seal(SealRecord {
                    parent: None,
                    cut: StreamCut {
                        fs: Lsn::new(0),
                        db: Lsn::new(0),
                        transcript: Lsn::new(0),
                    },
                    layer: LayerRef::new(1),
                    verdict: Verdict::Clean,
                    ledger_pos: Lsn::new(0),
                    turn: TurnId::new(1),
                }),
            );
            let snap = Snapshot {
                dataset: Dataset::new("tank/v").unwrap(),
                seal: p.lsn,
                guid: 7,
                seal_hash: Some(p.hash),
            };
            let s = self
                .packs
                .ship_seal(&[&self.seg], &snap, None)
                .unwrap()
                .unwrap();
            self.push(Stream::Ctl, Payload::FsShipped(s.record));
            p.lsn
        }
        fn ship(&self) {
            self.packs.ship_log(&[&self.seg], self.tail).unwrap();
        }
    }

    fn contract() -> ContractRecord {
        ContractRecord::GenesisStarted(Box::new(GenesisStarted {
            genesis_id: genesis_id(h(1), h(2), 1, None, "jarmo"),
            source_key: h(1),
            consistency: Consistency::Immutable,
            classmap_key: h(2),
            transform_version: 1,
            hook_waiver: None,
            authority: Authority {
                actor: "jarmo".into(),
                reason: "test".into(),
            },
            peer: Peer { uid: 0, pid: 1 },
        }))
    }

    struct World {
        dir: tempfile::TempDir,
        store: Arc<dyn ObjectStore + Send + Sync>,
        parent: Log,
        seal: Lsn,
    }

    /// A parent born from the void: Lineage, a Seal (shipped with its
    /// `fs`), its FsShipped, a contract record; all shipped.
    fn world() -> World {
        let dir = tempfile::tempdir().unwrap();
        let store: Arc<dyn ObjectStore + Send + Sync> =
            Arc::new(LocalStore::new(dir.path().join("bucket")));
        world_on(dir, store, PREFIX)
    }

    fn world_on(
        dir: tempfile::TempDir,
        store: Arc<dyn ObjectStore + Send + Sync>,
        prefix: &str,
    ) -> World {
        let id = ChronicleId::from_bytes([0xA1; 16]);
        let mut parent = Log::under(&store, prefix, id, Origin::Void);
        parent.push(Stream::Fs, Payload::Raw(vec![1, 2, 3]));
        let seal = parent.seal();
        parent.push(Stream::Ctl, Payload::Contract(Box::new(contract())));
        parent.ship();
        World {
            dir,
            store,
            parent,
            seal,
        }
    }

    fn file_of(w: &World, key: &str) -> std::path::PathBuf {
        w.dir.path().join("bucket").join(key)
    }

    #[test]
    fn carries_finds_the_record_in_a_verified_log() {
        let w = world();
        let cs = CoordStore::new(w.store.clone(), PREFIX);
        let c = w.parent.id;
        let names = w.parent.packs.pack_names().unwrap();
        let with = names.last().unwrap();
        let digest = contract().digest();
        assert!(cs.carries(c, with, digest));
        assert!(!cs.carries(c, with, h(9)), "another digest");
        assert!(!cs.carries(c, &names[0], digest), "another pack");
        assert!(!cs.carries(ChronicleId::from_bytes([2; 16]), with, digest));
        // A Birth is carried as its Lineage.
        let Ok(Some((_, frames))) = w.parent.packs.read_pack_log(&names[0]) else {
            panic!()
        };
        let Ok(Payload::Lineage(lineage)) = Payload::decode(&frames[0].payload) else {
            panic!()
        };
        let birth = Submitted::Birth {
            chronicle: c,
            lineage,
        };
        assert!(cs.carries(c, &names[0], birth.digest()));
        // A log that does not match its digest carries nothing.
        let hex: String = c.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
        let path = file_of(&w, &format!("{PREFIX}/{hex}/pack/{with}"));
        let mut b = std::fs::read(&path).unwrap();
        let i = b.len() - 50;
        b[i] ^= 1;
        std::fs::write(&path, &b).unwrap();
        assert!(!cs.carries(c, with, digest));
    }

    #[test]
    fn a_content_object_is_verified_once_then_checked_for_presence() {
        let w = world();
        let bytes = b"a manifest".to_vec();
        let key = object_key(ObjectKind::Manifest, &bytes);
        let path = object_key_path(PREFIX, ObjectKind::Manifest, key).unwrap();
        assert!(path.starts_with("taso/obj/manifest/") && path.len() == 18 + 64);
        let cs = CoordStore::new(w.store.clone(), PREFIX);
        let o = ObjectId::content(key);
        assert_eq!(cs.lookup(&o), Lookup::NotFound, "not there");
        w.store.put(&path, &mut &bytes[..]).unwrap();
        assert_eq!(
            cs.lookup(&o),
            Lookup::Found(()),
            "found under its kind, verified"
        );
        // Bytes that do not hash to the key, under the right path.
        let wrong = object_key(ObjectKind::Manifest, b"other");
        let wrong_path = object_key_path(PREFIX, ObjectKind::Manifest, wrong).unwrap();
        w.store.put(&wrong_path, &mut &bytes[..]).unwrap();
        assert_eq!(
            cs.lookup(&ObjectId::content(wrong)),
            Lookup::Unreadable,
            "an integrity fault is never an absence"
        );
        // Once verified, only presence is checked (D36) ...
        std::fs::write(file_of(&w, &path), b"tampered").unwrap();
        assert_eq!(cs.lookup(&o), Lookup::Found(()));
        // ... a new process verifies again.
        assert_eq!(
            CoordStore::new(w.store.clone(), PREFIX).lookup(&o),
            Lookup::Unreadable
        );
        w.store.delete(&path).unwrap();
        assert_eq!(cs.lookup(&o), Lookup::NotFound, "gone is gone");
    }

    #[test]
    fn packs_exist_once_their_log_verifies() {
        let w = world();
        let cs = CoordStore::new(w.store.clone(), PREFIX);
        let c = w.parent.id;
        let names = w.parent.packs.pack_names().unwrap();
        assert!(names
            .iter()
            .all(|n| cs.lookup(&ObjectId::pack(c, n)) == Lookup::Found(())));
        assert_eq!(
            cs.lookup(&ObjectId::pack(
                c,
                "00000000000000000009-00000000000000000008-00000000000000000000"
            )),
            Lookup::NotFound
        );
        assert_eq!(
            cs.lookup(&ObjectId::pack(c, "no-pack-name")),
            Lookup::NotFound
        );
        // A pack whose log is damaged before its first check: an integrity
        // fault, never an absence.
        let fresh = CoordStore::new(w.store.clone(), PREFIX);
        let hex: String = c.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
        let path = file_of(&w, &format!("{PREFIX}/{hex}/pack/{}", names[0]));
        let mut b = std::fs::read(&path).unwrap();
        b[300] ^= 1;
        std::fs::write(&path, &b).unwrap();
        assert_eq!(
            fresh.lookup(&ObjectId::pack(c, &names[0])),
            Lookup::Unreadable
        );
    }

    #[test]
    fn inventories_are_read_by_key() {
        let w = world();
        let cs = CoordStore::new(w.store.clone(), PREFIX);
        let items = cs.fs_packs(w.parent.id).expect("every pack accounted for");
        assert_eq!(items.len(), 1, "one fs-bearing pack");
        assert_eq!(items[0].sections, vec![w.seal]);
        let inv = Inventory::new(items).unwrap();
        let key = inv.key();
        assert_eq!(cs.lookup_inventory(key), Lookup::NotFound);
        let path = object_key_path(PREFIX, ObjectKind::Inventory, key).unwrap();
        w.store.put(&path, &mut &inv.bytes()[..]).unwrap();
        assert_eq!(cs.lookup_inventory(key), Lookup::Found(inv));
        assert_eq!(cs.lookup_inventory(h(3)), Lookup::NotFound);
        // Bytes under the key that do not hash to it.
        let other = object_key_path(PREFIX, ObjectKind::Inventory, h(4)).unwrap();
        w.store.put(&other, &mut &b"x"[..]).unwrap();
        assert_eq!(cs.lookup_inventory(h(4)), Lookup::Unreadable);
    }

    /// A pack that cannot be inspected is not left out of the answer: there
    /// is no answer, so no purge is computed from the packs that could be.
    #[test]
    fn an_uninspectable_pack_means_no_pack_list() {
        let w = world();
        let c = w.parent.id;
        let names = w.parent.packs.pack_names().unwrap();
        let hex: String = c.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
        let fs_pack = names
            .iter()
            .find(|n| name_bounds(n).is_some_and(|(_, _, fs)| fs.is_some()))
            .unwrap();
        let path = file_of(&w, &format!("{PREFIX}/{hex}/pack/{fs_pack}"));
        let mut b = std::fs::read(&path).unwrap();
        b.truncate(b.len() / 2);
        std::fs::write(&path, &b).unwrap();
        let cs = CoordStore::new(w.store.clone(), PREFIX);
        assert_eq!(cs.fs_packs(c), None, "a short list is not an answer");
    }

    #[test]
    fn a_replacement_is_verified_against_its_item() {
        let w = world();
        let cs = CoordStore::new(w.store.clone(), PREFIX);
        let item = cs.fs_packs(w.parent.id).unwrap().pop().unwrap();
        assert_eq!(cs.lookup_replacement(w.parent.id, &item), Lookup::NotFound);
        let d = w.parent.packs.install_replacement(&item).unwrap();
        assert_eq!(cs.lookup_replacement(w.parent.id, &item), Lookup::Found(d));
        // A replacement that does not match its item: an integrity fault.
        let mut other = item.clone();
        other.log_digest = h(7);
        assert_eq!(
            cs.lookup_replacement(w.parent.id, &other),
            Lookup::Unreadable
        );
    }

    #[test]
    fn a_seal_closure_follows_the_lineage_to_the_parent() {
        let w = world();
        let cs = CoordStore::new(w.store.clone(), PREFIX);
        let p = w.parent.id;
        let Lookup::Found(parent_closure) = cs.seal_closure(p, w.seal) else {
            panic!()
        };
        let names = w.parent.packs.pack_names().unwrap();
        // Every pack whose log starts before the Seal, or whose fs ends
        // at or before it.
        assert!(!parent_closure.is_empty());
        for o in &parent_closure {
            let ObjectId::Pack(c, n) = o else { panic!() };
            assert_eq!(*c, *p.as_bytes());
            assert!(names.contains(n));
        }
        // A fork of the parent's Seal.
        let parent_seal = ParentSeal {
            chronicle: p,
            seal: w.seal,
            seal_hash: HashVal::GENESIS,
        };
        let f = ChronicleId::from_bytes([0xB2; 16]);
        let mut fork = Log::new(
            &w.store,
            f,
            Origin::Fork {
                parent: parent_seal,
            },
        );
        fork.push(Stream::Fs, Payload::Raw(vec![9]));
        fork.ship();
        let Lookup::Found(closure) = cs.seal_closure(f, Lsn::new(100)) else {
            panic!()
        };
        let own: Vec<_> = closure
            .iter()
            .filter(|o| matches!(o, ObjectId::Pack(c, _) if *c == *f.as_bytes()))
            .collect();
        assert_eq!(own.len(), 1);
        assert!(
            parent_closure.iter().all(|o| closure.contains(o)),
            "the parent's closure"
        );
        assert!(closure.iter().all(|o| cs.lookup(o) == Lookup::Found(())));
        // A Chronicle the store holds no packs of: no such lineage.
        let g = ChronicleId::from_bytes([0xC3; 16]);
        assert_eq!(cs.seal_closure(g, Lsn::new(5)), Lookup::NotFound);
    }

    /// A store whose reads fail with `kind` while `on`: a timeout, a
    /// permission refused, an outage.  Writes pass.
    struct Failing {
        inner: Arc<dyn ObjectStore + Send + Sync>,
        on: std::sync::atomic::AtomicBool,
        kind: io::ErrorKind,
    }
    impl Failing {
        fn fail<T>(&self) -> io::Result<Option<T>> {
            if self.on.load(std::sync::atomic::Ordering::Relaxed) {
                Err(io::Error::new(self.kind, "the store failed"))
            } else {
                Ok(None)
            }
        }
    }
    impl ObjectStore for Failing {
        fn put(&self, key: &str, data: &mut dyn Read) -> io::Result<u64> {
            self.inner.put(key, data)
        }
        fn get(&self, key: &str) -> io::Result<Option<ByteStream>> {
            self.fail::<()>()?;
            self.inner.get(key)
        }
        fn exists(&self, key: &str) -> io::Result<bool> {
            self.fail::<()>()?;
            self.inner.exists(key)
        }
        fn list(&self, prefix: &str) -> io::Result<Vec<String>> {
            self.fail::<()>()?;
            self.inner.list(prefix)
        }
        fn list_times(&self, prefix: &str) -> io::Result<Vec<(String, std::time::SystemTime)>> {
            self.fail::<()>()?;
            self.inner.list_times(prefix)
        }
    }

    /// Review fix 5a: a timeout and a permission failure are each
    /// `Unreadable` for every read, before and after an object's first
    /// check -- never the store's not-found.  (Integrity faults: the
    /// content, pack, inventory and replacement tests above.)
    #[test]
    fn a_failed_read_is_never_not_found() {
        for kind in [io::ErrorKind::TimedOut, io::ErrorKind::PermissionDenied] {
            let dir = tempfile::tempdir().unwrap();
            let failing = Arc::new(Failing {
                inner: Arc::new(LocalStore::new(dir.path().join("bucket"))),
                on: false.into(),
                kind,
            });
            let store: Arc<dyn ObjectStore + Send + Sync> = failing.clone();
            let w = world_on(dir, store.clone(), PREFIX);
            let cs = CoordStore::new(store, PREFIX);
            let c = w.parent.id;
            let pack = ObjectId::pack(c, &w.parent.packs.pack_names().unwrap()[0]);
            let bytes = b"a manifest".to_vec();
            let key = object_key(ObjectKind::Manifest, &bytes);
            let path = object_key_path(PREFIX, ObjectKind::Manifest, key).unwrap();
            w.store.put(&path, &mut &bytes[..]).unwrap();
            let item = cs.fs_packs(c).unwrap().pop().unwrap();
            let checked = ObjectId::content(key);
            assert_eq!(cs.lookup(&checked), Lookup::Found(()));
            failing.on.store(true, std::sync::atomic::Ordering::Relaxed);
            for (what, got) in [
                ("checked content", cs.lookup(&checked)),
                ("unchecked content", cs.lookup(&ObjectId::content(h(5)))),
                ("a pack", cs.lookup(&pack)),
                (
                    "a missing pack",
                    cs.lookup(&ObjectId::pack(
                        c,
                        "00000000000000000009-00000000000000000008-00000000000000000000",
                    )),
                ),
            ] {
                assert_eq!(got, Lookup::Unreadable, "{kind:?}: {what}");
            }
            assert_eq!(cs.lookup_inventory(h(3)), Lookup::Unreadable, "{kind:?}");
            assert_eq!(
                cs.lookup_replacement(c, &item),
                Lookup::Unreadable,
                "{kind:?}"
            );
            assert_eq!(cs.seal_closure(c, w.seal), Lookup::Unreadable, "{kind:?}");
            assert_eq!(cs.fs_packs(c), None, "{kind:?}");
            assert!(!cs.carries(c, &pack_name(&pack), contract().digest()));
            // The store answers again: the same reads answer for real.
            failing
                .on
                .store(false, std::sync::atomic::Ordering::Relaxed);
            assert_eq!(cs.lookup(&checked), Lookup::Found(()));
            assert_eq!(cs.lookup(&ObjectId::content(h(5))), Lookup::NotFound);
            assert_eq!(cs.lookup_replacement(c, &item), Lookup::NotFound);
        }
    }

    fn pack_name(o: &ObjectId) -> String {
        match o {
            ObjectId::Pack(_, n) => n.clone(),
            ObjectId::Content(_) => panic!(),
        }
    }

    /// The same reads against a real Garage: set TASO_S3_ENDPOINT,
    /// TASO_S3_BUCKET, TASO_S3_KEY_ID, TASO_S3_SECRET (TASO_S3_REGION
    /// defaults to `garage`).
    #[test]
    #[ignore = "needs a Garage bucket: set TASO_S3_*"]
    fn the_coordinators_reads_on_garage() {
        use crate::s3::{S3Config, S3Store};
        let env = |k: &str| std::env::var(k).unwrap_or_else(|_| panic!("set {k}"));
        let s3 = S3Store::new(
            S3Config {
                endpoint: env("TASO_S3_ENDPOINT"),
                region: std::env::var("TASO_S3_REGION").unwrap_or_else(|_| "garage".into()),
                bucket: env("TASO_S3_BUCKET"),
                access_key_id: env("TASO_S3_KEY_ID"),
                secret_key: env("TASO_S3_SECRET"),
                ca_file: std::env::var_os("TASO_S3_CA").map(Into::into),
            },
            std::time::Duration::from_secs(10),
        )
        .unwrap();
        let store: Arc<dyn ObjectStore + Send + Sync> = Arc::new(s3);
        // A prefix of its own: nothing else in the bucket is touched.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let prefix = format!("t-coordstore-{nanos}");
        let w = world_on(tempfile::tempdir().unwrap(), store.clone(), &prefix);
        let cs = CoordStore::new(store.clone(), &prefix);
        let c = w.parent.id;
        let names = w.parent.packs.pack_names().unwrap();
        assert!(cs.carries(c, names.last().unwrap(), contract().digest()));
        let found = |o: &ObjectId| cs.lookup(o) == Lookup::Found(());
        assert!(names.iter().all(|n| found(&ObjectId::pack(c, n))));
        let item = cs.fs_packs(c).unwrap().pop().unwrap();
        assert_eq!(item.sections, vec![w.seal]);
        let Lookup::Found(closure) = cs.seal_closure(c, w.seal) else {
            panic!()
        };
        assert!(!closure.is_empty() && closure.iter().all(found));
        let bytes = format!("a classmap {nanos}").into_bytes();
        let key = object_key(ObjectKind::Classmap, &bytes);
        let path = object_key_path(&prefix, ObjectKind::Classmap, key).unwrap();
        // A real store's not-found (a 404) is the one absence.
        assert_eq!(cs.lookup(&ObjectId::content(key)), Lookup::NotFound);
        store.put(&path, &mut &bytes[..]).unwrap();
        assert!(found(&ObjectId::content(key)));
        assert_eq!(cs.lookup_replacement(c, &item), Lookup::NotFound);
        let d = w.parent.packs.install_replacement(&item).unwrap();
        assert_eq!(cs.lookup_replacement(c, &item), Lookup::Found(d));
        // Leave the bucket as found: only this run's prefix.
        for k in store.list(&prefix).unwrap() {
            store.delete(&k).unwrap();
        }
        assert!(store.list(&prefix).unwrap().is_empty());
    }
}
