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
//! - **`exists`** verifies an object the first time it is asked about it
//!   — a content object read whole and its key recomputed under its
//!   kind's domain; a pack's header and log — and after that, until this
//!   process ends, only checks it is still there (D36).
//! - **`inventory`** reads the inventory object and checks its key.
//! - **`fs_packs`** reads every fs-bearing pack of the Chronicle whole,
//!   trailer included ([`Packs::inventory_item`]); purges are rare.
//! - **`seal_closure`** lists the packs restoring a Seal needs, with its
//!   parent's closure for a fork or a succession (§2.1), from pack names
//!   and the Lineage record.
//! - **`verify_replacement`** is [`Packs::verify_replacement`].
//!
//! A store error answers "no" (not readable, not there): the coordinator
//! refuses rather than guesses, and the caller may submit again.
//!
//! Normative reference: `Taso_spec_p4_contracts` rev. 12, BLAKE3
//! `37c75f30580bf3edd79674be38702d7893af413813bbfe6d4585231e9477144a`.

use std::collections::BTreeMap;
use std::io::{self, Read};
use std::sync::{Arc, Mutex};

use taso_core::contract::{object_key, Inventory, InventoryItem, ObjectKind};
use taso_core::coordlog::{ObjectId, StoreView, Submitted};
use taso_core::envelope::{ChronicleId, HashVal, Lsn};
use taso_core::record::{Origin, Payload};

use crate::pack::{name_bounds, Packs};
use crate::ship::{ByteStream, ObjectStore, Sender};
use crate::zfs::Dataset;

/// The content-addressed kinds, in the order the coordinator looks for a
/// key whose kind it does not know (D35).
pub const CONTENT_KINDS: [ObjectKind; 7] = [
    ObjectKind::Artifact,
    ObjectKind::Manifest,
    ObjectKind::Classmap,
    ObjectKind::Vconf,
    ObjectKind::Inventory,
    ObjectKind::Local,
    ObjectKind::Tombstone,
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

/// The name a closure reports for what it could not read: no pack has it,
/// so a hold on it fails and the accept is refused (fail closed: a
/// closure is never silently smaller than it should be).
const UNREADABLE: &str = "unreadable";

/// The coordinator's view of an object store.
pub struct CoordStore {
    store: Arc<dyn ObjectStore + Send + Sync>,
    prefix: String,
    /// Objects verified by this process: a content key and the kind it was
    /// found under, or a pack.
    verified: Mutex<BTreeMap<ObjectId, Option<ObjectKind>>>,
}

/// Packs are only read here: no `fs` stream is ever produced.
struct NoSend;

impl Sender for NoSend {
    fn send(&self, _: &Dataset, _: Option<&str>, _: Lsn) -> io::Result<ByteStream> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "the coordinator never sends",
        ))
    }
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
    /// `Some(true)` verified, `Some(false)` there but wrong (an integrity
    /// fault), `None` not there or not readable.
    fn verify_content(&self, kind: ObjectKind, key: HashVal) -> Option<bool> {
        let path = object_key_path(&self.prefix, kind, key)?;
        let mut r = self.store.get(&path).ok()??;
        let mut h = blake3::Hasher::new_derive_key(kind.prefix());
        let mut buf = vec![0u8; 1 << 16];
        loop {
            match r.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    h.update(&buf[..n]);
                }
                Err(_) => return None,
            }
        }
        let ok = h.finalize().as_bytes() == key.as_bytes();
        if !ok {
            eprintln!("taso-coordd: store integrity: {path} does not hash to its key");
        }
        Some(ok)
    }

    fn content_exists(&self, key: HashVal) -> bool {
        let o = ObjectId::content(key);
        if let Some(Some(kind)) = self.known(&o) {
            return object_key_path(&self.prefix, kind, key)
                .is_some_and(|p| self.store.exists(&p).unwrap_or(false));
        }
        // The kind is the key's domain: at most one kind holds it.
        for kind in CONTENT_KINDS {
            match self.verify_content(kind, key) {
                Some(true) => {
                    self.remember(o, Some(kind));
                    return true;
                }
                Some(false) => return false,
                None => {}
            }
        }
        false
    }

    fn pack_exists(&self, c: ChronicleId, name: &str) -> bool {
        let o = ObjectId::pack(c, name);
        let Some(packs) = self.packs(c) else {
            return false;
        };
        if self.known(&o).is_some() {
            return packs.has_pack(name).unwrap_or(false);
        }
        match packs.read_pack_log(name) {
            Ok(Some(_)) => {
                self.remember(o, None);
                true
            }
            _ => false,
        }
    }

    fn closure(&self, c: ChronicleId, seal: Lsn, depth: usize, out: &mut Vec<ObjectId>) {
        let unreadable = |out: &mut Vec<ObjectId>| out.push(ObjectId::pack(c, UNREADABLE));
        if depth > MAX_LINEAGE_DEPTH {
            return unreadable(out);
        }
        let Some(packs) = self.packs(c) else {
            return unreadable(out);
        };
        let Ok(names) = packs.pack_names() else {
            return unreadable(out);
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
        // Template's) has no parent; one whose lsn 1 cannot be read is
        // reported unreadable.
        let first = first
            .and_then(|n| packs.read_pack_log(&n).ok().flatten())
            .and_then(|(_, frames)| frames.into_iter().next())
            .and_then(|f| Payload::decode(&f.payload).ok());
        match first {
            Some(Payload::Lineage(l)) => match l.origin {
                Origin::Void => {}
                Origin::Fork { parent } | Origin::Succession { parent, .. } => {
                    self.closure(parent.chronicle, parent.seal, depth + 1, out)
                }
            },
            Some(_) => {}
            None => unreadable(out),
        }
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

    fn exists(&self, object: &ObjectId) -> bool {
        match object {
            ObjectId::Content(k) => self.content_exists(HashVal::from_bytes(*k)),
            ObjectId::Pack(c, name) => self.pack_exists(ChronicleId::from_bytes(*c), name),
        }
    }

    fn inventory(&self, key: HashVal) -> Option<Inventory> {
        let path = object_key_path(&self.prefix, ObjectKind::Inventory, key)?;
        let mut bytes = Vec::new();
        self.store.get(&path).ok()??.read_to_end(&mut bytes).ok()?;
        if object_key(ObjectKind::Inventory, &bytes) != key {
            eprintln!("taso-coordd: store integrity: {path} does not hash to its key");
            return None;
        }
        Inventory::decode(&bytes).ok()
    }

    fn fs_packs(&self, chronicle: ChronicleId) -> Vec<InventoryItem> {
        let Some(packs) = self.packs(chronicle) else {
            return Vec::new();
        };
        packs
            .pack_names()
            .unwrap_or_default()
            .into_iter()
            .filter(|n| name_bounds(n).is_some_and(|(_, _, fs)| fs.is_some()))
            .filter_map(|n| packs.inventory_item(&n).ok())
            .collect()
    }

    fn seal_closure(&self, chronicle: ChronicleId, seal: Lsn) -> Vec<ObjectId> {
        let mut out = Vec::new();
        self.closure(chronicle, seal, 0, &mut out);
        out
    }

    fn verify_replacement(&self, chronicle: ChronicleId, item: &InventoryItem) -> Option<HashVal> {
        self.packs(chronicle)?
            .verify_replacement(item)
            .ok()
            .flatten()
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
    use crate::ship::LocalStore;
    use crate::zfs::Snapshot;

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
                createtxg: 1,
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
        assert!(!cs.exists(&o), "not there");
        w.store.put(&path, &mut &bytes[..]).unwrap();
        assert!(cs.exists(&o), "found under its kind, verified");
        // Bytes that do not hash to the key, under the right path.
        let wrong = object_key(ObjectKind::Manifest, b"other");
        let wrong_path = object_key_path(PREFIX, ObjectKind::Manifest, wrong).unwrap();
        w.store.put(&wrong_path, &mut &bytes[..]).unwrap();
        assert!(
            !cs.exists(&ObjectId::content(wrong)),
            "an integrity fault is no"
        );
        // Once verified, only presence is checked (D36) ...
        std::fs::write(file_of(&w, &path), b"tampered").unwrap();
        assert!(cs.exists(&o));
        // ... a new process verifies again.
        assert!(!CoordStore::new(w.store.clone(), PREFIX).exists(&o));
        w.store.delete(&path).unwrap();
        assert!(!cs.exists(&o), "gone is gone");
    }

    #[test]
    fn packs_exist_once_their_log_verifies() {
        let w = world();
        let cs = CoordStore::new(w.store.clone(), PREFIX);
        let c = w.parent.id;
        let names = w.parent.packs.pack_names().unwrap();
        assert!(names.iter().all(|n| cs.exists(&ObjectId::pack(c, n))));
        assert!(!cs.exists(&ObjectId::pack(
            c,
            "00000000000000000009-00000000000000000008-00000000000000000000"
        )));
        assert!(!cs.exists(&ObjectId::pack(c, UNREADABLE)));
        // A pack whose log is damaged before its first check does not exist.
        let fresh = CoordStore::new(w.store.clone(), PREFIX);
        let hex: String = c.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
        let path = file_of(&w, &format!("{PREFIX}/{hex}/pack/{}", names[0]));
        let mut b = std::fs::read(&path).unwrap();
        b[300] ^= 1;
        std::fs::write(&path, &b).unwrap();
        assert!(!fresh.exists(&ObjectId::pack(c, &names[0])));
    }

    #[test]
    fn inventories_are_read_by_key() {
        let w = world();
        let cs = CoordStore::new(w.store.clone(), PREFIX);
        let items = cs.fs_packs(w.parent.id);
        assert_eq!(items.len(), 1, "one fs-bearing pack");
        assert_eq!(items[0].sections, vec![w.seal]);
        let inv = Inventory::new(items).unwrap();
        let key = inv.key();
        assert_eq!(cs.inventory(key), None);
        let path = object_key_path(PREFIX, ObjectKind::Inventory, key).unwrap();
        w.store.put(&path, &mut &inv.bytes()[..]).unwrap();
        assert_eq!(cs.inventory(key), Some(inv));
        assert_eq!(cs.inventory(h(3)), None);
    }

    #[test]
    fn a_replacement_is_verified_against_its_item() {
        let w = world();
        let cs = CoordStore::new(w.store.clone(), PREFIX);
        let item = cs.fs_packs(w.parent.id).pop().unwrap();
        assert_eq!(cs.verify_replacement(w.parent.id, &item), None);
        let d = w.parent.packs.install_replacement(&item).unwrap();
        assert_eq!(cs.verify_replacement(w.parent.id, &item), Some(d));
    }

    #[test]
    fn a_seal_closure_follows_the_lineage_to_the_parent() {
        let w = world();
        let cs = CoordStore::new(w.store.clone(), PREFIX);
        let p = w.parent.id;
        let parent_closure = cs.seal_closure(p, w.seal);
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
        let closure = cs.seal_closure(f, Lsn::new(100));
        let own: Vec<_> = closure
            .iter()
            .filter(|o| matches!(o, ObjectId::Pack(c, _) if *c == *f.as_bytes()))
            .collect();
        assert_eq!(own.len(), 1);
        assert!(
            parent_closure.iter().all(|o| closure.contains(o)),
            "the parent's closure"
        );
        assert!(closure.iter().all(|o| cs.exists(o)));
        // A Chronicle whose first pack is unreadable: the closure names
        // something that does not exist, so a hold on it fails.
        let g = ChronicleId::from_bytes([0xC3; 16]);
        assert_eq!(
            cs.seal_closure(g, Lsn::new(5)),
            vec![ObjectId::pack(g, UNREADABLE)]
        );
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
        assert!(names.iter().all(|n| cs.exists(&ObjectId::pack(c, n))));
        let item = cs.fs_packs(c).pop().unwrap();
        assert_eq!(item.sections, vec![w.seal]);
        let closure = cs.seal_closure(c, w.seal);
        assert!(!closure.is_empty() && closure.iter().all(|o| cs.exists(o)));
        let bytes = format!("a classmap {nanos}").into_bytes();
        let key = object_key(ObjectKind::Classmap, &bytes);
        let path = object_key_path(&prefix, ObjectKind::Classmap, key).unwrap();
        assert!(!cs.exists(&ObjectId::content(key)));
        store.put(&path, &mut &bytes[..]).unwrap();
        assert!(cs.exists(&ObjectId::content(key)));
        assert_eq!(cs.verify_replacement(c, &item), None);
        let d = w.parent.packs.install_replacement(&item).unwrap();
        assert_eq!(cs.verify_replacement(c, &item), Some(d));
        // Leave the bucket as found: only this run's prefix.
        for k in store.list(&prefix).unwrap() {
            store.delete(&k).unwrap();
        }
        assert!(store.list(&prefix).unwrap().is_empty());
    }
}
