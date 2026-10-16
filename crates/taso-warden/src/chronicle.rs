//! One Vessel's Chronicle: the coordinator, the local segment and the
//! layer store joined into the Warden's append and Seal paths
//! (v1.0 §1 P1, §3; v0.4 §5.2, §8).
//!
//! # Append
//!
//! Build the record at `tail + 1` under our epoch → [`Segment::append`]
//! (fsync) → [`Coord::append`] (CAS).  A refused CAS cuts the frame
//! off again and **fences** the Chronicle: a refusal means our view of the
//! head is no longer the coordinator's, so this Warden may not write
//! again.  A failure whose outcome is unknown ([`CoordError::outcome_unknown`]:
//! storage, a corrupt row, a lost connection to a remote coordinator)
//! leaves it unknown whether the CAS landed; the frame is kept, the
//! Chronicle is **poisoned** and must be reopened, and recovery against
//! the anchored head settles it either way.
//!
//! # Seal
//!
//! Build the Seal record (stream `Ctl`, as in the model) — its hash is
//! known before it is appended → snapshot the layer as
//! `@taso-seal-<lsn>` bound to that hash → append and CAS the record.  If
//! the append fails, the snapshot is destroyed.
//!
//! **A snapshot is a Seal only once its record is accepted.**  The other
//! order (record, then snapshot) would let a crash leave an accepted Seal
//! naming a layer that never existed, and a later snapshot would freeze
//! the wrong state.  Snapshot-first leaves at worst an orphan snapshot,
//! which recovery recognises exactly: its lsn is past the head, or the
//! accepted record at its lsn has another hash.
//!
//! In Phase 1 the Seal's `layer` is its own lsn, because that is what
//! names the snapshot.  The ZFS guid cannot go into the record: the
//! record's hash is fixed before the snapshot exists.
//!
//! # Open
//!
//! Opening is a claim of ownership.  [`Chronicle::open`] first takes a new
//! epoch with [`Coord::transfer`], so a previous incarnation still
//! alive somewhere is fenced *before* anything is read; then recovers the
//! segment against the anchored head; then destroys orphan snapshots.
//! Who may call `open` is decided above this module (rebirth, P2).
//!
//! On one node, a lock file in the Chronicle's directory keeps two
//! processes off the same segment: without it, a fenced writer's frame
//! (and its truncation) could land on top of the new holder's accepted
//! frames before the CAS refuses it.
//!
//! Known gap: an accepted Seal whose snapshot is missing is not detected
//! yet.  That needs the record kind, i.e. the payload decoder; with
//! snapshot-first it can only happen if someone destroys a snapshot by
//! hand.
//!
//! Normative references: v0.4 §2.1, §5.2, §8.2–8.7; v1.0 §1 (P1), §3.

use std::collections::HashMap;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use taso_core::canon::Canonical;
use taso_core::envelope::{BranchId, ChronicleHead, ChronicleId, Epoch, HashVal, Lsn, Stream};
use taso_core::model::WardenId;
use taso_core::record::{LayerRef, Payload, Record, SealRecord, StreamCut, TurnId, Verdict};

use crate::coordinator::{Coord, CoordError};
use crate::segment::{self, Position, Segment, SegmentError};
use crate::zfs::{Cli, Dataset, Runner, Zfs};

/// File name of the (only, for now) segment in a Chronicle directory.
const SEGMENT_FILE: &str = "seg-00000000000000000000";

/// File name of the lock that keeps a second process out.
const LOCK_FILE: &str = "LOCK";

// ── Layers ──────────────────────────────────────────────────────────

/// Error from a layer store.
pub type LayerError = Box<dyn std::error::Error + Send + Sync>;

/// Where Seal layers live: ZFS snapshots in Phase 1 (Btrfs is the
/// fallback; v1.0 §3).
///
/// Only layers Taso made and bound to a record hash are reported; anything
/// else on the dataset is ignored, never destroyed.
pub trait Layers {
    /// Freeze the current state as the layer for the Seal record at `lsn`
    /// with hash `hash`.  An existing layer at `lsn` is an error.
    fn snapshot(&mut self, lsn: Lsn, hash: HashVal) -> Result<(), LayerError>;
    /// Every Seal layer, as `(lsn, record hash)`, in lsn order.
    fn list(&self) -> Result<Vec<(Lsn, HashVal)>, LayerError>;
    /// Destroy the layer at `lsn`, if it exists.  Used only for orphans:
    /// layers whose record was never accepted.
    fn destroy(&mut self, lsn: Lsn) -> Result<(), LayerError>;
}

/// [`Layers`] over a ZFS dataset.
#[derive(Clone, Debug)]
pub struct ZfsLayers<R: Runner = Cli> {
    zfs: Zfs<R>,
    dataset: Dataset,
}

impl<R: Runner> ZfsLayers<R> {
    /// Layers of `dataset`, driven by `zfs`.
    pub fn new(zfs: Zfs<R>, dataset: Dataset) -> Self {
        Self { zfs, dataset }
    }

    /// The dataset.
    pub fn dataset(&self) -> &Dataset {
        &self.dataset
    }
}

impl<R: Runner> Layers for ZfsLayers<R> {
    fn snapshot(&mut self, lsn: Lsn, hash: HashVal) -> Result<(), LayerError> {
        self.zfs.snapshot(&self.dataset, lsn, hash)?;
        Ok(())
    }

    fn list(&self) -> Result<Vec<(Lsn, HashVal)>, LayerError> {
        Ok(self
            .zfs
            .list(&self.dataset)?
            .into_iter()
            .filter_map(|s| s.seal_hash.map(|h| (s.seal, h)))
            .collect())
    }

    fn destroy(&mut self, lsn: Lsn) -> Result<(), LayerError> {
        if let Some(snap) = self.zfs.get(&self.dataset, lsn)? {
            self.zfs.destroy(&snap)?;
        }
        Ok(())
    }
}

// ── Errors and reports ──────────────────────────────────────────────

/// Why a Chronicle operation failed.
#[derive(Debug)]
pub enum ChronicleError {
    /// The coordinator failed (storage or corrupt row) outside an append.
    Coord(CoordError),
    /// The coordinator refused our append.  The frame was cut off and the
    /// Chronicle is now fenced.
    Refused(CoordError),
    /// The local segment failed.
    Segment(SegmentError),
    /// The layer store failed.
    Layer(LayerError),
    /// Another process holds this Chronicle directory.
    Locked(PathBuf),
    /// The coordinator has accepted records but there is no local segment.
    MissingSegment {
        /// The anchored lsn.
        anchored: Lsn,
    },
    /// This Warden lost ownership earlier; it may not write again.
    Fenced,
    /// An earlier append's outcome is unknown; reopen to recover.
    Poisoned,
    /// A Seal's check failed after the layer was frozen; the layer was
    /// destroyed and no Seal record was written.
    CheckFailed(String),
}

impl fmt::Display for ChronicleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Coord(e) => write!(f, "coordinator: {e}"),
            Self::Refused(e) => write!(f, "append refused, chronicle fenced: {e}"),
            Self::Segment(e) => write!(f, "segment: {e}"),
            Self::Layer(e) => write!(f, "layer: {e}"),
            Self::Locked(p) => write!(f, "{} is held by another process", p.display()),
            Self::MissingSegment { anchored } => write!(
                f,
                "coordinator is at lsn {} but there is no local segment",
                anchored.get()
            ),
            Self::Fenced => write!(f, "chronicle is fenced: ownership was lost"),
            Self::Poisoned => write!(f, "chronicle is poisoned: reopen to recover"),
            Self::CheckFailed(why) => write!(f, "seal check failed: {why}"),
        }
    }
}

impl std::error::Error for ChronicleError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Coord(e) | Self::Refused(e) => Some(e),
            Self::Segment(e) => Some(e),
            Self::Layer(e) => Some(e.as_ref()),
            _ => None,
        }
    }
}

impl From<SegmentError> for ChronicleError {
    fn from(e: SegmentError) -> Self {
        Self::Segment(e)
    }
}

/// What [`Chronicle::open`] did to reach a consistent state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Recovery {
    /// The epoch this Warden now holds.
    pub epoch: Epoch,
    /// The anchored head recovery landed on.
    pub head: ChronicleHead,
    /// What the segment dropped.
    pub segment: segment::Recovery,
    /// Orphan layers destroyed (their records were never accepted).
    pub orphan_layers: Vec<Lsn>,
    /// The last accepted Seal, if any.
    pub last_seal: Option<Position>,
}

/// A Seal that was taken and accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sealed {
    /// The Seal record's position (also its layer's name).
    pub seal: Position,
    /// The anchored head after it.
    pub head: ChronicleHead,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Health {
    Live,
    Fenced,
    Poisoned,
}

// ── Chronicle ───────────────────────────────────────────────────────

/// One Vessel's Chronicle, held by one Warden.
pub struct Chronicle<L: Layers> {
    id: ChronicleId,
    warden: WardenId,
    epoch: Epoch,
    coord: Arc<dyn Coord>,
    segment: Segment,
    layers: L,
    last_seal: Option<Position>,
    health: Health,
    _lock: File,
}

impl<L: Layers> Chronicle<L> {
    /// Register a new Chronicle with `warden` as its first holder and open
    /// it.  `dir` must exist; it holds the segment and the lock.
    pub fn create(
        dir: impl AsRef<Path>,
        coord: Arc<dyn Coord>,
        id: ChronicleId,
        warden: WardenId,
        layers: L,
    ) -> Result<(Self, Recovery), ChronicleError> {
        coord.register(id, warden).map_err(ChronicleError::Coord)?;
        Self::open(dir, coord, id, warden, layers)
    }

    /// Take ownership of an existing Chronicle and recover it.
    ///
    /// In order: lock `dir`; transfer ownership to `warden` (new epoch,
    /// fences any previous holder); open the segment against the anchored
    /// head (creating it if the Chronicle has no records yet); destroy
    /// orphan layers.
    pub fn open(
        dir: impl AsRef<Path>,
        coord: Arc<dyn Coord>,
        id: ChronicleId,
        warden: WardenId,
        mut layers: L,
    ) -> Result<(Self, Recovery), ChronicleError> {
        let dir = dir.as_ref();
        let lock = lock_dir(dir)?;

        let epoch = coord.transfer(id, warden).map_err(ChronicleError::Coord)?;
        let head = coord.head(id).map_err(ChronicleError::Coord)?;

        let seg_path = dir.join(SEGMENT_FILE);
        let (segment, seg_recovery) = if seg_path.exists() {
            Segment::open(&seg_path, head)?
        } else if head.lsn == Lsn::new(0) {
            (Segment::create(&seg_path, id, Position::GENESIS)?, segment::Recovery::default())
        } else {
            return Err(ChronicleError::MissingSegment { anchored: head.lsn });
        };

        // Accepted record hashes, by lsn, as the segment now holds them.
        let mut accepted: HashMap<Lsn, HashVal> =
            segment.frames()?.into_iter().map(|f| (f.envelope.lsn, f.envelope.hash)).collect();
        accepted.insert(segment.base().lsn, segment.base().hash);

        let mut orphan_layers = Vec::new();
        let mut last_seal = None;
        // A layer is a Seal iff the accepted record at its lsn has its hash.
        // Past the head there is no accepted record, so that case is
        // covered too.  Layers before the segment's base cannot be checked
        // here and are left alone.
        for (lsn, hash) in layers.list().map_err(ChronicleError::Layer)? {
            if lsn < segment.base().lsn {
                continue;
            }
            if accepted.get(&lsn) == Some(&hash) {
                last_seal = Some(Position { lsn, hash });
            } else {
                layers.destroy(lsn).map_err(ChronicleError::Layer)?;
                orphan_layers.push(lsn);
            }
        }

        let recovery = Recovery {
            epoch,
            head,
            segment: seg_recovery,
            orphan_layers,
            last_seal,
        };
        let chronicle = Self {
            id,
            warden,
            epoch,
            coord,
            segment,
            layers,
            last_seal,
            health: Health::Live,
            _lock: lock,
        };
        Ok((chronicle, recovery))
    }

    /// Append one record: segment (fsync), then CAS.
    pub fn append(&mut self, stream: Stream, payload: Payload) -> Result<ChronicleHead, ChronicleError> {
        self.ready()?;
        let rec = self.next_record(stream, payload);
        self.commit(&rec)
    }

    /// Take a Seal: snapshot the layer bound to the Seal record's hash,
    /// then append and CAS the record.  On failure the snapshot is
    /// destroyed, unless the outcome is unknown (poisoned), in which case
    /// recovery decides.
    pub fn seal(
        &mut self,
        cut: StreamCut,
        verdict: Verdict,
        ledger_pos: Lsn,
        turn: TurnId,
    ) -> Result<Sealed, ChronicleError> {
        self.seal_checked(cut, verdict, ledger_pos, turn, || Ok(()))
    }

    /// Like [`Chronicle::seal`], with `check` run after the layer is frozen
    /// and before the Seal record is written.  If it fails, the layer is
    /// destroyed and there is no Seal — a frozen layer is a Seal only once
    /// its record is accepted.  Phase 1 uses this to refuse a Seal whose
    /// database moved after the harness said it was quiescent.
    pub fn seal_checked(
        &mut self,
        cut: StreamCut,
        verdict: Verdict,
        ledger_pos: Lsn,
        turn: TurnId,
        check: impl FnOnce() -> Result<(), String>,
    ) -> Result<Sealed, ChronicleError> {
        self.ready()?;
        let lsn = self.segment.tail().lsn.next();
        let rec = self.next_record(
            Stream::Ctl,
            Payload::Seal(SealRecord {
                parent: self.last_seal.map(|p| p.hash),
                cut,
                layer: LayerRef::new(lsn.get()),
                verdict,
                ledger_pos,
                turn,
            }),
        );
        let hash = rec.envelope.hash;
        self.layers.snapshot(lsn, hash).map_err(ChronicleError::Layer)?;
        if let Err(why) = check() {
            // Best effort: if this fails, the next recovery destroys the
            // orphan, whose record does not exist.
            let _ = self.layers.destroy(lsn);
            return Err(ChronicleError::CheckFailed(why));
        }
        match self.commit(&rec) {
            Ok(head) => {
                let seal = Position { lsn, hash };
                self.last_seal = Some(seal);
                Ok(Sealed { seal, head })
            }
            Err(e) => {
                if self.health != Health::Poisoned {
                    // Best effort: if this fails, the next recovery
                    // destroys the orphan.
                    let _ = self.layers.destroy(lsn);
                }
                Err(e)
            }
        }
    }

    /// The Chronicle's id.
    pub fn id(&self) -> ChronicleId {
        self.id
    }

    /// The epoch this Warden holds.
    pub fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// The local tail (equal to the anchored head while live).
    pub fn tail(&self) -> Position {
        self.segment.tail()
    }

    /// The last accepted Seal.
    pub fn last_seal(&self) -> Option<Position> {
        self.last_seal
    }

    /// The local segment, for reading.
    pub fn segment(&self) -> &Segment {
        &self.segment
    }

    /// The layer store.
    pub fn layers(&self) -> &L {
        &self.layers
    }

    /// True once ownership was lost.
    pub fn is_fenced(&self) -> bool {
        self.health == Health::Fenced
    }

    // ── internals ───────────────────────────────────────────────────

    fn ready(&self) -> Result<(), ChronicleError> {
        match self.health {
            Health::Live => Ok(()),
            Health::Fenced => Err(ChronicleError::Fenced),
            Health::Poisoned => Err(ChronicleError::Poisoned),
        }
    }

    fn next_record(&self, stream: Stream, payload: Payload) -> Record {
        let tail = self.segment.tail();
        Record::new(self.id, BranchId::TRUNK, self.epoch, stream, tail.lsn.next(), tail.hash, payload)
    }

    /// Segment append (fsync), then CAS; on refusal cut the frame off and
    /// fence; on coordinator failure poison.
    fn commit(&mut self, rec: &Record) -> Result<ChronicleHead, ChronicleError> {
        let before = self.segment.tail();
        self.segment.append(&rec.envelope, &rec.payload.canon_bytes())?;
        match self.coord.append(self.warden, &rec.envelope) {
            Ok(head) => Ok(head),
            // The CAS may have landed: keep the frame, let reopen decide.
            Err(e) if e.outcome_unknown() => {
                self.health = Health::Poisoned;
                Err(ChronicleError::Coord(e))
            }
            Err(e) => {
                self.health = Health::Fenced;
                if self.segment.truncate_to(before.lsn).is_err() {
                    // The frame is on disk but unaccepted; reopen cuts it.
                    self.health = Health::Poisoned;
                }
                Err(ChronicleError::Refused(e))
            }
        }
    }
}

/// Take an exclusive lock on `dir/LOCK`, held for the Chronicle's life.
fn lock_dir(dir: &Path) -> Result<File, ChronicleError> {
    let path = dir.join(LOCK_FILE);
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&path)
        .map_err(|e| ChronicleError::Segment(SegmentError::Io(e)))?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(std::fs::TryLockError::WouldBlock) => Err(ChronicleError::Locked(path)),
        Err(std::fs::TryLockError::Error(e)) => Err(ChronicleError::Segment(SegmentError::Io(e))),
    }
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coordinator::Coordinator;
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::rc::Rc;

    /// In-memory layers; clones share the same "dataset".
    #[derive(Clone, Default)]
    struct FakeLayers {
        snaps: Rc<RefCell<BTreeMap<Lsn, HashVal>>>,
        /// Take the snapshot, then report failure (a crash after it).
        fail_after_snapshot: Rc<RefCell<bool>>,
    }

    impl FakeLayers {
        fn snaps(&self) -> Vec<(Lsn, HashVal)> {
            self.snaps.borrow().iter().map(|(&l, &h)| (l, h)).collect()
        }
    }

    impl Layers for FakeLayers {
        fn snapshot(&mut self, lsn: Lsn, hash: HashVal) -> Result<(), LayerError> {
            let mut s = self.snaps.borrow_mut();
            if s.contains_key(&lsn) {
                return Err(format!("layer {} exists", lsn.get()).into());
            }
            s.insert(lsn, hash);
            if *self.fail_after_snapshot.borrow() {
                return Err("crash after snapshot".into());
            }
            Ok(())
        }
        fn list(&self) -> Result<Vec<(Lsn, HashVal)>, LayerError> {
            Ok(self.snaps())
        }
        fn destroy(&mut self, lsn: Lsn) -> Result<(), LayerError> {
            self.snaps.borrow_mut().remove(&lsn);
            Ok(())
        }
    }

    const A: WardenId = WardenId::new(1);
    const B: WardenId = WardenId::new(2);

    fn cid() -> ChronicleId {
        ChronicleId::from_bytes([5; 16])
    }

    fn raw(n: u8) -> Payload {
        Payload::Raw(vec![n; 8])
    }

    fn cut() -> StreamCut {
        StreamCut { fs: Lsn::new(0), db: Lsn::new(0), transcript: Lsn::new(0) }
    }

    struct Env {
        _root: tempfile::TempDir,
        coord: Arc<dyn Coord>,
        dir: PathBuf,
        layers: FakeLayers,
    }

    fn env() -> Env {
        let root = tempfile::tempdir().unwrap();
        let coord = Arc::new(Coordinator::open(root.path().join("coord.redb")).unwrap());
        let dir = root.path().join("vessel");
        std::fs::create_dir(&dir).unwrap();
        Env { _root: root, coord, dir, layers: FakeLayers::default() }
    }

    impl Env {
        fn create(&self) -> Chronicle<FakeLayers> {
            Chronicle::create(&self.dir, self.coord.clone(), cid(), A, self.layers.clone()).unwrap().0
        }
        fn open(&self, w: WardenId) -> (Chronicle<FakeLayers>, Recovery) {
            Chronicle::open(&self.dir, self.coord.clone(), cid(), w, self.layers.clone()).unwrap()
        }
    }

    fn seal<L: Layers>(c: &mut Chronicle<L>, turn: u64) -> Result<Sealed, ChronicleError> {
        c.seal(cut(), Verdict::Clean, Lsn::new(0), TurnId::new(turn))
    }

    // ── happy paths ─────────────────────────────────────────────────

    #[test]
    fn append_advances_local_and_anchored_head_together() {
        let e = env();
        let mut c = e.create();
        for n in 1..=3 {
            let h = c.append(Stream::Fs, raw(n)).unwrap();
            assert_eq!(h.lsn, Lsn::new(n as u64));
            assert_eq!(Position::from(h), c.tail());
            assert_eq!(e.coord.head(cid()).unwrap(), h);
        }
    }

    #[test]
    fn seal_binds_snapshot_to_accepted_record_and_chains_parents() {
        let e = env();
        let mut c = e.create();
        c.append(Stream::Fs, raw(1)).unwrap();
        let s1 = seal(&mut c, 1).unwrap();
        c.append(Stream::Fs, raw(2)).unwrap();
        let s2 = seal(&mut c, 2).unwrap();
        assert_eq!(e.layers.snaps(), vec![(s1.seal.lsn, s1.seal.hash), (s2.seal.lsn, s2.seal.hash)]);
        assert_eq!(c.last_seal(), Some(s2.seal));

        let frames = c.segment().frames().unwrap();
        let at = |lsn: Lsn| frames.iter().find(|f| f.envelope.lsn == lsn).unwrap();
        assert_eq!(at(s2.seal.lsn).envelope.hash, s2.seal.hash);
        assert_eq!(at(s2.seal.lsn).envelope.stream, Stream::Ctl);
        // Seal 2's parent is Seal 1: rebuild the expected record and compare.
        let expected = Record::new(
            cid(),
            BranchId::TRUNK,
            c.epoch(),
            Stream::Ctl,
            s2.seal.lsn,
            at(Lsn::new(s2.seal.lsn.get() - 1)).envelope.hash,
            Payload::Seal(SealRecord {
                parent: Some(s1.seal.hash),
                cut: cut(),
                layer: LayerRef::new(s2.seal.lsn.get()),
                verdict: Verdict::Clean,
                ledger_pos: Lsn::new(0),
                turn: TurnId::new(2),
            }),
        );
        assert_eq!(expected.envelope.hash, s2.seal.hash);
    }

    #[test]
    fn reopen_finds_the_last_seal_and_continues() {
        let e = env();
        let mut c = e.create();
        c.append(Stream::Fs, raw(1)).unwrap();
        let s = seal(&mut c, 1).unwrap();
        c.append(Stream::Fs, raw(2)).unwrap();
        let tail = c.tail();
        drop(c);

        let (mut c, r) = e.open(A);
        assert_eq!(r.last_seal, Some(s.seal));
        assert!(r.orphan_layers.is_empty());
        assert_eq!(r.segment, segment::Recovery::default());
        assert_eq!(c.tail(), tail);
        assert_eq!(c.epoch(), Epoch::new(3)); // create took 2, reopen 3
        c.append(Stream::Fs, raw(3)).unwrap();
    }

    // ── fencing ─────────────────────────────────────────────────────

    #[test]
    fn second_process_on_same_dir_is_locked_out() {
        let e = env();
        let _c = e.create();
        assert!(matches!(
            Chronicle::open(&e.dir, e.coord.clone(), cid(), A, e.layers.clone()),
            Err(ChronicleError::Locked(_))
        ));
    }

    /// A second incarnation elsewhere (a copy of the segment, as rebirth
    /// will fetch it) takes ownership: the first is refused, cuts its
    /// frame, is fenced, and takes no Seal.
    #[test]
    fn new_incarnation_fences_the_old_one() {
        let e = env();
        let mut a = e.create();
        a.append(Stream::Fs, raw(1)).unwrap();
        let a_seg_len = std::fs::metadata(a.segment().path()).unwrap().len();

        let dir_b = e.dir.with_file_name("vessel-b");
        std::fs::create_dir(&dir_b).unwrap();
        std::fs::copy(a.segment().path(), dir_b.join(SEGMENT_FILE)).unwrap();
        let layers_b = FakeLayers::default();
        let (mut b, _) =
            Chronicle::open(&dir_b, e.coord.clone(), cid(), B, layers_b.clone()).unwrap();

        assert!(matches!(a.append(Stream::Fs, raw(2)), Err(ChronicleError::Refused(_))));
        assert!(a.is_fenced());
        assert_eq!(std::fs::metadata(a.segment().path()).unwrap().len(), a_seg_len);
        assert!(matches!(seal(&mut a, 9), Err(ChronicleError::Fenced)));
        assert!(e.layers.snaps().is_empty());

        assert_eq!(b.append(Stream::Fs, raw(2)).unwrap().lsn, Lsn::new(2));
        seal(&mut b, 1).unwrap();
        assert_eq!(layers_b.snaps().len(), 1);
    }

    /// A Seal refused by the coordinator leaves neither a frame nor a
    /// snapshot.
    #[test]
    fn refused_seal_leaves_no_layer() {
        let e = env();
        let mut a = e.create();
        // Ownership moves away underneath A (an operator transfer).
        e.coord.transfer(cid(), B).unwrap();
        assert!(matches!(seal(&mut a, 1), Err(ChronicleError::Refused(_))));
        assert!(e.layers.snaps().is_empty());
        assert_eq!(a.tail(), Position::GENESIS);
    }

    // ── crash points ────────────────────────────────────────────────

    /// Crash after the snapshot, before the record is written: reopen
    /// destroys the orphan.
    #[test]
    fn crash_after_snapshot_before_append() {
        let e = env();
        let mut c = e.create();
        c.append(Stream::Fs, raw(1)).unwrap();
        *e.layers.fail_after_snapshot.borrow_mut() = true;
        assert!(matches!(seal(&mut c, 1), Err(ChronicleError::Layer(_))));
        assert_eq!(e.layers.snaps().len(), 1);
        drop(c);
        *e.layers.fail_after_snapshot.borrow_mut() = false;

        let (c, r) = e.open(A);
        assert_eq!(r.orphan_layers, vec![Lsn::new(2)]);
        assert!(e.layers.snaps().is_empty());
        assert_eq!(r.last_seal, None);
        assert_eq!(c.tail().lsn, Lsn::new(1));
    }

    /// Crash after the snapshot and the local fsync, before the CAS:
    /// reopen cuts the frame and destroys the orphan.
    #[test]
    fn crash_after_local_fsync_before_cas() {
        let e = env();
        let mut c = e.create();
        c.append(Stream::Fs, raw(1)).unwrap();
        let tail = c.tail();
        let epoch = c.epoch();
        let seg_path = c.segment().path().to_path_buf();
        drop(c);

        // Replay exactly what `seal` does, stopping before the CAS.
        let rec = Record::new(
            cid(),
            BranchId::TRUNK,
            epoch,
            Stream::Ctl,
            tail.lsn.next(),
            tail.hash,
            Payload::Seal(SealRecord {
                parent: None,
                cut: cut(),
                layer: LayerRef::new(tail.lsn.next().get()),
                verdict: Verdict::Clean,
                ledger_pos: Lsn::new(0),
                turn: TurnId::new(1),
            }),
        );
        let mut layers = e.layers.clone();
        layers.snapshot(rec.envelope.lsn, rec.envelope.hash).unwrap();
        let (mut seg, _) = Segment::open(&seg_path, e.coord.head(cid()).unwrap()).unwrap();
        seg.append(&rec.envelope, &rec.payload.canon_bytes()).unwrap();
        drop(seg);

        let (c, r) = e.open(A);
        assert_eq!(r.segment.unaccepted_frames, 1);
        assert_eq!(r.orphan_layers, vec![Lsn::new(2)]);
        assert!(e.layers.snaps().is_empty());
        assert_eq!(c.tail(), tail);
    }

    /// Crash after the CAS, before `seal` returns: the Seal stands.
    #[test]
    fn crash_after_cas_keeps_the_seal() {
        let e = env();
        let mut c = e.create();
        let s = seal(&mut c, 1).unwrap();
        drop(c); // as if the process died right after the CAS
        let (_c, r) = e.open(A);
        assert!(r.orphan_layers.is_empty());
        assert_eq!(r.last_seal, Some(s.seal));
        assert_eq!(e.layers.snaps(), vec![(s.seal.lsn, s.seal.hash)]);
    }

    /// A failed check after the snapshot leaves neither a layer nor a
    /// record, and the Chronicle stays live.
    #[test]
    fn failed_seal_check_leaves_nothing() {
        let e = env();
        let mut c = e.create();
        c.append(Stream::Fs, raw(1)).unwrap();
        let tail = c.tail();
        let layers = e.layers.clone();
        let r = c.seal_checked(cut(), Verdict::Clean, Lsn::new(0), TurnId::new(1), || {
            // The check runs with the layer already frozen.
            assert_eq!(layers.snaps().len(), 1);
            Err("wal moved".into())
        });
        assert!(matches!(r, Err(ChronicleError::CheckFailed(ref w)) if w == "wal moved"));
        assert!(e.layers.snaps().is_empty());
        assert_eq!(c.tail(), tail);
        assert!(!c.is_fenced());
        seal(&mut c, 2).unwrap();
    }

    /// A layer whose lsn is accepted but holds another record (a refused
    /// Seal's snapshot that survived, then a different record was accepted
    /// at that lsn) is an orphan too.
    #[test]
    fn layer_with_wrong_hash_at_accepted_lsn_is_orphan() {
        let e = env();
        let mut c = e.create();
        let mut layers = e.layers.clone();
        layers.snapshot(Lsn::new(1), HashVal::from_bytes([0xEE; 32])).unwrap();
        c.append(Stream::Fs, raw(1)).unwrap();
        drop(c);
        let (_c, r) = e.open(A);
        assert_eq!(r.orphan_layers, vec![Lsn::new(1)]);
        assert!(e.layers.snaps().is_empty());
    }

    #[test]
    fn missing_segment_with_accepted_records_is_refused() {
        let e = env();
        let mut c = e.create();
        c.append(Stream::Fs, raw(1)).unwrap();
        let seg = c.segment().path().to_path_buf();
        drop(c);
        std::fs::remove_file(seg).unwrap();
        assert!(matches!(
            Chronicle::open(&e.dir, e.coord.clone(), cid(), A, e.layers.clone()),
            Err(ChronicleError::MissingSegment { .. })
        ));
    }

    // ── unknown outcomes (remote coordinator) ───────────────────────

    /// Applies every request; when armed, reports the next append's
    /// answer as lost (as a connection dropping after the CAS).
    struct LoseAnswer {
        inner: Coordinator,
        lose_next: std::sync::atomic::AtomicBool,
    }

    impl Coord for LoseAnswer {
        fn register(&self, c: ChronicleId, h: WardenId) -> Result<ChronicleHead, CoordError> {
            self.inner.register(c, h)
        }
        fn append(&self, w: WardenId, e: &taso_core::envelope::Envelope) -> Result<ChronicleHead, CoordError> {
            let r = self.inner.append(w, e);
            if self.lose_next.swap(false, std::sync::atomic::Ordering::SeqCst) {
                return Err(CoordError::Unavailable(std::io::ErrorKind::ConnectionReset.into()));
            }
            r
        }
        fn transfer(&self, c: ChronicleId, h: WardenId) -> Result<Epoch, CoordError> {
            self.inner.transfer(c, h)
        }
        fn ownership(&self, c: ChronicleId) -> Result<taso_core::model::Ownership, CoordError> {
            self.inner.ownership(c)
        }
        fn head(&self, c: ChronicleId) -> Result<ChronicleHead, CoordError> {
            self.inner.head(c)
        }
    }

    /// The CAS landed but the answer was lost.  The Chronicle must keep
    /// the frame (it is accepted) and be poisoned, not fenced; reopen
    /// finds it accepted and carries on after it.
    #[test]
    fn lost_answer_after_cas_keeps_the_frame() {
        let root = tempfile::tempdir().unwrap();
        let coord = Arc::new(LoseAnswer {
            inner: Coordinator::open(root.path().join("coord.redb")).unwrap(),
            lose_next: false.into(),
        });
        let dir = root.path().join("vessel");
        std::fs::create_dir(&dir).unwrap();
        let layers = FakeLayers::default();
        let (mut c, _) = Chronicle::create(&dir, coord.clone(), cid(), A, layers.clone()).unwrap();
        c.append(Stream::Fs, raw(1)).unwrap();

        coord.lose_next.store(true, std::sync::atomic::Ordering::SeqCst);
        let err = c.append(Stream::Fs, raw(2)).unwrap_err();
        assert!(matches!(err, ChronicleError::Coord(CoordError::Unavailable(_))), "{err}");
        assert!(!c.is_fenced(), "an unknown outcome is not a refusal");
        assert_eq!(c.tail().lsn, Lsn::new(2), "the frame is kept");
        assert_eq!(coord.head(cid()).unwrap().lsn, Lsn::new(2), "the CAS did land");
        assert!(matches!(c.append(Stream::Fs, raw(3)), Err(ChronicleError::Poisoned)));
        assert!(matches!(seal(&mut c, 1), Err(ChronicleError::Poisoned)));
        assert!(layers.snaps().is_empty());
        drop(c);

        let (mut c, r) = Chronicle::open(&dir, coord.clone(), cid(), A, layers).unwrap();
        assert_eq!(r.segment.unaccepted_frames, 0);
        assert_eq!(c.tail().lsn, Lsn::new(2));
        assert_eq!(c.append(Stream::Fs, raw(3)).unwrap().lsn, Lsn::new(3));
    }

    fn socket_env() -> (tempfile::TempDir, PathBuf, PathBuf, crate::coordsrv::Server) {
        let root = tempfile::tempdir().unwrap();
        let db = root.path().join("coord.redb");
        let sock = root.path().join("coord.sock");
        let server = spawn_server(&sock, &db);
        (root, db, sock, server)
    }

    fn spawn_server(sock: &Path, db: &Path) -> crate::coordsrv::Server {
        crate::coordsrv::Server::spawn(sock, Arc::new(Coordinator::open(db).unwrap())).unwrap()
    }

    fn remote(sock: &Path) -> Arc<dyn Coord> {
        Arc::new(crate::coordsrv::RemoteCoord::with_timeout(sock, std::time::Duration::from_secs(5)))
    }

    /// The coordinator process goes away during an append: the Chronicle
    /// is poisoned with the frame kept and takes no Seal; after a restart,
    /// reopen finds the frame unaccepted, cuts it, and carries on.
    #[test]
    fn coordinator_gone_mid_append_poisons_then_recovers() {
        let (root, db, sock, server) = socket_env();
        let coord = remote(&sock);
        let dir = root.path().join("vessel");
        std::fs::create_dir(&dir).unwrap();
        let layers = FakeLayers::default();
        let (mut c, _) = Chronicle::create(&dir, coord.clone(), cid(), A, layers.clone()).unwrap();
        c.append(Stream::Fs, raw(1)).unwrap();

        server.stop();
        let err = c.append(Stream::Fs, raw(2)).unwrap_err();
        assert!(matches!(err, ChronicleError::Coord(CoordError::Unavailable(_))), "{err}");
        assert!(!c.is_fenced());
        assert_eq!(c.tail().lsn, Lsn::new(2), "the frame is kept until recovery decides");
        assert!(matches!(seal(&mut c, 1), Err(ChronicleError::Poisoned)));
        assert!(layers.snaps().is_empty());
        drop(c);

        let _server = spawn_server(&sock, &db);
        let (mut c, r) = Chronicle::open(&dir, coord, cid(), A, layers).unwrap();
        assert_eq!(r.segment.unaccepted_frames, 1);
        assert_eq!(c.tail().lsn, Lsn::new(1));
        assert_eq!(c.append(Stream::Fs, raw(2)).unwrap().lsn, Lsn::new(2));
        seal(&mut c, 1).unwrap();
    }

    /// Two incarnations, each with its own connection to one coordinator
    /// process (the P2 topology): the newer one fences the older.
    #[test]
    fn new_incarnation_fences_the_old_one_over_the_socket() {
        let (root, _db, sock, _server) = socket_env();
        let dir_a = root.path().join("vessel-a");
        let dir_b = root.path().join("vessel-b");
        std::fs::create_dir(&dir_a).unwrap();
        std::fs::create_dir(&dir_b).unwrap();
        let layers_a = FakeLayers::default();
        let (mut a, _) = Chronicle::create(&dir_a, remote(&sock), cid(), A, layers_a.clone()).unwrap();
        a.append(Stream::Fs, raw(1)).unwrap();
        let a_len = std::fs::metadata(a.segment().path()).unwrap().len();

        std::fs::copy(a.segment().path(), dir_b.join(SEGMENT_FILE)).unwrap();
        let (mut b, rb) = Chronicle::open(&dir_b, remote(&sock), cid(), B, FakeLayers::default()).unwrap();
        assert_eq!(rb.head.lsn, Lsn::new(1));

        assert!(matches!(a.append(Stream::Fs, raw(2)), Err(ChronicleError::Refused(_))));
        assert!(a.is_fenced());
        assert_eq!(std::fs::metadata(a.segment().path()).unwrap().len(), a_len);
        assert!(matches!(seal(&mut a, 1), Err(ChronicleError::Fenced)));
        assert!(layers_a.snaps().is_empty());
        assert_eq!(b.append(Stream::Fs, raw(2)).unwrap().lsn, Lsn::new(2));
    }

    // ── on a real pool ──────────────────────────────────────────────

    mod node {
        use super::*;
        use std::process::Command;

        struct Scratch {
            ds: Dataset,
            mountpoint: PathBuf,
        }

        fn zfs_cmd(args: &[&str]) -> String {
            let out = Command::new("zfs").args(args).output().expect("run zfs");
            assert!(
                out.status.success(),
                "zfs {} failed: {}",
                args.join(" "),
                String::from_utf8_lossy(&out.stderr),
            );
            String::from_utf8_lossy(&out.stdout).into_owned()
        }

        impl Scratch {
            fn new(test: &str) -> Self {
                let base = std::env::var("TASO_ZFS_DATASET")
                    .expect("set TASO_ZFS_DATASET to a dataset these tests may use");
                let name = format!("{base}/c-{test}-{}", std::process::id());
                zfs_cmd(&["create", &name]);
                let mountpoint = PathBuf::from(
                    zfs_cmd(&["get", "-H", "-o", "value", "mountpoint", &name]).trim(),
                );
                Self { ds: Dataset::new(&name).unwrap(), mountpoint }
            }
        }

        impl Drop for Scratch {
            fn drop(&mut self) {
                let _ = Command::new("zfs").args(["destroy", "-r", self.ds.as_str()]).status();
            }
        }

        #[test]
        #[ignore = "needs a ZFS pool: set TASO_ZFS_DATASET"]
        fn seal_and_recover_on_zfs() {
            let s = Scratch::new("seal");
            let root = tempfile::tempdir().unwrap();
            let coord = Arc::new(Coordinator::open(root.path().join("coord.redb")).unwrap());
            let layers = ZfsLayers::new(Zfs::cli(), s.ds.clone());

            let (mut c, _) =
                Chronicle::create(root.path(), coord.clone(), cid(), A, layers).unwrap();
            std::fs::write(s.mountpoint.join("a.txt"), b"one").unwrap();
            c.append(Stream::Fs, raw(1)).unwrap();
            let s1 = seal(&mut c, 1).unwrap();
            std::fs::write(s.mountpoint.join("a.txt"), b"two").unwrap();
            c.append(Stream::Fs, raw(2)).unwrap();
            let s2 = seal(&mut c, 2).unwrap();
            assert_eq!(
                c.layers().list().unwrap(),
                vec![(s1.seal.lsn, s1.seal.hash), (s2.seal.lsn, s2.seal.hash)]
            );
            // The first Seal froze the first contents.
            let snap = s.mountpoint.join(format!(".zfs/snapshot/taso-seal-{:020}/a.txt", s1.seal.lsn.get()));
            assert_eq!(std::fs::read(snap).unwrap(), b"one");
            let tail = c.tail();
            drop(c);

            // An orphan past the head, as a crash after `zfs snapshot`.
            Zfs::cli()
                .snapshot(&s.ds, tail.lsn.next(), HashVal::from_bytes([0xAB; 32]))
                .unwrap();

            let layers = ZfsLayers::new(Zfs::cli(), s.ds.clone());
            let (c, r) = Chronicle::open(root.path(), coord, cid(), A, layers).unwrap();
            assert_eq!(r.orphan_layers, vec![tail.lsn.next()]);
            assert_eq!(r.last_seal, Some(s2.seal));
            assert_eq!(c.layers().list().unwrap().len(), 2);
            eprintln!("recovered: {r:?}");
        }
    }
}
