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
//! segment against the anchored head; then destroys orphan snapshots and
//! reports accepted Seals whose snapshot is missing
//! ([`Recovery::missing_layers`]).  Those stay in the log, and `last_seal`
//! still comes from the records, but nothing can build on their layer.
//! Who may call `open` is decided above this module (rebirth, P2).
//!
//! On one node, a lock file in the Chronicle's directory keeps two
//! processes off the same segment: without it, a fenced writer's frame
//! (and its truncation) could land on top of the new holder's accepted
//! frames before the CAS refuses it.  A lock that looks held is retried
//! briefly before it counts, because a process spawned at the moment the
//! previous holder closed may still hold a copy of its file (see
//! `lock_dir`).
//!
//! Known gap: an accepted Seal whose snapshot is missing is not detected
//! yet.  That needs the record kind, i.e. the payload decoder; with
//! snapshot-first it can only happen if someone destroys a snapshot by
//! hand.
//!
//! Normative references: v0.4 §2.1, §5.2, §8.2–8.7; v1.0 §1 (P1), §3.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use taso_core::canon::Canonical;
use taso_core::envelope::{BranchId, ChronicleHead, ChronicleId, Epoch, HashVal, Lsn, Stream, Envelope};
use taso_core::model::WardenId;
use taso_core::record::{GapRecord, LayerRef, Payload, Record, SealRecord, StreamCut, TurnId, Verdict};

use crate::coordinator::{Coord, CoordError};
use crate::segment::{self, Frame, Position, Segment, SegmentError};
use crate::zfs::{Cli, Dataset, Runner, Zfs};

/// File name of the first segment of a Chronicle (base lsn 0).
const SEGMENT_FILE: &str = "seg-00000000000000000000";

/// A segment past this many bytes is closed, and the next append starts
/// a new one at the tail ([`Chronicle::set_roll_at`] changes it).
pub const SEGMENT_MAX: u64 = 64 << 20;

/// Prefix of every segment file name: `seg-<base lsn, 20 digits>`.
const SEGMENT_PREFIX: &str = "seg-";

/// The file name of the segment whose first frame follows `base`.
fn segment_name(base: Lsn) -> String {
    format!("{SEGMENT_PREFIX}{:020}", base.get())
}

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
    /// Make the current state the layer at `lsn` again, which must be
    /// bound to `hash`: everything written after it is discarded.  Must
    /// refuse, changing nothing, if a later layer exists; never destroys
    /// one.  A store that cannot roll back says so (the default).
    fn rollback(&mut self, lsn: Lsn, hash: HashVal) -> Result<(), LayerError> {
        let _ = hash;
        Err(format!("this layer store cannot roll back (to layer {})", lsn.get()).into())
    }
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

    fn rollback(&mut self, lsn: Lsn, hash: HashVal) -> Result<(), LayerError> {
        self.zfs.rollback(&self.dataset, lsn, hash)?;
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
    /// A file in the Chronicle directory is named like a segment but is not
    /// `seg-<20 digits>`.
    BadSegmentName(String),
    /// Two segment files do not join: the later one neither starts where
    /// the earlier one ends nor opens with a Gap record naming exactly the
    /// lost span; or the first one does not start at genesis.
    SegmentsDisagree {
        /// The later segment's base.
        at: Lsn,
        /// What is wrong.
        why: &'static str,
    },
    /// [`restore_log`] found the directory already there.
    StateExists(PathBuf),
    /// A continuation segment exists but its Gap record was never accepted
    /// (a takeover was interrupted).  [`Chronicle::open_after_gap`]
    /// finishes it; a plain open does not.
    GapPending {
        /// The last record kept before the gap.
        kept: Lsn,
        /// The anchored head the continuation starts at.
        head: Lsn,
    },
    /// A local record's payload does not decode.
    Decode {
        /// The record.
        lsn: Lsn,
        /// Why.
        error: taso_core::decode::DecodeError,
    },
    /// A Checkpoint needs the Lineage record, and this log has none.
    NoLineage,
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
            Self::BadSegmentName(n) => write!(f, "{n} is not a segment file name"),
            Self::SegmentsDisagree { at, why } => {
                write!(f, "the segment at lsn {} does not join the one before: {why}", at.get())
            }
            Self::StateExists(p) => write!(f, "{} already exists", p.display()),
            Self::Decode { lsn, error } => write!(f, "record at lsn {} does not decode: {error}", lsn.get()),
            Self::NoLineage => write!(f, "the log has no Lineage record to checkpoint"),
            Self::GapPending { kept, head } => write!(
                f,
                "a takeover after a gap ({}..={}) was interrupted; open_after_gap finishes it",
                kept.get() + 1,
                head.get()
            ),
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
    /// The last accepted Seal record, if any.
    pub last_seal: Option<Position>,
    /// Accepted Seal records whose layer is not there: lost by hand, or
    /// never received after a rebirth (their `fs` section was not
    /// shipped).  Such a Seal stays in the log but cannot be forked,
    /// succeeded from or published.
    pub missing_layers: Vec<Position>,
    /// If this open continued past a gap: the last record kept and the
    /// head the Chronicle continued from (records in between are lost).
    pub gap: Option<(Position, Position)>,
}

/// What [`Chronicle::prune`] did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Pruned {
    /// The Checkpoint record written, if anything was pruned.
    pub checkpoint: Option<Position>,
    /// The segment files removed, oldest first.
    pub removed: Vec<PathBuf>,
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
    /// Older segment files, in order; read-only.
    closed: Vec<Segment>,
    /// The newest segment: the only one written.
    segment: Segment,
    layers: L,
    last_seal: Option<Position>,
    /// Accepted Seals whose layer was not there at open.
    missing_layers: HashSet<Lsn>,
    health: Health,
    /// Roll to a new segment once the current one has this many bytes.
    roll_at: u64,
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
    /// fences any previous holder); open the segment files, the newest one
    /// recovered against the anchored head and every older one read whole
    /// and verified (creating the first if the Chronicle has no records
    /// yet); check that the files join; destroy orphan layers.
    ///
    /// A takeover after a gap that was interrupted is refused
    /// ([`ChronicleError::GapPending`]); [`Chronicle::open_after_gap`]
    /// finishes it.
    pub fn open(
        dir: impl AsRef<Path>,
        coord: Arc<dyn Coord>,
        id: ChronicleId,
        warden: WardenId,
        layers: L,
    ) -> Result<(Self, Recovery), ChronicleError> {
        Self::open_inner(dir.as_ref(), coord, id, warden, layers, false)
    }

    /// Take ownership of a Chronicle whose local log may end before the
    /// anchored head (rebirth on another node: the log was rebuilt from the
    /// shipped packs up to the shipped anchor, and the records after it
    /// are lost).
    ///
    /// If the newest local segment ends at the head, this is [`Chronicle::open`].
    /// If it ends before, a new segment is started at the head and a
    /// [`GapRecord`] is appended as its first
    /// record, accepted by the coordinator like any record: the lost
    /// records keep their place in the chain, and history continues from
    /// the head.  Crash-resumable: an interrupted takeover is finished.
    pub fn open_after_gap(
        dir: impl AsRef<Path>,
        coord: Arc<dyn Coord>,
        id: ChronicleId,
        warden: WardenId,
        layers: L,
    ) -> Result<(Self, Recovery), ChronicleError> {
        Self::open_inner(dir.as_ref(), coord, id, warden, layers, true)
    }

    fn open_inner(
        dir: &Path,
        coord: Arc<dyn Coord>,
        id: ChronicleId,
        warden: WardenId,
        layers: L,
        continue_gap: bool,
    ) -> Result<(Self, Recovery), ChronicleError> {
        let lock = lock_dir(dir)?;

        let epoch = coord.transfer(id, warden).map_err(ChronicleError::Coord)?;
        let head = coord.head(id).map_err(ChronicleError::Coord)?;

        let files = list_segments(dir)?;
        let (closed, segment, seg_recovery) = match files.split_last() {
            None if head.lsn == Lsn::new(0) => {
                let seg = Segment::create(dir.join(SEGMENT_FILE), id, Position::GENESIS)?;
                (Vec::new(), seg, segment::Recovery::default())
            }
            None => return Err(ChronicleError::MissingSegment { anchored: head.lsn }),
            Some((last, older)) => {
                let mut closed = older.iter().map(Segment::open_closed).collect::<Result<Vec<_>, _>>()?;
                let local = Segment::peek_tail(last)?;
                if continue_gap && local.lsn < head.lsn {
                    // The head's records are not here.  Cut any torn tail,
                    // close this file, and start the continuation at the head.
                    let at = ChronicleHead { lsn: local.lsn, hash: local.hash, epoch };
                    let (_, rec) = Segment::open(last, at)?;
                    closed.push(Segment::open_closed(last)?);
                    let seg = Segment::create(dir.join(segment_name(head.lsn)), id, Position::from(head))?;
                    (closed, seg, rec)
                } else {
                    let (seg, rec) = Segment::open(last, head)?;
                    (closed, seg, rec)
                }
            }
        };
        for seg in closed.iter().chain(std::iter::once(&segment)) {
            if seg.chronicle() != id {
                return Err(ChronicleError::SegmentsDisagree { at: seg.base().lsn, why: "another Chronicle's segment" });
            }
        }
        // Older segments may have been pruned: then the first one starts
        // after genesis, at or below the shipped anchor (only shipped
        // records are pruned), and a Checkpoint in what is left stands for
        // what is gone.
        let first_base = closed.first().unwrap_or(&segment).base();
        let pruned = first_base != Position::GENESIS;
        if pruned {
            let shipped = coord.shipped(id).map_err(ChronicleError::Coord)?;
            if first_base.lsn > shipped.lsn {
                return Err(ChronicleError::SegmentsDisagree {
                    at: first_base.lsn,
                    why: "the first segment starts after genesis, past what was shipped",
                });
            }
            let has_checkpoint = closed.iter().chain(std::iter::once(&segment)).try_fold(false, |found, seg| {
                Ok::<bool, ChronicleError>(found || seg.frames()?.iter().any(is_checkpoint))
            })?;
            if !has_checkpoint {
                return Err(ChronicleError::SegmentsDisagree {
                    at: first_base.lsn,
                    why: "the first segment starts after genesis and no Checkpoint stands for what is gone",
                });
            }
        }
        let pending = check_joints(&closed, &segment, pruned)?;

        let mut chronicle = Self {
            id,
            warden,
            epoch,
            coord,
            closed,
            segment,
            layers,
            last_seal: None,
            missing_layers: HashSet::new(),
            health: Health::Live,
            roll_at: SEGMENT_MAX,
            _lock: lock,
        };
        let mut gap = None;
        if let Some(kept) = pending {
            let resumes = chronicle.segment.base();
            if !continue_gap {
                return Err(ChronicleError::GapPending { kept: kept.lsn, head: resumes.lsn });
            }
            // Only what was shipped may be kept: rebirth rebuilds the log
            // from the packs up to the shipped anchor, which the fenced
            // previous holder can no longer move.
            if chronicle.coord.shipped(id).map_err(ChronicleError::Coord)? != kept {
                return Err(ChronicleError::SegmentsDisagree {
                    at: resumes.lsn,
                    why: "the log kept before the gap does not end at the shipped anchor",
                });
            }
            chronicle.append(
                Stream::Ctl,
                Payload::Gap(GapRecord { kept: kept.lsn, kept_hash: kept.hash, resumes: resumes.lsn, resumes_hash: resumes.hash }),
            )?;
            gap = Some((kept, resumes));
        }

        // Accepted Seal records, in lsn order, across every local segment;
        // if older segments were pruned, the last Seal before the newest
        // Checkpoint comes from it.
        let frames = chronicle.frames()?;
        let local_from = frames.first().map_or(Lsn::new(1), |f| f.envelope.lsn);
        let mut seals: Vec<Position> = frames
            .iter()
            .filter(|f| f.envelope.stream == Stream::Ctl && matches!(Payload::decode(&f.payload), Ok(Payload::Seal(_))))
            .map(|f| Position { lsn: f.envelope.lsn, hash: f.envelope.hash })
            .collect();
        let summary =
            crate::summary::Summary::of(&frames).map_err(|(lsn, error)| ChronicleError::Decode { lsn, error })?;
        if let Some(cs) = summary.seal {
            if !seals.iter().any(|p| p.lsn == cs.lsn) {
                seals.insert(0, Position { lsn: cs.lsn, hash: cs.hash });
            }
        }
        let by_lsn: HashMap<Lsn, HashVal> = seals.iter().map(|p| (p.lsn, p.hash)).collect();

        let mut orphan_layers = Vec::new();
        let mut present = HashSet::new();
        // A layer is a Seal's iff the accepted Seal record at its lsn has
        // its hash.  Past the head there is no accepted record, so that
        // case is covered too.
        for (lsn, hash) in chronicle.layers.list().map_err(ChronicleError::Layer)? {
            if by_lsn.get(&lsn) == Some(&hash) {
                present.insert(lsn);
            } else if lsn < local_from {
                // Its record was pruned with its segment; it was judged
                // when it was taken.  Kept, not judged again.
            } else {
                chronicle.layers.destroy(lsn).map_err(ChronicleError::Layer)?;
                orphan_layers.push(lsn);
            }
        }
        // The other way round: a Seal record whose layer is not there.
        let missing_layers: Vec<Position> = seals.iter().filter(|p| !present.contains(&p.lsn)).copied().collect();
        let last_seal = seals.last().copied();
        chronicle.last_seal = last_seal;
        chronicle.missing_layers = missing_layers.iter().map(|p| p.lsn).collect();
        let head = chronicle.coord.head(id).map_err(ChronicleError::Coord)?;
        let recovery =
            Recovery { epoch, head, segment: seg_recovery, orphan_layers, last_seal, missing_layers, gap };
        Ok((chronicle, recovery))
    }

    /// Append one record: segment (fsync), then CAS.
    pub fn append(&mut self, stream: Stream, payload: Payload) -> Result<ChronicleHead, ChronicleError> {
        self.ready()?;
        let rec = self.next_record(stream, payload);
        self.commit(&rec)
    }

    /// Append consecutive records together: one segment write and fsync,
    /// one CAS ([`Coord::append_batch`]).  All are accepted or none: a
    /// refusal cuts them all and fences, an unknown outcome poisons.
    pub fn append_batch(&mut self, records: Vec<(Stream, Payload)>) -> Result<ChronicleHead, ChronicleError> {
        self.ready()?;
        let mut tail = self.segment.tail();
        let recs: Vec<Record> = records
            .into_iter()
            .map(|(stream, payload)| {
                let r = Record::new(self.id, BranchId::TRUNK, self.epoch, stream, tail.lsn.next(), tail.hash, payload);
                tail = Position { lsn: r.envelope.lsn, hash: r.envelope.hash };
                r
            })
            .collect();
        if recs.is_empty() {
            return self.coord.head(self.id).map_err(ChronicleError::Coord);
        }
        self.commit_all(&recs)
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
        let _total = crate::timing::span("seal.total");
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
        let snap = crate::timing::span("seal.snapshot");
        self.layers.snapshot(lsn, hash).map_err(ChronicleError::Layer)?;
        drop(snap);
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

    /// Whether the accepted Seal at `seal` had no layer when this
    /// Chronicle was opened (see [`Recovery::missing_layers`]).
    pub fn layer_missing(&self, seal: Lsn) -> bool {
        self.missing_layers.contains(&seal)
    }

    /// Roll the state back to the newest Seal whose layer is here,
    /// discarding everything written after it (a restart resumes from a
    /// Seal, as a rebirth does).  Returns that Seal, or `None` if no Seal
    /// has a layer here (nothing is touched).
    ///
    /// The target is normally the last Seal.  If its layer is missing
    /// ([`Self::layer_missing`]) it is the newest Seal before it that has
    /// one; the caller sees which from the returned position.  After open
    /// every layer left is a Seal's (orphans are destroyed), so a layer
    /// past the last Seal is an inconsistency and refused, as is a fenced
    /// or poisoned Chronicle.  Nothing is appended: the log is not state.
    pub fn rollback_to_last_seal(&mut self) -> Result<Option<Position>, ChronicleError> {
        self.ready()?;
        let Some(last) = self.last_seal else {
            return Ok(None);
        };
        let layers = self.layers.list().map_err(ChronicleError::Layer)?;
        let Some(&(lsn, hash)) = layers.last() else {
            return Ok(None);
        };
        if lsn > last.lsn {
            return Err(ChronicleError::Layer(
                format!("layer {} is past the last Seal {}: not rolling back", lsn.get(), last.lsn.get()).into(),
            ));
        }
        if lsn == last.lsn && hash != last.hash {
            return Err(ChronicleError::Layer(
                format!("layer {} is not bound to the last Seal's record", lsn.get()).into(),
            ));
        }
        self.layers.rollback(lsn, hash).map_err(ChronicleError::Layer)?;
        Ok(Some(Position { lsn, hash }))
    }

    /// The newest local segment: the one being written.
    pub fn segment(&self) -> &Segment {
        &self.segment
    }

    /// The coordinator this Chronicle commits through.
    pub(crate) fn coord(&self) -> &Arc<dyn Coord> {
        &self.coord
    }

    /// The Warden holding it.
    pub(crate) fn warden(&self) -> WardenId {
        self.warden
    }

    /// The local frame at `lsn`, if a local segment holds it (one read).
    pub fn frame(&self, lsn: Lsn) -> Result<Option<Frame>, SegmentError> {
        match self.segments().into_iter().rev().find(|s| s.base().lsn < lsn && lsn <= s.tail().lsn) {
            Some(s) => s.frame(lsn),
            None => Ok(None),
        }
    }

    /// Every local segment, oldest first; the last is the one written.
    pub fn segments(&self) -> Vec<&Segment> {
        self.closed.iter().chain(std::iter::once(&self.segment)).collect()
    }

    /// Every local record, oldest first, across all segment files.  After
    /// a gap the records jump from the kept lsn to the Gap record.
    pub fn frames(&self) -> Result<Vec<Frame>, SegmentError> {
        let mut out = Vec::new();
        for seg in self.closed.iter().chain(std::iter::once(&self.segment)) {
            out.extend(seg.frames()?);
        }
        Ok(out)
    }

    /// The layer store.
    pub fn layers(&self) -> &L {
        &self.layers
    }

    /// Remove the oldest local segment files that are no longer needed
    /// here, keeping the newest `keep_closed` closed ones (decision 1,
    /// 2026-10-16).
    ///
    /// A closed segment may go only when every record in it is at or
    /// below the shipped anchor: it is in the store, and a rebirth reads it
    /// from there.  Before any file goes, a Checkpoint record is appended
    /// and accepted: it carries what the readers need from the records
    /// before it ([`crate::summary`]), so they read from it instead.  Files
    /// are removed oldest first, so what is left is always a contiguous
    /// suffix of the log, which [`Chronicle::open`] accepts.  A crash
    /// anywhere leaves either nothing removed or a suffix with its
    /// Checkpoint.  Nothing to remove: nothing is written.
    pub fn prune(&mut self, keep_closed: usize) -> Result<Pruned, ChronicleError> {
        self.ready()?;
        if self.closed.len() <= keep_closed {
            return Ok(Pruned::default());
        }
        let shipped = self.coord.shipped(self.id).map_err(ChronicleError::Coord)?;
        let removable = |closed: &[Segment]| {
            closed[..closed.len().saturating_sub(keep_closed)].iter().take_while(|seg| seg.tail().lsn <= shipped.lsn).count()
        };
        if removable(&self.closed) == 0 {
            return Ok(Pruned::default());
        }
        let summary = crate::summary::Summary::of(&self.frames()?)
            .map_err(|(lsn, error)| ChronicleError::Decode { lsn, error })?;
        let checkpoint = summary.checkpoint().ok_or(ChronicleError::NoLineage)?;
        let head = self.append(Stream::Ctl, Payload::Checkpoint(Box::new(checkpoint)))?;
        // Counted again: the Checkpoint's own append may have rolled.
        let n = removable(&self.closed);
        let mut removed = Vec::with_capacity(n);
        for _ in 0..n {
            let path = self.closed[0].path().to_path_buf();
            std::fs::remove_file(&path).map_err(|e| ChronicleError::Segment(SegmentError::Io(e)))?;
            self.closed.remove(0);
            removed.push(path);
        }
        if let Some(dir) = removed.last().and_then(|p| p.parent()) {
            File::open(dir).and_then(|d| d.sync_all()).map_err(|e| ChronicleError::Segment(SegmentError::Io(e)))?;
        }
        Ok(Pruned { checkpoint: Some(Position { lsn: head.lsn, hash: head.hash }), removed })
    }

    /// Roll to a new segment file once the current one reaches `bytes`
    /// (default [`SEGMENT_MAX`]).
    pub fn set_roll_at(&mut self, bytes: u64) {
        self.roll_at = bytes.max(1);
    }

    /// True once ownership was lost.
    pub fn is_fenced(&self) -> bool {
        self.health == Health::Fenced
    }

    // ── internals ───────────────────────────────────────────────────

    /// Close a full segment and start the next at its tail.  Only called
    /// while live, so every frame in the old file is accepted: it opens
    /// later as a complete closed segment, and the new one joins it end to
    /// start.  A crash right after the new file is created leaves an empty
    /// newest segment based at the head, which opens as usual.
    fn roll_if_full(&mut self) -> Result<(), ChronicleError> {
        if self.segment.is_empty() || self.segment.bytes() < self.roll_at {
            return Ok(());
        }
        let tail = self.segment.tail();
        let dir = self.segment.path().parent().map(Path::to_path_buf).unwrap_or_default();
        let next = Segment::create(dir.join(segment_name(tail.lsn)), self.id, tail)?;
        let old = std::mem::replace(&mut self.segment, next);
        self.closed.push(old);
        Ok(())
    }

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
        self.commit_all(std::slice::from_ref(rec))
    }

    /// [`Chronicle::commit`] for consecutive records: one segment write and
    /// fsync, one CAS for all of them.  On refusal every one is cut.
    fn commit_all(&mut self, recs: &[Record]) -> Result<ChronicleHead, ChronicleError> {
        let _t = crate::timing::span("append.total");
        self.roll_if_full()?;
        let before = self.segment.tail();
        let payloads: Vec<Vec<u8>> = recs.iter().map(|r| r.payload.canon_bytes()).collect();
        let frames: Vec<(&Envelope, &[u8])> =
            recs.iter().zip(&payloads).map(|(r, p)| (&r.envelope, p.as_slice())).collect();
        self.segment.append_batch(&frames)?;
        let envelopes: Vec<Envelope> = recs.iter().map(|r| r.envelope).collect();
        let cas = crate::timing::span("append.cas");
        let accepted = if envelopes.len() == 1 {
            self.coord.append(self.warden, &envelopes[0])
        } else {
            self.coord.append_batch(self.warden, &envelopes)
        };
        drop(cas);
        match accepted {
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

/// How long [`lock_dir`] keeps retrying a lock that looks held.
const LOCK_WAIT: Duration = Duration::from_millis(500);

/// Take an exclusive lock on `dir/LOCK`, held for the Chronicle's life.
///
/// The lock (`flock`) belongs to the open file, not the process.  When
/// any thread spawns a process (`zfs`, `runc`), the child holds copies of
/// every open file from the fork until it execs; all of them are
/// close-on-exec, so that hold ends within microseconds to milliseconds.
/// A lock dropped in that window still looks held, and a Vessel reopened
/// right after closing would be refused although nobody owns it.  So a
/// held lock is retried with short sleeps for up to [`LOCK_WAIT`] before
/// it counts as [`ChronicleError::Locked`].  A real second holder is
/// still refused, only not at once.
fn lock_dir(dir: &Path) -> Result<File, ChronicleError> {
    let path = dir.join(LOCK_FILE);
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&path)
        .map_err(|e| ChronicleError::Segment(SegmentError::Io(e)))?;
    let start = Instant::now();
    let mut pause = Duration::from_millis(1);
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(file),
            Err(std::fs::TryLockError::WouldBlock) if start.elapsed() < LOCK_WAIT => {
                std::thread::sleep(pause);
                pause = (pause * 2).min(Duration::from_millis(20));
            }
            Err(std::fs::TryLockError::WouldBlock) => return Err(ChronicleError::Locked(path)),
            Err(std::fs::TryLockError::Error(e)) => {
                return Err(ChronicleError::Segment(SegmentError::Io(e)))
            }
        }
    }
}

/// Every valid frame in the Chronicle directory `dir`, oldest first,
/// read without writing anything and without the coordinator: no file is
/// opened for writing, a torn tail is ignored rather than cut, and
/// records past the anchored head are included.  For inspection (the gate
/// harness reads both nodes' logs this way); the joints and the chain are
/// for the caller to judge.
pub fn read_log(dir: &Path) -> Result<Vec<Frame>, ChronicleError> {
    let mut frames = Vec::new();
    for path in list_segments(dir)? {
        frames.extend(Segment::open_read_only(&path)?.frames()?);
    }
    Ok(frames)
}

/// Write a Chronicle's log into the new directory `dir` from `frames`:
/// oldest first, from genesis, jumping only at Gap records, as
/// [`crate::pack::Packs::chain`] returns them (rebirth, v1.0 §1 P2).
///
/// The files are what a Warden would have written: `seg-0` from genesis,
/// and at every jump a new file based at the Gap's `resumes` (the lsn
/// before it and its `prev`), so [`Chronicle::open_after_gap`] checks the
/// joints exactly as on any node.  Nothing here is trusted: the open
/// re-verifies every frame and the joints.
///
/// Written into `<dir>.restore` first (removed if left from a crash) and
/// renamed into place, so `dir` either does not exist or is complete.
/// Refuses if `dir` exists.
pub fn restore_log(dir: &Path, id: ChronicleId, frames: &[Frame]) -> Result<(), ChronicleError> {
    let io = |e| ChronicleError::Segment(SegmentError::Io(e));
    if dir.exists() {
        return Err(ChronicleError::StateExists(dir.to_path_buf()));
    }
    let mut tmp = dir.as_os_str().to_owned();
    tmp.push(".restore");
    let tmp = PathBuf::from(tmp);
    if tmp.exists() {
        std::fs::remove_dir_all(&tmp).map_err(io)?;
    }
    std::fs::create_dir_all(&tmp).map_err(io)?;
    let mut seg = Segment::create(tmp.join(SEGMENT_FILE), id, Position::GENESIS)?;
    let mut run: Vec<&Frame> = Vec::new();
    let flush = |seg: &mut Segment, run: &mut Vec<&Frame>| -> Result<(), ChronicleError> {
        for chunk in run.chunks(1024) {
            let batch: Vec<(&Envelope, &[u8])> = chunk.iter().map(|f| (&f.envelope, f.payload.as_slice())).collect();
            seg.append_batch(&batch)?;
        }
        run.clear();
        Ok(())
    };
    let mut tail = Position::GENESIS;
    for f in frames {
        if f.envelope.lsn != tail.lsn.next() {
            // A Gap record: the next file starts where it resumes.
            flush(&mut seg, &mut run)?;
            let base = Position { lsn: Lsn::new(f.envelope.lsn.get().saturating_sub(1)), hash: f.envelope.prev };
            seg = Segment::create(tmp.join(segment_name(base.lsn)), id, base)?;
        }
        run.push(f);
        tail = Position { lsn: f.envelope.lsn, hash: f.envelope.hash };
    }
    flush(&mut seg, &mut run)?;
    drop(seg);
    std::fs::File::open(&tmp).and_then(|d| d.sync_all()).map_err(io)?;
    std::fs::rename(&tmp, dir).map_err(io)?;
    if let Some(parent) = dir.parent() {
        std::fs::File::open(parent).and_then(|d| d.sync_all()).map_err(io)?;
    }
    Ok(())
}

/// The segment files in `dir`, ordered by base lsn.  Any other file whose
/// name starts with `seg-` is refused rather than skipped.
fn list_segments(dir: &Path) -> Result<Vec<PathBuf>, ChronicleError> {
    let io = |e| ChronicleError::Segment(SegmentError::Io(e));
    let mut found = Vec::new();
    for entry in std::fs::read_dir(dir).map_err(io)? {
        let name = entry.map_err(io)?.file_name();
        let Some(name) = name.to_str().map(str::to_owned) else { continue };
        let Some(digits) = name.strip_prefix(SEGMENT_PREFIX) else { continue };
        let base = (digits.len() == 20 && digits.bytes().all(|b| b.is_ascii_digit()))
            .then(|| digits.parse::<u64>().ok())
            .flatten()
            .ok_or_else(|| ChronicleError::BadSegmentName(name.clone()))?;
        found.push((base, dir.join(&name)));
    }
    found.sort();
    Ok(found.into_iter().map(|(_, p)| p).collect())
}

/// Whether a frame is a Checkpoint record.
fn is_checkpoint(f: &Frame) -> bool {
    f.envelope.stream == Stream::Ctl && matches!(Payload::decode(&f.payload), Ok(Payload::Checkpoint(_)))
}

/// Check that the segments form one chain.  The first starts at genesis
/// (or, `pruned`, wherever the oldest kept segment starts: the caller
/// checked that a Checkpoint stands for what is gone);
/// each later one either starts where the one before ends, or starts
/// further on (at the anchored head of a takeover after a gap) and opens
/// with a Gap record naming exactly both ends.
///
/// Returns the kept position if the newest segment is such a continuation
/// whose Gap record is not written yet.
fn check_joints(closed: &[Segment], newest: &Segment, pruned: bool) -> Result<Option<Position>, ChronicleError> {
    let disagree = |at: Lsn, why| ChronicleError::SegmentsDisagree { at, why };
    let first = closed.first().unwrap_or(newest);
    if first.base() != Position::GENESIS && !pruned {
        return Err(disagree(first.base().lsn, "the first segment does not start at genesis"));
    }
    let mut pending = None;
    let all: Vec<&Segment> = closed.iter().chain(std::iter::once(newest)).collect();
    for pair in all.windows(2) {
        let (prev, next) = (pair[0], pair[1]);
        let (kept, resumes) = (prev.tail(), next.base());
        if resumes == kept {
            continue;
        }
        if resumes.lsn <= kept.lsn {
            return Err(disagree(resumes.lsn, "it starts inside the one before"));
        }
        let frames = next.frames()?;
        let Some(first) = frames.first() else {
            // Only the newest can be empty: a continuation not yet begun.
            if std::ptr::eq(next, newest) {
                pending = Some(kept);
                continue;
            }
            return Err(disagree(resumes.lsn, "an empty segment after a gap"));
        };
        let gap = (first.envelope.stream == Stream::Ctl)
            .then(|| Payload::decode(&first.payload).ok())
            .flatten();
        let want = GapRecord { kept: kept.lsn, kept_hash: kept.hash, resumes: resumes.lsn, resumes_hash: resumes.hash };
        if gap != Some(Payload::Gap(want)) {
            return Err(disagree(resumes.lsn, "it skips records without a Gap record"));
        }
    }
    Ok(pending)
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coordinator::Coordinator;
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::io::Write;
    use std::rc::Rc;

    /// In-memory layers; clones share the same "dataset".
    #[derive(Clone, Default)]
    struct FakeLayers {
        snaps: Rc<RefCell<BTreeMap<Lsn, HashVal>>>,
        /// Take the snapshot, then report failure (a crash after it).
        fail_after_snapshot: Rc<RefCell<bool>>,
        /// Every rollback, by target lsn.
        rolled_back: Rc<RefCell<Vec<Lsn>>>,
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
        /// Like `zfs rollback`: the layer must be there with this hash,
        /// and nothing later may exist.
        fn rollback(&mut self, lsn: Lsn, hash: HashVal) -> Result<(), LayerError> {
            let s = self.snaps.borrow();
            match s.get(&lsn) {
                None => return Err(format!("no layer {}", lsn.get()).into()),
                Some(h) if *h != hash => return Err(format!("layer {} has another hash", lsn.get()).into()),
                Some(_) => {}
            }
            if s.range(lsn.next()..).next().is_some() {
                return Err("more recent layers exist".into());
            }
            self.rolled_back.borrow_mut().push(lsn);
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

    // ── rolling ─────────────────────────────────────────────────────

    /// A full segment is closed and the next starts at its tail: one log
    /// across many files, reopened whole, with a Seal found in a closed
    /// file and appends continuing.
    #[test]
    fn full_segments_roll_and_reopen_whole() {
        let e = env();
        let mut c = e.create();
        // Lineage-sized frames: roll after every second record or so.
        c.set_roll_at(crate::segment::HEADER_LEN + 300);
        for n in 0..9 {
            c.append(Stream::Fs, raw(n)).unwrap();
        }
        let sealed = seal(&mut c, 1).unwrap();
        c.append(Stream::Fs, raw(99)).unwrap();
        let files = list_segments(&e.dir).unwrap();
        assert!(files.len() >= 4, "{} files", files.len());
        assert_eq!(lsns(&c), (1..=11).collect::<Vec<_>>());
        // Every file starts where the one before ends.
        for pair in c.segments().windows(2) {
            assert_eq!(pair[0].tail(), pair[1].base());
        }
        drop(c);

        let (mut c, r) = e.open(A);
        assert_eq!(r.last_seal, Some(sealed.seal));
        assert_eq!((r.segment.unaccepted_frames, r.gap), (0, None));
        assert_eq!(lsns(&c), (1..=11).collect::<Vec<_>>());
        assert_eq!(c.frame(Lsn::new(3)).unwrap().unwrap().envelope.lsn, Lsn::new(3), "read from a closed file");
        c.append(Stream::Fs, raw(100)).unwrap();
        assert_eq!(c.tail().lsn, Lsn::new(12));
        // The default never rolls a small log.
        drop(c);
        let (mut c, _) = e.open(A);
        let n = list_segments(&e.dir).unwrap().len();
        c.set_roll_at(SEGMENT_MAX);
        c.append(Stream::Fs, raw(101)).unwrap();
        assert_eq!(list_segments(&e.dir).unwrap().len(), n);
    }

    /// A roll whose first append is refused leaves an empty newest file
    /// based at the head (the crash case too): it opens, and the next
    /// holder writes into it.
    #[test]
    fn an_empty_rolled_segment_opens_at_the_head() {
        let e = env();
        let mut a = e.create();
        a.append(Stream::Fs, raw(1)).unwrap();
        a.set_roll_at(1);
        // Another incarnation takes over: A's next append rolls, then is refused.
        e.coord.transfer(cid(), B).unwrap();
        assert!(matches!(a.append(Stream::Fs, raw(2)), Err(ChronicleError::Refused(_))));
        let files = list_segments(&e.dir).unwrap();
        assert_eq!(files.len(), 2);
        assert_eq!(files[1].file_name().unwrap().to_str().unwrap(), segment_name(Lsn::new(1)), "named after its base: the tail it starts at");
        assert!(a.segment().is_empty());
        drop(a);
        let (mut b, r) = e.open(B);
        assert_eq!(r.segment.unaccepted_frames, 0);
        // Rolling at every append, but an empty file is written, not rolled.
        b.set_roll_at(1);
        b.append(Stream::Fs, raw(3)).unwrap();
        assert_eq!(lsns(&b), vec![1, 2], "A's refused record was cut; B's is lsn 2");
        assert_eq!(b.segments().len(), 2, "written into the empty file, not past it");
        b.append(Stream::Fs, raw(4)).unwrap();
        b.append(Stream::Fs, raw(5)).unwrap();
        assert_eq!(lsns(&b), vec![1, 2, 3, 4]);
        assert_eq!(b.segments().len(), 4);
    }

    // ── pruning ─────────────────────────────────────────────────────

    fn lineage() -> Payload {
        Payload::Lineage(taso_core::record::LineageRecord {
            origin: taso_core::record::Origin::Void,
            namespace: taso_core::record::Namespace::from_bytes([1; 16]),
            ledger_pos: Lsn::new(0),
        })
    }

    /// A Chronicle with a Lineage and many small segments: `n` records,
    /// a Seal at the third.
    fn rolled(e: &Env, n: u8) -> (Chronicle<FakeLayers>, Sealed) {
        let mut c = e.create();
        c.append(Stream::Ctl, lineage()).unwrap();
        c.append(Stream::Fs, raw(0)).unwrap();
        let sealed = seal(&mut c, 1).unwrap();
        c.set_roll_at(crate::segment::HEADER_LEN + 200);
        for i in 0..n {
            c.append(Stream::Fs, raw(i)).unwrap();
        }
        (c, sealed)
    }

    fn ship_to_tail(e: &Env, c: &Chronicle<FakeLayers>) {
        e.coord.advance_shipped(A, cid(), c.epoch(), c.tail()).unwrap();
    }

    /// Nothing shipped: nothing pruned and nothing written.  Shipped:
    /// the oldest closed files go, the newest `keep` stay, a Checkpoint
    /// is accepted first, and the log reopens from what is left with its
    /// last Seal (whose record is gone) still known.
    #[test]
    fn prune_removes_only_shipped_segments_after_a_checkpoint() {
        let e = env();
        let (mut c, sealed) = rolled(&e, 12);
        let files = list_segments(&e.dir).unwrap().len();
        assert!(files >= 6, "{files}");
        let tail = c.tail();
        assert_eq!(c.prune(2).unwrap(), Pruned::default(), "nothing shipped");
        assert_eq!(c.tail(), tail, "no Checkpoint written");

        // Ship half of it: only files wholly at or below the anchor go.
        let half = c.segments()[files / 2].tail();
        e.coord.advance_shipped(A, cid(), c.epoch(), half).unwrap();
        let p = c.prune(2).unwrap();
        assert!(!p.removed.is_empty());
        assert_eq!(list_segments(&e.dir).unwrap().len(), c.segments().len(), "the files are the segments");
        for gone in &p.removed {
            assert!(!gone.exists());
        }
        assert!(c.segments()[0].base().lsn <= half.lsn, "nothing past the anchor went");
        let cp = p.checkpoint.unwrap();
        assert_eq!(cp.lsn, tail.lsn.next(), "the Checkpoint is the next record");

        // Everything shipped: prune down to 2 closed files.
        ship_to_tail(&e, &c);
        c.prune(2).unwrap();
        assert_eq!(c.segments().len(), 3);
        let first_kept = c.segments()[0].base().lsn;
        assert!(first_kept > sealed.seal.lsn, "the Seal's record is gone");
        let lsns_before = lsns(&c);
        drop(c);

        let (mut c, r) = e.open(A);
        assert_eq!(lsns(&c), lsns_before);
        assert_eq!(r.last_seal, Some(sealed.seal), "known from the Checkpoint");
        assert!(r.missing_layers.is_empty() && r.orphan_layers.is_empty(), "{r:?}");
        assert!(e.layers.snaps().iter().any(|(l, _)| *l == sealed.seal.lsn), "its layer is kept");
        c.append(Stream::Fs, raw(200)).unwrap();
        let s2 = seal(&mut c, 2).unwrap();
        drop(c);
        let (_, r) = e.open(A);
        assert_eq!(r.last_seal, Some(s2.seal));
    }

    /// Layers of Seals older than the summarised one, whose records went
    /// with their segment, are kept at open: not orphans.
    #[test]
    fn layers_of_pruned_seals_are_kept() {
        let e = env();
        let mut c = e.create();
        c.append(Stream::Ctl, lineage()).unwrap();
        c.append(Stream::Fs, raw(0)).unwrap();
        let first = seal(&mut c, 1).unwrap();
        c.append(Stream::Fs, raw(1)).unwrap();
        let second = seal(&mut c, 2).unwrap();
        c.set_roll_at(crate::segment::HEADER_LEN + 200);
        for i in 0..8 {
            c.append(Stream::Fs, raw(i)).unwrap();
        }
        ship_to_tail(&e, &c);
        c.prune(1).unwrap();
        assert!(c.segments()[0].base().lsn > second.seal.lsn, "both Seal records are gone");
        drop(c);

        let (_, r) = e.open(A);
        assert_eq!(r.last_seal, Some(second.seal));
        assert!(r.orphan_layers.is_empty(), "{r:?}");
        let snaps: Vec<Lsn> = e.layers.snaps().iter().map(|(l, _)| *l).collect();
        assert!(snaps.contains(&first.seal.lsn) && snaps.contains(&second.seal.lsn), "{snaps:?}");
    }

    #[test]
    fn prune_needs_a_lineage_and_a_live_chronicle() {
        let e = env();
        let mut c = e.create();
        c.set_roll_at(1);
        for i in 0..4 {
            c.append(Stream::Fs, raw(i)).unwrap();
        }
        ship_to_tail(&e, &c);
        assert!(matches!(c.prune(1), Err(ChronicleError::NoLineage)));
        assert_eq!(c.segments().len(), 4, "nothing removed");
        e.coord.transfer(cid(), B).unwrap();
        let (mut c2, _) = {
            drop(c);
            e.open(A)
        };
        c2.set_roll_at(1);
        e.coord.transfer(cid(), B).unwrap();
        assert!(c2.prune(0).is_err(), "fenced: it may not write the Checkpoint");
    }

    /// A log cut without a Checkpoint, or cut past what was shipped, is
    /// refused at open.
    #[test]
    fn a_cut_log_without_its_checkpoint_is_refused() {
        let e = env();
        let (c, _) = rolled(&e, 6);
        ship_to_tail(&e, &c);
        drop(c);
        let files = list_segments(&e.dir).unwrap();
        std::fs::remove_file(&files[0]).unwrap();
        let r = Chronicle::open(&e.dir, e.coord.clone(), cid(), A, e.layers.clone());
        assert!(
            matches!(r, Err(ChronicleError::SegmentsDisagree { why, .. }) if why.contains("no Checkpoint")),
            "{:?}",
            r.err()
        );

        let e = env();
        let (c, _) = rolled(&e, 6);
        drop(c);
        let files = list_segments(&e.dir).unwrap();
        std::fs::remove_file(&files[0]).unwrap();
        let r = Chronicle::open(&e.dir, e.coord.clone(), cid(), A, e.layers.clone());
        assert!(
            matches!(r, Err(ChronicleError::SegmentsDisagree { why, .. }) if why.contains("past what was shipped")),
            "{:?}",
            r.err()
        );
    }

    // ── batches ─────────────────────────────────────────────────────

    #[test]
    fn a_batch_is_accepted_whole() {
        let e = env();
        let mut c = e.create();
        c.append(Stream::Fs, raw(1)).unwrap();
        let h = c.append_batch(vec![(Stream::Effect, raw(2)), (Stream::Effect, raw(3)), (Stream::Fs, raw(4))]).unwrap();
        assert_eq!(h.lsn, Lsn::new(4));
        assert_eq!(e.coord.head(cid()).unwrap(), h);
        assert_eq!(Position::from(h), c.tail());
        drop(c);
        let (c, r) = e.open(A);
        assert_eq!(r.segment, segment::Recovery::default());
        assert_eq!(c.frames().unwrap().len(), 4);
    }

    /// A fenced Warden's batch is refused whole and cut whole.
    #[test]
    fn a_refused_batch_is_cut_whole() {
        let e = env();
        let mut a = e.create();
        a.append(Stream::Fs, raw(1)).unwrap();
        let len = std::fs::metadata(a.segment().path()).unwrap().len();
        e.coord.transfer(cid(), B).unwrap();
        let r = a.append_batch(vec![(Stream::Effect, raw(2)), (Stream::Effect, raw(3))]);
        assert!(matches!(r, Err(ChronicleError::Refused(_))), "{r:?}");
        assert!(a.is_fenced());
        assert_eq!(std::fs::metadata(a.segment().path()).unwrap().len(), len);
        assert_eq!(e.coord.head(cid()).unwrap().lsn, Lsn::new(1));
    }

    // ── rollback to the last Seal ───────────────────────────────────

    /// A restart rolls the state back to the last Seal: the newest layer,
    /// bound to the last Seal's record.
    #[test]
    fn rollback_goes_to_the_last_seal() {
        let e = env();
        let mut c = e.create();
        c.append(Stream::Fs, raw(1)).unwrap();
        seal(&mut c, 1).unwrap();
        let s2 = seal(&mut c, 2).unwrap().seal;
        c.append(Stream::Fs, raw(2)).unwrap(); // written after the Seal
        drop(c);
        let (mut c, _) = e.open(A);
        assert_eq!(c.rollback_to_last_seal().unwrap(), Some(s2));
        assert_eq!(*e.layers.rolled_back.borrow(), vec![s2.lsn]);
        assert_eq!(c.last_seal(), Some(s2), "the log is untouched");
    }

    /// No Seal yet: nothing to roll back to, nothing touched.
    #[test]
    fn rollback_without_a_seal_does_nothing() {
        let e = env();
        let mut c = e.create();
        c.append(Stream::Fs, raw(1)).unwrap();
        assert_eq!(c.rollback_to_last_seal().unwrap(), None);
        assert!(e.layers.rolled_back.borrow().is_empty());
    }

    /// The last Seal's layer is gone: roll back to the newest Seal that
    /// still has one, and say which.
    #[test]
    fn rollback_with_the_last_layer_missing_goes_to_the_one_before() {
        let e = env();
        let mut c = e.create();
        let s1 = seal(&mut c, 1).unwrap().seal;
        let s2 = seal(&mut c, 2).unwrap().seal;
        drop(c);
        e.layers.clone().destroy(s2.lsn).unwrap();
        let (mut c, _) = e.open(A);
        assert!(c.layer_missing(s2.lsn));
        assert_eq!(c.rollback_to_last_seal().unwrap(), Some(s1));
        assert_eq!(*e.layers.rolled_back.borrow(), vec![s1.lsn]);
    }

    /// No layer at all although Seals exist (every one lost): nothing to
    /// roll back to.
    #[test]
    fn rollback_with_every_layer_missing_does_nothing() {
        let e = env();
        let mut c = e.create();
        let s1 = seal(&mut c, 1).unwrap().seal;
        drop(c);
        e.layers.clone().destroy(s1.lsn).unwrap();
        let (mut c, _) = e.open(A);
        assert_eq!(c.rollback_to_last_seal().unwrap(), None);
        assert!(e.layers.rolled_back.borrow().is_empty());
    }

    /// A layer past the last Seal, or one bound to another record, is
    /// refused: nothing rolled back.
    #[test]
    fn rollback_refuses_layers_that_do_not_match_the_log() {
        let e = env();
        let mut c = e.create();
        let s1 = seal(&mut c, 1).unwrap().seal;
        // Made behind the Chronicle's back after open.
        e.layers.clone().snapshot(Lsn::new(9), HashVal::from_bytes([9; 32])).unwrap();
        let err = c.rollback_to_last_seal().unwrap_err();
        assert!(err.to_string().contains("past the last Seal"), "{err}");
        e.layers.clone().destroy(Lsn::new(9)).unwrap();
        e.layers.clone().destroy(s1.lsn).unwrap();
        e.layers.clone().snapshot(s1.lsn, HashVal::from_bytes([7; 32])).unwrap();
        let err = c.rollback_to_last_seal().unwrap_err();
        assert!(err.to_string().contains("not bound to the last Seal"), "{err}");
        assert!(e.layers.rolled_back.borrow().is_empty());
    }

    /// A fenced Chronicle does not touch the state.
    #[test]
    fn a_fenced_chronicle_does_not_roll_back() {
        let e = env();
        let mut a = e.create();
        seal(&mut a, 1).unwrap();
        e.coord.transfer(cid(), B).unwrap();
        assert!(matches!(a.append(Stream::Fs, raw(1)), Err(ChronicleError::Refused(_))));
        assert!(matches!(a.rollback_to_last_seal(), Err(ChronicleError::Fenced)));
        assert!(e.layers.rolled_back.borrow().is_empty());
    }

    /// ZFS layers roll back with `zfs rollback` on the Seal's snapshot,
    /// after checking its binding.
    #[test]
    fn zfs_layers_roll_back_with_zfs() {
        struct Rec(Rc<RefCell<Vec<Vec<String>>>>, RefCell<Vec<crate::zfs::Output>>);
        impl Runner for Rec {
            fn run(&self, args: &[String]) -> Result<crate::zfs::Output, crate::zfs::ZfsError> {
                self.0.borrow_mut().push(args.to_vec());
                Ok(self.1.borrow_mut().remove(0))
            }
            fn run_input(&self, _: &[String], _: &mut dyn std::io::Read) -> Result<crate::zfs::Output, crate::zfs::ZfsError> {
                unreachable!()
            }
        }
        let ok = |stdout: &str| crate::zfs::Output { success: true, code: Some(0), stdout: stdout.into(), stderr: String::new() };
        let ds = Dataset::new("tasotest/vessel/v").unwrap();
        let name = ds.seal_snapshot(Lsn::new(4));
        let h = HashVal::from_bytes([4; 32]);
        let calls = Rc::new(RefCell::new(vec![]));
        let rec = Rec(calls.clone(), RefCell::new(vec![ok(&format!("{name}\t845\t17\t{h}\n")), ok("")]));
        let mut layers = ZfsLayers::new(Zfs::with_runner(rec), ds);
        layers.rollback(Lsn::new(4), h).unwrap();
        let calls = calls.borrow().clone();
        assert_eq!(calls.last().unwrap(), &vec!["rollback".to_string(), name]);
        assert_eq!(calls.len(), 2, "get, then rollback: {calls:?}");
    }

    /// A layer store without rollback says so; nothing pretends it worked.
    #[test]
    fn a_store_without_rollback_refuses() {
        struct NoRollback;
        impl Layers for NoRollback {
            fn snapshot(&mut self, _: Lsn, _: HashVal) -> Result<(), LayerError> {
                Ok(())
            }
            fn list(&self) -> Result<Vec<(Lsn, HashVal)>, LayerError> {
                Ok(vec![])
            }
            fn destroy(&mut self, _: Lsn) -> Result<(), LayerError> {
                Ok(())
            }
        }
        let e = NoRollback.rollback(Lsn::new(3), HashVal::from_bytes([3; 32])).unwrap_err();
        assert!(e.to_string().contains("cannot roll back"), "{e}");
    }

    // ── layers that are not there ───────────────────────────────────

    /// An accepted Seal whose snapshot is gone is reported, stays the last
    /// Seal (it is in the log), and is marked so nothing builds on it.
    #[test]
    fn an_accepted_seal_without_its_layer_is_reported() {
        let e = env();
        let mut c = e.create();
        c.append(Stream::Fs, raw(1)).unwrap();
        let s1 = seal(&mut c, 1).unwrap().seal;
        c.append(Stream::Fs, raw(2)).unwrap();
        let s2 = seal(&mut c, 2).unwrap().seal;
        drop(c);
        e.layers.clone().destroy(s2.lsn).unwrap(); // lost by hand
        let (c, r) = e.open(A);
        assert_eq!(r.missing_layers, vec![s2]);
        assert_eq!(r.last_seal, Some(s2), "the last Seal comes from the records");
        assert!(r.orphan_layers.is_empty());
        assert!(c.layer_missing(s2.lsn));
        assert!(!c.layer_missing(s1.lsn));
        assert_eq!(e.layers.snaps(), vec![(s1.lsn, s1.hash)]);
        // Nothing missing: nothing reported.
        let e = env();
        let mut c = e.create();
        let s = seal(&mut c, 1).unwrap().seal;
        drop(c);
        let (c, r) = e.open(A);
        assert!(r.missing_layers.is_empty());
        assert!(!c.layer_missing(s.lsn));
    }

    /// A layer is a Seal's only: one bound to an accepted record that is
    /// not a Seal is an orphan.
    #[test]
    fn a_layer_on_a_record_that_is_not_a_seal_is_an_orphan() {
        let e = env();
        let mut c = e.create();
        let h = c.append(Stream::Ctl, raw(1)).unwrap();
        drop(c);
        e.layers.clone().snapshot(h.lsn, h.hash).unwrap();
        let (_c, r) = e.open(A);
        assert_eq!(r.orphan_layers, vec![h.lsn]);
        assert!(e.layers.snaps().is_empty());
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

    /// A lock dropped while another thread spawns processes may still be
    /// held for a moment by a child between fork and exec.  Reopening must
    /// not be refused for that.  (Without the retry about 1 in 20 relocks
    /// failed here.)
    #[test]
    fn relock_while_processes_spawn_is_not_refused() {
        use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
        let dir = tempfile::tempdir().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let spawned = Arc::new(AtomicU64::new(0));
        let spawner = {
            let (stop, spawned) = (stop.clone(), spawned.clone());
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    let _ = std::process::Command::new("true").status();
                    spawned.fetch_add(1, Ordering::Relaxed);
                }
            })
        };
        // Relock for as long as it takes the spawner to start 300
        // processes, so the two really overlap.
        let (mut relocks, mut refused) = (0u64, 0u64);
        let t = Instant::now();
        while spawned.load(Ordering::Relaxed) < 300 && t.elapsed() < Duration::from_secs(10) {
            match lock_dir(dir.path()) {
                Ok(lock) => drop(lock),
                Err(_) => refused += 1,
            }
            relocks += 1;
        }
        stop.store(true, Ordering::Relaxed);
        spawner.join().unwrap();
        let n = spawned.load(Ordering::Relaxed);
        assert!(n >= 300, "the spawner only started {n} processes");
        assert_eq!(refused, 0, "{refused} of {relocks} relocks refused while {n} processes were spawned");
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

    // ── several segments; takeover after a gap ──────────────────────

    /// Node A writes `n` records and ships the first `shipped` of them;
    /// node B's directory gets a log with exactly those (as rebirth
    /// rebuilds it from the packs).  Returns (A's chronicle, B's dir).
    fn shipped_elsewhere(e: &Env, n: u8, shipped: u64) -> (Chronicle<FakeLayers>, PathBuf) {
        let mut a = e.create();
        for k in 1..=n {
            a.append(Stream::Fs, raw(k)).unwrap();
        }
        let frames = a.frames().unwrap();
        let to = Position { lsn: Lsn::new(shipped), hash: frames[shipped as usize - 1].envelope.hash };
        e.coord.advance_shipped(A, cid(), a.epoch(), to).unwrap();
        let b_dir = e.dir.parent().unwrap().join("node-b");
        std::fs::create_dir(&b_dir).unwrap();
        let mut seg = Segment::create(b_dir.join(SEGMENT_FILE), cid(), Position::GENESIS).unwrap();
        for f in &frames[..shipped as usize] {
            seg.append(&f.envelope, &f.payload).unwrap();
        }
        (a, b_dir)
    }

    fn open_b(e: &Env, dir: &Path, layers: FakeLayers) -> Result<(Chronicle<FakeLayers>, Recovery), ChronicleError> {
        Chronicle::open_after_gap(dir, e.coord.clone(), cid(), B, layers)
    }

    fn lsns(c: &Chronicle<FakeLayers>) -> Vec<u64> {
        c.frames().unwrap().iter().map(|f| f.envelope.lsn.get()).collect()
    }

    #[test]
    fn takeover_after_a_gap_continues_from_the_head() {
        let e = env();
        let (mut a, b_dir) = shipped_elsewhere(&e, 5, 3);
        let head = e.coord.head(cid()).unwrap();
        let kept = e.coord.shipped(cid()).unwrap();
        // A crash on B tore the log's tail; that is cut, not refused.
        let seg0 = b_dir.join(SEGMENT_FILE);
        std::fs::OpenOptions::new().append(true).open(&seg0).unwrap().write_all(&[7; 20]).unwrap();

        let (mut b, r) = open_b(&e, &b_dir, FakeLayers::default()).unwrap();
        assert_eq!(r.gap, Some((kept, Position::from(head))));
        assert_eq!(r.segment.invalid_bytes, 20);
        assert_eq!(b.segment().path(), b_dir.join(segment_name(Lsn::new(5))));
        b.append(Stream::Fs, raw(9)).unwrap();
        assert_eq!(lsns(&b), vec![1, 2, 3, 6, 7]);
        let gap = &b.frames().unwrap()[3];
        assert_eq!(gap.envelope.stream, Stream::Ctl);
        assert_eq!(gap.envelope.prev, head.hash);
        assert_eq!(
            Payload::decode(&gap.payload).unwrap(),
            Payload::Gap(GapRecord { kept: kept.lsn, kept_hash: kept.hash, resumes: head.lsn, resumes_hash: head.hash })
        );
        assert_eq!(Position::from(e.coord.head(cid()).unwrap()), b.tail());
        // The old holder is fenced.
        assert!(matches!(a.append(Stream::Fs, raw(1)), Err(ChronicleError::Refused(_))));

        // Both opens read the joined files back the same way.
        drop(b);
        let (b, r) = Chronicle::open(&b_dir, e.coord.clone(), cid(), B, FakeLayers::default()).unwrap();
        assert_eq!((lsns(&b), r.gap), (vec![1, 2, 3, 6, 7], None));
        drop(b);
        let (b, r) = open_b(&e, &b_dir, FakeLayers::default()).unwrap();
        assert_eq!((lsns(&b), r.gap), (vec![1, 2, 3, 6, 7], None));
    }

    /// A log with a gap, restored from its frames into a fresh directory
    /// (as rebirth does on a third node), opens to the same records, the
    /// joint in the same place; and a restore never overwrites.
    #[test]
    fn a_restored_log_opens_to_the_same_records() {
        let e = env();
        let (_a, b_dir) = shipped_elsewhere(&e, 5, 3);
        let (mut b, _) = open_b(&e, &b_dir, FakeLayers::default()).unwrap();
        b.append(Stream::Fs, raw(9)).unwrap();
        let frames = b.frames().unwrap();
        drop(b);
        let c_dir = e.dir.with_file_name("vessel-c");
        restore_log(&c_dir, cid(), &frames).unwrap();
        assert!(c_dir.join(SEGMENT_FILE).exists() && c_dir.join(segment_name(Lsn::new(5))).exists());
        assert!(!c_dir.with_file_name("vessel-c.restore").exists());
        let (c, r) = Chronicle::open_after_gap(&c_dir, e.coord.clone(), cid(), WardenId::new(3), FakeLayers::default()).unwrap();
        assert_eq!((c.frames().unwrap(), r.gap), (frames.clone(), None));
        drop(c);
        assert!(matches!(restore_log(&c_dir, cid(), &frames), Err(ChronicleError::StateExists(_))));
        // A leftover from a crashed restore is replaced.
        let d_dir = e.dir.with_file_name("vessel-d");
        std::fs::create_dir_all(d_dir.with_file_name("vessel-d.restore")).unwrap();
        std::fs::write(d_dir.with_file_name("vessel-d.restore").join("junk"), b"x").unwrap();
        restore_log(&d_dir, cid(), &frames[..3]).unwrap();
        assert!(!d_dir.join("junk").exists());
        // Nothing yet: an empty first segment.
        let n_dir = e.dir.with_file_name("vessel-n");
        restore_log(&n_dir, cid(), &[]).unwrap();
        assert!(n_dir.join(SEGMENT_FILE).exists());
    }

    #[test]
    fn interrupted_takeover_is_finished_only_by_open_after_gap() {
        let e = env();
        let (_a, b_dir) = shipped_elsewhere(&e, 5, 3);
        let head = e.coord.head(cid()).unwrap();
        // Crash after the continuation file was created, before its Gap record.
        Segment::create(b_dir.join(segment_name(head.lsn)), cid(), Position::from(head)).unwrap();
        assert!(matches!(
            Chronicle::open(&b_dir, e.coord.clone(), cid(), B, FakeLayers::default()),
            Err(ChronicleError::GapPending { kept, head: h }) if kept == Lsn::new(3) && h == head.lsn
        ));
        let (b, r) = open_b(&e, &b_dir, FakeLayers::default()).unwrap();
        assert_eq!(r.gap.map(|(k, _)| k.lsn), Some(Lsn::new(3)));
        assert_eq!(lsns(&b), vec![1, 2, 3, 6]);
    }

    #[test]
    fn a_gap_must_start_at_the_shipped_anchor() {
        let e = env();
        let (a, b_dir) = shipped_elsewhere(&e, 5, 3);
        // B holds one record less than was shipped.
        let two = a.frames().unwrap()[1].envelope.hash;
        let at_two = ChronicleHead { lsn: Lsn::new(2), hash: two, epoch: a.epoch() };
        Segment::open(b_dir.join(SEGMENT_FILE), at_two).unwrap();
        let head = e.coord.head(cid()).unwrap();
        assert!(matches!(
            open_b(&e, &b_dir, FakeLayers::default()),
            Err(ChronicleError::SegmentsDisagree { at, .. }) if at == head.lsn
        ));
        // Nothing was accepted past the head.
        assert_eq!(e.coord.head(cid()).unwrap().lsn, head.lsn);
    }

    #[test]
    fn open_after_gap_without_a_gap_is_a_plain_open() {
        let e = env();
        let mut c = e.create();
        c.append(Stream::Fs, raw(1)).unwrap();
        drop(c);
        let (c, r) = open_b(&e, &e.dir, e.layers.clone()).unwrap();
        assert_eq!((lsns(&c), r.gap), (vec![1], None));
        assert_eq!(list_segments(&e.dir).unwrap().len(), 1);
    }

    #[test]
    fn last_seal_is_found_in_a_closed_segment() {
        let e = env();
        let mut a = e.create();
        a.append(Stream::Fs, raw(1)).unwrap();
        let s = seal(&mut a, 1).unwrap();
        a.append(Stream::Fs, raw(2)).unwrap();
        a.append(Stream::Fs, raw(3)).unwrap();
        e.coord.advance_shipped(A, cid(), a.epoch(), s.seal).unwrap();
        let b_dir = e.dir.parent().unwrap().join("node-b");
        std::fs::create_dir(&b_dir).unwrap();
        let mut seg = Segment::create(b_dir.join(SEGMENT_FILE), cid(), Position::GENESIS).unwrap();
        for f in &a.frames().unwrap()[..2] {
            seg.append(&f.envelope, &f.payload).unwrap();
        }
        drop(seg);
        // B's layers hold the Seal (rebirth received it) and an orphan.
        let layers = FakeLayers::default();
        layers.snaps.borrow_mut().insert(s.seal.lsn, s.seal.hash);
        layers.snaps.borrow_mut().insert(Lsn::new(3), HashVal::from_bytes([9; 32]));
        let (b, r) = open_b(&e, &b_dir, layers.clone()).unwrap();
        assert_eq!(b.last_seal(), Some(s.seal));
        assert_eq!(r.orphan_layers, vec![Lsn::new(3)]);
        assert_eq!(layers.snaps(), vec![(s.seal.lsn, s.seal.hash)]);
    }

    #[test]
    fn a_torn_closed_segment_is_refused() {
        let e = env();
        let (_a, b_dir) = shipped_elsewhere(&e, 5, 3);
        drop(open_b(&e, &b_dir, FakeLayers::default()).unwrap());
        let seg0 = b_dir.join(SEGMENT_FILE);
        std::fs::OpenOptions::new().append(true).open(&seg0).unwrap().write_all(&[7; 20]).unwrap();
        assert!(matches!(
            open_b(&e, &b_dir, FakeLayers::default()),
            Err(ChronicleError::Segment(SegmentError::ClosedTorn { invalid_bytes: 20 }))
        ));
    }

    /// `read_log` returns every valid frame across the segments and
    /// writes nothing: a torn tail stays on disk.
    #[test]
    fn read_log_reads_every_segment_and_writes_nothing() {
        let e = env();
        let (c, _) = rolled(&e, 6);
        assert!(c.segments().len() > 1);
        let want = c.frames().unwrap();
        drop(c);
        let newest = list_segments(&e.dir).unwrap().pop().unwrap();
        std::fs::OpenOptions::new().append(true).open(&newest).unwrap().write_all(&[7; 20]).unwrap();
        let bytes = |p: &Path| std::fs::read(p).unwrap();
        let before: Vec<Vec<u8>> = list_segments(&e.dir).unwrap().iter().map(|p| bytes(p)).collect();
        assert_eq!(read_log(&e.dir).unwrap(), want);
        let after: Vec<Vec<u8>> = list_segments(&e.dir).unwrap().iter().map(|p| bytes(p)).collect();
        assert_eq!(before, after, "nothing was cut or written");
        assert!(read_log(&e.dir.join("missing")).is_err());
    }

    #[test]
    fn another_chronicles_segment_is_refused() {
        let e = env();
        drop(e.create());
        let seg0 = e.dir.join(SEGMENT_FILE);
        std::fs::remove_file(&seg0).unwrap();
        Segment::create(&seg0, ChronicleId::from_bytes([6; 16]), Position::GENESIS).unwrap();
        assert!(matches!(
            Chronicle::open(&e.dir, e.coord.clone(), cid(), A, e.layers.clone()),
            Err(ChronicleError::SegmentsDisagree { why: "another Chronicle's segment", .. })
        ));
    }

    #[test]
    fn a_misnamed_segment_file_is_refused() {
        let e = env();
        drop(e.create());
        std::fs::write(e.dir.join("seg-12"), b"").unwrap();
        assert!(matches!(
            Chronicle::open(&e.dir, e.coord.clone(), cid(), A, e.layers.clone()),
            Err(ChronicleError::BadSegmentName(n)) if n == "seg-12"
        ));
    }

    /// Joint checks on segment files built directly.
    #[test]
    fn segments_join_only_end_to_start_or_through_a_gap_record() {
        let root = tempfile::tempdir().unwrap();
        let rec = |prev: Position, stream, payload| {
            Record::new(cid(), BranchId::TRUNK, Epoch::new(1), stream, prev.lsn.next(), prev.hash, payload)
        };
        let mut n = 0;
        // A segment from `base` holding `payloads`.
        let mut seg = |base: Position, payloads: Vec<(Stream, Payload)>| {
            n += 1;
            let mut s = Segment::create(root.path().join(format!("s{n}")), cid(), base).unwrap();
            for (stream, p) in payloads {
                let r = rec(s.tail(), stream, p);
                s.append(&r.envelope, &r.payload.canon_bytes()).unwrap();
            }
            s
        };
        let first = seg(Position::GENESIS, vec![(Stream::Fs, raw(1)), (Stream::Fs, raw(2))]);
        let kept = first.tail();
        let far = Position { lsn: Lsn::new(9), hash: HashVal::from_bytes([3; 32]) };
        let gap = |k: Position, r: Position| {
            (Stream::Ctl, Payload::Gap(GapRecord { kept: k.lsn, kept_hash: k.hash, resumes: r.lsn, resumes_hash: r.hash }))
        };
        let why = |r: Result<Option<Position>, ChronicleError>| match r {
            Err(ChronicleError::SegmentsDisagree { why, .. }) => why,
            other => panic!("expected disagreement, got {other:?}"),
        };

        // End to start; a gap with its record; a continuation not begun.
        let next = seg(kept, vec![(Stream::Fs, raw(3))]);
        assert_eq!(check_joints(std::slice::from_ref(&first), &next, false).unwrap(), None);
        let cont = seg(far, vec![gap(kept, far), (Stream::Fs, raw(4))]);
        assert_eq!(check_joints(std::slice::from_ref(&first), &cont, false).unwrap(), None);
        let empty = seg(far, vec![]);
        assert_eq!(check_joints(std::slice::from_ref(&first), &empty, false).unwrap(), Some(kept));

        // Refusals.
        let not_genesis = seg(kept, vec![]);
        assert_eq!(why(check_joints(&[], &not_genesis, false)), "the first segment does not start at genesis");
        let inside = seg(Position { lsn: Lsn::new(1), hash: HashVal::from_bytes([1; 32]) }, vec![]);
        assert_eq!(why(check_joints(std::slice::from_ref(&first), &inside, false)), "it starts inside the one before");
        let same_lsn = seg(Position { lsn: kept.lsn, hash: HashVal::from_bytes([1; 32]) }, vec![]);
        assert_eq!(why(check_joints(std::slice::from_ref(&first), &same_lsn, false)), "it starts inside the one before");
        let no_record = seg(far, vec![(Stream::Fs, raw(4))]);
        assert_eq!(why(check_joints(std::slice::from_ref(&first), &no_record, false)), "it skips records without a Gap record");
        let wrong_kept = seg(far, vec![gap(Position { lsn: Lsn::new(1), hash: kept.hash }, far)]);
        assert_eq!(why(check_joints(std::slice::from_ref(&first), &wrong_kept, false)), "it skips records without a Gap record");
        let wrong_resumes =
            seg(far, vec![gap(kept, Position { lsn: far.lsn, hash: HashVal::from_bytes([4; 32]) })]);
        assert_eq!(why(check_joints(std::slice::from_ref(&first), &wrong_resumes, false)), "it skips records without a Gap record");
        let gap_on_fs = seg(far, vec![(Stream::Fs, gap(kept, far).1)]);
        assert_eq!(why(check_joints(std::slice::from_ref(&first), &gap_on_fs, false)), "it skips records without a Gap record");
        let empty_middle = seg(far, vec![]);
        let after = seg(far, vec![(Stream::Fs, raw(5))]);
        assert_eq!(why(check_joints(&[first, empty_middle], &after, false)), "an empty segment after a gap");
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
        fn append_batch(&self, w: WardenId, es: &[taso_core::envelope::Envelope]) -> Result<ChronicleHead, CoordError> {
            let r = self.inner.append_batch(w, es);
            if self.lose_next.swap(false, std::sync::atomic::Ordering::SeqCst) {
                return Err(CoordError::Unavailable(std::io::ErrorKind::ConnectionReset.into()));
            }
            r
        }
        fn transfer_if(&self, c: ChronicleId, h: WardenId, e: (WardenId, Epoch)) -> Result<Epoch, CoordError> {
            self.inner.transfer_if(c, h, e)
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
        fn advance_shipped(&self, w: WardenId, c: ChronicleId, e: Epoch, to: Position) -> Result<Position, CoordError> {
            self.inner.advance_shipped(w, c, e, to)
        }
        fn shipped(&self, c: ChronicleId) -> Result<Position, CoordError> {
            self.inner.shipped(c)
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
