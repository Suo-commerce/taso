//! A Vessel: one dataset, one Chronicle, one Warden state directory
//! (v1.0 §0, §3; v0.4 §3).
//!
//! # Identity
//!
//! A Vessel's id is derived: [`vessel_id`]`(namespace, subject)`.  Its
//! dataset is `<root>/v-<id hex>` and its Warden state directory (segment
//! and lock) is `<state_dir>/<id hex>` — **outside** the dataset, because
//! the agent can write anywhere in its dataset and must never reach the
//! Chronicle.
//!
//! # Birth
//!
//! Every Chronicle opens with a [`LineageRecord`] at lsn 1 on `Ctl`.
//!
//! - **From the void** (the default): an empty dataset, `Origin::Void`.
//!   [`Host::ensure`] opens the Vessel if the coordinator knows it and
//!   births it from the void otherwise.
//! - **Fork**: `zfs clone` from an accepted Seal of a parent in the same
//!   namespace, `Origin::Fork`.
//! - **Succession**: an operator moves a Vessel's state to another
//!   identity.  Deliberately hard: refused without an actor and a reason,
//!   unless the predecessor's tail *is* its last Seal, while any of its
//!   effects is unresolved, and across namespaces unless explicitly
//!   allowed.  The predecessor ends with a [`SuccessionRecord`] and is
//!   closed; the successor is born with `Origin::Succession`.
//!
//! Every step is ordered so that a crash leaves something a retry of the
//! same call finishes: the dataset first, then the Chronicle registered
//! with no records, then (succession only) the predecessor closed, then
//! the Lineage record.  A registered Chronicle with no records is an
//! unfinished birth: `ensure` finishes a void one; fork and succession
//! finish theirs when called again with the same arguments.
//!
//! # Open
//!
//! Opening checks that the Vessel is what its Chronicle says: lsn 1 is a
//! Lineage record, the namespace matches, the dataset's `origin` and
//! `taso:parent` agree with the lineage, no second Lineage appears, and a
//! Succession record, if present, is the last record.  A Vessel with a
//! successor opens closed: readable, never writable.
//!
//! Normative references: v0.4 §3 (Lineage), §7.4 (barriers), §8; v1.0 §3.

use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;

use taso_core::decode::DecodeError;
use taso_core::envelope::{ChronicleHead, ChronicleId, HashVal, Lsn, Stream};
use taso_core::model::WardenId;
use taso_core::record::{
    vessel_id, Authority, LineageRecord, Namespace, OpId, Origin, OutcomeState, ParentSeal,
    Payload, StreamCut, SuccessionRecord, TurnId, Verdict,
};

use crate::chronicle::{Chronicle, ChronicleError, LayerError, Layers, Recovery, Sealed, ZfsLayers};
use crate::coordinator::{CoordError, Coordinator};
use crate::segment::{Frame, Position};
use crate::zfs::{Dataset, DatasetInfo, Runner, Zfs};

// ── Pool ────────────────────────────────────────────────────────────

/// Where Vessel datasets live: ZFS in Phase 1.
pub trait Pool {
    /// The layer store of one dataset.
    type Layers: Layers;
    /// Create an empty dataset.
    fn create(&self, dataset: &Dataset) -> Result<DatasetInfo, LayerError>;
    /// Fork `source@<seal>` (bound to `seal_hash`) into `target`, recording
    /// `seal_hash` as the target's parent.
    fn clone(
        &self,
        source: &Dataset,
        seal: Lsn,
        seal_hash: HashVal,
        target: &Dataset,
    ) -> Result<DatasetInfo, LayerError>;
    /// What the pool reports for `dataset`, `None` if it does not exist.
    fn info(&self, dataset: &Dataset) -> Result<Option<DatasetInfo>, LayerError>;
    /// The layer store of `dataset`.
    fn layers(&self, dataset: &Dataset) -> Self::Layers;
}

impl<R: Runner + Clone> Pool for Zfs<R> {
    type Layers = ZfsLayers<R>;

    fn create(&self, dataset: &Dataset) -> Result<DatasetInfo, LayerError> {
        Ok(Zfs::create(self, dataset)?)
    }

    fn clone(
        &self,
        source: &Dataset,
        seal: Lsn,
        seal_hash: HashVal,
        target: &Dataset,
    ) -> Result<DatasetInfo, LayerError> {
        Ok(Zfs::clone(self, source, seal, seal_hash, target)?)
    }

    fn info(&self, dataset: &Dataset) -> Result<Option<DatasetInfo>, LayerError> {
        Ok(self.dataset_info(dataset)?)
    }

    fn layers(&self, dataset: &Dataset) -> ZfsLayers<R> {
        ZfsLayers::new(Clone::clone(self), dataset.clone())
    }
}

// ── Errors ──────────────────────────────────────────────────────────

/// Why a Vessel operation failed.
#[derive(Debug)]
pub enum VesselError {
    /// The Chronicle failed.
    Chronicle(ChronicleError),
    /// The coordinator failed.
    Coord(CoordError),
    /// The pool failed.
    Pool(LayerError),
    /// A Taso record could not be decoded.
    Decode {
        /// Its lsn.
        lsn: Lsn,
        /// Why.
        error: DecodeError,
    },
    /// The Chronicle is not a well-formed Vessel Chronicle.
    NotAVessel(&'static str),
    /// The Vessel belongs to another namespace.
    NamespaceMismatch {
        /// What the caller expected.
        expected: Namespace,
        /// What the Lineage record says.
        found: Namespace,
    },
    /// The dataset does not agree with the Lineage record.
    LineageMismatch(&'static str),
    /// A dataset is in the way that this operation did not make.
    DatasetConflict(Dataset),
    /// The dataset is missing for a registered Vessel.
    DatasetMissing(Dataset),
    /// The Chronicle is registered but has no Lineage record yet, and this
    /// call cannot finish that birth.
    IncompleteBirth(ChronicleId),
    /// A Vessel with that id already exists.
    AlreadyExists(ChronicleId),
    /// The Vessel has a successor; it may not be written.
    Closed {
        /// Where its state went.
        successor: ChronicleId,
    },
    /// The position is not an accepted Seal of that Vessel.
    NotASeal(Position),
    /// Succession needs a Seal, and the Vessel has none.
    NoSeal,
    /// Succession needs the tail to be the last Seal.
    SealNotLast {
        /// The last Seal.
        seal: Position,
        /// The tail.
        tail: Position,
    },
    /// Succession refused: these effects are unresolved.
    OpenObligations(Vec<OpId>),
    /// Succession across namespaces was not explicitly allowed.
    CrossNamespace,
    /// Succession needs a non-empty actor and reason.
    EmptyAuthority,
    /// A Vessel cannot succeed itself.
    SelfSuccession,
    /// Lineage and Succession records are written by this module only.
    ReservedPayload,
}

impl fmt::Display for VesselError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Chronicle(e) => write!(f, "chronicle: {e}"),
            Self::Coord(e) => write!(f, "coordinator: {e}"),
            Self::Pool(e) => write!(f, "pool: {e}"),
            Self::Decode { lsn, error } => write!(f, "record at lsn {}: {error}", lsn.get()),
            Self::NotAVessel(why) => write!(f, "not a Vessel chronicle: {why}"),
            Self::NamespaceMismatch { .. } => write!(f, "vessel belongs to another namespace"),
            Self::LineageMismatch(why) => write!(f, "dataset disagrees with lineage: {why}"),
            Self::DatasetConflict(d) => write!(f, "dataset {d} is in the way"),
            Self::DatasetMissing(d) => write!(f, "dataset {d} is missing"),
            Self::IncompleteBirth(id) => write!(f, "vessel {} was never finished", hex(id)),
            Self::AlreadyExists(id) => write!(f, "vessel {} already exists", hex(id)),
            Self::Closed { successor } => {
                write!(f, "vessel is closed; its state moved to {}", hex(successor))
            }
            Self::NotASeal(p) => write!(f, "lsn {} is not an accepted Seal", p.lsn.get()),
            Self::NoSeal => write!(f, "vessel has no Seal"),
            Self::SealNotLast { seal, tail } => write!(
                f,
                "last Seal is at lsn {} but the tail is at {}: seal first",
                seal.lsn.get(),
                tail.lsn.get()
            ),
            Self::OpenObligations(ops) => write!(f, "{} effect(s) unresolved", ops.len()),
            Self::CrossNamespace => write!(f, "succession across namespaces was not allowed"),
            Self::EmptyAuthority => write!(f, "succession needs an actor and a reason"),
            Self::SelfSuccession => write!(f, "a vessel cannot succeed itself"),
            Self::ReservedPayload => write!(f, "Lineage and Succession records are reserved"),
        }
    }
}

impl std::error::Error for VesselError {}

impl From<ChronicleError> for VesselError {
    fn from(e: ChronicleError) -> Self {
        Self::Chronicle(e)
    }
}

fn pool_err(e: LayerError) -> VesselError {
    VesselError::Pool(e)
}

// ── Host ────────────────────────────────────────────────────────────

/// Everything a Warden needs to birth and open Vessels on one node.
pub struct Host<P: Pool> {
    /// The coordinator.
    pub coord: Arc<Coordinator>,
    /// The dataset pool.
    pub pool: P,
    /// Parent dataset of every Vessel dataset.
    pub root: Dataset,
    /// Parent directory of every Vessel's Warden state (outside `root`).
    pub state_dir: PathBuf,
    /// This Warden.
    pub warden: WardenId,
}

/// How [`Host::ensure`] found the Vessel.
#[derive(Debug)]
pub enum Ensured {
    /// It existed; it was opened and recovered.
    Opened(Recovery),
    /// It did not exist; it was born from the void.
    Born,
    /// A void birth had been interrupted; it was finished.
    BirthFinished,
}

impl<P: Pool> Host<P> {
    /// The dataset of the Vessel `id`.
    pub fn dataset_for(&self, id: ChronicleId) -> Dataset {
        Dataset::new(&format!("{}/v-{}", self.root, hex(&id)))
            .expect("root is valid and the suffix is hex")
    }

    /// The Warden state directory of the Vessel `id`.
    pub fn dir_for(&self, id: ChronicleId) -> PathBuf {
        self.state_dir.join(hex(&id))
    }

    /// Find the Vessel of `subject` in `namespace`, or birth it from the
    /// void.  A found Vessel is opened and continues from its last Seal.
    pub fn ensure(
        &self,
        namespace: Namespace,
        subject: &[u8],
    ) -> Result<(Vessel<P::Layers>, Ensured), VesselError> {
        let id = vessel_id(namespace, subject);
        match self.registered_head(id)? {
            None => {
                let v = self.birth_void(id, namespace, false)?;
                Ok((v, Ensured::Born))
            }
            Some(h) if h.lsn == Lsn::new(0) => {
                let v = self.birth_void(id, namespace, true)?;
                Ok((v, Ensured::BirthFinished))
            }
            Some(_) => {
                let (v, r) = self.open_in(id, Some(namespace))?;
                Ok((v, Ensured::Opened(r)))
            }
        }
    }

    /// Open an existing Vessel by id, in whatever namespace it is.
    pub fn open(&self, id: ChronicleId) -> Result<(Vessel<P::Layers>, Recovery), VesselError> {
        self.open_in(id, None)
    }

    /// Fork a new Vessel for `subject` from an accepted Seal of `parent`,
    /// in the parent's namespace.  Calling it again with the same
    /// arguments finishes an interrupted fork.
    pub fn fork(
        &self,
        parent: &Vessel<P::Layers>,
        seal: Position,
        subject: &[u8],
    ) -> Result<Vessel<P::Layers>, VesselError> {
        let ledger_pos = seal_ledger_pos(&parent.frames()?, seal)?;
        let namespace = parent.namespace();
        let id = vessel_id(namespace, subject);
        let ps = ParentSeal { chronicle: parent.id(), seal: seal.lsn, seal_hash: seal.hash };
        let lineage = LineageRecord { origin: Origin::Fork { parent: ps }, namespace, ledger_pos };
        let mut chronicle = self.unborn(id, Some((&parent.dataset, ps)))?;
        chronicle.append(Stream::Ctl, Payload::Lineage(lineage.clone()))?;
        Ok(Vessel { id, dataset: self.dataset_for(id), lineage, successor: None, chronicle })
    }

    /// Move `old`'s state to a new identity, `subject` in `namespace`.
    ///
    /// Returns the successor and the now closed predecessor.  Calling it
    /// again with the same arguments (on the closed predecessor) finishes
    /// an interrupted succession.
    pub fn succeed(
        &self,
        old: Vessel<P::Layers>,
        namespace: Namespace,
        subject: &[u8],
        authority: Authority,
        allow_cross_namespace: bool,
    ) -> Result<Succeeded<P::Layers>, VesselError> {
        let (successor, predecessor) =
            self.succeed_inner(old, namespace, subject, authority, allow_cross_namespace, false)?;
        Ok(Succeeded { successor: successor.expect("ran to the end"), predecessor })
    }

    // ── internals ───────────────────────────────────────────────────

    /// `Some(head)` if the coordinator knows `id`.
    fn registered_head(&self, id: ChronicleId) -> Result<Option<ChronicleHead>, VesselError> {
        match self.coord.head(id) {
            Ok(h) => Ok(Some(h)),
            Err(CoordError::UnknownChronicle(_)) => Ok(None),
            Err(e) => Err(VesselError::Coord(e)),
        }
    }

    /// Birth from the void, or finish one (`registered`).
    fn birth_void(
        &self,
        id: ChronicleId,
        namespace: Namespace,
        registered: bool,
    ) -> Result<Vessel<P::Layers>, VesselError> {
        let dataset = self.dataset_for(id);
        match self.pool.info(&dataset).map_err(pool_err)? {
            None => {
                self.pool.create(&dataset).map_err(pool_err)?;
            }
            // Left by an interrupted void birth: no origin, no parent, no
            // Seals.  Anything else is not ours to adopt.
            Some(info) if info.origin.is_none() && info.parent.is_none() => {
                if !self.pool.layers(&dataset).list().map_err(pool_err)?.is_empty() {
                    return Err(VesselError::DatasetConflict(dataset));
                }
            }
            Some(_) => return Err(VesselError::DatasetConflict(dataset)),
        }
        let mut chronicle = self.chronicle(id, registered)?;
        let lineage = LineageRecord { origin: Origin::Void, namespace, ledger_pos: Lsn::new(0) };
        chronicle.append(Stream::Ctl, Payload::Lineage(lineage.clone()))?;
        Ok(Vessel { id, dataset, lineage, successor: None, chronicle })
    }

    /// The Chronicle of a Vessel being born from `parent` (fork or
    /// succession): make or verify the cloned dataset, then register or
    /// reopen the Chronicle, which must have no records.
    fn unborn(
        &self,
        id: ChronicleId,
        parent: Option<(&Dataset, ParentSeal)>,
    ) -> Result<Chronicle<P::Layers>, VesselError> {
        let registered = match self.registered_head(id)? {
            None => false,
            Some(h) if h.lsn == Lsn::new(0) => true,
            Some(_) => return Err(VesselError::AlreadyExists(id)),
        };
        let dataset = self.dataset_for(id);
        if let Some((parent_ds, ps)) = parent {
            match self.pool.info(&dataset).map_err(pool_err)? {
                None => {
                    self.pool
                        .clone(parent_ds, ps.seal, ps.seal_hash, &dataset)
                        .map_err(pool_err)?;
                }
                Some(info) => {
                    let ours = info.parent == Some(ps.seal_hash)
                        && info.origin_seal() == Some((parent_ds.clone(), ps.seal));
                    if !ours {
                        return Err(VesselError::DatasetConflict(dataset));
                    }
                }
            }
        }
        self.chronicle(id, registered)
    }

    /// Create (register) or reopen a Chronicle that must have no records.
    fn chronicle(
        &self,
        id: ChronicleId,
        registered: bool,
    ) -> Result<Chronicle<P::Layers>, VesselError> {
        let dir = self.dir_for(id);
        std::fs::create_dir_all(&dir)
            .map_err(|e| VesselError::Chronicle(ChronicleError::Segment(e.into())))?;
        let layers = self.pool.layers(&self.dataset_for(id));
        let (chronicle, _) = if registered {
            Chronicle::open(&dir, self.coord.clone(), id, self.warden, layers)?
        } else {
            Chronicle::create(&dir, self.coord.clone(), id, self.warden, layers)?
        };
        if chronicle.tail().lsn != Lsn::new(0) {
            return Err(VesselError::AlreadyExists(id));
        }
        Ok(chronicle)
    }

    fn open_in(
        &self,
        id: ChronicleId,
        expected: Option<Namespace>,
    ) -> Result<(Vessel<P::Layers>, Recovery), VesselError> {
        let dataset = self.dataset_for(id);
        let dir = self.dir_for(id);
        let layers = self.pool.layers(&dataset);
        let (chronicle, recovery) = Chronicle::open(&dir, self.coord.clone(), id, self.warden, layers)?;
        if chronicle.tail().lsn == Lsn::new(0) {
            return Err(VesselError::IncompleteBirth(id));
        }
        let frames = chronicle.segment().frames().map_err(ChronicleError::Segment)?;
        let (lineage, successor) = read_lineage(&frames)?;
        if let Some(expected) = expected {
            if lineage.namespace != expected {
                return Err(VesselError::NamespaceMismatch { expected, found: lineage.namespace });
            }
        }
        let info = self
            .pool
            .info(&dataset)
            .map_err(pool_err)?
            .ok_or_else(|| VesselError::DatasetMissing(dataset.clone()))?;
        match lineage.origin.parent() {
            None => {
                if info.parent.is_some() || info.origin.is_some() {
                    return Err(VesselError::LineageMismatch("void-born vessel has a parent dataset"));
                }
            }
            Some(ps) => {
                if info.parent != Some(ps.seal_hash) {
                    return Err(VesselError::LineageMismatch("taso:parent is not the lineage Seal"));
                }
                if info.origin_seal() != Some((self.dataset_for(ps.chronicle), ps.seal)) {
                    return Err(VesselError::LineageMismatch("origin is not the lineage Seal"));
                }
            }
        }
        Ok((Vessel { id, dataset, lineage, successor, chronicle }, recovery))
    }

    fn succeed_inner(
        &self,
        mut old: Vessel<P::Layers>,
        namespace: Namespace,
        subject: &[u8],
        authority: Authority,
        allow_cross_namespace: bool,
        stop_after_close: bool,
    ) -> Result<Partial<P::Layers>, VesselError> {
        if authority.actor.trim().is_empty() || authority.reason.trim().is_empty() {
            return Err(VesselError::EmptyAuthority);
        }
        let id = vessel_id(namespace, subject);
        if id == old.id() {
            return Err(VesselError::SelfSuccession);
        }
        if namespace != old.namespace() && !allow_cross_namespace {
            return Err(VesselError::CrossNamespace);
        }
        let seal = old.chronicle.last_seal().ok_or(VesselError::NoSeal)?;
        let frames = old.frames()?;
        let ledger_pos = seal_ledger_pos(&frames, seal)?;
        let record = SuccessionRecord {
            successor: id,
            namespace,
            seal: seal.lsn,
            seal_hash: seal.hash,
            authority: authority.clone(),
        };

        // A closed predecessor may only be finishing this very succession.
        let resuming = match &old.successor {
            Some(s) if *s == record => true,
            Some(s) => return Err(VesselError::Closed { successor: s.successor }),
            None => false,
        };
        if !resuming {
            let tail = old.tail();
            if tail != seal {
                return Err(VesselError::SealNotLast { seal, tail });
            }
            let open = open_obligations(&frames)?;
            if !open.is_empty() {
                return Err(VesselError::OpenObligations(open));
            }
        }

        let ps = ParentSeal { chronicle: old.id(), seal: seal.lsn, seal_hash: seal.hash };
        let mut chronicle = self.unborn(id, Some((&old.dataset, ps)))?;
        if !resuming {
            old.chronicle.append(Stream::Ctl, Payload::Succession(record.clone()))?;
            old.successor = Some(record);
        }
        if stop_after_close {
            return Ok((None, old));
        }
        let lineage = LineageRecord {
            origin: Origin::Succession { parent: ps, authority },
            namespace,
            ledger_pos,
        };
        chronicle.append(Stream::Ctl, Payload::Lineage(lineage.clone()))?;
        let new = Vessel { id, dataset: self.dataset_for(id), lineage, successor: None, chronicle };
        Ok((Some(new), old))
    }
}

/// A succession's result.
pub struct Succeeded<L: Layers> {
    /// The new Vessel, born with `Origin::Succession`.
    pub successor: Vessel<L>,
    /// The old Vessel, now closed.
    pub predecessor: Vessel<L>,
}

/// A succession that may have stopped after closing the predecessor
/// (test hook for the crash point).
type Partial<L> = (Option<Vessel<L>>, Vessel<L>);

// ── Vessel ──────────────────────────────────────────────────────────

/// One open Vessel.
pub struct Vessel<L: Layers> {
    id: ChronicleId,
    dataset: Dataset,
    lineage: LineageRecord,
    successor: Option<SuccessionRecord>,
    chronicle: Chronicle<L>,
}

impl<L: Layers> Vessel<L> {
    /// Its id.
    pub fn id(&self) -> ChronicleId {
        self.id
    }

    /// Its namespace.
    pub fn namespace(&self) -> Namespace {
        self.lineage.namespace
    }

    /// Where it came from.
    pub fn lineage(&self) -> &LineageRecord {
        &self.lineage
    }

    /// Its dataset.
    pub fn dataset(&self) -> &Dataset {
        &self.dataset
    }

    /// The Succession record, if its state moved to another Vessel.
    pub fn successor(&self) -> Option<&SuccessionRecord> {
        self.successor.as_ref()
    }

    /// The local tail.
    pub fn tail(&self) -> Position {
        self.chronicle.tail()
    }

    /// The last accepted Seal.
    pub fn last_seal(&self) -> Option<Position> {
        self.chronicle.last_seal()
    }

    /// The Chronicle, for reading.
    pub fn chronicle(&self) -> &Chronicle<L> {
        &self.chronicle
    }

    /// Append a record.  Lineage and Succession records are refused: only
    /// this module writes them.
    pub fn append(&mut self, stream: Stream, payload: Payload) -> Result<ChronicleHead, VesselError> {
        self.writable()?;
        if matches!(payload, Payload::Lineage(_) | Payload::Succession(_)) {
            return Err(VesselError::ReservedPayload);
        }
        Ok(self.chronicle.append(stream, payload)?)
    }

    /// Take a Seal.
    pub fn seal(
        &mut self,
        cut: StreamCut,
        verdict: Verdict,
        ledger_pos: Lsn,
        turn: TurnId,
    ) -> Result<Sealed, VesselError> {
        self.writable()?;
        Ok(self.chronicle.seal(cut, verdict, ledger_pos, turn)?)
    }

    fn writable(&self) -> Result<(), VesselError> {
        match &self.successor {
            Some(s) => Err(VesselError::Closed { successor: s.successor }),
            None => Ok(()),
        }
    }

    fn frames(&self) -> Result<Vec<Frame>, VesselError> {
        Ok(self.chronicle.segment().frames().map_err(ChronicleError::Segment)?)
    }
}

// ── Reading records ─────────────────────────────────────────────────

fn decode(frame: &Frame) -> Result<Payload, VesselError> {
    Payload::decode(&frame.payload)
        .map_err(|error| VesselError::Decode { lsn: frame.envelope.lsn, error })
}

/// The Lineage record (lsn 1) and the Succession record, if it ends the
/// Chronicle.  Refuses a second Lineage and anything after a Succession.
fn read_lineage(frames: &[Frame]) -> Result<(LineageRecord, Option<SuccessionRecord>), VesselError> {
    let first = frames.first().ok_or(VesselError::NotAVessel("no records"))?;
    if first.envelope.lsn != Lsn::new(1) || first.envelope.stream != Stream::Ctl {
        return Err(VesselError::NotAVessel("lsn 1 is not a Ctl record"));
    }
    let Payload::Lineage(lineage) = decode(first)? else {
        return Err(VesselError::NotAVessel("lsn 1 is not a Lineage record"));
    };
    let mut successor = None;
    for (i, f) in frames.iter().enumerate().skip(1) {
        if f.envelope.stream != Stream::Ctl {
            continue;
        }
        match decode(f)? {
            Payload::Lineage(_) => return Err(VesselError::NotAVessel("a second Lineage record")),
            Payload::Succession(s) => {
                if i + 1 != frames.len() {
                    return Err(VesselError::NotAVessel("records after a Succession record"));
                }
                successor = Some(s);
            }
            _ => {}
        }
    }
    Ok((lineage, successor))
}

/// The `ledger_pos` of the accepted Seal at `seal`, or `NotASeal`.
fn seal_ledger_pos(frames: &[Frame], seal: Position) -> Result<Lsn, VesselError> {
    let f = frames
        .iter()
        .find(|f| f.envelope.lsn == seal.lsn)
        .filter(|f| f.envelope.hash == seal.hash && f.envelope.stream == Stream::Ctl)
        .ok_or(VesselError::NotASeal(seal))?;
    match decode(f)? {
        Payload::Seal(s) => Ok(s.ledger_pos),
        _ => Err(VesselError::NotASeal(seal)),
    }
}

/// Effects whose intent set a barrier and whose latest outcome is not
/// terminal (`ConfirmedApplied` / `ConfirmedNotApplied`), in op order.
fn open_obligations(frames: &[Frame]) -> Result<Vec<OpId>, VesselError> {
    let mut open: BTreeMap<OpId, bool> = BTreeMap::new();
    for f in frames.iter().filter(|f| f.envelope.stream == Stream::Effect) {
        match decode(f)? {
            Payload::Intent(i) if i.barrier.is_some() => {
                open.entry(i.op).or_insert(true);
            }
            Payload::Outcome(o) => {
                if let Some(is_open) = open.get_mut(&o.op) {
                    *is_open = !matches!(
                        o.state,
                        OutcomeState::ConfirmedApplied | OutcomeState::ConfirmedNotApplied
                    );
                }
            }
            _ => {}
        }
    }
    Ok(open.into_iter().filter(|&(_, o)| o).map(|(op, _)| op).collect())
}

fn hex(id: &ChronicleId) -> String {
    id.as_bytes().iter().map(|b| format!("{b:02x}")).collect()
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;
    use taso_core::record::{
        Consequence, Dispatch, IntentRecord, OutcomeRecord, RetryPolicy, BarrierId,
    };

    // ── an in-memory pool ───────────────────────────────────────────

    #[derive(Default)]
    struct FakeDs {
        origin: Option<String>,
        parent: Option<HashVal>,
        snaps: BTreeMap<Lsn, HashVal>,
    }

    #[derive(Clone, Default)]
    struct FakePool(Rc<RefCell<BTreeMap<String, FakeDs>>>);

    struct FakeLayers {
        pool: FakePool,
        ds: String,
    }

    impl FakePool {
        fn info_of(&self, name: &str) -> Option<DatasetInfo> {
            self.0.borrow().get(name).map(|d| DatasetInfo {
                dataset: Dataset::new(name).unwrap(),
                mountpoint: Some(PathBuf::from(format!("/fake/{name}"))),
                origin: d.origin.clone(),
                parent: d.parent,
            })
        }
        fn set_parent(&self, name: &str, parent: Option<HashVal>) {
            self.0.borrow_mut().get_mut(name).unwrap().parent = parent;
        }
    }

    impl Pool for FakePool {
        type Layers = FakeLayers;
        fn create(&self, dataset: &Dataset) -> Result<DatasetInfo, LayerError> {
            let name = dataset.to_string();
            if self.0.borrow().contains_key(&name) {
                return Err("exists".into());
            }
            self.0.borrow_mut().insert(name.clone(), FakeDs::default());
            Ok(self.info_of(&name).unwrap())
        }
        fn clone(
            &self,
            source: &Dataset,
            seal: Lsn,
            seal_hash: HashVal,
            target: &Dataset,
        ) -> Result<DatasetInfo, LayerError> {
            let bound = self.0.borrow().get(source.as_str()).and_then(|d| d.snaps.get(&seal).copied());
            if bound != Some(seal_hash) {
                return Err("no such bound Seal".into());
            }
            if self.0.borrow().contains_key(target.as_str()) {
                return Err("exists".into());
            }
            self.0.borrow_mut().insert(
                target.to_string(),
                FakeDs {
                    origin: Some(source.seal_snapshot(seal)),
                    parent: Some(seal_hash),
                    snaps: BTreeMap::new(),
                },
            );
            Ok(self.info_of(target.as_str()).unwrap())
        }
        fn info(&self, dataset: &Dataset) -> Result<Option<DatasetInfo>, LayerError> {
            Ok(self.info_of(dataset.as_str()))
        }
        fn layers(&self, dataset: &Dataset) -> FakeLayers {
            FakeLayers { pool: Clone::clone(self), ds: dataset.to_string() }
        }
    }

    impl Layers for FakeLayers {
        fn snapshot(&mut self, lsn: Lsn, hash: HashVal) -> Result<(), LayerError> {
            let mut p = self.pool.0.borrow_mut();
            let d = p.get_mut(&self.ds).ok_or("no dataset")?;
            if d.snaps.insert(lsn, hash).is_some() {
                return Err("exists".into());
            }
            Ok(())
        }
        fn list(&self) -> Result<Vec<(Lsn, HashVal)>, LayerError> {
            let p = self.pool.0.borrow();
            Ok(p.get(&self.ds).map(|d| d.snaps.iter().map(|(&l, &h)| (l, h)).collect()).unwrap_or_default())
        }
        fn destroy(&mut self, lsn: Lsn) -> Result<(), LayerError> {
            if let Some(d) = self.pool.0.borrow_mut().get_mut(&self.ds) {
                d.snaps.remove(&lsn);
            }
            Ok(())
        }
    }

    // ── fixtures ────────────────────────────────────────────────────

    struct Env {
        _tmp: tempfile::TempDir,
        host: Host<FakePool>,
    }

    fn env() -> Env {
        let tmp = tempfile::tempdir().unwrap();
        let coord = Arc::new(Coordinator::open(tmp.path().join("coord.redb")).unwrap());
        let host = Host {
            coord,
            pool: FakePool::default(),
            root: Dataset::new("tank/vessels").unwrap(),
            state_dir: tmp.path().join("state"),
            warden: WardenId::new(1),
        };
        Env { _tmp: tmp, host }
    }

    fn ns(b: u8) -> Namespace {
        Namespace::from_bytes([b; 16])
    }

    fn auth() -> Authority {
        Authority { actor: "jarmo".into(), reason: "accounts merged".into() }
    }

    fn raw(n: u8) -> Payload {
        Payload::Raw(vec![n; 4])
    }

    fn seal<L: Layers>(v: &mut Vessel<L>) -> Position {
        v.seal(StreamCut::EMPTY, Verdict::Clean, Lsn::new(0), TurnId::new(1)).unwrap().seal
    }

    // ── void birth and find ─────────────────────────────────────────

    #[test]
    fn ensure_births_from_the_void_then_finds_it() {
        let e = env();
        let (mut v, how) = e.host.ensure(ns(1), b"user-1").unwrap();
        assert!(matches!(how, Ensured::Born));
        assert_eq!(v.lineage().origin, Origin::Void);
        assert_eq!(v.namespace(), ns(1));
        assert_eq!(v.id(), vessel_id(ns(1), b"user-1"));
        assert_eq!(v.tail().lsn, Lsn::new(1), "lsn 1 is the Lineage record");
        v.append(Stream::Fs, raw(1)).unwrap();
        let s = seal(&mut v);
        drop(v);

        let (v, how) = e.host.ensure(ns(1), b"user-1").unwrap();
        assert!(matches!(how, Ensured::Opened(_)));
        assert_eq!(v.last_seal(), Some(s));
        assert_eq!(v.lineage().origin, Origin::Void);
    }

    #[test]
    fn same_subject_in_two_namespaces_is_two_vessels() {
        let e = env();
        let (a, _) = e.host.ensure(ns(1), b"user-1").unwrap();
        let (b, _) = e.host.ensure(ns(2), b"user-1").unwrap();
        assert_ne!(a.id(), b.id());
        assert_ne!(a.dataset(), b.dataset());
    }

    #[test]
    fn interrupted_void_birth_is_finished_by_ensure() {
        let e = env();
        let id = vessel_id(ns(1), b"user-1");
        // Crash after the dataset and the registration, before Lineage.
        e.host.pool.create(&e.host.dataset_for(id)).unwrap();
        drop(e.host.chronicle(id, false).unwrap());
        assert!(matches!(e.host.open(id), Err(VesselError::IncompleteBirth(_))));

        let (v, how) = e.host.ensure(ns(1), b"user-1").unwrap();
        assert!(matches!(how, Ensured::BirthFinished));
        assert_eq!(v.lineage().origin, Origin::Void);
    }

    #[test]
    fn foreign_dataset_in_the_way_is_refused() {
        let e = env();
        let id = vessel_id(ns(1), b"user-1");
        e.host.pool.create(&e.host.dataset_for(id)).unwrap();
        e.host.pool.set_parent(e.host.dataset_for(id).as_str(), Some(HashVal::from_bytes([3; 32])));
        assert!(matches!(e.host.ensure(ns(1), b"user-1"), Err(VesselError::DatasetConflict(_))));
    }

    #[test]
    fn open_checks_namespace_and_dataset() {
        let e = env();
        let (v, _) = e.host.ensure(ns(1), b"user-1").unwrap();
        let id = v.id();
        drop(v);
        assert!(matches!(
            e.host.open_in(id, Some(ns(2))),
            Err(VesselError::NamespaceMismatch { .. })
        ));
        e.host.pool.set_parent(e.host.dataset_for(id).as_str(), Some(HashVal::from_bytes([3; 32])));
        assert!(matches!(e.host.open(id), Err(VesselError::LineageMismatch(_))));
    }

    #[test]
    fn reserved_payloads_are_refused() {
        let e = env();
        let (mut v, _) = e.host.ensure(ns(1), b"user-1").unwrap();
        let l = v.lineage().clone();
        assert!(matches!(v.append(Stream::Ctl, Payload::Lineage(l)), Err(VesselError::ReservedPayload)));
    }

    // ── fork ────────────────────────────────────────────────────────

    #[test]
    fn fork_from_a_seal() {
        let e = env();
        let (mut p, _) = e.host.ensure(ns(1), b"base").unwrap();
        p.append(Stream::Fs, raw(1)).unwrap();
        let s = seal(&mut p);
        let child = e.host.fork(&p, s, b"child").unwrap();
        let Origin::Fork { parent } = child.lineage().origin else { panic!("not a fork") };
        assert_eq!((parent.chronicle, parent.seal, parent.seal_hash), (p.id(), s.lsn, s.hash));
        assert_eq!(child.namespace(), ns(1), "forks stay in the parent's namespace");
        let id = child.id();
        drop(child);
        let (child, _) = e.host.open(id).unwrap();
        assert!(matches!(child.lineage().origin, Origin::Fork { .. }));
        assert!(matches!(e.host.fork(&p, s, b"child"), Err(VesselError::AlreadyExists(_))));
    }

    #[test]
    fn forked_vessel_with_a_tampered_dataset_parent_is_refused() {
        let e = env();
        let (mut p, _) = e.host.ensure(ns(1), b"base").unwrap();
        let s = seal(&mut p);
        let child = e.host.fork(&p, s, b"child").unwrap();
        let (id, ds) = (child.id(), child.dataset().clone());
        drop(child);
        e.host.pool.set_parent(ds.as_str(), Some(HashVal::from_bytes([4; 32])));
        assert!(matches!(e.host.open(id), Err(VesselError::LineageMismatch(_))));
        e.host.pool.set_parent(ds.as_str(), None);
        assert!(matches!(e.host.open(id), Err(VesselError::LineageMismatch(_))));
        e.host.pool.set_parent(ds.as_str(), Some(s.hash));
        assert!(e.host.open(id).is_ok());
    }

    #[test]
    fn fork_refuses_positions_that_are_not_seals() {
        let e = env();
        let (mut p, _) = e.host.ensure(ns(1), b"base").unwrap();
        let rec = p.append(Stream::Fs, raw(1)).unwrap();
        let s = seal(&mut p);
        let not_seal = Position { lsn: rec.lsn, hash: rec.hash };
        assert!(matches!(e.host.fork(&p, not_seal, b"c"), Err(VesselError::NotASeal(_))));
        let wrong_hash = Position { lsn: s.lsn, hash: HashVal::from_bytes([1; 32]) };
        assert!(matches!(e.host.fork(&p, wrong_hash, b"c"), Err(VesselError::NotASeal(_))));
    }

    // ── succession ──────────────────────────────────────────────────

    #[test]
    fn succession_moves_state_and_closes_the_predecessor() {
        let e = env();
        let (mut old, _) = e.host.ensure(ns(1), b"user-old").unwrap();
        old.append(Stream::Fs, raw(1)).unwrap();
        let s = seal(&mut old);
        let old_id = old.id();

        let Succeeded { successor: new, predecessor: mut old } =
            e.host.succeed(old, ns(1), b"user-new", auth(), false).unwrap();
        let Origin::Succession { parent, authority } = &new.lineage().origin else { panic!() };
        assert_eq!((parent.chronicle, parent.seal, parent.seal_hash), (old_id, s.lsn, s.hash));
        assert_eq!(authority, &auth());
        assert_eq!(old.successor().unwrap().successor, new.id());
        assert!(matches!(old.append(Stream::Fs, raw(2)), Err(VesselError::Closed { .. })));
        drop((new, old));

        // Both sides read back after reopening.
        let (old, how) = e.host.ensure(ns(1), b"user-old").unwrap();
        assert!(matches!(how, Ensured::Opened(_)));
        let succ = old.successor().expect("closed").clone();
        let (new, _) = e.host.open(succ.successor).unwrap();
        assert!(matches!(new.lineage().origin, Origin::Succession { .. }));
    }

    #[test]
    fn succession_refusals() {
        let e = env();
        let (v, _) = e.host.ensure(ns(1), b"u").unwrap();
        let empty = Authority { actor: " ".into(), reason: "x".into() };
        let r = e.host.succeed(v, ns(1), b"n", empty, false);
        assert!(matches!(r, Err(VesselError::EmptyAuthority)));
        let (v, _) = e.host.ensure(ns(1), b"u").unwrap();
        let no_reason = Authority { actor: "jarmo".into(), reason: String::new() };
        let r = e.host.succeed(v, ns(1), b"n", no_reason, false);
        assert!(matches!(r, Err(VesselError::EmptyAuthority)));

        let (v2, _) = e.host.ensure(ns(1), b"u").unwrap();
        assert!(matches!(e.host.succeed(v2, ns(1), b"n", auth(), false), Err(VesselError::NoSeal)));

        let (mut v3, _) = e.host.ensure(ns(1), b"u").unwrap();
        seal(&mut v3);
        v3.append(Stream::Fs, raw(1)).unwrap();
        assert!(matches!(
            e.host.succeed(v3, ns(1), b"n", auth(), false),
            Err(VesselError::SealNotLast { .. })
        ));

        let (mut v4, _) = e.host.ensure(ns(1), b"u").unwrap();
        seal(&mut v4);
        assert!(matches!(e.host.succeed(v4, ns(2), b"n", auth(), false), Err(VesselError::CrossNamespace)));

        let (v5, _) = e.host.ensure(ns(1), b"u").unwrap();
        assert!(matches!(e.host.succeed(v5, ns(1), b"u", auth(), false), Err(VesselError::SelfSuccession)));

        // Nothing above created a successor, and the Vessel is still open
        // for writing.
        assert!(e.host.coord.head(vessel_id(ns(1), b"n")).is_err());
        let (mut v, _) = e.host.ensure(ns(1), b"u").unwrap();
        assert!(v.successor().is_none());
        v.append(Stream::Fs, raw(9)).unwrap();
    }

    #[test]
    fn succession_refuses_unresolved_effects() {
        let e = env();
        let (mut v, _) = e.host.ensure(ns(1), b"u").unwrap();
        let intent = |op: u64| {
            Payload::Intent(IntentRecord {
                op: OpId::new(op),
                footprint: vec![],
                dispatch: Dispatch::Immediate,
                retry: RetryPolicy::UnsafeToRetry,
                consequence: Consequence::Irreversible,
                authority: vec![],
                barrier: Some(BarrierId::new(op)),
            })
        };
        let outcome = |op: u64, state| Payload::Outcome(OutcomeRecord { op: OpId::new(op), state, evidence: None });
        v.append(Stream::Effect, intent(1)).unwrap();
        v.append(Stream::Effect, outcome(1, OutcomeState::ConfirmedApplied)).unwrap();
        v.append(Stream::Effect, intent(2)).unwrap();
        v.append(Stream::Effect, outcome(2, OutcomeState::OutcomeUnknown)).unwrap();
        seal(&mut v);
        let Err(VesselError::OpenObligations(ops)) = e.host.succeed(v, ns(1), b"n", auth(), false) else {
            panic!("expected OpenObligations")
        };
        assert_eq!(ops, vec![OpId::new(2)]);
    }

    #[test]
    fn cross_namespace_succession_when_allowed() {
        let e = env();
        let (mut v, _) = e.host.ensure(ns(1), b"u").unwrap();
        seal(&mut v);
        let new = e.host.succeed(v, ns(2), b"n", auth(), true).unwrap().successor;
        assert_eq!(new.namespace(), ns(2));
        assert_eq!(new.id(), vessel_id(ns(2), b"n"));
    }

    /// Crash after the predecessor is closed, before the successor's
    /// Lineage: the successor is an unfinished birth, the predecessor is
    /// closed, and the same call on the closed predecessor finishes it.
    #[test]
    fn interrupted_succession_is_finished_by_calling_again() {
        let e = env();
        let (mut v, _) = e.host.ensure(ns(1), b"u").unwrap();
        seal(&mut v);
        let (none, old) = e.host.succeed_inner(v, ns(1), b"n", auth(), false, true).unwrap();
        assert!(none.is_none());
        let new_id = vessel_id(ns(1), b"n");
        assert!(matches!(e.host.open(new_id), Err(VesselError::IncompleteBirth(_))));
        drop(old);

        let (old, _) = e.host.ensure(ns(1), b"u").unwrap();
        assert!(old.successor().is_some());
        // A different successor is refused…
        let other = Authority { actor: "jarmo".into(), reason: "something else".into() };
        let r = e.host.succeed(old, ns(1), b"n", other, false);
        assert!(matches!(r, Err(VesselError::Closed { .. })));
        // …the same one finishes.
        let (old, _) = e.host.ensure(ns(1), b"u").unwrap();
        let new = e.host.succeed(old, ns(1), b"n", auth(), false).unwrap().successor;
        assert_eq!(new.id(), new_id);
        assert!(matches!(new.lineage().origin, Origin::Succession { .. }));
    }

    // ── on a real pool ──────────────────────────────────────────────

    mod node {
        use super::*;
        use crate::zfs::Cli;
        use std::process::Command;

        #[test]
        #[ignore = "needs a ZFS pool: set TASO_ZFS_DATASET"]
        fn void_birth_fork_and_succession_on_zfs() {
            let base = std::env::var("TASO_ZFS_DATASET").expect("set TASO_ZFS_DATASET");
            let root = format!("{base}/vs-{}", std::process::id());
            let zfs = Zfs::<Cli>::cli();
            Zfs::create(&zfs, &Dataset::new(&root).unwrap()).unwrap();
            struct Cleanup(String);
            impl Drop for Cleanup {
                fn drop(&mut self) {
                    let _ = Command::new("zfs").args(["destroy", "-R", &self.0]).status();
                }
            }
            let _c = Cleanup(root.clone());

            let tmp = tempfile::tempdir().unwrap();
            let host = Host {
                coord: Arc::new(Coordinator::open(tmp.path().join("coord.redb")).unwrap()),
                pool: zfs,
                root: Dataset::new(&root).unwrap(),
                state_dir: tmp.path().join("state"),
                warden: WardenId::new(1),
            };

            let (mut v, _) = host.ensure(ns(1), b"user-1").unwrap();
            let mount = host.pool.dataset_info(v.dataset()).unwrap().unwrap().mountpoint.unwrap();
            std::fs::write(mount.join("notes.txt"), b"mine").unwrap();
            let s = seal(&mut v);

            let child = host.fork(&v, s, b"user-1-fork").unwrap();
            let cm = host.pool.dataset_info(child.dataset()).unwrap().unwrap().mountpoint.unwrap();
            assert_eq!(std::fs::read(cm.join("notes.txt")).unwrap(), b"mine");
            drop(child);

            let Succeeded { successor: new, predecessor: old } =
                host.succeed(v, ns(1), b"user-2", auth(), false).unwrap();
            let nm = host.pool.dataset_info(new.dataset()).unwrap().unwrap().mountpoint.unwrap();
            assert_eq!(std::fs::read(nm.join("notes.txt")).unwrap(), b"mine");
            let (new_id, old_id) = (new.id(), old.id());
            drop((new, old));

            let (old, _) = host.open(old_id).unwrap();
            assert_eq!(old.successor().unwrap().successor, new_id);
            let (new, _) = host.open(new_id).unwrap();
            println!("successor lineage: {:?}", new.lineage());
        }
    }
}
