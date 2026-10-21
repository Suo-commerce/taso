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
//! # Publishing a Seal
//!
//! A Seal is something rebirth can rebuild only once it is off the node
//! and anchored.  [`Vessel::publish_seal`] does it in an order that a
//! retry of the same call finishes from any crash:
//!
//! 1. ship the Seal's pack (its log section and `fs` stream);
//! 2. append the `FsShipped` record that names the section;
//! 3. ship the log up to the tail, the record included;
//! 4. advance the coordinator's shipped anchor to the tail.
//!
//! A crash after 1 leaves the section unnamed: nothing uses it, and the
//! retry ships it again under the same key.  A crash after 2 or 3 leaves
//! the record local or shipped but not anchored: the retry finds the
//! section named, and only ships the log and advances.
//!
//! Normative references: v0.4 §3 (Lineage), §7.4 (barriers), §8; v1.0 §3.

use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;

use taso_core::decode::DecodeError;
use taso_core::envelope::{ChronicleHead, ChronicleId, HashVal, Lsn, Stream};
use taso_core::model::WardenId;
use taso_core::record::{
    vessel_id, Authority, LineageRecord, Namespace, OpId, Origin, ParentSeal, Payload, StreamCut,
    SuccessionRecord, TurnId, Verdict,
};

use crate::chronicle::{
    Chronicle, ChronicleError, Claim, LayerError, Layers, Recovery, Sealed, ZfsLayers,
};
use crate::coordinator::{Coord, CoordError};
use crate::pack::{PackError, Packs};
use crate::segment::{Frame, Position};
use crate::ship::{ObjectStore, Sender};
use crate::zfs::{CloneBase, Dataset, DatasetInfo, Runner, Snapshot, Zfs};
use taso_core::record::FsShippedRecord;

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
    /// Receive a stream into `dataset` (rebirth): a full one into a new
    /// dataset (`from` is `None`), or an incremental from its Seal
    /// snapshot `from`.  The result is the Seal snapshot `to`, bound to its
    /// hash.  A stream that fails as it is read leaves nothing.  Calling it
    /// again for a snapshot already there binds it and returns.  Returns
    /// the snapshot's guid.
    fn receive(
        &self,
        dataset: &Dataset,
        from: Option<(Lsn, HashVal)>,
        to: (Lsn, HashVal),
        stream: &mut dyn std::io::Read,
    ) -> Result<u64, LayerError>;
    /// Receive a stream that is incremental from another dataset's Seal
    /// snapshot (`base`, a Template's) into the new clone `dataset`.  As
    /// [`Pool::receive`] otherwise.
    fn receive_clone(
        &self,
        dataset: &Dataset,
        base: &CloneBase,
        to: (Lsn, HashVal),
        stream: &mut dyn std::io::Read,
    ) -> Result<u64, LayerError>;
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

    fn receive(
        &self,
        dataset: &Dataset,
        from: Option<(Lsn, HashVal)>,
        to: (Lsn, HashVal),
        stream: &mut dyn std::io::Read,
    ) -> Result<u64, LayerError> {
        Ok(Zfs::receive(self, dataset, from, to, stream)?.guid)
    }

    fn receive_clone(
        &self,
        dataset: &Dataset,
        base: &CloneBase,
        to: (Lsn, HashVal),
        stream: &mut dyn std::io::Read,
    ) -> Result<u64, LayerError> {
        Ok(Zfs::receive_clone(self, dataset, base, to, stream)?.guid)
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
    /// Shipping to the store failed.
    Pack(PackError),
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
    /// The Seal's record is no longer in the local log (its segment was
    /// pruned after a Checkpoint); it is in the store.
    SealNotLocal(Position),
    /// The Seal is accepted but its layer is not on this node.
    LayerMissing(Position),
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
    /// Lineage, Succession, Gap and FsShipped records are written by the
    /// Warden only.
    ReservedPayload,
    /// The snapshot is not a Seal layer of this Vessel.
    NotThisSeal(String),
    /// Rebirth: nothing of this Vessel is anchored as shipped.
    NothingShipped(ChronicleId),
    /// Rebirth: the parent's Seal snapshot (a Template's) is not on this
    /// node, or not with that hash.
    ParentMissing(ParentSeal),
    /// Rebirth: a dataset of this Vessel is already here and is not a
    /// rebirth of this chain in progress.
    LocalState(String),
    /// A birth Seal was asked for, but the Vessel already has a Seal.
    AlreadySealed(Position),
    /// A birth Seal was asked for, but records follow the Lineage record:
    /// something ran without a Seal, and freezing that would make a
    /// half-done state the level to step up from.
    NotPristine(Position),
    /// Rebirth: a received snapshot is not the one the Seal was taken from.
    WrongSnapshot {
        /// The Seal.
        seal: Lsn,
        /// The guid the shipped chain names.
        expected: u64,
        /// The guid received.
        got: u64,
    },
}

impl fmt::Display for VesselError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Chronicle(e) => write!(f, "chronicle: {e}"),
            Self::Coord(e) => write!(f, "coordinator: {e}"),
            Self::Pack(e) => write!(f, "pack: {e}"),
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
            Self::SealNotLocal(p) => write!(f, "the Seal at lsn {} was pruned from the local log", p.lsn.get()),
            Self::LayerMissing(p) => write!(f, "the layer of Seal {} is not on this node", p.lsn.get()),
            Self::NoSeal => write!(f, "vessel has no Seal"),
            Self::AlreadySealed(p) => write!(f, "vessel already has a Seal (lsn {}): no birth Seal", p.lsn.get()),
            Self::NotPristine(tail) => write!(
                f,
                "vessel has no Seal but records up to lsn {} after its Lineage: no birth Seal over unsealed work",
                tail.lsn.get()
            ),
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
            Self::ReservedPayload => write!(f, "Lineage, Succession, Gap, FsShipped and Checkpoint records are reserved"),
            Self::NotThisSeal(why) => write!(f, "not a Seal of this vessel: {why}"),
            Self::NothingShipped(id) => write!(f, "nothing of vessel {} is shipped and anchored", hex(id)),
            Self::ParentMissing(p) => write!(
                f,
                "the parent Seal {} of vessel {} is not on this node",
                p.seal.get(),
                hex(&p.chronicle)
            ),
            Self::LocalState(why) => write!(f, "local state in the way: {why}"),
            Self::WrongSnapshot { seal, expected, got } => {
                write!(f, "Seal {} was received with guid {got}, not {expected}", seal.get())
            }
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
    pub coord: Arc<dyn Coord>,
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
    Opened(Box<Recovery>),
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
        self.ensure_as(namespace, subject, Claim::Mine)
    }

    /// [`Host::ensure`] opening a found Vessel on `claim` (a takeover of
    /// the ownership the caller read, or its own).  A birth, or the end
    /// of an interrupted one, is always this Warden's own.
    pub fn ensure_as(
        &self,
        namespace: Namespace,
        subject: &[u8],
        claim: Claim,
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
                let (v, r) = self.open_with(id, Some(namespace), false, claim)?;
                Ok((v, Ensured::Opened(Box::new(r))))
            }
        }
    }

    /// Open an existing Vessel by id, in whatever namespace it is, as
    /// this Warden's own.
    pub fn open(&self, id: ChronicleId) -> Result<(Vessel<P::Layers>, Recovery), VesselError> {
        self.open_in(id, None)
    }

    /// [`Host::open`] on `claim`.
    pub fn open_as(
        &self,
        id: ChronicleId,
        claim: Claim,
    ) -> Result<(Vessel<P::Layers>, Recovery), VesselError> {
        self.open_with(id, None, false, claim)
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
        parent.layer_present(seal)?;
        let namespace = parent.namespace();
        let id = vessel_id(namespace, subject);
        let ps = ParentSeal {
            chronicle: parent.id(),
            seal: seal.lsn,
            seal_hash: seal.hash,
        };
        let lineage = LineageRecord {
            origin: Origin::Fork { parent: ps },
            namespace,
            ledger_pos,
        };
        let mut chronicle = self.unborn(id, Some((&parent.dataset, ps)))?;
        chronicle.append(Stream::Ctl, Payload::Lineage(lineage.clone()))?;
        Ok(Vessel {
            id,
            dataset: self.dataset_for(id),
            lineage,
            successor: None,
            chronicle,
        })
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
        let (successor, predecessor) = self.succeed_inner(
            old,
            namespace,
            subject,
            authority,
            allow_cross_namespace,
            false,
        )?;
        Ok(Succeeded {
            successor: successor.expect("ran to the end"),
            predecessor,
        })
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
                if !self
                    .pool
                    .layers(&dataset)
                    .list()
                    .map_err(pool_err)?
                    .is_empty()
                {
                    return Err(VesselError::DatasetConflict(dataset));
                }
            }
            Some(_) => return Err(VesselError::DatasetConflict(dataset)),
        }
        let mut chronicle = self.chronicle(id, registered)?;
        let lineage = LineageRecord {
            origin: Origin::Void,
            namespace,
            ledger_pos: Lsn::new(0),
        };
        chronicle.append(Stream::Ctl, Payload::Lineage(lineage.clone()))?;
        Ok(Vessel {
            id,
            dataset,
            lineage,
            successor: None,
            chronicle,
        })
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

    /// Open a Vessel whose local log may end before the anchored head
    /// (rebirth): [`Chronicle::open_after_gap`], with every check of
    /// [`Host::open`].
    pub(crate) fn open_after_gap(
        &self,
        id: ChronicleId,
    ) -> Result<(Vessel<P::Layers>, Recovery), VesselError> {
        self.open_with(id, None, true, Claim::Mine)
    }

    fn open_in(
        &self,
        id: ChronicleId,
        expected: Option<Namespace>,
    ) -> Result<(Vessel<P::Layers>, Recovery), VesselError> {
        self.open_with(id, expected, false, Claim::Mine)
    }

    fn open_with(
        &self,
        id: ChronicleId,
        expected: Option<Namespace>,
        after_gap: bool,
        claim: Claim,
    ) -> Result<(Vessel<P::Layers>, Recovery), VesselError> {
        let dataset = self.dataset_for(id);
        let dir = self.dir_for(id);
        let layers = self.pool.layers(&dataset);
        let (chronicle, recovery) = if after_gap {
            Chronicle::open_after_gap_as(&dir, self.coord.clone(), id, self.warden, layers, claim)?
        } else {
            Chronicle::open_as(&dir, self.coord.clone(), id, self.warden, layers, claim)?
        };
        if chronicle.tail().lsn == Lsn::new(0) {
            return Err(VesselError::IncompleteBirth(id));
        }
        let frames = chronicle.frames().map_err(ChronicleError::Segment)?;
        let (lineage, successor) = read_lineage(&frames)?;
        if let Some(expected) = expected {
            if lineage.namespace != expected {
                return Err(VesselError::NamespaceMismatch {
                    expected,
                    found: lineage.namespace,
                });
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
                    return Err(VesselError::LineageMismatch(
                        "void-born vessel has a parent dataset",
                    ));
                }
            }
            Some(ps) => {
                if info.parent != Some(ps.seal_hash) {
                    return Err(VesselError::LineageMismatch(
                        "taso:parent is not the lineage Seal",
                    ));
                }
                if info.origin_seal() != Some((self.dataset_for(ps.chronicle), ps.seal)) {
                    return Err(VesselError::LineageMismatch(
                        "origin is not the lineage Seal",
                    ));
                }
            }
        }
        Ok((
            Vessel {
                id,
                dataset,
                lineage,
                successor,
                chronicle,
            },
            recovery,
        ))
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
        old.layer_present(seal)?;
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
            Some(s) => {
                return Err(VesselError::Closed {
                    successor: s.successor,
                })
            }
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

        let ps = ParentSeal {
            chronicle: old.id(),
            seal: seal.lsn,
            seal_hash: seal.hash,
        };
        let mut chronicle = self.unborn(id, Some((&old.dataset, ps)))?;
        if !resuming {
            old.chronicle
                .append(Stream::Ctl, Payload::Succession(record.clone()))?;
            old.successor = Some(record);
        }
        if stop_after_close {
            return Ok((None, old));
        }
        let lineage = LineageRecord {
            origin: Origin::Succession {
                parent: ps,
                authority,
            },
            namespace,
            ledger_pos,
        };
        chronicle.append(Stream::Ctl, Payload::Lineage(lineage.clone()))?;
        let new = Vessel {
            id,
            dataset: self.dataset_for(id),
            lineage,
            successor: None,
            chronicle,
        };
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

/// The turn of the birth Seal ([`Vessel::seal_birth`]).  It belongs to
/// the Warden: an agent's turns start at 1.
pub const BIRTH_TURN: TurnId = TurnId::new(0);

/// A succession that may have stopped after closing the predecessor
/// (test hook for the crash point).
type Partial<L> = (Option<Vessel<L>>, Vessel<L>);

// ── Vessel ──────────────────────────────────────────────────────────

/// What [`Vessel::publish_seal`] did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealPublished {
    /// The `FsShipped` record it appended; `None` if an earlier call had
    /// (a retry after a crash).
    pub record: Option<FsShippedRecord>,
    /// The coordinator's shipped anchor afterwards: the tail.
    pub anchor: Position,
}

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

    /// Judge resuming from the Seal at `seal` against this Vessel's log
    /// and the coordinator's anchor
    /// ([`crate::navigate::navigate_frames`]).
    ///
    /// The Navigator reads the log from genesis.  If older segments were
    /// pruned (amendment 17), the shipped history comes from `packs`,
    /// verified up to the shipped anchor, and the local records after it
    /// follow; the store is read only then.
    pub fn navigate<S: ObjectStore, X: Sender>(
        &self,
        packs: &Packs<S, X>,
        seal: Lsn,
    ) -> Result<taso_core::navigator::Navigation, VesselError> {
        let local = self.frames()?;
        let pruned = self
            .chronicle
            .segments()
            .first()
            .is_some_and(|s| s.base() != Position::GENESIS);
        let frames = if pruned {
            let shipped = self
                .chronicle
                .coord()
                .shipped(self.id())
                .map_err(VesselError::Coord)?;
            let mut chain = packs.chain(Some(shipped)).map_err(VesselError::Pack)?;
            chain
                .frames
                .extend(local.into_iter().filter(|f| f.envelope.lsn > chain.end.lsn));
            chain.frames
        } else {
            local
        };
        crate::navigate::navigate_frames(self.chronicle.coord().as_ref(), self.id(), &frames, seal)
            .map_err(VesselError::Coord)
    }

    /// The last accepted Seal.
    pub fn last_seal(&self) -> Option<Position> {
        self.chronicle.last_seal()
    }

    /// The Chronicle, for reading.
    pub fn chronicle(&self) -> &Chronicle<L> {
        &self.chronicle
    }

    /// Remove the oldest local segment files that are shipped, keeping
    /// `keep_closed` closed ones, after a Checkpoint
    /// ([`Chronicle::prune`]).
    pub fn prune(&mut self, keep_closed: usize) -> Result<crate::chronicle::Pruned, VesselError> {
        self.writable()?;
        Ok(self.chronicle.prune(keep_closed)?)
    }

    /// Roll to a new segment file at `bytes` ([`Chronicle::set_roll_at`]).
    pub fn set_roll_at(&mut self, bytes: u64) {
        self.chronicle.set_roll_at(bytes);
    }

    /// Append a record.  Lineage, Succession, Gap, FsShipped and Checkpoint
    /// records are refused: only the Warden writes them, each at its own
    /// step.
    pub fn append(
        &mut self,
        stream: Stream,
        payload: Payload,
    ) -> Result<ChronicleHead, VesselError> {
        self.writable()?;
        if matches!(
            payload,
            Payload::Lineage(_)
                | Payload::Succession(_)
                | Payload::Gap(_)
                | Payload::FsShipped(_)
                | Payload::Checkpoint(_)
        ) {
            return Err(VesselError::ReservedPayload);
        }
        Ok(self.chronicle.append(stream, payload)?)
    }

    /// Append records together: one write, one fsync, one CAS; all or
    /// none.  The same records are refused as by [`Vessel::append`].
    pub fn append_batch(
        &mut self,
        records: Vec<(Stream, Payload)>,
    ) -> Result<ChronicleHead, VesselError> {
        self.writable()?;
        if records.iter().any(|(_, p)| {
            matches!(
                p,
                Payload::Lineage(_)
                    | Payload::Succession(_)
                    | Payload::Gap(_)
                    | Payload::FsShipped(_)
                    | Payload::Checkpoint(_)
            )
        }) {
            return Err(VesselError::ReservedPayload);
        }
        Ok(self.chronicle.append_batch(records)?)
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

    /// Take the birth Seal: turn [`BIRTH_TURN`], an empty cut, ledger
    /// position 0, `Clean`.  It freezes the state the Vessel was born
    /// with (empty from the void; the parent's Seal for a fork or
    /// succession) so that every Vessel has a Seal before its agent ever
    /// runs: a restart always has a level to roll back to, and a Vessel is
    /// reborn elsewhere even if it dies before its first turn.
    ///
    /// Only on a pristine Vessel: refused ([`VesselError::AlreadySealed`])
    /// if it has a Seal, and ([`VesselError::NotPristine`]) if any record
    /// follows the Lineage record.  A crash between birth and this Seal
    /// leaves exactly the pristine case, so taking it again is the
    /// recovery.
    pub fn seal_birth(&mut self) -> Result<Sealed, VesselError> {
        self.writable()?;
        if let Some(s) = self.last_seal() {
            return Err(VesselError::AlreadySealed(s));
        }
        let tail = self.tail();
        if tail.lsn != Lsn::new(1) {
            return Err(VesselError::NotPristine(tail));
        }
        Ok(self
            .chronicle
            .seal(StreamCut::EMPTY, Verdict::Clean, Lsn::new(0), BIRTH_TURN)?)
    }

    /// Roll the state back to the newest Seal whose layer is here
    /// ([`Chronicle::rollback_to_last_seal`]): what was written after it is
    /// discarded.  Returns that Seal, or `None` if there is none.  The
    /// caller must make sure nothing is writing (no agent running).
    pub fn rollback(&mut self) -> Result<Option<Position>, VesselError> {
        self.writable()?;
        Ok(self.chronicle.rollback_to_last_seal()?)
    }

    /// Take a Seal, refused if `check` fails once the layer is frozen (see
    /// [`Chronicle::seal_checked`]).
    pub fn seal_checked(
        &mut self,
        cut: StreamCut,
        verdict: Verdict,
        ledger_pos: Lsn,
        turn: TurnId,
        check: impl FnOnce() -> Result<(), String>,
    ) -> Result<Sealed, VesselError> {
        self.writable()?;
        Ok(self
            .chronicle
            .seal_checked(cut, verdict, ledger_pos, turn, check)?)
    }

    /// Publish the Seal whose layer is `snapshot` (see the module docs):
    /// its pack, the `FsShipped` record naming its section, the log up to
    /// the tail, and the coordinator's shipped anchor there.  `origin` is
    /// the parent's Seal snapshot, for a forked or succeeded Vessel's first
    /// Seal only.  Calling it again for the same Seal finishes an
    /// interrupted publish; on success the Seal is anchored.
    pub fn publish_seal<S: ObjectStore, X: Sender>(
        &mut self,
        packs: &Packs<S, X>,
        snapshot: &Snapshot,
        origin: Option<&Snapshot>,
    ) -> Result<SealPublished, VesselError> {
        let _total = crate::timing::span("publish.total");
        self.writable()?;
        if snapshot.dataset != self.dataset {
            return Err(VesselError::NotThisSeal(format!(
                "{} is not this Vessel's dataset",
                snapshot.dataset
            )));
        }
        let hash = snapshot
            .seal_hash
            .ok_or_else(|| VesselError::NotThisSeal("the snapshot is not bound".into()))?;
        let t = crate::timing::span("publish.check");
        let is_seal = self
            .chronicle
            .frame(snapshot.seal)
            .map_err(ChronicleError::Segment)?
            .is_some_and(|f| {
                f.envelope.hash == hash
                    && matches!(Payload::decode(&f.payload), Ok(Payload::Seal(_)))
            });
        if !is_seal {
            return Err(VesselError::NotThisSeal(format!(
                "lsn {} is not a Seal record with this hash",
                snapshot.seal.get()
            )));
        }
        self.layer_present(Position {
            lsn: snapshot.seal,
            hash,
        })?;
        drop(t);
        let t = crate::timing::span("publish.seal_pack");
        let shipped = packs
            .ship_seal(&self.chronicle.segments(), snapshot, origin)
            .map_err(VesselError::Pack)?;
        drop(t);
        let record = match shipped {
            Some(s) => {
                self.chronicle
                    .append(Stream::Ctl, Payload::FsShipped(s.record.clone()))?;
                Some(s.record)
            }
            None => None,
        };
        let tail = self.chronicle.tail();
        let t = crate::timing::span("publish.log");
        packs
            .ship_log(&self.chronicle.segments(), tail)
            .map_err(VesselError::Pack)?;
        drop(t);
        let _t = crate::timing::span("publish.advance");
        let anchor = self
            .chronicle
            .coord()
            .advance_shipped(
                self.chronicle.warden(),
                self.id,
                self.chronicle.epoch(),
                tail,
            )
            .map_err(VesselError::Coord)?;
        Ok(SealPublished { record, anchor })
    }

    /// Refuse a Seal whose layer was missing at open.
    fn layer_present(&self, seal: Position) -> Result<(), VesselError> {
        if self.chronicle.layer_missing(seal.lsn) {
            return Err(VesselError::LayerMissing(seal));
        }
        Ok(())
    }

    fn writable(&self) -> Result<(), VesselError> {
        match &self.successor {
            Some(s) => Err(VesselError::Closed {
                successor: s.successor,
            }),
            None => Ok(()),
        }
    }

    fn frames(&self) -> Result<Vec<Frame>, VesselError> {
        Ok(self.chronicle.frames().map_err(ChronicleError::Segment)?)
    }
}

// ── Reading records ─────────────────────────────────────────────────

fn decode(frame: &Frame) -> Result<Payload, VesselError> {
    Payload::decode(&frame.payload).map_err(|error| VesselError::Decode {
        lsn: frame.envelope.lsn,
        error,
    })
}

/// The Lineage record (lsn 1) and the Succession record, if it ends the
/// Chronicle.  Refuses a second Lineage and anything after a Succession.
fn read_lineage(
    frames: &[Frame],
) -> Result<(LineageRecord, Option<SuccessionRecord>), VesselError> {
    let first = frames
        .first()
        .ok_or(VesselError::NotAVessel("no records"))?;
    // From lsn 1, or (older segments pruned) from the newest Checkpoint.
    let (lineage, rest) = if first.envelope.lsn == Lsn::new(1) {
        if first.envelope.stream != Stream::Ctl {
            return Err(VesselError::NotAVessel("lsn 1 is not a Ctl record"));
        }
        let Payload::Lineage(lineage) = decode(first)? else {
            return Err(VesselError::NotAVessel("lsn 1 is not a Lineage record"));
        };
        (lineage, &frames[1..])
    } else {
        let s = summary(frames)?;
        match (s.from_checkpoint, s.lineage) {
            (Some(_), Some(l)) => (l, frames),
            _ => {
                return Err(VesselError::NotAVessel(
                    "the log does not start at lsn 1 and holds no Checkpoint",
                ))
            }
        }
    };
    let mut successor = None;
    for (i, f) in rest.iter().enumerate() {
        if f.envelope.stream != Stream::Ctl {
            continue;
        }
        match decode(f)? {
            Payload::Lineage(_) => return Err(VesselError::NotAVessel("a second Lineage record")),
            Payload::Checkpoint(c) if c.lineage != lineage => {
                return Err(VesselError::NotAVessel(
                    "a Checkpoint disagrees with the Lineage",
                ))
            }
            Payload::Succession(s) => {
                if i + 1 != rest.len() {
                    return Err(VesselError::NotAVessel("records after a Succession record"));
                }
                successor = Some(s);
            }
            _ => {}
        }
    }
    Ok((lineage, successor))
}

/// The fold of `frames` ([`crate::summary`]).
fn summary(frames: &[Frame]) -> Result<crate::summary::Summary, VesselError> {
    crate::summary::Summary::of(frames).map_err(|(lsn, error)| VesselError::Decode { lsn, error })
}

/// The `ledger_pos` of the accepted Seal at `seal`: from its record, or
/// from a Checkpoint if that is the Seal it names.  `SealNotLocal` if its
/// record was pruned; `NotASeal` otherwise.
fn seal_ledger_pos(frames: &[Frame], seal: Position) -> Result<Lsn, VesselError> {
    if let Some(f) = frames.iter().find(|f| f.envelope.lsn == seal.lsn) {
        if f.envelope.hash != seal.hash || f.envelope.stream != Stream::Ctl {
            return Err(VesselError::NotASeal(seal));
        }
        return match decode(f)? {
            Payload::Seal(s) => Ok(s.ledger_pos),
            _ => Err(VesselError::NotASeal(seal)),
        };
    }
    let s = summary(frames)?;
    match s.seal {
        Some(c) if c.lsn == seal.lsn && c.hash == seal.hash => Ok(c.ledger_pos),
        _ if frames.first().is_some_and(|f| seal.lsn < f.envelope.lsn) => {
            Err(VesselError::SealNotLocal(seal))
        }
        _ => Err(VesselError::NotASeal(seal)),
    }
}

/// Effects whose intent set a barrier and whose latest outcome is not
/// terminal (`ConfirmedApplied` / `ConfirmedNotApplied`), in op order.
fn open_obligations(frames: &[Frame]) -> Result<Vec<OpId>, VesselError> {
    Ok(summary(frames)?
        .open
        .into_iter()
        .filter(|(_, e)| e.intent.barrier.is_some())
        .map(|(op, _)| op)
        .collect())
}

fn hex(id: &ChronicleId) -> String {
    id.as_bytes().iter().map(|b| format!("{b:02x}")).collect()
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::coordinator::Coordinator;
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::rc::Rc;
    use taso_core::record::OutcomeState;
    use taso_core::record::{
        BarrierId, Consequence, Dispatch, IntentRecord, OutcomeRecord, RetryPolicy,
    };

    // ── an in-memory pool ───────────────────────────────────────────

    #[derive(Default)]
    pub(crate) struct FakeDs {
        origin: Option<String>,
        parent: Option<HashVal>,
        snaps: BTreeMap<Lsn, HashVal>,
        /// Streams received into it, in order (rebirth).
        pub(crate) received: Vec<Vec<u8>>,
        /// Every rollback, by target lsn.
        pub(crate) rolled_back: Vec<Lsn>,
    }

    /// A Seal snapshot's guid in the fake pool: the same wherever it was
    /// taken or received, as with ZFS.
    pub(crate) fn fake_guid(seal: Lsn) -> u64 {
        1000 + seal.get()
    }

    #[derive(Clone, Default)]
    pub(crate) struct FakePool(Rc<RefCell<BTreeMap<String, FakeDs>>>);

    pub(crate) struct FakeLayers {
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
        /// The Seal snapshots of `name`, `(lsn, hash)`, in order.
        pub(crate) fn snaps_of(&self, name: &str) -> Vec<(Lsn, HashVal)> {
            self.0
                .borrow()
                .get(name)
                .map(|d| d.snaps.iter().map(|(&l, &h)| (l, h)).collect())
                .unwrap_or_default()
        }
        /// The streams received into `name`.
        pub(crate) fn received_of(&self, name: &str) -> Vec<Vec<u8>> {
            self.0
                .borrow()
                .get(name)
                .map(|d| d.received.clone())
                .unwrap_or_default()
        }
        /// Put a dataset with one Seal snapshot here, as if received from
        /// another node (a Template on node B).
        pub(crate) fn put_snapshot(&self, name: &str, seal: Lsn, hash: HashVal) {
            self.0
                .borrow_mut()
                .entry(name.to_string())
                .or_default()
                .snaps
                .insert(seal, hash);
        }
        /// Remove a dataset (a test's stale state).
        pub(crate) fn remove(&self, name: &str) {
            self.0.borrow_mut().remove(name);
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
            let bound = self
                .0
                .borrow()
                .get(source.as_str())
                .and_then(|d| d.snaps.get(&seal).copied());
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
                    received: Vec::new(),
                    rolled_back: Vec::new(),
                },
            );
            Ok(self.info_of(target.as_str()).unwrap())
        }
        fn info(&self, dataset: &Dataset) -> Result<Option<DatasetInfo>, LayerError> {
            Ok(self.info_of(dataset.as_str()))
        }
        fn layers(&self, dataset: &Dataset) -> FakeLayers {
            FakeLayers {
                pool: Clone::clone(self),
                ds: dataset.to_string(),
            }
        }
        fn receive(
            &self,
            dataset: &Dataset,
            from: Option<(Lsn, HashVal)>,
            to: (Lsn, HashVal),
            stream: &mut dyn std::io::Read,
        ) -> Result<u64, LayerError> {
            let name = dataset.to_string();
            if let Some(h) = self
                .0
                .borrow()
                .get(&name)
                .and_then(|d| d.snaps.get(&to.0).copied())
            {
                return if h == to.1 {
                    Ok(fake_guid(to.0))
                } else {
                    Err("another snapshot at that Seal".into())
                };
            }
            let exists = self.0.borrow().contains_key(&name);
            match from {
                None if exists => return Err("exists".into()),
                Some(_) if !exists => return Err("no dataset to receive into".into()),
                Some((l, h)) if self.0.borrow()[&name].snaps.get(&l) != Some(&h) => {
                    return Err("no such base".into())
                }
                _ => {}
            }
            let mut bytes = Vec::new();
            stream.read_to_end(&mut bytes)?; // a failing stream leaves nothing
            let mut p = self.0.borrow_mut();
            let d = p.entry(name).or_default();
            d.snaps.insert(to.0, to.1);
            d.received.push(bytes);
            Ok(fake_guid(to.0))
        }
        fn receive_clone(
            &self,
            dataset: &Dataset,
            base: &CloneBase,
            to: (Lsn, HashVal),
            stream: &mut dyn std::io::Read,
        ) -> Result<u64, LayerError> {
            let name = dataset.to_string();
            if self
                .0
                .borrow()
                .get(&name)
                .is_some_and(|d| d.snaps.get(&to.0) == Some(&to.1))
            {
                return Ok(fake_guid(to.0));
            }
            let bound = self
                .0
                .borrow()
                .get(base.dataset.as_str())
                .and_then(|d| d.snaps.get(&base.seal).copied());
            if bound != Some(base.hash) || base.guid != fake_guid(base.seal) {
                return Err("no such base".into());
            }
            if self.0.borrow().contains_key(&name) {
                return Err("exists".into());
            }
            let mut bytes = Vec::new();
            stream.read_to_end(&mut bytes)?;
            let mut snaps = BTreeMap::new();
            snaps.insert(to.0, to.1);
            self.0.borrow_mut().insert(
                name,
                FakeDs {
                    origin: Some(base.dataset.seal_snapshot(base.seal)),
                    parent: Some(base.hash),
                    snaps,
                    received: vec![bytes],
                    rolled_back: Vec::new(),
                },
            );
            Ok(fake_guid(to.0))
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
            // As `zfs list`: a dataset that does not exist is an error.
            let p = self.pool.0.borrow();
            let d = p
                .get(&self.ds)
                .ok_or_else(|| format!("{}: dataset does not exist", self.ds))?;
            Ok(d.snaps.iter().map(|(&l, &h)| (l, h)).collect())
        }
        fn destroy(&mut self, lsn: Lsn) -> Result<(), LayerError> {
            if let Some(d) = self.pool.0.borrow_mut().get_mut(&self.ds) {
                d.snaps.remove(&lsn);
            }
            Ok(())
        }
        /// Like `zfs rollback`: the layer must be there with this hash,
        /// and nothing later may exist.
        fn rollback(&mut self, lsn: Lsn, hash: HashVal) -> Result<(), LayerError> {
            let mut p = self.pool.0.borrow_mut();
            let d = p.get_mut(&self.ds).ok_or("no dataset")?;
            if d.snaps.get(&lsn) != Some(&hash) {
                return Err(format!("no layer {} with that hash", lsn.get()).into());
            }
            if d.snaps.range(lsn.next()..).next().is_some() {
                return Err("more recent layers exist".into());
            }
            d.rolled_back.push(lsn);
            Ok(())
        }
    }

    impl FakePool {
        fn rolled_back(&self, ds: &Dataset) -> Vec<Lsn> {
            self.0
                .borrow()
                .get(ds.as_str())
                .map(|d| d.rolled_back.clone())
                .unwrap_or_default()
        }
    }

    // ── fixtures ────────────────────────────────────────────────────

    pub(crate) struct Env {
        _tmp: tempfile::TempDir,
        pub(crate) host: Host<FakePool>,
    }

    pub(crate) fn env() -> Env {
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

    pub(crate) fn ns(b: u8) -> Namespace {
        Namespace::from_bytes([b; 16])
    }

    fn auth() -> Authority {
        Authority {
            actor: "jarmo".into(),
            reason: "accounts merged".into(),
        }
    }

    fn raw(n: u8) -> Payload {
        Payload::Raw(vec![n; 4])
    }

    fn seal<L: Layers>(v: &mut Vessel<L>) -> Position {
        v.seal(
            StreamCut::EMPTY,
            Verdict::Clean,
            Lsn::new(0),
            TurnId::new(1),
        )
        .unwrap()
        .seal
    }

    // ── birth Seal and rollback ─────────────────────────────────────

    fn seal_record<L: Layers>(v: &Vessel<L>, at: Position) -> taso_core::record::SealRecord {
        let frames = v.frames().unwrap();
        let f = frames.iter().find(|f| f.envelope.lsn == at.lsn).unwrap();
        match Payload::decode(&f.payload).unwrap() {
            Payload::Seal(s) => s,
            other => panic!("{other:?}"),
        }
    }

    /// A void-born Vessel's birth Seal: right after Lineage, turn 0, an
    /// empty cut, Clean, with its layer.
    #[test]
    fn the_birth_seal_follows_lineage() {
        let e = env();
        let (mut v, _) = e.host.ensure(ns(1), b"user-1").unwrap();
        let b = v.seal_birth().unwrap().seal;
        assert_eq!(b.lsn, Lsn::new(2));
        assert_eq!(v.last_seal(), Some(b));
        let rec = seal_record(&v, b);
        assert_eq!(
            (rec.turn, rec.cut, rec.ledger_pos, rec.verdict),
            (BIRTH_TURN, StreamCut::EMPTY, Lsn::new(0), Verdict::Clean)
        );
        assert_eq!(rec.turn.get(), 0, "turn 0: an agent's turns start at 1");
        assert_eq!(rec.parent, None, "the first Seal");
        assert_eq!(
            v.chronicle().layers().list().unwrap(),
            vec![(b.lsn, b.hash)]
        );
        // Kept across a reopen.
        drop(v);
        let (v, _) = e.host.ensure(ns(1), b"user-1").unwrap();
        assert_eq!(v.last_seal(), Some(b));
    }

    /// A fork's birth Seal freezes the parent's Seal state as its own
    /// first layer.
    #[test]
    fn a_fork_takes_its_birth_seal() {
        let e = env();
        let (mut parent, _) = e.host.ensure(ns(1), b"parent").unwrap();
        parent.append(Stream::Fs, raw(1)).unwrap();
        let s = seal(&mut parent);
        let mut child = e.host.fork(&parent, s, b"child").unwrap();
        let b = child.seal_birth().unwrap().seal;
        assert_eq!(b.lsn, Lsn::new(2));
        assert_eq!(seal_record(&child, b).turn, BIRTH_TURN);
        assert_eq!(
            child.chronicle().layers().list().unwrap(),
            vec![(b.lsn, b.hash)]
        );
    }

    /// Only once, and only before anything else was recorded.
    #[test]
    fn the_birth_seal_is_refused_unless_pristine() {
        let e = env();
        let (mut v, _) = e.host.ensure(ns(1), b"user-1").unwrap();
        let b = v.seal_birth().unwrap().seal;
        assert!(matches!(v.seal_birth(), Err(VesselError::AlreadySealed(p)) if p == b));

        let (mut w, _) = e.host.ensure(ns(1), b"user-2").unwrap();
        w.append(Stream::Transcript, raw(1)).unwrap();
        match w.seal_birth() {
            Err(VesselError::NotPristine(tail)) => assert_eq!(tail.lsn, Lsn::new(2)),
            other => panic!("{other:?}"),
        }
        assert_eq!(w.last_seal(), None, "nothing sealed");
        assert!(
            w.chronicle().layers().list().unwrap().is_empty(),
            "no layer left behind"
        );
    }

    /// Rollback goes to the last Seal (the birth Seal at first); with no
    /// Seal there is nothing to roll back to.
    #[test]
    fn rollback_goes_to_the_last_seal_from_birth_on() {
        let e = env();
        let (mut v, _) = e.host.ensure(ns(1), b"user-1").unwrap();
        assert_eq!(v.rollback().unwrap(), None);
        assert!(e.host.pool.rolled_back(v.dataset()).is_empty());
        let b = v.seal_birth().unwrap().seal;
        v.append(Stream::Transcript, raw(1)).unwrap();
        assert_eq!(v.rollback().unwrap(), Some(b));
        let s = seal(&mut v);
        assert_eq!(v.rollback().unwrap(), Some(s));
        assert_eq!(e.host.pool.rolled_back(v.dataset()), vec![b.lsn, s.lsn]);
    }

    /// A closed Vessel neither takes a birth Seal nor rolls back.
    #[test]
    fn a_closed_vessel_refuses_birth_seal_and_rollback() {
        let e = env();
        let (mut old, _) = e.host.ensure(ns(1), b"user-old").unwrap();
        seal(&mut old);
        let Succeeded {
            predecessor: mut old,
            ..
        } = e
            .host
            .succeed(old, ns(1), b"user-new", auth(), false)
            .unwrap();
        assert!(matches!(old.seal_birth(), Err(VesselError::Closed { .. })));
        assert!(matches!(old.rollback(), Err(VesselError::Closed { .. })));
        assert!(e.host.pool.rolled_back(old.dataset()).is_empty());
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
        assert!(matches!(
            e.host.open(id),
            Err(VesselError::IncompleteBirth(_))
        ));

        let (v, how) = e.host.ensure(ns(1), b"user-1").unwrap();
        assert!(matches!(how, Ensured::BirthFinished));
        assert_eq!(v.lineage().origin, Origin::Void);
    }

    #[test]
    fn foreign_dataset_in_the_way_is_refused() {
        let e = env();
        let id = vessel_id(ns(1), b"user-1");
        e.host.pool.create(&e.host.dataset_for(id)).unwrap();
        e.host.pool.set_parent(
            e.host.dataset_for(id).as_str(),
            Some(HashVal::from_bytes([3; 32])),
        );
        assert!(matches!(
            e.host.ensure(ns(1), b"user-1"),
            Err(VesselError::DatasetConflict(_))
        ));
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
        e.host.pool.set_parent(
            e.host.dataset_for(id).as_str(),
            Some(HashVal::from_bytes([3; 32])),
        );
        assert!(matches!(
            e.host.open(id),
            Err(VesselError::LineageMismatch(_))
        ));
    }

    #[test]
    fn reserved_payloads_are_refused() {
        let e = env();
        let (mut v, _) = e.host.ensure(ns(1), b"user-1").unwrap();
        let l = v.lineage().clone();
        assert!(matches!(
            v.append(Stream::Ctl, Payload::Lineage(l.clone())),
            Err(VesselError::ReservedPayload)
        ));
        let tail = v.tail();
        assert!(matches!(
            v.append_batch(vec![
                (Stream::Fs, raw(1)),
                (Stream::Ctl, Payload::Lineage(l))
            ]),
            Err(VesselError::ReservedPayload)
        ));
        assert_eq!(v.tail(), tail, "nothing of a refused batch is written");
    }

    // ── publishing a Seal ───────────────────────────────────────────

    mod publish {
        use super::*;
        use crate::pack::{FsBase, Packs, ShippedFs};
        use crate::ship::{ByteStream, LocalStore, ObjectStore, Sender};
        use crate::zfs::Snapshot;
        use std::io::{self, Read};
        use std::sync::atomic::{AtomicBool, Ordering};
        use taso_core::envelope::{Envelope, Epoch};
        use taso_core::model::Ownership;
        use taso_core::record::{GapRecord, StreamBase};

        /// The coordinator, with `advance_shipped` failing on demand.
        struct Flaky {
            inner: Coordinator,
            fail_advance: AtomicBool,
        }

        impl Coord for Flaky {
            fn register(&self, c: ChronicleId, h: WardenId) -> Result<ChronicleHead, CoordError> {
                self.inner.register(c, h)
            }
            fn append(&self, w: WardenId, e: &Envelope) -> Result<ChronicleHead, CoordError> {
                self.inner.append(w, e)
            }
            fn append_batch(
                &self,
                w: WardenId,
                es: &[Envelope],
            ) -> Result<ChronicleHead, CoordError> {
                self.inner.append_batch(w, es)
            }
            fn transfer_if(
                &self,
                c: ChronicleId,
                h: WardenId,
                e: (WardenId, Epoch),
            ) -> Result<Epoch, CoordError> {
                self.inner.transfer_if(c, h, e)
            }
            fn transfer(&self, c: ChronicleId, h: WardenId) -> Result<Epoch, CoordError> {
                self.inner.transfer(c, h)
            }
            fn ownership(&self, c: ChronicleId) -> Result<Ownership, CoordError> {
                self.inner.ownership(c)
            }
            fn head(&self, c: ChronicleId) -> Result<ChronicleHead, CoordError> {
                self.inner.head(c)
            }
            fn advance_shipped(
                &self,
                w: WardenId,
                c: ChronicleId,
                e: Epoch,
                to: Position,
            ) -> Result<Position, CoordError> {
                if self.fail_advance.load(Ordering::Relaxed) {
                    return Err(CoordError::Unavailable(io::Error::other(
                        "coordinator down",
                    )));
                }
                self.inner.advance_shipped(w, c, e, to)
            }
            fn shipped(&self, c: ChronicleId) -> Result<Position, CoordError> {
                self.inner.shipped(c)
            }
        }

        /// A store whose puts fail on demand.
        struct FlakyStore {
            inner: LocalStore,
            fail_put: Arc<AtomicBool>,
        }

        impl ObjectStore for FlakyStore {
            fn put(&self, key: &str, data: &mut dyn Read) -> io::Result<u64> {
                if self.fail_put.load(Ordering::Relaxed) {
                    return Err(io::Error::other("store down"));
                }
                self.inner.put(key, data)
            }
            fn get(&self, key: &str) -> io::Result<Option<ByteStream>> {
                self.inner.get(key)
            }
            fn exists(&self, key: &str) -> io::Result<bool> {
                self.inner.exists(key)
            }
            fn list(&self, prefix: &str) -> io::Result<Vec<String>> {
                self.inner.list(prefix)
            }
        }

        /// Streams that say what they are.
        struct Fake;
        impl Sender for Fake {
            fn send(&self, d: &Dataset, from: Option<&str>, to: Lsn) -> io::Result<ByteStream> {
                Ok(Box::new(io::Cursor::new(stream(d, from, to))))
            }
        }

        fn stream(d: &Dataset, from: Option<&str>, to: Lsn) -> Vec<u8> {
            format!("{d} from {from:?} to {} ", to.get())
                .repeat(1000)
                .into_bytes()
        }

        struct P {
            _tmp: tempfile::TempDir,
            host: Host<FakePool>,
            coord: Arc<Flaky>,
            fail_put: Arc<AtomicBool>,
            packs: Packs<FlakyStore, Fake>,
        }

        fn penv(id: ChronicleId) -> P {
            let tmp = tempfile::tempdir().unwrap();
            let coord = Arc::new(Flaky {
                inner: Coordinator::open(tmp.path().join("coord.redb")).unwrap(),
                fail_advance: AtomicBool::new(false),
            });
            let host = Host {
                coord: coord.clone(),
                pool: FakePool::default(),
                root: Dataset::new("tank/vessels").unwrap(),
                state_dir: tmp.path().join("state"),
                warden: WardenId::new(1),
            };
            let fail_put = Arc::new(AtomicBool::new(false));
            let store = FlakyStore {
                inner: LocalStore::new(tmp.path().join("store")),
                fail_put: fail_put.clone(),
            };
            let packs = Packs::new(store, Fake, "vessels", id).unwrap();
            P {
                _tmp: tmp,
                host,
                coord,
                fail_put,
                packs,
            }
        }

        fn snap<L: Layers>(v: &Vessel<L>, seal: Position) -> Snapshot {
            Snapshot {
                dataset: v.dataset().clone(),
                seal: seal.lsn,
                createtxg: 1,
                guid: 1000 + seal.lsn.get(),
                seal_hash: Some(seal.hash),
            }
        }

        fn sealed(p: &P) -> (Vessel<FakeLayers>, Position) {
            let (mut v, _) = p.host.ensure(ns(1), b"user-1").unwrap();
            v.append(Stream::Fs, raw(1)).unwrap();
            let s = seal(&mut v);
            (v, s)
        }

        /// The Seal packs that hold an fs section for `seal`.
        fn seal_packs(p: &P, seal: Position) -> usize {
            let dir = format!("vessels/{}/pack", hex(&p.packs_id()));
            p.packs_store()
                .list(&dir)
                .unwrap()
                .iter()
                .filter(|k| k.ends_with(&format!("-{:020}", seal.lsn.get())))
                .count()
        }

        impl P {
            fn packs_id(&self) -> ChronicleId {
                vessel_id(ns(1), b"user-1")
            }
            fn packs_store(&self) -> LocalStore {
                LocalStore::new(self._tmp.path().join("store"))
            }
            fn read(&self, s: &ShippedFs) -> Vec<u8> {
                let mut out = Vec::new();
                self.packs
                    .open_fs(s)
                    .unwrap()
                    .unwrap()
                    .read_to_end(&mut out)
                    .unwrap();
                out
            }
        }

        /// The end state every publish must reach: the anchor is the tail,
        /// the anchored chain is the local log, and every Seal is named by
        /// exactly one pack.
        fn assert_published<L: Layers>(p: &P, v: &Vessel<L>, seals: &[Position]) {
            let anchor = p.coord.shipped(v.id()).unwrap();
            assert_eq!(anchor, v.tail());
            let c = p.packs.chain(Some(anchor)).unwrap();
            assert_eq!(c.frames, v.chronicle().frames().unwrap());
            assert_eq!(c.seals.iter().map(|s| s.fs.to).collect::<Vec<_>>(), seals);
            for s in seals {
                assert_eq!(seal_packs(p, *s), 1, "one pack per Seal");
            }
        }

        /// After a prune that removed the newest FsShipped record, the next
        /// Seal still ships incrementally from the last named one (the
        /// Checkpoint carries it), the log pack starts where the store
        /// ends, and the store's chain holds the whole history.
        #[test]
        fn publish_after_a_prune_ships_from_the_checkpoint() {
            let p = penv(vessel_id(ns(1), b"user-1"));
            let (mut v, s1) = sealed(&p);
            v.publish_seal(&p.packs, &snap(&v, s1), None).unwrap();
            v.set_roll_at(1);
            for i in 0..3 {
                v.append(Stream::Fs, raw(i)).unwrap();
            }
            let s2 = seal(&mut v);
            let r2 = v.publish_seal(&p.packs, &snap(&v, s2), None).unwrap();
            let pruned = v.prune(0).unwrap();
            assert!(!pruned.removed.is_empty());
            let first = v.frames().unwrap()[0].envelope.lsn;
            assert!(
                first > r2.anchor.lsn,
                "the FsShipped record of s2 is gone locally"
            );
            v.append(Stream::Fs, raw(9)).unwrap();
            let s3 = seal(&mut v);
            let r3 = v.publish_seal(&p.packs, &snap(&v, s3), None).unwrap();
            assert_eq!(
                r3.record.unwrap().base,
                StreamBase::Seal {
                    lsn: s2.lsn,
                    hash: s2.hash
                }
            );
            let c = p.packs.chain(Some(r3.anchor)).unwrap();
            assert_eq!(
                c.frames.first().unwrap().envelope.lsn,
                Lsn::new(1),
                "the store has everything"
            );
            assert_eq!(c.frames.last().unwrap().envelope.lsn, v.tail().lsn);
            assert_eq!(
                c.seals.iter().map(|s| s.fs.to).collect::<Vec<_>>(),
                vec![s1, s2, s3]
            );
        }

        /// After a prune the Navigator reads the shipped history from the
        /// store and the rest from the local segments.
        #[test]
        fn navigate_after_a_prune_reads_the_store() {
            use taso_core::navigator::Navigation;
            let p = penv(vessel_id(ns(1), b"user-1"));
            let (mut v, s1) = sealed(&p);
            v.publish_seal(&p.packs, &snap(&v, s1), None).unwrap();
            v.set_roll_at(1);
            for i in 0..3 {
                v.append(Stream::Fs, raw(i)).unwrap();
            }
            let s2 = seal(&mut v);
            v.publish_seal(&p.packs, &snap(&v, s2), None).unwrap();
            assert_eq!(
                v.navigate(&p.packs, s1.lsn).unwrap(),
                Navigation::Consistent(vec![])
            );
            v.prune(0).unwrap();
            assert!(
                v.frames().unwrap()[0].envelope.lsn > s2.lsn,
                "both Seal records are gone locally"
            );
            v.append(Stream::Fs, raw(9)).unwrap(); // local only, after the anchor
            let s3 = seal(&mut v);
            for s in [s1, s2, s3] {
                assert_eq!(
                    v.navigate(&p.packs, s.lsn).unwrap(),
                    Navigation::Consistent(vec![]),
                    "{s:?}"
                );
            }
            // Shipped again: now local records overlap the store's; each
            // is read once.
            v.publish_seal(&p.packs, &snap(&v, s3), None).unwrap();
            v.append(Stream::Fs, raw(10)).unwrap(); // and one past the anchor
            let shipped = p.coord.shipped(v.id()).unwrap().lsn;
            assert!(v.frames().unwrap()[0].envelope.lsn <= shipped && shipped < v.tail().lsn);
            assert_eq!(
                v.navigate(&p.packs, s3.lsn).unwrap(),
                Navigation::Consistent(vec![])
            );

            // Without the store's history the log does not reach back to
            // genesis: never Consistent.
            let empty = penv(vessel_id(ns(1), b"user-2"));
            let r = v.navigate(&empty.packs, s1.lsn);
            assert!(matches!(r, Err(VesselError::Pack(_))), "{r:?}");
        }

        #[test]
        fn publish_ships_names_and_anchors() {
            let p = penv(vessel_id(ns(1), b"user-1"));
            let (mut v, s1) = sealed(&p);
            let r = v.publish_seal(&p.packs, &snap(&v, s1), None).unwrap();
            let rec = r.record.unwrap();
            assert_eq!(
                (rec.seal, rec.seal_hash, rec.base.clone()),
                (s1.lsn, s1.hash, StreamBase::Full)
            );
            assert_eq!(r.anchor, v.tail());
            assert_published(&p, &v, &[s1]);
            let c = p.packs.chain(Some(r.anchor)).unwrap();
            assert_eq!(p.read(&c.seals[0]), stream(v.dataset(), None, s1.lsn));
            // A second Seal is incremental from the first.
            v.append(Stream::Fs, raw(2)).unwrap();
            let s2 = seal(&mut v);
            let r2 = v.publish_seal(&p.packs, &snap(&v, s2), None).unwrap();
            assert_eq!(
                r2.record.unwrap().base,
                StreamBase::Seal {
                    lsn: s1.lsn,
                    hash: s1.hash
                }
            );
            assert_published(&p, &v, &[s1, s2]);
            let c = p.packs.chain(Some(r2.anchor)).unwrap();
            assert_eq!(
                p.read(&c.seals[1]),
                stream(
                    v.dataset(),
                    Some(v.dataset().seal_snapshot(s1.lsn).as_str()),
                    s2.lsn
                )
            );
            // Again: nothing new.
            let tail = v.tail();
            let again = v.publish_seal(&p.packs, &snap(&v, s2), None).unwrap();
            assert_eq!((again.record, again.anchor, v.tail()), (None, tail, tail));
        }

        /// Crash after the Seal pack's put, before its record.
        #[test]
        fn a_retry_after_the_put_names_the_same_pack() {
            let p = penv(vessel_id(ns(1), b"user-1"));
            let (mut v, s1) = sealed(&p);
            let first = p
                .packs
                .ship_seal(&v.chronicle().segments(), &snap(&v, s1), None)
                .unwrap()
                .unwrap();
            let tail = v.tail();
            let r = v.publish_seal(&p.packs, &snap(&v, s1), None).unwrap();
            assert_eq!(r.record.unwrap(), first.record);
            assert_eq!(v.tail().lsn, tail.lsn.next(), "one record");
            assert_published(&p, &v, &[s1]);
        }

        /// Crash after the record, before the log is shipped.
        #[test]
        fn a_retry_after_the_record_only_ships_and_anchors() {
            let p = penv(vessel_id(ns(1), b"user-1"));
            let (mut v, s1) = sealed(&p);
            let s = p
                .packs
                .ship_seal(&v.chronicle().segments(), &snap(&v, s1), None)
                .unwrap()
                .unwrap();
            v.chronicle
                .append(Stream::Ctl, Payload::FsShipped(s.record))
                .unwrap();
            let tail = v.tail();
            let r = v.publish_seal(&p.packs, &snap(&v, s1), None).unwrap();
            assert_eq!((r.record, v.tail()), (None, tail));
            assert_published(&p, &v, &[s1]);
        }

        /// The store or the coordinator fails at each step; a retry
        /// finishes.
        #[test]
        fn failures_at_each_step_are_finished_by_a_retry() {
            let p = penv(vessel_id(ns(1), b"user-1"));
            let (mut v, s1) = sealed(&p);
            // The Seal pack's put fails: nothing is appended.
            p.fail_put.store(true, Ordering::Relaxed);
            let tail = v.tail();
            assert!(matches!(
                v.publish_seal(&p.packs, &snap(&v, s1), None),
                Err(VesselError::Pack(_))
            ));
            assert_eq!(v.tail(), tail);
            // The anchor cannot move: the Seal is not published yet.
            p.fail_put.store(false, Ordering::Relaxed);
            p.coord.fail_advance.store(true, Ordering::Relaxed);
            assert!(matches!(
                v.publish_seal(&p.packs, &snap(&v, s1), None),
                Err(VesselError::Coord(_))
            ));
            assert_eq!(p.coord.shipped(v.id()).unwrap(), Position::GENESIS);
            p.coord.fail_advance.store(false, Ordering::Relaxed);
            let r = v.publish_seal(&p.packs, &snap(&v, s1), None).unwrap();
            assert_eq!(r.record, None, "named by the first try");
            assert_published(&p, &v, &[s1]);
        }

        #[test]
        fn publish_refuses_what_is_not_this_vessels_seal() {
            let p = penv(vessel_id(ns(1), b"user-1"));
            let (mut v, s1) = sealed(&p);
            let mut other = snap(&v, s1);
            other.dataset = Dataset::new("tank/vessels/elsewhere").unwrap();
            assert!(matches!(
                v.publish_seal(&p.packs, &other, None),
                Err(VesselError::NotThisSeal(_))
            ));
            let mut unbound = snap(&v, s1);
            unbound.seal_hash = None;
            assert!(
                matches!(v.publish_seal(&p.packs, &unbound, None), Err(VesselError::NotThisSeal(why)) if why.contains("not bound"))
            );
            let mut wrong = snap(&v, s1);
            wrong.seal_hash = Some(HashVal::from_bytes([9; 32]));
            assert!(matches!(
                v.publish_seal(&p.packs, &wrong, None),
                Err(VesselError::NotThisSeal(_))
            ));
            let not_a_seal = v.chronicle().frames().unwrap()[1].envelope; // the Raw record
            let raw_pos = Position {
                lsn: not_a_seal.lsn,
                hash: not_a_seal.hash,
            };
            assert!(matches!(
                v.publish_seal(&p.packs, &snap(&v, raw_pos), None),
                Err(VesselError::NotThisSeal(_))
            ));
            assert!(p.packs_store().list("vessels").unwrap().is_empty());
            // FsShipped and Gap records are the Warden's.
            let r = p
                .packs
                .ship_seal(&v.chronicle().segments(), &snap(&v, s1), None)
                .unwrap()
                .unwrap();
            assert!(matches!(
                v.append(Stream::Ctl, Payload::FsShipped(r.record)),
                Err(VesselError::ReservedPayload)
            ));
            let gap = GapRecord {
                kept: Lsn::new(1),
                kept_hash: s1.hash,
                resumes: s1.lsn,
                resumes_hash: s1.hash,
            };
            assert!(matches!(
                v.append(Stream::Ctl, Payload::Gap(gap)),
                Err(VesselError::ReservedPayload)
            ));
        }

        /// A Seal whose layer was missing at open cannot be built on: no
        /// fork, no succession, no publish.
        #[test]
        fn a_seal_without_its_layer_is_refused() {
            let p = penv(vessel_id(ns(1), b"user-1"));
            let (v, s1) = sealed(&p);
            let id = v.id();
            drop(v);
            p.host
                .pool
                .layers(&p.host.dataset_for(id))
                .destroy(s1.lsn)
                .unwrap();
            let (mut v, r) = p.host.open(id).unwrap();
            assert_eq!(r.missing_layers, vec![s1]);
            assert!(
                matches!(p.host.fork(&v, s1, b"child"), Err(VesselError::LayerMissing(s)) if s == s1)
            );
            assert!(matches!(
                v.publish_seal(&p.packs, &snap(&v, s1), None),
                Err(VesselError::LayerMissing(_))
            ));
            assert!(p.packs_store().list("vessels").unwrap().is_empty());
            assert!(matches!(
                p.host.succeed(v, ns(1), b"user-new", auth(), false),
                Err(VesselError::LayerMissing(_))
            ));
        }

        /// A closed Vessel (its state moved on) publishes nothing.
        #[test]
        fn a_closed_vessel_does_not_publish() {
            let p = penv(vessel_id(ns(1), b"user-1"));
            let (v, s1) = sealed(&p);
            let Succeeded {
                predecessor: mut old,
                ..
            } = p
                .host
                .succeed(v, ns(1), b"user-new", auth(), false)
                .unwrap();
            assert!(matches!(
                old.publish_seal(&p.packs, &snap(&old, s1), None),
                Err(VesselError::Closed { .. })
            ));
            assert!(p.packs_store().list("vessels").unwrap().is_empty());
        }

        /// A forked Vessel's first Seal is incremental from its parent's
        /// Seal snapshot.
        #[test]
        fn a_fork_publishes_from_its_origin() {
            let child_id = vessel_id(ns(1), b"user-2");
            let p = penv(child_id);
            let (parent, ps) = sealed(&p);
            let mut child = p.host.fork(&parent, ps, b"user-2").unwrap();
            child.append(Stream::Fs, raw(3)).unwrap();
            let cs = seal(&mut child);
            let origin = snap(&parent, ps);
            assert!(matches!(
                child.publish_seal(&p.packs, &snap(&child, cs), None),
                Err(VesselError::Pack(_))
            ));
            let r = child
                .publish_seal(&p.packs, &snap(&child, cs), Some(&origin))
                .unwrap();
            let want = ParentSeal {
                chronicle: parent.id(),
                seal: ps.lsn,
                seal_hash: ps.hash,
            };
            assert_eq!(
                r.record.unwrap().base,
                StreamBase::Origin {
                    parent: want,
                    guid: origin.guid
                }
            );
            let c = p.packs.chain(Some(r.anchor)).unwrap();
            assert!(matches!(c.seals[0].fs.base, FsBase::Origin { .. }));
            assert_eq!(
                p.read(&c.seals[0]),
                stream(
                    child.dataset(),
                    Some(parent.dataset().seal_snapshot(ps.lsn).as_str()),
                    cs.lsn
                )
            );
        }
    }

    // ── fork ────────────────────────────────────────────────────────

    #[test]
    fn fork_from_a_seal() {
        let e = env();
        let (mut p, _) = e.host.ensure(ns(1), b"base").unwrap();
        p.append(Stream::Fs, raw(1)).unwrap();
        let s = seal(&mut p);
        let child = e.host.fork(&p, s, b"child").unwrap();
        let Origin::Fork { parent } = child.lineage().origin else {
            panic!("not a fork")
        };
        assert_eq!(
            (parent.chronicle, parent.seal, parent.seal_hash),
            (p.id(), s.lsn, s.hash)
        );
        assert_eq!(
            child.namespace(),
            ns(1),
            "forks stay in the parent's namespace"
        );
        let id = child.id();
        drop(child);
        let (child, _) = e.host.open(id).unwrap();
        assert!(matches!(child.lineage().origin, Origin::Fork { .. }));
        assert!(matches!(
            e.host.fork(&p, s, b"child"),
            Err(VesselError::AlreadyExists(_))
        ));
    }

    #[test]
    fn forked_vessel_with_a_tampered_dataset_parent_is_refused() {
        let e = env();
        let (mut p, _) = e.host.ensure(ns(1), b"base").unwrap();
        let s = seal(&mut p);
        let child = e.host.fork(&p, s, b"child").unwrap();
        let (id, ds) = (child.id(), child.dataset().clone());
        drop(child);
        e.host
            .pool
            .set_parent(ds.as_str(), Some(HashVal::from_bytes([4; 32])));
        assert!(matches!(
            e.host.open(id),
            Err(VesselError::LineageMismatch(_))
        ));
        e.host.pool.set_parent(ds.as_str(), None);
        assert!(matches!(
            e.host.open(id),
            Err(VesselError::LineageMismatch(_))
        ));
        e.host.pool.set_parent(ds.as_str(), Some(s.hash));
        assert!(e.host.open(id).is_ok());
    }

    #[test]
    fn fork_refuses_positions_that_are_not_seals() {
        let e = env();
        let (mut p, _) = e.host.ensure(ns(1), b"base").unwrap();
        let rec = p.append(Stream::Fs, raw(1)).unwrap();
        let s = seal(&mut p);
        let not_seal = Position {
            lsn: rec.lsn,
            hash: rec.hash,
        };
        assert!(matches!(
            e.host.fork(&p, not_seal, b"c"),
            Err(VesselError::NotASeal(_))
        ));
        let wrong_hash = Position {
            lsn: s.lsn,
            hash: HashVal::from_bytes([1; 32]),
        };
        assert!(matches!(
            e.host.fork(&p, wrong_hash, b"c"),
            Err(VesselError::NotASeal(_))
        ));
    }

    // ── succession ──────────────────────────────────────────────────

    #[test]
    fn succession_moves_state_and_closes_the_predecessor() {
        let e = env();
        let (mut old, _) = e.host.ensure(ns(1), b"user-old").unwrap();
        old.append(Stream::Fs, raw(1)).unwrap();
        let s = seal(&mut old);
        let old_id = old.id();

        let Succeeded {
            successor: new,
            predecessor: mut old,
        } = e
            .host
            .succeed(old, ns(1), b"user-new", auth(), false)
            .unwrap();
        let Origin::Succession { parent, authority } = &new.lineage().origin else {
            panic!()
        };
        assert_eq!(
            (parent.chronicle, parent.seal, parent.seal_hash),
            (old_id, s.lsn, s.hash)
        );
        assert_eq!(authority, &auth());
        assert_eq!(old.successor().unwrap().successor, new.id());
        assert!(matches!(
            old.append(Stream::Fs, raw(2)),
            Err(VesselError::Closed { .. })
        ));
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
        let empty = Authority {
            actor: " ".into(),
            reason: "x".into(),
        };
        let r = e.host.succeed(v, ns(1), b"n", empty, false);
        assert!(matches!(r, Err(VesselError::EmptyAuthority)));
        let (v, _) = e.host.ensure(ns(1), b"u").unwrap();
        let no_reason = Authority {
            actor: "jarmo".into(),
            reason: String::new(),
        };
        let r = e.host.succeed(v, ns(1), b"n", no_reason, false);
        assert!(matches!(r, Err(VesselError::EmptyAuthority)));

        let (v2, _) = e.host.ensure(ns(1), b"u").unwrap();
        assert!(matches!(
            e.host.succeed(v2, ns(1), b"n", auth(), false),
            Err(VesselError::NoSeal)
        ));

        let (mut v3, _) = e.host.ensure(ns(1), b"u").unwrap();
        seal(&mut v3);
        v3.append(Stream::Fs, raw(1)).unwrap();
        assert!(matches!(
            e.host.succeed(v3, ns(1), b"n", auth(), false),
            Err(VesselError::SealNotLast { .. })
        ));

        let (mut v4, _) = e.host.ensure(ns(1), b"u").unwrap();
        seal(&mut v4);
        assert!(matches!(
            e.host.succeed(v4, ns(2), b"n", auth(), false),
            Err(VesselError::CrossNamespace)
        ));

        let (v5, _) = e.host.ensure(ns(1), b"u").unwrap();
        assert!(matches!(
            e.host.succeed(v5, ns(1), b"u", auth(), false),
            Err(VesselError::SelfSuccession)
        ));

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
                provider: String::new(),
                request: Vec::new(),
                footprint: vec![],
                dispatch: Dispatch::Immediate,
                retry: RetryPolicy::UnsafeToRetry,
                consequence: Consequence::Irreversible,
                authority: vec![],
                barrier: Some(BarrierId::new(op)),
            })
        };
        let outcome = |op: u64, state| {
            Payload::Outcome(OutcomeRecord {
                op: OpId::new(op),
                state,
                evidence: None,
            })
        };
        v.append(Stream::Effect, intent(1)).unwrap();
        v.append(Stream::Effect, outcome(1, OutcomeState::ConfirmedApplied))
            .unwrap();
        v.append(Stream::Effect, intent(2)).unwrap();
        v.append(Stream::Effect, outcome(2, OutcomeState::OutcomeUnknown))
            .unwrap();
        seal(&mut v);
        let Err(VesselError::OpenObligations(ops)) = e.host.succeed(v, ns(1), b"n", auth(), false)
        else {
            panic!("expected OpenObligations")
        };
        assert_eq!(ops, vec![OpId::new(2)]);
    }

    /// After pruning, every reader still sees what the pruned records
    /// said: the Vessel reopens (Lineage from the Checkpoint), an effect
    /// whose intent was pruned is still open, the last sealed turn is
    /// known, a fork from the last Seal works and one from an older pruned
    /// Seal is refused as not local, and a Checkpoint cannot be appended
    /// by hand.
    #[test]
    fn readers_see_through_a_prune() {
        let e = env();
        let (mut v, _) = e.host.ensure(ns(1), b"u").unwrap();
        let intent = Payload::Intent(IntentRecord {
            op: OpId::new(7),
            provider: "mail".into(),
            request: b"to: a".to_vec(),
            footprint: vec![],
            dispatch: Dispatch::Immediate,
            retry: RetryPolicy::UnsafeToRetry,
            consequence: Consequence::Irreversible,
            authority: vec![],
            barrier: Some(BarrierId::new(7)),
        });
        v.append(Stream::Effect, intent).unwrap();
        v.append(
            Stream::Effect,
            Payload::Outcome(OutcomeRecord {
                op: OpId::new(7),
                state: OutcomeState::OutcomeUnknown,
                evidence: None,
            }),
        )
        .unwrap();
        let old = v
            .seal(
                StreamCut::EMPTY,
                Verdict::Clean,
                Lsn::new(3),
                TurnId::new(4),
            )
            .unwrap()
            .seal;
        let last = v
            .seal(
                StreamCut::EMPTY,
                Verdict::Clean,
                Lsn::new(3),
                TurnId::new(5),
            )
            .unwrap()
            .seal;
        v.set_roll_at(1);
        for i in 0..6 {
            v.append(Stream::Fs, raw(i)).unwrap();
        }
        e.host
            .coord
            .advance_shipped(e.host.warden, v.id(), v.chronicle().epoch(), v.tail())
            .unwrap();
        let p = v.prune(1).unwrap();
        assert!(!p.removed.is_empty());
        assert!(
            v.frames().unwrap()[0].envelope.lsn > last.lsn,
            "every Seal and the intent are pruned"
        );
        assert!(matches!(
            v.append(
                Stream::Ctl,
                Payload::Checkpoint(Box::new(
                    crate::summary::Summary::of(&v.frames().unwrap())
                        .unwrap()
                        .checkpoint()
                        .unwrap()
                ))
            ),
            Err(VesselError::ReservedPayload)
        ));
        let id = v.id();
        drop(v);

        let (mut v, _) = e.host.open(id).unwrap();
        assert_eq!(v.lineage().origin, Origin::Void);
        let s = crate::field::Session::new(&mut v, Verdict::Clean).unwrap();
        assert_eq!(s.last_sealed_turn(), Some(5));
        drop(s);
        let (_, report) = crate::effects::Effects::open(
            taso_field::adapter::Registry::new(),
            Box::new(crate::effects::AlwaysPublish),
            &mut v,
        )
        .unwrap();
        assert_eq!(
            report.open,
            vec![OpId::new(7)],
            "the pruned intent is still open"
        );
        assert_eq!(
            open_obligations(&v.frames().unwrap()).unwrap(),
            vec![OpId::new(7)]
        );
        e.host.fork(&v, last, b"child").unwrap();
        assert!(
            matches!(e.host.fork(&v, old, b"child2"), Err(VesselError::SealNotLocal(p)) if p == old)
        );
    }

    #[test]
    fn cross_namespace_succession_when_allowed() {
        let e = env();
        let (mut v, _) = e.host.ensure(ns(1), b"u").unwrap();
        seal(&mut v);
        let new = e
            .host
            .succeed(v, ns(2), b"n", auth(), true)
            .unwrap()
            .successor;
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
        let (none, old) = e
            .host
            .succeed_inner(v, ns(1), b"n", auth(), false, true)
            .unwrap();
        assert!(none.is_none());
        let new_id = vessel_id(ns(1), b"n");
        assert!(matches!(
            e.host.open(new_id),
            Err(VesselError::IncompleteBirth(_))
        ));
        drop(old);

        let (old, _) = e.host.ensure(ns(1), b"u").unwrap();
        assert!(old.successor().is_some());
        // A different successor is refused…
        let other = Authority {
            actor: "jarmo".into(),
            reason: "something else".into(),
        };
        let r = e.host.succeed(old, ns(1), b"n", other, false);
        assert!(matches!(r, Err(VesselError::Closed { .. })));
        // …the same one finishes.
        let (old, _) = e.host.ensure(ns(1), b"u").unwrap();
        let new = e
            .host
            .succeed(old, ns(1), b"n", auth(), false)
            .unwrap()
            .successor;
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
                    let _ = Command::new("zfs")
                        .args(["destroy", "-R", &self.0])
                        .status();
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
            let mount = host
                .pool
                .dataset_info(v.dataset())
                .unwrap()
                .unwrap()
                .mountpoint
                .unwrap();
            std::fs::write(mount.join("notes.txt"), b"mine").unwrap();
            let s = seal(&mut v);

            let child = host.fork(&v, s, b"user-1-fork").unwrap();
            let cm = host
                .pool
                .dataset_info(child.dataset())
                .unwrap()
                .unwrap()
                .mountpoint
                .unwrap();
            assert_eq!(std::fs::read(cm.join("notes.txt")).unwrap(), b"mine");
            drop(child);

            let Succeeded {
                successor: new,
                predecessor: old,
            } = host.succeed(v, ns(1), b"user-2", auth(), false).unwrap();
            let nm = host
                .pool
                .dataset_info(new.dataset())
                .unwrap()
                .unwrap()
                .mountpoint
                .unwrap();
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
