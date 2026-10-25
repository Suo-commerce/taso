//! Nomination: a Vessel's accepted, shipped Seal put forward as a
//! Candidate (P4 spec rev. 19 §3.1, §3.2, §4.1, §4.3; D57–D63; file 6a).
//!
//! [`Nominator::nominate`] runs §3.1's steps under the Chronicle's
//! lifecycle lock (§3.6):
//!
//! 0. **The Seal** (D60): a Seal record at the lsn asked (or the newest)
//!    in the Vessel's local log, within the coordinator's head, and
//!    **shipped**.  Not shipped yet: `Retry`, nothing recorded.
//! 1. **The answer already in the log** (D61): a closed Candidate of this
//!    id refuses `Closed`; an accepted one answers `Nominated` to the same
//!    kind of request and refuses `Duplicate` to another; an accepted
//!    refusal for this Seal and exclusion answers it again.
//! 2. **Warden-local limits** (D62): open Candidates per Vessel, the
//!    minimum interval, concurrent walks.  Over one: `Retry`.
//! 3. **Walk** the Seal's read-only view (§8) and put the input manifest.
//!    Refused on an incomplete walk, an unsupported entry (a reserved
//!    mismatch named as such) or an `Unknown` path.
//! 4. **Transform** (§4.1) and put the output manifest.  A kept symlink
//!    whose target the exclusion drops refuses `DanglingByExclusion`.
//! 5. **Export** the artifact straight from the view by the output
//!    manifest (D59), each file checked against its BLAKE3 while written;
//!    put it, the classmap and the vconf.
//! 6. **The Candidate**, with its facts (D63), appended to the Vessel's
//!    log and accepted through it ([`crate::submit`]).
//!
//! A refusal (§3.1's reasons) is a `NominationRefused`, appended and
//! accepted the same way; it holds nothing and is one per Seal and
//! exclusion.  Every step before the accept leaves nothing accepted, and
//! a retry derives the same `candidate_id` and puts the same objects
//! (artifacts are deterministic, D39).
//!
//! Normative reference: `Taso_spec_p4_contracts` rev. 19, BLAKE3
//! `42b70ff3bd15aed222212265479e404d698d7e126b47b28c5328b61510bcbbc1`.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use taso_core::canon::Canonical;
use taso_core::contract::logical_id;
use taso_core::contract::{
    candidate_id, facts_hash, object_key, Candidate, ClassCounts, ContractRecord, Facts,
    LogicalKey, NominatedBy, NominationRefusal, NominationRefused, ObjectKind, PathClass, SealRef,
    VerifierRequirement, WalkRefusal, TRANSFORM_VERSION,
};
use taso_core::coordlog::Submitted;
use taso_core::envelope::{ChronicleId, HashVal, Lsn, Stream};
use taso_core::model::WardenId;
use taso_core::record::Payload;

use crate::artifact::{self, ArtifactError};
use crate::chronicle::{LayerError, Layers};
use crate::classify::{
    self, Classmap, Content, Kind, Limits, Manifest, Owner, Reserved, Unsupported,
};
use crate::coordinator::{Coord, CoordError};
use crate::coordstore::object_key_path;
use crate::pack::Packs;
use crate::segment::Frame;
use crate::ship::{Sender, SharedStore};
use crate::submit::{self, SubmitError};
use crate::vessel::{SealView, Vessel, VesselError};

/// One slot's range of host ids.
const SLOT: u32 = 65536;

/// The node's sanction configuration (D58) and the Warden-local limits
/// (D62, §11.1).
pub struct SanctionConf {
    /// The classification map every nomination walks with.
    pub classmap: Classmap,
    /// Its bytes, put as the `classmap` object.
    pub classmap_bytes: Vec<u8>,
    /// `sanction.allowed_exclude`.
    pub allowed_exclude: BTreeSet<PathClass>,
    /// The walk's limits.
    pub limits: Limits,
    /// `fs.reserved`.
    pub reserved: Vec<Reserved>,
    /// `warden.max_open_candidates_per_vessel`.
    pub max_open_candidates: usize,
    /// `warden.nominate_min_interval`.
    pub min_interval: Duration,
    /// `warden.max_concurrent_walks`.
    pub max_concurrent_walks: usize,
}

impl SanctionConf {
    /// The defaults of §11.1 for `classmap`.
    pub fn new(classmap_bytes: Vec<u8>) -> Result<Self, classify::MapError> {
        Ok(Self {
            classmap: Classmap::parse(&classmap_bytes)?,
            classmap_bytes,
            allowed_exclude: [PathClass::Scratch].into(),
            limits: Limits::default(),
            reserved: Reserved::defaults(),
            max_open_candidates: 4,
            min_interval: Duration::from_secs(60),
            max_concurrent_walks: 2,
        })
    }
}

/// What is asked for.
#[derive(Clone, Debug)]
pub struct Ask {
    /// The Seal's lsn; `None`: the newest.
    pub seal: Option<Lsn>,
    /// The classes to drop.
    pub exclude: BTreeSet<PathClass>,
    /// The verifier Template (D57).
    pub verifier: ChronicleId,
    /// The verifier config's bytes (the `vconf` object, opaque here).
    pub vconf: Vec<u8>,
    /// The requirement's version.
    pub version: u32,
    /// Who asks.
    pub by: NominatedBy,
}

impl Ask {
    /// The verifier requirement this asks for.
    pub fn requirement(&self) -> VerifierRequirement {
        VerifierRequirement {
            template: self.verifier,
            vconf_key: object_key(ObjectKind::Vconf, &self.vconf),
            version: self.version,
        }
    }
}

/// The answer (§3.1, D60, D61).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Answer {
    /// The Candidate is accepted.
    Nominated(HashVal),
    /// Its accept's outcome is unknown (§1.3).
    Pending(HashVal),
    /// Refused; a `NominationRefused` is accepted (or, for a Seal that is
    /// not in the log, nothing could be recorded).
    Refused(NominationRefusal),
    /// Nothing decided, nothing recorded: ask again later.
    Retry(String),
}

/// Why a nomination failed (nothing accepted by it).
#[derive(Debug)]
pub enum NominateError {
    /// The Vessel failed.
    Vessel(VesselError),
    /// The coordinator failed.
    Coord(CoordError),
    /// Submitting failed.
    Submit(SubmitError),
    /// The store failed.
    Store(io::Error),
    /// Walking failed.
    Walk(io::Error),
    /// The artifact could not be written.
    Artifact(ArtifactError),
    /// The Seal's view could not be had.
    View(LayerError),
    /// The Seal's top directory names no slot base (D44).
    Base {
        /// Its owner uid.
        uid: u32,
        /// Its owner gid.
        gid: u32,
    },
    /// A stored object's bytes are not its key's.
    Integrity(String),
    /// A deliberate stop at a named failpoint (tests).
    Failpoint(&'static str),
}

impl fmt::Display for NominateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Vessel(e) => write!(f, "vessel: {e}"),
            Self::Coord(e) => write!(f, "coordinator: {e}"),
            Self::Submit(e) => write!(f, "submit: {e}"),
            Self::Store(e) => write!(f, "store: {e}"),
            Self::Walk(e) => write!(f, "walk: {e}"),
            Self::Artifact(e) => write!(f, "artifact: {e}"),
            Self::View(e) => write!(f, "the Seal's view: {e}"),
            Self::Base { uid, gid } => write!(
                f,
                "the Seal's top directory is owned by {uid}:{gid}, which names no slot base"
            ),
            Self::Integrity(p) => write!(f, "{p}: the stored bytes are not the key's"),
            Self::Failpoint(p) => write!(f, "stopped at failpoint {p}"),
        }
    }
}

impl std::error::Error for NominateError {}

impl From<VesselError> for NominateError {
    fn from(e: VesselError) -> Self {
        Self::Vessel(e)
    }
}
impl From<CoordError> for NominateError {
    fn from(e: CoordError) -> Self {
        Self::Coord(e)
    }
}
impl From<SubmitError> for NominateError {
    fn from(e: SubmitError) -> Self {
        match e {
            SubmitError::Stopped(p) => Self::Failpoint(p),
            e => Self::Submit(e),
        }
    }
}

/// A failpoint hook: `Err` stops the nomination there.
pub type Failpoint = Box<dyn Fn(&'static str) -> Result<(), NominateError> + Send + Sync>;

/// No failpoints.
pub fn no_failpoints() -> Failpoint {
    Box::new(|_| Ok(()))
}

/// The five failpoints of a nomination up to its accept (§10.2).
pub const FAILPOINTS: [&str; 5] = [
    "nominate.after_input_manifest",
    "nominate.after_output_manifest",
    "nominate.after_artifact_put",
    "nominate.after_announce",
    "nominate.before_accept",
];

/// Nominates Seals of this node's Vessels.
pub struct Nominator {
    /// The store.
    pub store: SharedStore,
    /// Key prefix in the store.
    pub prefix: String,
    /// The coordinator.
    pub coord: Arc<dyn Coord>,
    /// This Warden.
    pub warden: WardenId,
    /// The node's `host_uid_base` (a Seal's slot base, D44).
    pub host_uid_base: u32,
    /// Where an artifact is written before it is put.
    pub tmp_dir: PathBuf,
    /// The sanction configuration.
    pub conf: SanctionConf,
    /// Stops at a failpoint (tests).
    pub failpoint: Failpoint,
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    /// The lifecycle locks (§3.6), by Chronicle.
    locks: BTreeMap<[u8; 16], Arc<Mutex<()>>>,
    /// When each Vessel last nominated.
    last: BTreeMap<[u8; 16], Instant>,
    /// Walks running now.
    walks: usize,
}

/// Holds a walk slot until dropped.
struct WalkSlot<'a>(&'a Mutex<State>);

impl Drop for WalkSlot<'_> {
    fn drop(&mut self) {
        let mut s = self.0.lock().unwrap_or_else(|e| e.into_inner());
        s.walks -= 1;
    }
}

impl Nominator {
    /// A nominator.
    pub fn new(
        store: SharedStore,
        prefix: impl Into<String>,
        coord: Arc<dyn Coord>,
        warden: WardenId,
        host_uid_base: u32,
        tmp_dir: PathBuf,
        conf: SanctionConf,
    ) -> Self {
        Self {
            store,
            prefix: prefix.into(),
            coord,
            warden,
            host_uid_base,
            tmp_dir,
            conf,
            failpoint: no_failpoints(),
            state: Mutex::default(),
        }
    }

    /// Nominate `ask` for `vessel` (see the module docs).  `view` gives
    /// the read-only files of one of its Seals (`Pool::seal_view`).
    pub fn nominate<L: Layers, X: Sender>(
        &self,
        vessel: &mut Vessel<L>,
        packs: &Packs<SharedStore, X>,
        ask: &Ask,
        view: &dyn Fn(Lsn) -> Result<SealView, LayerError>,
    ) -> Result<Answer, NominateError> {
        let id = vessel.id();
        let lock = {
            let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
            s.locks.entry(*id.as_bytes()).or_default().clone()
        };
        let _lifecycle = lock.lock().unwrap_or_else(|e| e.into_inner());

        // 0. The Seal.
        let frames = vessel
            .chronicle()
            .frames()
            .map_err(|e| VesselError::Chronicle(crate::chronicle::ChronicleError::Segment(e)))?;
        let Some((seal, record)) = find_seal(&frames, ask.seal)? else {
            return Ok(Answer::Refused(NominationRefusal::SealNotAccepted));
        };
        let refuse = |vessel: &mut Vessel<L>, reason, input: Option<HashVal>| {
            self.refuse(vessel, packs, seal, &ask.exclude, reason, input)
        };
        let Some(record) = record else {
            // A record at that lsn, not a Seal: refused for good.
            return refuse(vessel, NominationRefusal::SealNotAccepted, None);
        };
        if self.coord.head(id)?.lsn < seal.lsn {
            return refuse(vessel, NominationRefusal::SealNotAccepted, None);
        }
        let shipped = self.coord.shipped(id)?;
        if shipped.lsn < seal.lsn {
            return Ok(Answer::Retry(format!(
                "the Seal at lsn {} is not shipped yet (shipped up to lsn {})",
                seal.lsn.get(),
                shipped.lsn.get()
            )));
        }
        if !ask.exclude.is_subset(&self.conf.allowed_exclude) {
            return refuse(vessel, NominationRefusal::BadExclude, None);
        }

        // 1. The answer already in the log.
        let requirement = ask.requirement();
        let cid = candidate_id(
            id,
            seal.hash,
            &ask.exclude,
            self.conf.classmap.key(),
            TRANSFORM_VERSION,
            &requirement,
        );
        if self.accepted(LogicalKey::CandidateClose(cid))?.is_some() {
            return refuse(vessel, NominationRefusal::Closed, None);
        }
        if let Some(ContractRecord::Candidate(c)) = self.accepted(LogicalKey::Candidate(cid))? {
            return if same_kind(&c.nominated_by, &ask.by) {
                Ok(Answer::Nominated(cid))
            } else {
                refuse(vessel, NominationRefusal::Duplicate, None)
            };
        }
        let probe = NominationRefused {
            chronicle: id,
            seal,
            exclude: ask.exclude.clone(),
            reason: NominationRefusal::SealNotAccepted,
            input_manifest_key: None,
        };
        if let Some(ContractRecord::NominationRefused(r)) =
            self.accepted_id(ContractRecord::NominationRefused(probe).logical_id())?
        {
            return Ok(Answer::Refused(r.reason));
        }

        // 2. Warden-local limits.
        let open = self.open_candidates(&frames)?;
        if open >= self.conf.max_open_candidates {
            return Ok(Answer::Retry(format!(
                "{open} open Candidates, the most a Vessel may have (warden.max_open_candidates_per_vessel)"
            )));
        }
        let _slot = {
            let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(t) = s.last.get(id.as_bytes()) {
                if t.elapsed() < self.conf.min_interval {
                    return Ok(Answer::Retry(format!(
                        "nominated {}s ago; warden.nominate_min_interval is {}s",
                        t.elapsed().as_secs(),
                        self.conf.min_interval.as_secs()
                    )));
                }
            }
            if s.walks >= self.conf.max_concurrent_walks {
                return Ok(Answer::Retry(format!(
                    "{} walks running (warden.max_concurrent_walks)",
                    s.walks
                )));
            }
            s.walks += 1;
            s.last.insert(*id.as_bytes(), Instant::now());
            WalkSlot(&self.state)
        };

        // 3. Walk the Seal's files.
        let view = view(seal.lsn).map_err(NominateError::View)?;
        let root = view.path().to_path_buf();
        let base = seal_base(&root, self.host_uid_base)?;
        let owner = Owner {
            uid_base: base,
            gid_base: base,
        };
        let input = classify::walk(
            &root,
            &self.conf.classmap,
            owner,
            &self.conf.limits,
            &self.conf.reserved,
        )
        .map_err(NominateError::Walk)?;
        let input_key = input.key();
        self.put_content(ObjectKind::Manifest, input_key, &mut &input.bytes()[..])?;
        (self.failpoint)("nominate.after_input_manifest")?;
        if let Some(w) = walk_refusal(&input) {
            return refuse(vessel, NominationRefusal::Walk(w), Some(input_key));
        }

        // 4. Transform.
        let Ok(output) = transform(&input, &ask.exclude) else {
            return refuse(
                vessel,
                NominationRefusal::Walk(WalkRefusal::DanglingByExclusion),
                Some(input_key),
            );
        };
        let output_key = output.key();
        self.put_content(ObjectKind::Manifest, output_key, &mut &output.bytes()[..])?;
        (self.failpoint)("nominate.after_output_manifest")?;

        // 5. Export.
        let artifact_key = self.put_artifact(&root, &output, cid)?;
        drop(view);
        self.put_content(
            ObjectKind::Classmap,
            self.conf.classmap.key(),
            &mut &self.conf.classmap_bytes[..],
        )?;
        self.put_content(
            ObjectKind::Vconf,
            requirement.vconf_key,
            &mut &ask.vconf[..],
        )?;
        (self.failpoint)("nominate.after_artifact_put")?;

        // 6. The Candidate.
        let facts = Facts {
            input: input.counts(),
            excluded: dropped_counts(&input, &output),
            open_obligations: self.coord.obligations(id)?.len() as u64,
            effects_adopted: effects_adopted(&frames, seal.lsn)?,
            ledger_lsn: record.ledger_pos,
            requirement,
        };
        let candidate = Candidate {
            candidate_id: cid,
            chronicle: id,
            seal,
            exclude: ask.exclude.clone(),
            transform_version: TRANSFORM_VERSION,
            classmap_key: self.conf.classmap.key(),
            input_manifest_key: input_key,
            output_manifest_key: output_key,
            artifact_key,
            requirement,
            facts_hash: facts_hash(&facts),
            facts,
            nominated_by: ask.by,
            nominated_at: vessel.tail().lsn,
        };
        debug_assert!(candidate.is_consistent());
        let rec = ContractRecord::Candidate(Box::new(candidate));
        if let Some(why) = self.unshippable(vessel)? {
            return Ok(Answer::Retry(why));
        }
        vessel.append_contract(rec.clone())?;
        let sub = Submitted::Contract(rec);
        let pack = submit::put(
            self.coord.as_ref(),
            self.warden,
            vessel.chronicle(),
            packs,
            &sub,
        )?;
        (self.failpoint)("nominate.before_accept")?;
        let fp = &self.failpoint;
        let after_announce = || match fp("nominate.after_announce") {
            Ok(()) => Ok(()),
            Err(NominateError::Failpoint(p)) => Err(SubmitError::Stopped(p)),
            Err(e) => Err(SubmitError::Inconsistent(leak(e.to_string()))),
        };
        let ours = sub.digest();
        let mut attempt = *vessel.attempt_mut();
        let got = submit::accept_with(
            self.coord.as_ref(),
            self.warden,
            vessel.chronicle(),
            sub,
            pack,
            &mut attempt,
            &after_announce,
        );
        *vessel.attempt_mut() = attempt;
        match got {
            Ok(r) if r.digest() == ours => Ok(Answer::Nominated(cid)),
            // Another Candidate of this id was accepted first.
            Ok(Submitted::Contract(ContractRecord::Candidate(c))) => {
                if same_kind(&c.nominated_by, &ask.by) {
                    Ok(Answer::Nominated(cid))
                } else {
                    refuse(vessel, NominationRefusal::Duplicate, None)
                }
            }
            Ok(other) => Err(NominateError::Submit(SubmitError::Inconsistent(leak(
                format!("the Candidate's logical id holds {other:?}"),
            )))),
            Err(SubmitError::Coord(_)) => Ok(Answer::Pending(cid)),
            Err(e) => Err(e.into()),
        }
    }

    /// Record a refusal: a `NominationRefused`, appended to the Vessel's
    /// log and accepted (or the one already accepted for this Seal and
    /// exclusion, whose reason is then the answer).
    fn refuse<L: Layers, X: Sender>(
        &self,
        vessel: &mut Vessel<L>,
        packs: &Packs<SharedStore, X>,
        seal: SealRef,
        exclude: &BTreeSet<PathClass>,
        reason: NominationRefusal,
        input_manifest_key: Option<HashVal>,
    ) -> Result<Answer, NominateError> {
        if let Some(why) = self.unshippable(vessel)? {
            return Ok(Answer::Retry(why));
        }
        let rec = ContractRecord::NominationRefused(NominationRefused {
            chronicle: vessel.id(),
            seal,
            exclude: exclude.clone(),
            reason,
            input_manifest_key,
        });
        if let Some(ContractRecord::NominationRefused(r)) = self.accepted_id(rec.logical_id())? {
            return Ok(Answer::Refused(r.reason));
        }
        vessel.append_contract(rec.clone())?;
        let mut attempt = *vessel.attempt_mut();
        let got = submit::submit(
            self.coord.as_ref(),
            self.warden,
            vessel.chronicle(),
            packs,
            Submitted::Contract(rec),
            &mut attempt,
        );
        *vessel.attempt_mut() = attempt;
        match got? {
            Submitted::Contract(ContractRecord::NominationRefused(r)) => {
                Ok(Answer::Refused(r.reason))
            }
            other => Err(NominateError::Submit(SubmitError::Inconsistent(leak(
                format!("a refusal's logical id holds {other:?}"),
            )))),
        }
    }

    /// Why a record appended now could not be shipped yet, if it could
    /// not: the log is never shipped past a Seal whose `fs` section is not
    /// (F4), so a record after the Vessel's newest Seal waits for it.
    fn unshippable<L: Layers>(&self, vessel: &Vessel<L>) -> Result<Option<String>, NominateError> {
        let Some(last) = vessel.last_seal() else {
            return Ok(None);
        };
        let shipped = self.coord.shipped(vessel.id())?;
        Ok((shipped.lsn < last.lsn).then(|| {
            format!(
                "the Vessel's newest Seal (lsn {}) is not shipped yet: nothing can be recorded after it",
                last.lsn.get()
            )
        }))
    }

    /// The contract record accepted for `key`, if any.
    fn accepted(&self, key: LogicalKey) -> Result<Option<ContractRecord>, NominateError> {
        self.accepted_id(logical_id(&key))
    }

    fn accepted_id(&self, logical: HashVal) -> Result<Option<ContractRecord>, NominateError> {
        Ok(match self.coord.query_logical(logical)? {
            Some((_, Submitted::Contract(r))) => Some(r),
            _ => None,
        })
    }

    /// The Vessel's open Candidates: those its log carries that are
    /// accepted and not closed.
    fn open_candidates(&self, frames: &[Frame]) -> Result<usize, NominateError> {
        let ids: BTreeSet<[u8; 32]> = frames
            .iter()
            .filter(|f| f.envelope.stream == Stream::Ctl)
            .filter_map(|f| match Payload::decode(&f.payload) {
                Ok(Payload::Contract(r)) => match *r {
                    ContractRecord::Candidate(c) => Some(*c.candidate_id.as_bytes()),
                    _ => None,
                },
                _ => None,
            })
            .collect();
        let mut open = 0;
        for id in ids {
            let id = HashVal::from_bytes(id);
            if self.accepted(LogicalKey::Candidate(id))?.is_some()
                && self.accepted(LogicalKey::CandidateClose(id))?.is_none()
            {
                open += 1;
            }
        }
        Ok(open)
    }

    /// Write the archive of `root` by `manifest` to a temporary file, then
    /// put it under its key.
    fn put_artifact(
        &self,
        root: &Path,
        manifest: &Manifest,
        cid: HashVal,
    ) -> Result<HashVal, NominateError> {
        std::fs::create_dir_all(&self.tmp_dir).map_err(NominateError::Store)?;
        let tmp = self.tmp_dir.join(format!(
            "{}-{}.part",
            hex(cid.as_bytes()),
            std::process::id()
        ));
        let written = (|| -> Result<HashVal, NominateError> {
            let mut f = File::create(&tmp).map_err(NominateError::Store)?;
            let (key, _) =
                artifact::write(root, manifest, &mut f).map_err(NominateError::Artifact)?;
            f.sync_all().map_err(NominateError::Store)?;
            drop(f);
            let mut f = File::open(&tmp).map_err(NominateError::Store)?;
            self.put_content(ObjectKind::Artifact, key, &mut f)?;
            Ok(key)
        })();
        let _ = std::fs::remove_file(&tmp);
        written
    }

    /// Put a content object (D35); one already there is read back and
    /// checked against its key instead.
    fn put_content(
        &self,
        kind: ObjectKind,
        key: HashVal,
        data: &mut dyn Read,
    ) -> Result<(), NominateError> {
        let path = object_key_path(&self.prefix, kind, key).expect("a content kind");
        if let Some(mut r) = self.store.get(&path).map_err(NominateError::Store)? {
            let mut h = blake3::Hasher::new_derive_key(kind.prefix());
            io::copy(&mut r, &mut h).map_err(NominateError::Store)?;
            if h.finalize().as_bytes() != key.as_bytes() {
                return Err(NominateError::Integrity(path));
            }
            return Ok(());
        }
        self.store.put(&path, data).map_err(NominateError::Store)?;
        Ok(())
    }
}

fn leak(s: String) -> &'static str {
    Box::leak(s.into_boxed_str())
}

/// Whether two nominations are the same kind of request (D61): the agent
/// twice, the config twice, or a supersession of the same Candidate.
fn same_kind(a: &NominatedBy, b: &NominatedBy) -> bool {
    a == b
}

/// The Seal at `lsn` (or the newest Seal) in the local log: `None` if no
/// record is at that lsn (or no Seal at all); `Some((seal, None))` if the
/// record there is not a Seal.
fn find_seal(
    frames: &[Frame],
    lsn: Option<Lsn>,
) -> Result<Option<(SealRef, Option<taso_core::record::SealRecord>)>, NominateError> {
    let seal_of = |f: &Frame| match Payload::decode(&f.payload) {
        Ok(Payload::Seal(s)) if f.envelope.stream == Stream::Ctl => Some(s),
        _ => None,
    };
    let frame = match lsn {
        Some(l) => frames.iter().find(|f| f.envelope.lsn == l),
        None => frames.iter().rev().find(|f| seal_of(f).is_some()),
    };
    Ok(frame.map(|f| {
        (
            SealRef {
                lsn: f.envelope.lsn,
                hash: f.envelope.hash,
            },
            seal_of(f),
        )
    }))
}

/// A Seal's slot base (D44): its top directory's owner, uid = gid, a
/// whole number of slots at or above `host_uid_base`; never 0.
fn seal_base(top: &Path, host_uid_base: u32) -> Result<u32, NominateError> {
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::symlink_metadata(top).map_err(NominateError::Walk)?;
    let (uid, gid) = (m.uid(), m.gid());
    let aligned = uid
        .checked_sub(host_uid_base)
        .is_some_and(|off| off % SLOT == 0);
    if uid == gid && uid != 0 && aligned {
        Ok(uid)
    } else {
        Err(NominateError::Base { uid, gid })
    }
}

/// §3.1 step 1's refusals of the input walk: incomplete, unsupported (a
/// reserved mismatch named as such), `Unknown`.  `Secret` and `Hook` are
/// not refused here: the sanction's hard rules decide on them (§1.2).
pub fn walk_refusal(m: &Manifest) -> Option<WalkRefusal> {
    if !m.complete() {
        return Some(WalkRefusal::IncompleteWalk);
    }
    if m.unsupported
        .iter()
        .any(|(_, u)| *u == Unsupported::ReservedMismatch)
    {
        return Some(WalkRefusal::ReservedMismatch);
    }
    if !m.unsupported.is_empty() {
        return Some(WalkRefusal::Unsupported);
    }
    if m.counts().unknown > 0 {
        return Some(WalkRefusal::UnknownPaths);
    }
    None
}

/// A kept symlink points at a path the exclusion dropped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dangling {
    /// The symlink.
    pub link: Vec<u8>,
    /// Its lexically resolved target.
    pub target: Vec<u8>,
}

/// The output manifest transform, `transform_version = 1` (§4.1):
/// entries of an excluded class dropped; ancestors of kept entries kept,
/// reclassified `Structural` if their own class is excluded; a kept
/// symlink whose lexically resolved target was dropped refuses the
/// transform.  Metadata and slots are copied unchanged.
pub fn transform(input: &Manifest, exclude: &BTreeSet<PathClass>) -> Result<Manifest, Dangling> {
    let kept_own: BTreeSet<&[u8]> = input
        .entries
        .iter()
        .filter(|e| !exclude.contains(&e.class))
        .map(|e| e.path.as_slice())
        .collect();
    let mut ancestors: BTreeSet<&[u8]> = BTreeSet::new();
    for p in &kept_own {
        let mut i = p.len();
        while let Some(j) = p[..i].iter().rposition(|&b| b == b'/') {
            ancestors.insert(&p[..j]);
            i = j;
        }
    }
    let mut entries = Vec::new();
    for e in &input.entries {
        let own = kept_own.contains(e.path.as_slice());
        let needed = ancestors.contains(e.path.as_slice());
        if own {
            entries.push(e.clone());
        } else if needed {
            debug_assert_eq!(e.kind, Kind::Dir);
            let mut s = e.clone();
            s.class = PathClass::Structural;
            entries.push(s);
        }
    }
    let input_paths: BTreeSet<&[u8]> = input.entries.iter().map(|e| e.path.as_slice()).collect();
    let output_paths: BTreeSet<&[u8]> = entries.iter().map(|e| e.path.as_slice()).collect();
    for e in &entries {
        let (Kind::Symlink, Content::Target(t)) = (e.kind, &e.content) else {
            continue;
        };
        let Some(target) = resolve(&e.path, t) else {
            continue; // leaves the root: the walk lists it unsupported
        };
        if input_paths.contains(target.as_slice()) && !output_paths.contains(target.as_slice()) {
            return Err(Dangling {
                link: e.path.clone(),
                target,
            });
        }
    }
    let top = |p: &[u8]| !p.contains(&b'/');
    let input_top = input.entries.iter().filter(|e| top(&e.path)).count() as u64;
    let output_top = entries.iter().filter(|e| top(&e.path)).count() as u64;
    Ok(Manifest {
        classmap_key: input.classmap_key,
        // Reserved names under the root stay; the dropped ones go.
        root_entries: input.root_entries - input_top + output_top,
        total_bytes: entries
            .iter()
            .filter(|e| e.kind == Kind::File)
            .map(|e| e.size)
            .sum(),
        incomplete: None,
        entries,
        unsupported: Vec::new(),
    })
}

/// The lexical resolution of a symlink at `link` with target `target`,
/// relative to the root: `None` if it leaves the root or is absolute.
fn resolve(link: &[u8], target: &[u8]) -> Option<Vec<u8>> {
    if target.first() == Some(&b'/') {
        return None;
    }
    let mut parts: Vec<&[u8]> = link.split(|&b| b == b'/').collect();
    parts.pop(); // the link's own name
    for c in target.split(|&b| b == b'/') {
        match c {
            b"" | b"." => {}
            b".." => {
                parts.pop()?;
            }
            c => parts.push(c),
        }
    }
    Some(parts.join(&b'/'))
}

/// The class counts of the entries the transform dropped.
fn dropped_counts(input: &Manifest, output: &Manifest) -> ClassCounts {
    let kept: BTreeSet<&[u8]> = output.entries.iter().map(|e| e.path.as_slice()).collect();
    let dropped = Manifest {
        entries: input
            .entries
            .iter()
            .filter(|e| !kept.contains(e.path.as_slice()))
            .cloned()
            .collect(),
        unsupported: Vec::new(),
        ..input.clone()
    };
    dropped.counts()
}

/// The operations adopted by promotion in the log up to `seal` (D63):
/// intents whose authority is an `AdoptedFrom` naming a child and Seal of
/// an earlier Promotion record.
fn effects_adopted(frames: &[Frame], seal: Lsn) -> Result<u64, NominateError> {
    let mut prefixes: Vec<Vec<u8>> = Vec::new();
    let mut n = 0;
    for f in frames.iter().take_while(|f| f.envelope.lsn <= seal) {
        match Payload::decode(&f.payload) {
            Ok(Payload::Promotion(p)) => {
                let mut c = taso_core::canon::Canon::default();
                p.child.canon(&mut c);
                p.seal.canon(&mut c);
                prefixes.push(c.as_bytes().to_vec());
            }
            Ok(Payload::Intent(i))
                if i.authority.len() == 32
                    && prefixes.iter().any(|p| i.authority.starts_with(p)) =>
            {
                n += 1;
            }
            _ => {}
        }
    }
    Ok(n)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    use taso_core::record::{StreamCut, TurnId, Verdict};

    use crate::coordinator::{Coordinator, LogConfig};
    use crate::coordstore::CoordStore;
    use crate::ship::{ByteStream, LocalStore, ObjectStore};
    use crate::vessel::tests::{fake_guid, ns, FakePool};
    use crate::vessel::Host;
    use crate::zfs::{Dataset, Snapshot};

    const PREFIX: &str = "taso";
    const BASE: u32 = 200_000;
    const VBASE: u32 = BASE + SLOT; // the Vessel's slot 1

    const MAP: &str = "version = 1
[[rule]]
glob = \"**\"
class = \"Source\"
[[rule]]
glob = \"tmp/\"
class = \"Scratch\"
[[rule]]
glob = \"cache/\"
class = \"Scratch\"
";

    struct Bytes;
    impl Sender for Bytes {
        fn send(&self, d: &Dataset, from: Option<&str>, to: Lsn) -> io::Result<ByteStream> {
            Ok(Box::new(io::Cursor::new(
                format!("{d} {from:?} {}", to.get()).into_bytes(),
            )))
        }
    }

    struct World {
        dir: tempfile::TempDir,
        store: SharedStore,
        coord: Arc<Coordinator>,
        host: Host<FakePool>,
        tree: PathBuf,
    }

    fn world() -> World {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("store")).unwrap();
        let store: SharedStore = Arc::new(LocalStore::new(dir.path().join("store")));
        let coord = Arc::new(
            Coordinator::open_with(
                dir.path().join("coord.redb"),
                LogConfig {
                    store: Arc::new(CoordStore::new(store.clone(), PREFIX)),
                    ..LogConfig::default()
                },
            )
            .unwrap(),
        );
        let host = Host {
            coord: coord.clone(),
            pool: FakePool::default(),
            root: Dataset::new("tank/vessels").unwrap(),
            state_dir: dir.path().join("state"),
            warden: WardenId::new(1),
        };
        let tree = dir.path().join("seal");
        World {
            dir,
            store,
            coord,
            host,
            tree,
        }
    }

    /// The Seal's files: a source tree, a scratch directory and file, an
    /// excluded directory under a kept one, all owned by the Vessel's range.
    fn make_tree(t: &Path) {
        std::fs::create_dir_all(t.join("app/tmp")).unwrap();
        std::fs::create_dir_all(t.join("tmp")).unwrap();
        std::fs::create_dir_all(t.join("cache/deep")).unwrap();
        std::fs::write(t.join("app/main.py"), "print(1)\n").unwrap();
        std::fs::write(t.join("app/tmp/build.o"), "obj").unwrap();
        std::fs::write(t.join("tmp/scratch"), "x").unwrap();
        std::fs::write(t.join("cache/deep/blob"), "y").unwrap();
        symlink("app/main.py", t.join("main")).unwrap();
        chown_all(t);
    }

    fn chown_all(t: &Path) {
        let st = std::process::Command::new("chown")
            .args(["-hR", &format!("{VBASE}:{VBASE}")])
            .arg(t)
            .status()
            .unwrap();
        assert!(st.success());
        std::fs::set_permissions(t, std::fs::Permissions::from_mode(0o750)).unwrap();
    }

    fn nominator(w: &World, conf: SanctionConf) -> Nominator {
        Nominator::new(
            w.store.clone(),
            PREFIX,
            w.coord.clone(),
            WardenId::new(1),
            BASE,
            w.dir.path().join("tmp"),
            conf,
        )
    }

    fn conf() -> SanctionConf {
        let mut c = SanctionConf::new(MAP.as_bytes().to_vec()).unwrap();
        c.min_interval = Duration::ZERO;
        c
    }

    fn ask(by: NominatedBy) -> Ask {
        Ask {
            seal: None,
            exclude: [PathClass::Scratch].into(),
            verifier: ChronicleId::from_bytes([0x99; 16]),
            vconf: b"entry = [\"/bin/check\"]\n".to_vec(),
            version: 1,
            by,
        }
    }

    type V = Vessel<<FakePool as crate::vessel::Pool>::Layers>;

    /// A Vessel with one turn sealed; shipped if `ship`.
    fn vessel(w: &World, subject: &[u8], ship: bool) -> (V, Packs<SharedStore, Bytes>) {
        let (mut v, _) = w.host.ensure(ns(1), subject).unwrap();
        let packs = Packs::new(w.store.clone(), Bytes, PREFIX, v.id()).unwrap();
        v.append(Stream::Fs, Payload::Raw(vec![1; 8])).unwrap();
        let s = v
            .seal(
                StreamCut::EMPTY,
                Verdict::Clean,
                Lsn::new(0),
                TurnId::new(1),
            )
            .unwrap()
            .seal;
        if ship {
            let snap = Snapshot {
                dataset: v.dataset().clone(),
                seal: s.lsn,
                createtxg: 1,
                guid: fake_guid(s.lsn),
                seal_hash: Some(s.hash),
            };
            v.publish_seal(&packs, &snap, None).unwrap();
        }
        (v, packs)
    }

    fn view(t: &Path) -> impl Fn(Lsn) -> Result<SealView, LayerError> + '_ {
        move |_| Ok(SealView::new(t.to_path_buf(), None))
    }

    fn contracts(v: &V) -> Vec<ContractRecord> {
        v.chronicle()
            .frames()
            .unwrap()
            .iter()
            .filter_map(|f| match Payload::decode(&f.payload) {
                Ok(Payload::Contract(r)) => Some(*r),
                _ => None,
            })
            .collect()
    }

    fn candidate(w: &World, cid: HashVal) -> Candidate {
        match w
            .coord
            .query_logical(logical_id(&LogicalKey::Candidate(cid)))
            .unwrap()
        {
            Some((_, Submitted::Contract(ContractRecord::Candidate(c)))) => *c,
            other => panic!("{other:?}"),
        }
    }

    fn manifest(w: &World, key: HashVal) -> Manifest {
        let path = object_key_path(PREFIX, ObjectKind::Manifest, key).unwrap();
        let mut b = Vec::new();
        w.store
            .get(&path)
            .unwrap()
            .unwrap()
            .read_to_end(&mut b)
            .unwrap();
        Manifest::decode(&b[..]).unwrap()
    }

    #[test]
    fn a_shipped_seal_becomes_a_candidate_once() {
        let w = world();
        make_tree(&w.tree);
        let n = nominator(&w, conf());
        let (mut v, packs) = vessel(&w, b"a", true);
        let a = n
            .nominate(&mut v, &packs, &ask(NominatedBy::Agent), &view(&w.tree))
            .unwrap();
        let Answer::Nominated(cid) = a else {
            panic!("{a:?}")
        };
        let c = candidate(&w, cid);
        assert!(c.is_consistent());
        assert_eq!(c.seal.lsn, v.last_seal().unwrap().lsn);
        // The output keeps app/ (and app/tmp/ is dropped with its file),
        // drops tmp/ and cache/ wholly; the input counted them.
        let out = manifest(&w, c.output_manifest_key);
        let paths: Vec<String> = out
            .entries
            .iter()
            .map(|e| String::from_utf8(e.path.clone()).unwrap())
            .collect();
        // `tmp/` names the top-level tmp only (D26): app/tmp is Source.
        assert_eq!(
            paths,
            ["app", "app/main.py", "app/tmp", "app/tmp/build.o", "main"]
        );
        assert_eq!(c.facts.excluded.scratch, 5, "{:?}", c.facts.excluded);
        assert_eq!(c.facts.input.scratch, 5);
        assert_eq!(c.facts.input.source, 5);
        assert_eq!(c.facts.ledger_lsn, Lsn::new(0));
        assert_eq!(c.facts.effects_adopted, 0);
        // The artifact holds exactly the output.
        let path = object_key_path(PREFIX, ObjectKind::Artifact, c.artifact_key).unwrap();
        let am = artifact::read_manifest(&mut w.store.get(&path).unwrap().unwrap()).unwrap();
        assert_eq!(am, out);
        // Held by the Vessel: artifact, both manifests, classmap, vconf.
        let holds = w.coord.query_chronicle(v.id()).unwrap().unwrap().holds;
        for k in [
            c.artifact_key,
            c.input_manifest_key,
            c.output_manifest_key,
            c.classmap_key,
            c.requirement.vconf_key,
        ] {
            assert!(holds.contains(&taso_core::coordlog::ObjectId::content(k)));
        }
        // The same request again: the same answer, nothing appended.
        let again = n
            .nominate(&mut v, &packs, &ask(NominatedBy::Agent), &view(&w.tree))
            .unwrap();
        assert_eq!(again, Answer::Nominated(cid));
        assert_eq!(contracts(&v).len(), 1);
        // Another kind of request for the same id: Duplicate, recorded once.
        let dup = n
            .nominate(&mut v, &packs, &ask(NominatedBy::Config), &view(&w.tree))
            .unwrap();
        assert_eq!(dup, Answer::Refused(NominationRefusal::Duplicate));
        let dup2 = n
            .nominate(&mut v, &packs, &ask(NominatedBy::Config), &view(&w.tree))
            .unwrap();
        assert_eq!(dup2, dup);
        assert_eq!(contracts(&v).len(), 2);
    }

    #[test]
    fn a_seal_not_shipped_is_retried_never_recorded() {
        let w = world();
        make_tree(&w.tree);
        let n = nominator(&w, conf());
        let (mut v, packs) = vessel(&w, b"a", false);
        let a = n
            .nominate(&mut v, &packs, &ask(NominatedBy::Agent), &view(&w.tree))
            .unwrap();
        assert!(
            matches!(a, Answer::Retry(ref why) if why.contains("not shipped")),
            "{a:?}"
        );
        assert!(contracts(&v).is_empty());
        // A record that is not a Seal: refused for good, and an lsn with
        // nothing: refused, nothing to record.
        // A refusal waits too while the newest Seal is not shipped.
        let mut a = ask(NominatedBy::Agent);
        a.seal = Some(Lsn::new(1)); // the Lineage
        assert!(matches!(
            n.nominate(&mut v, &packs, &a, &view(&w.tree)).unwrap(),
            Answer::Retry(ref why) if why.contains("nothing can be recorded")
        ));
        assert!(contracts(&v).is_empty());
        // Shipped: a record that is not a Seal is refused for good, and
        // an lsn with nothing is refused, with nothing to record.
        let s = v.last_seal().unwrap();
        let snap = Snapshot {
            dataset: v.dataset().clone(),
            seal: s.lsn,
            createtxg: 1,
            guid: fake_guid(s.lsn),
            seal_hash: Some(s.hash),
        };
        v.publish_seal(&packs, &snap, None).unwrap();
        assert_eq!(
            n.nominate(&mut v, &packs, &a, &view(&w.tree)).unwrap(),
            Answer::Refused(NominationRefusal::SealNotAccepted)
        );
        assert_eq!(contracts(&v).len(), 1);
        a.seal = Some(Lsn::new(999));
        assert_eq!(
            n.nominate(&mut v, &packs, &a, &view(&w.tree)).unwrap(),
            Answer::Refused(NominationRefusal::SealNotAccepted)
        );
        assert_eq!(contracts(&v).len(), 1);
    }

    #[test]
    fn refusals_are_recorded_once_per_seal_and_exclusion() {
        let w = world();
        make_tree(&w.tree);
        std::fs::write(w.tree.join("odd"), "?").unwrap();
        chown_all(&w.tree);
        // A map without a catch-all: `odd` (and everything) is Unknown.
        let mut c = SanctionConf::new(
            b"version = 1\n[[rule]]\nglob = \"app/\"\nclass = \"Source\"\n".to_vec(),
        )
        .unwrap();
        c.min_interval = Duration::ZERO;
        let n = nominator(&w, c);
        let (mut v, packs) = vessel(&w, b"a", true);
        let a = n
            .nominate(&mut v, &packs, &ask(NominatedBy::Agent), &view(&w.tree))
            .unwrap();
        assert_eq!(
            a,
            Answer::Refused(NominationRefusal::Walk(WalkRefusal::UnknownPaths))
        );
        let Some(ContractRecord::NominationRefused(r)) = contracts(&v).pop() else {
            panic!()
        };
        assert!(
            r.input_manifest_key.is_some(),
            "the walk is kept for diagnosis"
        );
        // An exclusion outside the allowed set.
        let mut bad = ask(NominatedBy::Agent);
        bad.exclude = [PathClass::Source].into();
        assert_eq!(
            n.nominate(&mut v, &packs, &bad, &view(&w.tree)).unwrap(),
            Answer::Refused(NominationRefusal::BadExclude)
        );
        assert_eq!(
            n.nominate(&mut v, &packs, &bad, &view(&w.tree)).unwrap(),
            Answer::Refused(NominationRefusal::BadExclude)
        );
        assert_eq!(contracts(&v).len(), 2);
    }

    #[test]
    fn a_kept_link_into_the_exclusion_refuses() {
        let w = world();
        make_tree(&w.tree);
        symlink("../tmp/scratch", w.tree.join("app/scratch-link")).unwrap();
        chown_all(&w.tree);
        let n = nominator(&w, conf());
        let (mut v, packs) = vessel(&w, b"a", true);
        assert_eq!(
            n.nominate(&mut v, &packs, &ask(NominatedBy::Agent), &view(&w.tree))
                .unwrap(),
            Answer::Refused(NominationRefusal::Walk(WalkRefusal::DanglingByExclusion))
        );
        // Without the exclusion it is kept and nominates.
        let mut all = ask(NominatedBy::Agent);
        all.exclude = BTreeSet::new();
        assert!(matches!(
            n.nominate(&mut v, &packs, &all, &view(&w.tree)).unwrap(),
            Answer::Nominated(_)
        ));
    }

    #[test]
    fn every_failpoint_leaves_nothing_accepted_and_the_retry_is_the_same() {
        for fp in FAILPOINTS {
            let w = world();
            make_tree(&w.tree);
            let mut n = nominator(&w, conf());
            n.failpoint = Box::new(move |p| {
                if p == fp {
                    Err(NominateError::Failpoint(p))
                } else {
                    Ok(())
                }
            });
            let (mut v, packs) = vessel(&w, b"a", true);
            let e = n
                .nominate(&mut v, &packs, &ask(NominatedBy::Agent), &view(&w.tree))
                .unwrap_err();
            assert!(
                matches!(e, NominateError::Failpoint(p) if p == fp),
                "{fp}: {e}"
            );
            n.failpoint = no_failpoints();
            // A new epoch, as a rerun has: reopen the Vessel.
            let id = v.id();
            drop(v);
            let (mut v, _) = w.host.open(id).unwrap();
            let a = n
                .nominate(&mut v, &packs, &ask(NominatedBy::Agent), &view(&w.tree))
                .unwrap();
            let Answer::Nominated(cid) = a else {
                panic!("{fp}: {a:?}")
            };
            let c = candidate(&w, cid);
            // One artifact in the store: the retry put the same one.
            let arts =
                std::fs::read_dir(w.dir.path().join("store").join(PREFIX).join("obj/artifact"))
                    .unwrap()
                    .count();
            assert_eq!(arts, 1, "{fp}");
            assert!(w
                .coord
                .query_chronicle(id)
                .unwrap()
                .unwrap()
                .holds
                .contains(&taso_core::coordlog::ObjectId::content(c.artifact_key)));
        }
    }

    #[test]
    fn warden_local_limits_answer_retry() {
        let w = world();
        make_tree(&w.tree);
        let mut c = conf();
        c.max_open_candidates = 1;
        let n = nominator(&w, c);
        let (mut v, packs) = vessel(&w, b"a", true);
        assert!(matches!(
            n.nominate(&mut v, &packs, &ask(NominatedBy::Agent), &view(&w.tree))
                .unwrap(),
            Answer::Nominated(_)
        ));
        let mut other = ask(NominatedBy::Agent);
        other.exclude = BTreeSet::new();
        let a = n.nominate(&mut v, &packs, &other, &view(&w.tree)).unwrap();
        assert!(
            matches!(a, Answer::Retry(ref why) if why.contains("open Candidates")),
            "{a:?}"
        );
        // The minimum interval.
        let mut c = conf();
        c.min_interval = Duration::from_secs(3600);
        let n = nominator(&w, c);
        let (mut v2, packs2) = vessel(&w, b"b", true);
        assert!(matches!(
            n.nominate(&mut v2, &packs2, &other, &view(&w.tree))
                .unwrap(),
            Answer::Nominated(_)
        ));
        let a = n
            .nominate(&mut v2, &packs2, &ask(NominatedBy::Agent), &view(&w.tree))
            .unwrap();
        assert!(
            matches!(a, Answer::Retry(ref why) if why.contains("min_interval")),
            "{a:?}"
        );
    }

    // ── the transform alone ─────────────────────────────────────────

    fn e(path: &str, kind: Kind, class: PathClass, target: Option<&str>) -> classify::Entry {
        classify::Entry {
            path: path.as_bytes().to_vec(),
            kind,
            content: match (kind, target) {
                (Kind::Symlink, Some(t)) => Content::Target(t.as_bytes().to_vec()),
                (Kind::File, _) => Content::Blake3(HashVal::from_bytes([1; 32])),
                _ => Content::None,
            },
            size: if kind == Kind::File { 3 } else { 0 },
            mode: 0o644,
            uid_slot: 0,
            gid_slot: 0,
            mtime: classify::Mtime { secs: 1, nsec: 0 },
            class,
        }
    }

    fn m(entries: Vec<classify::Entry>, root_entries: u64) -> Manifest {
        Manifest {
            classmap_key: HashVal::from_bytes([2; 32]),
            root_entries,
            total_bytes: 0,
            incomplete: None,
            entries,
            unsupported: Vec::new(),
        }
    }

    #[test]
    fn the_transform_keeps_ancestors_as_structural_and_refuses_dangling_links() {
        use Kind::*;
        use PathClass::*;
        let input = m(
            vec![
                e("a", Dir, Scratch, None),
                e("a/keep.py", File, Source, None),
                e("a/x", File, Scratch, None),
                e("b", Dir, Scratch, None),
                e("b/y", File, Scratch, None),
                e("c", Dir, Source, None),
                e("c/z", File, Scratch, None),
                e("l", Symlink, Source, Some("a/keep.py")),
            ],
            5, // a, b, c, l and a reserved lost+found
        );
        let ex: BTreeSet<PathClass> = [Scratch].into();
        let out = transform(&input, &ex).unwrap();
        let got: Vec<(String, PathClass)> = out
            .entries
            .iter()
            .map(|e| (String::from_utf8(e.path.clone()).unwrap(), e.class))
            .collect();
        assert_eq!(
            got,
            [
                ("a".into(), Structural),
                ("a/keep.py".into(), Source),
                ("c".into(), Source),
                ("l".into(), Source)
            ]
        );
        assert_eq!(out.root_entries, 4, "b dropped; lost+found stays counted");
        assert_eq!(out.total_bytes, 3);
        // A kept link into a dropped file, or a dropped directory.
        for t in ["b/y", "a/x", "b", "c/../b/./y"] {
            let mut i = input.clone();
            i.entries.push(e("m", Symlink, Source, Some(t)));
            assert!(transform(&i, &ex).is_err(), "{t}");
        }
        // A link that was dangling already, or at the root, is not the
        // exclusion's doing.
        for t in ["nowhere", "."] {
            let mut i = input.clone();
            i.entries.push(e("m", Symlink, Source, Some(t)));
            assert!(transform(&i, &ex).is_ok(), "{t}");
        }
        // A dropped link into a dropped file is no matter.
        let mut i = input.clone();
        i.entries.push(e("n", Symlink, Scratch, Some("b/y")));
        assert!(transform(&i, &ex).is_ok());
        assert_eq!(resolve(b"a/b/l", b"../../x"), Some(b"x".to_vec()));
        assert_eq!(resolve(b"l", b"../x"), None);
        assert_eq!(resolve(b"l", b"/etc"), None);
    }
}
