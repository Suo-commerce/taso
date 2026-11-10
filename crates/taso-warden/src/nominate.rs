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
//! 2. **The verifier Template** must be ready (review fix N2a), and
//!    **Warden-local limits** (D62): open Candidates per Vessel, the
//!    minimum interval, concurrent walks.  Otherwise: `Retry`.
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
//! A walk refused for good -- one the content decides (review fixes 4a,
//! W) -- is a `NominationRefused` keyed by the Candidate id, appended and
//! accepted the same way; it holds nothing.  Every other refusal is
//! answered and not recorded: the log or the node's settings already say
//! it, or (a limit, the clock, an unreadable file) asking later can go
//! otherwise, answered `Retry`.  Every step before the accept leaves nothing accepted, and
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

/// A class by its name in the classification map (`"Scratch"`, …): one
/// of the six a map assigns.
pub fn class_named(name: &str) -> Option<PathClass> {
    Some(match name {
        "Source" => PathClass::Source,
        "Config" => PathClass::Config,
        "Hook" => PathClass::Hook,
        "Secret" => PathClass::Secret,
        "Scratch" => PathClass::Scratch,
        "Artifact" => PathClass::Artifact,
        _ => return None,
    })
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
        let found = match (find_seal(&frames, ask.seal)?, ask.seal) {
            (Some(found), _) => Some(found),
            // A named Seal before the local log's first record: pruned
            // here after it was shipped, so its pack has it (audit
            // 2026-11-09, A5; D&D P2 (a)).  Read from the log alone, an
            // accepted and shipped Seal was refused as never accepted.
            (None, Some(lsn)) if frames.first().is_some_and(|f| lsn < f.envelope.lsn) => {
                let shipped = packs
                    .shipped_frame(lsn)
                    .map_err(|e| NominateError::Vessel(VesselError::Pack(e)))?;
                find_seal(shipped.as_slice(), Some(lsn))?
            }
            (None, _) => None,
        };
        let Some((seal, record)) = found else {
            return Ok(Answer::Refused(NominationRefusal::SealNotAccepted));
        };
        // Refused, nothing recorded: the log or the node's settings already
        // say it (review fix 4a: only a walk refusal is recorded).
        let refused = |reason| Ok(Answer::Refused(reason));
        let Some(record) = record else {
            // A record at that lsn, not a Seal.
            return refused(NominationRefusal::SealNotAccepted);
        };
        if self.coord.head(id)?.lsn < seal.lsn {
            return refused(NominationRefusal::SealNotAccepted);
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
            return refused(NominationRefusal::BadExclude);
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
            return refused(NominationRefusal::Closed);
        }
        if let Some(ContractRecord::Candidate(c)) = self.accepted(LogicalKey::Candidate(cid))? {
            return if same_kind(&c.nominated_by, &ask.by) {
                Ok(Answer::Nominated(cid))
            } else {
                refused(NominationRefusal::Duplicate)
            };
        }
        // A walk refusal recorded for this very Candidate id: the files and
        // the map are the same, so the walk would be refused again.
        if let Some(ContractRecord::NominationRefused(r)) =
            self.accepted(LogicalKey::NominationRefused(cid))?
        {
            return refused(NominationRefusal::Walk(r.reason));
        }
        let walk_refused = |reason, input_manifest_key| NominationRefused {
            chronicle: id,
            seal,
            exclude: ask.exclude.clone(),
            transform_version: TRANSFORM_VERSION,
            classmap_key: self.conf.classmap.key(),
            requirement,
            reason,
            input_manifest_key,
        };

        // The verifier Template must be ready (review fix N2a): a
        // Candidate naming one that is not could never start an attempt,
        // and would stay open where policy never sees it.  Nothing is
        // recorded: it may yet be registered.
        if !matches!(
            self.accepted(LogicalKey::Template(ask.verifier))?,
            Some(ContractRecord::TemplateReady(_))
        ) {
            return Ok(Answer::Retry(format!(
                "the verifier Template {} is not a ready Template",
                hex(ask.verifier.as_bytes())
            )));
        }

        // 2. Warden-local limits.
        let open = self.open_candidates(id)?;
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
            return self.refuse_walk(vessel, packs, walk_refused(w, input_key), &input);
        }

        // 4. Transform.
        let Ok(output) = transform(&input, &ask.exclude) else {
            return self.refuse_walk(
                vessel,
                packs,
                walk_refused(WalkRefusal::DanglingByExclusion, input_key),
                &input,
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
        // The adopted effects are counted over the whole log up to the
        // Seal: what pruning took from the local log is read from the
        // shipped packs (D&D P1 (a1); a Checkpoint will carry the count
        // at the next format break).
        let earlier = match frames.first().map(|f| f.envelope.lsn.get()) {
            Some(first) if first > 1 => packs
                .shipped_frames(Lsn::new(1), Lsn::new(first - 1))
                .map_err(|e| NominateError::Vessel(VesselError::Pack(e)))?,
            _ => Vec::new(),
        };
        let facts = Facts {
            input: input.counts(),
            excluded: dropped_counts(&input, &output),
            open_obligations: self.coord.obligations(id)?.len() as u64,
            effects_adopted: effects_adopted(earlier.iter().chain(frames.iter()), seal.lsn)?,
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
            Err(e) => Err(SubmitError::Inconsistent(e.to_string())),
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
                    Ok(Answer::Refused(NominationRefusal::Duplicate))
                }
            }
            Ok(other) => Err(NominateError::Submit(SubmitError::Inconsistent(format!(
                "the Candidate's logical id holds {other:?}"
            )))),
            Err(SubmitError::Coord(_)) => Ok(Answer::Pending(cid)),
            // Refused for now and cancelled: nothing decided (R2a: an
            // object it holds was reclaimed within the quarantine, and
            // is held once that has passed).
            Err(SubmitError::NotAccepted(t)) => Ok(Answer::Retry(match t {
                taso_core::coordlog::Transient::Quarantined(o) => {
                    format!("{o:?} was reclaimed within the store's quarantine; ask again later")
                }
                t => format!("the Candidate was not accepted for now: {t:?}"),
            })),
            Err(e) => Err(e.into()),
        }
    }

    /// A walk refused (review fixes 4a, W).  Recorded, as a
    /// `NominationRefused` keyed by the Candidate id, only if the content
    /// decides it ([`WalkRefusal::decided_by_content`], and no entry was
    /// unreadable): then the same request is answered from the record and
    /// never walked again, while a changed map, requirement or rule makes
    /// another id and walks.  Otherwise -- a limit or the clock stopped
    /// the walk, `fs.reserved`, a file that could not be read -- asking
    /// later can go otherwise: `Retry`, nothing recorded.
    fn refuse_walk<L: Layers, X: Sender>(
        &self,
        vessel: &mut Vessel<L>,
        packs: &Packs<SharedStore, X>,
        refused: NominationRefused,
        walked: &Manifest,
    ) -> Result<Answer, NominateError> {
        let unreadable = walked
            .unsupported
            .iter()
            .any(|(_, u)| *u == Unsupported::Unreadable);
        if !refused.reason.decided_by_content()
            || (refused.reason == WalkRefusal::Unsupported && unreadable)
        {
            return Ok(Answer::Retry(format!(
                "the walk was refused for now ({:?}{}): nothing in the files decides it, \
                 so nothing is recorded; ask again",
                refused.reason,
                if unreadable {
                    ", an entry could not be read"
                } else {
                    ""
                }
            )));
        }
        if let Some(why) = self.unshippable(vessel)? {
            return Ok(Answer::Retry(why));
        }
        let rec = ContractRecord::NominationRefused(refused);
        if let Some(ContractRecord::NominationRefused(r)) = self.accepted_id(rec.logical_id())? {
            return Ok(Answer::Refused(NominationRefusal::Walk(r.reason)));
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
                Ok(Answer::Refused(NominationRefusal::Walk(r.reason)))
            }
            other => Err(NominateError::Submit(SubmitError::Inconsistent(format!(
                "a refusal's logical id holds {other:?}"
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

    /// The Vessel's open Candidates: those the coordinator has accepted
    /// and not closed.  Closed (§3.5): by `Never`, `Cancel` or
    /// `Supersede`, and sanctioned once the commit's `TemplateReady` is
    /// accepted (a commit before that is "committing", still counted).
    /// Soak, taso-test 2026-11-09: a sanctioned Candidate was counted open
    /// for good, so after four sanctions a Vessel's every nomination was
    /// answered Retry for the rest of its life (12 000 times in 5 hours).
    fn open_candidates(&self, chronicle: ChronicleId) -> Result<usize, NominateError> {
        // From the coordinator's list of the Vessel's outstanding work,
        // never its local log, which loses its prefix to pruning (audit
        // 2026-11-09, A5; review fix A2-1's class): counted from the log,
        // the limit read 0 once the Candidates' records were pruned.  The
        // list holds every Candidate not closed, and a Candidate closes
        // at its close record or at its Template's `TemplateReady`.
        Ok(crate::attempt::open_work(self.coord.as_ref(), chronicle)?
            .iter()
            .filter(|r| matches!(r, ContractRecord::Candidate(_)))
            .count())
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
/// intents whose authority is an `AdoptedFrom` naming the child and Seal
/// of the Promotion record before them, written before the next Seal.
///
/// An adoption is written right after its Promotion, and the Vessel takes
/// no effect from its agent until the next Seal, its adoption Seal (C7,
/// audit A3/A4).  `authority` is otherwise the agent's own bytes: it used
/// to count any later intent whose authority began with a promoted
/// child's id and Seal, so an agent could raise the count by declaring
/// effects that named them (audit 2026-11-09, an agent-declared
/// authority inflates the adopted-effects count).
///
/// `frames` is the Vessel's log from its first record: a local log that
/// has lost its prefix to pruning counts only what is left (audit
/// 2026-11-09, A5), so the caller puts the shipped records before it.
pub(crate) fn effects_adopted<'a>(
    frames: impl Iterator<Item = &'a Frame>,
    seal: Lsn,
) -> Result<u64, NominateError> {
    // The Promotion whose adoption may still be written: until the next
    // Seal.
    let mut adopting: Option<Vec<u8>> = None;
    let mut n = 0;
    for f in frames.take_while(|f| f.envelope.lsn <= seal) {
        match Payload::decode(&f.payload) {
            Ok(Payload::Promotion(p)) => {
                let mut c = taso_core::canon::Canon::default();
                p.child.canon(&mut c);
                p.seal.canon(&mut c);
                adopting = Some(c.as_bytes().to_vec());
            }
            Ok(Payload::Seal(_)) => adopting = None,
            Ok(Payload::Intent(i))
                if i.authority.len() == 32
                    && adopting
                        .as_ref()
                        .is_some_and(|p| i.authority.starts_with(p)) =>
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
    use crate::storage::{Dataset, Snapshot};
    use crate::vessel::tests::{fake_guid, ns, FakePool};
    use crate::vessel::Host;

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
        /// A ready Template, the verifier every [`ask`] names.
        verifier: ChronicleId,
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
        let mut w = World {
            dir,
            store,
            coord,
            host,
            tree,
            verifier: ChronicleId::from_bytes([0; 16]),
        };
        w.verifier = ready_template(&w);
        w
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

    /// A ready Template by genesis of a small tree, for an `Ask` to name
    /// as its verifier (review fix N2a: nomination checks it is ready).
    fn ready_template(w: &World) -> ChronicleId {
        use crate::genesis::{self, tests::DirPool, Genesis, Outcome, Request, Source};
        let src = w.dir.path().join("verifier-src");
        std::fs::create_dir_all(src.join("bin")).unwrap();
        std::fs::write(src.join("bin/check"), "#!/bin/sh\n").unwrap();
        let pool = w.dir.path().join("gpool");
        std::fs::create_dir_all(&pool).unwrap();
        let g = Genesis {
            pool: DirPool::new(&pool),
            store: w.store.clone(),
            prefix: PREFIX.into(),
            coord: w.coord.clone(),
            warden: WardenId::new(100),
            state_dir: w.dir.path().join("gstate"),
            root: Dataset::new("tank/taso").unwrap(),
            host_uid_base: BASE,
            limits: Limits::default(),
            reserved: Reserved::defaults(),
            failpoint: genesis::no_failpoints(),
        };
        let r = g
            .run(&Request {
                source: Source::Dir(src),
                classmap: MAP.as_bytes().to_vec(),
                authority: taso_core::record::Authority {
                    actor: "operator".into(),
                    reason: "a verifier".into(),
                },
                hook_waiver: None,
                best_effort: true,
                peer: taso_core::contract::Peer { uid: 0, pid: 1 },
            })
            .unwrap();
        let Outcome::Ready { template_id, .. } = r.outcome else {
            panic!("{:?}", r.outcome)
        };
        template_id
    }

    /// An ask naming `w`'s ready verifier Template.
    fn ask(w: &World, by: NominatedBy) -> Ask {
        Ask {
            seal: None,
            exclude: [PathClass::Scratch].into(),
            verifier: w.verifier,
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
            .nominate(&mut v, &packs, &ask(&w, NominatedBy::Agent), &view(&w.tree))
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
            .nominate(&mut v, &packs, &ask(&w, NominatedBy::Agent), &view(&w.tree))
            .unwrap();
        assert_eq!(again, Answer::Nominated(cid));
        assert_eq!(contracts(&v).len(), 1);
        // Another kind of request for the same id: Duplicate, answered from
        // the log and not recorded (review fix 4a).
        let dup = n
            .nominate(
                &mut v,
                &packs,
                &ask(&w, NominatedBy::Config),
                &view(&w.tree),
            )
            .unwrap();
        assert_eq!(dup, Answer::Refused(NominationRefusal::Duplicate));
        let dup2 = n
            .nominate(
                &mut v,
                &packs,
                &ask(&w, NominatedBy::Config),
                &view(&w.tree),
            )
            .unwrap();
        assert_eq!(dup2, dup);
        assert_eq!(contracts(&v).len(), 1, "only the Candidate");
    }

    #[test]
    fn a_seal_not_shipped_is_retried_never_recorded() {
        let w = world();
        make_tree(&w.tree);
        let n = nominator(&w, conf());
        let (mut v, packs) = vessel(&w, b"a", false);
        let a = n
            .nominate(&mut v, &packs, &ask(&w, NominatedBy::Agent), &view(&w.tree))
            .unwrap();
        assert!(
            matches!(a, Answer::Retry(ref why) if why.contains("not shipped")),
            "{a:?}"
        );
        assert!(contracts(&v).is_empty());
        // A record that is not a Seal, and an lsn with nothing: refused,
        // and never recorded (review fix 4a), shipped or not.
        let mut a = ask(&w, NominatedBy::Agent);
        a.seal = Some(Lsn::new(1)); // the Lineage
        assert_eq!(
            n.nominate(&mut v, &packs, &a, &view(&w.tree)).unwrap(),
            Answer::Refused(NominationRefusal::SealNotAccepted)
        );
        assert!(contracts(&v).is_empty());
        let s = v.last_seal().unwrap();
        let snap = Snapshot {
            dataset: v.dataset().clone(),
            seal: s.lsn,
            guid: fake_guid(s.lsn),
            seal_hash: Some(s.hash),
        };
        v.publish_seal(&packs, &snap, None).unwrap();
        assert_eq!(
            n.nominate(&mut v, &packs, &a, &view(&w.tree)).unwrap(),
            Answer::Refused(NominationRefusal::SealNotAccepted)
        );
        a.seal = Some(Lsn::new(999));
        assert_eq!(
            n.nominate(&mut v, &packs, &a, &view(&w.tree)).unwrap(),
            Answer::Refused(NominationRefusal::SealNotAccepted)
        );
        assert!(contracts(&v).is_empty());
    }

    /// Review fix 4a: a walk the content refuses is recorded once, under
    /// the Candidate id, and the same request is answered from it without
    /// walking; once the operator fixes the classification map, the request
    /// is another Candidate id and walks again.  Other refusals are not
    /// recorded.
    #[test]
    fn a_walk_refusal_is_recorded_by_candidate_id_and_a_fixed_map_walks_again() {
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
        let narrow = c.classmap.key();
        let n = nominator(&w, c);
        let (mut v, packs) = vessel(&w, b"a", true);
        let unknown = Answer::Refused(NominationRefusal::Walk(WalkRefusal::UnknownPaths));
        let a = n
            .nominate(&mut v, &packs, &ask(&w, NominatedBy::Agent), &view(&w.tree))
            .unwrap();
        assert_eq!(a, unknown);
        let Some(ContractRecord::NominationRefused(r)) = contracts(&v).pop() else {
            panic!()
        };
        assert_eq!(r.classmap_key, narrow);
        assert_eq!(
            w.coord
                .query_logical(logical_id(&LogicalKey::NominationRefused(r.candidate_id())))
                .unwrap()
                .map(|(_, rec)| rec.digest()),
            Some(Submitted::Contract(ContractRecord::NominationRefused(r.clone())).digest()),
            "recorded under the Candidate id"
        );
        // Asked again: answered from the record, nothing walked (the
        // Seal's view is never opened) or added.
        let never = |_: Lsn| -> Result<SealView, LayerError> { Err("walked again".into()) };
        assert_eq!(
            n.nominate(&mut v, &packs, &ask(&w, NominatedBy::Agent), &never)
                .unwrap(),
            unknown
        );
        assert_eq!(contracts(&v).len(), 1);
        // An exclusion outside the allowed set: refused, never recorded.
        let mut bad = ask(&w, NominatedBy::Agent);
        bad.exclude = [PathClass::Source].into();
        for _ in 0..2 {
            assert_eq!(
                n.nominate(&mut v, &packs, &bad, &view(&w.tree)).unwrap(),
                Answer::Refused(NominationRefusal::BadExclude)
            );
        }
        assert_eq!(contracts(&v).len(), 1);
        // The operator fixes the map (a catch-all): another Candidate id,
        // walked again, and nominated.
        let fixed = nominator(&w, conf());
        assert!(matches!(
            fixed
                .nominate(&mut v, &packs, &ask(&w, NominatedBy::Agent), &view(&w.tree))
                .unwrap(),
            Answer::Nominated(_)
        ));
    }

    /// Review W: a walk a limit stopped is not about the files: `Retry`,
    /// nothing recorded; with room, the same request nominates.
    #[test]
    fn an_incomplete_walk_answers_retry_and_records_nothing() {
        let w = world();
        make_tree(&w.tree);
        let mut tight = conf();
        tight.limits.max_entries = 2;
        let n = nominator(&w, tight);
        let (mut v, packs) = vessel(&w, b"a", true);
        let a = n
            .nominate(&mut v, &packs, &ask(&w, NominatedBy::Agent), &view(&w.tree))
            .unwrap();
        assert!(
            matches!(a, Answer::Retry(ref why) if why.contains("IncompleteWalk")),
            "{a:?}"
        );
        assert!(contracts(&v).is_empty(), "nothing recorded");
        let roomy = nominator(&w, conf());
        assert!(matches!(
            roomy
                .nominate(&mut v, &packs, &ask(&w, NominatedBy::Agent), &view(&w.tree))
                .unwrap(),
            Answer::Nominated(_)
        ));
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
            n.nominate(&mut v, &packs, &ask(&w, NominatedBy::Agent), &view(&w.tree))
                .unwrap(),
            Answer::Refused(NominationRefusal::Walk(WalkRefusal::DanglingByExclusion))
        );
        // Without the exclusion it is kept and nominates.
        let mut all = ask(&w, NominatedBy::Agent);
        all.exclude = BTreeSet::new();
        assert!(matches!(
            n.nominate(&mut v, &packs, &all, &view(&w.tree)).unwrap(),
            Answer::Nominated(_)
        ));
    }

    /// Review fix N2a: a verifier Template that is not ready answers
    /// `Retry` and records nothing (no Candidate, no refusal); once it is
    /// ready, the same ask nominates.
    #[test]
    fn an_unknown_verifier_template_answers_retry_and_records_nothing() {
        let w = world();
        make_tree(&w.tree);
        let n = nominator(&w, conf());
        let (mut v, packs) = vessel(&w, b"a", true);
        let before = contracts(&v);
        let mut unknown = ask(&w, NominatedBy::Agent);
        unknown.verifier = ChronicleId::from_bytes([0x99; 16]);
        let a = n
            .nominate(&mut v, &packs, &unknown, &view(&w.tree))
            .unwrap();
        let Answer::Retry(why) = a else {
            panic!("{a:?}")
        };
        assert!(why.contains("not a ready Template"), "{why}");
        assert_eq!(contracts(&v), before, "nothing appended");
        let objects = |kind: &str| {
            std::fs::read_dir(
                w.dir
                    .path()
                    .join("store")
                    .join(PREFIX)
                    .join("obj")
                    .join(kind),
            )
            .map_or(0, |d| d.count())
        };
        assert_eq!(objects("vconf"), 0, "nothing put for it");
        // A real Template: the same Vessel nominates.
        assert!(matches!(
            n.nominate(&mut v, &packs, &ask(&w, NominatedBy::Agent), &view(&w.tree))
                .unwrap(),
            Answer::Nominated(_)
        ));
    }

    #[test]
    fn every_failpoint_leaves_nothing_accepted_and_the_retry_is_the_same() {
        let artifacts = |w: &World| {
            std::fs::read_dir(w.dir.path().join("store").join(PREFIX).join("obj/artifact"))
                .map_or(0, |d| d.count())
        };
        for fp in FAILPOINTS {
            let w = world();
            make_tree(&w.tree);
            // The verifier Template's own artifact is there already.
            let before = artifacts(&w);
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
                .nominate(&mut v, &packs, &ask(&w, NominatedBy::Agent), &view(&w.tree))
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
                .nominate(&mut v, &packs, &ask(&w, NominatedBy::Agent), &view(&w.tree))
                .unwrap();
            let Answer::Nominated(cid) = a else {
                panic!("{fp}: {a:?}")
            };
            let c = candidate(&w, cid);
            // One artifact more in the store: the retry put the same one.
            assert_eq!(artifacts(&w), before + 1, "{fp}");
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
            n.nominate(&mut v, &packs, &ask(&w, NominatedBy::Agent), &view(&w.tree))
                .unwrap(),
            Answer::Nominated(_)
        ));
        let mut other = ask(&w, NominatedBy::Agent);
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
            .nominate(
                &mut v2,
                &packs2,
                &ask(&w, NominatedBy::Agent),
                &view(&w.tree),
            )
            .unwrap();
        assert!(
            matches!(a, Answer::Retry(ref why) if why.contains("min_interval")),
            "{a:?}"
        );
    }

    /// Audit 2026-11-09, A5: the limit of open Candidates is counted from
    /// the coordinator's list, not from the Vessel's local log.  That log
    /// loses its prefix to pruning: counted from it, the limit read 0
    /// once the Candidates' records were pruned, and never held.
    #[test]
    fn the_open_candidate_limit_holds_after_the_log_is_pruned() {
        let w = world();
        make_tree(&w.tree);
        let mut c = conf();
        c.max_open_candidates = 1;
        let n = nominator(&w, c);
        let (mut v, packs) = vessel(&w, b"a", true);
        assert!(matches!(
            n.nominate(&mut v, &packs, &ask(&w, NominatedBy::Agent), &view(&w.tree))
                .unwrap(),
            Answer::Nominated(_)
        ));
        // The Candidate's record leaves the local log: roll after every
        // record, write past it, and prune everything shipped.
        let has_candidate = |v: &Vessel<_>| {
            v.chronicle().frames().unwrap().iter().any(|f| {
                matches!(
                    Payload::decode(&f.payload),
                    Ok(Payload::Contract(r)) if matches!(*r, ContractRecord::Candidate(_))
                )
            })
        };
        assert!(has_candidate(&v));
        // A later turn in a new segment file, sealed and published as the
        // agent's run does: the newest Seal stays local, the file before
        // it is shipped and pruned.
        v.set_roll_at(1);
        v.append(Stream::Transcript, Payload::Raw(b"later".to_vec()))
            .unwrap();
        v.set_roll_at(u64::MAX);
        let s = v
            .seal(
                StreamCut::EMPTY,
                Verdict::Clean,
                Lsn::new(0),
                TurnId::new(2),
            )
            .unwrap()
            .seal;
        let snap = Snapshot {
            dataset: v.dataset().clone(),
            seal: s.lsn,
            guid: fake_guid(s.lsn),
            seal_hash: Some(s.hash),
        };
        v.publish_seal(&packs, &snap, None).unwrap();
        v.prune(0).unwrap();
        assert!(!has_candidate(&v), "pruned");
        let mut other = ask(&w, NominatedBy::Agent);
        other.exclude = BTreeSet::new();
        let a = n.nominate(&mut v, &packs, &other, &view(&w.tree)).unwrap();
        assert!(
            matches!(a, Answer::Retry(ref why) if why.contains("open Candidates")),
            "{a:?}"
        );
    }

    /// Audit 2026-11-09, A5 (D&D P2 (a)): a named Seal whose record was
    /// pruned from the local log is read from the pack that shipped it.
    /// Read from the local log alone, an accepted and shipped Seal was
    /// refused for good as "not accepted".
    #[test]
    fn a_named_seal_pruned_from_the_log_is_read_from_its_pack() {
        let w = world();
        make_tree(&w.tree);
        let n = nominator(&w, conf());
        let (mut v, packs) = vessel(&w, b"a", true);
        let first = v.last_seal().unwrap();
        v.set_roll_at(1);
        v.append(Stream::Transcript, Payload::Raw(b"later".to_vec()))
            .unwrap();
        v.set_roll_at(u64::MAX);
        let s = v
            .seal(
                StreamCut::EMPTY,
                Verdict::Clean,
                Lsn::new(0),
                TurnId::new(2),
            )
            .unwrap()
            .seal;
        let snap = Snapshot {
            dataset: v.dataset().clone(),
            seal: s.lsn,
            guid: fake_guid(s.lsn),
            seal_hash: Some(s.hash),
        };
        v.publish_seal(&packs, &snap, None).unwrap();
        v.prune(0).unwrap();
        let local = v.chronicle().frames().unwrap();
        assert!(
            local[0].envelope.lsn > first.lsn,
            "the first Seal is pruned"
        );
        // What pruning took is in the packs, every record of it.
        let before = local[0].envelope.lsn.get() - 1;
        let shipped = packs.shipped_frames(Lsn::new(1), Lsn::new(before)).unwrap();
        assert_eq!(
            shipped
                .iter()
                .map(|f| f.envelope.lsn.get())
                .collect::<Vec<_>>(),
            (1..=before).collect::<Vec<_>>()
        );
        assert!(matches!(
            packs.shipped_frames(Lsn::new(1), Lsn::new(9999)),
            Err(crate::pack::PackError::Gap { .. })
        ));

        let mut a = ask(&w, NominatedBy::Agent);
        a.seal = Some(first.lsn);
        let Answer::Nominated(cid) = n.nominate(&mut v, &packs, &a, &view(&w.tree)).unwrap() else {
            panic!("the pruned Seal is nominated");
        };
        assert_eq!(candidate(&w, cid).seal.lsn, first.lsn);
        // A pruned lsn that holds no Seal, and one past the log: refused.
        a.seal = Some(Lsn::new(1));
        assert_eq!(
            n.nominate(&mut v, &packs, &a, &view(&w.tree)).unwrap(),
            Answer::Refused(NominationRefusal::SealNotAccepted)
        );
        a.seal = Some(Lsn::new(9999));
        assert_eq!(
            n.nominate(&mut v, &packs, &a, &view(&w.tree)).unwrap(),
            Answer::Refused(NominationRefusal::SealNotAccepted)
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
        // A chain whose final target the exclusion drops (review N1): a
        // kept link to a dropped link, and a kept link to a kept link
        // into a dropped file.
        for (l2_class, l2_target) in [(Scratch, "a/keep.py"), (Source, "b/y")] {
            let mut i = input.clone();
            i.entries.push(e("l1", Symlink, Source, Some("l2")));
            i.entries.push(e("l2", Symlink, l2_class, Some(l2_target)));
            i.entries.sort_by(|a, b| a.path.cmp(&b.path));
            assert!(
                transform(&i, &ex).is_err(),
                "l2 {l2_class:?} -> {l2_target}"
            );
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
