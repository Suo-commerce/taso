//! Verification attempts: their records and their runs (P4 spec rev. 30
//! §3.4; D66, D68–D70, D88, D90; files 7b, 15).
//!
//! **Records** ([`Attempts`]), on the Vessel's session thread, through
//! the Vessel's own log: [`Attempts::start`] appends and accepts
//! `VerificationStarted` (`started_at` = the tail) before anything runs;
//! [`Attempts::finish`] appends and accepts `VerificationFinished`;
//! [`Attempts::interrupt_open`] closes every open attempt `Interrupted`
//! at an open (D69); [`Attempts::to_attempt`] lists the open Candidates
//! the Warden launches an attempt for: those that never had one (D68),
//! and those whose attempts all ended `Interrupted`, fewer than
//! [`MAX_INTERRUPTED`] of them (D88).
//!
//! **A run** ([`AttemptRun::run`]), on its own thread: the vconf (D64),
//! the verifier Template's layer as the read-only root (D65), the
//! artifact restored into `<root>/a-<attempt_id hex>`, checked against
//! the output manifest and sealed (D66), the container run with its
//! output captured and its limits enforced (D67).  Anything that keeps it
//! from starting ends it `LaunchFailed`, with the reason as its output.
//! [`destroy_candidate`] removes the `/candidate` dataset once the
//! attempt's `VerificationFinished` is accepted (D66).
//!
//! Normative reference: `Taso_spec_p4_contracts` rev. 30, BLAKE3
//! `b5f59255657885a8c056c1e758e76699f1a36485a2e2327ca21d47c6ead1ccd8`.

use std::collections::BTreeSet;
use std::fmt;
use std::io::Read;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use taso_core::contract::{
    attempt_id, logical_id, output_digest, result_digest, Candidate, ContractRecord, LogicalKey,
    ObjectKind, Outcome, VerificationFinished, VerificationStarted,
};
use taso_core::coordlog::Submitted;
use taso_core::envelope::{HashVal, Lsn, Stream};
use taso_core::model::WardenId;
use taso_core::record::Payload;

use crate::artifact;
use crate::chronicle::{ChronicleError, Layers};
use crate::classify::{self, Classmap, Limits, Manifest, Owner, Reserved};
use crate::coordinator::{Coord, CoordError};
use crate::coordstore::object_key_path;
use crate::pack::Packs;
use crate::runtime::{write_verifier_bundle, VerifierSpec, VERIFIER_DIRS};
use crate::segment::Frame;
use crate::ship::{Sender, SharedStore};
use crate::submit::{self, SubmitError};
use crate::template::{own_top, same_entries, TemplateLayers, LAYER_LSN};
use crate::verify::{outcome_of, run_capped, Vconf, VerifierLimits};
use crate::vessel::{Pool, Vessel, VesselError};
use crate::zfs::Dataset;

/// The three failpoints of an attempt (§10.2 row 7).
pub const FAILPOINTS: [&str; 3] = [
    "verify.before_started_accept",
    "verify.mid_run",
    "verify.before_finished_accept",
];

/// After this many interrupted attempts of a Candidate the Warden stops
/// running its verifier again (D88): it waits for a verdict and its TTL.
pub const MAX_INTERRUPTED: u32 = 3;

/// The `/candidate` Seal's lsn in its dataset.
const CANDIDATE_LSN: Lsn = Lsn::new(1);

/// Why an attempt's record was not accepted.
#[derive(Debug)]
pub enum AttemptError {
    /// The Vessel failed.
    Vessel(VesselError),
    /// The coordinator failed.
    Coord(CoordError),
    /// Submitting failed (a refusal included).
    Submit(SubmitError),
    /// A deliberate stop at a named failpoint (tests).
    Failpoint(&'static str),
}

impl fmt::Display for AttemptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Vessel(e) => write!(f, "vessel: {e}"),
            Self::Coord(e) => write!(f, "coordinator: {e}"),
            Self::Submit(e) => write!(f, "submit: {e}"),
            Self::Failpoint(p) => write!(f, "stopped at failpoint {p}"),
        }
    }
}

impl std::error::Error for AttemptError {}

impl From<VesselError> for AttemptError {
    fn from(e: VesselError) -> Self {
        Self::Vessel(e)
    }
}
impl From<CoordError> for AttemptError {
    fn from(e: CoordError) -> Self {
        Self::Coord(e)
    }
}
impl From<SubmitError> for AttemptError {
    fn from(e: SubmitError) -> Self {
        match e {
            SubmitError::Stopped(p) => Self::Failpoint(p),
            e => Self::Submit(e),
        }
    }
}

/// A failpoint hook shared by the records and the runs.
pub type Failpoint = Arc<dyn Fn(&'static str) -> bool + Send + Sync>;

/// No failpoints.
pub fn no_failpoints() -> Failpoint {
    Arc::new(|_| false)
}

/// An attempt's records, through a Vessel's own log.
pub struct Attempts {
    /// The coordinator.
    pub coord: Arc<dyn Coord>,
    /// This Warden.
    pub warden: WardenId,
    /// `true` stops at that failpoint.
    pub failpoint: Failpoint,
}

impl Attempts {
    /// Start an attempt of `candidate`: `VerificationStarted` appended and
    /// accepted (holds on the verifier layer and the artifact).
    pub fn start<L: Layers, X: Sender>(
        &self,
        vessel: &mut Vessel<L>,
        packs: &Packs<SharedStore, X>,
        candidate: &Candidate,
    ) -> Result<VerificationStarted, AttemptError> {
        let started_at = vessel.tail().lsn;
        let st = VerificationStarted {
            candidate_id: candidate.candidate_id,
            attempt_id: attempt_id(candidate.candidate_id, started_at),
            artifact_key: candidate.artifact_key,
            requirement: candidate.requirement,
            started_at,
        };
        self.record(
            vessel,
            packs,
            ContractRecord::VerificationStarted(st),
            "verify.before_started_accept",
        )?;
        Ok(st)
    }

    /// Finish `started` with `outcome` and `output` (cut to the bound by
    /// the run): `VerificationFinished` appended and accepted.
    pub fn finish<L: Layers, X: Sender>(
        &self,
        vessel: &mut Vessel<L>,
        packs: &Packs<SharedStore, X>,
        started: &VerificationStarted,
        outcome: Outcome,
        output: Vec<u8>,
    ) -> Result<VerificationFinished, AttemptError> {
        let od = output_digest(&output);
        let f = VerificationFinished {
            attempt_id: started.attempt_id,
            result_digest: result_digest(
                started.candidate_id,
                started.artifact_key,
                &started.requirement,
                started.attempt_id,
                &outcome,
                od,
            ),
            outcome,
            output_digest: od,
            output,
            finished_at: vessel.tail().lsn,
        };
        debug_assert!(f.is_consistent_with(started));
        self.record(
            vessel,
            packs,
            ContractRecord::VerificationFinished(f.clone()),
            "verify.before_finished_accept",
        )?;
        Ok(f)
    }

    /// Close every open attempt of `vessel` `Interrupted` (D69): the
    /// attempts closed.
    pub fn interrupt_open<L: Layers, X: Sender>(
        &self,
        vessel: &mut Vessel<L>,
        packs: &Packs<SharedStore, X>,
    ) -> Result<Vec<VerificationStarted>, AttemptError> {
        let open = self.open(vessel)?;
        for st in &open {
            self.finish(vessel, packs, st, Outcome::Interrupted, Vec::new())?;
        }
        Ok(open)
    }

    /// The attempts of `vessel` whose `VerificationStarted` is accepted
    /// and whose `VerificationFinished` is not.
    pub fn open<L: Layers>(
        &self,
        vessel: &Vessel<L>,
    ) -> Result<Vec<VerificationStarted>, AttemptError> {
        let mut out = Vec::new();
        for st in self.started(vessel)? {
            if self.accepted(LogicalKey::Attempt(st.attempt_id))?
                && !self.accepted(LogicalKey::AttemptFinished(st.attempt_id))?
            {
                out.push(st);
            }
        }
        Ok(out)
    }

    /// Every accepted `VerificationStarted` in `vessel`'s log whose
    /// attempt is finished.
    pub fn finished<L: Layers>(
        &self,
        vessel: &Vessel<L>,
    ) -> Result<Vec<VerificationStarted>, AttemptError> {
        let mut out = Vec::new();
        for st in self.started(vessel)? {
            if self.accepted(LogicalKey::AttemptFinished(st.attempt_id))? {
                out.push(st);
            }
        }
        Ok(out)
    }

    /// The open Candidates of `vessel` (accepted, not closed) the Warden
    /// launches an attempt for: no accepted attempt (D68), or every
    /// accepted attempt finished `Interrupted` and fewer than
    /// [`MAX_INTERRUPTED`] of them (D88).  An attempt that is still open,
    /// or that ended otherwise (a result about the files), keeps the
    /// Candidate out.
    pub fn to_attempt<L: Layers>(
        &self,
        vessel: &Vessel<L>,
    ) -> Result<Vec<Candidate>, AttemptError> {
        self.to_attempt_in(&frames(vessel)?, false)
    }

    /// [`Attempts::to_attempt`] over a Vessel's local log read without
    /// opening it.  With `open_as_interrupted`, an attempt still open
    /// counts as interrupted: the open that settles it (D69) closes it so
    /// (the Warden's own start, D88).
    pub fn to_attempt_in(
        &self,
        frames: &[Frame],
        open_as_interrupted: bool,
    ) -> Result<Vec<Candidate>, AttemptError> {
        // Per Candidate: the interrupted attempts, or None once one is
        // open or ended otherwise.
        let mut tried: std::collections::BTreeMap<[u8; 32], Option<u32>> = Default::default();
        for st in started_in(frames) {
            if !self.accepted(LogicalKey::Attempt(st.attempt_id))? {
                continue;
            }
            let interrupted = match self
                .coord
                .query_logical(logical_id(&LogicalKey::AttemptFinished(st.attempt_id)))?
            {
                Some((_, Submitted::Contract(ContractRecord::VerificationFinished(f)))) => {
                    f.outcome == Outcome::Interrupted
                }
                None => open_as_interrupted,
                _ => false,
            };
            let e = tried.entry(*st.candidate_id.as_bytes()).or_insert(Some(0));
            *e = match (*e, interrupted) {
                (Some(n), true) => Some(n + 1),
                _ => None,
            };
        }
        let mut seen = BTreeSet::new();
        let mut out = Vec::new();
        for r in contracts(frames) {
            let ContractRecord::Candidate(c) = r else {
                continue;
            };
            if !seen.insert(*c.candidate_id.as_bytes()) {
                continue;
            }
            match tried.get(c.candidate_id.as_bytes()) {
                None => {}
                Some(Some(n)) if *n < MAX_INTERRUPTED => {}
                Some(_) => continue,
            }
            // The accepted one (a retry may have appended another copy).
            let Some((_, Submitted::Contract(ContractRecord::Candidate(acc)))) = self
                .coord
                .query_logical(logical_id(&LogicalKey::Candidate(c.candidate_id)))?
            else {
                continue;
            };
            if !self.accepted(LogicalKey::CandidateClose(c.candidate_id))? {
                out.push(*acc);
            }
        }
        Ok(out)
    }

    fn started<L: Layers>(
        &self,
        vessel: &Vessel<L>,
    ) -> Result<Vec<VerificationStarted>, AttemptError> {
        Ok(started_in(&frames(vessel)?))
    }

    fn accepted(&self, key: LogicalKey) -> Result<bool, AttemptError> {
        Ok(self.coord.query_logical(logical_id(&key))?.is_some())
    }

    /// Append `rec`, put it, stop at `before_accept` if asked, accept it.
    fn record<L: Layers, X: Sender>(
        &self,
        vessel: &mut Vessel<L>,
        packs: &Packs<SharedStore, X>,
        rec: ContractRecord,
        before_accept: &'static str,
    ) -> Result<(), AttemptError> {
        let sub = Submitted::Contract(rec.clone());
        if let Some((_, got)) = self.coord.query_logical(sub.logical_id())? {
            return if got.digest() == sub.digest() {
                Ok(())
            } else {
                Err(SubmitError::Inconsistent(
                    "another record holds the attempt's logical id".into(),
                )
                .into())
            };
        }
        vessel.append_contract(rec)?;
        let pack = submit::put(
            self.coord.as_ref(),
            self.warden,
            vessel.chronicle(),
            packs,
            &sub,
        )?;
        if (self.failpoint)(before_accept) {
            return Err(AttemptError::Failpoint(before_accept));
        }
        let mut attempt = *vessel.attempt_mut();
        let got = submit::accept(
            self.coord.as_ref(),
            self.warden,
            vessel.chronicle(),
            sub.clone(),
            pack,
            &mut attempt,
        );
        *vessel.attempt_mut() = attempt;
        let got = got?;
        if got.digest() != sub.digest() {
            return Err(SubmitError::Inconsistent(
                "another record holds the attempt's logical id".into(),
            )
            .into());
        }
        Ok(())
    }
}

fn frames<L: Layers>(vessel: &Vessel<L>) -> Result<Vec<Frame>, AttemptError> {
    Ok(vessel
        .chronicle()
        .frames()
        .map_err(|e| VesselError::Chronicle(ChronicleError::Segment(e)))?)
}

/// Every `VerificationStarted` in `frames`, once each.
fn started_in(frames: &[Frame]) -> Vec<VerificationStarted> {
    let mut seen = BTreeSet::new();
    contracts(frames)
        .filter_map(|r| match r {
            ContractRecord::VerificationStarted(st) if seen.insert(*st.attempt_id.as_bytes()) => {
                Some(st)
            }
            _ => None,
        })
        .collect()
}

fn contracts(frames: &[Frame]) -> impl Iterator<Item = ContractRecord> + '_ {
    frames
        .iter()
        .filter(|f| f.envelope.stream == Stream::Ctl)
        .filter_map(|f| match Payload::decode(&f.payload) {
            Ok(Payload::Contract(r)) => Some(*r),
            _ => None,
        })
}

/// The `/candidate` dataset of an attempt, `<root>/a-<attempt_id hex>`.
pub fn candidate_dataset(root: &Dataset, attempt: HashVal) -> Dataset {
    Dataset::new(&format!("{root}/a-{}", hex(attempt.as_bytes())))
        .expect("root is valid and the suffix is hex")
}

/// Destroy an attempt's `/candidate` dataset by guid, once its
/// `VerificationFinished` is accepted (D66): `true` if one was there.
pub fn destroy_candidate<P: Pool>(
    pool: &P,
    root: &Dataset,
    attempt: HashVal,
) -> Result<bool, String> {
    let ds = candidate_dataset(root, attempt);
    match pool.guid(&ds).map_err(|e| e.to_string())? {
        None => Ok(false),
        Some(g) => pool.destroy(&ds, g).map_err(|e| e.to_string()),
    }
}

/// One attempt's run on this node (D64–D67).
pub struct AttemptRun<'a, P: Pool, X: Sender> {
    /// The pool.
    pub pool: &'a P,
    /// The Template layers on this node (the verifier Template's root).
    pub layers: &'a TemplateLayers<P, X>,
    /// The store.
    pub store: &'a SharedStore,
    /// Key prefix in the store.
    pub prefix: &'a str,
    /// Parent of the `/candidate` datasets.
    pub root: &'a Dataset,
    /// Where bundles go and runc keeps its state (`<run_dir>`).
    pub run_dir: &'a Path,
    /// The node's verifier limits.
    pub limits: VerifierLimits,
    /// The walk's limits (the restore check).
    pub walk_limits: &'a Limits,
    /// `fs.reserved`.
    pub reserved: &'a [Reserved],
    /// `true` stops at that failpoint.
    pub failpoint: Failpoint,
}

/// A run stopped at a failpoint: no result, the attempt stays open.
#[derive(Debug)]
pub struct Stopped(pub &'static str);

impl<P: Pool, X: Sender> AttemptRun<'_, P, X> {
    /// Run `started` (an attempt of `candidate`): how it ended and its
    /// output.  `Err` only for a failpoint (the attempt stays open).
    pub fn run(
        &self,
        started: &VerificationStarted,
        candidate: &Candidate,
    ) -> Result<(Outcome, Vec<u8>), Stopped> {
        match self.prepare_and_run(started, candidate) {
            Ok(r) => r,
            Err(why) => Ok((Outcome::LaunchFailed, why.into_bytes())),
        }
    }

    fn prepare_and_run(
        &self,
        st: &VerificationStarted,
        candidate: &Candidate,
    ) -> Result<Result<(Outcome, Vec<u8>), Stopped>, String> {
        // The vconf (D64).
        let vconf = Vconf::parse(
            &self.object(ObjectKind::Vconf, st.requirement.vconf_key)?,
            &self.limits,
        )?;
        // The root: the verifier Template's layer here (D65).
        let layer = self
            .layers
            .ensure(st.requirement.template)
            .map_err(|e| format!("the verifier Template's layer: {e}"))?;
        let root_view = self
            .pool
            .seal_view(&layer.dataset, LAYER_LSN)
            .map_err(|e| format!("the verifier Template's layer: {e}"))?;
        for d in VERIFIER_DIRS {
            if !root_view.path().join(d).is_dir() {
                return Err(format!(
                    "the verifier Template has no /{d} to mount on (it needs /{})",
                    VERIFIER_DIRS.join(", /")
                ));
            }
        }
        // /candidate (D66).
        let base = self.layers.template_base;
        let ds = candidate_dataset(self.root, st.attempt_id);
        if let Some(g) = self.pool.guid(&ds).map_err(|e| e.to_string())? {
            self.pool.destroy(&ds, g).map_err(|e| e.to_string())?;
        }
        let info = self
            .pool
            .create(&ds)
            .map_err(|e| format!("making {ds}: {e}"))?;
        let mount = info
            .mountpoint
            .ok_or_else(|| format!("{ds} has no mountpoint"))?;
        let owner = Owner {
            uid_base: base,
            gid_base: base,
        };
        {
            let mut r = self.reader(ObjectKind::Artifact, st.artifact_key)?;
            artifact::restore(&mut r, &mount, owner, self.reserved, Some(st.artifact_key))
                .map_err(|e| format!("restoring the Candidate: {e}"))?;
        }
        own_top(&mount, base).map_err(|e| format!("owning {}: {e}", mount.display()))?;
        let map = Classmap::parse(&self.object(ObjectKind::Classmap, candidate.classmap_key)?)
            .map_err(|e| format!("the Candidate's classification map: {e}"))?;
        let want =
            Manifest::decode(&self.object(ObjectKind::Manifest, candidate.output_manifest_key)?)
                .map_err(|e| format!("the Candidate's output manifest: {e}"))?;
        let walked = classify::walk(&mount, &map, owner, self.walk_limits, self.reserved)
            .map_err(|e| format!("walking the restored Candidate: {e}"))?;
        if !same_entries(&walked, &want) {
            return Err("the restored Candidate does not walk to its output manifest".into());
        }
        self.pool
            .layers(&ds)
            .snapshot(CANDIDATE_LSN, st.artifact_key)
            .map_err(|e| format!("sealing {ds}: {e}"))?;
        let cand_view = self
            .pool
            .seal_view(&ds, CANDIDATE_LSN)
            .map_err(|e| format!("the sealed Candidate: {e}"))?;
        // The container (D65, D67).
        let id = format!("verify-{}", &hex(st.attempt_id.as_bytes())[..24]);
        let bundle = self.run_dir.join("verify").join(&id);
        let _ = std::fs::remove_dir_all(&bundle);
        write_verifier_bundle(
            &bundle,
            &VerifierSpec {
                id: id.clone(),
                rootfs: root_view.path().to_path_buf(),
                candidate: cand_view.path().to_path_buf(),
                uid_base: base,
                args: vconf.entry.clone(),
                env: vconf.env.clone(),
                memory_bytes: vconf.limits.memory_bytes,
                cpu_seconds: vconf.limits.cpu_seconds,
                pids: 256,
            },
        )
        .map_err(|e| format!("the verifier's bundle: {e:?}"))?;
        let runc_root = self.run_dir.join("runc");
        let runc = |args: &[&str]| {
            Command::new("runc")
                .arg("--root")
                .arg(&runc_root)
                .args(args)
                .output()
        };
        let _ = runc(&["delete", "--force", &id]);
        let mut cmd = Command::new("runc");
        cmd.arg("--root")
            .arg(&runc_root)
            .args(["run", "--bundle"])
            .arg(&bundle)
            .arg(&id);
        let kill = |_pid: u32| {
            let _ = runc(&["kill", &id, "KILL"]);
        };
        let wall = Duration::from_secs(vconf.limits.wall_seconds);
        let result = if (self.failpoint)("verify.mid_run") {
            // The Warden "dies" while the verifier runs: it is killed (as
            // the next start's sweep would) and no result is given.  No
            // terminal: a `runc run` that inherits one is stopped by job
            // control when it touches it, and its wait never returns
            // (taso-test, 2026-10-25).  The container is killed, then
            // `runc run` itself, so the wait returns even when the kill
            // found no container yet.
            let mut c = cmd;
            c.stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null());
            let child = c.spawn();
            std::thread::sleep(Duration::from_millis(500));
            kill(0);
            if let Ok(mut ch) = child {
                let _ = ch.kill();
                let _ = ch.wait();
            }
            let _ = runc(&["delete", "--force", &id]);
            return Ok(Err(Stopped("verify.mid_run")));
        } else {
            run_capped(&mut cmd, wall, vconf.limits.output_bound, &kill)
        };
        let _ = runc(&["delete", "--force", &id]);
        let _ = std::fs::remove_dir_all(&bundle);
        drop(cand_view);
        drop(root_view);
        match result {
            Ok((ended, out)) => Ok(Ok((outcome_of(ended), out))),
            Err(e) => Err(format!("running the verifier: {e}")),
        }
    }

    fn reader(&self, kind: ObjectKind, key: HashVal) -> Result<crate::ship::ByteStream, String> {
        let path = object_key_path(self.prefix, kind, key).expect("a content kind");
        self.store
            .get(&path)
            .map_err(|e| format!("{path}: {e}"))?
            .ok_or_else(|| format!("{path} is not in the store"))
    }

    fn object(&self, kind: ObjectKind, key: HashVal) -> Result<Vec<u8>, String> {
        let mut b = Vec::new();
        self.reader(kind, key)?
            .read_to_end(&mut b)
            .map_err(|e| format!("reading a {kind:?} object: {e}"))?;
        let got = taso_core::contract::object_key(kind, &b);
        if got != key {
            return Err(format!(
                "the {kind:?} object {key} does not have its key's bytes"
            ));
        }
        Ok(b)
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
