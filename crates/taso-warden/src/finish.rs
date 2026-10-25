//! Finishing a sanction: the Template born from an accepted
//! `SanctionCommitted` (P4 spec rev. 30 §5.3 steps 5–6, D21, D79, D87, D90;
//! files 9a, 15).
//!
//! [`Finisher::finish`], from the accepted commit, in order:
//!
//! 1. A `TemplateReady` accepted for `template_id` → step 4.
//! 2. **Claim** the target Chronicle `template_id` with the commit as its
//!    authority (`ClaimAuthority::Sanction`).  Claimed by this Warden
//!    already (an earlier run): continue.  Claimed by another: wait
//!    `claim_wait` (politeness only), then `takeover_target` with the same
//!    authority, which fences that owner.
//! 3. **Put, then accept** the target's one `TemplateReady`: the commit's
//!    definition, `born_from: Sanction { source, candidate_id, verdict }`,
//!    the verdict's authority (D79).  A `Conflict` (another run's record)
//!    is compared, never assumed: the same `born_from` and `layer`
//!    continue; anything else is [`FinishError::Inconsistent`], the
//!    operator's `SanctionInconsistent`, and the source stays committed.
//!    This is a check against a defect, not a state (D87): `template_id`
//!    is derived from the commit, so a correct Warden never finds the two
//!    different.
//! 4. **`SanctionCompleted { template_id }`** in the source, through the
//!    Vessel's own log.
//!
//! **A fenced finisher** (D87): when the coordinator refuses one of the
//! finish's submissions `StaleEpoch` (another Warden took over the target
//! or the source), the Warden asks for the Template's `TemplateReady`.
//! Accepted: another Warden finished the sanction, and [`Finished`] says
//! so (`elsewhere`), with no error.  Not accepted: the refusal is the
//! error, and the next holder's open finishes it.
//!
//! [`Finisher::unfinished`] is the restart rule (step 6): every accepted
//! commit in a Vessel's local log without an accepted `SanctionCompleted`.
//!
//! The target's local log lives in `<state_dir>/template/<template_id
//! hex>` (D79); a node without it rebuilds it from the shipped packs.
//!
//! Normative reference: `Taso_spec_p4_contracts` rev. 30, BLAKE3
//! `b5f59255657885a8c056c1e758e76699f1a36485a2e2327ca21d47c6ead1ccd8`.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use taso_core::contract::{
    logical_id, BornFrom, ContractRecord, LogicalKey, SanctionCommitted, TemplateReady,
};
use taso_core::coordlog::{ClaimAuthority, ClaimError, Final, Submitted};
use taso_core::envelope::{ChronicleId, HashVal, Lsn, Stream};
use taso_core::model::WardenId;
use taso_core::record::Payload;

use crate::attempt::Failpoint;
use crate::chronicle::{restore_log, Chronicle, ChronicleError, LayerError, Layers};
use crate::coordinator::{Coord, CoordError};
use crate::pack::{PackError, Packs};
use crate::segment::Position;
use crate::ship::{ByteStream, Sender, SharedStore};
use crate::submit::{self, SubmitError};
use crate::vessel::{Vessel, VesselError};
use crate::zfs::Dataset;

/// The failpoints of a sanction's finish (§10.2 row 9), in order.
pub const FAILPOINTS: [&str; 6] = [
    "sanction.after_commit_accept",
    "sanction.after_claim_chronicle",
    "sanction.after_target_put",
    "sanction.before_ready_accept",
    "sanction.after_ready_accept",
    "sanction.before_completed_accept",
];

/// `finish.claim_wait` (§11.1).
pub const CLAIM_WAIT: Duration = Duration::from_secs(30);

/// Why a finish stopped.  Nothing it did is undone; running it again
/// continues (step 6).
#[derive(Debug)]
pub enum FinishError {
    /// The coordinator failed.
    Coord(CoordError),
    /// The target's local log failed.
    Chronicle(ChronicleError),
    /// Its packs failed.
    Pack(PackError),
    /// A submission failed.
    Submit(SubmitError),
    /// The source Vessel failed.
    Vessel(VesselError),
    /// `SanctionInconsistent` (§5.3 step 5.3), or a log that does not
    /// agree with itself: for the operator.
    Inconsistent(String),
    /// Not finished yet, nothing wrong (the source's newest Seal is not
    /// shipped, an accept's outcome is unknown): run it again.
    NotYet(String),
    /// A deliberate stop at a named failpoint (tests).
    Failpoint(&'static str),
}

impl fmt::Display for FinishError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Coord(e) => write!(f, "coordinator: {e}"),
            Self::Chronicle(e) => write!(f, "the Template's log: {e}"),
            Self::Pack(e) => write!(f, "the Template's packs: {e}"),
            Self::Submit(e) => write!(f, "submit: {e}"),
            Self::Vessel(e) => write!(f, "the source: {e}"),
            Self::Inconsistent(why) => write!(f, "SanctionInconsistent: {why}"),
            Self::NotYet(why) => write!(f, "not yet: {why}"),
            Self::Failpoint(p) => write!(f, "stopped at failpoint {p}"),
        }
    }
}

impl std::error::Error for FinishError {}

impl FinishError {
    /// The coordinator refused this Warden's epoch: another Warden holds
    /// the target or the source now (D87).  The fence reaches a finish as
    /// `StaleEpoch` at accept, as `NotHolder` or `EpochMismatch` when the
    /// shipped anchor is advanced before the announce, or when the
    /// Vessel's own log refuses the append (the Warden's epoch check).
    pub fn is_stale_epoch(&self) -> bool {
        let fenced = |e: &CoordError| {
            matches!(
                e,
                CoordError::NotHolder { .. } | CoordError::EpochMismatch { .. }
            )
        };
        match self {
            Self::Submit(SubmitError::Refused(Final::StaleEpoch)) => true,
            Self::Submit(SubmitError::Coord(e))
            | Self::Coord(e)
            | Self::Chronicle(ChronicleError::Refused(e))
            | Self::Submit(SubmitError::Chronicle(ChronicleError::Refused(e)))
            | Self::Vessel(VesselError::Coord(e))
            | Self::Vessel(VesselError::Chronicle(ChronicleError::Refused(e))) => fenced(e),
            _ => false,
        }
    }
}

impl From<CoordError> for FinishError {
    fn from(e: CoordError) -> Self {
        Self::Coord(e)
    }
}
impl From<ChronicleError> for FinishError {
    fn from(e: ChronicleError) -> Self {
        Self::Chronicle(e)
    }
}
impl From<PackError> for FinishError {
    fn from(e: PackError) -> Self {
        Self::Pack(e)
    }
}
impl From<VesselError> for FinishError {
    fn from(e: VesselError) -> Self {
        Self::Vessel(e)
    }
}
impl From<SubmitError> for FinishError {
    fn from(e: SubmitError) -> Self {
        match e {
            SubmitError::Stopped(p) => Self::Failpoint(p),
            e => Self::Submit(e),
        }
    }
}

/// What a finish did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finished {
    /// The Template.
    pub template_id: ChronicleId,
    /// What a reader of the log should know (a takeover, an earlier
    /// run's record).
    pub notes: Vec<String>,
    /// Another Warden finished it; this one was fenced (D87).
    pub elsewhere: bool,
}

/// Finishes sanctions on this Warden.
pub struct Finisher {
    /// The coordinator.
    pub coord: Arc<dyn Coord>,
    /// The store.
    pub store: SharedStore,
    /// Its key prefix.
    pub prefix: String,
    /// This Warden.
    pub warden: WardenId,
    /// The Warden's state directory (targets in `template/`).
    pub state_dir: PathBuf,
    /// `finish.claim_wait`.
    pub claim_wait: Duration,
    /// `true` stops at that failpoint.
    pub failpoint: Failpoint,
}

impl Finisher {
    /// The target's local log directory (D79).
    pub fn log_dir(&self, template_id: ChronicleId) -> PathBuf {
        self.state_dir
            .join("template")
            .join(hex(template_id.as_bytes()))
    }

    fn stop(&self, p: &'static str) -> Result<(), FinishError> {
        if (self.failpoint)(p) {
            Err(FinishError::Failpoint(p))
        } else {
            Ok(())
        }
    }

    fn accepted(&self, key: LogicalKey) -> Result<Option<ContractRecord>, FinishError> {
        Ok(match self.coord.query_logical(logical_id(&key))? {
            Some((_, Submitted::Contract(r))) => Some(r),
            Some((_, other)) => {
                return Err(FinishError::Inconsistent(format!(
                    "a contract logical id holds {other:?}"
                )))
            }
            None => None,
        })
    }

    /// The accepted commits in `vessel`'s local log whose sanction is not
    /// completed (step 6).
    pub fn unfinished<L: Layers>(
        &self,
        vessel: &Vessel<L>,
    ) -> Result<Vec<SanctionCommitted>, FinishError> {
        let frames = vessel
            .chronicle()
            .frames()
            .map_err(|e| FinishError::Chronicle(ChronicleError::Segment(e)))?;
        let mut out: Vec<SanctionCommitted> = Vec::new();
        for f in frames.iter().filter(|f| f.envelope.stream == Stream::Ctl) {
            let Ok(Payload::Contract(r)) = Payload::decode(&f.payload) else {
                continue;
            };
            let ContractRecord::SanctionCommitted(s) = *r else {
                continue;
            };
            if out.iter().any(|o| o.candidate_id == s.candidate_id) {
                continue;
            }
            match self.accepted(LogicalKey::Sanction(s.candidate_id))? {
                Some(ContractRecord::SanctionCommitted(a)) if a == s => {}
                _ => continue,
            }
            if self
                .accepted(LogicalKey::SanctionCompleted(s.template_id))?
                .is_none()
            {
                out.push(s);
            }
        }
        Ok(out)
    }

    /// Finish `commit`, an accepted commit of `vessel` (§5.3 step 5).  A
    /// finish fenced by another Warden that has published the Template
    /// answers `Finished { elsewhere: true }` (D87).
    pub fn finish<L: Layers, X: Sender>(
        &self,
        vessel: &mut Vessel<L>,
        packs: &Packs<SharedStore, X>,
        commit: &SanctionCommitted,
    ) -> Result<Finished, FinishError> {
        match self.finish_here(vessel, packs, commit) {
            Err(e) if e.is_stale_epoch() => {
                match self.accepted(LogicalKey::Template(commit.template_id))? {
                    Some(ContractRecord::TemplateReady(_)) => Ok(Finished {
                        template_id: commit.template_id,
                        notes: vec![format!(
                            "this Warden was fenced ({e}); another Warden finished the sanction"
                        )],
                        elsewhere: true,
                    }),
                    _ => Err(e),
                }
            }
            r => r,
        }
    }

    fn finish_here<L: Layers, X: Sender>(
        &self,
        vessel: &mut Vessel<L>,
        packs: &Packs<SharedStore, X>,
        commit: &SanctionCommitted,
    ) -> Result<Finished, FinishError> {
        let tid = commit.template_id;
        let cid = commit.candidate_id;
        match self.accepted(LogicalKey::Sanction(cid))? {
            Some(ContractRecord::SanctionCommitted(a)) if a == *commit => {}
            other => {
                return Err(FinishError::Inconsistent(format!(
                    "the commit to finish is not the accepted one ({other:?})"
                )))
            }
        }
        let mut notes = Vec::new();
        let want = self.definition(vessel.id(), commit)?;
        // 5.1
        let ready = match self.accepted(LogicalKey::Template(tid))? {
            Some(ContractRecord::TemplateReady(t)) => *t,
            Some(other) => {
                return Err(FinishError::Inconsistent(format!(
                    "the Template's logical id holds {other:?}"
                )))
            }
            None => self.publish(commit, &want, &mut notes)?,
        };
        // 5.3's comparison, for a record found as for one just accepted.
        if ready.born_from != want.born_from || ready.layer != want.layer {
            return Err(FinishError::Inconsistent(format!(
                "Template {} is accepted with born_from {:?} and layer {}, the commit names {:?} and {}",
                hex(tid.as_bytes()),
                ready.born_from,
                ready.layer,
                want.born_from,
                want.layer
            )));
        }
        if ready != want {
            notes.push(
                "an earlier run's TemplateReady stands (the same born_from and layer)".into(),
            );
        }
        // 5.4
        self.stop("sanction.before_completed_accept")?;
        let v = crate::verdict::Verdicts {
            coord: self.coord.clone(),
            warden: self.warden,
            failpoint: crate::attempt::no_failpoints(),
        };
        let done = ContractRecord::SanctionCompleted { template_id: tid };
        match v.record(vessel, packs, done.clone()).map_err(|e| match e {
            crate::verdict::VerdictError::Vessel(e) => FinishError::Vessel(e),
            crate::verdict::VerdictError::Coord(e) => FinishError::Coord(e),
            crate::verdict::VerdictError::Submit(e) => FinishError::from(e),
            e => FinishError::Inconsistent(e.to_string()),
        })? {
            crate::verdict::Recorded::Accepted(r) if r == done => {}
            crate::verdict::Recorded::Accepted(r) => {
                return Err(FinishError::Inconsistent(format!(
                    "SanctionCompleted's logical id holds {r:?}"
                )))
            }
            crate::verdict::Recorded::Unknown(why) => return Err(FinishError::NotYet(why)),
        }
        Ok(Finished {
            template_id: tid,
            notes,
            elsewhere: false,
        })
    }

    /// The `TemplateReady` the commit defines (D79: the verdict's
    /// authority).
    fn definition(
        &self,
        source: ChronicleId,
        commit: &SanctionCommitted,
    ) -> Result<TemplateReady, FinishError> {
        let authority = match self.coord.query_logical(commit.verdict)? {
            Some((_, Submitted::Contract(ContractRecord::VerdictSubmitted(v)))) => {
                v.request.authority.clone()
            }
            other => {
                return Err(FinishError::Inconsistent(format!(
                    "the commit's verdict is not an accepted VerdictSubmitted ({other:?})"
                )))
            }
        };
        let t = TemplateReady {
            template_id: commit.template_id,
            parent_template: commit.parent_template,
            born_from: BornFrom::Sanction {
                source,
                candidate_id: commit.candidate_id,
                verdict: commit.verdict,
            },
            layer: commit.artifact_key,
            output_manifest_key: commit.output_manifest_key,
            classmap_key: commit.classmap_key,
            vconf_key: Some(commit.vconf_key),
            authority,
        };
        if !t.is_consistent() {
            return Err(FinishError::Inconsistent(
                "the commit defines an inconsistent TemplateReady".into(),
            ));
        }
        Ok(t)
    }

    /// Steps 5.2–5.3: the accepted `TemplateReady` (this one or another
    /// run's).
    fn publish(
        &self,
        commit: &SanctionCommitted,
        want: &TemplateReady,
        notes: &mut Vec<String>,
    ) -> Result<TemplateReady, FinishError> {
        let tid = commit.template_id;
        let authority = ClaimAuthority::Sanction {
            commit: logical_id(&LogicalKey::Sanction(commit.candidate_id)),
        };
        // 5.2
        let mut took_over = false;
        match self.coord.claim_chronicle(tid, self.warden, authority) {
            Ok(_) => {}
            Err(CoordError::AlreadyRegistered(_))
            | Err(CoordError::Claim(ClaimError::AlreadyClaimed { .. })) => {
                let own = self.coord.ownership(tid)?;
                if own.holder != self.warden {
                    // Politeness only: a live owner may finish meanwhile.
                    std::thread::sleep(self.claim_wait);
                    if let Some(ContractRecord::TemplateReady(t)) =
                        self.accepted(LogicalKey::Template(tid))?
                    {
                        return Ok(*t);
                    }
                    let (epoch, _) =
                        self.coord
                            .takeover_target(tid, self.warden, authority, own.epoch)?;
                    notes.push(format!(
                        "took Template {} over from Warden {} (epoch {} → {})",
                        hex(tid.as_bytes()),
                        own.holder.get(),
                        own.epoch.get(),
                        epoch.get()
                    ));
                    took_over = true;
                }
            }
            Err(e) => return Err(e.into()),
        }
        self.stop("sanction.after_claim_chronicle")?;
        // 5.3
        let (mut target, packs) = self.open_target(tid, took_over, notes)?;
        let rec = ContractRecord::TemplateReady(Box::new(want.clone()));
        let rec = prepare(&mut target, rec)?;
        let sub = Submitted::Contract(rec);
        let got = match submit::accepted(self.coord.as_ref(), sub.logical_id())? {
            Some(r) => r,
            None => {
                let pack = submit::put(self.coord.as_ref(), self.warden, &target, &packs, &sub)?;
                self.stop("sanction.after_target_put")?;
                let mut attempt = 0;
                let before = || {
                    if (self.failpoint)("sanction.before_ready_accept") {
                        Err(SubmitError::Stopped("sanction.before_ready_accept"))
                    } else {
                        Ok(())
                    }
                };
                submit::accept_with(
                    self.coord.as_ref(),
                    self.warden,
                    &target,
                    sub,
                    pack,
                    &mut attempt,
                    &before,
                )?
            }
        };
        let Submitted::Contract(ContractRecord::TemplateReady(t)) = got else {
            return Err(FinishError::Inconsistent(format!(
                "the Template's logical id holds {got:?}"
            )));
        };
        self.stop("sanction.after_ready_accept")?;
        Ok(*t)
    }

    /// The target's local log, opened under this Warden's claim; rebuilt
    /// from the shipped packs when this node does not have it (or has an
    /// older owner's, after a takeover).
    fn open_target(
        &self,
        tid: ChronicleId,
        took_over: bool,
        notes: &mut Vec<String>,
    ) -> Result<(Chronicle<NoLayers>, Packs<SharedStore, NoSend>), FinishError> {
        let dir = self.log_dir(tid);
        let packs = Packs::new(self.store.clone(), NoSend, &self.prefix, tid)
            .map_err(|e| FinishError::Pack(PackError::Io(e)))?;
        let anchor = self.coord.shipped(tid)?;
        if took_over && dir.exists() && !has_position(&dir, anchor)? {
            let aside = dir.with_extension(format!("superseded-{}", std::process::id()));
            std::fs::rename(&dir, &aside)
                .map_err(|e| FinishError::Chronicle(ChronicleError::Segment(e.into())))?;
            notes.push(format!(
                "this node's log of the Template was behind the shipped anchor; kept at {}",
                aside.display()
            ));
        }
        if !dir.exists() {
            let frames = if anchor.lsn > Lsn::new(0) {
                packs.chain(Some(anchor))?.frames
            } else {
                Vec::new()
            };
            if let Some(parent) = dir.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| FinishError::Chronicle(ChronicleError::Segment(e.into())))?;
            }
            restore_log(&dir, tid, &frames)?;
        }
        let (chronicle, recovery) =
            Chronicle::open_after_gap(&dir, self.coord.clone(), tid, self.warden, NoLayers)?;
        if let Some((kept, resumes)) = recovery.gap {
            notes.push(format!(
                "records {}..{} of the Template's log were lost with an earlier holder (Gap)",
                kept.lsn.get() + 1,
                resumes.lsn.get()
            ));
        }
        Ok((chronicle, packs))
    }
}

/// Append `rec` unless a frame with its logical id is in the log (an
/// earlier run's); the record the log holds.
fn prepare(
    chronicle: &mut Chronicle<NoLayers>,
    rec: ContractRecord,
) -> Result<ContractRecord, FinishError> {
    let logical = rec.logical_id();
    for f in chronicle.frames().map_err(ChronicleError::from)? {
        if f.envelope.stream != Stream::Ctl {
            continue;
        }
        if let Ok(Payload::Contract(r)) = Payload::decode(&f.payload) {
            if r.logical_id() == logical {
                return Ok(*r);
            }
        }
    }
    chronicle.append(Stream::Ctl, Payload::Contract(Box::new(rec.clone())))?;
    Ok(rec)
}

fn has_position(dir: &Path, pos: Position) -> Result<bool, FinishError> {
    if pos.lsn == Lsn::new(0) {
        return Ok(true);
    }
    Ok(crate::chronicle::read_log(dir)?
        .iter()
        .any(|f| f.envelope.lsn == pos.lsn && f.envelope.hash == pos.hash))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// A Template's Chronicle has records only: no layers.
pub(crate) struct NoLayers;

impl Layers for NoLayers {
    fn snapshot(&mut self, lsn: Lsn, _: HashVal) -> Result<(), LayerError> {
        Err(format!("a Template's log has no layers (lsn {})", lsn.get()).into())
    }
    fn list(&self) -> Result<Vec<(Lsn, HashVal)>, LayerError> {
        Ok(Vec::new())
    }
    fn destroy(&mut self, _: Lsn) -> Result<(), LayerError> {
        Ok(())
    }
}

/// … and no `fs` sections.
pub(crate) struct NoSend;

impl Sender for NoSend {
    fn send(&self, _: &Dataset, _: Option<&str>, _: Lsn) -> std::io::Result<ByteStream> {
        Err(std::io::Error::other("a Template's log has no fs sections"))
    }
}
