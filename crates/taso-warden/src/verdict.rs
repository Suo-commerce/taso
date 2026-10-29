//! Verdicts: a caller's decision on a Candidate, recorded and acted on
//! (P4 spec rev. 30 §5.1, §5.3 steps 1–4; D73, D75–D78, D86; files 8a, 15).
//!
//! [`Verdicts::handle`] runs §5.3's steps through the Vessel's own log:
//!
//! 1. **Receive**: a commit already accepted for the Candidate answers
//!    `Committed`; a retried request continues from what the log holds
//!    (its `Refused` again, or the steps after its `VerdictSubmitted`);
//!    otherwise the request's binding is checked and one of `Refused`
//!    (the permanent refusals, D75) or `VerdictSubmitted` is accepted.
//! 2. **Hold**: the Warden answers.  **Never**: the Warden closes the
//!    Candidate, or answers `Retry { Rule { OpenAttempt } }` while an
//!    attempt is open.
//! 3. **Pre-check** of a Sanction: what can still change, the Warden
//!    answers `Retry { Rule { rule } }` (D75, D86).  A Candidate closed
//!    since (by another verdict) is `Refused { Closed }`, final; a
//!    coordinator refusal at step 4 is `Retry { Rule { Conflict } }`, its
//!    reason logged (D78).
//! 4. **Commit**: `SanctionCommitted` with `template_id` (§9) and
//!    `parent_template` (D76).
//!
//! [`pending`] is what a caller is shown (D73).
//!
//! Normative reference: `Taso_spec_p4_contracts` rev. 30, BLAKE3
//! `b5f59255657885a8c056c1e758e76699f1a36485a2e2327ca21d47c6ead1ccd8`.

use std::collections::BTreeSet;
use std::fmt;
use std::sync::Arc;

use taso_core::contract::{
    logical_id, template_id, CandidateClosed, CloseKind, ContractRecord, Decision, LogicalKey,
    Peer, Refusal, Refused, SanctionCommitted, VerdictRequest, VerdictSubmitted,
    VerificationStarted,
};
use taso_core::coordlog::Submitted;
use taso_core::envelope::{HashVal, Stream};
use taso_core::model::WardenId;
use taso_core::record::{Origin, Payload};

pub use taso_core::decider::{PendingItem, RetryReason, VerdictAnswer};

use crate::attempt::Failpoint;
use crate::chronicle::{ChronicleError, Layers};
use crate::coordinator::{Coord, CoordError};
use crate::pack::Packs;
use crate::segment::Frame;
use crate::ship::{Sender, SharedStore};
use crate::submit::{self, SubmitError};
use crate::vessel::{Vessel, VesselError};

/// The two failpoints of a verdict (§10.2 row 8).
pub const FAILPOINTS: [&str; 2] = ["verdict.after_submitted", "verdict.in_check"];

/// Why a verdict could not be handled (nothing more than what the log
/// holds was recorded).
#[derive(Debug)]
pub enum VerdictError {
    /// The request's id is not its peer's (D72).
    BadRequestId,
    /// The Vessel failed.
    Vessel(VesselError),
    /// The coordinator failed.
    Coord(CoordError),
    /// Submitting failed.
    Submit(SubmitError),
    /// A deliberate stop at a named failpoint (tests).
    Failpoint(&'static str),
}

impl fmt::Display for VerdictError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadRequestId => f.write_str("the request_id is not this peer's request's"),
            Self::Vessel(e) => write!(f, "vessel: {e}"),
            Self::Coord(e) => write!(f, "coordinator: {e}"),
            Self::Submit(e) => write!(f, "submit: {e}"),
            Self::Failpoint(p) => write!(f, "stopped at failpoint {p}"),
        }
    }
}

impl std::error::Error for VerdictError {}

impl From<VesselError> for VerdictError {
    fn from(e: VesselError) -> Self {
        Self::Vessel(e)
    }
}
impl From<CoordError> for VerdictError {
    fn from(e: CoordError) -> Self {
        Self::Coord(e)
    }
}
impl From<SubmitError> for VerdictError {
    fn from(e: SubmitError) -> Self {
        Self::Submit(e)
    }
}

/// Verdicts through a Vessel's own log.
pub struct Verdicts {
    /// The coordinator.
    pub coord: Arc<dyn Coord>,
    /// This Warden.
    pub warden: WardenId,
    /// `true` stops at that failpoint.
    pub failpoint: Failpoint,
}

impl Verdicts {
    /// Handle `req` from `peer` for `vessel` (§5.3 steps 1–4).
    pub fn handle<L: Layers, X: Sender>(
        &self,
        vessel: &mut Vessel<L>,
        packs: &Packs<SharedStore, X>,
        req: &VerdictRequest,
        peer: Peer,
    ) -> Result<VerdictAnswer, VerdictError> {
        if !req.id_matches(peer) {
            return Err(VerdictError::BadRequestId);
        }
        let cid = req.candidate_id;
        // 1. Receive: a commit answers whatever the state.
        if let Some(ContractRecord::SanctionCommitted(s)) =
            self.accepted(LogicalKey::Sanction(cid))?
        {
            return Ok(VerdictAnswer::Committed {
                template_id: s.template_id,
            });
        }
        let verdict = logical_id(&LogicalKey::Verdict(req.request_id));
        match self.accepted_id(verdict)? {
            Some(ContractRecord::Refused(r)) => return Ok(VerdictAnswer::Refused(r.rule)),
            Some(ContractRecord::VerdictSubmitted(_)) => {}
            Some(other) => {
                return Err(SubmitError::Inconsistent(format!(
                    "the verdict's logical id holds {other:?}"
                ))
                .into())
            }
            None => {
                let rec = match self.binding(vessel, req)? {
                    Err(rule) => ContractRecord::Refused(Refused {
                        request_id: req.request_id,
                        candidate_id: cid,
                        peer,
                        rule,
                    }),
                    Ok(()) => ContractRecord::VerdictSubmitted(Box::new(VerdictSubmitted {
                        request: req.clone(),
                        peer,
                    })),
                };
                match self.record(vessel, packs, rec)? {
                    Recorded::Accepted(ContractRecord::Refused(r)) => {
                        return Ok(VerdictAnswer::Refused(r.rule))
                    }
                    Recorded::Accepted(_) => {}
                    Recorded::Unknown(why) => {
                        return Ok(VerdictAnswer::Retry(RetryReason::Pending(why)))
                    }
                }
                if (self.failpoint)("verdict.after_submitted") {
                    return Err(VerdictError::Failpoint("verdict.after_submitted"));
                }
            }
        }
        let cand = match self.accepted(LogicalKey::Candidate(cid))? {
            Some(ContractRecord::Candidate(c)) => *c,
            _ => return Ok(VerdictAnswer::Refused(Refusal::NoSuchCandidate)),
        };
        match &req.decision {
            // 2. Hold.
            Decision::Hold => Ok(VerdictAnswer::Held),
            // 2. Never.
            Decision::Never { reason } => {
                if let Some(ContractRecord::CandidateClosed(c)) =
                    self.accepted(LogicalKey::CandidateClose(cid))?
                {
                    return Ok(match c.how {
                        CloseKind::Never { verdict: v, .. } if v == verdict => {
                            VerdictAnswer::ClosedNever
                        }
                        _ => VerdictAnswer::Refused(Refusal::Closed),
                    });
                }
                if self.open_attempt(vessel, cid)? {
                    return Ok(VerdictAnswer::Retry(RetryReason::Rule(
                        Refusal::OpenAttempt,
                    )));
                }
                let rec = ContractRecord::CandidateClosed(CandidateClosed {
                    candidate_id: cid,
                    how: CloseKind::Never {
                        verdict,
                        reason: reason.clone(),
                    },
                });
                Ok(match self.record(vessel, packs, rec)? {
                    Recorded::Accepted(ContractRecord::CandidateClosed(CandidateClosed {
                        how: CloseKind::Never { verdict: v, .. },
                        ..
                    })) if v == verdict => VerdictAnswer::ClosedNever,
                    Recorded::Accepted(_) => VerdictAnswer::Refused(Refusal::Closed),
                    Recorded::Unknown(why) => VerdictAnswer::Retry(RetryReason::Pending(why)),
                })
            }
            Decision::Sanction => {
                // 3. Pre-check what can still change.
                if (self.failpoint)("verdict.in_check") {
                    return Err(VerdictError::Failpoint("verdict.in_check"));
                }
                if let Some((rule, why)) = self.pre_check(vessel, req)? {
                    eprintln!(
                        "taso-warden: verdict {}: not committed: {why}",
                        req.request_id
                    );
                    // Closed since: final; anything else can still change.
                    return Ok(match rule {
                        Refusal::Closed => VerdictAnswer::Refused(Refusal::Closed),
                        rule => VerdictAnswer::Retry(RetryReason::Rule(rule)),
                    });
                }
                // 4. Commit.
                let parent_template = match vessel.lineage().origin {
                    Origin::Template { template_id, .. } => Some(template_id),
                    _ => None,
                };
                let commit = SanctionCommitted {
                    candidate_id: cid,
                    template_id: template_id(cid, verdict),
                    parent_template,
                    artifact_key: cand.artifact_key,
                    output_manifest_key: cand.output_manifest_key,
                    classmap_key: cand.classmap_key,
                    vconf_key: cand.requirement.vconf_key,
                    attempt_id: req.attempt_id,
                    result_digest: req.result_digest,
                    verdict,
                };
                debug_assert!(commit.is_consistent());
                match self.record(vessel, packs, ContractRecord::SanctionCommitted(commit)) {
                    Ok(Recorded::Accepted(ContractRecord::SanctionCommitted(s))) => {
                        Ok(VerdictAnswer::Committed {
                            template_id: s.template_id,
                        })
                    }
                    Ok(Recorded::Accepted(other)) => Err(SubmitError::Inconsistent(format!(
                        "the sanction's logical id holds {other:?}"
                    ))
                    .into()),
                    Ok(Recorded::Unknown(why)) => {
                        Ok(VerdictAnswer::Retry(RetryReason::Pending(why)))
                    }
                    // The coordinator is authoritative: final for this
                    // submission only (§5.3 step 4).
                    Err(VerdictError::Submit(SubmitError::Refused(f))) => {
                        eprintln!(
                            "taso-warden: verdict {}: the coordinator refused the commit: {f:?}",
                            req.request_id
                        );
                        Ok(VerdictAnswer::Retry(RetryReason::Rule(Refusal::Conflict)))
                    }
                    Err(e) => Err(e),
                }
            }
        }
    }

    /// Step 1's binding (D75): the permanent refusals, or `Ok`.
    fn binding<L: Layers>(
        &self,
        vessel: &Vessel<L>,
        req: &VerdictRequest,
    ) -> Result<Result<(), Refusal>, VerdictError> {
        let cid = req.candidate_id;
        let cand = match self.accepted(LogicalKey::Candidate(cid))? {
            Some(ContractRecord::Candidate(c)) if c.chronicle == vessel.id() => *c,
            _ => return Ok(Err(Refusal::NoSuchCandidate)),
        };
        if self.accepted(LogicalKey::CandidateClose(cid))?.is_some() {
            return Ok(Err(Refusal::Closed));
        }
        if req.facts_hash != cand.facts_hash
            || req.artifact_key != cand.artifact_key
            || req.requirement != cand.requirement
            || req.exclude != cand.exclude
        {
            return Ok(Err(Refusal::StaleFacts));
        }
        let started = match self.accepted(LogicalKey::Attempt(req.attempt_id))? {
            Some(ContractRecord::VerificationStarted(st))
                if st.candidate_id == cid
                    && st.artifact_key == cand.artifact_key
                    && st.requirement == cand.requirement =>
            {
                st
            }
            _ => return Ok(Err(Refusal::WrongAttempt)),
        };
        let finished = match self.accepted(LogicalKey::AttemptFinished(started.attempt_id))? {
            Some(ContractRecord::VerificationFinished(f))
                if f.result_digest == req.result_digest =>
            {
                f
            }
            _ => return Ok(Err(Refusal::WrongAttempt)),
        };
        if req.decision == Decision::Sanction {
            if !finished.outcome.passed() {
                return Ok(Err(Refusal::AttemptNotPassed));
            }
            if !cand.facts.input.passes_hard_rules() {
                return Ok(Err(Refusal::HardRules));
            }
            if self
                .coord
                .query_chronicle(vessel.id())?
                .is_some_and(|v| v.retired)
            {
                return Ok(Err(Refusal::Retired));
            }
        }
        Ok(Ok(()))
    }

    /// Step 3 (D75): what can still change, answered.
    fn pre_check<L: Layers>(
        &self,
        vessel: &Vessel<L>,
        req: &VerdictRequest,
    ) -> Result<Option<(Refusal, String)>, VerdictError> {
        let id = vessel.id();
        // Closed by another verdict since this one was recorded.
        if self
            .accepted(LogicalKey::CandidateClose(req.candidate_id))?
            .is_some()
        {
            return Ok(Some((Refusal::Closed, "the Candidate is closed".into())));
        }
        let ob = self.coord.obligations(id)?;
        if !ob.is_empty() {
            return Ok(Some((
                Refusal::OpenObligation,
                format!("{} effect obligation(s) are open", ob.len()),
            )));
        }
        if self.open_attempt(vessel, req.candidate_id)? {
            return Ok(Some((Refusal::OpenAttempt, "an attempt is open".into())));
        }
        let named = match self.accepted(LogicalKey::Attempt(req.attempt_id))? {
            Some(ContractRecord::VerificationStarted(st)) => st,
            _ => return Ok(Some((Refusal::WrongAttempt, "no such attempt".into()))),
        };
        for st in started_in(&frames(vessel)?) {
            if st.candidate_id != req.candidate_id || st.started_at <= named.started_at {
                continue;
            }
            if let Some(ContractRecord::VerificationFinished(f)) =
                self.accepted(LogicalKey::AttemptFinished(st.attempt_id))?
            {
                if !f.outcome.passed() {
                    return Ok(Some((
                        Refusal::LaterAttemptFailed,
                        format!(
                            "attempt {} started later and ended {:?}",
                            st.attempt_id, f.outcome
                        ),
                    )));
                }
            }
        }
        if let Some(p) = self.coord.query_chronicle(id)?.and_then(|v| v.pending) {
            return Ok(Some((
                Refusal::Pending,
                format!("submission {p} is pending on the Vessel"),
            )));
        }
        Ok(None)
    }

    /// Whether an attempt of `cid` is open (its start accepted, its finish
    /// not).
    fn open_attempt<L: Layers>(
        &self,
        vessel: &Vessel<L>,
        cid: HashVal,
    ) -> Result<bool, VerdictError> {
        for st in started_in(&frames(vessel)?) {
            if st.candidate_id == cid
                && self.accepted(LogicalKey::Attempt(st.attempt_id))?.is_some()
                && self
                    .accepted(LogicalKey::AttemptFinished(st.attempt_id))?
                    .is_none()
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn accepted(&self, key: LogicalKey) -> Result<Option<ContractRecord>, VerdictError> {
        self.accepted_id(logical_id(&key))
    }

    fn accepted_id(&self, logical: HashVal) -> Result<Option<ContractRecord>, VerdictError> {
        Ok(match self.coord.query_logical(logical)? {
            Some((_, Submitted::Contract(r))) => Some(r),
            _ => None,
        })
    }

    /// Append `rec` to the Vessel's log and have it accepted: the record
    /// accepted for its logical id (this one or another's).
    pub(crate) fn record<L: Layers, X: Sender>(
        &self,
        vessel: &mut Vessel<L>,
        packs: &Packs<SharedStore, X>,
        rec: ContractRecord,
    ) -> Result<Recorded, VerdictError> {
        let sub = Submitted::Contract(rec.clone());
        if let Some(r) = self.accepted_id(sub.logical_id())? {
            return Ok(Recorded::Accepted(r));
        }
        if let Some(last) = vessel.last_seal() {
            if self.coord.shipped(vessel.id())?.lsn < last.lsn {
                return Ok(Recorded::Unknown(format!(
                    "the Vessel's newest Seal (lsn {}) is not shipped yet: nothing can be recorded after it",
                    last.lsn.get()
                )));
            }
        }
        vessel.append_contract(rec)?;
        let mut attempt = *vessel.attempt_mut();
        let got = submit::submit(
            self.coord.as_ref(),
            self.warden,
            vessel.chronicle(),
            packs,
            sub,
            &mut attempt,
        );
        *vessel.attempt_mut() = attempt;
        match got {
            Ok(Submitted::Contract(r)) => Ok(Recorded::Accepted(r)),
            Ok(other) => Err(SubmitError::Inconsistent(format!(
                "a contract logical id holds {other:?}"
            ))
            .into()),
            Err(SubmitError::Coord(e)) => Ok(Recorded::Unknown(format!("coordinator: {e}"))),
            Err(e) => Err(e.into()),
        }
    }
}

/// What [`Verdicts::record`] learnt (short-lived, matched at once).
#[allow(clippy::large_enum_variant)]
pub(crate) enum Recorded {
    Accepted(ContractRecord),
    Unknown(String),
}

fn frames<L: Layers>(vessel: &Vessel<L>) -> Result<Vec<Frame>, VerdictError> {
    Ok(vessel
        .chronicle()
        .frames()
        .map_err(|e| VesselError::Chronicle(ChronicleError::Segment(e)))?)
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

/// The pending Candidates in a Vessel's local log (D73): open (accepted,
/// not closed), not committed, with at least one finished attempt.
pub fn pending(coord: &dyn Coord, frames: &[Frame]) -> Result<Vec<PendingItem>, CoordError> {
    let q = |key: LogicalKey| -> Result<Option<ContractRecord>, CoordError> {
        Ok(match coord.query_logical(logical_id(&key))? {
            Some((_, Submitted::Contract(r))) => Some(r),
            _ => None,
        })
    };
    let started = started_in(frames);
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for r in contracts(frames) {
        let ContractRecord::Candidate(c) = r else {
            continue;
        };
        if !seen.insert(*c.candidate_id.as_bytes()) {
            continue;
        }
        let Some(ContractRecord::Candidate(cand)) = q(LogicalKey::Candidate(c.candidate_id))?
        else {
            continue;
        };
        if q(LogicalKey::CandidateClose(c.candidate_id))?.is_some()
            || q(LogicalKey::Sanction(c.candidate_id))?.is_some()
        {
            continue;
        }
        let mut attempts = Vec::new();
        for st in started.iter().filter(|s| s.candidate_id == c.candidate_id) {
            if q(LogicalKey::Attempt(st.attempt_id))?.is_none() {
                continue;
            }
            if let Some(ContractRecord::VerificationFinished(f)) =
                q(LogicalKey::AttemptFinished(st.attempt_id))?
            {
                attempts.push((*st, f));
            }
        }
        if !attempts.is_empty() {
            out.push(PendingItem {
                candidate: *cand,
                attempts,
            });
        }
    }
    Ok(out)
}
