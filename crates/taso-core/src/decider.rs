//! The decider socket's messages (P4 spec rev. 22 §5.1, D72, D73, D77, D78).
//!
//! Framed as the Field's (`crate::frame`). A body is a tag and its fields
//! in the canonical encoding (§9); decoding is strict: unknown tags,
//! truncation and trailing bytes are refused, so every accepted body
//! re-encodes to itself.
//!
//! | Request | tag | Reply | tag |
//! | --- | --- | --- | --- |
//! | `Hello { version }` | 0 | `Hello { version }` | 0 |
//! | `Pending` | 1 | `Pending { items }` | 1 |
//! | `Verdict { request }` | 2 | `Verdict { answer }` | 2 |
//! | | | `Error { message }` | 3 |
//!
//! Answers (D77): `Committed { template_id }` 0, `Held` 1, `ClosedNever`
//! 2, `Refused { rule }` 3, `NotCommitted { rule }` 4, `NotClosed { rule }`
//! 5, `Pending { why }` 6, `NotHere { why }` 7. A rule is the `Refusal`
//! tag of §5.1.

use crate::canon::{Canon, Canonical};
use crate::contract::{
    Candidate, Reader, Refusal, VerdictRequest, VerificationFinished, VerificationStarted,
};
use crate::decode::DecodeError;
use crate::envelope::ChronicleId;

/// The protocol version.
pub const VERSION: u32 = 1;

/// One pending Candidate (D73): the accepted record and its finished
/// attempts, in the order they started.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingItem {
    /// The accepted Candidate.
    pub candidate: Candidate,
    /// Its finished attempts.
    pub attempts: Vec<(VerificationStarted, VerificationFinished)>,
}

/// The answer to a verdict (D77).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerdictAnswer {
    /// A `SanctionCommitted` is accepted for the Candidate.
    Committed {
        /// The Template it commits to.
        template_id: ChronicleId,
    },
    /// Recorded; a human decides later.
    Held,
    /// The Candidate is closed by this `Never`.
    ClosedNever,
    /// An accepted `Refused`, for good.
    Refused(Refusal),
    /// Recorded, not committed: something that can still change (step 3),
    /// or the coordinator refused this commit (step 4).
    NotCommitted(Refusal),
    /// Recorded, not closed (step 2).
    NotClosed(Refusal),
    /// An accept's outcome is unknown: send the same request again.
    Pending(String),
    /// Not handled on this Warden (D74): nothing recorded.
    NotHere(String),
}

/// A request to the decider socket.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Request {
    /// First, once.
    Hello {
        /// [`VERSION`].
        version: u32,
    },
    /// The pending Candidates (D73).
    Pending,
    /// A verdict.
    Verdict {
        /// The request; its `request_id` is checked against the peer.
        request: Box<VerdictRequest>,
    },
}

/// A reply from the decider socket.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reply {
    /// The Warden's version.
    Hello {
        /// [`VERSION`].
        version: u32,
    },
    /// The pending Candidates.
    Pending {
        /// Each one.
        items: Vec<PendingItem>,
    },
    /// The answer to a verdict.
    Verdict {
        /// It.
        answer: VerdictAnswer,
    },
    /// A malformed or out-of-order request: nothing recorded.
    Error {
        /// Why.
        message: String,
    },
}

impl PendingItem {
    /// A verdict request by `uid` bound to this item's Candidate and its
    /// attempt `attempt` (an index into `attempts`): everything a caller
    /// binds a verdict to (§5.1), its `request_id` derived.
    pub fn request(
        &self,
        attempt: usize,
        decision: crate::contract::Decision,
        authority: crate::record::Authority,
        policy_digest: Option<crate::envelope::HashVal>,
        uid: u32,
    ) -> VerdictRequest {
        let k = &self.candidate;
        let (s, f) = &self.attempts[attempt];
        let mut r = VerdictRequest {
            request_id: crate::envelope::HashVal::from_bytes([0; 32]),
            candidate_id: k.candidate_id,
            facts_hash: k.facts_hash,
            artifact_key: k.artifact_key,
            requirement: k.requirement,
            exclude: k.exclude.clone(),
            attempt_id: s.attempt_id,
            result_digest: f.result_digest,
            decision,
            authority,
            policy_digest,
        };
        r.request_id =
            crate::contract::request_id(uid, crate::contract::OpKind::Verdict, &r.body());
        r
    }
}

impl Canonical for PendingItem {
    fn canon(&self, out: &mut Canon) {
        self.candidate.canon(out);
        out.u64(self.attempts.len() as u64);
        for (s, f) in &self.attempts {
            s.canon(out);
            f.canon(out);
        }
    }
}

impl Canonical for VerdictAnswer {
    fn canon(&self, out: &mut Canon) {
        match self {
            Self::Committed { template_id } => {
                out.tag(0);
                template_id.canon(out);
            }
            Self::Held => {
                out.tag(1);
            }
            Self::ClosedNever => {
                out.tag(2);
            }
            Self::Refused(r) => {
                out.tag(3);
                r.canon(out);
            }
            Self::NotCommitted(r) => {
                out.tag(4);
                r.canon(out);
            }
            Self::NotClosed(r) => {
                out.tag(5);
                r.canon(out);
            }
            Self::Pending(why) => {
                out.tag(6).str(why);
            }
            Self::NotHere(why) => {
                out.tag(7).str(why);
            }
        }
    }
}

impl Request {
    /// The canonical body.
    pub fn encode(&self) -> Vec<u8> {
        let mut c = Canon::new();
        match self {
            Self::Hello { version } => {
                c.tag(0).u32(*version);
            }
            Self::Pending => {
                c.tag(1);
            }
            Self::Verdict { request } => {
                c.tag(2);
                request.canon(&mut c);
            }
        }
        c.into_bytes()
    }

    /// Strict decoding.
    pub fn decode(b: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(b);
        let v = match r.tag()? {
            (_, 0) => Self::Hello { version: r.u32()? },
            (_, 1) => Self::Pending,
            (_, 2) => Self::Verdict {
                request: Box::new(r.verdict_request()?),
            },
            (at, t) => return Reader::bad(at, "decider request", t),
        };
        r.finish()?;
        Ok(v)
    }
}

impl Reply {
    /// The canonical body.
    pub fn encode(&self) -> Vec<u8> {
        let mut c = Canon::new();
        match self {
            Self::Hello { version } => {
                c.tag(0).u32(*version);
            }
            Self::Pending { items } => {
                c.tag(1).seq(items.iter());
            }
            Self::Verdict { answer } => {
                c.tag(2);
                answer.canon(&mut c);
            }
            Self::Error { message } => {
                c.tag(3).str(message);
            }
        }
        c.into_bytes()
    }

    /// Strict decoding.
    pub fn decode(b: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(b);
        let v = match r.tag()? {
            (_, 0) => Self::Hello { version: r.u32()? },
            (_, 1) => Self::Pending {
                items: r.seq(|r| {
                    Ok(PendingItem {
                        candidate: r.candidate()?,
                        attempts: r.seq(|r| Ok((r.started()?, r.finished()?)))?,
                    })
                })?,
            },
            (_, 2) => Self::Verdict {
                answer: answer(&mut r)?,
            },
            (_, 3) => Self::Error {
                message: r.string()?,
            },
            (at, t) => return Reader::bad(at, "decider reply", t),
        };
        r.finish()?;
        Ok(v)
    }
}

fn answer(r: &mut Reader<'_>) -> Result<VerdictAnswer, DecodeError> {
    Ok(match r.tag()? {
        (_, 0) => VerdictAnswer::Committed {
            template_id: r.chronicle()?,
        },
        (_, 1) => VerdictAnswer::Held,
        (_, 2) => VerdictAnswer::ClosedNever,
        (_, 3) => VerdictAnswer::Refused(r.refusal()?),
        (_, 4) => VerdictAnswer::NotCommitted(r.refusal()?),
        (_, 5) => VerdictAnswer::NotClosed(r.refusal()?),
        (_, 6) => VerdictAnswer::Pending(r.string()?),
        (_, 7) => VerdictAnswer::NotHere(r.string()?),
        (at, t) => return Reader::bad(at, "verdict answer", t),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::tests::{candidate, finished, started, verdict_request};

    fn every_reply() -> Vec<Reply> {
        let mut v = vec![
            Reply::Hello { version: VERSION },
            Reply::Pending { items: vec![] },
            Reply::Pending {
                items: vec![PendingItem {
                    candidate: candidate(),
                    attempts: vec![(started(), finished()), (started(), finished())],
                }],
            },
            Reply::Error {
                message: "out of order".into(),
            },
        ];
        for answer in [
            VerdictAnswer::Committed {
                template_id: ChronicleId::from_bytes([7; 16]),
            },
            VerdictAnswer::Held,
            VerdictAnswer::ClosedNever,
            VerdictAnswer::Refused(Refusal::StaleFacts),
            VerdictAnswer::NotCommitted(Refusal::LaterAttemptFailed),
            VerdictAnswer::NotClosed(Refusal::OpenAttempt),
            VerdictAnswer::Pending("unknown".into()),
            VerdictAnswer::NotHere("held elsewhere".into()),
        ] {
            v.push(Reply::Verdict { answer });
        }
        v
    }

    #[test]
    fn every_message_round_trips_and_decoding_is_strict() {
        let reqs = [
            Request::Hello { version: VERSION },
            Request::Pending,
            Request::Verdict {
                request: Box::new(verdict_request()),
            },
        ];
        for (i, q) in reqs.iter().enumerate() {
            let b = q.encode();
            assert_eq!(b[0] as usize, i);
            assert_eq!(&Request::decode(&b).unwrap(), q);
            let mut t = b.clone();
            t.push(0);
            assert!(matches!(
                Request::decode(&t),
                Err(DecodeError::Trailing { .. })
            ));
            if b.len() > 1 {
                assert!(Request::decode(&b[..b.len() - 1]).is_err());
            }
        }
        assert!(matches!(
            Request::decode(&[3]),
            Err(DecodeError::BadTag { .. })
        ));
        for p in every_reply() {
            let b = p.encode();
            assert_eq!(&Reply::decode(&b).unwrap(), &p);
            let mut t = b.clone();
            t.push(0);
            assert!(Reply::decode(&t).is_err());
            assert!(Reply::decode(&b[..b.len() - 1]).is_err());
        }
        assert!(matches!(
            Reply::decode(&[4]),
            Err(DecodeError::BadTag { .. })
        ));
        assert!(Reply::decode(&[2, 8]).is_err(), "no answer tag 8");
        assert!(Reply::decode(&[2, 4, 12]).is_err(), "no refusal tag 12");
    }
}
