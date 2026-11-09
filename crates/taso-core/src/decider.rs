//! The decider socket's messages (P4 spec rev. 30 §5.1, D72, D73, D77, D78, D86).
//!
//! Framed as the Field's (`crate::frame`). A body is a tag and its fields
//! in the canonical encoding (§9); decoding is strict: unknown tags,
//! truncation and trailing bytes are refused, so every accepted body
//! re-encodes to itself.
//!
//! | Request | tag | Reply | tag |
//! | --- | --- | --- | --- |
//! | `Hello { version }` | 0 | `Hello { version }` | 0 |
//! | `Pending { after }` | 1 | `Pending { items, more }` | 1 |
//! | `Verdict { request }` | 2 | `Verdict { answer }` | 2 |
//! | | | `Error { message }` | 3 |
//! | `Proposals { vessel, after }` | 3 | `Proposals { items, more, last_seal }` | 4 |
//!
//! Answers (D77, D86): `Committed { template_id }` 0, `Held` 1,
//! `ClosedNever` 2, `Refused { rule }` 3, `Retry { reason }` 4.  A Retry's
//! reason: `NotHere { why }` 0, `Pending { why }` 1, `Rule { rule }` 2.  A
//! rule is the `Refusal` tag of §5.1.
//!
//! `Pending` is read in pages (version 2, review fix N3b-a): the pending
//! Candidates in `candidate_id` order after `after` (from the first when
//! `None`), at most [`PENDING_PAGE`] of them and about
//! [`PENDING_PAGE_BYTES`], and `more` while any remain.  A caller reads
//! until `more` is false, passing the last item's id as `after`, so every
//! pending Candidate is seen whatever their number.
//!
//! `Proposals` (version 3) is a read: the held proposals of one Vessel,
//! in op order after `after`, in pages cut the same way.  It records
//! nothing and changes nothing; it never releases, adopts or refuses.
//! A proposal is what an agent asked for on a branch that may never be
//! promoted: only the sender socket's `Open` list says what may be sent.

use crate::canon::{Canon, Canonical};
use crate::contract::{
    Candidate, Refusal, VerdictRequest, VerificationFinished, VerificationStarted,
};
use crate::decode::{DecodeError, Reader};
use crate::envelope::{ChronicleId, HashVal, Lsn};
use crate::record::IntentRecord;

/// The protocol version.  2: `Pending` in pages (review fix N3b-a).  3:
/// `Proposals`.  A peer speaking another version is refused at `Hello`.
pub const VERSION: u32 = 3;

/// The most items in one `Pending` page.
pub const PENDING_PAGE: usize = 64;

/// A `Pending` page ends early once its items' encoding passes this, so a
/// reply stays well under the 16 MiB frame whatever an item holds (64
/// items are about 4.3 MiB today).  A page always holds at least one item.
pub const PENDING_PAGE_BYTES: usize = 8 << 20;

/// One pending Candidate (D73): the accepted record and its finished
/// attempts, in the order they started.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingItem {
    /// The accepted Candidate.
    pub candidate: Candidate,
    /// Its finished attempts.
    pub attempts: Vec<(VerificationStarted, VerificationFinished)>,
}

/// One held proposal of a Vessel: an intent its agent declared that no
/// Vessel has released.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProposalItem {
    /// The Intent record's lsn in the Vessel's Chronicle.
    pub lsn: Lsn,
    /// The intent, with the exact request bytes.
    pub intent: IntentRecord,
    /// Whether the Vessel's last Seal covers it (the intent is at or
    /// before that Seal's ledger position).  One that is not can vanish
    /// when the Vessel is rolled back, and cannot be promoted yet.
    pub sealed: bool,
}

impl Canonical for ProposalItem {
    fn canon(&self, out: &mut Canon) {
        self.lsn.canon(out);
        self.intent.canon(out);
        out.bool(self.sealed);
    }
}

/// One page of `items` (every held proposal of one Vessel, any order)
/// after the op `after`: in op order, at most [`PENDING_PAGE`] items and
/// about [`PENDING_PAGE_BYTES`] (at least one), and whether more remain.
/// What a Warden answers `Proposals { after }` with.
pub fn proposal_page(
    mut items: Vec<ProposalItem>,
    after: Option<u64>,
) -> (Vec<ProposalItem>, bool) {
    let op = |i: &ProposalItem| i.intent.op.get();
    items.retain(|i| after.is_none_or(|a| op(i) > a));
    items.sort_by_key(op);
    items.dedup_by_key(|i| op(i));
    let mut bytes = 0;
    let mut n = 0;
    for i in &items {
        if n == PENDING_PAGE || (n > 0 && bytes >= PENDING_PAGE_BYTES) {
            break;
        }
        let mut c = Canon::new();
        i.canon(&mut c);
        bytes += c.as_bytes().len();
        n += 1;
    }
    let more = items.len() > n;
    items.truncate(n);
    (items, more)
}

/// Why the Warden answers [`VerdictAnswer::Retry`] (D86): for a person
/// reading it.  The caller does the same for each: it sends the same
/// request again later.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RetryReason {
    /// The Warden did not handle it here (D74): nothing recorded
    /// (tag 0).  Ask again, or ask the Vessel's Warden.
    NotHere(String),
    /// An accept's outcome is unknown, or a running session did not take
    /// it in time; it may be recorded (tag 1).
    Pending(String),
    /// Recorded, not done: a rule that can still change (steps 2–3), or
    /// the coordinator refused this commit (step 4) (tag 2).
    Rule(Refusal),
}

impl Canonical for RetryReason {
    fn canon(&self, out: &mut Canon) {
        match self {
            Self::NotHere(why) => {
                out.tag(0).str(why);
            }
            Self::Pending(why) => {
                out.tag(1).str(why);
            }
            Self::Rule(r) => {
                out.tag(2);
                r.canon(out);
            }
        }
    }
}

/// The answer to a verdict (D77, D86).
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
    /// For good: an accepted `Refused`, or `Closed` when another verdict
    /// closed the Candidate after this one was recorded (D86).
    Refused(Refusal),
    /// Send the same request again later (D86).
    Retry(RetryReason),
}

/// A request to the decider socket.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Request {
    /// First, once.
    Hello {
        /// [`VERSION`].
        version: u32,
    },
    /// A page of the pending Candidates (D73): those after `after`.
    Pending {
        /// The last `candidate_id` of the page before; `None`: from the
        /// first.
        after: Option<HashVal>,
    },
    /// A verdict.
    Verdict {
        /// The request; its `request_id` is checked against the peer.
        request: Box<VerdictRequest>,
    },
    /// A page of one Vessel's held proposals: those after the op `after`.
    /// A read; nothing is recorded.
    Proposals {
        /// The Vessel's Chronicle id.
        vessel: ChronicleId,
        /// The last op of the page before; `None`: from the first.
        after: Option<u64>,
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
    /// A page of the pending Candidates, in `candidate_id` order.
    Pending {
        /// Each one.
        items: Vec<PendingItem>,
        /// Whether more remain after the last of `items`.
        more: bool,
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
    /// A page of a Vessel's held proposals, in op order.
    Proposals {
        /// Each one.
        items: Vec<ProposalItem>,
        /// Whether more remain after the last of `items`.
        more: bool,
        /// The Vessel's last Seal, by which `sealed` was decided; `None`:
        /// it has none.
        last_seal: Option<Lsn>,
    },
}

/// One page of `items` (every pending Candidate, any order) after
/// `after`: sorted by `candidate_id`, at most [`PENDING_PAGE`] items and
/// about [`PENDING_PAGE_BYTES`] (at least one), and whether more remain.
/// What a Warden answers `Pending { after }` with.
pub fn page(mut items: Vec<PendingItem>, after: Option<HashVal>) -> (Vec<PendingItem>, bool) {
    let id = |i: &PendingItem| *i.candidate.candidate_id.as_bytes();
    items.retain(|i| after.is_none_or(|a| id(i) > *a.as_bytes()));
    items.sort_by_key(id);
    items.dedup_by(|a, b| a.candidate.candidate_id == b.candidate.candidate_id);
    let mut bytes = 0;
    let mut n = 0;
    for i in &items {
        if n == PENDING_PAGE || (n > 0 && bytes >= PENDING_PAGE_BYTES) {
            break;
        }
        let mut c = Canon::new();
        i.canon(&mut c);
        bytes += c.as_bytes().len();
        n += 1;
    }
    let more = items.len() > n;
    items.truncate(n);
    (items, more)
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
            Self::Retry(r) => {
                out.tag(4);
                r.canon(out);
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
            Self::Pending { after } => {
                c.tag(1).option(after.as_ref());
            }
            Self::Verdict { request } => {
                c.tag(2);
                request.canon(&mut c);
            }
            Self::Proposals { vessel, after } => {
                c.tag(3);
                vessel.canon(&mut c);
                match after {
                    None => c.tag(0),
                    Some(op) => c.tag(1).u64(*op),
                };
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
                after: r.option(Reader::hash)?,
            },
            (_, 2) => Self::Verdict {
                request: Box::new(r.verdict_request()?),
            },
            (_, 3) => Self::Proposals {
                vessel: r.chronicle()?,
                after: r.option(Reader::u64)?,
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
            Self::Pending { items, more } => {
                c.tag(1).seq(items.iter()).bool(*more);
            }
            Self::Verdict { answer } => {
                c.tag(2);
                answer.canon(&mut c);
            }
            Self::Error { message } => {
                c.tag(3).str(message);
            }
            Self::Proposals {
                items,
                more,
                last_seal,
            } => {
                c.tag(4)
                    .seq(items.iter())
                    .bool(*more)
                    .option(last_seal.as_ref());
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
                more: r.bool()?,
            },
            (_, 2) => Self::Verdict {
                answer: answer(&mut r)?,
            },
            (_, 3) => Self::Error {
                message: r.string()?,
            },
            (_, 4) => Self::Proposals {
                items: r.seq(|r| {
                    Ok(ProposalItem {
                        lsn: r.lsn()?,
                        intent: r.intent()?,
                        sealed: r.bool()?,
                    })
                })?,
                more: r.bool()?,
                last_seal: r.option(Reader::lsn)?,
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
        (_, 4) => VerdictAnswer::Retry(match r.tag()? {
            (_, 0) => RetryReason::NotHere(r.string()?),
            (_, 1) => RetryReason::Pending(r.string()?),
            (_, 2) => RetryReason::Rule(r.refusal()?),
            (at, t) => return Reader::bad(at, "retry reason", t),
        }),
        (at, t) => return Reader::bad(at, "verdict answer", t),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::tests::{candidate, finished, started, verdict_request};
    use crate::envelope::Lsn;
    use crate::record::{BarrierId, Consequence, Dispatch, IntentRecord, OpId, RetryPolicy};

    fn every_reply() -> Vec<Reply> {
        let mut v = vec![
            Reply::Hello { version: VERSION },
            Reply::Pending {
                items: vec![],
                more: false,
            },
            Reply::Pending {
                items: vec![PendingItem {
                    candidate: candidate(),
                    attempts: vec![(started(), finished()), (started(), finished())],
                }],
                more: true,
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
            VerdictAnswer::Retry(RetryReason::NotHere("held elsewhere".into())),
            VerdictAnswer::Retry(RetryReason::Pending("unknown".into())),
            VerdictAnswer::Retry(RetryReason::Rule(Refusal::LaterAttemptFailed)),
            VerdictAnswer::Retry(RetryReason::Rule(Refusal::OpenAttempt)),
        ] {
            v.push(Reply::Verdict { answer });
        }
        v
    }

    #[test]
    fn every_message_round_trips_and_decoding_is_strict() {
        let reqs = [
            Request::Hello { version: VERSION },
            Request::Pending { after: None },
            Request::Pending {
                after: Some(HashVal::from_bytes([9; 32])),
            },
            Request::Verdict {
                request: Box::new(verdict_request()),
            },
        ];
        for (q, tag) in reqs.iter().zip([0, 1, 1, 2]) {
            let b = q.encode();
            assert_eq!(b[0], tag);
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
            Request::decode(&[4]),
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
            Reply::decode(&[5]),
            Err(DecodeError::BadTag { .. })
        ));
        assert!(Reply::decode(&[2, 5]).is_err(), "no answer tag 5 (D86)");
        assert!(Reply::decode(&[2, 3, 12]).is_err(), "no refusal tag 12");
        assert!(Reply::decode(&[2, 4, 3]).is_err(), "no retry reason tag 3");
        assert!(Reply::decode(&[2, 4, 2, 12]).is_err(), "no refusal tag 12");
        // Version 1's Pending (no `after`, no `more`) is not version 2's.
        assert!(Request::decode(&[1]).is_err(), "a v1 Pending request");
        assert!(
            Reply::decode(&[1, 0, 0, 0, 0, 0, 0, 0, 0]).is_err(),
            "a v1 Pending reply"
        );
    }

    fn item(id: u8) -> PendingItem {
        let mut c = candidate();
        c.candidate_id = HashVal::from_bytes([id; 32]);
        PendingItem {
            candidate: c,
            attempts: vec![(started(), finished())],
        }
    }

    /// Review fix N3b-a: 200 pending Candidates, read page by page from
    /// any order, are each seen once, in id order, in pages of at most
    /// 64; the last page says no more.
    #[test]
    fn pages_cover_every_pending_candidate_once() {
        let all: Vec<PendingItem> = (0..200u32)
            .map(|i| {
                let mut it = item(0);
                let mut b = [0u8; 32];
                b[..4].copy_from_slice(&(i.wrapping_mul(2_654_435_761)).to_be_bytes());
                it.candidate.candidate_id = HashVal::from_bytes(b);
                it
            })
            .collect();
        let mut seen = Vec::new();
        let mut after = None;
        let mut pages = 0;
        loop {
            let (got, more) = page(all.clone(), after);
            pages += 1;
            assert!(got.len() <= PENDING_PAGE);
            assert!(!got.is_empty() || !more);
            seen.extend(got.iter().map(|i| i.candidate.candidate_id));
            after = got.last().map(|i| i.candidate.candidate_id);
            if !more {
                break;
            }
        }
        assert_eq!(pages, 4, "64 + 64 + 64 + 8");
        let mut want: Vec<HashVal> = all.iter().map(|i| i.candidate.candidate_id).collect();
        want.sort_by_key(|h| *h.as_bytes());
        assert_eq!(seen, want, "each once, in order");
        // Nothing pending: one empty page.
        assert_eq!(page(Vec::new(), None), (Vec::new(), false));
    }

    /// A page ends early at about PENDING_PAGE_BYTES, never empty.
    #[test]
    fn a_page_ends_at_its_byte_bound() {
        let mut big = item(1);
        let mut f = big.attempts[0].1.clone();
        f.output = vec![0; PENDING_PAGE_BYTES / 2];
        big.attempts[0].1 = f;
        let items: Vec<PendingItem> = (1..=4u8)
            .map(|i| {
                let mut b = big.clone();
                b.candidate.candidate_id = HashVal::from_bytes([i; 32]);
                b
            })
            .collect();
        let (got, more) = page(items.clone(), None);
        assert_eq!(got.len(), 2, "two halves reach the bound");
        assert!(more);
        // One item larger than the bound still makes a page.
        let mut huge = items[0].clone();
        huge.attempts[0].1.output = vec![0; PENDING_PAGE_BYTES + 1];
        let (got, more) = page(vec![huge], None);
        assert_eq!((got.len(), more), (1, false));
    }

    fn proposal(op: u64, request_len: usize) -> ProposalItem {
        ProposalItem {
            lsn: Lsn::new(10 + op),
            intent: IntentRecord {
                op: OpId::new(op),
                provider: "mail".into(),
                request: vec![7; request_len],
                footprint: b"inbox:a".to_vec(),
                dispatch: Dispatch::Immediate,
                retry: RetryPolicy::ProviderDeduplicated { key: b"k".to_vec() },
                consequence: Consequence::Irreversible,
                authority: Vec::new(),
                barrier: Some(BarrierId::new(op)),
            },
            sealed: op.is_multiple_of(2),
        }
    }

    /// 4a: the Proposals request and reply round-trip under their own
    /// tags, and decoding stays strict.
    #[test]
    fn proposals_round_trip_and_decoding_is_strict() {
        let vessel = ChronicleId::from_bytes([5; 16]);
        for q in [
            Request::Proposals {
                vessel,
                after: None,
            },
            Request::Proposals {
                vessel,
                after: Some(41),
            },
        ] {
            let b = q.encode();
            assert_eq!(b[0], 3);
            assert_eq!(Request::decode(&b).unwrap(), q);
            let mut t = b.clone();
            t.push(0);
            assert!(matches!(
                Request::decode(&t),
                Err(DecodeError::Trailing { .. })
            ));
            assert!(Request::decode(&b[..b.len() - 1]).is_err());
        }
        for p in [
            Reply::Proposals {
                items: vec![],
                more: false,
                last_seal: None,
            },
            Reply::Proposals {
                items: vec![proposal(1, 3), proposal(2, 0)],
                more: true,
                last_seal: Some(Lsn::new(12)),
            },
        ] {
            let b = p.encode();
            assert_eq!(b[0], 4);
            assert_eq!(Reply::decode(&b).unwrap(), p);
            let mut t = b.clone();
            t.push(0);
            assert!(Reply::decode(&t).is_err());
            assert!(Reply::decode(&b[..b.len() - 1]).is_err());
        }
    }

    /// 4a: 150 proposals, given in any order, are each seen once, in op
    /// order, in pages of at most 64; nothing held is one empty page.
    #[test]
    fn proposal_pages_cover_every_proposal_once() {
        let all: Vec<ProposalItem> = (1..=150u64).rev().map(|op| proposal(op, 8)).collect();
        let mut seen = Vec::new();
        let mut after = None;
        let mut pages = 0;
        loop {
            let (got, more) = proposal_page(all.clone(), after);
            pages += 1;
            assert!(got.len() <= PENDING_PAGE);
            assert!(!got.is_empty() || !more);
            seen.extend(got.iter().map(|i| i.intent.op.get()));
            after = got.last().map(|i| i.intent.op.get());
            if !more {
                break;
            }
        }
        assert_eq!(pages, 3, "64 + 64 + 22");
        assert_eq!(
            seen,
            (1..=150).collect::<Vec<u64>>(),
            "each once, in op order"
        );
        assert_eq!(proposal_page(Vec::new(), None), (Vec::new(), false));
        // `after` at or past the last op: an empty page, no more.
        assert_eq!(proposal_page(all, Some(150)), (Vec::new(), false));
    }

    /// 4a: a page of proposals ends at about PENDING_PAGE_BYTES, and one
    /// proposal larger than the bound still makes a page.
    #[test]
    fn a_proposal_page_ends_at_its_byte_bound() {
        let items: Vec<ProposalItem> = (1..=4)
            .map(|op| proposal(op, PENDING_PAGE_BYTES / 2))
            .collect();
        let (got, more) = proposal_page(items, None);
        assert_eq!((got.len(), more), (2, true), "two halves reach the bound");
        let (got, more) = proposal_page(vec![proposal(1, PENDING_PAGE_BYTES + 1)], None);
        assert_eq!((got.len(), more), (1, false));
    }
}
