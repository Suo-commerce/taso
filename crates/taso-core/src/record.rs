//! Record types: the payloads that ride inside an [`Envelope`].
//!
//! A Chronicle record is an [`Envelope`] (position in the hash chain)
//! plus a [`Payload`].  Taso parses envelopes on every record; it parses
//! payloads only for its own types — [`SealRecord`], [`GroupRecord`],
//! [`IntentRecord`], [`OutcomeRecord`] — and treats everything else as
//! opaque bytes ([`Payload::Raw`]).
//!
//! Normative references: v0.4 §§3–7.

use crate::canon::{Canon, Canonical};
use crate::envelope::{
    BranchId, ChronicleId, ChronicleHead, Envelope, Epoch, HashVal, Lsn,
    Stream, payload_hash,
};

// ── Identity newtypes ───────────────────────────────────────────────

/// A group's identity within a Chronicle.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct GroupId(u64);

impl GroupId {
    /// Wrap a raw value.
    pub const fn new(v: u64) -> Self { Self(v) }
    /// The raw value.
    pub const fn get(self) -> u64 { self.0 }
}

impl Canonical for GroupId {
    fn canon(&self, out: &mut Canon) { out.u64(self.0); }
}

/// A stable logical identity for an effect operation.
///
/// Survives rebirth: if the same logical operation is retried after a
/// crash, it keeps the same `OpId` (v0.4 §7).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct OpId(u64);

impl OpId {
    /// Wrap a raw value.
    pub const fn new(v: u64) -> Self { Self(v) }
    /// The raw value.
    pub const fn get(self) -> u64 { self.0 }
}

impl Canonical for OpId {
    fn canon(&self, out: &mut Canon) { out.u64(self.0); }
}

/// A monotone identifier for an intent whose consequence is irreversible
/// or whose outcome is unknown.
///
/// A target Seal must account for every barrier through the authoritative
/// head (v0.4 §7.4).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct BarrierId(u64);

impl BarrierId {
    /// Wrap a raw value.
    pub const fn new(v: u64) -> Self { Self(v) }
    /// The raw value.
    pub const fn get(self) -> u64 { self.0 }
}

impl Canonical for BarrierId {
    fn canon(&self, out: &mut Canon) { out.u64(self.0); }
}

/// A turn boundary identifier.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct TurnId(u64);

impl TurnId {
    /// Wrap a raw value.
    pub const fn new(v: u64) -> Self { Self(v) }
    /// The raw value.
    pub const fn get(self) -> u64 { self.0 }
}

impl Canonical for TurnId {
    fn canon(&self, out: &mut Canon) { out.u64(self.0); }
}

/// A reference to a copy-on-write layer.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct LayerRef(u64);

impl LayerRef {
    /// Wrap a raw value.
    pub const fn new(v: u64) -> Self { Self(v) }
    /// The raw value.
    pub const fn get(self) -> u64 { self.0 }
}

impl Canonical for LayerRef {
    fn canon(&self, out: &mut Canon) { out.u64(self.0); }
}

// ── StreamCut ───────────────────────────────────────────────────────

/// Per-stream positions at a Seal's cut (state streams only).
///
/// A cut records the highest LSN observed on each state stream at the
/// time the Seal was taken.  `Lsn(0)` means no records on that stream.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct StreamCut {
    /// Highest `Fs` LSN at the cut.
    pub fs: Lsn,
    /// Highest `Db` LSN at the cut.
    pub db: Lsn,
    /// Highest `Transcript` LSN at the cut.
    pub transcript: Lsn,
}

impl StreamCut {
    /// A cut before any state-stream records.
    pub const EMPTY: Self = Self {
        fs: Lsn::new(0),
        db: Lsn::new(0),
        transcript: Lsn::new(0),
    };
}

impl Canonical for StreamCut {
    fn canon(&self, out: &mut Canon) {
        self.fs.canon(out);
        self.db.canon(out);
        self.transcript.canon(out);
    }
}

// ── Member ──────────────────────────────────────────────────────────

/// A `(stream, lsn)` pair in a [`GroupRecord`]'s member list.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Member {
    /// Which stream.
    pub stream: Stream,
    /// Position in that stream.
    pub lsn: Lsn,
}

impl Canonical for Member {
    fn canon(&self, out: &mut Canon) {
        self.stream.canon(out);
        self.lsn.canon(out);
    }
}

// ── Classification enums ────────────────────────────────────────────

/// How a Seal's state is tainted (v0.4 §5.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TaintKind {
    /// The hash chain has a gap or mismatch.
    ChainBroken = 0,
    /// A group at the cut is uncommitted or causally open.
    GroupIncomplete = 1,
    /// A barrier after the cut is unaccounted.
    BarrierViolation = 2,
}

impl Canonical for TaintKind {
    fn canon(&self, out: &mut Canon) {
        out.tag(*self as u8);
    }
}

/// A Seal's verdict on the state at its cut (v0.4 §5.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// State is clean.
    Clean,
    /// State is unverified; the reason names what is missing.
    Unverified(String),
    /// State is tainted.
    Tainted(TaintKind),
}

impl Canonical for Verdict {
    fn canon(&self, out: &mut Canon) {
        match self {
            Self::Clean => { out.tag(0); }
            Self::Unverified(reason) => {
                out.tag(1);
                out.str(reason);
            }
            Self::Tainted(kind) => {
                out.tag(2);
                kind.canon(out);
            }
        }
    }
}

/// Whether an effect dispatches immediately or at the next Seal
/// (v0.4 §7.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dispatch {
    /// Dispatch now.
    Immediate = 0,
    /// Dispatch at the next Seal commit.
    Deferrable = 1,
}

impl Canonical for Dispatch {
    fn canon(&self, out: &mut Canon) {
        out.tag(*self as u8);
    }
}

/// How an intent may be retried after a crash (v0.4 §7.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RetryPolicy {
    /// Provider deduplicates by key.
    ProviderDeduplicated {
        /// Opaque idempotency key.
        key: Vec<u8>,
    },
    /// Outcome can be queried from the provider.
    Queryable {
        /// Opaque probe descriptor.
        probe: Vec<u8>,
    },
    /// No safe retry; manual reconciliation required (v0.4 §14).
    UnsafeToRetry,
}

impl Canonical for RetryPolicy {
    fn canon(&self, out: &mut Canon) {
        match self {
            Self::ProviderDeduplicated { key } => {
                out.tag(0);
                out.bytes(key);
            }
            Self::Queryable { probe } => {
                out.tag(1);
                out.bytes(probe);
            }
            Self::UnsafeToRetry => {
                out.tag(2);
            }
        }
    }
}

/// The consequence class of an effect (v0.4 §7.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Consequence {
    /// Cannot be undone.
    Irreversible,
    /// Can be compensated by another operation.
    Compensatable {
        /// The operation that compensates this one.
        by: OpId,
    },
    /// No external state change.
    NoExternalMutation,
}

impl Canonical for Consequence {
    fn canon(&self, out: &mut Canon) {
        match self {
            Self::Irreversible => { out.tag(0); }
            Self::Compensatable { by } => {
                out.tag(1);
                by.canon(out);
            }
            Self::NoExternalMutation => { out.tag(2); }
        }
    }
}

/// The five-state lifecycle of an effect outcome (v0.4 §7.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutcomeState {
    /// Intent recorded, not yet authorized.
    Prepared = 0,
    /// Dispatch authorized (intent durable).
    DispatchAuthorized = 1,
    /// Dispatch happened but outcome is unknown (crash during dispatch).
    OutcomeUnknown = 2,
    /// Provider confirmed the effect was applied.
    ConfirmedApplied = 3,
    /// Provider confirmed the effect was not applied.
    ConfirmedNotApplied = 4,
}

impl Canonical for OutcomeState {
    fn canon(&self, out: &mut Canon) {
        out.tag(*self as u8);
    }
}

// ── Structured payloads ─────────────────────────────────────────────

/// A Seal: metadata-only freeze at a causally closed cut (v0.4 §5.2).
///
/// Identity and Chronicle association come from the enclosing
/// [`Envelope`]; only Seal-specific data lives here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealRecord {
    /// Hash of the parent Seal's record, or `None` for the first.
    pub parent: Option<HashVal>,
    /// Per-stream positions at the cut.
    pub cut: StreamCut,
    /// The CoW layer this Seal freezes.
    pub layer: LayerRef,
    /// Verdict on the state at this cut.
    pub verdict: Verdict,
    /// Highest effect-ledger LSN observed at the cut.
    pub ledger_pos: Lsn,
    /// The turn that triggered this Seal.
    pub turn: TurnId,
}

impl Canonical for SealRecord {
    fn canon(&self, out: &mut Canon) {
        out.option(self.parent.as_ref());
        self.cut.canon(out);
        self.layer.canon(out);
        self.verdict.canon(out);
        self.ledger_pos.canon(out);
        self.turn.canon(out);
    }
}

/// A group: a set of state-stream records that commit atomically
/// (v0.4 §4).
///
/// Every `fs`/`db` record belongs to a group.  A Seal cut is valid only
/// at a point where every included group is committed and every
/// `depends_on` is satisfied (causal closure).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupRecord {
    /// This group's identity.
    pub gid: GroupId,
    /// The `(stream, lsn)` positions that belong to this group.
    pub members: Vec<Member>,
    /// Groups that must be committed before this one.
    pub depends_on: Vec<GroupId>,
    /// True only in the group's final (commit) record.
    pub commit: bool,
}

impl Canonical for GroupRecord {
    fn canon(&self, out: &mut Canon) {
        self.gid.canon(out);
        out.u64(self.members.len() as u64);
        for m in &self.members {
            m.canon(out);
        }
        out.seq(self.depends_on.iter());
        out.bool(self.commit);
    }
}

/// A durable intent written before an effect may dispatch (v0.4 §7.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IntentRecord {
    /// Stable logical identity; survives rebirth.
    pub op: OpId,
    /// Canonical resource set (opaque; Field-assigned).
    pub footprint: Vec<u8>,
    /// Immediate or deferrable.
    pub dispatch: Dispatch,
    /// How the effect can be retried.
    pub retry: RetryPolicy,
    /// Consequence class.
    pub consequence: Consequence,
    /// Which credential/lease permitted this effect (opaque).
    pub authority: Vec<u8>,
    /// Set iff consequence is not `NoExternalMutation`.
    pub barrier: Option<BarrierId>,
}

impl Canonical for IntentRecord {
    fn canon(&self, out: &mut Canon) {
        self.op.canon(out);
        out.bytes(&self.footprint);
        self.dispatch.canon(out);
        self.retry.canon(out);
        self.consequence.canon(out);
        out.bytes(&self.authority);
        out.option(self.barrier.as_ref());
    }
}

/// An outcome record in the effect ledger (v0.4 §7.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutcomeRecord {
    /// The operation this outcome belongs to.
    pub op: OpId,
    /// Current state.
    pub state: OutcomeState,
    /// Provider receipt or probe result (opaque).
    pub evidence: Option<Vec<u8>>,
}

impl Canonical for OutcomeRecord {
    fn canon(&self, out: &mut Canon) {
        self.op.canon(out);
        self.state.canon(out);
        self.evidence.canon(out);
    }
}

// ── Payload ─────────────────────────────────────────────────────────

/// The payload of a Chronicle record.
///
/// Each variant carries a distinct tag so different payload kinds never
/// collide in their canonical encoding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Payload {
    /// A Seal record (tag 0).
    Seal(SealRecord),
    /// A Group record (tag 1).
    Group(GroupRecord),
    /// An Intent record (tag 2).
    Intent(IntentRecord),
    /// An Outcome record (tag 3).
    Outcome(OutcomeRecord),
    /// Opaque bytes: `fs`, `db`, `transcript`, or `ctl` data (tag 4).
    Raw(Vec<u8>),
}

impl Canonical for Payload {
    fn canon(&self, out: &mut Canon) {
        match self {
            Self::Seal(r)    => { out.tag(0); r.canon(out); }
            Self::Group(r)   => { out.tag(1); r.canon(out); }
            Self::Intent(r)  => { out.tag(2); r.canon(out); }
            Self::Outcome(r) => { out.tag(3); r.canon(out); }
            Self::Raw(b)     => { out.tag(4); out.bytes(b); }
        }
    }
}

// ── Record ──────────────────────────────────────────────────────────

/// A complete Chronicle record: [`Envelope`] + [`Payload`].
///
/// The constructor computes the payload hash from the payload's canonical
/// encoding, then builds the envelope with the chained record hash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    /// Position and hash chain.
    pub envelope: Envelope,
    /// The record's content.
    pub payload: Payload,
}

impl Record {
    /// Construct a record, computing both hashes.
    pub fn new(
        chronicle: ChronicleId,
        branch: BranchId,
        epoch: Epoch,
        stream: Stream,
        lsn: Lsn,
        prev: HashVal,
        payload: Payload,
    ) -> Self {
        let ph = payload_hash(&payload.canon_bytes());
        let envelope = Envelope::new(
            chronicle, branch, epoch, stream, lsn, prev, ph,
        );
        Self { envelope, payload }
    }

    /// Recompute both hashes and check they match.
    pub fn verify(&self) -> bool {
        let ph = payload_hash(&self.payload.canon_bytes());
        ph == self.envelope.payload_hash && self.envelope.verify()
    }

    /// The [`ChronicleHead`] this record advances to.
    pub fn head(&self) -> ChronicleHead {
        self.envelope.head()
    }
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn cid() -> ChronicleId {
        ChronicleId::from_bytes([1; 16])
    }

    fn seal_payload() -> Payload {
        Payload::Seal(SealRecord {
            parent: None,
            cut: StreamCut {
                fs: Lsn::new(5),
                db: Lsn::new(3),
                transcript: Lsn::new(1),
            },
            layer: LayerRef::new(1),
            verdict: Verdict::Clean,
            ledger_pos: Lsn::new(2),
            turn: TurnId::new(1),
        })
    }

    fn group_payload() -> Payload {
        Payload::Group(GroupRecord {
            gid: GroupId::new(1),
            members: vec![
                Member { stream: Stream::Fs, lsn: Lsn::new(4) },
                Member { stream: Stream::Db, lsn: Lsn::new(3) },
            ],
            depends_on: vec![],
            commit: true,
        })
    }

    fn intent_payload() -> Payload {
        Payload::Intent(IntentRecord {
            op: OpId::new(1),
            footprint: b"resource:mail:send".to_vec(),
            dispatch: Dispatch::Immediate,
            retry: RetryPolicy::ProviderDeduplicated {
                key: b"idem-001".to_vec(),
            },
            consequence: Consequence::Irreversible,
            authority: b"lease-42".to_vec(),
            barrier: Some(BarrierId::new(1)),
        })
    }

    fn outcome_payload() -> Payload {
        Payload::Outcome(OutcomeRecord {
            op: OpId::new(1),
            state: OutcomeState::ConfirmedApplied,
            evidence: Some(b"receipt-xyz".to_vec()),
        })
    }

    fn raw_payload() -> Payload {
        Payload::Raw(b"hello, world".to_vec())
    }

    fn make_record(payload: Payload) -> Record {
        Record::new(
            cid(),
            BranchId::TRUNK,
            Epoch::FIRST,
            Stream::Fs,
            Lsn::new(1),
            HashVal::GENESIS,
            payload,
        )
    }

    #[test]
    fn seal_record_verifies() {
        let r = make_record(seal_payload());
        assert!(r.verify());
    }

    #[test]
    fn group_record_verifies() {
        let r = make_record(group_payload());
        assert!(r.verify());
    }

    #[test]
    fn intent_record_verifies() {
        let r = make_record(intent_payload());
        assert!(r.verify());
    }

    #[test]
    fn outcome_record_verifies() {
        let r = make_record(outcome_payload());
        assert!(r.verify());
    }

    #[test]
    fn raw_record_verifies() {
        let r = make_record(raw_payload());
        assert!(r.verify());
    }

    #[test]
    fn tampered_payload_fails_verify() {
        let mut r = make_record(raw_payload());
        r.payload = Payload::Raw(b"tampered".to_vec());
        assert!(!r.verify());
    }

    #[test]
    fn canonical_encoding_is_deterministic() {
        let p1 = intent_payload();
        let p2 = intent_payload();
        assert_eq!(p1.canon_bytes(), p2.canon_bytes());
    }

    #[test]
    fn different_payload_types_never_collide() {
        let payloads = [
            seal_payload(),
            group_payload(),
            intent_payload(),
            outcome_payload(),
            raw_payload(),
        ];
        let enc: Vec<Vec<u8>> =
            payloads.iter().map(|p| p.canon_bytes()).collect();
        for i in 0..enc.len() {
            for j in (i + 1)..enc.len() {
                assert_ne!(enc[i], enc[j], "types {i} and {j} collide");
            }
        }
    }

    #[test]
    fn record_head_matches_envelope() {
        let r = make_record(seal_payload());
        let head = r.head();
        assert_eq!(head.lsn, r.envelope.lsn);
        assert_eq!(head.hash, r.envelope.hash);
        assert_eq!(head.epoch, r.envelope.epoch);
    }

    #[test]
    fn chained_records_verify() {
        let r1 = make_record(raw_payload());
        let r2 = Record::new(
            cid(),
            BranchId::TRUNK,
            Epoch::FIRST,
            Stream::Fs,
            Lsn::new(2),
            r1.envelope.hash,
            intent_payload(),
        );
        let r3 = Record::new(
            cid(),
            BranchId::TRUNK,
            Epoch::FIRST,
            Stream::Effect,
            Lsn::new(3),
            r2.envelope.hash,
            outcome_payload(),
        );
        assert!(r1.verify());
        assert!(r2.verify());
        assert!(r3.verify());
        assert_eq!(r2.envelope.prev, r1.envelope.hash);
        assert_eq!(r3.envelope.prev, r2.envelope.hash);
    }

    #[test]
    fn verdict_variants_encode_distinctly() {
        let enc = [
            Verdict::Clean.canon_bytes(),
            Verdict::Unverified("dropped groups".into()).canon_bytes(),
            Verdict::Tainted(TaintKind::ChainBroken).canon_bytes(),
        ];
        assert_ne!(enc[0], enc[1]);
        assert_ne!(enc[0], enc[2]);
        assert_ne!(enc[1], enc[2]);
    }

    #[test]
    fn outcome_state_five_distinct() {
        let states = [
            OutcomeState::Prepared,
            OutcomeState::DispatchAuthorized,
            OutcomeState::OutcomeUnknown,
            OutcomeState::ConfirmedApplied,
            OutcomeState::ConfirmedNotApplied,
        ];
        let enc: Vec<Vec<u8>> =
            states.iter().map(|s| s.canon_bytes()).collect();
        for i in 0..enc.len() {
            for j in (i + 1)..enc.len() {
                assert_ne!(enc[i], enc[j]);
            }
        }
    }

    #[test]
    fn stream_cut_empty() {
        let cut = StreamCut::EMPTY;
        assert_eq!(cut.fs, Lsn::new(0));
        assert_eq!(cut.db, Lsn::new(0));
        assert_eq!(cut.transcript, Lsn::new(0));
    }
}
