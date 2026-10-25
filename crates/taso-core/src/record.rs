//! Record types: the payloads that ride inside an [`Envelope`].
//!
//! A Chronicle record is an [`Envelope`] (position in the hash chain)
//! plus a [`Payload`].  Taso parses envelopes on every record; it parses
//! payloads only for its own types — [`SealRecord`], [`GroupRecord`],
//! [`IntentRecord`], [`OutcomeRecord`], [`LineageRecord`],
//! [`SuccessionRecord`] — and treats everything else as opaque bytes
//! ([`Payload::Raw`]).
//!
//! # Birth, lineage and succession
//!
//! Every Vessel's Chronicle opens with a [`LineageRecord`] at lsn 1 on
//! `Ctl`.  The default birth is from the void ([`Origin::Void`]): an empty
//! dataset, no parent.  [`Origin::Fork`] starts from a parent's Seal.
//! [`Origin::Succession`] is the deliberate, operator-authorised move of a
//! Vessel's state to another identity; the old Chronicle then ends with a
//! [`SuccessionRecord`] naming its successor, so the coupling is visible
//! from both sides.
//!
//! A Vessel's id is derived, not assigned: [`vessel_id`]`(namespace,
//! subject)`.  `subject` is the platform's stable key for the owner (an
//! opaque user id), never a display name, so renaming a user changes
//! nothing here.
//!
//! Normative references: v0.4 §§3–7 (Lineage: §3, §4).

use crate::canon::{Canon, Canonical};
use crate::contract::ContractRecord;
use crate::envelope::{
    payload_hash, BranchId, ChronicleHead, ChronicleId, Envelope, Epoch, HashVal, Lsn, Stream,
};

// ── Identity newtypes ───────────────────────────────────────────────

/// A group's identity within a Chronicle.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct GroupId(u64);

impl GroupId {
    /// Wrap a raw value.
    pub const fn new(v: u64) -> Self {
        Self(v)
    }
    /// The raw value.
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl Canonical for GroupId {
    fn canon(&self, out: &mut Canon) {
        out.u64(self.0);
    }
}

/// A stable logical identity for an effect operation.
///
/// Survives rebirth: if the same logical operation is retried after a
/// crash, it keeps the same `OpId` (v0.4 §7).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct OpId(u64);

impl OpId {
    /// Wrap a raw value.
    pub const fn new(v: u64) -> Self {
        Self(v)
    }
    /// The raw value.
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl Canonical for OpId {
    fn canon(&self, out: &mut Canon) {
        out.u64(self.0);
    }
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
    pub const fn new(v: u64) -> Self {
        Self(v)
    }
    /// The raw value.
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl Canonical for BarrierId {
    fn canon(&self, out: &mut Canon) {
        out.u64(self.0);
    }
}

/// A turn boundary identifier.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct TurnId(u64);

impl TurnId {
    /// Wrap a raw value.
    pub const fn new(v: u64) -> Self {
        Self(v)
    }
    /// The raw value.
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl Canonical for TurnId {
    fn canon(&self, out: &mut Canon) {
        out.u64(self.0);
    }
}

/// A reference to a copy-on-write layer.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct LayerRef(u64);

impl LayerRef {
    /// Wrap a raw value.
    pub const fn new(v: u64) -> Self {
        Self(v)
    }
    /// The raw value.
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl Canonical for LayerRef {
    fn canon(&self, out: &mut Canon) {
        out.u64(self.0);
    }
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
            Self::Clean => {
                out.tag(0);
            }
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
            Self::Irreversible => {
                out.tag(0);
            }
            Self::Compensatable { by } => {
                out.tag(1);
                by.canon(out);
            }
            Self::NoExternalMutation => {
                out.tag(2);
            }
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
    /// Held: the intent is a proposal from a Vessel that may not release
    /// effects (a fork, P3).  Terminal in that Chronicle.  Nothing reads
    /// it as open, and no sender may act on it; it is released only by
    /// the parent re-recording it as its own intent under a
    /// [`PromotionRecord`].
    Proposed = 5,
    /// An operator closed the effect without knowing whether it was
    /// applied (P4 spec D34): terminal, recorded only by operator
    /// resolution with an actor and a reason.  Says nothing about what
    /// happened; never re-issued, probed or reported again.
    AcceptedUnknown = 6,
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
    /// The provider whose adapter planned it, and re-issues or probes it
    /// on reconciliation.
    pub provider: String,
    /// The exact request the adapter will send (opaque, adapter-normalised).
    /// Durable with the intent, so a `ProviderDeduplicated` effect can be
    /// re-issued after a crash with the same bytes (v0.4 §7.2).  It may
    /// carry user data and lives in the retention-locked ledger.
    pub request: Vec<u8>,
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
        out.str(&self.provider);
        out.bytes(&self.request);
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

// ── Lineage ─────────────────────────────────────────────────────────

/// An isolation domain: a tenant, an organisation, a deployment.  Opaque
/// to Taso; forks and successions record it so policy can check it.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Namespace([u8; 16]);

impl Namespace {
    /// Wrap raw bytes.
    pub const fn from_bytes(b: [u8; 16]) -> Self {
        Self(b)
    }
    /// The raw bytes.
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl Canonical for Namespace {
    fn canon(&self, out: &mut Canon) {
        out.fixed(&self.0);
    }
}

/// A Seal in another Chronicle: the point a Vessel was born from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParentSeal {
    /// The parent Chronicle.
    pub chronicle: ChronicleId,
    /// The Seal record's lsn there.
    pub seal: Lsn,
    /// The Seal record's hash there.
    pub seal_hash: HashVal,
}

impl Canonical for ParentSeal {
    fn canon(&self, out: &mut Canon) {
        self.chronicle.canon(out);
        self.seal.canon(out);
        self.seal_hash.canon(out);
    }
}

/// Who authorised an operation that only a human or operator may do, and
/// why.  Never a Vessel.  Emptiness is refused at the point of use, not
/// here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Authority {
    /// A named human or operator identity.
    pub actor: String,
    /// Why, in their words.
    pub reason: String,
}

impl Canonical for Authority {
    fn canon(&self, out: &mut Canon) {
        out.str(&self.actor);
        out.str(&self.reason);
    }
}

/// How a Vessel came to be.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Origin {
    /// Born from the void: empty state, no parent (tag 0).
    Void,
    /// Forked from a parent's Seal (tag 1).
    Fork {
        /// The Seal it was forked from.
        parent: ParentSeal,
    },
    /// Took over another Vessel's state by operator decision (tag 2).
    /// The parent Chronicle ends with a matching [`SuccessionRecord`].
    Succession {
        /// The predecessor's last Seal.
        parent: ParentSeal,
        /// Who authorised it, and why.
        authority: Authority,
    },
    /// Born from a Template (tag 3; P4 spec rev. 16 §5.6, D54): a clone of
    /// the Template's layer on this storage kind.  It inherits files,
    /// never effects (`ledger_pos` is 0), and never goes back into the
    /// Template.
    Template {
        /// The Template.
        template_id: ChronicleId,
        /// The layer object it was cloned from (`taso.layer.v1`), which is
        /// also the layer Seal's binding hash on every node (D52).
        layer_key: HashVal,
        /// The `name@version` its config named, if it named one: a label,
        /// checked by the coordinator at birth (D50).
        asked: Option<TemplateAsked>,
    },
}

/// The `name@version` a Template-born Vessel was asked by (P4 spec
/// rev. 16 §5.5, D50).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TemplateAsked {
    /// The Template name.
    pub name: String,
    /// Its version, from 1.
    pub version: u32,
}

impl Canonical for TemplateAsked {
    fn canon(&self, out: &mut Canon) {
        out.str(&self.name).u32(self.version);
    }
}

impl Origin {
    /// The parent Seal, for a fork or a succession.  A Template is not a
    /// parent Seal: its layer is not a Seal record of any Chronicle
    /// ([`Origin::Template`]).
    pub fn parent(&self) -> Option<&ParentSeal> {
        match self {
            Self::Void | Self::Template { .. } => None,
            Self::Fork { parent } | Self::Succession { parent, .. } => Some(parent),
        }
    }
}

impl Canonical for Origin {
    fn canon(&self, out: &mut Canon) {
        match self {
            Self::Void => {
                out.tag(0);
            }
            Self::Fork { parent } => {
                out.tag(1);
                parent.canon(out);
            }
            Self::Succession { parent, authority } => {
                out.tag(2);
                parent.canon(out);
                authority.canon(out);
            }
            Self::Template {
                template_id,
                layer_key,
                asked,
            } => {
                out.tag(3);
                template_id.canon(out);
                layer_key.canon(out);
                out.option(asked.as_ref());
            }
        }
    }
}

/// The first record of every Chronicle (lsn 1, `Ctl`): where the Vessel
/// came from (v0.4 §3, Lineage).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LineageRecord {
    /// How it was born.
    pub origin: Origin,
    /// Its namespace.
    pub namespace: Namespace,
    /// The parent's highest ledger lsn at the parent Seal; `0` for the
    /// void.  Barriers after it in the parent are this Vessel's concern
    /// too (v0.4 §7.4).
    pub ledger_pos: Lsn,
}

impl Canonical for LineageRecord {
    fn canon(&self, out: &mut Canon) {
        self.origin.canon(out);
        self.namespace.canon(out);
        self.ledger_pos.canon(out);
    }
}

/// The last record of a Chronicle whose state moved to another identity.
/// Nothing may follow it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SuccessionRecord {
    /// The successor Chronicle.
    pub successor: ChronicleId,
    /// The successor's namespace.
    pub namespace: Namespace,
    /// The Seal the successor is born from (this Chronicle's last).
    pub seal: Lsn,
    /// That Seal's record hash.
    pub seal_hash: HashVal,
    /// Who authorised it, and why.  Must equal the successor's.
    pub authority: Authority,
}

impl Canonical for SuccessionRecord {
    fn canon(&self, out: &mut Canon) {
        self.successor.canon(out);
        self.namespace.canon(out);
        self.seal.canon(out);
        self.seal_hash.canon(out);
        self.authority.canon(out);
    }
}

// ── Promotion ───────────────────────────────────────────────────────

/// A parent chose one of its forks (P3, M7): "this Vessel adopted the
/// futures of `child` as of its Seal `seal`".  A `Ctl` record in the
/// **parent's** Chronicle; the child's Chronicle is not touched.
///
/// It is a reference, never a merge: the parent keeps its one Lineage
/// and stays a tree node.  The adopted proposals follow it as the
/// parent's own intents (new op ids), each naming the child's op in
/// its `authority`, so every released effect traces back to the
/// proposal it came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PromotionRecord {
    /// The chosen child.
    pub child: ChronicleId,
    /// The child's Seal the choice is made at: proposals at or before it
    /// are adopted, later ones are not (open-at-S).
    pub seal: Lsn,
    /// That Seal record's hash in the child.
    pub seal_hash: HashVal,
    /// The child's highest ledger lsn at that Seal.
    pub ledger_pos: Lsn,
}

impl Canonical for PromotionRecord {
    fn canon(&self, out: &mut Canon) {
        self.child.canon(out);
        self.seal.canon(out);
        self.seal_hash.canon(out);
        self.ledger_pos.canon(out);
    }
}

// ── Gap ─────────────────────────────────────────────────────────────

/// Records `(kept, resumes]` were accepted, but are lost: they were never
/// shipped before the node that held them was lost (v1.0 §1 P2).
///
/// Written by the Warden that takes the Chronicle over, at lsn
/// `resumes + 1`, chained to `resumes_hash` like any record, so history is
/// never rewritten: the lost records keep their place and their hashes.
/// `kept` is the last record the new holder has (the shipped anchor);
/// everything after the gap continues from `resumes`.  Nothing ever
/// dispatched an effect from inside a gap: the authorization of every
/// sent effect is shipped and anchored before the send.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GapRecord {
    /// The last record kept.
    pub kept: Lsn,
    /// Its hash.
    pub kept_hash: HashVal,
    /// The last record lost: the anchored head at takeover.
    pub resumes: Lsn,
    /// Its hash; the gap record's `prev`.
    pub resumes_hash: HashVal,
}

impl Canonical for GapRecord {
    fn canon(&self, out: &mut Canon) {
        self.kept.canon(out);
        self.kept_hash.canon(out);
        self.resumes.canon(out);
        self.resumes_hash.canon(out);
    }
}

// ── Checkpoint ──────────────────────────────────────────────────────

/// The last Seal before a Checkpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckpointSeal {
    /// The Seal record's lsn.
    pub lsn: Lsn,
    /// Its hash.
    pub hash: HashVal,
    /// The turn it sealed.
    pub turn: TurnId,
    /// Its `ledger_pos`.
    pub ledger_pos: Lsn,
}

impl Canonical for CheckpointSeal {
    fn canon(&self, out: &mut Canon) {
        self.lsn.canon(out);
        self.hash.canon(out);
        self.turn.canon(out);
        self.ledger_pos.canon(out);
    }
}

/// An effect not settled before a Checkpoint: its intent and the latest
/// outcome recorded for it (`None`: none yet).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenEffect {
    /// The Intent record's lsn.
    pub lsn: Lsn,
    /// The intent.
    pub intent: IntentRecord,
    /// Its latest outcome, never terminal here.
    pub state: Option<OutcomeState>,
}

impl Canonical for OpenEffect {
    fn canon(&self, out: &mut Canon) {
        self.lsn.canon(out);
        self.intent.canon(out);
        out.option(self.state.as_ref());
    }
}

/// What the readers of a Chronicle need from every record before this
/// one, so that a node may remove its oldest local segments
/// (decision 1, 2026-10-16).  It is computed from the records it replaces
/// (by the Warden, from its local log) and is a record like any other:
/// hash-chained and accepted by the coordinator.  The records it
/// summarises stay in the store; only local copies are removed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckpointRecord {
    /// The Chronicle's Lineage record (lsn 1).
    pub lineage: LineageRecord,
    /// The last Transcript record's lsn (0: none).
    pub transcript: Lsn,
    /// The last Effect record's lsn (0: none).
    pub effect: Lsn,
    /// The last accepted Seal, if any.
    pub seal: Option<CheckpointSeal>,
    /// The last FsShipped record, if any.
    pub fs_shipped: Option<FsShippedRecord>,
    /// Every effect whose latest outcome is not terminal, in op order.
    pub open: Vec<OpenEffect>,
    /// The next unused effect op id.
    pub next_op: u64,
    /// A Promotion whose adoption is not finished: the last Promotion
    /// record seen, kept until every proposal it names is recorded as
    /// this Chronicle's own intent (P3).  Carried here so a prune can
    /// never hide a half-done promotion from the reopen that finishes it.
    pub promotion: Option<PromotionRecord>,
}

impl Canonical for CheckpointRecord {
    fn canon(&self, out: &mut Canon) {
        self.lineage.canon(out);
        self.transcript.canon(out);
        self.effect.canon(out);
        out.option(self.seal.as_ref());
        out.option(self.fs_shipped.as_ref());
        out.seq(self.open.iter());
        out.u64(self.next_op);
        out.option(self.promotion.as_ref());
    }
}

// ── FsShipped ───────────────────────────────────────────────────────

/// What a shipped `fs` stream starts from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StreamBase {
    /// Nothing: a full stream (a Vessel born from the void) (tag 0).
    Full,
    /// This Chronicle's previous shipped Seal (tag 1).
    Seal {
        /// Its lsn.
        lsn: Lsn,
        /// Its record hash.
        hash: HashVal,
    },
    /// The parent's Seal snapshot this Vessel is a clone of (tag 2).
    Origin {
        /// The parent Seal.
        parent: ParentSeal,
        /// The ZFS guid of its snapshot.
        guid: u64,
    },
}

impl Canonical for StreamBase {
    fn canon(&self, out: &mut Canon) {
        match self {
            Self::Full => {
                out.tag(0);
            }
            Self::Seal { lsn, hash } => {
                out.tag(1);
                lsn.canon(out);
                hash.canon(out);
            }
            Self::Origin { parent, guid } => {
                out.tag(2);
                parent.canon(out);
                out.u64(*guid);
            }
        }
    }
}

/// The `fs` stream of a Seal was shipped: what it is, and the hash of its
/// plain bytes (v1.0 §1 P2).
///
/// A ZFS send stream lives outside the hash chain, and the guid it carries
/// can be forged.  Recording the stream's digest in the Chronicle binds the
/// dataset to the chain: once this record is under the coordinator's
/// shipped anchor, rebirth rebuilds a dataset from a stream only if it has
/// exactly this length and hash.  Appended by the holder after the Seal's
/// pack is put.  A Phase 1 bridge: in the block log, records carry chunk
/// hashes and the chain covers the data by construction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FsShippedRecord {
    /// The Seal the stream brings the dataset to.
    pub seal: Lsn,
    /// That Seal record's hash.
    pub seal_hash: HashVal,
    /// What it is incremental from.
    pub base: StreamBase,
    /// The ZFS guid of the Seal's snapshot.
    pub guid: u64,
    /// The stream's length.
    pub bytes: u64,
    /// BLAKE3 (derive-key `taso.fs.stream.v1`) of the stream's plain bytes.
    pub digest: HashVal,
}

impl Canonical for FsShippedRecord {
    fn canon(&self, out: &mut Canon) {
        self.seal.canon(out);
        self.seal_hash.canon(out);
        self.base.canon(out);
        out.u64(self.guid);
        out.u64(self.bytes);
        self.digest.canon(out);
    }
}

/// Derive-key domain of [`FsShippedRecord::digest`].
pub const FS_STREAM_DOMAIN: &str = "taso.fs.stream.v1";

/// Domain string for deriving a Vessel's id.
const VESSEL_ID_DOMAIN: &str = "taso.vessel.id.v1";

/// The Chronicle id of the Vessel owned by `subject` in `namespace`.
///
/// Deterministic, so the same owner always finds the same Vessel; the
/// namespace is part of the input, so two namespaces never share an id.
/// `subject` must be the platform's stable key for the owner (an opaque
/// user id), never a display name.
pub fn vessel_id(namespace: Namespace, subject: &[u8]) -> ChronicleId {
    let mut c = Canon::new();
    namespace.canon(&mut c);
    c.bytes(subject);
    let h = blake3::derive_key(VESSEL_ID_DOMAIN, c.as_bytes());
    let mut id = [0u8; 16];
    id.copy_from_slice(&h[..16]);
    ChronicleId::from_bytes(id)
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
    /// A Lineage record: the first record of every Chronicle (tag 5).
    Lineage(LineageRecord),
    /// A Succession record: the last record of a Chronicle (tag 6).
    Succession(SuccessionRecord),
    /// A Gap record: lost records before it (tag 7).
    Gap(GapRecord),
    /// An FsShipped record: a Seal's `fs` stream is shipped (tag 8).
    FsShipped(FsShippedRecord),
    /// A Checkpoint record: what readers need from the records before it,
    /// so older local segments can be removed (tag 9).
    Checkpoint(Box<CheckpointRecord>),
    /// A Promotion record: the parent chose a fork at its Seal (tag 10).
    Promotion(PromotionRecord),
    /// A P4 contract record (tag 11): a Candidate, a verification, a
    /// verdict, a sanction, a Template, a purge or a genesis step
    /// ([`crate::contract`]).  Encoded as the tag, then the record's own
    /// canonical bytes; the record is always the payload's last field.
    Contract(Box<ContractRecord>),
}

impl Canonical for Payload {
    fn canon(&self, out: &mut Canon) {
        match self {
            Self::Seal(r) => {
                out.tag(0);
                r.canon(out);
            }
            Self::Group(r) => {
                out.tag(1);
                r.canon(out);
            }
            Self::Intent(r) => {
                out.tag(2);
                r.canon(out);
            }
            Self::Outcome(r) => {
                out.tag(3);
                r.canon(out);
            }
            Self::Raw(b) => {
                out.tag(4);
                out.bytes(b);
            }
            Self::Lineage(r) => {
                out.tag(5);
                r.canon(out);
            }
            Self::Succession(r) => {
                out.tag(6);
                r.canon(out);
            }
            Self::Gap(r) => {
                out.tag(7);
                r.canon(out);
            }
            Self::FsShipped(r) => {
                out.tag(8);
                r.canon(out);
            }
            Self::Checkpoint(r) => {
                out.tag(9);
                r.canon(out);
            }
            Self::Promotion(r) => {
                out.tag(10);
                r.canon(out);
            }
            Self::Contract(r) => {
                out.tag(11);
                r.canon(out);
            }
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
        let envelope = Envelope::new(chronicle, branch, epoch, stream, lsn, prev, ph);
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
                Member {
                    stream: Stream::Fs,
                    lsn: Lsn::new(4),
                },
                Member {
                    stream: Stream::Db,
                    lsn: Lsn::new(3),
                },
            ],
            depends_on: vec![],
            commit: true,
        })
    }

    fn intent_payload() -> Payload {
        Payload::Intent(IntentRecord {
            op: OpId::new(1),
            request: Vec::new(),
            provider: String::new(),
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
        let enc: Vec<Vec<u8>> = payloads.iter().map(|p| p.canon_bytes()).collect();
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
    fn outcome_states_distinct() {
        let states = [
            OutcomeState::Prepared,
            OutcomeState::DispatchAuthorized,
            OutcomeState::OutcomeUnknown,
            OutcomeState::ConfirmedApplied,
            OutcomeState::ConfirmedNotApplied,
            OutcomeState::Proposed,
            OutcomeState::AcceptedUnknown,
        ];
        let enc: Vec<Vec<u8>> = states.iter().map(|s| s.canon_bytes()).collect();
        assert_eq!(OutcomeState::AcceptedUnknown.canon_bytes(), vec![6]);
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

    /// Record hashes under payload domain v2 (v1 had no `provider` or
    /// `request` in `IntentRecord`).  A change here is a format change:
    /// bump the domain.
    #[test]
    fn existing_record_hashes_are_pinned() {
        let pins = [
            "09bda33c6470f8a91d4fe4517473c16b443e294f3dbcded1f8209f799ee6e6f3",
            "48cc01a42756f90bf98eacbdca8a9bfcdee76948ae835a1693f40010f49ff52a",
            "5a5028714f892e8233b9114a5d539b3037a4c81a9c044f958a453adaa46f8f2c",
            "ac080516e89c43165f8ac222bc801ef16cac440f376eb498fb40c4ef5a1e9a4f",
            "bddb5d242e86cf985daac1bc2525b6a951c3a7a116cf35d24adb7cca17ac2dba",
        ];
        let payloads = [
            seal_payload(),
            group_payload(),
            intent_payload(),
            outcome_payload(),
            raw_payload(),
        ];
        let got: Vec<String> = payloads
            .into_iter()
            .map(|p| make_record(p).envelope.hash.to_string())
            .collect();
        assert_eq!(got, pins);
    }

    /// The two record kinds added after v2 are additive: the existing pins
    /// above are unchanged, and these pin the new encodings.
    #[test]
    fn gap_and_fs_shipped_hashes_are_pinned() {
        let gap = Payload::Gap(GapRecord {
            kept: Lsn::new(5),
            kept_hash: HashVal::from_bytes([5; 32]),
            resumes: Lsn::new(9),
            resumes_hash: HashVal::from_bytes([9; 32]),
        });
        let fs = |base| {
            Payload::FsShipped(FsShippedRecord {
                seal: Lsn::new(12),
                seal_hash: HashVal::from_bytes([12; 32]),
                base,
                guid: 0xDEAD_BEEF,
                bytes: 4096,
                digest: HashVal::from_bytes([0xD1; 32]),
            })
        };
        let payloads = [
            gap,
            fs(StreamBase::Full),
            fs(StreamBase::Seal {
                lsn: Lsn::new(7),
                hash: HashVal::from_bytes([7; 32]),
            }),
            fs(StreamBase::Origin {
                parent: ParentSeal {
                    chronicle: ChronicleId::from_bytes([3; 16]),
                    seal: Lsn::new(40),
                    seal_hash: HashVal::from_bytes([40; 32]),
                },
                guid: 77,
            }),
        ];
        let got: Vec<String> = payloads
            .into_iter()
            .map(|p| make_record(p).envelope.hash.to_string())
            .collect();
        assert_eq!(got, PINS_NEW);
    }

    /// The Checkpoint payload (tag 9) is pinned too: a change to its
    /// encoding changes every hash after the first checkpoint.  Pinned
    /// twice: without a pending promotion, and with one (P3, 2026-10-22:
    /// the `promotion` field was added; a Checkpoint written before it
    /// no longer decodes, which is a format change made before any
    /// production log existed).
    #[test]
    fn checkpoint_hash_is_pinned() {
        let lineage = LineageRecord {
            origin: Origin::Void,
            namespace: Namespace::from_bytes([1; 16]),
            ledger_pos: Lsn::new(0),
        };
        let intent = IntentRecord {
            op: OpId::new(4),
            provider: "mail".into(),
            request: b"to: a".to_vec(),
            footprint: b"mailbox".to_vec(),
            dispatch: Dispatch::Immediate,
            retry: RetryPolicy::UnsafeToRetry,
            consequence: Consequence::Irreversible,
            authority: b"jarmo".to_vec(),
            barrier: Some(BarrierId::new(30)),
        };
        let cp = Payload::Checkpoint(Box::new(CheckpointRecord {
            lineage,
            transcript: Lsn::new(41),
            effect: Lsn::new(31),
            seal: Some(CheckpointSeal {
                lsn: Lsn::new(40),
                hash: HashVal::from_bytes([40; 32]),
                turn: TurnId::new(9),
                ledger_pos: Lsn::new(31),
            }),
            fs_shipped: None,
            open: vec![OpenEffect {
                lsn: Lsn::new(30),
                intent,
                state: Some(OutcomeState::OutcomeUnknown),
            }],
            next_op: 5,
            promotion: None,
        }));
        assert_eq!(
            make_record(cp.clone()).envelope.hash.to_string(),
            PIN_CHECKPOINT[0]
        );
        let Payload::Checkpoint(mut pending) = cp else {
            unreachable!()
        };
        pending.promotion = Some(promotion());
        assert_eq!(
            make_record(Payload::Checkpoint(pending))
                .envelope
                .hash
                .to_string(),
            PIN_CHECKPOINT[1]
        );
    }

    const PIN_CHECKPOINT: [&str; 2] = [
        "cfd3905def40d7511b24598dcd2ee981b1526b698c145e0a169d5ffe9eaaa622",
        "2f79df47f43767c538211083219317fca57e0d7956f09fad1060c9b60caa3171",
    ];

    // ── Promotion (P3) ──────────────────────────────────────────────

    fn promotion() -> PromotionRecord {
        PromotionRecord {
            child: ChronicleId::from_bytes([4; 16]),
            seal: Lsn::new(21),
            seal_hash: HashVal::from_bytes([21; 32]),
            ledger_pos: Lsn::new(17),
        }
    }

    #[test]
    fn promotion_record_verifies() {
        assert!(make_record(Payload::Promotion(promotion())).verify());
    }

    /// The Promotion payload (tag 10) and the `Proposed` outcome state
    /// (tag 5) are additive: every pin above is unchanged, and these pin
    /// the two new encodings.
    #[test]
    fn promotion_and_proposed_hashes_are_pinned() {
        let proposed = Payload::Outcome(OutcomeRecord {
            op: OpId::new(3),
            state: OutcomeState::Proposed,
            evidence: None,
        });
        let got: Vec<String> = [Payload::Promotion(promotion()), proposed]
            .into_iter()
            .map(|p| make_record(p).envelope.hash.to_string())
            .collect();
        assert_eq!(got, PINS_P3);
    }

    const PINS_P3: [&str; 2] = [
        "79960c4a62fd764981fbe060c16e6436bdb7027cfe27b8ef2c8b58d1854604bb",
        "f097668914148f83780cb092ba1631c01a19d3009af9be4ec3e8e85698000558",
    ];

    /// Each Promotion field changes the hash: a promotion of another
    /// child, at another Seal, with another hash or ledger position is a
    /// different record.
    #[test]
    fn every_promotion_field_is_bound_by_the_hash() {
        let base = make_record(Payload::Promotion(promotion())).envelope.hash;
        let variants = [
            PromotionRecord {
                child: ChronicleId::from_bytes([5; 16]),
                ..promotion()
            },
            PromotionRecord {
                seal: Lsn::new(22),
                ..promotion()
            },
            PromotionRecord {
                seal_hash: HashVal::from_bytes([22; 32]),
                ..promotion()
            },
            PromotionRecord {
                ledger_pos: Lsn::new(18),
                ..promotion()
            },
        ];
        for (i, v) in variants.into_iter().enumerate() {
            let h = make_record(Payload::Promotion(v)).envelope.hash;
            assert_ne!(h, base, "field {i} is not bound");
        }
    }

    /// A Promotion is never mistaken for a Succession or a Lineage whose
    /// parent names the same Seal: different tags, different bytes.
    #[test]
    fn promotion_is_distinct_from_the_other_cross_chronicle_records() {
        let p = promotion();
        let seal = ParentSeal {
            chronicle: p.child,
            seal: p.seal,
            seal_hash: p.seal_hash,
        };
        let others = [
            Payload::Lineage(LineageRecord {
                origin: Origin::Fork { parent: seal },
                namespace: ns(1),
                ledger_pos: p.ledger_pos,
            }),
            Payload::Succession(SuccessionRecord {
                successor: p.child,
                namespace: ns(1),
                seal: p.seal,
                seal_hash: p.seal_hash,
                authority: authority(),
            }),
        ];
        let mine = Payload::Promotion(p).canon_bytes();
        for o in others {
            assert_ne!(mine, o.canon_bytes());
        }
    }

    const PINS_NEW: [&str; 4] = [
        "7c4f392fd70a68dcfbb1b8296cbb5da3391d1763687717f48d66dbdb19132b8a",
        "2ad30a34d7be8a1e1f31f13a6674cf947d7f818e06eb125c9972477b39aeeda8",
        "ca5a2767568910af62db1d19131cb3f9d913cd6f5337c3c86b8d6e15e6cb6251",
        "b6edec20cef88108e0f09da199de7dc716c1d24832d3009e27633c54dd306f07",
    ];

    // ── Lineage and succession ──────────────────────────────────────

    fn ns(b: u8) -> Namespace {
        Namespace::from_bytes([b; 16])
    }

    fn parent() -> ParentSeal {
        ParentSeal {
            chronicle: ChronicleId::from_bytes([7; 16]),
            seal: Lsn::new(9),
            seal_hash: HashVal::from_bytes([9; 32]),
        }
    }

    fn authority() -> Authority {
        Authority {
            actor: "jarmo".into(),
            reason: "account merge".into(),
        }
    }

    fn lineage(origin: Origin, namespace: Namespace) -> Payload {
        Payload::Lineage(LineageRecord {
            origin,
            namespace,
            ledger_pos: Lsn::new(0),
        })
    }

    fn succession_payload() -> Payload {
        Payload::Succession(SuccessionRecord {
            successor: ChronicleId::from_bytes([8; 16]),
            namespace: ns(1),
            seal: Lsn::new(9),
            seal_hash: HashVal::from_bytes([9; 32]),
            authority: authority(),
        })
    }

    #[test]
    fn lineage_and_succession_records_verify() {
        for p in [
            lineage(Origin::Void, ns(1)),
            lineage(Origin::Fork { parent: parent() }, ns(1)),
            lineage(
                Origin::Succession {
                    parent: parent(),
                    authority: authority(),
                },
                ns(1),
            ),
            succession_payload(),
        ] {
            assert!(make_record(p).verify());
        }
    }

    #[test]
    fn all_payload_kinds_and_origins_encode_distinctly() {
        let payloads = [
            seal_payload(),
            group_payload(),
            intent_payload(),
            outcome_payload(),
            raw_payload(),
            lineage(Origin::Void, ns(1)),
            lineage(Origin::Fork { parent: parent() }, ns(1)),
            lineage(
                Origin::Succession {
                    parent: parent(),
                    authority: authority(),
                },
                ns(1),
            ),
            succession_payload(),
            Payload::Promotion(promotion()),
        ];
        let enc: Vec<Vec<u8>> = payloads.iter().map(|p| p.canon_bytes()).collect();
        for i in 0..enc.len() {
            for j in (i + 1)..enc.len() {
                assert_ne!(enc[i], enc[j], "payloads {i} and {j} collide");
            }
        }
    }

    #[test]
    fn every_lineage_field_is_bound_by_the_hash() {
        let base = LineageRecord {
            origin: Origin::Succession {
                parent: parent(),
                authority: authority(),
            },
            namespace: ns(1),
            ledger_pos: Lsn::new(4),
        };
        let h = |r: &LineageRecord| make_record(Payload::Lineage(r.clone())).envelope.hash;
        let h0 = h(&base);
        let mut changed = Vec::new();
        let mut r = base.clone();
        r.namespace = ns(2);
        changed.push(r);
        let mut r = base.clone();
        r.ledger_pos = Lsn::new(5);
        changed.push(r);
        for f in 0..5 {
            let mut p = parent();
            let mut a = authority();
            match f {
                0 => p.chronicle = ChronicleId::from_bytes([6; 16]),
                1 => p.seal = Lsn::new(10),
                2 => p.seal_hash = HashVal::from_bytes([1; 32]),
                3 => a.actor = "someone-else".into(),
                _ => a.reason = "another reason".into(),
            }
            let mut r = base.clone();
            r.origin = Origin::Succession {
                parent: p,
                authority: a,
            };
            changed.push(r);
        }
        for r in &changed {
            assert_ne!(h(r), h0, "{r:?} hashes like the original");
        }
    }

    #[test]
    fn authority_strings_are_length_prefixed() {
        // ("ab", "c") and ("a", "bc") must not collide.
        let a = Authority {
            actor: "ab".into(),
            reason: "c".into(),
        };
        let b = Authority {
            actor: "a".into(),
            reason: "bc".into(),
        };
        assert_ne!(a.canon_bytes(), b.canon_bytes());
    }

    #[test]
    fn origin_parent() {
        assert_eq!(Origin::Void.parent(), None);
        assert_eq!(Origin::Fork { parent: parent() }.parent(), Some(&parent()));
        let s = Origin::Succession {
            parent: parent(),
            authority: authority(),
        };
        assert_eq!(s.parent(), Some(&parent()));
    }

    #[test]
    fn vessel_id_is_deterministic_and_namespaced() {
        let a = vessel_id(ns(1), b"user-0001");
        assert_eq!(a, vessel_id(ns(1), b"user-0001"));
        assert_ne!(
            a,
            vessel_id(ns(2), b"user-0001"),
            "namespaces must not share ids"
        );
        assert_ne!(a, vessel_id(ns(1), b"user-0002"));
        // Subject bytes are length-prefixed: no boundary ambiguity with the
        // namespace.
        assert_ne!(vessel_id(ns(1), b""), vessel_id(ns(1), &[0]));
        // Pinned, so the derivation cannot drift.
        assert_eq!(
            a.as_bytes(),
            &[250, 160, 64, 131, 137, 178, 98, 44, 52, 130, 138, 243, 169, 140, 233, 171],
            "vessel_id derivation changed",
        );
    }

    // ── P4 contract payloads (tag 11) ───────────────────────────────

    fn contract_payloads() -> Vec<Payload> {
        use crate::contract::{ContractRecord, ReclaimOutcome};
        vec![
            Payload::Contract(Box::new(ContractRecord::ReclaimClaimed {
                object_key: HashVal::from_bytes([0xE0; 32]),
            })),
            Payload::Contract(Box::new(ContractRecord::ReclaimComplete {
                object_key: HashVal::from_bytes([0xE0; 32]),
                outcome: ReclaimOutcome::Absent,
            })),
            Payload::Contract(Box::new(ContractRecord::SanctionCompleted {
                template_id: ChronicleId::from_bytes([0x7E; 16]),
            })),
        ]
    }

    #[test]
    fn contract_payloads_round_trip_strictly() {
        for p in contract_payloads() {
            let b = p.canon_bytes();
            assert_eq!(b[0], 11, "tag 11");
            assert_eq!(Payload::decode(&b).unwrap(), p);
            let mut trailing = b.clone();
            trailing.push(0);
            assert!(Payload::decode(&trailing).is_err(), "trailing bytes");
            assert!(Payload::decode(&b[..b.len() - 1]).is_err(), "truncated");
            assert!(make_record(p).verify());
        }
        assert!(Payload::decode(&[11]).is_err(), "an empty contract record");
        assert!(Payload::decode(&[12]).is_err(), "tag 12 is not a payload");
    }

    /// Additive: every earlier pin is unchanged (the other pin tests), and
    /// these pin contract payloads inside a Chronicle record.
    #[test]
    fn contract_payload_hashes_are_pinned() {
        let got: Vec<String> = contract_payloads()
            .into_iter()
            .map(|p| make_record(p).envelope.hash.to_string())
            .collect();
        assert_eq!(got, PINS_CONTRACT);
    }

    const PINS_CONTRACT: [&str; 3] = [
        "aa28dd78f22460398ad7e73dedf7ae6bf08ef3a98759b4fe6c96598e77a35d2a",
        "761c04378b93bcdc86bff19701bd204e44b6e07d7d89d930cbf3575d0bfdfdab",
        "e54dff3e751d20933a39c1b90dab35432577a23e2620b6f7d9485e5fb493f9dd",
    ];

    /// A Template-born Vessel's Lineage (origin tag 3; P4 spec rev. 16
    /// D54), asked by name and by id.  Additive: every earlier pin is
    /// unchanged.
    fn template_lineages() -> Vec<Payload> {
        [
            Some(TemplateAsked {
                name: "acme-base".into(),
                version: 3,
            }),
            None,
        ]
        .into_iter()
        .map(|asked| {
            Payload::Lineage(LineageRecord {
                origin: Origin::Template {
                    template_id: ChronicleId::from_bytes([0x7E; 16]),
                    layer_key: HashVal::from_bytes([0x1A; 32]),
                    asked,
                },
                namespace: Namespace::from_bytes([1; 16]),
                ledger_pos: Lsn::new(0),
            })
        })
        .collect()
    }

    #[test]
    fn template_origin_round_trips_and_is_pinned() {
        let got: Vec<String> = template_lineages()
            .into_iter()
            .map(|p| {
                assert_eq!(Payload::decode(&p.canon_bytes()).unwrap(), p);
                make_record(p).envelope.hash.to_string()
            })
            .collect();
        assert_eq!(got, PINS_TEMPLATE_ORIGIN);
        // No parent Seal: a Template is not a Seal record.
        for p in template_lineages() {
            let Payload::Lineage(l) = p else {
                unreachable!()
            };
            assert!(l.origin.parent().is_none());
        }
        // An origin tag past 3 is refused.
        let mut b = template_lineages()[1].canon_bytes();
        let at = 1; // payload tag, then the origin tag
        b[at] = 4;
        assert!(Payload::decode(&b).is_err());
    }

    const PINS_TEMPLATE_ORIGIN: [&str; 2] = [
        "03ceba5ce527f5c08f4e0c2e8a4188257cd4ea550872195df465fa75f4067480",
        "4cc600f1261d931488275ce49dc96e11cfef5400cc94195b199ffe7339bfc97b",
    ];
}
