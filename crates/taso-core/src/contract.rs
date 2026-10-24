//! P4 contract records: Candidates, verification, sanction, Templates,
//! purge, genesis and reclamation, with every identity and hash they
//! carry.
//!
//! Normative reference: `Taso_spec_p4_contracts` rev. 9 (file 0), frozen
//! 2026-10-24, BLAKE3
//! `9c3a984fc45d213b024a4b93a1cb519c4f176c0a3366db7a3f81484029892dc5`.
//! Section numbers below (§) are rev. 9's.
//!
//! This module is pure data: the records, their canonical encoding (the
//! same rules as [`crate::canon`]), their strict decoding, and the
//! derivations of §9.  Who may submit a record, its predicate and its
//! effects (§1.2) are the coordinator's, in a later file; nothing here
//! decides anything.
//!
//! # What is fixed here
//!
//! - [`ContractRecord`]: one enum, one tag per record kind of the §1.2
//!   table.  A record never carries an epoch: the epoch is an argument of
//!   `announce`/`accept`, so a retry across a fence keeps its digest (§9).
//! - [`LogicalKey`]: one variant per **row** of the §1.2 table; the
//!   logical id is the hash of that key.  Records sharing a row share a
//!   logical id (`VerdictSubmitted`/`Refused`; `PurgeComplete`/
//!   `PurgeDamaged`; `TemplateReady` from sanction or genesis), so at
//!   most one of them can ever be accepted for it.
//! - The ids of §9, each under its own derive-key domain.
//! - The two purge objects of §6.2: [`Inventory`] and [`LocalState`].
//!
//! Not here (later files): the manifest and classification map (file 3),
//! the `Payload` tag that carries a [`ContractRecord`] in a Chronicle
//! (file 1b).
//!
//! # Hashing
//!
//! Every hash is BLAKE3 in derive-key mode with a versioned domain string,
//! as in [`crate::envelope`]: §9's `"domain" ‖ fields` is
//! `blake3::derive_key("domain", canon(fields))`.  Ids that name a
//! Chronicle ([`template_id`], [`genesis_id`]) are its first 16 bytes, as
//! [`crate::record::vessel_id`] is.

use std::collections::BTreeSet;
use std::fmt;

use crate::canon::{Canon, Canonical};
use crate::decode::DecodeError;
use crate::envelope::{ChronicleId, Epoch, HashVal, Lsn};
use crate::record::{Authority, LayerRef};

// ── Domains ─────────────────────────────────────────────────────────

/// Domain of [`logical_id`].
pub const LOGICAL_DOMAIN: &str = "taso.logical.v1";
/// Domain of [`record_digest`].
pub const RECORD_DOMAIN: &str = "taso.contract.record.v1";
/// Domain of [`submission_id`].
pub const SUBMISSION_DOMAIN: &str = "taso.submission.v1";
/// Domain of [`hold_id`].
pub const HOLD_DOMAIN: &str = "taso.hold.v1";
/// Domain of [`claim_id`].
pub const CLAIM_DOMAIN: &str = "taso.claim.v1";
/// Domain of [`candidate_id`].
pub const CANDIDATE_DOMAIN: &str = "taso.candidate.v1";
/// Domain of [`facts_hash`].
pub const FACTS_DOMAIN: &str = "taso.facts.v1";
/// Domain of [`attempt_id`].
pub const VERIFY_DOMAIN: &str = "taso.verify.v1";
/// Domain of [`output_digest`].
pub const VERIFY_OUTPUT_DOMAIN: &str = "taso.verify.output.v1";
/// Domain of [`result_digest`].
pub const VRESULT_DOMAIN: &str = "taso.vresult.v1";
/// Domain of [`template_id`].
pub const TEMPLATE_DOMAIN: &str = "taso.template.v1";
/// Domain of [`genesis_id`].
pub const GENESIS_DOMAIN: &str = "taso.genesis.v1";
/// Domain of [`request_id`].
pub const REQUEST_DOMAIN: &str = "taso.request.v1";

/// The transformation of §4.1 this code implements.
pub const TRANSFORM_VERSION: u32 = 1;

// ── Objects ─────────────────────────────────────────────────────────

/// The kinds of content-addressed objects in the store (§2.1).  The kind
/// is the key's domain, so two kinds never share a key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ObjectKind {
    /// A Chronicle pack, or a log-only replacement of one.
    Pack,
    /// One full fs section: a Candidate output or a Template layer.
    Artifact,
    /// A manifest (file 3).
    Manifest,
    /// A classification map (file 3).
    Classmap,
    /// A verifier configuration.
    Vconf,
    /// A purge inventory ([`Inventory`]).
    Inventory,
    /// A purge's local-state description ([`LocalState`]).
    Local,
    /// A tombstone pack.
    Tombstone,
}

impl ObjectKind {
    /// The kind's domain string (§2.1).
    pub const fn prefix(self) -> &'static str {
        match self {
            Self::Pack => "taso.pack.v1",
            Self::Artifact => "taso.artifact.v1",
            Self::Manifest => "taso.manifest.v1",
            Self::Classmap => "taso.classmap.v1",
            Self::Vconf => "taso.vconf.v1",
            Self::Inventory => "taso.inventory.v1",
            Self::Local => "taso.local.v1",
            Self::Tombstone => "taso.tombstone.v1",
        }
    }
}

/// An object's key: `blake3(prefix ‖ bytes)` (§2.1, §9).
pub fn object_key(kind: ObjectKind, bytes: &[u8]) -> HashVal {
    HashVal::from_bytes(blake3::derive_key(kind.prefix(), bytes))
}

// ── Small types ─────────────────────────────────────────────────────

/// A path class (§8).  `Structural` is assigned only by the §4.1
/// transform, never by a classification map.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PathClass {
    /// Tag 0.
    Source,
    /// Tag 1.
    Config,
    /// Tag 2.
    Hook,
    /// Tag 3.
    Secret,
    /// Tag 4.
    Scratch,
    /// Tag 5.
    Artifact,
    /// No glob matched, or two equally specific globs disagree (tag 6).
    Unknown,
    /// A kept ancestor directory of a kept entry (tag 7).
    Structural,
}

impl PathClass {
    const ALL: [Self; 8] = [
        Self::Source,
        Self::Config,
        Self::Hook,
        Self::Secret,
        Self::Scratch,
        Self::Artifact,
        Self::Unknown,
        Self::Structural,
    ];
}

impl Canonical for PathClass {
    fn canon(&self, out: &mut Canon) {
        out.tag(*self as u8);
    }
}

/// Per-class entry counts, plus entries no class can describe.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ClassCounts {
    /// `Source` entries.
    pub source: u64,
    /// `Config` entries.
    pub config: u64,
    /// `Hook` entries.
    pub hook: u64,
    /// `Secret` entries.
    pub secret: u64,
    /// `Scratch` entries.
    pub scratch: u64,
    /// `Artifact` entries.
    pub artifact: u64,
    /// `Unknown` entries.
    pub unknown: u64,
    /// `Structural` entries (output manifests only).
    pub structural: u64,
    /// Entries of an unsupported kind (§8, fail closed).
    pub unsupported: u64,
}

impl ClassCounts {
    /// The input-classification part of predicate (5) of
    /// `SanctionCommitted` (§1.2): `Secret = 0`, `Unknown = 0`,
    /// `unsupported = 0`.
    pub const fn passes_hard_rules(&self) -> bool {
        self.secret == 0 && self.unknown == 0 && self.unsupported == 0
    }
}

impl Canonical for ClassCounts {
    fn canon(&self, out: &mut Canon) {
        out.u64(self.source)
            .u64(self.config)
            .u64(self.hook)
            .u64(self.secret)
            .u64(self.scratch)
            .u64(self.artifact)
            .u64(self.unknown)
            .u64(self.structural)
            .u64(self.unsupported);
    }
}

/// A Seal of the record's own Chronicle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SealRef {
    /// The Seal record's lsn.
    pub lsn: Lsn,
    /// Its record hash.
    pub hash: HashVal,
}

impl Canonical for SealRef {
    fn canon(&self, out: &mut Canon) {
        self.lsn.canon(out);
        self.hash.canon(out);
    }
}

/// What a Candidate's verification must use (§3.3), pinned at
/// nomination.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifierRequirement {
    /// The verifier Template.
    pub template: ChronicleId,
    /// The verifier configuration object.
    pub vconf_key: HashVal,
    /// The requirement's version.
    pub version: u32,
}

impl Canonical for VerifierRequirement {
    fn canon(&self, out: &mut Canon) {
        self.template.canon(out);
        self.vconf_key.canon(out);
        out.u32(self.version);
    }
}

/// A Candidate's facts at nomination (§3.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Facts {
    /// Counts of the input manifest.
    pub input: ClassCounts,
    /// Counts of the entries the exclusion dropped.
    pub excluded: ClassCounts,
    /// Open obligations at nomination (informational; §1.5 is
    /// authoritative at commit).
    pub open_obligations: u64,
    /// Effects adopted by promotion into this Vessel.
    pub effects_adopted: u64,
    /// The ledger position the facts were read at.
    pub ledger_lsn: Lsn,
    /// The pinned verifier requirement.
    pub requirement: VerifierRequirement,
}

impl Canonical for Facts {
    fn canon(&self, out: &mut Canon) {
        self.input.canon(out);
        self.excluded.canon(out);
        out.u64(self.open_obligations);
        out.u64(self.effects_adopted);
        self.ledger_lsn.canon(out);
        self.requirement.canon(out);
    }
}

/// Who put a Candidate forward (§3.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NominatedBy {
    /// The agent, over the Field (tag 0).
    Agent,
    /// The Vessel's config (tag 1).
    Config,
    /// An operator's `supersede` of an earlier Candidate (tag 2).
    Supersede {
        /// The superseded Candidate.
        of: HashVal,
    },
}

impl Canonical for NominatedBy {
    fn canon(&self, out: &mut Canon) {
        match self {
            Self::Agent => {
                out.tag(0);
            }
            Self::Config => {
                out.tag(1);
            }
            Self::Supersede { of } => {
                out.tag(2);
                of.canon(out);
            }
        }
    }
}

/// How a verification attempt ended (§3.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The verifier exited (tag 0).  Only `code == 0` passes.
    Exit {
        /// Its exit code.
        code: u32,
    },
    /// Stopped before it finished, or closed by a new owner (tag 1).
    Interrupted,
    /// Exceeded its wall-time limit (tag 2).
    Timeout,
    /// Exceeded its output bound (tag 3).
    OutputLimit,
    /// Never started (tag 4).
    LaunchFailed,
}

impl Outcome {
    /// `Exit { code: 0 }`.
    pub const fn passed(&self) -> bool {
        matches!(self, Self::Exit { code: 0 })
    }
}

impl Canonical for Outcome {
    fn canon(&self, out: &mut Canon) {
        match self {
            Self::Exit { code } => {
                out.tag(0).u32(*code);
            }
            Self::Interrupted => {
                out.tag(1);
            }
            Self::Timeout => {
                out.tag(2);
            }
            Self::OutputLimit => {
                out.tag(3);
            }
            Self::LaunchFailed => {
                out.tag(4);
            }
        }
    }
}

/// A caller's decision (§5.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    /// Make the Candidate's artifact a Template (tag 0).
    Sanction,
    /// A human decides later (tag 1).
    Hold,
    /// It can never be sanctioned (tag 2).
    Never {
        /// Why.
        reason: String,
    },
}

impl Canonical for Decision {
    fn canon(&self, out: &mut Canon) {
        match self {
            Self::Sanction => {
                out.tag(0);
            }
            Self::Hold => {
                out.tag(1);
            }
            Self::Never { reason } => {
                out.tag(2).str(reason);
            }
        }
    }
}

/// The authenticated peer of a socket request (§11.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Peer {
    /// Its uid.
    pub uid: u32,
    /// Its pid.
    pub pid: u32,
}

impl Canonical for Peer {
    fn canon(&self, out: &mut Canon) {
        out.u32(self.uid).u32(self.pid);
    }
}

/// What kind of request a [`request_id`] is for (§3.7), so equal bodies of
/// different operations never share an id.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpKind {
    /// An agent or config nomination (tag 0).
    Nominate,
    /// An operator supersession (tag 1).
    Supersede,
    /// A verdict on the decider socket (tag 2).
    Verdict,
}

impl Canonical for OpKind {
    fn canon(&self, out: &mut Canon) {
        out.tag(*self as u8);
    }
}

/// A verdict as submitted on the decider socket (§5.1).  The first group
/// of fields must equal the Candidate record; the attempt and its result
/// must equal an accepted verification of this Candidate; the rest is
/// recorded as claimed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerdictRequest {
    /// [`request_id`] of this request, with `OpKind::Verdict`.
    pub request_id: HashVal,
    /// The Candidate.
    pub candidate_id: HashVal,
    /// Must equal the Candidate's.
    pub facts_hash: HashVal,
    /// Must equal the Candidate's.
    pub artifact_key: HashVal,
    /// Must equal the Candidate's.
    pub requirement: VerifierRequirement,
    /// Must equal the Candidate's.
    pub exclude: BTreeSet<PathClass>,
    /// An accepted attempt of this Candidate.
    pub attempt_id: HashVal,
    /// That attempt's [`result_digest`].
    pub result_digest: HashVal,
    /// The decision.
    pub decision: Decision,
    /// Claimed.
    pub authority: Authority,
    /// Claimed.
    pub policy_digest: Option<HashVal>,
}

impl VerdictRequest {
    /// The canonical body: every field except `request_id` (§9).
    pub fn body(&self) -> Vec<u8> {
        let mut c = Canon::new();
        self.candidate_id.canon(&mut c);
        self.facts_hash.canon(&mut c);
        self.artifact_key.canon(&mut c);
        self.requirement.canon(&mut c);
        c.set(self.exclude.iter());
        self.attempt_id.canon(&mut c);
        self.result_digest.canon(&mut c);
        self.decision.canon(&mut c);
        self.authority.canon(&mut c);
        c.option(self.policy_digest.as_ref());
        c.into_bytes()
    }

    /// Whether `request_id` is this body's id for `peer`.
    pub fn id_matches(&self, peer: Peer) -> bool {
        self.request_id == request_id(peer.uid, OpKind::Verdict, &self.body())
    }
}

impl Canonical for VerdictRequest {
    fn canon(&self, out: &mut Canon) {
        self.request_id.canon(out);
        out.fixed_bytes(&self.body());
    }
}

/// Why a verdict request was refused (§5.3, §1.2).  A refusal is never a
/// Candidate outcome (§3.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// A bound field differs from the Candidate or its attempt (tag 0).
    StaleFacts,
    /// The Candidate is closed (tag 1).
    Closed,
    /// No such Candidate (tag 2).
    NoSuchCandidate,
    /// The attempt is not this Candidate's, or not under its requirement
    /// (tag 3).
    WrongAttempt,
    /// The Chronicle is retired (tag 4).
    Retired,
    /// An obligation is open (tag 5).
    OpenObligation,
    /// The input classification fails the hard rules (tag 6).
    HardRules,
    /// The named attempt did not exit 0 with the named result (tag 7).
    AttemptNotPassed,
    /// A later attempt finished otherwise (tag 8).
    LaterAttemptFailed,
    /// An attempt is open (tag 9).
    OpenAttempt,
    /// Another lifecycle submission is pending (tag 10).
    Pending,
    /// The same request id with a different body (tag 11).
    Conflict,
}

impl Refusal {
    const ALL: [Self; 12] = [
        Self::StaleFacts,
        Self::Closed,
        Self::NoSuchCandidate,
        Self::WrongAttempt,
        Self::Retired,
        Self::OpenObligation,
        Self::HardRules,
        Self::AttemptNotPassed,
        Self::LaterAttemptFailed,
        Self::OpenAttempt,
        Self::Pending,
        Self::Conflict,
    ];
}

impl Canonical for Refusal {
    fn canon(&self, out: &mut Canon) {
        out.tag(*self as u8);
    }
}

/// How a Candidate was closed without a sanction (§3.5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CloseKind {
    /// A `Never` verdict (tag 0).
    Never {
        /// The verdict's logical id.
        verdict: HashVal,
        /// Its reason.
        reason: String,
    },
    /// An operator cancellation (tag 1).
    Cancelled {
        /// Who, and why.
        authority: Authority,
    },
    /// An operator supersession (tag 2).
    Superseded {
        /// Who, and why.
        authority: Authority,
        /// The Candidate that replaces it.
        by: HashVal,
    },
}

impl Canonical for CloseKind {
    fn canon(&self, out: &mut Canon) {
        match self {
            Self::Never { verdict, reason } => {
                out.tag(0);
                verdict.canon(out);
                out.str(reason);
            }
            Self::Cancelled { authority } => {
                out.tag(1);
                authority.canon(out);
            }
            Self::Superseded { authority, by } => {
                out.tag(2);
                authority.canon(out);
                by.canon(out);
            }
        }
    }
}

/// Where a Template came from (§5.3, D22).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BornFrom {
    /// A sanction (tag 0).
    Sanction {
        /// The Chronicle whose `SanctionCommitted` this is.
        source: ChronicleId,
        /// The Candidate.
        candidate_id: HashVal,
        /// The verdict's logical id.
        verdict: HashVal,
    },
    /// A genesis (tag 1).
    Genesis {
        /// The genesis operation.
        genesis_id: ChronicleId,
    },
}

impl Canonical for BornFrom {
    fn canon(&self, out: &mut Canon) {
        match self {
            Self::Sanction {
                source,
                candidate_id,
                verdict,
            } => {
                out.tag(0);
                source.canon(out);
                candidate_id.canon(out);
                verdict.canon(out);
            }
            Self::Genesis { genesis_id } => {
                out.tag(1);
                genesis_id.canon(out);
            }
        }
    }
}

/// Why a purge was deferred (§6.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeferReason {
    /// An obligation is open (tag 0).
    OpenObligation,
    /// Chronicles that need this one live (tag 1).  Both lists ascending,
    /// no duplicates.
    LivenessDependency {
        /// Known holders.
        holders: Vec<ChronicleId>,
        /// Holders whose records the coordinator could not verify.
        unknown: Vec<ChronicleId>,
    },
    /// A committed sanction is not finished (tag 2).
    OpenSanction {
        /// Its Candidate.
        candidate_id: HashVal,
    },
    /// An operator retention pin (tag 3).
    RetentionPin,
    /// A verification attempt is open (tag 4).
    OpenAttempt,
    /// The store did not answer (tag 5).
    StoreUnavailable,
    /// The coordinator did not answer (tag 6).
    CoordinatorUnavailable,
}

impl Canonical for DeferReason {
    fn canon(&self, out: &mut Canon) {
        match self {
            Self::OpenObligation => {
                out.tag(0);
            }
            Self::LivenessDependency { holders, unknown } => {
                out.tag(1);
                out.seq(holders.iter());
                out.seq(unknown.iter());
            }
            Self::OpenSanction { candidate_id } => {
                out.tag(2);
                candidate_id.canon(out);
            }
            Self::RetentionPin => {
                out.tag(3);
            }
            Self::OpenAttempt => {
                out.tag(4);
            }
            Self::StoreUnavailable => {
                out.tag(5);
            }
            Self::CoordinatorUnavailable => {
                out.tag(6);
            }
        }
    }
}

/// What a purge cuts at (§6.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cutoff {
    /// The last Seal.
    pub seal: SealRef,
    /// The last `FsShipped` record's lsn.
    pub fs_shipped: Lsn,
}

impl Canonical for Cutoff {
    fn canon(&self, out: &mut Canon) {
        self.seal.canon(out);
        self.fs_shipped.canon(out);
    }
}

/// How consistent a genesis source is (§7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Consistency {
    /// An existing snapshot or sealed dataset (tag 0).
    Immutable,
    /// A directory copied under `--best-effort` (tag 1).
    BestEffort,
}

impl Canonical for Consistency {
    fn canon(&self, out: &mut Canon) {
        out.tag(*self as u8);
    }
}

/// Why a walk or materialisation refuses a tree (§4, §7, §8).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WalkRefusal {
    /// A path is classified `Secret` (tag 0).
    SecretPaths,
    /// A `Hook` path without a waiver (tag 1, genesis only).
    HookNotWaived,
    /// A path is `Unknown` (tag 2).
    UnknownPaths,
    /// An entry of an unsupported kind (tag 3).
    Unsupported,
    /// A limit stopped the walk (tag 4).
    IncompleteWalk,
    /// A reserved entry does not match its definition (tag 5).
    ReservedMismatch,
    /// A kept symlink points at a dropped path (tag 6).
    DanglingByExclusion,
    /// The output walk differs from the output manifest (tag 7).
    MaterialisationMismatch,
}

impl WalkRefusal {
    const ALL: [Self; 8] = [
        Self::SecretPaths,
        Self::HookNotWaived,
        Self::UnknownPaths,
        Self::Unsupported,
        Self::IncompleteWalk,
        Self::ReservedMismatch,
        Self::DanglingByExclusion,
        Self::MaterialisationMismatch,
    ];
}

impl Canonical for WalkRefusal {
    fn canon(&self, out: &mut Canon) {
        out.tag(*self as u8);
    }
}

/// How a reclaimed object ended (§2.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReclaimOutcome {
    /// Deleted by the claim holder (tag 0).
    Deleted,
    /// Already absent (tag 1).
    Absent,
}

impl Canonical for ReclaimOutcome {
    fn canon(&self, out: &mut Canon) {
        out.tag(*self as u8);
    }
}

// ── Purge objects (§6.2) ────────────────────────────────────────────

/// What a purge leaves of an inventoried pack.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplacementForm {
    /// The same frames, no fs section (tag 0).
    LogOnly,
    /// No frames: the pack held no log (tag 1).
    Tombstone,
}

impl Canonical for ReplacementForm {
    fn canon(&self, out: &mut Canon) {
        out.tag(*self as u8);
    }
}

/// The frames a pack holds: `first..=last`; for a tombstone, empty and
/// `first == last + 1` by convention of the pack format (file 2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameRange {
    /// The first frame's lsn.
    pub first: Lsn,
    /// The last frame's lsn.
    pub last: Lsn,
}

impl Canonical for FrameRange {
    fn canon(&self, out: &mut Canon) {
        self.first.canon(out);
        self.last.canon(out);
    }
}

/// A Chronicle pack in the store (D25): where it is and what it
/// is.  Packs keep their positional names (`<end>-<base>-<fs to>`, 20
/// digits each); `digest` is the pack's trailer digest (derive-key
/// `taso.pack.v1` over everything before the trailer), its content
/// identity.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PackRef {
    /// The pack's name under the Chronicle's `pack/` prefix.
    pub name: String,
    /// Its trailer digest.
    pub digest: HashVal,
}

impl Canonical for PackRef {
    fn canon(&self, out: &mut Canon) {
        out.str(&self.name);
        self.digest.canon(out);
    }
}

/// One inventoried pack.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InventoryItem {
    /// The original pack.
    pub pack: PackRef,
    /// The fs sections it holds, named by their Seal's lsn, ascending.
    pub sections: Vec<Lsn>,
    /// The digest its replacement's frames must hash to.
    pub log_digest: HashVal,
    /// The frames its replacement must hold.
    pub frames: FrameRange,
    /// What replaces it.
    pub form: ReplacementForm,
}

impl Canonical for InventoryItem {
    fn canon(&self, out: &mut Canon) {
        self.pack.canon(out);
        out.seq(self.sections.iter());
        self.log_digest.canon(out);
        self.frames.canon(out);
        self.form.canon(out);
    }
}

/// A purge inventory: an immutable object, items ascending by pack name
/// with no duplicates.  Its key is the `inventory_digest` (§6.2, §9).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Inventory {
    items: Vec<InventoryItem>,
}

/// Why an [`Inventory`] or a list in a record is not well-formed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OrderError {
    /// Two items share a key, or are out of order.
    NotStrictlyAscending,
}

impl fmt::Display for OrderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("not strictly ascending")
    }
}

impl std::error::Error for OrderError {}

impl Inventory {
    /// Build an inventory: items are sorted by pack name; each item's
    /// sections are sorted.  Duplicate pack names or sections are refused.
    pub fn new(mut items: Vec<InventoryItem>) -> Result<Self, OrderError> {
        items.sort_by(|a, b| a.pack.name.cmp(&b.pack.name));
        for it in &mut items {
            it.sections.sort();
            if !strictly_ascending(&it.sections) {
                return Err(OrderError::NotStrictlyAscending);
            }
        }
        let keys: Vec<&str> = items.iter().map(|i| i.pack.name.as_str()).collect();
        if !strictly_ascending(&keys) {
            return Err(OrderError::NotStrictlyAscending);
        }
        Ok(Self { items })
    }

    /// The items, ascending by pack name.
    pub fn items(&self) -> &[InventoryItem] {
        &self.items
    }

    /// The canonical bytes stored in the object.
    pub fn bytes(&self) -> Vec<u8> {
        self.canon_bytes()
    }

    /// Its object key: the `inventory_digest`.
    pub fn key(&self) -> HashVal {
        object_key(ObjectKind::Inventory, &self.bytes())
    }

    /// Strict decoding of the object's bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let v = r.inventory()?;
        r.finish()?;
        Ok(v)
    }
}

impl Canonical for Inventory {
    fn canon(&self, out: &mut Canon) {
        out.seq(self.items.iter());
    }
}

/// What a purge deletes locally (§6.2): an immutable object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalState {
    /// The dataset's guid (not its reusable name).
    pub dataset_guid: u64,
    /// Its layers, ascending.
    pub layers: Vec<LayerRef>,
}

impl LocalState {
    /// The canonical bytes stored in the object.
    pub fn bytes(&self) -> Vec<u8> {
        self.canon_bytes()
    }

    /// Its object key.
    pub fn key(&self) -> HashVal {
        object_key(ObjectKind::Local, &self.bytes())
    }

    /// Strict decoding of the object's bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let v = r.local_state()?;
        r.finish()?;
        Ok(v)
    }
}

impl Canonical for LocalState {
    fn canon(&self, out: &mut Canon) {
        out.u64(self.dataset_guid);
        out.seq(self.layers.iter());
    }
}

// ── Records ─────────────────────────────────────────────────────────

/// A Candidate (§3.2).  No epoch field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Candidate {
    /// [`candidate_id`] of the fields below.
    pub candidate_id: HashVal,
    /// The Vessel.
    pub chronicle: ChronicleId,
    /// The nominated Seal.
    pub seal: SealRef,
    /// The classes dropped, ⊆ `sanction.allowed_exclude`.
    pub exclude: BTreeSet<PathClass>,
    /// The §4.1 transform.
    pub transform_version: u32,
    /// The classification map.
    pub classmap_key: HashVal,
    /// The walk of the Seal.
    pub input_manifest_key: HashVal,
    /// The transformed manifest.
    pub output_manifest_key: HashVal,
    /// The selected artifact: what is verified and what ships (D9).
    pub artifact_key: HashVal,
    /// The pinned verifier requirement.
    pub requirement: VerifierRequirement,
    /// The facts at nomination.
    pub facts: Facts,
    /// [`facts_hash`] of `facts`.
    pub facts_hash: HashVal,
    /// Who nominated it.
    pub nominated_by: NominatedBy,
    /// The ledger position of the nomination.
    pub nominated_at: Lsn,
}

impl Candidate {
    /// Whether the record's derived fields agree with the rest:
    /// `candidate_id`, `facts_hash`, and the requirement inside the
    /// facts.  A record failing this is never submitted.
    pub fn is_consistent(&self) -> bool {
        self.candidate_id
            == candidate_id(
                self.chronicle,
                self.seal.hash,
                &self.exclude,
                self.classmap_key,
                self.transform_version,
                &self.requirement,
            )
            && self.facts_hash == facts_hash(&self.facts)
            && self.facts.requirement == self.requirement
    }
}

impl Canonical for Candidate {
    fn canon(&self, out: &mut Canon) {
        self.candidate_id.canon(out);
        self.chronicle.canon(out);
        self.seal.canon(out);
        out.set(self.exclude.iter());
        out.u32(self.transform_version);
        self.classmap_key.canon(out);
        self.input_manifest_key.canon(out);
        self.output_manifest_key.canon(out);
        self.artifact_key.canon(out);
        self.requirement.canon(out);
        self.facts.canon(out);
        self.facts_hash.canon(out);
        self.nominated_by.canon(out);
        self.nominated_at.canon(out);
    }
}

/// A verification attempt starts (§3.4).  It names the artifact and the
/// requirement, as predicate (6) of `SanctionCommitted` reads them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerificationStarted {
    /// The Candidate.
    pub candidate_id: HashVal,
    /// [`attempt_id`]`(candidate_id, started_at)`.
    pub attempt_id: HashVal,
    /// The artifact mounted at `/candidate`.
    pub artifact_key: HashVal,
    /// The requirement it runs under.
    pub requirement: VerifierRequirement,
    /// The ledger position of the start.
    pub started_at: Lsn,
}

impl VerificationStarted {
    /// Whether `attempt_id` is derived from the other fields.
    pub fn is_consistent(&self) -> bool {
        self.attempt_id == attempt_id(self.candidate_id, self.started_at)
    }
}

impl Canonical for VerificationStarted {
    fn canon(&self, out: &mut Canon) {
        self.candidate_id.canon(out);
        self.attempt_id.canon(out);
        self.artifact_key.canon(out);
        self.requirement.canon(out);
        self.started_at.canon(out);
    }
}

/// A verification attempt finished (§3.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerificationFinished {
    /// The attempt.
    pub attempt_id: HashVal,
    /// How it ended.
    pub outcome: Outcome,
    /// [`output_digest`] of `output`.
    pub output_digest: HashVal,
    /// Bounded output (≤ `verifier.output_bound`, config).
    pub output: Vec<u8>,
    /// [`result_digest`] of the attempt.
    pub result_digest: HashVal,
    /// The ledger position of the finish.
    pub finished_at: Lsn,
}

impl VerificationFinished {
    /// Whether the digests agree with `output` and with the attempt's
    /// start record.
    pub fn is_consistent_with(&self, started: &VerificationStarted) -> bool {
        self.attempt_id == started.attempt_id
            && self.output_digest == output_digest(&self.output)
            && self.result_digest
                == result_digest(
                    started.candidate_id,
                    started.artifact_key,
                    &started.requirement,
                    self.attempt_id,
                    &self.outcome,
                    self.output_digest,
                )
    }
}

impl Canonical for VerificationFinished {
    fn canon(&self, out: &mut Canon) {
        self.attempt_id.canon(out);
        self.outcome.canon(out);
        self.output_digest.canon(out);
        out.bytes(&self.output);
        self.result_digest.canon(out);
        self.finished_at.canon(out);
    }
}

/// A verdict request was accepted for consideration (§5.3 step 1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerdictSubmitted {
    /// The request as received.
    pub request: VerdictRequest,
    /// Its authenticated peer.
    pub peer: Peer,
}

impl Canonical for VerdictSubmitted {
    fn canon(&self, out: &mut Canon) {
        self.request.canon(out);
        self.peer.canon(out);
    }
}

/// A verdict request was refused (§5.3 step 1).  Shares its logical id
/// with [`VerdictSubmitted`]: one of the two per request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Refused {
    /// The request.
    pub request_id: HashVal,
    /// The Candidate it named.
    pub candidate_id: HashVal,
    /// Its authenticated peer.
    pub peer: Peer,
    /// Why.
    pub rule: Refusal,
}

impl Canonical for Refused {
    fn canon(&self, out: &mut Canon) {
        self.request_id.canon(out);
        self.candidate_id.canon(out);
        self.peer.canon(out);
        self.rule.canon(out);
    }
}

/// A Candidate closed by `Never`, `Cancel` or `Supersede` (§1.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CandidateClosed {
    /// The Candidate.
    pub candidate_id: HashVal,
    /// How.
    pub how: CloseKind,
}

impl Canonical for CandidateClosed {
    fn canon(&self, out: &mut Canon) {
        self.candidate_id.canon(out);
        self.how.canon(out);
    }
}

/// A sanction is committed (§5.3 step 4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SanctionCommitted {
    /// The Candidate.
    pub candidate_id: HashVal,
    /// [`template_id`]`(candidate_id, verdict)`.
    pub template_id: ChronicleId,
    /// The Template the Vessel came from, if any.
    pub parent_template: Option<ChronicleId>,
    /// The Candidate's artifact.
    pub artifact_key: HashVal,
    /// The Candidate's output manifest.
    pub output_manifest_key: HashVal,
    /// The Candidate's classification map.
    pub classmap_key: HashVal,
    /// The requirement's verifier configuration.
    pub vconf_key: HashVal,
    /// The passing attempt.
    pub attempt_id: HashVal,
    /// Its [`result_digest`].
    pub result_digest: HashVal,
    /// The verdict's logical id.
    pub verdict: HashVal,
}

impl SanctionCommitted {
    /// Whether `template_id` is derived from the other fields.
    pub fn is_consistent(&self) -> bool {
        self.template_id == template_id(self.candidate_id, self.verdict)
    }
}

impl Canonical for SanctionCommitted {
    fn canon(&self, out: &mut Canon) {
        self.candidate_id.canon(out);
        self.template_id.canon(out);
        out.option(self.parent_template.as_ref());
        self.artifact_key.canon(out);
        self.output_manifest_key.canon(out);
        self.classmap_key.canon(out);
        self.vconf_key.canon(out);
        self.attempt_id.canon(out);
        self.result_digest.canon(out);
        self.verdict.canon(out);
    }
}

/// A Template is ready: the whole definition in one record (D22).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TemplateReady {
    /// The Template's Chronicle.
    pub template_id: ChronicleId,
    /// The Template it descends from, if any.
    pub parent_template: Option<ChronicleId>,
    /// Sanction or genesis.
    pub born_from: BornFrom,
    /// The layer: the verified artifact, by key.
    pub layer: HashVal,
    /// Its output manifest.
    pub output_manifest_key: HashVal,
    /// Its classification map.
    pub classmap_key: HashVal,
    /// The verifier configuration (none for genesis).
    pub vconf_key: Option<HashVal>,
    /// Who authorised it.
    pub authority: Authority,
}

impl TemplateReady {
    /// Whether `template_id` follows from `born_from`.
    pub fn is_consistent(&self) -> bool {
        match self.born_from {
            BornFrom::Sanction {
                candidate_id,
                verdict,
                ..
            } => self.template_id == template_id(candidate_id, verdict),
            BornFrom::Genesis { genesis_id } => {
                self.template_id == genesis_id && self.vconf_key.is_none()
            }
        }
    }
}

impl Canonical for TemplateReady {
    fn canon(&self, out: &mut Canon) {
        self.template_id.canon(out);
        out.option(self.parent_template.as_ref());
        self.born_from.canon(out);
        self.layer.canon(out);
        self.output_manifest_key.canon(out);
        self.classmap_key.canon(out);
        out.option(self.vconf_key.as_ref());
        self.authority.canon(out);
    }
}

/// A Purge deferred at its TTL (§6.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PurgeDeferred {
    /// The Vessel.
    pub chronicle: ChronicleId,
    /// The position the check read.
    pub checked_at: Lsn,
    /// Why.
    pub reason: DeferReason,
}

impl Canonical for PurgeDeferred {
    fn canon(&self, out: &mut Canon) {
        self.chronicle.canon(out);
        self.checked_at.canon(out);
        self.reason.canon(out);
    }
}

/// A purge is committed: retire, release, close, claim (D20).
/// Constant-size: the inventory and the local state are objects.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PurgeCommitted {
    /// The Vessel.
    pub chronicle: ChronicleId,
    /// Where it cuts.
    pub cutoff: Cutoff,
    /// The [`Inventory`] object.
    pub inventory_key: HashVal,
    /// The [`LocalState`] object.
    pub local_key: HashVal,
}

impl Canonical for PurgeCommitted {
    fn canon(&self, out: &mut Canon) {
        self.chronicle.canon(out);
        self.cutoff.canon(out);
        self.inventory_key.canon(out);
        self.local_key.canon(out);
    }
}

/// A replacement pack is installed for one inventoried pack (§6.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplacementInstalled {
    /// The Vessel.
    pub chronicle: ChronicleId,
    /// The original.
    pub pack: PackRef,
    /// The replacement's content digest (its trailer digest), verified by
    /// the coordinator against the inventory item.
    pub replacement_key: HashVal,
    /// [`replacement_name`] of the original: `<end>-<base>-0`.
    pub replacement_name: String,
}

impl Canonical for ReplacementInstalled {
    fn canon(&self, out: &mut Canon) {
        self.chronicle.canon(out);
        self.pack.canon(out);
        self.replacement_key.canon(out);
        out.str(&self.replacement_name);
    }
}

/// An inventoried pack is lost: no original, no replacement (§6.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ItemLost {
    /// The Vessel.
    pub chronicle: ChronicleId,
    /// The lost original.
    pub pack: PackRef,
}

impl Canonical for ItemLost {
    fn canon(&self, out: &mut Canon) {
        self.chronicle.canon(out);
        self.pack.canon(out);
    }
}

/// A purge ended with its retained history verified (§6.3 step 7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PurgeComplete {
    /// The Vessel.
    pub chronicle: ChronicleId,
    /// The inventory.
    pub inventory_key: HashVal,
    /// Replacements installed.
    pub items_replaced: u64,
    /// The Warden's attestation: the chain's end-to-end digest.
    pub history_attestation: HashVal,
}

impl Canonical for PurgeComplete {
    fn canon(&self, out: &mut Canon) {
        self.chronicle.canon(out);
        self.inventory_key.canon(out);
        out.u64(self.items_replaced);
        self.history_attestation.canon(out);
    }
}

/// A purge ended with history lost (§6.3 step 7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PurgeDamaged {
    /// The Vessel.
    pub chronicle: ChronicleId,
    /// The inventory.
    pub inventory_key: HashVal,
    /// Replacements installed.
    pub items_replaced: u64,
    /// Items lost.
    pub items_lost: u64,
}

impl Canonical for PurgeDamaged {
    fn canon(&self, out: &mut Canon) {
        self.chronicle.canon(out);
        self.inventory_key.canon(out);
        out.u64(self.items_replaced);
        out.u64(self.items_lost);
    }
}

/// A genesis operation starts (§7).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenesisStarted {
    /// [`genesis_id`] of the fields below; also the Template's id.
    pub genesis_id: ChronicleId,
    /// The source pack's object key.
    pub source_key: HashVal,
    /// How consistent the source is.
    pub consistency: Consistency,
    /// The classification map.
    pub classmap_key: HashVal,
    /// The §4.1 transform.
    pub transform_version: u32,
    /// A `Hook` waiver's reason, if any.
    pub hook_waiver: Option<String>,
    /// Who, and why.
    pub authority: Authority,
    /// The authenticated peer.
    pub peer: Peer,
}

impl GenesisStarted {
    /// Whether `genesis_id` is derived from the other fields.
    pub fn is_consistent(&self) -> bool {
        self.genesis_id
            == genesis_id(
                self.source_key,
                self.classmap_key,
                self.transform_version,
                self.hook_waiver.as_deref(),
                &self.authority.actor,
            )
    }
}

impl Canonical for GenesisStarted {
    fn canon(&self, out: &mut Canon) {
        self.genesis_id.canon(out);
        self.source_key.canon(out);
        self.consistency.canon(out);
        self.classmap_key.canon(out);
        out.u32(self.transform_version);
        out.option(self.hook_waiver.as_ref());
        self.authority.canon(out);
        self.peer.canon(out);
    }
}

/// A genesis operation refused its source (§7 step 4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GenesisRefused {
    /// The operation.
    pub genesis_id: ChronicleId,
    /// Why.
    pub reason: WalkRefusal,
}

impl Canonical for GenesisRefused {
    fn canon(&self, out: &mut Canon) {
        self.genesis_id.canon(out);
        self.reason.canon(out);
    }
}

/// Why a nomination made no Candidate (§3.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NominationRefusal {
    /// The walk or the materialisation refused the tree (tag 0).
    Walk(WalkRefusal),
    /// The Seal is not accepted (tag 1).
    SealNotAccepted,
    /// The Seal is not this Vessel's (tag 2).
    NotThisVessel,
    /// `exclude` is not a subset of `sanction.allowed_exclude` (tag 3).
    BadExclude,
    /// A Candidate with this id is already accepted (tag 4).
    Duplicate,
    /// The same id belongs to a closed Candidate (tag 5).
    Closed,
    /// A supersession that changes nothing (tag 6).
    NoChange,
    /// A store quota is exhausted (tag 7).
    Quota {
        /// The config key.
        key: String,
    },
}

impl Canonical for NominationRefusal {
    fn canon(&self, out: &mut Canon) {
        match self {
            Self::Walk(w) => {
                out.tag(0);
                w.canon(out);
            }
            Self::SealNotAccepted => {
                out.tag(1);
            }
            Self::NotThisVessel => {
                out.tag(2);
            }
            Self::BadExclude => {
                out.tag(3);
            }
            Self::Duplicate => {
                out.tag(4);
            }
            Self::Closed => {
                out.tag(5);
            }
            Self::NoChange => {
                out.tag(6);
            }
            Self::Quota { key } => {
                out.tag(7).str(key);
            }
        }
    }
}

/// A nomination was refused (§3.1; logical id by D23).  For
/// diagnosis: it holds nothing and is not a Candidate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NominationRefused {
    /// The Vessel.
    pub chronicle: ChronicleId,
    /// The Seal put forward.
    pub seal: SealRef,
    /// The exclusion asked for.
    pub exclude: BTreeSet<PathClass>,
    /// Why.
    pub reason: NominationRefusal,
    /// The walk's manifest, if the walk ran.
    pub input_manifest_key: Option<HashVal>,
}

impl Canonical for NominationRefused {
    fn canon(&self, out: &mut Canon) {
        self.chronicle.canon(out);
        self.seal.canon(out);
        out.set(self.exclude.iter());
        self.reason.canon(out);
        out.option(self.input_manifest_key.as_ref());
    }
}

/// A genesis operation's scratch was removed after its `TemplateReady`
/// (§7 step 7; logical id by D23).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GenesisCleanedUp {
    /// The operation.
    pub genesis_id: ChronicleId,
    /// The scratch dataset's guid, if one was made (`--best-effort`).
    pub scratch_guid: Option<u64>,
}

impl Canonical for GenesisCleanedUp {
    fn canon(&self, out: &mut Canon) {
        self.genesis_id.canon(out);
        out.option(self.scratch_guid.as_ref());
    }
}

/// The exclusion set as a bitmask, one bit per [`PathClass`] tag: a
/// fixed-size stand-in for the set inside a [`LogicalKey`].
pub fn exclude_mask(exclude: &BTreeSet<PathClass>) -> u8 {
    exclude.iter().fold(0u8, |m, c| m | (1 << (*c as u8)))
}

// ── The record enum ─────────────────────────────────────────────────

/// A P4 contract record.  Tags are fixed; a new kind is a new tag.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ContractRecord {
    /// Tag 0.
    Candidate(Box<Candidate>),
    /// Tag 1.
    VerificationStarted(VerificationStarted),
    /// Tag 2.
    VerificationFinished(VerificationFinished),
    /// Tag 3.
    VerdictSubmitted(Box<VerdictSubmitted>),
    /// Tag 4.
    Refused(Refused),
    /// Tag 5.
    CandidateClosed(CandidateClosed),
    /// Tag 6.
    SanctionCommitted(SanctionCommitted),
    /// Tag 7.
    TemplateReady(Box<TemplateReady>),
    /// Tag 8.
    SanctionCompleted {
        /// The Template.
        template_id: ChronicleId,
    },
    /// Tag 9.
    PurgeDeferred(PurgeDeferred),
    /// Tag 10.
    PurgeCommitted(PurgeCommitted),
    /// Tag 11.
    ReplacementInstalled(ReplacementInstalled),
    /// Tag 12.
    ItemLost(ItemLost),
    /// Tag 13.
    PurgeComplete(PurgeComplete),
    /// Tag 14.
    PurgeDamaged(PurgeDamaged),
    /// Tag 15.
    GenesisStarted(Box<GenesisStarted>),
    /// Tag 16.
    GenesisRefused(GenesisRefused),
    /// An orphan is claimed for deletion (tag 17; coordinator-side).
    ReclaimClaimed {
        /// The object.
        object_key: HashVal,
    },
    /// A reclaim claim is resolved; the key is quarantined (tag 18).
    ReclaimComplete {
        /// The object.
        object_key: HashVal,
        /// How it ended.
        outcome: ReclaimOutcome,
    },
    /// Tag 19 (D23).
    NominationRefused(NominationRefused),
    /// Tag 20 (D23).
    GenesisCleanedUp(GenesisCleanedUp),
}

impl ContractRecord {
    /// The record's logical key: its row of the §1.2 table.
    pub fn logical_key(&self) -> LogicalKey {
        match self {
            Self::Candidate(c) => LogicalKey::Candidate(c.candidate_id),
            Self::VerificationStarted(s) => LogicalKey::Attempt(s.attempt_id),
            Self::VerificationFinished(f) => LogicalKey::AttemptFinished(f.attempt_id),
            Self::VerdictSubmitted(v) => LogicalKey::Verdict(v.request.request_id),
            Self::Refused(r) => LogicalKey::Verdict(r.request_id),
            Self::CandidateClosed(c) => LogicalKey::CandidateClose(c.candidate_id),
            Self::SanctionCommitted(s) => LogicalKey::Sanction(s.candidate_id),
            Self::TemplateReady(t) => LogicalKey::Template(t.template_id),
            Self::SanctionCompleted { template_id } => LogicalKey::SanctionCompleted(*template_id),
            Self::PurgeDeferred(p) => LogicalKey::PurgeDefer(p.chronicle, p.checked_at),
            Self::PurgeCommitted(p) => LogicalKey::Purge(p.chronicle),
            Self::ReplacementInstalled(r) => LogicalKey::Replacement(r.chronicle, r.pack.digest),
            Self::ItemLost(i) => LogicalKey::ItemLost(i.chronicle, i.pack.digest),
            Self::PurgeComplete(p) => LogicalKey::PurgeEnd(p.chronicle),
            Self::PurgeDamaged(p) => LogicalKey::PurgeEnd(p.chronicle),
            Self::GenesisStarted(g) => LogicalKey::Genesis(g.genesis_id),
            Self::GenesisRefused(g) => LogicalKey::GenesisRefused(g.genesis_id),
            Self::ReclaimClaimed { object_key } => LogicalKey::Reclaim(*object_key),
            Self::ReclaimComplete { object_key, .. } => LogicalKey::ReclaimDone(*object_key),
            Self::NominationRefused(n) => {
                LogicalKey::NominationRefused(n.chronicle, n.seal.hash, exclude_mask(&n.exclude))
            }
            Self::GenesisCleanedUp(g) => LogicalKey::GenesisCleaned(g.genesis_id),
        }
    }

    /// The record's logical id.
    pub fn logical_id(&self) -> HashVal {
        logical_id(&self.logical_key())
    }

    /// The record's digest (§9).
    pub fn digest(&self) -> HashVal {
        record_digest(self)
    }

    /// Strict decoding: the bytes must be exactly one record.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let v = r.record()?;
        r.finish()?;
        Ok(v)
    }
}

impl Canonical for ContractRecord {
    fn canon(&self, out: &mut Canon) {
        match self {
            Self::Candidate(r) => {
                out.tag(0);
                r.canon(out);
            }
            Self::VerificationStarted(r) => {
                out.tag(1);
                r.canon(out);
            }
            Self::VerificationFinished(r) => {
                out.tag(2);
                r.canon(out);
            }
            Self::VerdictSubmitted(r) => {
                out.tag(3);
                r.canon(out);
            }
            Self::Refused(r) => {
                out.tag(4);
                r.canon(out);
            }
            Self::CandidateClosed(r) => {
                out.tag(5);
                r.canon(out);
            }
            Self::SanctionCommitted(r) => {
                out.tag(6);
                r.canon(out);
            }
            Self::TemplateReady(r) => {
                out.tag(7);
                r.canon(out);
            }
            Self::SanctionCompleted { template_id } => {
                out.tag(8);
                template_id.canon(out);
            }
            Self::PurgeDeferred(r) => {
                out.tag(9);
                r.canon(out);
            }
            Self::PurgeCommitted(r) => {
                out.tag(10);
                r.canon(out);
            }
            Self::ReplacementInstalled(r) => {
                out.tag(11);
                r.canon(out);
            }
            Self::ItemLost(r) => {
                out.tag(12);
                r.canon(out);
            }
            Self::PurgeComplete(r) => {
                out.tag(13);
                r.canon(out);
            }
            Self::PurgeDamaged(r) => {
                out.tag(14);
                r.canon(out);
            }
            Self::GenesisStarted(r) => {
                out.tag(15);
                r.canon(out);
            }
            Self::GenesisRefused(r) => {
                out.tag(16);
                r.canon(out);
            }
            Self::ReclaimClaimed { object_key } => {
                out.tag(17);
                object_key.canon(out);
            }
            Self::ReclaimComplete {
                object_key,
                outcome,
            } => {
                out.tag(18);
                object_key.canon(out);
                outcome.canon(out);
            }
            Self::NominationRefused(r) => {
                out.tag(19);
                r.canon(out);
            }
            Self::GenesisCleanedUp(r) => {
                out.tag(20);
                r.canon(out);
            }
        }
    }
}

// ── Logical ids ─────────────────────────────────────────────────────

/// One row of the §1.2 table.  The row is part of the key, so two rows
/// never share a logical id even when their raw fields are equal
/// (`GenesisStarted` and a genesis `TemplateReady` both name `genesis_id`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogicalKey {
    /// `Candidate`: `candidate_id` (tag 0).
    Candidate(HashVal),
    /// `VerificationStarted`: `attempt_id` (tag 1).
    Attempt(HashVal),
    /// `VerificationFinished`: `attempt_id ‖ "finished"` (tag 2).
    AttemptFinished(HashVal),
    /// `VerdictSubmitted`, `Refused`: `request_id` (tag 3).
    Verdict(HashVal),
    /// `Never`, `Cancel`, `Supersede`: `candidate_id ‖ "close"` (tag 4).
    CandidateClose(HashVal),
    /// `SanctionCommitted`: `candidate_id ‖ "sanction"` (tag 5).
    Sanction(HashVal),
    /// `TemplateReady` (sanction or genesis): `template_id` (tag 6).
    Template(ChronicleId),
    /// `SanctionCompleted`: `template_id ‖ "completed"` (tag 7).
    SanctionCompleted(ChronicleId),
    /// `PurgeDeferred`: `chronicle ‖ "defer" ‖ checked_at_lsn` (tag 8).
    PurgeDefer(ChronicleId, Lsn),
    /// `PurgeCommitted`: `chronicle ‖ "purge"` (tag 9).
    Purge(ChronicleId),
    /// `ReplacementInstalled`: `chronicle ‖ pack` (tag 10); the pack by
    /// its trailer digest (D25).
    Replacement(ChronicleId, HashVal),
    /// `ItemLost`: `chronicle ‖ pack ‖ "lost"` (tag 11); the pack by its
    /// trailer digest (D25).
    ItemLost(ChronicleId, HashVal),
    /// `PurgeComplete`, `PurgeDamaged`: `chronicle ‖ "purge-end"` (tag 12).
    PurgeEnd(ChronicleId),
    /// `GenesisStarted`: `genesis_id` (tag 13).
    Genesis(ChronicleId),
    /// `GenesisRefused`: `genesis_id ‖ "refused"` (tag 14).
    GenesisRefused(ChronicleId),
    /// `ReclaimClaimed`: `"reclaim" ‖ object_key` (tag 15).
    Reclaim(HashVal),
    /// `ReclaimComplete`: `"reclaim" ‖ object_key ‖ "done"` (tag 16).
    ReclaimDone(HashVal),
    /// `Birth` (a fork's Lineage record): `chronicle ‖ "birth"` (tag 17).
    Birth(ChronicleId),
    /// `NominationRefused`: `chronicle ‖ seal ‖ exclude ‖ "refused"`
    /// (tag 18; D23).  `exclude` as [`exclude_mask`].
    NominationRefused(ChronicleId, HashVal, u8),
    /// `GenesisCleanedUp`: `genesis_id ‖ "cleaned"` (tag 19; D23).
    GenesisCleaned(ChronicleId),
}

impl Canonical for LogicalKey {
    fn canon(&self, out: &mut Canon) {
        match self {
            Self::Candidate(h) => {
                out.tag(0);
                h.canon(out);
            }
            Self::Attempt(h) => {
                out.tag(1);
                h.canon(out);
            }
            Self::AttemptFinished(h) => {
                out.tag(2);
                h.canon(out);
            }
            Self::Verdict(h) => {
                out.tag(3);
                h.canon(out);
            }
            Self::CandidateClose(h) => {
                out.tag(4);
                h.canon(out);
            }
            Self::Sanction(h) => {
                out.tag(5);
                h.canon(out);
            }
            Self::Template(c) => {
                out.tag(6);
                c.canon(out);
            }
            Self::SanctionCompleted(c) => {
                out.tag(7);
                c.canon(out);
            }
            Self::PurgeDefer(c, l) => {
                out.tag(8);
                c.canon(out);
                l.canon(out);
            }
            Self::Purge(c) => {
                out.tag(9);
                c.canon(out);
            }
            Self::Replacement(c, h) => {
                out.tag(10);
                c.canon(out);
                h.canon(out);
            }
            Self::ItemLost(c, h) => {
                out.tag(11);
                c.canon(out);
                h.canon(out);
            }
            Self::PurgeEnd(c) => {
                out.tag(12);
                c.canon(out);
            }
            Self::Genesis(c) => {
                out.tag(13);
                c.canon(out);
            }
            Self::GenesisRefused(c) => {
                out.tag(14);
                c.canon(out);
            }
            Self::Reclaim(h) => {
                out.tag(15);
                h.canon(out);
            }
            Self::ReclaimDone(h) => {
                out.tag(16);
                h.canon(out);
            }
            Self::Birth(c) => {
                out.tag(17);
                c.canon(out);
            }
            Self::NominationRefused(c, h, m) => {
                out.tag(18);
                c.canon(out);
                h.canon(out);
                out.u8(*m);
            }
            Self::GenesisCleaned(c) => {
                out.tag(19);
                c.canon(out);
            }
        }
    }
}

// ── Derivations (§9) ────────────────────────────────────────────────

fn derive(domain: &str, c: &Canon) -> HashVal {
    HashVal::from_bytes(blake3::derive_key(domain, c.as_bytes()))
}

fn derive16(domain: &str, c: &Canon) -> ChronicleId {
    let h = blake3::derive_key(domain, c.as_bytes());
    let mut id = [0u8; 16];
    id.copy_from_slice(&h[..16]);
    ChronicleId::from_bytes(id)
}

/// The logical id of a row (§1.2).
pub fn logical_id(key: &LogicalKey) -> HashVal {
    let mut c = Canon::new();
    key.canon(&mut c);
    derive(LOGICAL_DOMAIN, &c)
}

/// A record's digest: its canonical bytes, no acceptance metadata (§9).
pub fn record_digest(record: &ContractRecord) -> HashVal {
    let mut c = Canon::new();
    record.canon(&mut c);
    derive(RECORD_DOMAIN, &c)
}

/// One submission of a logical id under one epoch (§9, D19).
/// `attempt_no` counts the Warden's submissions of `logical` under
/// `epoch`.
pub fn submission_id(
    logical: HashVal,
    record_digest: HashVal,
    epoch: Epoch,
    attempt_no: u64,
) -> HashVal {
    let mut c = Canon::new();
    logical.canon(&mut c);
    record_digest.canon(&mut c);
    epoch.canon(&mut c);
    c.u64(attempt_no);
    derive(SUBMISSION_DOMAIN, &c)
}

/// A hold created at log position `log_pos` (§9).
pub fn hold_id(log_pos: u64, object_key: HashVal, on_behalf_of: ChronicleId) -> HashVal {
    let mut c = Canon::new();
    c.u64(log_pos);
    object_key.canon(&mut c);
    on_behalf_of.canon(&mut c);
    derive(HOLD_DOMAIN, &c)
}

/// A claim created at log position `log_pos` (§9).
pub fn claim_id(log_pos: u64, object_key: HashVal) -> HashVal {
    let mut c = Canon::new();
    c.u64(log_pos);
    object_key.canon(&mut c);
    derive(CLAIM_DOMAIN, &c)
}

/// A Candidate's id (§9).  `exclude` is a set: order and duplicates in the
/// caller's collection cannot change it.
pub fn candidate_id(
    chronicle: ChronicleId,
    seal_hash: HashVal,
    exclude: &BTreeSet<PathClass>,
    classmap_key: HashVal,
    transform_version: u32,
    requirement: &VerifierRequirement,
) -> HashVal {
    let mut c = Canon::new();
    chronicle.canon(&mut c);
    seal_hash.canon(&mut c);
    c.set(exclude.iter());
    classmap_key.canon(&mut c);
    c.u32(transform_version);
    requirement.canon(&mut c);
    derive(CANDIDATE_DOMAIN, &c)
}

/// The hash of a Candidate's facts (§9).
pub fn facts_hash(facts: &Facts) -> HashVal {
    let mut c = Canon::new();
    facts.canon(&mut c);
    derive(FACTS_DOMAIN, &c)
}

/// A verification attempt's id (§9).
pub fn attempt_id(candidate_id: HashVal, started_at: Lsn) -> HashVal {
    let mut c = Canon::new();
    candidate_id.canon(&mut c);
    started_at.canon(&mut c);
    derive(VERIFY_DOMAIN, &c)
}

/// The digest of a verifier's bounded output.
pub fn output_digest(output: &[u8]) -> HashVal {
    let mut c = Canon::new();
    c.bytes(output);
    derive(VERIFY_OUTPUT_DOMAIN, &c)
}

/// The digest of a complete verification result (§9): Candidate, the
/// exact artifact, the verifier and its configuration, the attempt, the
/// outcome and the output.
pub fn result_digest(
    candidate_id: HashVal,
    artifact_key: HashVal,
    requirement: &VerifierRequirement,
    attempt_id: HashVal,
    outcome: &Outcome,
    output_digest: HashVal,
) -> HashVal {
    let mut c = Canon::new();
    candidate_id.canon(&mut c);
    artifact_key.canon(&mut c);
    requirement.template.canon(&mut c);
    requirement.vconf_key.canon(&mut c);
    attempt_id.canon(&mut c);
    outcome.canon(&mut c);
    output_digest.canon(&mut c);
    derive(VRESULT_DOMAIN, &c)
}

/// The Chronicle id of the Template a sanction makes (§9).  `verdict` is
/// the verdict's logical id.
pub fn template_id(candidate_id: HashVal, verdict: HashVal) -> ChronicleId {
    let mut c = Canon::new();
    candidate_id.canon(&mut c);
    verdict.canon(&mut c);
    derive16(TEMPLATE_DOMAIN, &c)
}

/// A genesis operation's id, which is also its Template's id (§9).
pub fn genesis_id(
    source_key: HashVal,
    classmap_key: HashVal,
    transform_version: u32,
    hook_waiver: Option<&str>,
    actor: &str,
) -> ChronicleId {
    let mut c = Canon::new();
    source_key.canon(&mut c);
    classmap_key.canon(&mut c);
    c.u32(transform_version);
    match hook_waiver {
        None => {
            c.tag(0);
        }
        Some(w) => {
            c.tag(1).str(w);
        }
    }
    c.str(actor);
    derive16(GENESIS_DOMAIN, &c)
}

/// The name of a pack's log-only replacement (D25): the pack
/// `<end>-<base>-<fs to>` is replaced by `<end>-<base>-0`, the log pack of
/// the same frames.  It holds no fs bytes, so every writer produces the
/// same object under it.  `None` if `name` is not a pack name, or names a
/// pack without an fs section (nothing to replace).
pub fn replacement_name(name: &str) -> Option<String> {
    const DIGITS: usize = 20;
    let parts: Vec<&str> = name.split('-').collect();
    let [end, base, to] = parts[..] else {
        return None;
    };
    let num = |x: &str| {
        (x.len() == DIGITS && x.bytes().all(|c| c.is_ascii_digit()))
            .then(|| x.parse::<u64>().ok())
            .flatten()
    };
    let (_, _, to) = (num(end)?, num(base)?, num(to)?);
    (to != 0).then(|| format!("{end}-{base}-{:0DIGITS$}", 0))
}

/// A request's id (§3.7, §9): the peer's uid, the operation, and the
/// canonical body without the id.
pub fn request_id(peer_uid: u32, op: OpKind, body: &[u8]) -> HashVal {
    let mut c = Canon::new();
    c.u32(peer_uid);
    op.canon(&mut c);
    c.bytes(body);
    derive(REQUEST_DOMAIN, &c)
}

// ── Helpers ─────────────────────────────────────────────────────────

fn strictly_ascending<T: Ord>(xs: &[T]) -> bool {
    xs.windows(2).all(|w| w[0] < w[1])
}

/// Appending pre-encoded canonical bytes (no length prefix).
trait CanonExt {
    fn fixed_bytes(&mut self, b: &[u8]) -> &mut Self;
}

impl CanonExt for Canon {
    fn fixed_bytes(&mut self, b: &[u8]) -> &mut Self {
        for byte in b {
            self.u8(*byte);
        }
        self
    }
}

// ── Decoding ────────────────────────────────────────────────────────
//
// The exact inverse of the encodings above, strict as `crate::decode`:
// unknown tags, bad bools, invalid UTF-8, truncation, trailing bytes,
// and sets or ordered lists not in strictly ascending order are refused,
// so every accepted input re-encodes to itself.

struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
}

type R<T> = Result<T, DecodeError>;

impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self { b, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.b.len() - self.pos
    }

    fn take(&mut self, n: u64) -> R<&'a [u8]> {
        if n > self.remaining() as u64 {
            return Err(DecodeError::Truncated {
                at: self.pos,
                need: n,
            });
        }
        let start = self.pos;
        self.pos += n as usize;
        Ok(&self.b[start..self.pos])
    }

    fn u8(&mut self) -> R<u8> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> R<u32> {
        let mut a = [0u8; 4];
        a.copy_from_slice(self.take(4)?);
        Ok(u32::from_le_bytes(a))
    }

    fn u64(&mut self) -> R<u64> {
        let mut a = [0u8; 8];
        a.copy_from_slice(self.take(8)?);
        Ok(u64::from_le_bytes(a))
    }

    fn fixed<const N: usize>(&mut self) -> R<[u8; N]> {
        let mut a = [0u8; N];
        a.copy_from_slice(self.take(N as u64)?);
        Ok(a)
    }

    fn tag(&mut self) -> R<(usize, u8)> {
        let at = self.pos;
        Ok((at, self.u8()?))
    }

    fn bad<T>(at: usize, what: &'static str, tag: u8) -> R<T> {
        Err(DecodeError::BadTag { at, what, tag })
    }

    fn bytes(&mut self) -> R<Vec<u8>> {
        let len = self.u64()?;
        Ok(self.take(len)?.to_vec())
    }

    fn string(&mut self) -> R<String> {
        let len = self.u64()?;
        let at = self.pos;
        let raw = self.take(len)?;
        std::str::from_utf8(raw)
            .map(str::to_owned)
            .map_err(|_| DecodeError::BadUtf8 { at })
    }

    fn option<T>(&mut self, f: impl FnOnce(&mut Self) -> R<T>) -> R<Option<T>> {
        match self.tag()? {
            (_, 0) => Ok(None),
            (_, 1) => f(self).map(Some),
            (at, t) => Self::bad(at, "option", t),
        }
    }

    fn seq<T>(&mut self, mut f: impl FnMut(&mut Self) -> R<T>) -> R<Vec<T>> {
        let at = self.pos;
        let n = self.u64()?;
        if n > self.remaining() as u64 {
            return Err(DecodeError::Truncated { at, need: n });
        }
        let mut out = Vec::with_capacity(n as usize);
        for _ in 0..n {
            out.push(f(self)?);
        }
        Ok(out)
    }

    /// A sequence that must be strictly ascending by `key`.
    fn ascending<T, K: Ord>(
        &mut self,
        what: &'static str,
        f: impl FnMut(&mut Self) -> R<T>,
        key: impl Fn(&T) -> K,
    ) -> R<Vec<T>> {
        let at = self.pos;
        let v = self.seq(f)?;
        let keys: Vec<K> = v.iter().map(key).collect();
        if !strictly_ascending(&keys) {
            return Self::bad(at, what, 0);
        }
        Ok(v)
    }

    fn finish(&self) -> R<()> {
        match self.remaining() {
            0 => Ok(()),
            extra => Err(DecodeError::Trailing {
                at: self.pos,
                extra,
            }),
        }
    }

    // ── leaves ──────────────────────────────────────────────────────

    fn hash(&mut self) -> R<HashVal> {
        self.fixed().map(HashVal::from_bytes)
    }

    fn chronicle(&mut self) -> R<ChronicleId> {
        self.fixed().map(ChronicleId::from_bytes)
    }

    fn lsn(&mut self) -> R<Lsn> {
        self.u64().map(Lsn::new)
    }

    fn authority(&mut self) -> R<Authority> {
        Ok(Authority {
            actor: self.string()?,
            reason: self.string()?,
        })
    }

    fn class(&mut self) -> R<PathClass> {
        match self.tag()? {
            (_, t) if (t as usize) < PathClass::ALL.len() => Ok(PathClass::ALL[t as usize]),
            (at, t) => Self::bad(at, "path class", t),
        }
    }

    fn class_set(&mut self) -> R<BTreeSet<PathClass>> {
        let v = self.ascending("path class set order", Self::class, |c| *c as u8)?;
        Ok(v.into_iter().collect())
    }

    fn counts(&mut self) -> R<ClassCounts> {
        Ok(ClassCounts {
            source: self.u64()?,
            config: self.u64()?,
            hook: self.u64()?,
            secret: self.u64()?,
            scratch: self.u64()?,
            artifact: self.u64()?,
            unknown: self.u64()?,
            structural: self.u64()?,
            unsupported: self.u64()?,
        })
    }

    fn seal_ref(&mut self) -> R<SealRef> {
        Ok(SealRef {
            lsn: self.lsn()?,
            hash: self.hash()?,
        })
    }

    fn requirement(&mut self) -> R<VerifierRequirement> {
        Ok(VerifierRequirement {
            template: self.chronicle()?,
            vconf_key: self.hash()?,
            version: self.u32()?,
        })
    }

    fn facts(&mut self) -> R<Facts> {
        Ok(Facts {
            input: self.counts()?,
            excluded: self.counts()?,
            open_obligations: self.u64()?,
            effects_adopted: self.u64()?,
            ledger_lsn: self.lsn()?,
            requirement: self.requirement()?,
        })
    }

    fn nominated_by(&mut self) -> R<NominatedBy> {
        match self.tag()? {
            (_, 0) => Ok(NominatedBy::Agent),
            (_, 1) => Ok(NominatedBy::Config),
            (_, 2) => Ok(NominatedBy::Supersede { of: self.hash()? }),
            (at, t) => Self::bad(at, "nominated_by", t),
        }
    }

    fn outcome(&mut self) -> R<Outcome> {
        match self.tag()? {
            (_, 0) => Ok(Outcome::Exit { code: self.u32()? }),
            (_, 1) => Ok(Outcome::Interrupted),
            (_, 2) => Ok(Outcome::Timeout),
            (_, 3) => Ok(Outcome::OutputLimit),
            (_, 4) => Ok(Outcome::LaunchFailed),
            (at, t) => Self::bad(at, "outcome", t),
        }
    }

    fn decision(&mut self) -> R<Decision> {
        match self.tag()? {
            (_, 0) => Ok(Decision::Sanction),
            (_, 1) => Ok(Decision::Hold),
            (_, 2) => Ok(Decision::Never {
                reason: self.string()?,
            }),
            (at, t) => Self::bad(at, "decision", t),
        }
    }

    fn peer(&mut self) -> R<Peer> {
        Ok(Peer {
            uid: self.u32()?,
            pid: self.u32()?,
        })
    }

    fn verdict_request(&mut self) -> R<VerdictRequest> {
        Ok(VerdictRequest {
            request_id: self.hash()?,
            candidate_id: self.hash()?,
            facts_hash: self.hash()?,
            artifact_key: self.hash()?,
            requirement: self.requirement()?,
            exclude: self.class_set()?,
            attempt_id: self.hash()?,
            result_digest: self.hash()?,
            decision: self.decision()?,
            authority: self.authority()?,
            policy_digest: self.option(Self::hash)?,
        })
    }

    fn refusal(&mut self) -> R<Refusal> {
        match self.tag()? {
            (_, t) if (t as usize) < Refusal::ALL.len() => Ok(Refusal::ALL[t as usize]),
            (at, t) => Self::bad(at, "refusal", t),
        }
    }

    fn close_kind(&mut self) -> R<CloseKind> {
        match self.tag()? {
            (_, 0) => Ok(CloseKind::Never {
                verdict: self.hash()?,
                reason: self.string()?,
            }),
            (_, 1) => Ok(CloseKind::Cancelled {
                authority: self.authority()?,
            }),
            (_, 2) => Ok(CloseKind::Superseded {
                authority: self.authority()?,
                by: self.hash()?,
            }),
            (at, t) => Self::bad(at, "close kind", t),
        }
    }

    fn born_from(&mut self) -> R<BornFrom> {
        match self.tag()? {
            (_, 0) => Ok(BornFrom::Sanction {
                source: self.chronicle()?,
                candidate_id: self.hash()?,
                verdict: self.hash()?,
            }),
            (_, 1) => Ok(BornFrom::Genesis {
                genesis_id: self.chronicle()?,
            }),
            (at, t) => Self::bad(at, "born_from", t),
        }
    }

    fn chronicle_list(&mut self) -> R<Vec<ChronicleId>> {
        self.ascending("chronicle list order", Self::chronicle, |c| *c.as_bytes())
    }

    fn defer_reason(&mut self) -> R<DeferReason> {
        match self.tag()? {
            (_, 0) => Ok(DeferReason::OpenObligation),
            (_, 1) => Ok(DeferReason::LivenessDependency {
                holders: self.chronicle_list()?,
                unknown: self.chronicle_list()?,
            }),
            (_, 2) => Ok(DeferReason::OpenSanction {
                candidate_id: self.hash()?,
            }),
            (_, 3) => Ok(DeferReason::RetentionPin),
            (_, 4) => Ok(DeferReason::OpenAttempt),
            (_, 5) => Ok(DeferReason::StoreUnavailable),
            (_, 6) => Ok(DeferReason::CoordinatorUnavailable),
            (at, t) => Self::bad(at, "defer reason", t),
        }
    }

    fn consistency(&mut self) -> R<Consistency> {
        match self.tag()? {
            (_, 0) => Ok(Consistency::Immutable),
            (_, 1) => Ok(Consistency::BestEffort),
            (at, t) => Self::bad(at, "consistency", t),
        }
    }

    fn walk_refusal(&mut self) -> R<WalkRefusal> {
        match self.tag()? {
            (_, t) if (t as usize) < WalkRefusal::ALL.len() => Ok(WalkRefusal::ALL[t as usize]),
            (at, t) => Self::bad(at, "walk refusal", t),
        }
    }

    fn reclaim_outcome(&mut self) -> R<ReclaimOutcome> {
        match self.tag()? {
            (_, 0) => Ok(ReclaimOutcome::Deleted),
            (_, 1) => Ok(ReclaimOutcome::Absent),
            (at, t) => Self::bad(at, "reclaim outcome", t),
        }
    }

    fn form(&mut self) -> R<ReplacementForm> {
        match self.tag()? {
            (_, 0) => Ok(ReplacementForm::LogOnly),
            (_, 1) => Ok(ReplacementForm::Tombstone),
            (at, t) => Self::bad(at, "replacement form", t),
        }
    }

    fn nomination_refusal(&mut self) -> R<NominationRefusal> {
        match self.tag()? {
            (_, 0) => Ok(NominationRefusal::Walk(self.walk_refusal()?)),
            (_, 1) => Ok(NominationRefusal::SealNotAccepted),
            (_, 2) => Ok(NominationRefusal::NotThisVessel),
            (_, 3) => Ok(NominationRefusal::BadExclude),
            (_, 4) => Ok(NominationRefusal::Duplicate),
            (_, 5) => Ok(NominationRefusal::Closed),
            (_, 6) => Ok(NominationRefusal::NoChange),
            (_, 7) => Ok(NominationRefusal::Quota {
                key: self.string()?,
            }),
            (at, t) => Self::bad(at, "nomination refusal", t),
        }
    }

    fn pack_ref(&mut self) -> R<PackRef> {
        Ok(PackRef {
            name: self.string()?,
            digest: self.hash()?,
        })
    }

    fn inventory_item(&mut self) -> R<InventoryItem> {
        Ok(InventoryItem {
            pack: self.pack_ref()?,
            sections: self.ascending("section order", Self::lsn, |l| *l)?,
            log_digest: self.hash()?,
            frames: FrameRange {
                first: self.lsn()?,
                last: self.lsn()?,
            },
            form: self.form()?,
        })
    }

    fn inventory(&mut self) -> R<Inventory> {
        let items = self.ascending("inventory order", Self::inventory_item, |i| {
            i.pack.name.clone()
        })?;
        Ok(Inventory { items })
    }

    fn local_state(&mut self) -> R<LocalState> {
        Ok(LocalState {
            dataset_guid: self.u64()?,
            layers: self.ascending("layer order", |r| r.u64().map(LayerRef::new), |l| l.get())?,
        })
    }

    // ── records ─────────────────────────────────────────────────────

    fn candidate(&mut self) -> R<Candidate> {
        Ok(Candidate {
            candidate_id: self.hash()?,
            chronicle: self.chronicle()?,
            seal: self.seal_ref()?,
            exclude: self.class_set()?,
            transform_version: self.u32()?,
            classmap_key: self.hash()?,
            input_manifest_key: self.hash()?,
            output_manifest_key: self.hash()?,
            artifact_key: self.hash()?,
            requirement: self.requirement()?,
            facts: self.facts()?,
            facts_hash: self.hash()?,
            nominated_by: self.nominated_by()?,
            nominated_at: self.lsn()?,
        })
    }

    fn record(&mut self) -> R<ContractRecord> {
        Ok(match self.tag()? {
            (_, 0) => ContractRecord::Candidate(Box::new(self.candidate()?)),
            (_, 1) => ContractRecord::VerificationStarted(VerificationStarted {
                candidate_id: self.hash()?,
                attempt_id: self.hash()?,
                artifact_key: self.hash()?,
                requirement: self.requirement()?,
                started_at: self.lsn()?,
            }),
            (_, 2) => ContractRecord::VerificationFinished(VerificationFinished {
                attempt_id: self.hash()?,
                outcome: self.outcome()?,
                output_digest: self.hash()?,
                output: self.bytes()?,
                result_digest: self.hash()?,
                finished_at: self.lsn()?,
            }),
            (_, 3) => ContractRecord::VerdictSubmitted(Box::new(VerdictSubmitted {
                request: self.verdict_request()?,
                peer: self.peer()?,
            })),
            (_, 4) => ContractRecord::Refused(Refused {
                request_id: self.hash()?,
                candidate_id: self.hash()?,
                peer: self.peer()?,
                rule: self.refusal()?,
            }),
            (_, 5) => ContractRecord::CandidateClosed(CandidateClosed {
                candidate_id: self.hash()?,
                how: self.close_kind()?,
            }),
            (_, 6) => ContractRecord::SanctionCommitted(SanctionCommitted {
                candidate_id: self.hash()?,
                template_id: self.chronicle()?,
                parent_template: self.option(Self::chronicle)?,
                artifact_key: self.hash()?,
                output_manifest_key: self.hash()?,
                classmap_key: self.hash()?,
                vconf_key: self.hash()?,
                attempt_id: self.hash()?,
                result_digest: self.hash()?,
                verdict: self.hash()?,
            }),
            (_, 7) => ContractRecord::TemplateReady(Box::new(TemplateReady {
                template_id: self.chronicle()?,
                parent_template: self.option(Self::chronicle)?,
                born_from: self.born_from()?,
                layer: self.hash()?,
                output_manifest_key: self.hash()?,
                classmap_key: self.hash()?,
                vconf_key: self.option(Self::hash)?,
                authority: self.authority()?,
            })),
            (_, 8) => ContractRecord::SanctionCompleted {
                template_id: self.chronicle()?,
            },
            (_, 9) => ContractRecord::PurgeDeferred(PurgeDeferred {
                chronicle: self.chronicle()?,
                checked_at: self.lsn()?,
                reason: self.defer_reason()?,
            }),
            (_, 10) => ContractRecord::PurgeCommitted(PurgeCommitted {
                chronicle: self.chronicle()?,
                cutoff: Cutoff {
                    seal: self.seal_ref()?,
                    fs_shipped: self.lsn()?,
                },
                inventory_key: self.hash()?,
                local_key: self.hash()?,
            }),
            (_, 11) => ContractRecord::ReplacementInstalled(ReplacementInstalled {
                chronicle: self.chronicle()?,
                pack: self.pack_ref()?,
                replacement_key: self.hash()?,
                replacement_name: self.string()?,
            }),
            (_, 12) => ContractRecord::ItemLost(ItemLost {
                chronicle: self.chronicle()?,
                pack: self.pack_ref()?,
            }),
            (_, 13) => ContractRecord::PurgeComplete(PurgeComplete {
                chronicle: self.chronicle()?,
                inventory_key: self.hash()?,
                items_replaced: self.u64()?,
                history_attestation: self.hash()?,
            }),
            (_, 14) => ContractRecord::PurgeDamaged(PurgeDamaged {
                chronicle: self.chronicle()?,
                inventory_key: self.hash()?,
                items_replaced: self.u64()?,
                items_lost: self.u64()?,
            }),
            (_, 15) => ContractRecord::GenesisStarted(Box::new(GenesisStarted {
                genesis_id: self.chronicle()?,
                source_key: self.hash()?,
                consistency: self.consistency()?,
                classmap_key: self.hash()?,
                transform_version: self.u32()?,
                hook_waiver: self.option(Self::string)?,
                authority: self.authority()?,
                peer: self.peer()?,
            })),
            (_, 16) => ContractRecord::GenesisRefused(GenesisRefused {
                genesis_id: self.chronicle()?,
                reason: self.walk_refusal()?,
            }),
            (_, 17) => ContractRecord::ReclaimClaimed {
                object_key: self.hash()?,
            },
            (_, 18) => ContractRecord::ReclaimComplete {
                object_key: self.hash()?,
                outcome: self.reclaim_outcome()?,
            },
            (_, 19) => ContractRecord::NominationRefused(NominationRefused {
                chronicle: self.chronicle()?,
                seal: self.seal_ref()?,
                exclude: self.class_set()?,
                reason: self.nomination_refusal()?,
                input_manifest_key: self.option(Self::hash)?,
            }),
            (_, 20) => ContractRecord::GenesisCleanedUp(GenesisCleanedUp {
                genesis_id: self.chronicle()?,
                scratch_guid: self.option(Self::u64)?,
            }),
            (at, t) => return Self::bad(at, "contract record", t),
        })
    }
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // ── fixed examples ──────────────────────────────────────────────

    fn h(b: u8) -> HashVal {
        HashVal::from_bytes([b; 32])
    }
    fn cid(b: u8) -> ChronicleId {
        ChronicleId::from_bytes([b; 16])
    }
    fn auth() -> Authority {
        Authority {
            actor: "jarmo".into(),
            reason: "gate".into(),
        }
    }
    fn req() -> VerifierRequirement {
        VerifierRequirement {
            template: cid(0x70),
            vconf_key: h(0x71),
            version: 1,
        }
    }
    fn scratch() -> BTreeSet<PathClass> {
        [PathClass::Scratch].into_iter().collect()
    }
    fn facts() -> Facts {
        Facts {
            input: ClassCounts {
                source: 10,
                config: 2,
                scratch: 5,
                structural: 0,
                ..Default::default()
            },
            excluded: ClassCounts {
                scratch: 5,
                ..Default::default()
            },
            open_obligations: 0,
            effects_adopted: 1,
            ledger_lsn: Lsn::new(30),
            requirement: req(),
        }
    }
    fn candidate() -> Candidate {
        let f = facts();
        Candidate {
            candidate_id: candidate_id(cid(1), h(2), &scratch(), h(3), TRANSFORM_VERSION, &req()),
            chronicle: cid(1),
            seal: SealRef {
                lsn: Lsn::new(20),
                hash: h(2),
            },
            exclude: scratch(),
            transform_version: TRANSFORM_VERSION,
            classmap_key: h(3),
            input_manifest_key: h(4),
            output_manifest_key: h(5),
            artifact_key: h(6),
            requirement: req(),
            facts: f,
            facts_hash: facts_hash(&f),
            nominated_by: NominatedBy::Agent,
            nominated_at: Lsn::new(31),
        }
    }
    fn started() -> VerificationStarted {
        let c = candidate();
        VerificationStarted {
            candidate_id: c.candidate_id,
            attempt_id: attempt_id(c.candidate_id, Lsn::new(32)),
            artifact_key: c.artifact_key,
            requirement: c.requirement,
            started_at: Lsn::new(32),
        }
    }
    fn finished() -> VerificationFinished {
        let s = started();
        let out = b"ok\n".to_vec();
        let od = output_digest(&out);
        let outcome = Outcome::Exit { code: 0 };
        VerificationFinished {
            attempt_id: s.attempt_id,
            outcome,
            output_digest: od,
            output: out,
            result_digest: result_digest(
                s.candidate_id,
                s.artifact_key,
                &s.requirement,
                s.attempt_id,
                &outcome,
                od,
            ),
            finished_at: Lsn::new(33),
        }
    }
    fn peer() -> Peer {
        Peer { uid: 1000, pid: 42 }
    }
    fn verdict_request() -> VerdictRequest {
        let c = candidate();
        let f = finished();
        let mut v = VerdictRequest {
            request_id: HashVal::GENESIS,
            candidate_id: c.candidate_id,
            facts_hash: c.facts_hash,
            artifact_key: c.artifact_key,
            requirement: c.requirement,
            exclude: c.exclude.clone(),
            attempt_id: f.attempt_id,
            result_digest: f.result_digest,
            decision: Decision::Sanction,
            authority: auth(),
            policy_digest: Some(h(0x50)),
        };
        v.request_id = request_id(peer().uid, OpKind::Verdict, &v.body());
        v
    }
    fn verdict_lid() -> HashVal {
        logical_id(&LogicalKey::Verdict(verdict_request().request_id))
    }
    fn committed() -> SanctionCommitted {
        let c = candidate();
        let f = finished();
        let v = verdict_lid();
        SanctionCommitted {
            candidate_id: c.candidate_id,
            template_id: template_id(c.candidate_id, v),
            parent_template: Some(cid(0x60)),
            artifact_key: c.artifact_key,
            output_manifest_key: c.output_manifest_key,
            classmap_key: c.classmap_key,
            vconf_key: c.requirement.vconf_key,
            attempt_id: f.attempt_id,
            result_digest: f.result_digest,
            verdict: v,
        }
    }
    fn ready() -> TemplateReady {
        let s = committed();
        TemplateReady {
            template_id: s.template_id,
            parent_template: s.parent_template,
            born_from: BornFrom::Sanction {
                source: cid(1),
                candidate_id: s.candidate_id,
                verdict: s.verdict,
            },
            layer: s.artifact_key,
            output_manifest_key: s.output_manifest_key,
            classmap_key: s.classmap_key,
            vconf_key: Some(s.vconf_key),
            authority: auth(),
        }
    }
    fn genesis() -> GenesisStarted {
        GenesisStarted {
            genesis_id: genesis_id(h(0x40), h(3), TRANSFORM_VERSION, None, "jarmo"),
            source_key: h(0x40),
            consistency: Consistency::Immutable,
            classmap_key: h(3),
            transform_version: TRANSFORM_VERSION,
            hook_waiver: None,
            authority: auth(),
            peer: peer(),
        }
    }
    fn pname(end: u64, base: u64, to: u64) -> String {
        format!("{end:020}-{base:020}-{to:020}")
    }
    fn pack(end: u64, base: u64, to: u64, d: u8) -> PackRef {
        PackRef {
            name: pname(end, base, to),
            digest: h(d),
        }
    }
    fn inventory() -> Inventory {
        Inventory::new(vec![
            InventoryItem {
                pack: pack(14, 9, 12, 0x91),
                sections: vec![Lsn::new(12)],
                log_digest: h(0xA1),
                frames: FrameRange {
                    first: Lsn::new(10),
                    last: Lsn::new(14),
                },
                form: ReplacementForm::LogOnly,
            },
            InventoryItem {
                pack: pack(8, 4, 8, 0x90),
                sections: vec![Lsn::new(8), Lsn::new(4)],
                log_digest: h(0xA0),
                frames: FrameRange {
                    first: Lsn::new(5),
                    last: Lsn::new(4),
                },
                form: ReplacementForm::Tombstone,
            },
        ])
        .unwrap()
    }
    fn local() -> LocalState {
        LocalState {
            dataset_guid: 0xDEAD_BEEF,
            layers: vec![LayerRef::new(1), LayerRef::new(2)],
        }
    }

    /// One record of every kind, in tag order.
    fn every_record() -> Vec<ContractRecord> {
        let inv = inventory();
        let pack = inv.items()[0].pack.clone();
        vec![
            ContractRecord::Candidate(Box::new(candidate())),
            ContractRecord::VerificationStarted(started()),
            ContractRecord::VerificationFinished(finished()),
            ContractRecord::VerdictSubmitted(Box::new(VerdictSubmitted {
                request: verdict_request(),
                peer: peer(),
            })),
            ContractRecord::Refused(Refused {
                request_id: verdict_request().request_id,
                candidate_id: candidate().candidate_id,
                peer: peer(),
                rule: Refusal::StaleFacts,
            }),
            ContractRecord::CandidateClosed(CandidateClosed {
                candidate_id: candidate().candidate_id,
                how: CloseKind::Superseded {
                    authority: auth(),
                    by: h(0x0F),
                },
            }),
            ContractRecord::SanctionCommitted(committed()),
            ContractRecord::TemplateReady(Box::new(ready())),
            ContractRecord::SanctionCompleted {
                template_id: committed().template_id,
            },
            ContractRecord::PurgeDeferred(PurgeDeferred {
                chronicle: cid(1),
                checked_at: Lsn::new(40),
                reason: DeferReason::LivenessDependency {
                    holders: vec![cid(2), cid(3)],
                    unknown: vec![cid(9)],
                },
            }),
            ContractRecord::PurgeCommitted(PurgeCommitted {
                chronicle: cid(1),
                cutoff: Cutoff {
                    seal: SealRef {
                        lsn: Lsn::new(41),
                        hash: h(0x41),
                    },
                    fs_shipped: Lsn::new(42),
                },
                inventory_key: inv.key(),
                local_key: local().key(),
            }),
            ContractRecord::ReplacementInstalled(ReplacementInstalled {
                chronicle: cid(1),
                pack: pack.clone(),
                replacement_key: h(0xB0),
                replacement_name: replacement_name(&pack.name).unwrap(),
            }),
            ContractRecord::ItemLost(ItemLost {
                chronicle: cid(1),
                pack,
            }),
            ContractRecord::PurgeComplete(PurgeComplete {
                chronicle: cid(1),
                inventory_key: inv.key(),
                items_replaced: 2,
                history_attestation: h(0xC0),
            }),
            ContractRecord::PurgeDamaged(PurgeDamaged {
                chronicle: cid(1),
                inventory_key: inv.key(),
                items_replaced: 1,
                items_lost: 1,
            }),
            ContractRecord::GenesisStarted(Box::new(genesis())),
            ContractRecord::GenesisRefused(GenesisRefused {
                genesis_id: genesis().genesis_id,
                reason: WalkRefusal::HookNotWaived,
            }),
            ContractRecord::ReclaimClaimed {
                object_key: h(0xE0),
            },
            ContractRecord::ReclaimComplete {
                object_key: h(0xE0),
                outcome: ReclaimOutcome::Deleted,
            },
            ContractRecord::NominationRefused(nomination_refused(NominationRefusal::Walk(
                WalkRefusal::UnknownPaths,
            ))),
            ContractRecord::GenesisCleanedUp(GenesisCleanedUp {
                genesis_id: genesis().genesis_id,
                scratch_guid: Some(0xC1EA),
            }),
        ]
    }

    fn nomination_refused(reason: NominationRefusal) -> NominationRefused {
        NominationRefused {
            chronicle: cid(1),
            seal: SealRef {
                lsn: Lsn::new(20),
                hash: h(2),
            },
            exclude: scratch(),
            reason,
            input_manifest_key: Some(h(4)),
        }
    }

    // ── round trips and strictness ──────────────────────────────────

    #[test]
    fn every_record_round_trips_and_tags_are_in_order() {
        for (i, r) in every_record().into_iter().enumerate() {
            let b = r.canon_bytes();
            assert_eq!(b[0] as usize, i, "tag of {r:?}");
            assert_eq!(ContractRecord::decode(&b).unwrap(), r);
        }
    }

    #[test]
    fn decoding_is_strict() {
        let b = ContractRecord::Candidate(Box::new(candidate())).canon_bytes();
        let mut trailing = b.clone();
        trailing.push(0);
        assert!(matches!(
            ContractRecord::decode(&trailing),
            Err(DecodeError::Trailing { .. })
        ));
        assert!(matches!(
            ContractRecord::decode(&b[..b.len() - 1]),
            Err(DecodeError::Truncated { .. })
        ));
        assert!(matches!(
            ContractRecord::decode(&[21]),
            Err(DecodeError::BadTag { .. })
        ));
    }

    #[test]
    fn an_unsorted_or_repeated_set_is_refused() {
        // Candidate encoding: id(32) chronicle(16) seal(8+32), then the set.
        let mut b = ContractRecord::Candidate(Box::new(Candidate {
            exclude: [PathClass::Config, PathClass::Scratch]
                .into_iter()
                .collect(),
            ..candidate()
        }))
        .canon_bytes();
        let set_at = 1 + 32 + 16 + 40;
        assert_eq!(b[set_at..set_at + 8], 2u64.to_le_bytes());
        b.swap(set_at + 8, set_at + 9);
        assert!(ContractRecord::decode(&b).is_err());
        b[set_at + 8] = b[set_at + 9];
        assert!(ContractRecord::decode(&b).is_err());
    }

    #[test]
    fn inventory_is_sorted_and_rejects_duplicates() {
        let inv = inventory();
        assert_eq!(inv.items()[0].pack.name, pname(8, 4, 8), "sorted by name");
        assert_eq!(inv.items()[0].sections, vec![Lsn::new(4), Lsn::new(8)]);
        assert_eq!(Inventory::decode(&inv.bytes()).unwrap(), inv);
        let dup = inv.items()[0].clone();
        assert_eq!(
            Inventory::new(vec![dup.clone(), dup]),
            Err(OrderError::NotStrictlyAscending)
        );
        assert_eq!(LocalState::decode(&local().bytes()).unwrap(), local());
    }

    // ── consistency ─────────────────────────────────────────────────

    #[test]
    fn derived_fields_are_consistent_and_any_change_breaks_them() {
        assert!(candidate().is_consistent());
        assert!(started().is_consistent());
        assert!(finished().is_consistent_with(&started()));
        assert!(verdict_request().id_matches(peer()));
        assert!(committed().is_consistent());
        assert!(ready().is_consistent());
        assert!(genesis().is_consistent());

        let mut c = candidate();
        c.exclude.insert(PathClass::Artifact);
        assert!(!c.is_consistent(), "exclude is part of the id");
        let mut c = candidate();
        c.requirement.version = 2;
        assert!(
            !c.is_consistent(),
            "the requirement is part of the id (D18)"
        );
        let mut f = finished();
        f.outcome = Outcome::Exit { code: 1 };
        assert!(!f.is_consistent_with(&started()));
        assert!(!verdict_request().id_matches(Peer { uid: 0, pid: 42 }));
        let mut g = genesis();
        g.hook_waiver = Some("needed".into());
        assert!(!g.is_consistent(), "the hook waiver is part of the id");
    }

    #[test]
    fn no_record_carries_an_epoch() {
        // The epoch is an accept argument: the digest of a record is the
        // same whatever epoch submits it, and submissions differ.
        let r = ContractRecord::SanctionCommitted(committed());
        let d = r.digest();
        let a = submission_id(r.logical_id(), d, Epoch::new(1), 0);
        let b = submission_id(r.logical_id(), d, Epoch::new(2), 0);
        let c = submission_id(r.logical_id(), d, Epoch::new(1), 1);
        assert_ne!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn hard_rules_read_secret_unknown_unsupported() {
        assert!(facts().input.passes_hard_rules());
        for f in [
            |c: &mut ClassCounts| c.secret = 1,
            |c: &mut ClassCounts| c.unknown = 1,
            |c: &mut ClassCounts| c.unsupported = 1,
        ] {
            let mut c = facts().input;
            f(&mut c);
            assert!(!c.passes_hard_rules());
        }
        let mut c = facts().input;
        c.hook = 3;
        c.scratch = 9;
        assert!(c.passes_hard_rules());
    }

    // ── logical ids ─────────────────────────────────────────────────

    #[test]
    fn rows_that_share_a_logical_id_share_it_and_no_other_does() {
        let rs = every_record();
        let ids: Vec<HashVal> = rs.iter().map(ContractRecord::logical_id).collect();
        // VerdictSubmitted (3) and Refused (4) name the same request.
        assert_eq!(ids[3], ids[4]);
        // PurgeComplete (13) and PurgeDamaged (14) name the same purge.
        assert_eq!(ids[13], ids[14]);
        // Every other pair differs.
        for i in 0..ids.len() {
            for j in i + 1..ids.len() {
                if (i, j) == (3, 4) || (i, j) == (13, 14) {
                    continue;
                }
                assert_ne!(ids[i], ids[j], "rows {i} and {j}");
            }
        }
    }

    #[test]
    fn genesis_operation_and_its_template_have_different_logical_ids() {
        let g = genesis();
        let t = TemplateReady {
            template_id: g.genesis_id,
            parent_template: None,
            born_from: BornFrom::Genesis {
                genesis_id: g.genesis_id,
            },
            layer: h(0x41),
            output_manifest_key: h(0x42),
            classmap_key: g.classmap_key,
            vconf_key: None,
            authority: auth(),
        };
        assert!(t.is_consistent());
        assert_ne!(
            ContractRecord::GenesisStarted(Box::new(g)).logical_id(),
            ContractRecord::TemplateReady(Box::new(t)).logical_id()
        );
    }

    #[test]
    fn a_template_has_one_logical_id_whatever_its_definition() {
        // Two finishers building different TemplateReady records for the
        // same template_id collide on the logical id (one is accepted,
        // the other is a Conflict), but not on the digest.
        let a = ready();
        let mut b = ready();
        b.authority.reason = "other".into();
        let (a, b) = (
            ContractRecord::TemplateReady(Box::new(a)),
            ContractRecord::TemplateReady(Box::new(b)),
        );
        assert_eq!(a.logical_id(), b.logical_id());
        assert_ne!(a.digest(), b.digest());
    }

    #[test]
    fn object_kinds_never_share_a_key() {
        let kinds = [
            ObjectKind::Pack,
            ObjectKind::Artifact,
            ObjectKind::Manifest,
            ObjectKind::Classmap,
            ObjectKind::Vconf,
            ObjectKind::Inventory,
            ObjectKind::Local,
            ObjectKind::Tombstone,
        ];
        let keys: BTreeSet<[u8; 32]> = kinds
            .iter()
            .map(|k| *object_key(*k, b"same bytes").as_bytes())
            .collect();
        assert_eq!(keys.len(), kinds.len());
    }

    #[test]
    fn a_pack_is_replaced_by_the_log_pack_of_the_same_frames() {
        assert_eq!(
            replacement_name(&pname(14, 9, 12)).as_deref(),
            Some(pname(14, 9, 0).as_str())
        );
        assert_eq!(
            replacement_name(&pname(14, 9, 0)),
            None,
            "no fs: nothing to replace"
        );
        assert_eq!(replacement_name("purged-abc"), None);
        assert_eq!(replacement_name("14-9-12"), None, "names are 20 digits");
        assert_eq!(replacement_name(&format!("{}-x", pname(14, 9, 12))), None);
    }

    #[test]
    fn a_seal_and_exclusion_have_one_refusal_logical_id() {
        let a = ContractRecord::NominationRefused(nomination_refused(NominationRefusal::Duplicate));
        let b = ContractRecord::NominationRefused(nomination_refused(NominationRefusal::Quota {
            key: "store.max_pending_artifacts".into(),
        }));
        assert_eq!(a.logical_id(), b.logical_id());
        assert_ne!(a.digest(), b.digest());
        let mut other = nomination_refused(NominationRefusal::Duplicate);
        other.exclude.insert(PathClass::Artifact);
        assert_ne!(
            ContractRecord::NominationRefused(other).logical_id(),
            a.logical_id()
        );
        assert_eq!(exclude_mask(&scratch()), 1 << 4);
    }

    // ── pins ────────────────────────────────────────────────────────

    /// Digests of every record kind, in tag order.  A change here is a
    /// format change: bump the domain or add a tag, never edit a pin.
    #[test]
    fn record_digests_are_pinned() {
        let got: Vec<String> = every_record()
            .iter()
            .map(|r| r.digest().to_string())
            .collect();
        assert_eq!(got, PINS_RECORDS);
    }

    /// The §9 derivations on fixed inputs.
    #[test]
    fn derivations_are_pinned() {
        let g = genesis();
        let got = [
            candidate().candidate_id.to_string(),
            candidate().facts_hash.to_string(),
            started().attempt_id.to_string(),
            finished().result_digest.to_string(),
            verdict_request().request_id.to_string(),
            HashVal::from_bytes({
                let mut b = [0u8; 32];
                b[..16].copy_from_slice(committed().template_id.as_bytes());
                b
            })
            .to_string(),
            HashVal::from_bytes({
                let mut b = [0u8; 32];
                b[..16].copy_from_slice(g.genesis_id.as_bytes());
                b
            })
            .to_string(),
            inventory().key().to_string(),
            hold_id(7, h(6), cid(1)).to_string(),
            claim_id(7, h(6)).to_string(),
            logical_id(&LogicalKey::Birth(cid(1))).to_string(),
        ];
        assert_eq!(got, PINS_DERIVED);
    }

    const PINS_RECORDS: [&str; 21] = [
        "4c679c6a0022ae188b75236abe543c1fdad404ad556c55f8efecfa1f842053e6",
        "220b967695a40c425c53a626ffed0635d40528a852489b0ad66772c87e6b0e18",
        "7449db856743d73ce30398c37ba97b2295e43b6715875f8f55fe0f859ae15bfe",
        "00b43d9d5c84ba41780ce578efa9e28243f75572d25b928db62954fdf8c5e32e",
        "2989bf589bc3d0e12a4561edd85f8c5c49404a80db1c47f3baa35a6dc0dcd31d",
        "514660383a17f000904479ccd479c77795f3f15615764291a26c800876b127b6",
        "e9fdb86f83c1dbd9ff1b92a912c3daf0902986b0d6def0f83d37ab3789463691",
        "6c947a3f7fb84f260a8b963fb82a4e93156882ae40d8561a91b55aedce2c5000",
        "305f9805d49234b85987ab9ce76c4fc44737dcc51af3f62c35e1680484ffdf0d",
        "f1677cdd630eca1c9421e343bb41c2c515fe0b163ec38bf2bf7e20e0362ada4f",
        "4604b817eb6188722cb619d15e728d7e3899e455e6e8d5360d4b1543ca72e206",
        "3483b8e7bac5cbc38f44edb841fff258423c22cb21ffd7b80844e4258e1a3154",
        "05d07e61d8e2f2456ef75d171d9835f8b736aa9abd81ecdaa7b0606d6a859129",
        "8373fc4772c5b11de462534112f85d96ce00feee95bff3201e6775fc3317199f",
        "717041ba8ca2cf3b31e182daad281330e750fce94fc95a8f4b2f2875d9e41172",
        "82c11cad087ed0120e35e321b57cbc2c2c267b4f73b225d462ba82fdba83d540",
        "4502cf30e826d40531e67207983c00e5dd82f7663f9fda28a0983953524f8684",
        "4d820c377642a1bcbcd67bf235dcfa8ad964b5cd4a45017a22f970376e44ea41",
        "7bc1209031258d3bdb68e1f7ad43245b8fc10bfe4c28d3135489bb12047bc6a5",
        "9de7174a6d7d5362a88b620704dbeff81314ae846ad53bc5373b663caae60133",
        "81568db9b33f001502c0cf7993a2c50cb65ca6df2a1e58c1669a91a802187a7f",
    ];
    const PINS_DERIVED: [&str; 11] = [
        "f6091f83116ec7fcb319e5f951fe6b5c709360d89baa30307925bd36d6a59e05",
        "56ca8a77730eeb5a08131010723d9fd944c83afebcc8590d741761932b5b9d14",
        "fc1e0a251a4a8fb312d6f57acc628772976d614377604f0c58b1eee9f041a6a2",
        "fa0a9d5bd20e7e6ad9e032b49e772a0d868c0a0eae7d89e885743b478e053fc9",
        "3a76a6820afbe5c58197069fcaf53cb25604b2c85a40f488795d6f6ce1f22792",
        "f0a9612b06bf5e01a5bc8e4e05bea81a00000000000000000000000000000000",
        "bbd324b6f8aeca6e03c85a430b49b9e800000000000000000000000000000000",
        "1698eb7a470a00825a38b7183edca3d6764faf4e7971fdeab4b8e51cda042779",
        "12203a1c3d5eae0ffbfb4d23b7169b421e5449a4109d6f1cc682a22342fe3a26",
        "9faafa3b90f351a8a5f09e29101835caf9be58e1371ac1fc7c23a661b59afac0",
        "ca48e4f67689a85d431715b63a5e113e1beddd76e68cc20153b4bb7b46f8665a",
    ];

    // ── property tests ──────────────────────────────────────────────

    fn hash() -> impl Strategy<Value = HashVal> {
        any::<[u8; 32]>().prop_map(HashVal::from_bytes)
    }
    fn chron() -> impl Strategy<Value = ChronicleId> {
        any::<[u8; 16]>().prop_map(ChronicleId::from_bytes)
    }
    fn text() -> impl Strategy<Value = String> {
        "\\PC{0,20}"
    }
    fn class() -> impl Strategy<Value = PathClass> {
        (0usize..8).prop_map(|i| PathClass::ALL[i])
    }
    fn classes() -> impl Strategy<Value = BTreeSet<PathClass>> {
        proptest::collection::btree_set(class(), 0..8)
    }
    fn counts() -> impl Strategy<Value = ClassCounts> {
        proptest::array::uniform9(any::<u64>()).prop_map(|a| ClassCounts {
            source: a[0],
            config: a[1],
            hook: a[2],
            secret: a[3],
            scratch: a[4],
            artifact: a[5],
            unknown: a[6],
            structural: a[7],
            unsupported: a[8],
        })
    }
    fn requirement() -> impl Strategy<Value = VerifierRequirement> {
        (chron(), hash(), any::<u32>()).prop_map(|(template, vconf_key, version)| {
            VerifierRequirement {
                template,
                vconf_key,
                version,
            }
        })
    }
    fn authority() -> impl Strategy<Value = Authority> {
        (text(), text()).prop_map(|(actor, reason)| Authority { actor, reason })
    }
    fn chronicles() -> impl Strategy<Value = Vec<ChronicleId>> {
        proptest::collection::btree_set(any::<[u8; 16]>(), 0..4)
            .prop_map(|s| s.into_iter().map(ChronicleId::from_bytes).collect())
    }

    fn arb_record() -> impl Strategy<Value = ContractRecord> {
        let candidate = (
            (
                hash(),
                chron(),
                any::<u64>(),
                hash(),
                classes(),
                any::<u32>(),
            ),
            (hash(), hash(), hash(), hash(), requirement()),
            (counts(), counts(), any::<u64>(), any::<u64>(), any::<u64>()),
            (
                hash(),
                prop_oneof![
                    Just(NominatedBy::Agent),
                    Just(NominatedBy::Config),
                    hash().prop_map(|of| NominatedBy::Supersede { of })
                ],
                any::<u64>(),
            ),
        )
            .prop_map(
                |(
                    (id, ch, sl, sh, ex, tv),
                    (cm, im, om, ak, rq),
                    (i, e, oo, ea, ll),
                    (fh, nb, na),
                )| {
                    ContractRecord::Candidate(Box::new(Candidate {
                        candidate_id: id,
                        chronicle: ch,
                        seal: SealRef {
                            lsn: Lsn::new(sl),
                            hash: sh,
                        },
                        exclude: ex,
                        transform_version: tv,
                        classmap_key: cm,
                        input_manifest_key: im,
                        output_manifest_key: om,
                        artifact_key: ak,
                        requirement: rq,
                        facts: Facts {
                            input: i,
                            excluded: e,
                            open_obligations: oo,
                            effects_adopted: ea,
                            ledger_lsn: Lsn::new(ll),
                            requirement: rq,
                        },
                        facts_hash: fh,
                        nominated_by: nb,
                        nominated_at: Lsn::new(na),
                    }))
                },
            );
        let outcome = prop_oneof![
            any::<u32>().prop_map(|code| Outcome::Exit { code }),
            Just(Outcome::Interrupted),
            Just(Outcome::Timeout),
            Just(Outcome::OutputLimit),
            Just(Outcome::LaunchFailed),
        ];
        let finished = (
            hash(),
            outcome,
            hash(),
            proptest::collection::vec(any::<u8>(), 0..64),
            hash(),
            any::<u64>(),
        )
            .prop_map(|(a, o, od, out, rd, fa)| {
                ContractRecord::VerificationFinished(VerificationFinished {
                    attempt_id: a,
                    outcome: o,
                    output_digest: od,
                    output: out,
                    result_digest: rd,
                    finished_at: Lsn::new(fa),
                })
            });
        let decision = prop_oneof![
            Just(Decision::Sanction),
            Just(Decision::Hold),
            text().prop_map(|reason| Decision::Never { reason }),
        ];
        let verdict = (
            (hash(), hash(), hash(), hash(), requirement(), classes()),
            (
                hash(),
                hash(),
                decision,
                authority(),
                proptest::option::of(hash()),
            ),
            (any::<u32>(), any::<u32>()),
        )
            .prop_map(
                |((ri, ci, fh, ak, rq, ex), (ai, rd, d, au, pd), (uid, pid))| {
                    ContractRecord::VerdictSubmitted(Box::new(VerdictSubmitted {
                        request: VerdictRequest {
                            request_id: ri,
                            candidate_id: ci,
                            facts_hash: fh,
                            artifact_key: ak,
                            requirement: rq,
                            exclude: ex,
                            attempt_id: ai,
                            result_digest: rd,
                            decision: d,
                            authority: au,
                            policy_digest: pd,
                        },
                        peer: Peer { uid, pid },
                    }))
                },
            );
        let close = (
            hash(),
            prop_oneof![
                (hash(), text()).prop_map(|(verdict, reason)| CloseKind::Never { verdict, reason }),
                authority().prop_map(|authority| CloseKind::Cancelled { authority }),
                (authority(), hash())
                    .prop_map(|(authority, by)| CloseKind::Superseded { authority, by }),
            ],
        )
            .prop_map(|(candidate_id, how)| {
                ContractRecord::CandidateClosed(CandidateClosed { candidate_id, how })
            });
        let ready = (
            chron(),
            proptest::option::of(chron()),
            prop_oneof![
                (chron(), hash(), hash()).prop_map(|(source, candidate_id, verdict)| {
                    BornFrom::Sanction {
                        source,
                        candidate_id,
                        verdict,
                    }
                }),
                chron().prop_map(|genesis_id| BornFrom::Genesis { genesis_id }),
            ],
            (
                hash(),
                hash(),
                hash(),
                proptest::option::of(hash()),
                authority(),
            ),
        )
            .prop_map(|(t, p, b, (l, om, cm, vk, au))| {
                ContractRecord::TemplateReady(Box::new(TemplateReady {
                    template_id: t,
                    parent_template: p,
                    born_from: b,
                    layer: l,
                    output_manifest_key: om,
                    classmap_key: cm,
                    vconf_key: vk,
                    authority: au,
                }))
            });
        let deferred = (
            chron(),
            any::<u64>(),
            prop_oneof![
                Just(DeferReason::OpenObligation),
                (chronicles(), chronicles()).prop_map(|(holders, unknown)| {
                    DeferReason::LivenessDependency { holders, unknown }
                }),
                hash().prop_map(|candidate_id| DeferReason::OpenSanction { candidate_id }),
                Just(DeferReason::RetentionPin),
                Just(DeferReason::OpenAttempt),
                Just(DeferReason::StoreUnavailable),
                Just(DeferReason::CoordinatorUnavailable),
            ],
        )
            .prop_map(|(chronicle, c, reason)| {
                ContractRecord::PurgeDeferred(PurgeDeferred {
                    chronicle,
                    checked_at: Lsn::new(c),
                    reason,
                })
            });
        let genesis = (
            chron(),
            hash(),
            any::<bool>(),
            hash(),
            any::<u32>(),
            proptest::option::of(text()),
            authority(),
            any::<u32>(),
            any::<u32>(),
        )
            .prop_map(|(g, s, be, cm, tv, hw, au, uid, pid)| {
                ContractRecord::GenesisStarted(Box::new(GenesisStarted {
                    genesis_id: g,
                    source_key: s,
                    consistency: if be {
                        Consistency::BestEffort
                    } else {
                        Consistency::Immutable
                    },
                    classmap_key: cm,
                    transform_version: tv,
                    hook_waiver: hw,
                    authority: au,
                    peer: Peer { uid, pid },
                }))
            });
        let small = (
            chron(),
            hash(),
            hash(),
            any::<u64>(),
            any::<u64>(),
            (0usize..12),
            text(),
            (0usize..8),
        )
            .prop_map(|(c, a, b, n, m, r, s, w)| match n % 11 {
                0 => ContractRecord::Refused(Refused {
                    request_id: a,
                    candidate_id: b,
                    peer: Peer {
                        uid: m as u32,
                        pid: n as u32,
                    },
                    rule: Refusal::ALL[r],
                }),
                1 => ContractRecord::SanctionCompleted { template_id: c },
                2 => ContractRecord::ReplacementInstalled(ReplacementInstalled {
                    chronicle: c,
                    pack: PackRef {
                        name: s.clone(),
                        digest: a,
                    },
                    replacement_key: b,
                    replacement_name: s,
                }),
                3 => ContractRecord::ItemLost(ItemLost {
                    chronicle: c,
                    pack: PackRef { name: s, digest: a },
                }),
                4 => ContractRecord::PurgeComplete(PurgeComplete {
                    chronicle: c,
                    inventory_key: a,
                    items_replaced: m,
                    history_attestation: b,
                }),
                5 => ContractRecord::PurgeDamaged(PurgeDamaged {
                    chronicle: c,
                    inventory_key: a,
                    items_replaced: m,
                    items_lost: n,
                }),
                6 => ContractRecord::GenesisRefused(GenesisRefused {
                    genesis_id: c,
                    reason: WalkRefusal::ALL[w],
                }),
                7 => ContractRecord::ReclaimClaimed { object_key: a },
                8 => ContractRecord::NominationRefused(NominationRefused {
                    chronicle: c,
                    seal: SealRef {
                        lsn: Lsn::new(m),
                        hash: a,
                    },
                    exclude: [PathClass::ALL[w]].into_iter().collect(),
                    reason: if m % 2 == 0 {
                        NominationRefusal::Walk(WalkRefusal::ALL[w])
                    } else {
                        NominationRefusal::Quota { key: s }
                    },
                    input_manifest_key: (n % 2 == 0).then_some(b),
                }),
                9 => ContractRecord::GenesisCleanedUp(GenesisCleanedUp {
                    genesis_id: c,
                    scratch_guid: (m % 2 == 0).then_some(n),
                }),
                _ => ContractRecord::ReclaimComplete {
                    object_key: a,
                    outcome: if m % 2 == 0 {
                        ReclaimOutcome::Deleted
                    } else {
                        ReclaimOutcome::Absent
                    },
                },
            });
        let committed = (
            hash(),
            chron(),
            proptest::option::of(chron()),
            hash(),
            hash(),
            hash(),
            hash(),
            hash(),
            hash(),
            hash(),
        )
            .prop_map(|(ci, t, p, ak, om, cm, vk, ai, rd, v)| {
                ContractRecord::SanctionCommitted(SanctionCommitted {
                    candidate_id: ci,
                    template_id: t,
                    parent_template: p,
                    artifact_key: ak,
                    output_manifest_key: om,
                    classmap_key: cm,
                    vconf_key: vk,
                    attempt_id: ai,
                    result_digest: rd,
                    verdict: v,
                })
            });
        let purge = (chron(), any::<u64>(), hash(), any::<u64>(), hash(), hash()).prop_map(
            |(c, sl, sh, fs, ik, lk)| {
                ContractRecord::PurgeCommitted(PurgeCommitted {
                    chronicle: c,
                    cutoff: Cutoff {
                        seal: SealRef {
                            lsn: Lsn::new(sl),
                            hash: sh,
                        },
                        fs_shipped: Lsn::new(fs),
                    },
                    inventory_key: ik,
                    local_key: lk,
                })
            },
        );
        let started =
            (hash(), hash(), hash(), requirement(), any::<u64>()).prop_map(|(c, a, k, r, s)| {
                ContractRecord::VerificationStarted(VerificationStarted {
                    candidate_id: c,
                    attempt_id: a,
                    artifact_key: k,
                    requirement: r,
                    started_at: Lsn::new(s),
                })
            });
        prop_oneof![
            candidate, started, finished, verdict, close, committed, ready, deferred, purge,
            genesis, small
        ]
    }

    proptest! {
        #[test]
        fn decode_inverts_encode(r in arb_record()) {
            let b = r.canon_bytes();
            prop_assert_eq!(ContractRecord::decode(&b).unwrap(), r);
        }

        #[test]
        fn decode_never_panics_and_accepts_only_canonical_bytes(b in proptest::collection::vec(any::<u8>(), 0..256)) {
            if let Ok(r) = ContractRecord::decode(&b) {
                prop_assert_eq!(r.canon_bytes(), b);
            }
        }

        #[test]
        fn candidate_id_ignores_the_order_exclusions_are_given_in(
            v in proptest::collection::vec(class(), 0..12)
        ) {
            let a: BTreeSet<PathClass> = v.iter().copied().collect();
            let b: BTreeSet<PathClass> = v.iter().rev().copied().collect();
            prop_assert_eq!(
                candidate_id(cid(1), h(2), &a, h(3), 1, &req()),
                candidate_id(cid(1), h(2), &b, h(3), 1, &req())
            );
        }
    }
}
