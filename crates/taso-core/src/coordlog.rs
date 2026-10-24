//! The coordinator log of P4 contract records (spec rev. 12 §1; D11–D13,
//! D16, D19).
//!
//! One durable, ordered log of accepted records is the registry, the holds,
//! the claims and the recovery point.  This module is that log as a pure
//! state machine: every operation of §1 (`announce`, `accept`, `cancel`,
//! the queries, `claim_chronicle`, `takeover_target`, fences and expiry)
//! and the predicate and derived effects of every row of the §1.2 table.
//! It does no I/O: the store is reached through [`StoreView`], and time is
//! passed in.  Durability and the wire (`taso-coordd`) wrap it later; the
//! state is a function of the accepted records, so it can be rebuilt by
//! replaying them.
//!
//! Normative reference: `Taso_spec_p4_contracts` rev. 12, BLAKE3
//! `37c75f30580bf3edd79674be38702d7893af413813bbfe6d4585231e9477144a`.
//!
//! # What the coordinator knows about packs
//!
//! A Chronicle's ordinary records reach the coordinator through the P1–P3
//! append path, not this log.  Its packs are therefore held by their own
//! Chronicle implicitly, until its `PurgeCommitted`.  This log tracks the
//! holds other records create, on packs (a fork on its parent's Seal) and
//! on content-addressed objects (artifacts, manifests, …).

use std::collections::{BTreeMap, BTreeSet};

use crate::canon::{Canon, Canonical};
use crate::contract::{
    hold_id, replacement_name, BornFrom, Candidate, CloseKind, ContractRecord, Decision, Inventory,
    InventoryItem, LogicalKey, VerificationFinished, VerificationStarted, RECORD_DOMAIN,
};
use crate::envelope::{ChronicleId, Epoch, HashVal, Lsn};
use crate::record::{LineageRecord, Origin, Payload};

type C16 = [u8; 16];
type H32 = [u8; 32];

/// Domain of a pack's object key in hold and claim ids ([`ObjectId::key`]).
pub const OBJECT_PACK_DOMAIN: &str = "taso.object.pack.v1";

// ── Objects and the store ───────────────────────────────────────────

/// An object a hold or a claim names (spec §2.1).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ObjectId {
    /// A content-addressed object, by its key.
    Content(H32),
    /// A Chronicle pack, by Chronicle and name.
    Pack(C16, String),
}

impl ObjectId {
    /// A content-addressed object.
    pub fn content(key: HashVal) -> Self {
        Self::Content(*key.as_bytes())
    }

    /// A pack of `chronicle`.
    pub fn pack(chronicle: ChronicleId, name: &str) -> Self {
        Self::Pack(*chronicle.as_bytes(), name.to_string())
    }

    /// The 32-byte key hold and claim ids are derived over: the content
    /// key, or `"taso.object.pack.v1" ‖ chronicle ‖ name` for a pack.
    pub fn key(&self) -> HashVal {
        match self {
            Self::Content(h) => HashVal::from_bytes(*h),
            Self::Pack(c, name) => {
                let mut b = Canon::new();
                b.fixed(c).str(name);
                HashVal::from_bytes(blake3::derive_key(OBJECT_PACK_DOMAIN, b.as_bytes()))
            }
        }
    }
}

/// What the coordinator reads from the store (spec §0.4, §1.2 step 5).
/// The coordinator never trusts a Warden's word for these.
pub trait StoreView {
    /// The pack `name` of `chronicle` is readable, verifies, and carries a
    /// record with this digest.
    fn carries(&self, chronicle: ChronicleId, name: &str, digest: HashVal) -> bool;
    /// The object is in the store and verifies.
    fn exists(&self, object: &ObjectId) -> bool;
    /// The inventory object under `key`, if readable.
    fn inventory(&self, key: HashVal) -> Option<Inventory>;
    /// Every fs-bearing pack of `chronicle`, as inventory items.
    fn fs_packs(&self, chronicle: ChronicleId) -> Vec<InventoryItem>;
    /// The objects needed to restore `chronicle` at Seal `seal`.
    fn seal_closure(&self, chronicle: ChronicleId, seal: Lsn) -> Vec<ObjectId>;
    /// The trailer digest of `item`'s replacement if it is in the store
    /// and matches the item (as `Packs::verify_replacement`).
    fn verify_replacement(&self, chronicle: ChronicleId, item: &InventoryItem) -> Option<HashVal>;
}

// ── Submissions and answers ─────────────────────────────────────────

/// A record submitted to the log: a contract record, or a fork's Lineage
/// (the Birth row).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Submitted {
    /// A P4 contract record.
    Contract(ContractRecord),
    /// A fork's Lineage record (the Birth row of §1.2).
    Birth {
        /// The fork.
        chronicle: ChronicleId,
        /// Its Lineage record; the origin must be a fork.
        lineage: LineageRecord,
    },
}

impl Submitted {
    /// Its logical id (§1.2).
    pub fn logical_id(&self) -> HashVal {
        match self {
            Self::Contract(r) => r.logical_id(),
            Self::Birth { chronicle, .. } => {
                crate::contract::logical_id(&LogicalKey::Birth(*chronicle))
            }
        }
    }

    /// Its digest: [`crate::contract::record_digest`] for a contract
    /// record; for a Birth, the same domain over the Lineage payload.
    pub fn digest(&self) -> HashVal {
        match self {
            Self::Contract(r) => r.digest(),
            Self::Birth { lineage, .. } => {
                let mut c = Canon::new();
                Payload::Lineage(lineage.clone()).canon(&mut c);
                HashVal::from_bytes(blake3::derive_key(RECORD_DOMAIN, c.as_bytes()))
            }
        }
    }
}

/// The last accepted record of a Chronicle in this log.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Head {
    /// Its log position (0: none).
    pub pos: u64,
    /// Its digest ([`HashVal::GENESIS`]: none).
    pub digest: HashVal,
}

impl Head {
    /// No record accepted yet.
    pub const EMPTY: Self = Self {
        pos: 0,
        digest: HashVal::GENESIS,
    };
}

/// A transient refusal: the submission stays pending (§1.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Transient {
    /// The head moved: re-read, then cancel and resubmit.
    HeadMoved {
        /// The head now.
        head: Head,
    },
    /// The pack is not (yet) readable, or does not carry the record.
    NotReadable,
    /// Another submission of this Chronicle is unresolved.
    Pending {
        /// That submission.
        submission: HashVal,
    },
}

/// Why a submission can never be accepted (§0.1: says nothing about its
/// logical id).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Final {
    /// Another record is accepted for this logical id.
    Conflict,
    /// Not the Chronicle's current epoch.
    StaleEpoch,
    /// Not announced under this epoch, or announced with other content.
    NotAnnounced,
    /// The row's predicate failed; the rule's name.
    Predicate(&'static str),
    /// An object to hold is claimed for deletion.
    Claimed(ObjectId),
    /// An object to hold was deleted within the quarantine window.
    Quarantined(ObjectId),
    /// An object to hold is not in the store.
    NoSuchObject(ObjectId),
    /// Cancelled by its Warden.
    Cancelled,
    /// Not resolved within `announce.ttl`, or its epoch was fenced.
    Expired,
}

/// The coordinator's answer to `accept` and `cancel`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Answer {
    /// Appended at `log_pos`.
    Accepted {
        /// Its position.
        log_pos: u64,
        /// Its logical id.
        logical_id: HashVal,
    },
    /// A record with this logical id and digest is already accepted.
    AlreadyAccepted {
        /// Its position.
        log_pos: u64,
        /// Its digest.
        record_digest: HashVal,
    },
    /// Transient: the submission stays pending.
    Refused(Transient),
    /// This submission can never be accepted.
    FinalRefused(Final),
}

/// `query { submission }` (§1.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SubmissionStatus {
    /// Accepted at this position.
    Accepted(u64),
    /// Not accepted at the time of the read; not final.
    AbsentAtRead,
    /// Never acceptable.
    FinalRefused(Final),
}

/// Who may claim a new Chronicle id, or take one over (§1.6, D21).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClaimAuthority {
    /// An ordinary Vessel (the P1–P3 registration).
    Vessel,
    /// An operator starting a genesis.
    Genesis,
    /// The accepted `GenesisStarted` of this id (takeover only).
    GenesisStarted,
    /// The accepted `SanctionCommitted` (by logical id) naming this id.
    Sanction {
        /// The commit's logical id.
        commit: HashVal,
    },
}

/// Why a claim or takeover was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClaimError {
    /// Someone holds it; read, do not create.
    AlreadyClaimed {
        /// Its epoch.
        epoch: Epoch,
    },
    /// The authority does not name this id.
    BadAuthority,
    /// No such Chronicle (takeover).
    Unknown,
    /// The epoch moved since it was read (takeover is conditional).
    EpochMoved {
        /// The epoch now.
        epoch: Epoch,
    },
}

/// Timing parameters (spec §11.1).
#[derive(Clone, Copy, Debug)]
pub struct Config {
    /// `announce.ttl`, in the caller's time unit.
    pub announce_ttl: u64,
    /// `store.deleted_quarantine`, same unit.
    pub deleted_quarantine: u64,
}

// ── State ───────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
struct Pending {
    submission: H32,
    logical: H32,
    digest: H32,
    at: u64,
}

#[derive(Clone, Debug)]
struct Chron {
    epoch: Epoch,
    head: Head,
    retired: bool,
    pending: Option<Pending>,
    claimed_by: ClaimAuthority,
    obligations: BTreeSet<u64>,
    pinned: bool,
}

#[derive(Clone, Debug)]
struct Entry {
    chronicle: C16,
    logical: H32,
    digest: H32,
    record: Submitted,
    pack: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Hold {
    object: ObjectId,
    holder: C16,
    created_by: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CandState {
    Open,
    Committing,
    Closed,
}

#[derive(Clone, Debug)]
struct Cand {
    chronicle: C16,
    state: CandState,
    record: Candidate,
    created_by: u64,
    /// Accepted Sanction verdicts: verdict logical id → (attempt, result).
    sanction_verdicts: BTreeMap<H32, (H32, H32)>,
    commit: Option<u64>,
}

#[derive(Clone, Debug)]
struct Attempt {
    started: VerificationStarted,
    started_by: u64,
    finished: Option<(VerificationFinished, u64)>,
}

/// A dependency that keeps a Chronicle from retiring (§1.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Live {
    /// A node-bound fork on its parent, while the fork is open.
    Fork,
    /// A committed sanction not yet ready, on its source.
    OpenSanction { candidate: H32 },
}

#[derive(Clone, Debug)]
enum Progress {
    Replaced,
    Lost,
}

#[derive(Clone, Debug)]
struct PurgeState {
    inventory_key: H32,
    items: Vec<InventoryItem>,
    progressed: BTreeMap<String, Progress>,
    ended: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ClaimBy {
    Purge(C16),
    Reclaim,
}

/// The coordinator log.
#[derive(Clone, Debug)]
pub struct CoordLog {
    config: Config,
    chrons: BTreeMap<C16, Chron>,
    log: Vec<Entry>,
    logical: BTreeMap<H32, u64>,
    /// (chronicle, submission) → position.
    accepted_subs: BTreeMap<(C16, H32), u64>,
    /// (chronicle, submission) → why it can never be accepted.
    refused_subs: BTreeMap<(C16, H32), Final>,
    holds: BTreeMap<H32, Hold>,
    claims: BTreeMap<ObjectId, ClaimBy>,
    quarantine: BTreeMap<ObjectId, u64>,
    cands: BTreeMap<H32, Cand>,
    attempts: BTreeMap<H32, Attempt>,
    live: Vec<(C16, C16, Live)>,
    templates: BTreeMap<C16, u64>,
    genesis: BTreeMap<C16, u64>,
    purges: BTreeMap<C16, PurgeState>,
}

/// What a record does once accepted, computed before anything changes.
#[derive(Default)]
struct Effects {
    holds: Vec<(ObjectId, C16)>,
    release_created_by: Vec<u64>,
    release_all_of: Option<C16>,
    claims: Vec<(ObjectId, ClaimBy)>,
    resolve_claims: Vec<ObjectId>,
    retire: bool,
    changes: Vec<Change>,
}

enum Change {
    CandOpen(Box<Candidate>),
    CandClose(H32),
    CandCommitting(H32),
    CloseOpenCandidatesOf(C16),
    SanctionVerdict {
        cand: H32,
        verdict: H32,
        attempt: H32,
        result: H32,
    },
    AttemptOpen(VerificationStarted),
    AttemptClose(VerificationFinished),
    LiveAdd(C16, C16, Live),
    LiveRemoveDependent(C16),
    LiveRemoveSanction(H32),
    Register(C16),
    GenesisStart(C16),
    PurgeStart(C16, H32, Vec<InventoryItem>),
    PurgeProgress(C16, String, Progress),
    PurgeEnd(C16),
}

type Plan = Result<Effects, Final>;

fn need(ok: bool, rule: &'static str) -> Result<(), Final> {
    if ok {
        Ok(())
    } else {
        Err(Final::Predicate(rule))
    }
}

impl CoordLog {
    /// An empty log.
    pub fn new(config: Config) -> Self {
        Self {
            config,
            chrons: BTreeMap::new(),
            log: Vec::new(),
            logical: BTreeMap::new(),
            accepted_subs: BTreeMap::new(),
            refused_subs: BTreeMap::new(),
            holds: BTreeMap::new(),
            claims: BTreeMap::new(),
            quarantine: BTreeMap::new(),
            cands: BTreeMap::new(),
            attempts: BTreeMap::new(),
            live: Vec::new(),
            templates: BTreeMap::new(),
            genesis: BTreeMap::new(),
            purges: BTreeMap::new(),
        }
    }

    // ── Chronicle ids and epochs ────────────────────────────────────

    /// Claim a new Chronicle id (§1.6): the first claimant gets epoch 1.
    pub fn claim_chronicle(
        &mut self,
        id: ChronicleId,
        authority: ClaimAuthority,
    ) -> Result<Epoch, ClaimError> {
        let c = *id.as_bytes();
        if let Some(ch) = self.chrons.get(&c) {
            return Err(ClaimError::AlreadyClaimed { epoch: ch.epoch });
        }
        match authority {
            ClaimAuthority::Vessel | ClaimAuthority::Genesis => {}
            ClaimAuthority::GenesisStarted => return Err(ClaimError::BadAuthority),
            ClaimAuthority::Sanction { commit } => {
                if !self.commit_names(commit, id) {
                    return Err(ClaimError::BadAuthority);
                }
            }
        }
        self.chrons.insert(
            c,
            Chron {
                epoch: Epoch::FIRST,
                head: Head::EMPTY,
                retired: false,
                pending: None,
                claimed_by: authority,
                obligations: BTreeSet::new(),
                pinned: false,
            },
        );
        Ok(Epoch::FIRST)
    }

    fn commit_names(&self, commit: HashVal, id: ChronicleId) -> bool {
        self.logical.get(commit.as_bytes()).is_some_and(|&pos| {
            matches!(
                &self.log[pos as usize - 1].record,
                Submitted::Contract(ContractRecord::SanctionCommitted(s)) if s.template_id == id
            )
        })
    }

    /// Take over a claimed target (D21): verified by the same authority as
    /// its claim, conditional on `current_epoch`.  Advances the epoch
    /// (fencing the old owner) and returns it with the target's head.
    pub fn takeover_target(
        &mut self,
        id: ChronicleId,
        authority: ClaimAuthority,
        current_epoch: Epoch,
    ) -> Result<(Epoch, Head), ClaimError> {
        let ok = match authority {
            ClaimAuthority::Sanction { commit } => self.commit_names(commit, id),
            ClaimAuthority::GenesisStarted => self.genesis.contains_key(id.as_bytes()),
            ClaimAuthority::Vessel | ClaimAuthority::Genesis => false,
        };
        if !ok {
            return Err(ClaimError::BadAuthority);
        }
        let ch = self.chrons.get(id.as_bytes()).ok_or(ClaimError::Unknown)?;
        if ch.epoch != current_epoch {
            return Err(ClaimError::EpochMoved { epoch: ch.epoch });
        }
        let e = self.fence(id).expect("exists");
        Ok((e, self.chrons[id.as_bytes()].head))
    }

    /// A new epoch for `chronicle` (a fence, F3 step 1): every pending
    /// submission of the old epoch expires.
    pub fn fence(&mut self, chronicle: ChronicleId) -> Option<Epoch> {
        let c = *chronicle.as_bytes();
        let ch = self.chrons.get_mut(&c)?;
        ch.epoch = ch.epoch.next();
        let e = ch.epoch;
        if let Some(p) = ch.pending.take() {
            self.refused_subs.insert((c, p.submission), Final::Expired);
        }
        Some(e)
    }

    /// Expire every pending submission older than `announce.ttl`.
    pub fn expire(&mut self, now: u64) {
        let ttl = self.config.announce_ttl;
        for (c, ch) in self.chrons.iter_mut() {
            if ch
                .pending
                .as_ref()
                .is_some_and(|p| now.saturating_sub(p.at) > ttl)
            {
                let p = ch.pending.take().expect("checked");
                self.refused_subs.insert((*c, p.submission), Final::Expired);
            }
        }
    }

    /// Record that an effect intent of `chronicle` is open or settled
    /// (§1.5); called by the append path when it accepts the intent and
    /// its terminal outcome.
    pub fn note_obligation(&mut self, chronicle: ChronicleId, op: u64, open: bool) {
        if let Some(ch) = self.chrons.get_mut(chronicle.as_bytes()) {
            if open {
                ch.obligations.insert(op);
            } else {
                ch.obligations.remove(&op);
            }
        }
    }

    /// Set or lift an operator retention pin on `chronicle`.
    pub fn set_retention_pin(&mut self, chronicle: ChronicleId, pinned: bool) {
        if let Some(ch) = self.chrons.get_mut(chronicle.as_bytes()) {
            ch.pinned = pinned;
        }
    }

    // ── Announce, accept, cancel ────────────────────────────────────

    /// Announce a submission (§1.2): creates the pending entry `accept`
    /// resolves.  Repeating the same announce is a no-op.
    pub fn announce(
        &mut self,
        chronicle: ChronicleId,
        epoch: Epoch,
        submission: HashVal,
        logical: HashVal,
        digest: HashVal,
        now: u64,
    ) -> Result<(), Answer> {
        self.expire(now);
        let key = (*chronicle.as_bytes(), *submission.as_bytes());
        if let Some(f) = self.refused_subs.get(&key) {
            return Err(Answer::FinalRefused(f.clone()));
        }
        let Some(ch) = self.chrons.get_mut(chronicle.as_bytes()) else {
            return Err(Answer::FinalRefused(Final::StaleEpoch));
        };
        if ch.epoch != epoch {
            return Err(Answer::FinalRefused(Final::StaleEpoch));
        }
        match &ch.pending {
            Some(p) if p.submission == *submission.as_bytes() => {
                if p.logical == *logical.as_bytes() && p.digest == *digest.as_bytes() {
                    Ok(())
                } else {
                    Err(Answer::FinalRefused(Final::NotAnnounced))
                }
            }
            Some(p) => Err(Answer::Refused(Transient::Pending {
                submission: HashVal::from_bytes(p.submission),
            })),
            None => {
                ch.pending = Some(Pending {
                    submission: *submission.as_bytes(),
                    logical: *logical.as_bytes(),
                    digest: *digest.as_bytes(),
                    at: now,
                });
                Ok(())
            }
        }
    }

    /// Cancel a submission: `FinalRefused { Cancelled }`, or the existing
    /// answer if it was accepted or refused already.  Idempotent.
    pub fn cancel(&mut self, chronicle: ChronicleId, epoch: Epoch, submission: HashVal) -> Answer {
        let s = *submission.as_bytes();
        let key = (*chronicle.as_bytes(), s);
        if let Some(&pos) = self.accepted_subs.get(&key) {
            return Answer::AlreadyAccepted {
                log_pos: pos,
                record_digest: HashVal::from_bytes(self.log[pos as usize - 1].digest),
            };
        }
        if let Some(f) = self.refused_subs.get(&key) {
            return Answer::FinalRefused(f.clone());
        }
        if let Some(ch) = self.chrons.get_mut(chronicle.as_bytes()) {
            if ch.epoch == epoch && ch.pending.as_ref().is_some_and(|p| p.submission == s) {
                ch.pending = None;
            }
        }
        self.refused_subs.insert(key, Final::Cancelled);
        Answer::FinalRefused(Final::Cancelled)
    }

    fn finalize(&mut self, chronicle: ChronicleId, submission: H32, reason: Final) -> Answer {
        if let Some(ch) = self.chrons.get_mut(chronicle.as_bytes()) {
            if ch
                .pending
                .as_ref()
                .is_some_and(|p| p.submission == submission)
            {
                ch.pending = None;
            }
        }
        self.refused_subs
            .insert((*chronicle.as_bytes(), submission), reason.clone());
        Answer::FinalRefused(reason)
    }

    /// Accept a submission (§1.2), in the order of the spec: logical
    /// lookup, epoch, pending guard, head, readability, predicate,
    /// effects; then append.  `record` is the record `pack` carries; step
    /// 5 checks the store agrees.
    #[allow(clippy::too_many_arguments)]
    pub fn accept(
        &mut self,
        chronicle: ChronicleId,
        epoch: Epoch,
        submission: HashVal,
        expected_head: Head,
        pack: &str,
        record: Submitted,
        store: &dyn StoreView,
        now: u64,
    ) -> Answer {
        self.expire(now);
        let s = *submission.as_bytes();
        let logical = record.logical_id();
        let digest = record.digest();
        // 1. Logical lookup first.
        if let Some(&pos) = self.logical.get(logical.as_bytes()) {
            let e = &self.log[pos as usize - 1];
            if e.digest == *digest.as_bytes() {
                if let Some(ch) = self.chrons.get_mut(chronicle.as_bytes()) {
                    if ch.pending.as_ref().is_some_and(|p| p.submission == s) {
                        ch.pending = None;
                    }
                }
                return Answer::AlreadyAccepted {
                    log_pos: pos,
                    record_digest: digest,
                };
            }
            return self.finalize(chronicle, s, Final::Conflict);
        }
        if let Some(f) = self.refused_subs.get(&(*chronicle.as_bytes(), s)) {
            return Answer::FinalRefused(f.clone());
        }
        // 2. Epoch.
        let Some(ch) = self.chrons.get(chronicle.as_bytes()) else {
            return self.finalize(chronicle, s, Final::StaleEpoch);
        };
        if ch.epoch != epoch {
            return self.finalize(chronicle, s, Final::StaleEpoch);
        }
        // 3. Pending guard.
        match &ch.pending {
            Some(p) if p.submission == s => {
                if p.logical != *logical.as_bytes() || p.digest != *digest.as_bytes() {
                    return self.finalize(chronicle, s, Final::NotAnnounced);
                }
            }
            Some(p) => {
                return Answer::Refused(Transient::Pending {
                    submission: HashVal::from_bytes(p.submission),
                })
            }
            None => return self.finalize(chronicle, s, Final::NotAnnounced),
        }
        // 4. Head.
        if ch.head != expected_head {
            return Answer::Refused(Transient::HeadMoved { head: ch.head });
        }
        // 5. Readability.
        if !store.carries(chronicle, pack, digest) {
            return Answer::Refused(Transient::NotReadable);
        }
        // 6–7. Predicate and effects.
        let pos = self.log.len() as u64 + 1;
        let plan = self
            .plan(chronicle, &record, pack, store, now)
            .and_then(|fx| self.check_effects(fx, store, now));
        let fx = match plan {
            Ok(fx) => fx,
            Err(f) => return self.finalize(chronicle, s, f),
        };
        // 8. Append.
        self.log.push(Entry {
            chronicle: *chronicle.as_bytes(),
            logical: *logical.as_bytes(),
            digest: *digest.as_bytes(),
            record,
            pack: pack.to_string(),
        });
        self.logical.insert(*logical.as_bytes(), pos);
        self.accepted_subs.insert((*chronicle.as_bytes(), s), pos);
        let ch = self.chrons.get_mut(chronicle.as_bytes()).expect("checked");
        ch.pending = None;
        ch.head = Head { pos, digest };
        self.apply(pos, chronicle, fx, now);
        Answer::Accepted {
            log_pos: pos,
            logical_id: logical,
        }
    }

    // ── Queries (§1.3) ──────────────────────────────────────────────

    /// `query { submission }` of `chronicle`.
    pub fn query_submission(
        &self,
        chronicle: ChronicleId,
        submission: HashVal,
    ) -> SubmissionStatus {
        let key = (*chronicle.as_bytes(), *submission.as_bytes());
        if let Some(&p) = self.accepted_subs.get(&key) {
            SubmissionStatus::Accepted(p)
        } else if let Some(f) = self.refused_subs.get(&key) {
            SubmissionStatus::FinalRefused(f.clone())
        } else {
            SubmissionStatus::AbsentAtRead
        }
    }

    /// `query { logical }`: the accepted record and its position.
    pub fn query_logical(&self, logical: HashVal) -> Option<(u64, &Submitted)> {
        self.logical
            .get(logical.as_bytes())
            .map(|&p| (p, &self.log[p as usize - 1].record))
    }

    /// `query { chronicle }`: epoch, head, whether retired, the pending
    /// submission, and the positions of its accepted records.
    pub fn query_chronicle(&self, chronicle: ChronicleId) -> Option<ChronicleView> {
        let c = chronicle.as_bytes();
        let ch = self.chrons.get(c)?;
        Some(ChronicleView {
            epoch: ch.epoch,
            head: ch.head,
            retired: ch.retired,
            pending: ch
                .pending
                .as_ref()
                .map(|p| HashVal::from_bytes(p.submission)),
            accepted: (1..=self.log.len() as u64)
                .filter(|p| self.log[*p as usize - 1].chronicle == *c)
                .collect(),
            holds: self
                .holds
                .values()
                .filter(|h| h.holder == *c)
                .map(|h| h.object.clone())
                .collect(),
        })
    }

    /// The current epoch of `chronicle`, if the log knows it (what
    /// [`CoordLog::query_chronicle`] answers, without building the view).
    pub fn epoch(&self, chronicle: ChronicleId) -> Option<Epoch> {
        self.chrons.get(chronicle.as_bytes()).map(|ch| ch.epoch)
    }

    /// The open obligations of `chronicle` (§1.5), ascending by op id.
    pub fn obligations(&self, chronicle: ChronicleId) -> Vec<u64> {
        self.chrons
            .get(chronicle.as_bytes())
            .map(|ch| ch.obligations.iter().copied().collect())
            .unwrap_or_default()
    }

    /// Every holder of `object`.
    pub fn holders(&self, object: &ObjectId) -> Vec<ChronicleId> {
        let mut v: Vec<C16> = self
            .holds
            .values()
            .filter(|h| h.object == *object)
            .map(|h| h.holder)
            .collect();
        v.sort();
        v.dedup();
        v.into_iter().map(ChronicleId::from_bytes).collect()
    }

    /// Whether `object` is claimed for deletion.
    pub fn is_claimed(&self, object: &ObjectId) -> bool {
        self.claims.contains_key(object)
    }

    /// Whether `template` is registered (its `TemplateReady` accepted).
    pub fn is_template(&self, template: ChronicleId) -> bool {
        self.templates.contains_key(template.as_bytes())
    }

    /// `query { purge_projection }` (§6.3 step 2): the inventory the
    /// coordinator would compute now — the fs packs of `chronicle` no
    /// other Chronicle holds — ascending by name.
    pub fn purge_projection(
        &self,
        chronicle: ChronicleId,
        store: &dyn StoreView,
    ) -> Vec<InventoryItem> {
        let c = *chronicle.as_bytes();
        let mut v: Vec<InventoryItem> = store
            .fs_packs(chronicle)
            .into_iter()
            .filter(|it| {
                let obj = ObjectId::pack(chronicle, &it.pack.name);
                !self
                    .holds
                    .values()
                    .any(|h| h.object == obj && h.holder != c)
            })
            .collect();
        v.sort_by(|a, b| a.pack.name.cmp(&b.pack.name));
        v
    }

    // ── Predicates and effects (§1.2) ───────────────────────────────

    fn entry(&self, logical: &LogicalKey) -> Option<(u64, &Entry)> {
        let id = crate::contract::logical_id(logical);
        self.logical
            .get(id.as_bytes())
            .map(|&p| (p, &self.log[p as usize - 1]))
    }

    fn chron(&self, c: &C16) -> &Chron {
        &self.chrons[c]
    }

    fn plan(
        &self,
        chronicle: ChronicleId,
        record: &Submitted,
        pack: &str,
        store: &dyn StoreView,
        _now: u64,
    ) -> Plan {
        let c = *chronicle.as_bytes();
        let me = self.chron(&c);
        let mut fx = Effects::default();
        let rec = match record {
            Submitted::Birth {
                chronicle: b,
                lineage,
            } => {
                need(*b == chronicle, "not this Chronicle's record")?;
                let Origin::Fork { parent } = &lineage.origin else {
                    return Err(Final::Predicate("a Birth is a fork's Lineage"));
                };
                let p = *parent.chronicle.as_bytes();
                need(
                    !self.chrons.get(&p).is_some_and(|x| x.retired),
                    "parent retired",
                )?;
                for o in store.seal_closure(parent.chronicle, parent.seal) {
                    fx.holds.push((o, c));
                }
                if !self.templates.contains_key(&p) {
                    fx.changes.push(Change::LiveAdd(c, p, Live::Fork));
                }
                return Ok(fx);
            }
            Submitted::Contract(r) => r,
        };
        let cand = |id: &HashVal| self.cands.get(id.as_bytes());
        match rec {
            ContractRecord::Candidate(k) => {
                need(k.chronicle == chronicle, "not this Chronicle's record")?;
                need(!me.retired, "retired")?;
                need(k.is_consistent(), "inconsistent record")?;
                need(cand(&k.candidate_id).is_none(), "Candidate exists")?;
                for key in [
                    k.artifact_key,
                    k.input_manifest_key,
                    k.output_manifest_key,
                    k.classmap_key,
                    k.requirement.vconf_key,
                ] {
                    fx.holds.push((ObjectId::content(key), c));
                }
                for o in store.seal_closure(chronicle, k.seal.lsn) {
                    fx.holds.push((o, c));
                }
                fx.changes.push(Change::CandOpen(k.clone()));
            }
            ContractRecord::NominationRefused(n) => {
                need(n.chronicle == chronicle, "not this Chronicle's record")?;
            }
            ContractRecord::VerificationStarted(st) => {
                let k = cand(&st.candidate_id).ok_or(Final::Predicate("no such Candidate"))?;
                need(k.chronicle == c, "not this Chronicle's record")?;
                need(st.is_consistent(), "inconsistent record")?;
                need(k.state == CandState::Open, "Candidate not open")?;
                need(!self.open_attempt(&st.candidate_id), "an attempt is open")?;
                let tpl = self
                    .template_ready(st.requirement.template)
                    .ok_or(Final::Predicate("no such verifier Template"))?;
                fx.holds.push((ObjectId::content(tpl.layer), c));
                fx.holds.push((ObjectId::content(st.artifact_key), c));
                fx.changes.push(Change::AttemptOpen(*st));
            }
            ContractRecord::VerificationFinished(f) => {
                let a = self
                    .attempts
                    .get(f.attempt_id.as_bytes())
                    .ok_or(Final::Predicate("no such attempt"))?;
                need(a.finished.is_none(), "attempt not open")?;
                let k = &self.cands[a.started.candidate_id.as_bytes()];
                need(k.chronicle == c, "not this Chronicle's record")?;
                need(f.is_consistent_with(&a.started), "inconsistent record")?;
                fx.release_created_by.push(a.started_by);
                fx.changes.push(Change::AttemptClose(f.clone()));
            }
            ContractRecord::VerdictSubmitted(v) => {
                let k =
                    cand(&v.request.candidate_id).ok_or(Final::Predicate("no such Candidate"))?;
                need(k.chronicle == c, "not this Chronicle's record")?;
                need(v.request.id_matches(v.peer), "inconsistent record")?;
                if v.request.decision == Decision::Sanction {
                    fx.changes.push(Change::SanctionVerdict {
                        cand: *v.request.candidate_id.as_bytes(),
                        verdict: *rec.logical_id().as_bytes(),
                        attempt: *v.request.attempt_id.as_bytes(),
                        result: *v.request.result_digest.as_bytes(),
                    });
                }
            }
            ContractRecord::Refused(r) => {
                let k = cand(&r.candidate_id).ok_or(Final::Predicate("no such Candidate"))?;
                need(k.chronicle == c, "not this Chronicle's record")?;
            }
            ContractRecord::CandidateClosed(cl) => {
                let k = cand(&cl.candidate_id).ok_or(Final::Predicate("no such Candidate"))?;
                need(k.chronicle == c, "not this Chronicle's record")?;
                need(k.state == CandState::Open, "Candidate not open")?;
                need(!self.open_attempt(&cl.candidate_id), "an attempt is open")?;
                if let CloseKind::Never { verdict, .. } = &cl.how {
                    need(
                        self.logical.contains_key(verdict.as_bytes()),
                        "no such verdict",
                    )?;
                }
                fx.release_created_by.push(k.created_by);
                fx.changes
                    .push(Change::CandClose(*cl.candidate_id.as_bytes()));
            }
            ContractRecord::SanctionCommitted(s) => {
                let k = cand(&s.candidate_id).ok_or(Final::Predicate("no such Candidate"))?;
                need(k.chronicle == c, "not this Chronicle's record")?;
                need(s.is_consistent(), "inconsistent record")?;
                // (1)
                need(k.state == CandState::Open, "Candidate not open")?;
                // (3) the pending guard admits only this submission.
                need(!me.retired, "retired")?;
                // (4)
                need(me.obligations.is_empty(), "open obligation")?;
                // (5)
                need(k.record.facts.input.passes_hard_rules(), "hard rules")?;
                // The commit names the Candidate's own objects.
                need(
                    s.artifact_key == k.record.artifact_key
                        && s.output_manifest_key == k.record.output_manifest_key
                        && s.classmap_key == k.record.classmap_key
                        && s.vconf_key == k.record.requirement.vconf_key,
                    "not the Candidate's objects",
                )?;
                // The verdict it names: an accepted Sanction for this
                // Candidate, bound to this attempt and result.
                need(
                    k.sanction_verdicts.get(s.verdict.as_bytes())
                        == Some(&(*s.attempt_id.as_bytes(), *s.result_digest.as_bytes())),
                    "no Sanction verdict for this attempt",
                )?;
                // (6)
                let a = self
                    .attempts
                    .get(s.attempt_id.as_bytes())
                    .ok_or(Final::Predicate("no such attempt"))?;
                need(
                    a.started.candidate_id == s.candidate_id
                        && a.started.artifact_key == k.record.artifact_key
                        && a.started.requirement == k.record.requirement,
                    "attempt is not this Candidate's",
                )?;
                let (fin, fin_pos) = a
                    .finished
                    .as_ref()
                    .ok_or(Final::Predicate("attempt not finished"))?;
                need(
                    fin.outcome.passed() && fin.result_digest == s.result_digest,
                    "attempt did not pass",
                )?;
                // (7)
                need(!self.open_attempt(&s.candidate_id), "an attempt is open")?;
                need(
                    !self.attempts.values().any(|b| {
                        b.started.candidate_id == s.candidate_id
                            && b.started.started_at > a.started.started_at
                            && b.finished
                                .as_ref()
                                .is_some_and(|(f, _)| !f.outcome.passed())
                    }),
                    "a later attempt failed",
                )?;
                // (8) holds on behalf of the Template.
                let t = *s.template_id.as_bytes();
                for key in [
                    s.artifact_key,
                    s.output_manifest_key,
                    s.classmap_key,
                    s.vconf_key,
                ] {
                    fx.holds.push((ObjectId::content(key), t));
                }
                let fin_pack = &self.log[*fin_pos as usize - 1];
                fx.holds
                    .push((ObjectId::Pack(fin_pack.chronicle, fin_pack.pack.clone()), t));
                fx.changes
                    .push(Change::CandCommitting(*s.candidate_id.as_bytes()));
                fx.changes.push(Change::LiveAdd(
                    t,
                    c,
                    Live::OpenSanction {
                        candidate: *s.candidate_id.as_bytes(),
                    },
                ));
            }
            ContractRecord::TemplateReady(t) => {
                need(t.template_id == chronicle, "not this Chronicle's record")?;
                need(t.is_consistent(), "inconsistent record")?;
                need(
                    me.head == Head::EMPTY || matches!(t.born_from, BornFrom::Genesis { .. }),
                    "target not empty",
                )?;
                let tid = *t.template_id.as_bytes();
                for key in [t.layer, t.output_manifest_key, t.classmap_key] {
                    fx.holds.push((ObjectId::content(key), tid));
                }
                match t.born_from {
                    BornFrom::Sanction {
                        source,
                        candidate_id,
                        verdict,
                    } => {
                        let (cpos, ce) = self
                            .entry(&LogicalKey::Sanction(candidate_id))
                            .ok_or(Final::Predicate("no SanctionCommitted"))?;
                        let Submitted::Contract(ContractRecord::SanctionCommitted(s)) = &ce.record
                        else {
                            unreachable!("the Sanction row holds SanctionCommitted");
                        };
                        need(
                            ce.chronicle == *source.as_bytes(),
                            "not the commit's source",
                        )?;
                        need(
                            matches!(me.claimed_by, ClaimAuthority::Sanction { commit } if commit.as_bytes() == &ce.logical),
                            "target not claimed by this commit",
                        )?;
                        need(
                            s.template_id == t.template_id
                                && s.verdict == verdict
                                && t.layer == s.artifact_key
                                && t.output_manifest_key == s.output_manifest_key
                                && t.classmap_key == s.classmap_key
                                && t.vconf_key == Some(s.vconf_key)
                                && t.parent_template == s.parent_template,
                            "definition differs from the commit",
                        )?;
                        fx.holds.push((ObjectId::content(s.vconf_key), tid));
                        let k = &self.cands[candidate_id.as_bytes()];
                        fx.release_created_by.push(k.created_by);
                        fx.release_created_by.push(cpos);
                        fx.changes.push(Change::CandClose(*candidate_id.as_bytes()));
                        fx.changes
                            .push(Change::LiveRemoveSanction(*candidate_id.as_bytes()));
                    }
                    BornFrom::Genesis { genesis_id } => {
                        let (gpos, ge) = self
                            .entry(&LogicalKey::Genesis(genesis_id))
                            .ok_or(Final::Predicate("no GenesisStarted"))?;
                        need(me.head.pos == gpos, "head is not GenesisStarted")?;
                        let Submitted::Contract(ContractRecord::GenesisStarted(g)) = &ge.record
                        else {
                            unreachable!("the Genesis row holds GenesisStarted");
                        };
                        need(
                            t.classmap_key == g.classmap_key
                                && t.vconf_key.is_none()
                                && t.parent_template.is_none(),
                            "definition differs from the operation",
                        )?;
                        fx.release_created_by.push(gpos);
                    }
                }
                fx.changes.push(Change::Register(tid));
            }
            ContractRecord::SanctionCompleted { template_id } => {
                let (_, ce) = self
                    .entry(&LogicalKey::Template(*template_id))
                    .ok_or(Final::Predicate("no TemplateReady"))?;
                let Submitted::Contract(ContractRecord::TemplateReady(t)) = &ce.record else {
                    unreachable!("the Template row holds TemplateReady");
                };
                need(
                    matches!(t.born_from, BornFrom::Sanction { source, .. } if source == chronicle),
                    "not this Chronicle's sanction",
                )?;
            }
            ContractRecord::PurgeDeferred(p) => {
                need(p.chronicle == chronicle, "not this Chronicle's record")?;
                need(!me.retired, "retired")?;
            }
            ContractRecord::PurgeCommitted(p) => {
                need(p.chronicle == chronicle, "not this Chronicle's record")?;
                need(!me.retired, "retired")?;
                need(me.obligations.is_empty(), "open obligation")?;
                for (_, on, kind) in &self.live {
                    if *on == c {
                        return Err(Final::Predicate(match kind {
                            Live::Fork => "liveness dependency",
                            Live::OpenSanction { .. } => "open sanction",
                        }));
                    }
                }
                need(
                    !self.attempts.values().any(|a| {
                        a.finished.is_none()
                            && self.cands[a.started.candidate_id.as_bytes()].chronicle == c
                    }),
                    "an attempt is open",
                )?;
                need(!me.pinned, "retention pin")?;
                let inv = store
                    .inventory(p.inventory_key)
                    .ok_or(Final::Predicate("inventory unreadable"))?;
                need(inv.key() == p.inventory_key, "inventory unreadable")?;
                need(
                    store.exists(&ObjectId::content(p.local_key)),
                    "local state unreadable",
                )?;
                let projected = self.purge_projection(chronicle, store);
                need(inv.items() == projected.as_slice(), "inventory mismatch")?;
                fx.retire = true;
                fx.release_all_of = Some(c);
                for it in inv.items() {
                    fx.claims
                        .push((ObjectId::pack(chronicle, &it.pack.name), ClaimBy::Purge(c)));
                }
                fx.changes.push(Change::CloseOpenCandidatesOf(c));
                fx.changes.push(Change::LiveRemoveDependent(c));
                fx.changes.push(Change::PurgeStart(
                    c,
                    *p.inventory_key.as_bytes(),
                    inv.items().to_vec(),
                ));
            }
            ContractRecord::ReplacementInstalled(r) => {
                need(r.chronicle == chronicle, "not this Chronicle's record")?;
                let ps = self
                    .purges
                    .get(&c)
                    .ok_or(Final::Predicate("no PurgeCommitted"))?;
                let item = ps
                    .items
                    .iter()
                    .find(|i| i.pack == r.pack)
                    .ok_or(Final::Predicate("not in the inventory"))?;
                need(!ps.progressed.contains_key(&r.pack.name), "item progressed")?;
                need(
                    replacement_name(&r.pack.name).as_deref() == Some(r.replacement_name.as_str()),
                    "replacement name",
                )?;
                need(
                    store.verify_replacement(chronicle, item) == Some(r.replacement_key),
                    "replacement does not match the inventory",
                )?;
                fx.holds
                    .push((ObjectId::pack(chronicle, &r.replacement_name), c));
                fx.changes.push(Change::PurgeProgress(
                    c,
                    r.pack.name.clone(),
                    Progress::Replaced,
                ));
            }
            ContractRecord::ItemLost(l) => {
                need(l.chronicle == chronicle, "not this Chronicle's record")?;
                let ps = self
                    .purges
                    .get(&c)
                    .ok_or(Final::Predicate("no PurgeCommitted"))?;
                let item = ps
                    .items
                    .iter()
                    .find(|i| i.pack == l.pack)
                    .ok_or(Final::Predicate("not in the inventory"))?;
                need(!ps.progressed.contains_key(&l.pack.name), "item progressed")?;
                need(
                    !store.exists(&ObjectId::pack(chronicle, &l.pack.name))
                        && store.verify_replacement(chronicle, item).is_none(),
                    "original or replacement readable",
                )?;
                fx.changes.push(Change::PurgeProgress(
                    c,
                    l.pack.name.clone(),
                    Progress::Lost,
                ));
            }
            ContractRecord::PurgeComplete(p) => {
                need(p.chronicle == chronicle, "not this Chronicle's record")?;
                let ps = self
                    .purges
                    .get(&c)
                    .ok_or(Final::Predicate("no PurgeCommitted"))?;
                need(
                    ps.inventory_key == *p.inventory_key.as_bytes(),
                    "not this purge's inventory",
                )?;
                need(
                    ps.progressed.len() == ps.items.len(),
                    "items not progressed",
                )?;
                need(
                    ps.progressed
                        .values()
                        .all(|g| matches!(g, Progress::Replaced))
                        && p.items_replaced == ps.items.len() as u64,
                    "history damaged",
                )?;
                need(
                    ps.items
                        .iter()
                        .all(|i| !store.exists(&ObjectId::pack(chronicle, &i.pack.name))),
                    "originals not deleted",
                )?;
                self.purge_end(&mut fx, chronicle, ps);
            }
            ContractRecord::PurgeDamaged(p) => {
                need(p.chronicle == chronicle, "not this Chronicle's record")?;
                let ps = self
                    .purges
                    .get(&c)
                    .ok_or(Final::Predicate("no PurgeCommitted"))?;
                need(
                    ps.inventory_key == *p.inventory_key.as_bytes(),
                    "not this purge's inventory",
                )?;
                need(
                    ps.progressed.len() == ps.items.len(),
                    "items not progressed",
                )?;
                let lost = ps
                    .progressed
                    .values()
                    .filter(|g| matches!(g, Progress::Lost))
                    .count() as u64;
                need(
                    p.items_lost == lost && p.items_replaced == ps.items.len() as u64 - lost,
                    "counts differ",
                )?;
                self.purge_end(&mut fx, chronicle, ps);
            }
            ContractRecord::GenesisStarted(g) => {
                need(g.genesis_id == chronicle, "not this Chronicle's record")?;
                need(g.is_consistent(), "inconsistent record")?;
                need(
                    matches!(me.claimed_by, ClaimAuthority::Genesis),
                    "not claimed for a genesis",
                )?;
                fx.holds.push((ObjectId::content(g.source_key), c));
                fx.holds.push((ObjectId::content(g.classmap_key), c));
                fx.changes.push(Change::GenesisStart(c));
            }
            ContractRecord::GenesisRefused(g) => {
                need(g.genesis_id == chronicle, "not this Chronicle's record")?;
                let (gpos, _) = self
                    .entry(&LogicalKey::Genesis(g.genesis_id))
                    .ok_or(Final::Predicate("no GenesisStarted"))?;
                need(
                    self.entry(&LogicalKey::Template(g.genesis_id)).is_none(),
                    "Template ready",
                )?;
                fx.release_created_by.push(gpos);
            }
            ContractRecord::GenesisCleanedUp(g) => {
                need(g.genesis_id == chronicle, "not this Chronicle's record")?;
                need(self.templates.contains_key(&c), "no TemplateReady")?;
            }
            ContractRecord::ReclaimClaimed { object_key } => {
                let o = ObjectId::content(*object_key);
                need(!self.holds.values().any(|h| h.object == o), "held")?;
                need(!self.claims.contains_key(&o), "claimed")?;
                need(!self.quarantined(&o, _now), "quarantined")?;
                fx.claims.push((o, ClaimBy::Reclaim));
            }
            ContractRecord::ReclaimComplete { object_key, .. } => {
                let o = ObjectId::content(*object_key);
                need(self.claims.get(&o) == Some(&ClaimBy::Reclaim), "no claim")?;
                need(!store.exists(&o), "not deleted")?;
                fx.resolve_claims.push(o);
            }
        }
        let _ = pack;
        Ok(fx)
    }

    fn purge_end(&self, fx: &mut Effects, chronicle: ChronicleId, ps: &PurgeState) {
        for i in &ps.items {
            fx.resolve_claims
                .push(ObjectId::pack(chronicle, &i.pack.name));
        }
        fx.changes.push(Change::PurgeEnd(*chronicle.as_bytes()));
    }

    fn template_ready(&self, t: ChronicleId) -> Option<&crate::contract::TemplateReady> {
        let pos = self.templates.get(t.as_bytes())?;
        match &self.log[*pos as usize - 1].record {
            Submitted::Contract(ContractRecord::TemplateReady(r)) => Some(r),
            _ => None,
        }
    }

    fn open_attempt(&self, candidate: &HashVal) -> bool {
        self.attempts
            .values()
            .any(|a| a.started.candidate_id == *candidate && a.finished.is_none())
    }

    fn quarantined(&self, o: &ObjectId, now: u64) -> bool {
        self.quarantine.get(o).is_some_and(|&until| now < until)
    }

    /// Step 7: every object to hold exists, is not claimed, not
    /// quarantined; every claim target has no hold left after the
    /// record's releases.
    fn check_effects(&self, fx: Effects, store: &dyn StoreView, now: u64) -> Plan {
        for (o, _) in &fx.holds {
            if self.claims.contains_key(o) {
                return Err(Final::Claimed(o.clone()));
            }
            if self.quarantined(o, now) {
                return Err(Final::Quarantined(o.clone()));
            }
            if !store.exists(o) {
                return Err(Final::NoSuchObject(o.clone()));
            }
        }
        for (o, _) in &fx.claims {
            let held_after = self.holds.values().any(|h| {
                h.object == *o
                    && Some(h.holder) != fx.release_all_of
                    && !fx.release_created_by.contains(&h.created_by)
            });
            if held_after {
                return Err(Final::Predicate("claim target held"));
            }
        }
        Ok(fx)
    }

    fn apply(&mut self, pos: u64, chronicle: ChronicleId, fx: Effects, now: u64) {
        // New holds first, then releases: an object kept across the record
        // is never unheld in between.
        for (object, holder) in fx.holds {
            let id = hold_id(pos, object.key(), ChronicleId::from_bytes(holder));
            self.holds.insert(
                *id.as_bytes(),
                Hold {
                    object,
                    holder,
                    created_by: pos,
                },
            );
        }
        self.holds.retain(|_, h| {
            h.created_by == pos
                || !(fx.release_created_by.contains(&h.created_by)
                    || fx.release_all_of == Some(h.holder))
        });
        for (o, by) in fx.claims {
            self.claims.insert(o, by);
        }
        let until = now + self.config.deleted_quarantine;
        for o in fx.resolve_claims {
            self.claims.remove(&o);
            self.quarantine.insert(o, until);
        }
        if fx.retire {
            self.chrons
                .get_mut(chronicle.as_bytes())
                .expect("exists")
                .retired = true;
        }
        for ch in fx.changes {
            match ch {
                Change::CandOpen(k) => {
                    self.cands.insert(
                        *k.candidate_id.as_bytes(),
                        Cand {
                            chronicle: *k.chronicle.as_bytes(),
                            state: CandState::Open,
                            record: *k,
                            created_by: pos,
                            sanction_verdicts: BTreeMap::new(),
                            commit: None,
                        },
                    );
                }
                Change::CandClose(id) => {
                    if let Some(k) = self.cands.get_mut(&id) {
                        k.state = CandState::Closed;
                    }
                }
                Change::CandCommitting(id) => {
                    if let Some(k) = self.cands.get_mut(&id) {
                        k.state = CandState::Committing;
                        k.commit = Some(pos);
                    }
                }
                Change::CloseOpenCandidatesOf(c) => {
                    for k in self.cands.values_mut() {
                        if k.chronicle == c && k.state == CandState::Open {
                            k.state = CandState::Closed;
                        }
                    }
                }
                Change::SanctionVerdict {
                    cand,
                    verdict,
                    attempt,
                    result,
                } => {
                    if let Some(k) = self.cands.get_mut(&cand) {
                        k.sanction_verdicts.insert(verdict, (attempt, result));
                    }
                }
                Change::AttemptOpen(st) => {
                    self.attempts.insert(
                        *st.attempt_id.as_bytes(),
                        Attempt {
                            started: st,
                            started_by: pos,
                            finished: None,
                        },
                    );
                }
                Change::AttemptClose(f) => {
                    if let Some(a) = self.attempts.get_mut(f.attempt_id.as_bytes()) {
                        a.finished = Some((f, pos));
                    }
                }
                Change::LiveAdd(d, on, kind) => self.live.push((d, on, kind)),
                Change::LiveRemoveDependent(d) => self.live.retain(|(x, _, _)| *x != d),
                Change::LiveRemoveSanction(cand) => self
                    .live
                    .retain(|(_, _, k)| *k != Live::OpenSanction { candidate: cand }),
                Change::Register(t) => {
                    self.templates.insert(t, pos);
                }
                Change::GenesisStart(g) => {
                    self.genesis.insert(g, pos);
                }
                Change::PurgeStart(c, key, items) => {
                    self.purges.insert(
                        c,
                        PurgeState {
                            inventory_key: key,
                            items,
                            progressed: BTreeMap::new(),
                            ended: false,
                        },
                    );
                }
                Change::PurgeProgress(c, name, g) => {
                    if let Some(ps) = self.purges.get_mut(&c) {
                        ps.progressed.insert(name, g);
                    }
                }
                Change::PurgeEnd(c) => {
                    if let Some(ps) = self.purges.get_mut(&c) {
                        ps.ended = true;
                    }
                }
            }
        }
    }
}

/// `query { chronicle }` (§1.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChronicleView {
    /// The current epoch.
    pub epoch: Epoch,
    /// The head.
    pub head: Head,
    /// Whether its `PurgeCommitted` is accepted.
    pub retired: bool,
    /// The pending submission, if any.
    pub pending: Option<HashVal>,
    /// Log positions of its accepted records, in order.
    pub accepted: Vec<u64>,
    /// Objects it holds.
    pub holds: Vec<ObjectId>,
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::{
        attempt_id, candidate_id, facts_hash, genesis_id, object_key, output_digest, request_id,
        result_digest, template_id, CandidateClosed, ClassCounts, Consistency, Facts, FrameRange,
        GenesisStarted, ItemLost, NominatedBy, ObjectKind, OpKind, Outcome, PackRef, Peer,
        PurgeCommitted, PurgeComplete, ReplacementForm, ReplacementInstalled, SanctionCommitted,
        SealRef, TemplateReady, VerdictRequest, VerdictSubmitted, VerifierRequirement,
        TRANSFORM_VERSION,
    };
    use crate::record::{Authority, Namespace, ParentSeal};
    use std::cell::RefCell;
    use std::collections::BTreeSet;

    // ── a fake store ────────────────────────────────────────────────

    #[derive(Default)]
    struct Store {
        objects: RefCell<BTreeSet<ObjectId>>,
        /// (chronicle, pack name) → digests of the records it carries.
        carried: RefCell<BTreeMap<(C16, String), BTreeSet<H32>>>,
        inventories: RefCell<BTreeMap<H32, Inventory>>,
        fs: RefCell<BTreeMap<C16, Vec<InventoryItem>>>,
        closure: RefCell<BTreeMap<C16, Vec<ObjectId>>>,
        replacements: RefCell<BTreeMap<(C16, String), HashVal>>,
    }

    impl Store {
        fn put(&self, o: ObjectId) {
            self.objects.borrow_mut().insert(o);
        }
        fn del(&self, o: &ObjectId) {
            self.objects.borrow_mut().remove(o);
        }
        fn ship(&self, c: ChronicleId, name: &str, r: &Submitted) {
            self.put(ObjectId::pack(c, name));
            self.carried
                .borrow_mut()
                .entry((*c.as_bytes(), name.into()))
                .or_default()
                .insert(*r.digest().as_bytes());
        }
    }

    impl StoreView for Store {
        fn carries(&self, c: ChronicleId, name: &str, d: HashVal) -> bool {
            self.carried
                .borrow()
                .get(&(*c.as_bytes(), name.into()))
                .is_some_and(|s| s.contains(d.as_bytes()))
        }
        fn exists(&self, o: &ObjectId) -> bool {
            self.objects.borrow().contains(o)
        }
        fn inventory(&self, key: HashVal) -> Option<Inventory> {
            self.inventories.borrow().get(key.as_bytes()).cloned()
        }
        fn fs_packs(&self, c: ChronicleId) -> Vec<InventoryItem> {
            self.fs
                .borrow()
                .get(c.as_bytes())
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .filter(|i| self.exists(&ObjectId::pack(c, &i.pack.name)))
                .collect()
        }
        fn seal_closure(&self, c: ChronicleId, _seal: Lsn) -> Vec<ObjectId> {
            self.closure
                .borrow()
                .get(c.as_bytes())
                .cloned()
                .unwrap_or_default()
        }
        fn verify_replacement(&self, c: ChronicleId, item: &InventoryItem) -> Option<HashVal> {
            let name = replacement_name(&item.pack.name)?;
            if !self.exists(&ObjectId::pack(c, &name)) {
                return None;
            }
            self.replacements
                .borrow()
                .get(&(*c.as_bytes(), name))
                .copied()
        }
    }

    // ── a Warden in a test ──────────────────────────────────────────

    struct W<'a> {
        log: &'a mut CoordLog,
        store: &'a Store,
        now: u64,
    }

    fn sub(r: &Submitted, epoch: Epoch, n: u64) -> HashVal {
        crate::contract::submission_id(r.logical_id(), r.digest(), epoch, n)
    }

    impl W<'_> {
        fn head(&self, c: ChronicleId) -> Head {
            self.log.query_chronicle(c).unwrap().head
        }
        fn epoch(&self, c: ChronicleId) -> Epoch {
            self.log.query_chronicle(c).unwrap().epoch
        }
        /// Announce, ship, accept under the current epoch, as a new
        /// submission each time (the Warden's `attempt_no`).
        fn submit(&mut self, c: ChronicleId, r: Submitted) -> Answer {
            use std::sync::atomic::{AtomicU64, Ordering};
            static ATTEMPT: AtomicU64 = AtomicU64::new(1000);
            let e = self.epoch(c);
            let n = ATTEMPT.fetch_add(1, Ordering::Relaxed);
            self.submit_as(c, e, n, r)
        }
        fn submit_as(&mut self, c: ChronicleId, e: Epoch, n: u64, r: Submitted) -> Answer {
            let s = sub(&r, e, n);
            if let Err(a) = self
                .log
                .announce(c, e, s, r.logical_id(), r.digest(), self.now)
            {
                return a;
            }
            let pack = format!("p{}", self.now);
            self.store.ship(c, &pack, &r);
            let head = self.head(c);
            self.log
                .accept(c, e, s, head, &pack, r, self.store, self.now)
        }
        fn ok(&mut self, c: ChronicleId, r: ContractRecord) -> u64 {
            match self.submit(c, Submitted::Contract(r)) {
                Answer::Accepted { log_pos, .. } => log_pos,
                other => panic!("not accepted: {other:?}"),
            }
        }
        fn refused(&mut self, c: ChronicleId, r: ContractRecord) -> Final {
            match self.submit(c, Submitted::Contract(r)) {
                Answer::FinalRefused(f) => f,
                other => panic!("not refused: {other:?}"),
            }
        }
    }

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
    fn peer() -> Peer {
        Peer { uid: 1000, pid: 7 }
    }
    fn cfg() -> Config {
        Config {
            announce_ttl: 600,
            deleted_quarantine: 7 * 86400,
        }
    }
    fn pname(end: u64, base: u64, to: u64) -> String {
        format!("{end:020}-{base:020}-{to:020}")
    }

    /// T0 by genesis: claim, start, ready.  Its layer is `h(0x30)`.
    fn genesis_t0(w: &mut W) -> ChronicleId {
        let g = GenesisStarted {
            genesis_id: genesis_id(h(0x20), h(0x21), TRANSFORM_VERSION, None, "jarmo"),
            source_key: h(0x20),
            consistency: Consistency::Immutable,
            classmap_key: h(0x21),
            transform_version: TRANSFORM_VERSION,
            hook_waiver: None,
            authority: auth(),
            peer: peer(),
        };
        let t0 = g.genesis_id;
        for k in [0x20, 0x21, 0x30, 0x31] {
            w.store.put(ObjectId::content(h(k)));
        }
        w.log.claim_chronicle(t0, ClaimAuthority::Genesis).unwrap();
        w.ok(t0, ContractRecord::GenesisStarted(Box::new(g)));
        w.ok(t0, genesis_ready(t0));
        t0
    }

    fn genesis_ready(t0: ChronicleId) -> ContractRecord {
        ContractRecord::TemplateReady(Box::new(TemplateReady {
            template_id: t0,
            parent_template: None,
            born_from: BornFrom::Genesis { genesis_id: t0 },
            layer: h(0x30),
            output_manifest_key: h(0x31),
            classmap_key: h(0x21),
            vconf_key: None,
            authority: auth(),
        }))
    }

    /// A Vessel V with two fs packs, and its Candidate's objects in the store.
    struct Fix {
        t0: ChronicleId,
        v: ChronicleId,
        k: Candidate,
    }

    fn vessel(w: &mut W) -> Fix {
        let t0 = genesis_t0(w);
        let v = cid(0x0A);
        w.log.claim_chronicle(v, ClaimAuthority::Vessel).unwrap();
        // Born from T0: a Birth with T0 registered holds, no liveness.
        let packs = [pname(6, 0, 6), pname(9, 6, 9)];
        w.store.closure.borrow_mut().insert(
            *v.as_bytes(),
            packs.iter().map(|n| ObjectId::pack(v, n)).collect(),
        );
        w.store.fs.borrow_mut().insert(
            *v.as_bytes(),
            packs
                .iter()
                .enumerate()
                .map(|(i, n)| InventoryItem {
                    pack: PackRef {
                        name: n.clone(),
                        digest: h(0x50 + i as u8),
                    },
                    sections: vec![Lsn::new(if i == 0 { 6 } else { 9 })],
                    log_digest: h(0x60 + i as u8),
                    frames: FrameRange {
                        first: Lsn::new(if i == 0 { 1 } else { 7 }),
                        last: Lsn::new(if i == 0 { 6 } else { 9 }),
                    },
                    form: ReplacementForm::LogOnly,
                })
                .collect(),
        );
        for n in &packs {
            w.store.put(ObjectId::pack(v, n));
        }
        for k in 0x40..0x46 {
            w.store.put(ObjectId::content(h(k)));
        }
        let req = VerifierRequirement {
            template: t0,
            vconf_key: h(0x45),
            version: 1,
        };
        let exclude: BTreeSet<_> = [crate::contract::PathClass::Scratch].into_iter().collect();
        let facts = Facts {
            input: ClassCounts {
                source: 3,
                scratch: 2,
                ..Default::default()
            },
            excluded: ClassCounts {
                scratch: 2,
                ..Default::default()
            },
            open_obligations: 0,
            effects_adopted: 0,
            ledger_lsn: Lsn::new(9),
            requirement: req,
        };
        let k = Candidate {
            candidate_id: candidate_id(v, h(0x09), &exclude, h(0x41), TRANSFORM_VERSION, &req),
            chronicle: v,
            seal: SealRef {
                lsn: Lsn::new(9),
                hash: h(0x09),
            },
            exclude,
            transform_version: TRANSFORM_VERSION,
            classmap_key: h(0x41),
            input_manifest_key: h(0x42),
            output_manifest_key: h(0x43),
            artifact_key: h(0x44),
            requirement: req,
            facts,
            facts_hash: facts_hash(&facts),
            nominated_by: NominatedBy::Agent,
            nominated_at: Lsn::new(10),
        };
        Fix { t0, v, k }
    }

    fn started(k: &Candidate, at: u64) -> VerificationStarted {
        VerificationStarted {
            candidate_id: k.candidate_id,
            attempt_id: attempt_id(k.candidate_id, Lsn::new(at)),
            artifact_key: k.artifact_key,
            requirement: k.requirement,
            started_at: Lsn::new(at),
        }
    }

    fn finished(st: &VerificationStarted, code: u32) -> VerificationFinished {
        let out = b"out".to_vec();
        let od = output_digest(&out);
        let outcome = Outcome::Exit { code };
        VerificationFinished {
            attempt_id: st.attempt_id,
            outcome,
            output_digest: od,
            output: out,
            result_digest: result_digest(
                st.candidate_id,
                st.artifact_key,
                &st.requirement,
                st.attempt_id,
                &outcome,
                od,
            ),
            finished_at: Lsn::new(st.started_at.get() + 1),
        }
    }

    fn verdict(k: &Candidate, f: &VerificationFinished, d: Decision) -> VerdictSubmitted {
        let mut r = VerdictRequest {
            request_id: HashVal::GENESIS,
            candidate_id: k.candidate_id,
            facts_hash: k.facts_hash,
            artifact_key: k.artifact_key,
            requirement: k.requirement,
            exclude: k.exclude.clone(),
            attempt_id: f.attempt_id,
            result_digest: f.result_digest,
            decision: d,
            authority: auth(),
            policy_digest: None,
        };
        r.request_id = request_id(peer().uid, OpKind::Verdict, &r.body());
        VerdictSubmitted {
            request: r,
            peer: peer(),
        }
    }

    fn commit(
        k: &Candidate,
        f: &VerificationFinished,
        v: &VerdictSubmitted,
        t0: ChronicleId,
    ) -> SanctionCommitted {
        let vl = ContractRecord::VerdictSubmitted(Box::new(v.clone())).logical_id();
        SanctionCommitted {
            candidate_id: k.candidate_id,
            template_id: template_id(k.candidate_id, vl),
            parent_template: Some(t0),
            artifact_key: k.artifact_key,
            output_manifest_key: k.output_manifest_key,
            classmap_key: k.classmap_key,
            vconf_key: k.requirement.vconf_key,
            attempt_id: f.attempt_id,
            result_digest: f.result_digest,
            verdict: vl,
        }
    }

    fn ready(s: &SanctionCommitted, source: ChronicleId) -> ContractRecord {
        ContractRecord::TemplateReady(Box::new(TemplateReady {
            template_id: s.template_id,
            parent_template: s.parent_template,
            born_from: BornFrom::Sanction {
                source,
                candidate_id: s.candidate_id,
                verdict: s.verdict,
            },
            layer: s.artifact_key,
            output_manifest_key: s.output_manifest_key,
            classmap_key: s.classmap_key,
            vconf_key: Some(s.vconf_key),
            authority: auth(),
        }))
    }

    /// Candidate, a passing attempt, a Sanction verdict: ready to commit.
    fn to_verdict(w: &mut W, f: &Fix) -> (VerificationFinished, VerdictSubmitted) {
        w.ok(f.v, ContractRecord::Candidate(Box::new(f.k.clone())));
        let st = started(&f.k, 11);
        w.ok(f.v, ContractRecord::VerificationStarted(st));
        let fin = finished(&st, 0);
        w.ok(f.v, ContractRecord::VerificationFinished(fin.clone()));
        let vd = verdict(&f.k, &fin, Decision::Sanction);
        w.ok(f.v, ContractRecord::VerdictSubmitted(Box::new(vd.clone())));
        (fin, vd)
    }

    fn purge_inventory(w: &mut W, v: ChronicleId) -> (PurgeCommitted, Inventory) {
        let inv = Inventory::new(w.log.purge_projection(v, w.store)).unwrap();
        w.store
            .inventories
            .borrow_mut()
            .insert(*inv.key().as_bytes(), inv.clone());
        w.store.put(ObjectId::content(h(0x70)));
        (
            PurgeCommitted {
                chronicle: v,
                cutoff: crate::contract::Cutoff {
                    seal: SealRef {
                        lsn: Lsn::new(9),
                        hash: h(9),
                    },
                    fs_shipped: Lsn::new(10),
                },
                inventory_key: inv.key(),
                local_key: h(0x70),
            },
            inv,
        )
    }

    /// Replace and delete every item, accepting each step.
    fn finish_purge(w: &mut W, v: ChronicleId, inv: &Inventory) {
        for it in inv.items() {
            let rname = replacement_name(&it.pack.name).unwrap();
            w.store.put(ObjectId::pack(v, &rname));
            w.store
                .replacements
                .borrow_mut()
                .insert((*v.as_bytes(), rname.clone()), h(0xB0));
            w.ok(
                v,
                ContractRecord::ReplacementInstalled(ReplacementInstalled {
                    chronicle: v,
                    pack: it.pack.clone(),
                    replacement_key: h(0xB0),
                    replacement_name: rname,
                }),
            );
            w.store.del(&ObjectId::pack(v, &it.pack.name));
        }
        w.ok(
            v,
            ContractRecord::PurgeComplete(PurgeComplete {
                chronicle: v,
                inventory_key: inv.key(),
                items_replaced: inv.items().len() as u64,
                history_attestation: h(0xC0),
            }),
        );
    }

    // ── the full loop ───────────────────────────────────────────────

    #[test]
    fn sanction_then_purge_of_the_source_keeps_the_template() {
        let store = Store::default();
        let mut log = CoordLog::new(cfg());
        let mut w = W {
            log: &mut log,
            store: &store,
            now: 100,
        };
        let f = vessel(&mut w);
        assert!(w.log.is_template(f.t0));
        let (fin, vd) = to_verdict(&mut w, &f);
        let s = commit(&f.k, &fin, &vd, f.t0);
        w.ok(f.v, ContractRecord::SanctionCommitted(s));
        // The source cannot retire while the sanction is open.
        let (pc, _) = purge_inventory(&mut w, f.v);
        assert_eq!(
            w.refused(f.v, ContractRecord::PurgeCommitted(pc)),
            Final::Predicate("open sanction")
        );
        // Finish: claim the target by the commit's authority, then ready.
        let commit_lid = ContractRecord::SanctionCommitted(s).logical_id();
        w.log
            .claim_chronicle(
                s.template_id,
                ClaimAuthority::Sanction { commit: commit_lid },
            )
            .unwrap();
        w.ok(s.template_id, ready(&s, f.v));
        assert!(w.log.is_template(s.template_id));
        w.ok(
            f.v,
            ContractRecord::SanctionCompleted {
                template_id: s.template_id,
            },
        );
        // The artifact is the Template's now.
        assert_eq!(
            w.log.holders(&ObjectId::content(s.artifact_key)),
            vec![s.template_id]
        );
        // The source retires; its packs are the inventory; the Template stays.
        let (pc, inv) = purge_inventory(&mut w, f.v);
        assert_eq!(inv.items().len(), 2);
        w.ok(f.v, ContractRecord::PurgeCommitted(pc));
        assert!(w.log.query_chronicle(f.v).unwrap().retired);
        finish_purge(&mut w, f.v, &inv);
        assert_eq!(
            w.log.holders(&ObjectId::content(s.artifact_key)),
            vec![s.template_id]
        );
        assert!(
            w.log
                .query_chronicle(f.v)
                .unwrap()
                .holds
                .iter()
                .all(|o| matches!(o, ObjectId::Pack(_, n) if n.ends_with(&format!("{:020}", 0)))),
            "only the replacements stay held"
        );
    }

    // ── §10.3 traces ────────────────────────────────────────────────

    /// Announce → lose node → fence → resubmit: exactly one commitment.
    #[test]
    fn trace_announce_lose_node_fence_resubmit() {
        let store = Store::default();
        let mut log = CoordLog::new(cfg());
        let mut w = W {
            log: &mut log,
            store: &store,
            now: 100,
        };
        let f = vessel(&mut w);
        let (fin, vd) = to_verdict(&mut w, &f);
        let s = Submitted::Contract(ContractRecord::SanctionCommitted(commit(
            &f.k, &fin, &vd, f.t0,
        )));
        let e1 = w.epoch(f.v);
        let s1 = sub(&s, e1, 0);
        w.log
            .announce(f.v, e1, s1, s.logical_id(), s.digest(), 100)
            .unwrap();
        // The node is lost; another Warden fences.
        let e2 = w.log.fence(f.v).unwrap();
        assert_eq!(
            w.log.query_submission(f.v, s1),
            SubmissionStatus::FinalRefused(Final::Expired)
        );
        // The old submission arriving late is refused, whatever it carries.
        let head = w.head(f.v);
        store.ship(f.v, "late", &s);
        assert_eq!(
            w.log
                .accept(f.v, e1, s1, head, "late", s.clone(), &store, 101),
            Answer::FinalRefused(Final::Expired)
        );
        // A new submission of the same logical id under the new epoch.
        let a = w.submit_as(f.v, e2, 0, s.clone());
        assert!(matches!(a, Answer::Accepted { .. }));
        // And a third try is AlreadyAccepted: one logical commitment.
        let e3 = w.log.fence(f.v).unwrap();
        assert!(matches!(
            w.submit_as(f.v, e3, 0, s),
            Answer::AlreadyAccepted { .. }
        ));
    }

    /// A delayed accept after a negative query: cancelled, then refused.
    #[test]
    fn trace_delayed_accept_after_a_negative_query() {
        let store = Store::default();
        let mut log = CoordLog::new(cfg());
        let mut w = W {
            log: &mut log,
            store: &store,
            now: 100,
        };
        let f = vessel(&mut w);
        let r = Submitted::Contract(ContractRecord::Candidate(Box::new(f.k.clone())));
        let e = w.epoch(f.v);
        let s1 = sub(&r, e, 0);
        w.log
            .announce(f.v, e, s1, r.logical_id(), r.digest(), 100)
            .unwrap();
        assert_eq!(
            w.log.query_submission(f.v, s1),
            SubmissionStatus::AbsentAtRead
        );
        // Conflicting work is blocked by the pending guard.
        let other = Submitted::Contract(ContractRecord::PurgeDeferred(
            crate::contract::PurgeDeferred {
                chronicle: f.v,
                checked_at: Lsn::new(1),
                reason: crate::contract::DeferReason::RetentionPin,
            },
        ));
        assert!(matches!(
            w.log.announce(
                f.v,
                e,
                sub(&other, e, 0),
                other.logical_id(),
                other.digest(),
                100
            ),
            Err(Answer::Refused(Transient::Pending { .. }))
        ));
        assert_eq!(
            w.log.cancel(f.v, e, s1),
            Answer::FinalRefused(Final::Cancelled)
        );
        store.ship(f.v, "late", &r);
        let head = w.head(f.v);
        assert_eq!(
            w.log
                .accept(f.v, e, s1, head, "late", r.clone(), &store, 101),
            Answer::FinalRefused(Final::Cancelled)
        );
        // The logical operation is still possible: a new submission.
        assert!(matches!(w.submit_as(f.v, e, 1, r), Answer::Accepted { .. }));
    }

    /// Reclamation and a new hold are ordered by the log.
    #[test]
    fn trace_reclaim_races_a_new_hold() {
        let store = Store::default();
        let mut log = CoordLog::new(cfg());
        let mut w = W {
            log: &mut log,
            store: &store,
            now: 100,
        };
        let f = vessel(&mut w);
        let op = cid(0xEE);
        w.log.claim_chronicle(op, ClaimAuthority::Vessel).unwrap();
        // Reclaim first: the Candidate that would hold the artifact is refused.
        w.ok(
            op,
            ContractRecord::ReclaimClaimed {
                object_key: f.k.artifact_key,
            },
        );
        assert_eq!(
            w.refused(f.v, ContractRecord::Candidate(Box::new(f.k.clone()))),
            Final::Claimed(ObjectId::content(f.k.artifact_key))
        );
        // Hold first: a reclaim of a held object is refused.
        assert_eq!(
            w.refused(
                op,
                ContractRecord::ReclaimClaimed {
                    object_key: h(0x30)
                }
            ),
            Final::Predicate("held"),
            "T0's layer is held by T0"
        );
        // After deletion the key is quarantined.
        store.del(&ObjectId::content(f.k.artifact_key));
        w.ok(
            op,
            ContractRecord::ReclaimComplete {
                object_key: f.k.artifact_key,
                outcome: crate::contract::ReclaimOutcome::Deleted,
            },
        );
        store.put(ObjectId::content(f.k.artifact_key));
        let mut k2 = f.k.clone();
        k2.nominated_at = Lsn::new(99);
        assert_eq!(
            w.refused(f.v, ContractRecord::Candidate(Box::new(k2))),
            Final::Quarantined(ObjectId::content(f.k.artifact_key))
        );
    }

    /// Several holds of one Chronicle on K are released together; an
    /// external hold keeps K out of the inventory.
    #[test]
    fn trace_external_hold_keeps_a_pack_out_of_the_inventory() {
        let store = Store::default();
        let mut log = CoordLog::new(cfg());
        let mut w = W {
            log: &mut log,
            store: &store,
            now: 100,
        };
        let f = vessel(&mut w);
        w.ok(f.v, ContractRecord::Candidate(Box::new(f.k.clone())));
        let first = pname(6, 0, 6);
        assert_eq!(
            w.log.holders(&ObjectId::pack(f.v, &first)),
            vec![f.v],
            "V's Candidate holds it"
        );
        assert_eq!(
            w.log.purge_projection(f.v, &store).len(),
            2,
            "V's own holds do not count"
        );
        // A fork of V (not a Template) holds V's first pack.
        let fork = cid(0x0F);
        w.log.claim_chronicle(fork, ClaimAuthority::Vessel).unwrap();
        store
            .closure
            .borrow_mut()
            .insert(*f.v.as_bytes(), vec![ObjectId::pack(f.v, &first)]);
        let birth = Submitted::Birth {
            chronicle: fork,
            lineage: LineageRecord {
                origin: Origin::Fork {
                    parent: ParentSeal {
                        chronicle: f.v,
                        seal: Lsn::new(6),
                        seal_hash: h(6),
                    },
                },
                namespace: Namespace::from_bytes([1; 16]),
                ledger_pos: Lsn::new(0),
            },
        };
        assert!(matches!(w.submit(fork, birth), Answer::Accepted { .. }));
        let proj = w.log.purge_projection(f.v, &store);
        assert_eq!(proj.len(), 1, "the forked pack is not V's to delete");
        assert_ne!(proj[0].pack.name, first);
        // And V cannot retire while the fork is open (a liveness dependency).
        let (pc, _) = purge_inventory(&mut w, f.v);
        assert_eq!(
            w.refused(f.v, ContractRecord::PurgeCommitted(pc)),
            Final::Predicate("liveness dependency")
        );
    }

    /// A replacement is held from its acceptance, so a stalled purge
    /// cannot lose it to reclamation; and a lost item is never fabricated.
    #[test]
    fn trace_purge_stalls_after_deleting_an_original() {
        let store = Store::default();
        let mut log = CoordLog::new(cfg());
        let mut w = W {
            log: &mut log,
            store: &store,
            now: 100,
        };
        let f = vessel(&mut w);
        let (pc, inv) = purge_inventory(&mut w, f.v);
        w.ok(f.v, ContractRecord::PurgeCommitted(pc));
        let it = &inv.items()[0];
        let rname = replacement_name(&it.pack.name).unwrap();
        store.put(ObjectId::pack(f.v, &rname));
        store
            .replacements
            .borrow_mut()
            .insert((*f.v.as_bytes(), rname.clone()), h(0xB0));
        // A replacement that does not verify to the key is refused.
        assert_eq!(
            w.refused(
                f.v,
                ContractRecord::ReplacementInstalled(ReplacementInstalled {
                    chronicle: f.v,
                    pack: it.pack.clone(),
                    replacement_key: h(0xBB),
                    replacement_name: rname.clone(),
                })
            ),
            Final::Predicate("replacement does not match the inventory")
        );
        w.ok(
            f.v,
            ContractRecord::ReplacementInstalled(ReplacementInstalled {
                chronicle: f.v,
                pack: it.pack.clone(),
                replacement_key: h(0xB0),
                replacement_name: rname.clone(),
            }),
        );
        store.del(&ObjectId::pack(f.v, &it.pack.name));
        // ... stall: the replacement stays held.
        assert_eq!(w.log.holders(&ObjectId::pack(f.v, &rname)), vec![f.v]);
        // The second item: the original is still readable, so it is not lost.
        let it2 = inv.items()[1].clone();
        let lost = ContractRecord::ItemLost(ItemLost {
            chronicle: f.v,
            pack: it2.pack.clone(),
        });
        assert_eq!(
            w.refused(f.v, lost.clone()),
            Final::Predicate("original or replacement readable")
        );
        // Gone with no replacement: lost; then the purge ends damaged, never complete.
        store.del(&ObjectId::pack(f.v, &it2.pack.name));
        w.ok(
            f.v,
            ContractRecord::ItemLost(ItemLost {
                chronicle: f.v,
                pack: it2.pack.clone(),
            }),
        );
        assert_eq!(
            w.refused(
                f.v,
                ContractRecord::PurgeComplete(PurgeComplete {
                    chronicle: f.v,
                    inventory_key: inv.key(),
                    items_replaced: 1,
                    history_attestation: h(0xC0),
                })
            ),
            Final::Predicate("history damaged")
        );
        w.ok(
            f.v,
            ContractRecord::PurgeDamaged(crate::contract::PurgeDamaged {
                chronicle: f.v,
                inventory_key: inv.key(),
                items_replaced: 1,
                items_lost: 1,
            }),
        );
    }

    /// An accepted genesis survives its node: takeover by its
    /// GenesisStarted, then TemplateReady from the new epoch.
    #[test]
    fn trace_genesis_and_finisher_lose_their_node() {
        let store = Store::default();
        let mut log = CoordLog::new(cfg());
        let mut w = W {
            log: &mut log,
            store: &store,
            now: 100,
        };
        let g = GenesisStarted {
            genesis_id: genesis_id(h(0x20), h(0x21), TRANSFORM_VERSION, None, "jarmo"),
            source_key: h(0x20),
            consistency: Consistency::BestEffort,
            classmap_key: h(0x21),
            transform_version: TRANSFORM_VERSION,
            hook_waiver: None,
            authority: auth(),
            peer: peer(),
        };
        let t0 = g.genesis_id;
        for k in [0x20, 0x21, 0x30, 0x31] {
            store.put(ObjectId::content(h(k)));
        }
        let e1 = w.log.claim_chronicle(t0, ClaimAuthority::Genesis).unwrap();
        w.ok(t0, ContractRecord::GenesisStarted(Box::new(g)));
        // Lost node; another one takes over by the accepted operation.
        assert_eq!(
            w.log.claim_chronicle(t0, ClaimAuthority::Genesis),
            Err(ClaimError::AlreadyClaimed { epoch: e1 })
        );
        assert_eq!(
            w.log.takeover_target(t0, ClaimAuthority::Genesis, e1),
            Err(ClaimError::BadAuthority)
        );
        let (e2, _) = w
            .log
            .takeover_target(t0, ClaimAuthority::GenesisStarted, e1)
            .unwrap();
        // The old owner is fenced.
        let r = Submitted::Contract(genesis_ready(t0));
        assert_eq!(
            w.submit_as(t0, e1, 0, r.clone()),
            Answer::FinalRefused(Final::StaleEpoch)
        );
        assert!(matches!(w.submit_as(t0, e2, 0, r), Answer::Accepted { .. }));

        // A sanction finisher lost after claiming the empty target.
        let f = {
            let v = cid(0x0A);
            w.log.claim_chronicle(v, ClaimAuthority::Vessel).unwrap();
            let mut fx = vessel_like(&mut w, t0, v);
            fx.t0 = t0;
            fx
        };
        let (fin, vd) = to_verdict(&mut w, &f);
        let s = commit(&f.k, &fin, &vd, f.t0);
        w.ok(f.v, ContractRecord::SanctionCommitted(s));
        let lid = ContractRecord::SanctionCommitted(s).logical_id();
        let wrong = ClaimAuthority::Sanction { commit: h(0x99) };
        assert_eq!(
            w.log.claim_chronicle(s.template_id, wrong),
            Err(ClaimError::BadAuthority)
        );
        let ea = w
            .log
            .claim_chronicle(s.template_id, ClaimAuthority::Sanction { commit: lid })
            .unwrap();
        // ... that node is lost.  Another takes over by the same authority.
        let (eb, head) = w
            .log
            .takeover_target(s.template_id, ClaimAuthority::Sanction { commit: lid }, ea)
            .unwrap();
        assert_eq!(head, Head::EMPTY);
        assert_eq!(
            w.log
                .takeover_target(s.template_id, ClaimAuthority::Sanction { commit: lid }, ea),
            Err(ClaimError::EpochMoved { epoch: eb }),
            "takeover is conditional"
        );
        let r = Submitted::Contract(ready(&s, f.v));
        assert_eq!(
            w.submit_as(s.template_id, ea, 0, r.clone()),
            Answer::FinalRefused(Final::StaleEpoch)
        );
        assert!(matches!(
            w.submit_as(s.template_id, eb, 0, r),
            Answer::Accepted { .. }
        ));
    }

    /// `vessel()` without its own genesis: a Vessel `v` verified by `t0`.
    fn vessel_like(w: &mut W, t0: ChronicleId, v: ChronicleId) -> Fix {
        let store = Store::default();
        let mut tmp = CoordLog::new(cfg());
        let mut w2 = W {
            log: &mut tmp,
            store: &store,
            now: 0,
        };
        let mut fx = vessel(&mut w2);
        // Re-point the fixture at the real log's T0 and Vessel.
        let req = VerifierRequirement {
            template: t0,
            ..fx.k.requirement
        };
        fx.k.requirement = req;
        fx.k.facts.requirement = req;
        fx.k.chronicle = v;
        fx.k.facts_hash = facts_hash(&fx.k.facts);
        fx.k.candidate_id = candidate_id(
            v,
            fx.k.seal.hash,
            &fx.k.exclude,
            fx.k.classmap_key,
            fx.k.transform_version,
            &req,
        );
        for k in 0x40..0x46 {
            w.store.put(ObjectId::content(h(k)));
        }
        fx.v = v;
        fx
    }

    // ── predicates ──────────────────────────────────────────────────

    #[test]
    fn a_commit_needs_a_sanction_verdict_and_a_passing_last_attempt() {
        let store = Store::default();
        let mut log = CoordLog::new(cfg());
        let mut w = W {
            log: &mut log,
            store: &store,
            now: 100,
        };
        let f = vessel(&mut w);
        w.ok(f.v, ContractRecord::Candidate(Box::new(f.k.clone())));
        let st = started(&f.k, 11);
        w.ok(f.v, ContractRecord::VerificationStarted(st));
        // An attempt is open: no second one.
        assert_eq!(
            w.refused(f.v, ContractRecord::VerificationStarted(started(&f.k, 12))),
            Final::Predicate("an attempt is open")
        );
        let fin = finished(&st, 0);
        w.ok(f.v, ContractRecord::VerificationFinished(fin.clone()));
        // A Hold verdict does not authorise a commit.
        let hold = verdict(&f.k, &fin, Decision::Hold);
        w.ok(
            f.v,
            ContractRecord::VerdictSubmitted(Box::new(hold.clone())),
        );
        assert_eq!(
            w.refused(
                f.v,
                ContractRecord::SanctionCommitted(commit(&f.k, &fin, &hold, f.t0))
            ),
            Final::Predicate("no Sanction verdict for this attempt")
        );
        // A later attempt that fails blocks the earlier pass.
        let st2 = started(&f.k, 20);
        w.ok(f.v, ContractRecord::VerificationStarted(st2));
        w.ok(f.v, ContractRecord::VerificationFinished(finished(&st2, 1)));
        let vd = verdict(&f.k, &fin, Decision::Sanction);
        w.ok(f.v, ContractRecord::VerdictSubmitted(Box::new(vd.clone())));
        assert_eq!(
            w.refused(
                f.v,
                ContractRecord::SanctionCommitted(commit(&f.k, &fin, &vd, f.t0))
            ),
            Final::Predicate("a later attempt failed")
        );
    }

    #[test]
    fn hard_rules_and_obligations_refuse_a_commit() {
        let store = Store::default();
        let mut log = CoordLog::new(cfg());
        let mut w = W {
            log: &mut log,
            store: &store,
            now: 100,
        };
        let mut f = vessel(&mut w);
        f.k.facts.input.secret = 1;
        f.k.facts_hash = facts_hash(&f.k.facts);
        let (fin, vd) = to_verdict(&mut w, &f);
        assert_eq!(
            w.refused(
                f.v,
                ContractRecord::SanctionCommitted(commit(&f.k, &fin, &vd, f.t0))
            ),
            Final::Predicate("hard rules")
        );

        let store = Store::default();
        let mut log = CoordLog::new(cfg());
        let mut w = W {
            log: &mut log,
            store: &store,
            now: 100,
        };
        let f = vessel(&mut w);
        let (fin, vd) = to_verdict(&mut w, &f);
        w.log.note_obligation(f.v, 5, true);
        let s = ContractRecord::SanctionCommitted(commit(&f.k, &fin, &vd, f.t0));
        assert_eq!(
            w.refused(f.v, s.clone()),
            Final::Predicate("open obligation")
        );
        // A refused submission reserves nothing: once settled, a new one is accepted.
        w.log.note_obligation(f.v, 5, false);
        let e = w.epoch(f.v);
        assert!(matches!(
            w.submit_as(f.v, e, 1, Submitted::Contract(s)),
            Answer::Accepted { .. }
        ));
    }

    #[test]
    fn a_purge_refused_for_an_obligation_succeeds_after_it_settles() {
        let store = Store::default();
        let mut log = CoordLog::new(cfg());
        let mut w = W {
            log: &mut log,
            store: &store,
            now: 100,
        };
        let f = vessel(&mut w);
        w.ok(f.v, ContractRecord::Candidate(Box::new(f.k.clone())));
        w.log.note_obligation(f.v, 1, true);
        let (pc, inv) = purge_inventory(&mut w, f.v);
        assert_eq!(
            w.refused(f.v, ContractRecord::PurgeCommitted(pc)),
            Final::Predicate("open obligation")
        );
        w.log.note_obligation(f.v, 1, false);
        let e = w.epoch(f.v);
        let r = Submitted::Contract(ContractRecord::PurgeCommitted(pc));
        assert!(matches!(w.submit_as(f.v, e, 1, r), Answer::Accepted { .. }));
        // One atomic transition: retired, holds released, Candidate closed, claims held.
        let view = w.log.query_chronicle(f.v).unwrap();
        assert!(view.retired);
        assert!(view.holds.is_empty());
        for it in inv.items() {
            assert!(w.log.is_claimed(&ObjectId::pack(f.v, &it.pack.name)));
        }
        assert_eq!(
            w.refused(
                f.v,
                ContractRecord::CandidateClosed(CandidateClosed {
                    candidate_id: f.k.candidate_id,
                    how: CloseKind::Cancelled { authority: auth() },
                })
            ),
            Final::Predicate("Candidate not open"),
            "closed by the purge"
        );
        finish_purge(&mut w, f.v, &inv);
        for it in inv.items() {
            assert!(
                !w.log.is_claimed(&ObjectId::pack(f.v, &it.pack.name)),
                "resolved"
            );
        }
    }

    #[test]
    fn an_inventory_that_is_not_the_projection_is_refused() {
        let store = Store::default();
        let mut log = CoordLog::new(cfg());
        let mut w = W {
            log: &mut log,
            store: &store,
            now: 100,
        };
        let f = vessel(&mut w);
        let full = w.log.purge_projection(f.v, &store);
        let short = Inventory::new(full[..1].to_vec()).unwrap();
        store
            .inventories
            .borrow_mut()
            .insert(*short.key().as_bytes(), short.clone());
        store.put(ObjectId::content(h(0x70)));
        let pc = PurgeCommitted {
            chronicle: f.v,
            cutoff: crate::contract::Cutoff {
                seal: SealRef {
                    lsn: Lsn::new(9),
                    hash: h(9),
                },
                fs_shipped: Lsn::new(10),
            },
            inventory_key: short.key(),
            local_key: h(0x70),
        };
        assert_eq!(
            w.refused(f.v, ContractRecord::PurgeCommitted(pc)),
            Final::Predicate("inventory mismatch")
        );
    }

    #[test]
    fn a_late_result_from_a_fenced_verifier_is_refused() {
        let store = Store::default();
        let mut log = CoordLog::new(cfg());
        let mut w = W {
            log: &mut log,
            store: &store,
            now: 100,
        };
        let f = vessel(&mut w);
        w.ok(f.v, ContractRecord::Candidate(Box::new(f.k.clone())));
        let st = started(&f.k, 11);
        w.ok(f.v, ContractRecord::VerificationStarted(st));
        let e1 = w.epoch(f.v);
        let e2 = w.log.fence(f.v).unwrap();
        // The new owner closes the attempt as interrupted.
        let mut intr = finished(&st, 0);
        intr.outcome = Outcome::Interrupted;
        intr.result_digest = result_digest(
            st.candidate_id,
            st.artifact_key,
            &st.requirement,
            st.attempt_id,
            &intr.outcome,
            intr.output_digest,
        );
        assert!(matches!(
            w.submit_as(
                f.v,
                e2,
                0,
                Submitted::Contract(ContractRecord::VerificationFinished(intr))
            ),
            Answer::Accepted { .. }
        ));
        // The old process's Exit 0 under its stale epoch: refused (§10.2).
        let late = Submitted::Contract(ContractRecord::VerificationFinished(finished(&st, 0)));
        assert_eq!(
            w.submit_as(f.v, e1, 0, late.clone()),
            Answer::FinalRefused(Final::StaleEpoch)
        );
        // Even sent straight to accept, the logical id is taken.
        store.ship(f.v, "late", &late);
        let head = w.head(f.v);
        assert_eq!(
            w.log
                .accept(f.v, e1, sub(&late, e1, 1), head, "late", late, &store, 100),
            Answer::FinalRefused(Final::Conflict)
        );
    }

    #[test]
    fn head_readability_and_announce_are_checked() {
        let store = Store::default();
        let mut log = CoordLog::new(cfg());
        let mut w = W {
            log: &mut log,
            store: &store,
            now: 100,
        };
        let f = vessel(&mut w);
        let r = Submitted::Contract(ContractRecord::Candidate(Box::new(f.k.clone())));
        let e = w.epoch(f.v);
        let s = sub(&r, e, 0);
        // Not announced.
        store.ship(f.v, "p", &r);
        let head = w.head(f.v);
        assert_eq!(
            w.log.accept(f.v, e, s, head, "p", r.clone(), &store, 100),
            Answer::FinalRefused(Final::NotAnnounced)
        );
        let s = sub(&r, e, 1);
        w.log
            .announce(f.v, e, s, r.logical_id(), r.digest(), 100)
            .unwrap();
        // Not readable: transient; the submission stays pending.
        assert_eq!(
            w.log
                .accept(f.v, e, s, head, "missing", r.clone(), &store, 100),
            Answer::Refused(Transient::NotReadable)
        );
        // Head moved: transient.
        let wrong = Head {
            pos: 99,
            digest: h(1),
        };
        assert!(matches!(
            w.log.accept(f.v, e, s, wrong, "p", r.clone(), &store, 100),
            Answer::Refused(Transient::HeadMoved { .. })
        ));
        // Expired after announce.ttl.
        assert_eq!(
            w.log
                .accept(f.v, e, s, head, "p", r.clone(), &store, 100 + 601),
            Answer::FinalRefused(Final::Expired)
        );
        // Still possible as a new submission.
        w.now = 800;
        assert!(matches!(w.submit_as(f.v, e, 2, r), Answer::Accepted { .. }));
    }

    #[test]
    fn records_name_their_own_chronicle_and_objects_must_exist() {
        let store = Store::default();
        let mut log = CoordLog::new(cfg());
        let mut w = W {
            log: &mut log,
            store: &store,
            now: 100,
        };
        let f = vessel(&mut w);
        let other = cid(0x0B);
        w.log
            .claim_chronicle(other, ClaimAuthority::Vessel)
            .unwrap();
        assert_eq!(
            w.refused(other, ContractRecord::Candidate(Box::new(f.k.clone()))),
            Final::Predicate("not this Chronicle's record")
        );
        store.del(&ObjectId::content(f.k.artifact_key));
        assert_eq!(
            w.refused(f.v, ContractRecord::Candidate(Box::new(f.k.clone()))),
            Final::NoSuchObject(ObjectId::content(f.k.artifact_key))
        );
        let mut bad = f.k.clone();
        bad.facts.open_obligations = 9;
        store.put(ObjectId::content(f.k.artifact_key));
        assert_eq!(
            w.refused(f.v, ContractRecord::Candidate(Box::new(bad))),
            Final::Predicate("inconsistent record")
        );
        let _ = object_key(ObjectKind::Pack, b"");
    }
}
