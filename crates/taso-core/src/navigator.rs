//! Navigator: is resuming from a Seal consistent with recorded evidence?
//! (v0.4 §6, v1.0 §9.4).
//!
//! Navigator reads records only.  It proves presence and never infers
//! absence: anything it cannot establish from the accepted prefix is
//! `Insufficient`, never `Consistent`.  It does not and cannot establish
//! current external validity; that is enforced at the point of use
//! (v0.4 §7.6).
//!
//! Inputs are split by trust.  `records` is the log as storage returns it
//! and is untrusted: every record is verified and chained.  [`Anchor`] is
//! what the coordinator holds (anchored head, ownership) and is trusted.
//!
//! # Open at S (stricter than v0.4 §7.4's wording)
//!
//! A barrier intent is *settled at S* only if both the intent and its
//! terminal outcome are at or before `S.ledger_pos`.  Every other barrier
//! intent is *open at S*.  §7.4 literally counts only barriers after
//! `S.ledger_pos`; that misses an intent recorded before the cut whose
//! outcome lands after it, where the effect was applied but S's state
//! does not know.  Resuming from S could repeat it, so it is open.
//!
//! # Unresolved outcomes are `Insufficient`, not `Inconsistent`
//!
//! An open intent whose latest state is not terminal (no outcome,
//! `DispatchAuthorized`, `OutcomeUnknown`) is
//! [`Reason::MissingOutcome`].  Rebirth after a crash during dispatch must
//! proceed inspect-only and reconcile (v0.4 §7.2); making it
//! `Inconsistent` would refuse it.  [`Mode::AmbiguousOutcome`] is kept for
//! evidence that contradicts itself.
//!
//! # Not produced by the P0 model
//!
//! [`Mode::StaleDependency`], [`Mode::Nondeterministic`],
//! [`Mode::AuthorizationDrift`], [`Reason::HeadUnanchored`] and
//! [`Reason::UnknownFootprintOverlap`] are part of the frozen contract but
//! need records the model does not have yet (verify results, transcript
//! replayability, revocations in `ctl`, branches).  Policy hash and
//! sibling-branch barriers are out of scope here.

use std::collections::BTreeMap;

use crate::envelope::{ChronicleHead, ChronicleId, HashVal, Lsn, Stream};
use crate::model::{Coordinator, Ownership};
use crate::record::{
    BarrierId, Consequence, GroupId, IntentRecord, Member, OpId,
    OutcomeState, Payload, Record, SealRecord, StreamCut, TaintKind, Verdict,
};

// ── Anchor ─────────────────────────────────────────────────────────

/// The trusted input: what the coordinator anchors for a Chronicle.
#[derive(Clone, Debug)]
pub struct Anchor {
    /// The Chronicle the records must belong to.
    pub chronicle: ChronicleId,
    /// The coordinator's anchored head (the authority, v0.4 §8.3).
    pub head: ChronicleHead,
    /// Current ownership, including the sealed prefix.
    pub ownership: Ownership,
}

impl Anchor {
    /// Read the anchor from a coordinator.
    pub fn of(coord: &Coordinator) -> Self {
        Self {
            chronicle: coord.chronicle(),
            head: coord.head(),
            ownership: coord.ownership().clone(),
        }
    }
}

// ── Result types ───────────────────────────────────────────────────

/// What the caller must discharge before effect authority is granted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObligationKind {
    /// The effect already happened: tell the resumed Vessel so, and refuse
    /// re-dispatch of the same op (v0.4 §7.4).  Compensation instead of
    /// suppression is a policy choice, not a Navigator verdict.
    Suppress,
}

/// A barrier open at S that the caller must discharge.
///
/// Distinct from `adapter::Obligation`, which reports `UnsafeToRetry`
/// intents left open by reconciliation; those surface here as
/// [`Reason::MissingOutcome`].  The two are to be unified later.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Obligation {
    /// The operation.
    pub op: OpId,
    /// Its barrier.
    pub barrier: BarrierId,
    /// What discharging it means.
    pub kind: ObligationKind,
}

/// A structural fault in the state or the chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StateFault {
    /// A record fails verification, is out of sequence, belongs to another
    /// Chronicle, or breaks the `prev` link.
    ChainBroken {
        /// The first position that failed.
        lsn: Lsn,
    },
    /// The records do not reach the head.
    HeadNotReached,
    /// No Seal record at the requested position.
    SealMissing,
    /// A cut position or `ledger_pos` does not point at an earlier record
    /// on its own stream.
    CutInvalid,
    /// An intent or outcome outside the effect stream.
    MisplacedRecord {
        /// Where it is.
        lsn: Lsn,
    },
    /// A group in the cut has no commit record before the Seal.
    GroupUncommitted(GroupId),
    /// A group is only partly inside the cut.
    GroupSplit(GroupId),
    /// A group in the cut depends on a group not committed before the Seal.
    GroupDependencyOpen {
        /// The group in the cut.
        gid: GroupId,
        /// The dependency that is open.
        dep: GroupId,
    },
    /// The Seal's own verdict says the state is tainted.
    Tainted(TaintKind),
}

/// Why the authority of the inputs is invalid.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorityFault {
    /// The supplied head is not the coordinator's anchored head.
    HeadMismatch,
    /// The Seal belongs to a fenced epoch's unsealed region.
    FencedEpoch,
}

/// A provable inconsistency (v0.4 §6, modes 1–7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// 1. A cut is missing, a record fails the chain, or a group in the
    ///    cut is uncommitted or causally open.
    IncompleteState(StateFault),
    /// 2. A dependency S reads has changed.  Not produced by the P0 model.
    StaleDependency,
    /// 3. Non-replayable transcript records after S.  Not produced by the
    ///    P0 model.
    Nondeterministic,
    /// 4. A barrier that cannot be accounted for: an irreversible or
    ///    compensatable intent with no barrier id (`Some(op)`), or a Seal
    ///    tainted by a barrier violation (`None`).
    UnaccountedBarrier(Option<OpId>),
    /// 5. The ledger contradicts itself for this op: an outcome without an
    ///    intent, an outcome before its intent, a duplicate intent, or
    ///    conflicting terminal outcomes.
    AmbiguousOutcome(OpId),
    /// 6. The head or the Seal's epoch is not authoritative.
    InvalidAuthority(AuthorityFault),
    /// 7. An authority used after S is revoked or expired.  Not produced
    ///    by the P0 model.
    AuthorizationDrift,
}

/// Why the evidence is not enough to decide (v0.4 §6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reason {
    /// The Seal is unverified; the string is its stated reason.
    MissingVerification(String),
    /// A barrier open at S has no terminal outcome.
    MissingOutcome(OpId),
    /// The head cannot be checked against an anchor.  Not produced by the
    /// P0 model.
    HeadUnanchored,
    /// Footprint overlap cannot be decided.  Not produced by the P0 model.
    UnknownFootprintOverlap,
}

/// Navigator's answer.  Precedence: `Inconsistent` > `Insufficient` >
/// `Consistent`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Navigation {
    /// Consistent with recorded evidence.  A non-empty obligation list is
    /// the normal case after any external effect; it is not a failure.
    Consistent(Vec<Obligation>),
    /// At least one mode is provable.
    Inconsistent(Vec<Mode>),
    /// No mode is provable, but at least one reason holds.
    Insufficient(Vec<Reason>),
}

impl Navigation {
    /// True only for `Consistent` with no obligations: resuming needs
    /// nothing discharged first.
    pub fn is_clear(&self) -> bool {
        matches!(self, Self::Consistent(o) if o.is_empty())
    }
}

// ── navigate ───────────────────────────────────────────────────────

/// Decide whether resuming from the Seal at `seal` is consistent with
/// the records through `head` (v0.4 §6).
pub fn navigate(
    records: &[Record],
    anchor: &Anchor,
    seal: Lsn,
    head: ChronicleHead,
) -> Navigation {
    // Phase 1: authority and chain.  If either fails, nothing in the
    // records can be trusted, so stop here.
    if head != anchor.head {
        return Navigation::Inconsistent(vec![Mode::InvalidAuthority(
            AuthorityFault::HeadMismatch,
        )]);
    }
    if let Some(fault) = check_chain(records, anchor.chronicle, head) {
        return Navigation::Inconsistent(vec![Mode::IncompleteState(fault)]);
    }
    // check_chain confirmed the records reach the head.
    let prefix = &records[..head.lsn.get() as usize];

    // Phase 2: the Seal.
    let Some((seal_env_epoch, s)) = find_seal(prefix, seal) else {
        return Navigation::Inconsistent(vec![Mode::IncompleteState(
            StateFault::SealMissing,
        )]);
    };

    let mut modes = Vec::new();
    let mut reasons = Vec::new();
    let mut obligations = Vec::new();

    if seal_env_epoch < anchor.ownership.epoch
        && seal > anchor.ownership.sealed_prefix.lsn
    {
        modes.push(Mode::InvalidAuthority(AuthorityFault::FencedEpoch));
    }

    match &s.verdict {
        Verdict::Clean => {}
        Verdict::Unverified(why) => {
            reasons.push(Reason::MissingVerification(why.clone()));
        }
        Verdict::Tainted(TaintKind::BarrierViolation) => {
            modes.push(Mode::UnaccountedBarrier(None));
        }
        Verdict::Tainted(kind) => {
            modes.push(Mode::IncompleteState(StateFault::Tainted(*kind)));
        }
    }

    if check_cut(prefix, seal, s) {
        modes.push(Mode::IncompleteState(StateFault::CutInvalid));
    } else {
        for fault in check_groups(prefix, seal, &s.cut) {
            modes.push(Mode::IncompleteState(fault));
        }
    }

    // Phase 3: the ledger.
    check_ledger(prefix, s.ledger_pos, &mut modes, &mut reasons, &mut obligations);

    if !modes.is_empty() {
        Navigation::Inconsistent(modes)
    } else if !reasons.is_empty() {
        Navigation::Insufficient(reasons)
    } else {
        Navigation::Consistent(obligations)
    }
}

// ── Checks ─────────────────────────────────────────────────────────

/// Verify every record through `head`: in sequence from lsn 1, same
/// Chronicle, `prev` linked, hashes valid, ending exactly at the head.
fn check_chain(
    records: &[Record],
    chronicle: ChronicleId,
    head: ChronicleHead,
) -> Option<StateFault> {
    let mut prev = HashVal::GENESIS;
    for (i, r) in records.iter().enumerate() {
        let expected = Lsn::new(i as u64 + 1);
        if expected > head.lsn {
            break;
        }
        if r.envelope.lsn != expected
            || r.envelope.chronicle != chronicle
            || r.envelope.prev != prev
            || !r.verify()
        {
            return Some(StateFault::ChainBroken { lsn: expected });
        }
        prev = r.envelope.hash;
    }
    let reached = (records.len() as u64) >= head.lsn.get();
    if !reached || prev != head.hash {
        return Some(StateFault::HeadNotReached);
    }
    None
}

/// The Seal at `seal`, with the epoch it was written under.
fn find_seal(prefix: &[Record], seal: Lsn) -> Option<(crate::envelope::Epoch, &SealRecord)> {
    let i = seal.get().checked_sub(1)? as usize;
    let r = prefix.get(i)?;
    match &r.payload {
        Payload::Seal(s) => Some((r.envelope.epoch, s)),
        _ => None,
    }
}

/// True if a cut position or `ledger_pos` is invalid: it must be zero, or
/// point at a record before the Seal on its own stream.
fn check_cut(prefix: &[Record], seal: Lsn, s: &SealRecord) -> bool {
    let positions = [
        (Stream::Fs, s.cut.fs),
        (Stream::Db, s.cut.db),
        (Stream::Transcript, s.cut.transcript),
        (Stream::Effect, s.ledger_pos),
    ];
    positions.iter().any(|&(stream, lsn)| {
        lsn.get() != 0
            && (lsn >= seal
                || prefix[lsn.get() as usize - 1].envelope.stream != stream)
    })
}

/// True if a member falls inside the cut.
fn in_cut(cut: &StreamCut, m: &Member) -> bool {
    let limit = match m.stream {
        Stream::Fs => cut.fs,
        Stream::Db => cut.db,
        Stream::Transcript => cut.transcript,
        Stream::Effect | Stream::Ctl => return false,
    };
    m.lsn.get() != 0 && m.lsn <= limit
}

/// Everything known about one group across its records.
#[derive(Default)]
struct GroupInfo {
    members: Vec<Member>,
    depends_on: Vec<GroupId>,
    /// Position of the first commit record, if any.
    commit: Option<Lsn>,
}

/// Every group touching the cut must be committed before the Seal, lie
/// wholly inside the cut, and depend only on groups committed before the
/// Seal (causal closure, v0.4 §5.1).
fn check_groups(prefix: &[Record], seal: Lsn, cut: &StreamCut) -> Vec<StateFault> {
    let mut groups: BTreeMap<GroupId, GroupInfo> = BTreeMap::new();
    for r in prefix {
        if let Payload::Group(g) = &r.payload {
            let info = groups.entry(g.gid).or_default();
            info.members.extend_from_slice(&g.members);
            info.depends_on.extend_from_slice(&g.depends_on);
            if g.commit && info.commit.is_none() {
                info.commit = Some(r.envelope.lsn);
            }
        }
    }
    let committed_before_seal =
        |info: Option<&GroupInfo>| info.and_then(|i| i.commit).is_some_and(|l| l < seal);

    let mut faults = Vec::new();
    for (&gid, info) in &groups {
        if !info.members.iter().any(|m| in_cut(cut, m)) {
            continue;
        }
        if !committed_before_seal(Some(info)) {
            faults.push(StateFault::GroupUncommitted(gid));
            continue;
        }
        if !info.members.iter().all(|m| in_cut(cut, m)) {
            faults.push(StateFault::GroupSplit(gid));
        }
        for &dep in &info.depends_on {
            if !committed_before_seal(groups.get(&dep)) {
                faults.push(StateFault::GroupDependencyOpen { gid, dep });
            }
        }
    }
    faults
}

/// What the ledger says about one op.
#[derive(Default)]
struct OpTrack<'a> {
    intent: Option<(Lsn, &'a IntentRecord)>,
    duplicate_intent: bool,
    outcomes: Vec<(Lsn, OutcomeState)>,
}

const fn is_terminal(s: OutcomeState) -> bool {
    matches!(s, OutcomeState::ConfirmedApplied | OutcomeState::ConfirmedNotApplied)
}

/// Classify every op in the ledger against S.
fn check_ledger(
    prefix: &[Record],
    ledger_pos: Lsn,
    modes: &mut Vec<Mode>,
    reasons: &mut Vec<Reason>,
    obligations: &mut Vec<Obligation>,
) {
    let mut ops: BTreeMap<OpId, OpTrack<'_>> = BTreeMap::new();
    for r in prefix {
        let lsn = r.envelope.lsn;
        let misplaced = r.envelope.stream != Stream::Effect;
        match &r.payload {
            Payload::Intent(i) => {
                if misplaced {
                    modes.push(Mode::IncompleteState(StateFault::MisplacedRecord { lsn }));
                }
                let t = ops.entry(i.op).or_default();
                if t.intent.is_some() {
                    t.duplicate_intent = true;
                } else {
                    t.intent = Some((lsn, i));
                }
            }
            Payload::Outcome(o) => {
                if misplaced {
                    modes.push(Mode::IncompleteState(StateFault::MisplacedRecord { lsn }));
                }
                ops.entry(o.op).or_default().outcomes.push((lsn, o.state));
            }
            _ => {}
        }
    }

    for (&op, t) in &ops {
        let Some((intent_lsn, intent)) = t.intent else {
            modes.push(Mode::AmbiguousOutcome(op));
            continue;
        };
        if t.duplicate_intent || t.outcomes.iter().any(|&(l, _)| l < intent_lsn) {
            modes.push(Mode::AmbiguousOutcome(op));
            continue;
        }

        // The first terminal outcome; anything after it must agree.
        let mut terminal: Option<(Lsn, OutcomeState)> = None;
        let mut contradictory = false;
        for &(l, st) in &t.outcomes {
            match terminal {
                None if is_terminal(st) => terminal = Some((l, st)),
                None => {}
                Some((_, first)) => {
                    if st != first {
                        contradictory = true;
                    }
                }
            }
        }
        if contradictory {
            modes.push(Mode::AmbiguousOutcome(op));
            continue;
        }

        if intent.consequence == Consequence::NoExternalMutation {
            continue;
        }
        let Some(barrier) = intent.barrier else {
            modes.push(Mode::UnaccountedBarrier(Some(op)));
            continue;
        };

        let settled = intent_lsn <= ledger_pos
            && terminal.is_some_and(|(l, _)| l <= ledger_pos);
        if settled {
            continue;
        }
        match terminal.map(|(_, st)| st) {
            Some(OutcomeState::ConfirmedApplied) => obligations.push(Obligation {
                op,
                barrier,
                kind: ObligationKind::Suppress,
            }),
            Some(_) => {} // ConfirmedNotApplied: nothing happened.
            None => reasons.push(Reason::MissingOutcome(op)),
        }
    }
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::{AdapterModel, CrashPoint, FakeProvider};
    use crate::envelope::Epoch;
    use crate::model::{WardenId, WardenModel};
    use crate::record::{
        Dispatch, GroupRecord, LayerRef, OutcomeRecord, RetryPolicy, TurnId,
    };

    fn cid() -> ChronicleId {
        ChronicleId::from_bytes([7; 16])
    }

    /// One Chronicle with its coordinator, Warden, adapter and provider.
    struct Sim {
        coord: Coordinator,
        warden: WardenModel,
        warden_id: WardenId,
        adapter: AdapterModel,
        provider: FakeProvider,
        last_seal: Option<HashVal>,
        turn: u64,
        keys: u64,
    }

    impl Sim {
        fn new() -> Self {
            let id = WardenId::new(1);
            Self {
                coord: Coordinator::new(cid(), id),
                warden: WardenModel::new(id, cid(), Epoch::FIRST),
                warden_id: id,
                adapter: AdapterModel::new(),
                provider: FakeProvider::new(),
                last_seal: None,
                turn: 0,
                keys: 0,
            }
        }

        fn append(&mut self, stream: Stream, payload: Payload) -> Lsn {
            self.warden.append(&mut self.coord, stream, payload).unwrap().lsn
        }

        /// A fresh retry policy: 0 dedup, 1 queryable, 2 unsafe.
        fn retry(&mut self, kind: u8) -> RetryPolicy {
            self.keys += 1;
            let tag = format!("k-{}", self.keys).into_bytes();
            match kind {
                0 => RetryPolicy::ProviderDeduplicated { key: tag },
                1 => RetryPolicy::Queryable { probe: tag },
                _ => RetryPolicy::UnsafeToRetry,
            }
        }

        /// Dispatch one effect; returns its op whether or not it crashed.
        fn effect(
            &mut self,
            retry: RetryPolicy,
            consequence: Consequence,
            crash: Option<CrashPoint>,
        ) -> OpId {
            let _ = self.adapter.dispatch_effect(
                &mut self.warden,
                &mut self.coord,
                &mut self.provider,
                b"mail:alice",
                retry,
                consequence,
                crash,
            );
            self.coord
                .log()
                .iter()
                .rev()
                .find_map(|r| match &r.payload {
                    Payload::Intent(i) => Some(i.op),
                    _ => None,
                })
                .unwrap()
        }

        fn mail(&mut self, crash: Option<CrashPoint>) -> OpId {
            let retry = self.retry(0);
            self.effect(retry, Consequence::Irreversible, crash)
        }

        fn reconcile(&mut self) {
            self.adapter
                .reconcile(&mut self.warden, &mut self.coord, &mut self.provider)
                .unwrap();
        }

        /// Transfer ownership to the other Warden and reconcile (v0.4 §8.4).
        fn rebirth(&mut self) {
            let next = WardenId::new(if self.warden_id.get() == 1 { 2 } else { 1 });
            let epoch = self.coord.transfer(next);
            let head = self.coord.head();
            self.warden = WardenModel::resume(next, cid(), epoch, head, head.lsn.next());
            self.warden_id = next;
            self.adapter = AdapterModel::resume(&self.coord);
            self.reconcile();
        }

        /// One fs write and its group record.
        fn fs_group(&mut self, gid: u64, depends_on: Vec<GroupId>, commit: bool) {
            let lsn = self.append(Stream::Fs, Payload::Raw(b"fs-write".to_vec()));
            self.append(
                Stream::Fs,
                Payload::Group(GroupRecord {
                    gid: GroupId::new(gid),
                    members: vec![Member { stream: Stream::Fs, lsn }],
                    depends_on,
                    commit,
                }),
            );
        }

        fn seal(&mut self) -> Lsn {
            self.seal_with(Verdict::Clean)
        }

        /// A Seal cutting every state stream at its current end, with
        /// `ledger_pos` at the last effect record.
        fn seal_with(&mut self, verdict: Verdict) -> Lsn {
            let mut cut = StreamCut::EMPTY;
            let mut ledger_pos = Lsn::new(0);
            for r in self.coord.log() {
                let l = r.envelope.lsn;
                match r.envelope.stream {
                    Stream::Fs => cut.fs = l,
                    Stream::Db => cut.db = l,
                    Stream::Transcript => cut.transcript = l,
                    Stream::Effect => ledger_pos = l,
                    Stream::Ctl => {}
                }
            }
            self.turn += 1;
            let rec = SealRecord {
                parent: self.last_seal,
                cut,
                layer: LayerRef::new(self.turn),
                verdict,
                ledger_pos,
                turn: TurnId::new(self.turn),
            };
            let head = self
                .warden
                .append(&mut self.coord, Stream::Ctl, Payload::Seal(rec))
                .unwrap();
            self.last_seal = Some(head.hash);
            head.lsn
        }

        fn nav(&self, seal: Lsn) -> Navigation {
            self.nav_records(self.coord.log(), seal)
        }

        fn nav_records(&self, records: &[Record], seal: Lsn) -> Navigation {
            navigate(records, &Anchor::of(&self.coord), seal, self.coord.head())
        }
    }

    fn suppress(op: OpId, barrier: u64) -> Obligation {
        Obligation { op, barrier: BarrierId::new(barrier), kind: ObligationKind::Suppress }
    }

    fn intent(op: u64, consequence: Consequence, barrier: Option<u64>) -> Payload {
        Payload::Intent(IntentRecord {
            op: OpId::new(op),
            request: Vec::new(),
            provider: String::new(),
            footprint: b"pay:bob".to_vec(),
            dispatch: Dispatch::Immediate,
            retry: RetryPolicy::UnsafeToRetry,
            consequence,
            authority: b"lease".to_vec(),
            barrier: barrier.map(BarrierId::new),
        })
    }

    fn outcome(op: u64, state: OutcomeState) -> Payload {
        Payload::Outcome(OutcomeRecord { op: OpId::new(op), state, evidence: None })
    }

    /// A copy of the log with the first raw record's payload replaced.
    fn tampered(log: &[Record]) -> (Vec<Record>, Lsn) {
        let mut copy = log.to_vec();
        let r = copy
            .iter_mut()
            .find(|r| matches!(r.payload, Payload::Raw(_)))
            .unwrap();
        r.payload = Payload::Raw(b"tampered".to_vec());
        let lsn = r.envelope.lsn;
        (copy, lsn)
    }

    // ── The first ten labelled Chronicles ──────────────────────────

    #[test]
    fn chronicle_01_empty_genesis_seal() {
        let mut sim = Sim::new();
        let s = sim.seal();
        assert_eq!(sim.nav(s), Navigation::Consistent(vec![]));
    }

    #[test]
    fn chronicle_02_effect_settled_before_seal() {
        let mut sim = Sim::new();
        sim.mail(None);
        let s = sim.seal();
        assert_eq!(sim.nav(s), Navigation::Consistent(vec![]));
    }

    #[test]
    fn chronicle_03_irreversible_applied_after_seal() {
        let mut sim = Sim::new();
        let s = sim.seal();
        let op = sim.mail(None);
        assert_eq!(sim.nav(s), Navigation::Consistent(vec![suppress(op, 1)]));
    }

    #[test]
    fn chronicle_04_mail_duplication_before_reconcile() {
        let mut sim = Sim::new();
        let s = sim.seal();
        let op = sim.mail(Some(CrashPoint::DuringDispatchReceived));
        assert_eq!(sim.provider.effect_count(op), 1);
        assert_eq!(sim.nav(s), Navigation::Insufficient(vec![Reason::MissingOutcome(op)]));
    }

    #[test]
    fn chronicle_05_mail_duplication_after_reconcile() {
        let mut sim = Sim::new();
        let s = sim.seal();
        let op = sim.mail(Some(CrashPoint::DuringDispatchReceived));
        sim.reconcile();
        assert_eq!(sim.provider.effect_count(op), 1, "reconcile must not duplicate");
        assert_eq!(sim.nav(s), Navigation::Consistent(vec![suppress(op, 1)]));
    }

    #[test]
    fn chronicle_06_payment_timeout_stays_insufficient() {
        let mut sim = Sim::new();
        let s = sim.seal();
        let op = sim.effect(
            RetryPolicy::UnsafeToRetry,
            Consequence::Irreversible,
            Some(CrashPoint::DuringDispatchReceived),
        );
        sim.reconcile();
        assert_eq!(sim.nav(s), Navigation::Insufficient(vec![Reason::MissingOutcome(op)]));
        // Rebirth reconciles again; still no trusted outcome, no re-dispatch.
        sim.rebirth();
        assert_eq!(sim.nav(s), Navigation::Insufficient(vec![Reason::MissingOutcome(op)]));
        assert_eq!(sim.provider.effect_count(op), 1);
    }

    #[test]
    fn chronicle_07_crash_after_intent_reconciled_not_applied() {
        let mut sim = Sim::new();
        let s = sim.seal();
        let op = sim.mail(Some(CrashPoint::AfterIntent));
        assert_eq!(sim.nav(s), Navigation::Insufficient(vec![Reason::MissingOutcome(op)]));
        sim.reconcile();
        assert_eq!(sim.provider.effect_count(op), 0);
        assert_eq!(sim.nav(s), Navigation::Consistent(vec![]));
    }

    #[test]
    fn chronicle_08_intent_before_seal_outcome_after() {
        let mut sim = Sim::new();
        let op = sim.mail(Some(CrashPoint::AfterDispatch));
        let s = sim.seal();
        sim.reconcile();
        // The intent is at or before ledger_pos: §7.4's literal rule would
        // ignore it and answer Consistent([]) although the mail was sent.
        let Payload::Seal(seal) = &sim.coord.log()[s.get() as usize - 1].payload else {
            unreachable!()
        };
        let intent_lsn = sim.coord.log().iter().find(|r| matches!(r.payload, Payload::Intent(_))).unwrap().envelope.lsn;
        assert!(intent_lsn <= seal.ledger_pos);
        assert_eq!(sim.provider.effect_count(op), 1);
        assert_eq!(sim.nav(s), Navigation::Consistent(vec![suppress(op, 1)]));
    }

    #[test]
    fn chronicle_09_tampered_record_in_prefix() {
        let mut sim = Sim::new();
        sim.mail(None);
        sim.fs_group(1, vec![], true);
        let s = sim.seal();
        sim.mail(None);
        let (log, lsn) = tampered(sim.coord.log());
        assert_eq!(
            sim.nav_records(&log, s),
            Navigation::Inconsistent(vec![Mode::IncompleteState(StateFault::ChainBroken { lsn })]),
        );
    }

    #[test]
    fn chronicle_10_uncommitted_group_in_cut() {
        let mut sim = Sim::new();
        sim.fs_group(1, vec![], false);
        let s = sim.seal();
        assert_eq!(
            sim.nav(s),
            Navigation::Inconsistent(vec![Mode::IncompleteState(StateFault::GroupUncommitted(
                GroupId::new(1)
            ))]),
        );
    }

    // ── Further cases ──────────────────────────────────────────────

    #[test]
    fn committed_group_in_cut_is_consistent() {
        let mut sim = Sim::new();
        sim.fs_group(1, vec![], true);
        sim.fs_group(2, vec![GroupId::new(1)], true);
        let s = sim.seal();
        assert_eq!(sim.nav(s), Navigation::Consistent(vec![]));
    }

    #[test]
    fn group_with_open_dependency() {
        let mut sim = Sim::new();
        sim.fs_group(2, vec![GroupId::new(3)], true);
        let s = sim.seal();
        assert_eq!(
            sim.nav(s),
            Navigation::Inconsistent(vec![Mode::IncompleteState(StateFault::GroupDependencyOpen {
                gid: GroupId::new(2),
                dep: GroupId::new(3),
            })]),
        );
    }

    #[test]
    fn stale_head_is_invalid_authority() {
        let mut sim = Sim::new();
        let s = sim.seal();
        let stale = sim.coord.head();
        sim.mail(None);
        let nav = navigate(sim.coord.log(), &Anchor::of(&sim.coord), s, stale);
        assert_eq!(
            nav,
            Navigation::Inconsistent(vec![Mode::InvalidAuthority(AuthorityFault::HeadMismatch)]),
        );
    }

    #[test]
    fn seal_in_fenced_region() {
        let mut sim = Sim::new();
        sim.append(Stream::Transcript, Payload::Raw(b"t".to_vec()));
        let s = sim.seal();
        // An anchor whose last transfer sealed the prefix before the Seal.
        let mut anchor = Anchor::of(&sim.coord);
        anchor.ownership.epoch = Epoch::new(2);
        anchor.ownership.sealed_prefix.lsn = Lsn::new(1);
        let nav = navigate(sim.coord.log(), &anchor, s, sim.coord.head());
        assert_eq!(
            nav,
            Navigation::Inconsistent(vec![Mode::InvalidAuthority(AuthorityFault::FencedEpoch)]),
        );
    }

    #[test]
    fn position_that_is_not_a_seal() {
        let mut sim = Sim::new();
        let lsn = sim.append(Stream::Transcript, Payload::Raw(b"t".to_vec()));
        sim.seal();
        assert_eq!(
            sim.nav(lsn),
            Navigation::Inconsistent(vec![Mode::IncompleteState(StateFault::SealMissing)]),
        );
    }

    #[test]
    fn irreversible_intent_without_barrier() {
        let mut sim = Sim::new();
        let s = sim.seal();
        sim.append(Stream::Effect, intent(9, Consequence::Irreversible, None));
        sim.append(Stream::Effect, outcome(9, OutcomeState::ConfirmedApplied));
        assert_eq!(
            sim.nav(s),
            Navigation::Inconsistent(vec![Mode::UnaccountedBarrier(Some(OpId::new(9)))]),
        );
    }

    #[test]
    fn contradictory_terminal_outcomes() {
        let mut sim = Sim::new();
        let s = sim.seal();
        sim.append(Stream::Effect, intent(9, Consequence::Irreversible, Some(1)));
        sim.append(Stream::Effect, outcome(9, OutcomeState::ConfirmedApplied));
        sim.append(Stream::Effect, outcome(9, OutcomeState::ConfirmedNotApplied));
        assert_eq!(
            sim.nav(s),
            Navigation::Inconsistent(vec![Mode::AmbiguousOutcome(OpId::new(9))]),
        );
    }

    #[test]
    fn outcome_without_intent() {
        let mut sim = Sim::new();
        let s = sim.seal();
        sim.append(Stream::Effect, outcome(9, OutcomeState::ConfirmedApplied));
        assert_eq!(
            sim.nav(s),
            Navigation::Inconsistent(vec![Mode::AmbiguousOutcome(OpId::new(9))]),
        );
    }

    #[test]
    fn unverified_seal_is_insufficient() {
        let mut sim = Sim::new();
        let s = sim.seal_with(Verdict::Unverified("dropped groups".into()));
        assert_eq!(
            sim.nav(s),
            Navigation::Insufficient(vec![Reason::MissingVerification("dropped groups".into())]),
        );
    }

    #[test]
    fn tainted_seal_is_inconsistent() {
        let mut sim = Sim::new();
        let s = sim.seal_with(Verdict::Tainted(TaintKind::BarrierViolation));
        assert_eq!(sim.nav(s), Navigation::Inconsistent(vec![Mode::UnaccountedBarrier(None)]));
        let s = sim.seal_with(Verdict::Tainted(TaintKind::GroupIncomplete));
        assert_eq!(
            sim.nav(s),
            Navigation::Inconsistent(vec![Mode::IncompleteState(StateFault::Tainted(
                TaintKind::GroupIncomplete
            ))]),
        );
    }

    #[test]
    fn inconsistent_takes_precedence_over_insufficient() {
        let mut sim = Sim::new();
        sim.append(Stream::Transcript, Payload::Raw(b"t".to_vec()));
        let s = sim.seal();
        sim.mail(Some(CrashPoint::DuringDispatchReceived));
        sim.append(Stream::Effect, outcome(99, OutcomeState::ConfirmedApplied));
        assert!(matches!(sim.nav(s), Navigation::Inconsistent(_)));
    }

    #[test]
    fn seal_before_rebirth_still_navigable() {
        let mut sim = Sim::new();
        let s = sim.seal();
        let op = sim.mail(Some(CrashPoint::AfterDispatchAuth));
        sim.rebirth();
        assert_eq!(sim.provider.effect_count(op), 1);
        assert_eq!(sim.nav(s), Navigation::Consistent(vec![suppress(op, 1)]));
    }

    // ── Soundness ──────────────────────────────────────────────────

    mod prop {
        use super::*;
        use proptest::prelude::*;
        use std::collections::HashSet;

        #[derive(Clone, Debug)]
        enum Step {
            Effect { retry: u8, compensatable: bool, crash: Option<CrashPoint> },
            Seal,
            Reconcile,
            Rebirth,
            State,
        }

        fn crash() -> impl Strategy<Value = Option<CrashPoint>> {
            prop_oneof![
                5 => Just(None),
                1 => Just(Some(CrashPoint::AfterIntent)),
                1 => Just(Some(CrashPoint::AfterDispatchAuth)),
                1 => Just(Some(CrashPoint::DuringDispatchNotReceived)),
                1 => Just(Some(CrashPoint::DuringDispatchReceived)),
                1 => Just(Some(CrashPoint::AfterDispatch)),
            ]
        }

        fn step() -> impl Strategy<Value = Step> {
            prop_oneof![
                4 => (0u8..3, any::<bool>(), crash()).prop_map(|(retry, compensatable, crash)| {
                    Step::Effect { retry, compensatable, crash }
                }),
                3 => Just(Step::Seal),
                1 => Just(Step::Reconcile),
                1 => Just(Step::Rebirth),
                2 => Just(Step::State),
            ]
        }

        proptest! {
            #![proptest_config(ProptestConfig { cases: 10_000, ..ProptestConfig::default() })]

            /// Navigator never returns `Consistent([])` where a duplicate
            /// effect is possible, every `Consistent` answer suppresses
            /// every applied effect S does not know about, and an honest
            /// Chronicle is never `Inconsistent`.
            ///
            /// Ground truth comes from the harness, not from lsn
            /// arithmetic: an op is *known at S* if its outcome was
            /// delivered (dispatch returned, or reconcile resolved it)
            /// before S was taken.
            #[test]
            fn navigator_soundness(steps in proptest::collection::vec(step(), 1..40)) {
                let mut sim = Sim::new();
                let mut known: HashSet<OpId> = HashSet::new();
                // Crashed ops not yet resolved: op → (retry kind, crash point).
                let mut pending: BTreeMap<OpId, (u8, CrashPoint)> = BTreeMap::new();
                let mut barrier_ops: Vec<OpId> = Vec::new();
                let mut seals: Vec<(Lsn, HashSet<OpId>)> = Vec::new();
                let mut gid = 0u64;

                let resolve = |pending: &mut BTreeMap<OpId, (u8, CrashPoint)>, known: &mut HashSet<OpId>| {
                    pending.retain(|op, &mut (kind, at)| {
                        let resolved = kind != 2 || at == CrashPoint::AfterIntent;
                        if resolved { known.insert(*op); }
                        !resolved
                    });
                };

                for s in &steps {
                    match s {
                        Step::Effect { retry, compensatable, crash } => {
                            let policy = sim.retry(*retry);
                            let consequence = if *compensatable {
                                Consequence::Compensatable { by: OpId::new(0) }
                            } else {
                                Consequence::Irreversible
                            };
                            let op = sim.effect(policy, consequence, *crash);
                            barrier_ops.push(op);
                            match crash {
                                None => { known.insert(op); }
                                Some(at) => { pending.insert(op, (*retry, *at)); }
                            }
                        }
                        Step::Seal => {
                            let lsn = sim.seal();
                            seals.push((lsn, known.clone()));
                        }
                        Step::Reconcile => {
                            sim.reconcile();
                            resolve(&mut pending, &mut known);
                        }
                        Step::Rebirth => {
                            sim.rebirth();
                            resolve(&mut pending, &mut known);
                        }
                        Step::State => {
                            gid += 1;
                            sim.fs_group(gid, vec![], true);
                        }
                    }
                }

                prop_assert!(sim.provider.no_duplicates(), "duplicate provider effect");

                for (seal, known_at_s) in &seals {
                    let nav = sim.nav(*seal);
                    prop_assert!(
                        !matches!(nav, Navigation::Inconsistent(_)),
                        "honest Chronicle judged inconsistent at {:?}: {:?}", seal, nav,
                    );
                    let danger: Vec<OpId> = barrier_ops
                        .iter()
                        .copied()
                        .filter(|op| sim.provider.effect_count(*op) > 0 && !known_at_s.contains(op))
                        .collect();
                    if !danger.is_empty() {
                        prop_assert!(!nav.is_clear(), "Consistent([]) at {:?} but {:?} applied and unknown", seal, danger);
                    }
                    if let Navigation::Consistent(obligations) = &nav {
                        for op in &danger {
                            prop_assert!(
                                obligations.iter().any(|o| o.op == *op && o.kind == ObligationKind::Suppress),
                                "{:?} applied and unknown at {:?} but not suppressed: {:?}", op, seal, obligations,
                            );
                        }
                    }
                }
            }
        }
    }
}
