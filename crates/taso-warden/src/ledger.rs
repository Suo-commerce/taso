//! The effect ledger: the storage half of the effect engine (v0.4
//! §7.2–7.4).
//!
//! Taso keeps the record of every effect a Vessel asks for; it never
//! decides whether to send one and never sends one.  This is the
//! transactional outbox: the ledger holds the outgoing request durably,
//! with the state it belongs to, and whoever is outside sends what the
//! ledger has released (P3, 2026-10-22: no adapter and no sender live in
//! this repository; `docs/relay.md` is the sender's contract).
//!
//! # What the ledger guarantees
//!
//! - **Intent before release.**  [`Ledger::release`] appends the
//!   `Intent` (with the exact request bytes, as the caller declared it)
//!   and `DispatchAuthorized` in one write, one fsync, one CAS.  Both or
//!   neither are accepted.  The barrier is the intent's own lsn unless
//!   the consequence is `NoExternalMutation`.
//! - **Held, not released.**  A Vessel that may not release effects (a
//!   fork, unless its entry says otherwise) records the same intent with
//!   `Proposed` instead ([`Ledger::propose`]): durable, shipped with the
//!   rest, never an obligation, and never released by that Vessel.  Its
//!   parent may adopt it ([`Ledger::adopt`]): a released intent of the
//!   parent's own, with a new op id, whose `authority` names the child,
//!   its Seal and the child's op ([`AdoptedFrom`]).
//! - **Off the node before anything is sent.**
//!   [`Ledger::ship_before_send`] publishes the ledger up to its tail
//!   ([`Publish`]): shipped and recorded as the coordinator's shipped
//!   anchor.  If that fails, `ConfirmedNotApplied` ("ledger not shipped")
//!   is recorded and the caller must not send.  An effect whose
//!   authorization exists only on this node could not be reconciled by
//!   another node that takes the Vessel over.
//! - **Every answer recorded.**  [`Ledger::record`]: `ConfirmedApplied`,
//!   `ConfirmedNotApplied` or `OutcomeUnknown`.  An unknown outcome on a
//!   barrier intent withdraws effect authority.
//! - **Reconciliation before authority.**  [`Ledger::open`] walks every
//!   intent whose latest outcome is not terminal, in op order.  One never
//!   authorized (a crash after the intent) is `ConfirmedNotApplied` here:
//!   it was never authorized, so it never happened.  One authorized or
//!   unknown is handed to the caller's `settle`, which may probe, ship
//!   and re-send through this ledger, or leave it open
//!   ([`Ledger::mark_unknown`]).  A barrier intent left open is an
//!   obligation; authority is granted only when there are none.
//! - **A human in the recovery path, by design (v0.4 §14).**
//!   [`Ledger::resolve`]: an operator, with a reason, records what really
//!   happened to an open effect.

use std::collections::{BTreeMap, BTreeSet};

use taso_core::canon::Canonical;
use taso_core::envelope::{ChronicleId, Epoch, Lsn, Stream};
use taso_core::record::{
    Authority, BarrierId, Consequence, Dispatch, IntentRecord, OpId, OutcomeRecord, OutcomeState,
    Payload, RetryPolicy,
};

use crate::chronicle::{ChronicleError, Layers};
use crate::segment::{Position, Segment};
use crate::vessel::{Vessel, VesselError};

/// What reconciliation did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Reconciled {
    /// Intents settled to a terminal outcome now.
    pub settled: Vec<OpId>,
    /// Barrier intents still open: obligations an operator must resolve.
    pub open: Vec<OpId>,
}

// ── Publishing ──────────────────────────────────────────────────────

/// Why the ledger could not be published.  Whatever the cause (the store,
/// a coordinator refusal, an unknown coordinator outcome), nothing is sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishError(pub String);

impl std::fmt::Display for PublishError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for PublishError {}

/// Makes the ledger durable off the node before anything is sent.
///
/// The real one is [`crate::pack::PackPublisher`].  There is deliberately
/// no implementation that skips publishing outside tests: a Warden that
/// cannot ship cannot send.
pub trait Publish {
    /// Ship every accepted record of `chronicle` up to `upto` (which is
    /// accepted: at or below the anchored head) from its local `segments`
    /// (oldest first), then record `upto` as the
    /// coordinator's shipped anchor under `epoch`.  `Ok` only when both
    /// are done.
    fn publish(
        &mut self,
        chronicle: ChronicleId,
        epoch: Epoch,
        segments: &[&Segment],
        upto: Position,
    ) -> Result<(), PublishError>;
}

/// Publishes nothing and always succeeds.  Tests only: there is no such
/// thing outside them.
#[cfg(test)]
pub(crate) struct AlwaysPublish;

#[cfg(test)]
impl Publish for AlwaysPublish {
    fn publish(
        &mut self,
        _: ChronicleId,
        _: Epoch,
        _: &[&Segment],
        _: Position,
    ) -> Result<(), PublishError> {
        Ok(())
    }
}

// ── Types ───────────────────────────────────────────────────────────

/// An effect as the caller declares it: everything its intent records
/// except the op id and the barrier, which the ledger assigns.  Taso
/// records the declaration; whether it is honest is the caller's policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Declared {
    /// The provider that will send it (a namespace to the ledger), and
    /// re-issues or probes it after a crash.
    pub provider: String,
    /// The exact request that will be sent.
    pub request: Vec<u8>,
    /// Canonical resource set (opaque).
    pub footprint: Vec<u8>,
    /// Immediate or deferrable.
    pub dispatch: Dispatch,
    /// How it can be retried after a crash.
    pub retry: RetryPolicy,
    /// What it does to the world.
    pub consequence: Consequence,
    /// Which credential or lease permits it (a name, opaque).
    pub authority: Vec<u8>,
}

/// Where an adopted intent came from: written as the parent's
/// `authority`, so every released effect traces back to the proposal it
/// was (canonical bytes, [`AdoptedFrom::canon_bytes`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdoptedFrom {
    /// The child that proposed it.
    pub child: ChronicleId,
    /// The child's Seal the promotion was made at.
    pub seal: Lsn,
    /// The child's op id of the proposal.
    pub op: OpId,
}

impl Canonical for AdoptedFrom {
    fn canon(&self, out: &mut taso_core::canon::Canon) {
        self.child.canon(out);
        self.seal.canon(out);
        self.op.canon(out);
    }
}

/// An effect the ledger has released (or, from [`Ledger::propose`], held).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Authorized {
    /// Its op id.
    pub op: OpId,
    /// Its barrier: the intent's own lsn, unless the consequence is
    /// `NoExternalMutation`.
    pub barrier: Option<BarrierId>,
}

/// What the provider said, as the ledger records it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Answer {
    /// It happened; the receipt is the evidence.
    Applied {
        /// Provider receipt, opaque.
        receipt: Vec<u8>,
    },
    /// It did not happen.
    NotApplied {
        /// Why.
        reason: String,
    },
    /// No answer, or an ambiguous one.
    Unknown,
}

/// An operator's answer for an open effect ([`Ledger::resolve`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Resolution {
    /// It happened: `ConfirmedApplied`.
    Applied,
    /// It did not happen: `ConfirmedNotApplied`.
    NotApplied,
    /// Nobody knows, and the operator closes it anyway:
    /// `AcceptedUnknown` (P4 spec D34).  Never re-issued or probed.
    AcceptedUnknown,
}

impl Resolution {
    /// The outcome state it records.
    pub fn state(self) -> OutcomeState {
        match self {
            Self::Applied => OutcomeState::ConfirmedApplied,
            Self::NotApplied => OutcomeState::ConfirmedNotApplied,
            Self::AcceptedUnknown => OutcomeState::AcceptedUnknown,
        }
    }
}

/// Why an operator resolution was refused.
#[derive(Debug)]
pub enum ResolveError {
    /// No actor or no reason.
    EmptyAuthority,
    /// The effect is not open.
    NotOpen(OpId),
    /// Recording it failed.
    Vessel(VesselError),
}

// ── The ledger ──────────────────────────────────────────────────────

/// The effect ledger of one Vessel.
pub struct Ledger {
    publisher: Box<dyn Publish>,
    next_op: u64,
    /// Open barrier intents: effect authority is withheld while any exist.
    open: BTreeSet<OpId>,
}

impl Ledger {
    /// Open the ledger of an opened Vessel and reconcile it.
    ///
    /// Every intent whose latest outcome is not terminal is visited in op
    /// order.  One never authorized is settled here as
    /// `ConfirmedNotApplied`.  One authorized or unknown goes to `settle`,
    /// which returns `true` if it left the effect terminal (through
    /// [`Ledger::record`]) and `false` if not (through
    /// [`Ledger::mark_unknown`]).  A barrier intent not settled becomes
    /// an open obligation.  `publisher` ships the ledger before every send,
    /// here and later.
    pub fn open<L, F>(
        publisher: Box<dyn Publish>,
        vessel: &mut Vessel<L>,
        mut settle: F,
    ) -> Result<(Self, Reconciled), VesselError>
    where
        L: Layers,
        F: FnMut(
            &mut Self,
            &mut Vessel<L>,
            &IntentRecord,
            Option<OutcomeState>,
        ) -> Result<bool, VesselError>,
    {
        let mut l = Self {
            publisher,
            next_op: 1,
            open: BTreeSet::new(),
        };
        let r = l.reconcile(vessel, &mut settle)?;
        Ok((l, r))
    }

    /// True if effects may be dispatched: no open obligation.
    pub fn authorized(&self) -> bool {
        self.open.is_empty()
    }

    /// Open obligations, in op order.
    pub fn open_obligations(&self) -> Vec<OpId> {
        self.open.iter().copied().collect()
    }

    /// The op id the next [`Ledger::release`] or [`Ledger::propose`] will
    /// assign.  A caller that derives anything from it (a deduplication
    /// key) reads it here first; nothing is consumed until the effect is
    /// recorded.
    pub fn next_op(&self) -> OpId {
        OpId::new(self.next_op)
    }

    /// Record the intent and its release together: one write, one fsync,
    /// one CAS.  A crash during it leaves both or neither accepted.  From
    /// here on a sender may act on it.
    pub fn release<L: Layers>(
        &mut self,
        vessel: &mut Vessel<L>,
        d: &Declared,
    ) -> Result<Authorized, VesselError> {
        self.write(
            vessel,
            d,
            OutcomeState::DispatchAuthorized,
            "effect.release",
        )
    }

    /// Record the intent as a held proposal: `Intent` and `Proposed`
    /// together, one write, one fsync, one CAS.  Durable like a release,
    /// never an obligation, and never released by this Vessel: only its
    /// parent may adopt it.
    pub fn propose<L: Layers>(
        &mut self,
        vessel: &mut Vessel<L>,
        d: &Declared,
    ) -> Result<Authorized, VesselError> {
        self.write(vessel, d, OutcomeState::Proposed, "effect.propose")
    }

    /// Adopt a child's proposals, all in one write, one fsync, one CAS:
    /// every one of them or none, so a promotion is never half adopted.
    /// Each becomes this Vessel's own intent (new op id, own barrier),
    /// with its [`AdoptedFrom`] as `authority`; the request, footprint,
    /// retry and consequence are the child's, unchanged, and the child's
    /// Chronicle is not touched.  Released (`DispatchAuthorized`) if this
    /// Vessel may release effects; held (`Proposed`) again if not, so a
    /// holder's adoption travels up to the Vessel that may.
    pub fn adopt<L: Layers>(
        &mut self,
        vessel: &mut Vessel<L>,
        child: ChronicleId,
        seal: Lsn,
        proposals: &[IntentRecord],
        held: bool,
    ) -> Result<Vec<Authorized>, VesselError> {
        let state = if held {
            OutcomeState::Proposed
        } else {
            OutcomeState::DispatchAuthorized
        };
        let first_op = self.next_op;
        let first_lsn = vessel.tail().lsn.next();
        let mut records = Vec::with_capacity(proposals.len() * 2);
        let mut out = Vec::with_capacity(proposals.len());
        for (i, proposal) in proposals.iter().enumerate() {
            let from = AdoptedFrom {
                child,
                seal,
                op: proposal.op,
            };
            let d = Declared {
                provider: proposal.provider.clone(),
                request: proposal.request.clone(),
                footprint: proposal.footprint.clone(),
                dispatch: proposal.dispatch,
                retry: proposal.retry.clone(),
                consequence: proposal.consequence,
                authority: from.canon_bytes(),
            };
            let op = OpId::new(first_op + i as u64);
            // Each intent lands two records after the previous one.
            let lsn = first_lsn.get() + 2 * i as u64;
            let barrier =
                (d.consequence != Consequence::NoExternalMutation).then(|| BarrierId::new(lsn));
            let a = Authorized { op, barrier };
            records.push((Stream::Effect, Payload::Intent(intent(a, &d))));
            records.push((Stream::Effect, outcome(op, state, None)));
            out.push(a);
        }
        if records.is_empty() {
            return Ok(out);
        }
        let t = crate::timing::span("effect.adopt");
        vessel.append_batch(records)?;
        drop(t);
        self.next_op = first_op + proposals.len() as u64;
        Ok(out)
    }

    fn write<L: Layers>(
        &mut self,
        vessel: &mut Vessel<L>,
        d: &Declared,
        state: OutcomeState,
        span: &'static str,
    ) -> Result<Authorized, VesselError> {
        let a = self.assign(vessel, d);
        let t = crate::timing::span(span);
        vessel.append_batch(vec![
            (Stream::Effect, Payload::Intent(intent(a, d))),
            (Stream::Effect, outcome(a.op, state, None)),
        ])?;
        drop(t);
        Ok(a)
    }

    /// Fault injection, for tests of recovery only: append an intent
    /// without its authorization, as an older Warden that wrote them apart
    /// could leave it.  Reconciliation settles it as never authorized.
    /// Never part of a dispatch.
    #[doc(hidden)]
    pub fn append_intent_alone<L: Layers>(
        &mut self,
        vessel: &mut Vessel<L>,
        d: &Declared,
    ) -> Result<Authorized, VesselError> {
        let a = self.assign(vessel, d);
        vessel.append(Stream::Effect, Payload::Intent(intent(a, d)))?;
        Ok(a)
    }

    /// Before the first send of `a`: publish the ledger up to its tail.
    ///
    /// `Ok(Ok(()))`: shipped; the caller may send.  `Ok(Err(reason))`:
    /// not shipped; `ConfirmedNotApplied` with `reason` is recorded and the
    /// caller must not send.  `Err`: recording that failed.
    pub fn ship_before_send<L: Layers>(
        &mut self,
        vessel: &mut Vessel<L>,
        a: &Authorized,
    ) -> Result<Result<(), String>, VesselError> {
        let t = crate::timing::span("effect.publish");
        let shipped = self.ship(vessel);
        drop(t);
        match shipped {
            Ok(()) => Ok(Ok(())),
            Err(e) => {
                let reason = format!("ledger not shipped: {e}");
                vessel.append(
                    Stream::Effect,
                    outcome(
                        a.op,
                        OutcomeState::ConfirmedNotApplied,
                        Some(reason.clone().into_bytes()),
                    ),
                )?;
                Ok(Err(reason))
            }
        }
    }

    /// Publish the ledger up to the Vessel's tail.  For re-sends during
    /// reconciliation: on failure the caller sends nothing and leaves the
    /// effect open ([`Ledger::mark_unknown`]), because an earlier send may
    /// have happened.
    pub fn ship<L: Layers>(&mut self, vessel: &Vessel<L>) -> Result<(), PublishError> {
        let c = vessel.chronicle();
        self.publisher
            .publish(c.id(), c.epoch(), &c.segments(), c.tail())
    }

    /// Record what the provider said about `op`.  A terminal answer closes
    /// it; an unknown answer on a barrier intent opens an obligation.
    pub fn record<L: Layers>(
        &mut self,
        vessel: &mut Vessel<L>,
        op: OpId,
        barrier: Option<BarrierId>,
        answer: &Answer,
    ) -> Result<(), VesselError> {
        match answer {
            Answer::Applied { receipt } => {
                vessel.append(
                    Stream::Effect,
                    outcome(op, OutcomeState::ConfirmedApplied, Some(receipt.clone())),
                )?;
                self.open.remove(&op);
            }
            Answer::NotApplied { reason } => {
                vessel.append(
                    Stream::Effect,
                    outcome(
                        op,
                        OutcomeState::ConfirmedNotApplied,
                        Some(reason.clone().into_bytes()),
                    ),
                )?;
                self.open.remove(&op);
            }
            Answer::Unknown => {
                vessel.append(
                    Stream::Effect,
                    outcome(op, OutcomeState::OutcomeUnknown, None),
                )?;
                if barrier.is_some() {
                    self.open.insert(op);
                }
            }
        }
        Ok(())
    }

    /// During reconciliation: `op` could not be settled.  Records
    /// `OutcomeUnknown` unless that is already its `state`.  Returns
    /// `false` ("not settled"), for `settle` to return.
    pub fn mark_unknown<L: Layers>(
        &mut self,
        vessel: &mut Vessel<L>,
        op: OpId,
        state: Option<OutcomeState>,
    ) -> Result<bool, VesselError> {
        if state != Some(OutcomeState::OutcomeUnknown) {
            vessel.append(
                Stream::Effect,
                outcome(op, OutcomeState::OutcomeUnknown, None),
            )?;
        }
        Ok(false)
    }

    /// Operator resolution of an open effect: record what really happened,
    /// or that nobody knows ([`Resolution::AcceptedUnknown`]).  Each closes
    /// the obligation and restores effect authority.  Refused without an
    /// actor and a reason, or for an effect that is not open.
    pub fn resolve<L: Layers>(
        &mut self,
        vessel: &mut Vessel<L>,
        op: OpId,
        resolution: Resolution,
        authority: Authority,
    ) -> Result<(), ResolveError> {
        if authority.actor.trim().is_empty() || authority.reason.trim().is_empty() {
            return Err(ResolveError::EmptyAuthority);
        }
        if !self.open.contains(&op) {
            return Err(ResolveError::NotOpen(op));
        }
        vessel
            .append(
                Stream::Effect,
                outcome(op, resolution.state(), Some(authority.canon_bytes())),
            )
            .map_err(ResolveError::Vessel)?;
        self.open.remove(&op);
        Ok(())
    }

    // ── internals ───────────────────────────────────────────────────

    /// Take the next op id; the barrier is the lsn the intent will get.
    fn assign<L: Layers>(&mut self, vessel: &Vessel<L>, d: &Declared) -> Authorized {
        let op = OpId::new(self.next_op);
        self.next_op += 1;
        let lsn = vessel.tail().lsn.next();
        let barrier =
            (d.consequence != Consequence::NoExternalMutation).then(|| BarrierId::new(lsn.get()));
        Authorized { op, barrier }
    }

    fn reconcile<L, F>(
        &mut self,
        vessel: &mut Vessel<L>,
        settle: &mut F,
    ) -> Result<Reconciled, VesselError>
    where
        L: Layers,
        F: FnMut(
            &mut Self,
            &mut Vessel<L>,
            &IntentRecord,
            Option<OutcomeState>,
        ) -> Result<bool, VesselError>,
    {
        let frames = vessel
            .chronicle()
            .frames()
            .map_err(|e| VesselError::Chronicle(ChronicleError::Segment(e)))?;
        // From the newest Checkpoint on: older segments may be gone.
        let summary = crate::summary::Summary::of(&frames)
            .map_err(|(lsn, error)| VesselError::Decode { lsn, error })?;
        self.next_op = self.next_op.max(summary.next_op);
        // Held proposals are not visited: they are nobody's obligation
        // here, and only the parent may release them.
        let intents: BTreeMap<OpId, IntentRecord> = summary
            .obligations()
            .map(|e| (e.intent.op, e.intent.clone()))
            .collect();
        let latest: BTreeMap<OpId, OutcomeState> = summary
            .obligations()
            .filter_map(|e| e.state.map(|s| (e.intent.op, s)))
            .collect();

        let mut report = Reconciled::default();
        for (op, i) in intents {
            let state = latest.get(&op).copied();
            if matches!(
                state,
                Some(
                    OutcomeState::ConfirmedApplied
                        | OutcomeState::ConfirmedNotApplied
                        | OutcomeState::AcceptedUnknown
                )
            ) {
                continue;
            }
            let settled = match state {
                None | Some(OutcomeState::Prepared) => {
                    vessel.append(
                        Stream::Effect,
                        outcome(
                            op,
                            OutcomeState::ConfirmedNotApplied,
                            Some(b"reconcile: never authorized".to_vec()),
                        ),
                    )?;
                    true
                }
                _ => settle(self, vessel, &i, state)?,
            };
            if settled {
                report.settled.push(op);
            } else if i.barrier.is_some() {
                self.open.insert(op);
                report.open.push(op);
            }
        }
        Ok(report)
    }
}

fn intent(a: Authorized, d: &Declared) -> IntentRecord {
    IntentRecord {
        op: a.op,
        provider: d.provider.clone(),
        request: d.request.clone(),
        footprint: d.footprint.clone(),
        dispatch: d.dispatch,
        retry: d.retry.clone(),
        consequence: d.consequence,
        authority: d.authority.clone(),
        barrier: a.barrier,
    }
}

fn outcome(op: OpId, state: OutcomeState, evidence: Option<Vec<u8>>) -> Payload {
    Payload::Outcome(OutcomeRecord {
        op,
        state,
        evidence,
    })
}

// ── Tests ───────────────────────────────────────────────────────────
//
// The ledger on its own, with no adapter and no runner: what storage
// promises whoever sends.  The full sequence with a provider is tested in
// `crate::effects`.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vessel::tests::{env, ns, Env, FakeLayers};

    /// A publisher that fails every time.
    struct NeverPublish;

    impl Publish for NeverPublish {
        fn publish(
            &mut self,
            _: ChronicleId,
            _: Epoch,
            _: &[&Segment],
            _: Position,
        ) -> Result<(), PublishError> {
            Err(PublishError("store unavailable".into()))
        }
    }

    fn vessel(e: &Env) -> Vessel<FakeLayers> {
        e.host.ensure(ns(1), b"u").unwrap().0
    }

    fn declared(request: &str, consequence: Consequence) -> Declared {
        Declared {
            provider: "mail".into(),
            request: request.as_bytes().to_vec(),
            footprint: Vec::new(),
            dispatch: Dispatch::Immediate,
            retry: RetryPolicy::UnsafeToRetry,
            consequence,
            authority: Vec::new(),
        }
    }

    /// A `settle` that must never be called.
    fn no_settle(
        _: &mut Ledger,
        _: &mut Vessel<FakeLayers>,
        i: &IntentRecord,
        _: Option<OutcomeState>,
    ) -> Result<bool, VesselError> {
        panic!("settle called for op {}", i.op.get())
    }

    /// A `settle` that cannot settle anything.
    fn cannot_settle(
        l: &mut Ledger,
        v: &mut Vessel<FakeLayers>,
        i: &IntentRecord,
        s: Option<OutcomeState>,
    ) -> Result<bool, VesselError> {
        l.mark_unknown(v, i.op, s)
    }

    fn open(v: &mut Vessel<FakeLayers>) -> (Ledger, Reconciled) {
        Ledger::open(Box::new(AlwaysPublish), v, cannot_settle).unwrap()
    }

    /// Effect records, decoded, in order.
    fn records(v: &Vessel<FakeLayers>) -> Vec<Payload> {
        v.chronicle()
            .frames()
            .unwrap()
            .iter()
            .filter(|f| f.envelope.stream == Stream::Effect)
            .map(|f| Payload::decode(&f.payload).unwrap())
            .collect()
    }

    fn outcomes(v: &Vessel<FakeLayers>) -> Vec<(u64, OutcomeState)> {
        records(v)
            .into_iter()
            .filter_map(|p| match p {
                Payload::Outcome(o) => Some((o.op.get(), o.state)),
                _ => None,
            })
            .collect()
    }

    fn auth() -> Authority {
        Authority {
            actor: "jarmo".into(),
            reason: "checked the provider by hand".into(),
        }
    }

    #[test]
    fn release_writes_the_intent_and_its_release_together() {
        let e = env();
        let mut v = vessel(&e);
        let (mut l, r) = open(&mut v);
        assert_eq!(r, Reconciled::default());
        assert_eq!(l.next_op(), OpId::new(1));
        let intent_lsn = v.tail().lsn.next();

        let a = l
            .release(&mut v, &declared("send bob", Consequence::Irreversible))
            .unwrap();
        assert_eq!(
            a,
            Authorized {
                op: OpId::new(1),
                barrier: Some(BarrierId::new(intent_lsn.get()))
            }
        );
        assert_eq!(l.next_op(), OpId::new(2));
        let recs = records(&v);
        assert_eq!(recs.len(), 2);
        let Payload::Intent(i) = &recs[0] else {
            panic!("intent first")
        };
        assert_eq!(i.request, b"send bob");
        assert_eq!(i.barrier, a.barrier);
        assert_eq!(outcomes(&v), vec![(1, OutcomeState::DispatchAuthorized)]);
    }

    #[test]
    fn no_external_mutation_has_no_barrier() {
        let e = env();
        let mut v = vessel(&e);
        let (mut l, _) = open(&mut v);
        let a = l
            .release(&mut v, &declared("read", Consequence::NoExternalMutation))
            .unwrap();
        assert_eq!(a.barrier, None);
        // An unknown answer without a barrier opens no obligation.
        l.record(&mut v, a.op, a.barrier, &Answer::Unknown).unwrap();
        assert!(l.authorized());
    }

    #[test]
    fn a_failed_ship_is_recorded_as_not_applied() {
        let e = env();
        let mut v = vessel(&e);
        let (mut l, _) = Ledger::open(Box::new(NeverPublish), &mut v, cannot_settle).unwrap();
        let a = l
            .release(&mut v, &declared("send bob", Consequence::Irreversible))
            .unwrap();
        let reason = l.ship_before_send(&mut v, &a).unwrap().unwrap_err();
        assert_eq!(reason, "ledger not shipped: store unavailable");
        assert_eq!(
            outcomes(&v),
            vec![
                (1, OutcomeState::DispatchAuthorized),
                (1, OutcomeState::ConfirmedNotApplied)
            ]
        );
        assert!(
            l.authorized(),
            "a refused send is terminal, not an obligation"
        );
    }

    #[test]
    fn a_successful_ship_records_nothing() {
        let e = env();
        let mut v = vessel(&e);
        let (mut l, _) = open(&mut v);
        let a = l
            .release(&mut v, &declared("send bob", Consequence::Irreversible))
            .unwrap();
        let tail = v.tail();
        assert_eq!(l.ship_before_send(&mut v, &a).unwrap(), Ok(()));
        assert_eq!(v.tail(), tail);
    }

    #[test]
    fn answers_close_or_open_the_effect() {
        let e = env();
        let mut v = vessel(&e);
        let (mut l, _) = open(&mut v);
        let a = l
            .release(&mut v, &declared("a", Consequence::Irreversible))
            .unwrap();
        l.record(&mut v, a.op, a.barrier, &Answer::Unknown).unwrap();
        assert_eq!(l.open_obligations(), vec![a.op]);
        assert!(!l.authorized());
        // A later terminal answer for it (a probe) closes it.
        l.record(
            &mut v,
            a.op,
            a.barrier,
            &Answer::Applied {
                receipt: b"r".to_vec(),
            },
        )
        .unwrap();
        assert!(l.authorized());
    }

    #[test]
    fn a_crash_after_the_intent_never_happened() {
        let e = env();
        let mut v = vessel(&e);
        let (mut l, _) = open(&mut v);
        l.append_intent_alone(&mut v, &declared("send bob", Consequence::Irreversible))
            .unwrap();
        drop((l, v));

        let mut v = vessel(&e);
        let (l, r) = Ledger::open(Box::new(AlwaysPublish), &mut v, no_settle).unwrap();
        assert_eq!(
            r,
            Reconciled {
                settled: vec![OpId::new(1)],
                open: vec![]
            }
        );
        assert!(l.authorized());
        assert_eq!(outcomes(&v), vec![(1, OutcomeState::ConfirmedNotApplied)]);
        assert_eq!(l.next_op(), OpId::new(2), "the op id is not reused");
    }

    #[test]
    fn an_authorized_effect_the_caller_cannot_settle_stays_open_until_resolved() {
        let e = env();
        let mut v = vessel(&e);
        let (mut l, _) = open(&mut v);
        let a = l
            .release(&mut v, &declared("fire", Consequence::Irreversible))
            .unwrap();
        drop((l, v));

        let mut v = vessel(&e);
        let (l, r) = open(&mut v);
        assert_eq!(
            r,
            Reconciled {
                settled: vec![],
                open: vec![a.op]
            }
        );
        assert!(!l.authorized());
        assert_eq!(
            outcomes(&v),
            vec![
                (1, OutcomeState::DispatchAuthorized),
                (1, OutcomeState::OutcomeUnknown)
            ]
        );

        // Opening again does not record a second unknown.
        drop((l, v));
        let mut v = vessel(&e);
        let (mut l, r) = open(&mut v);
        assert_eq!(r.open, vec![a.op]);
        assert_eq!(outcomes(&v).len(), 2);

        // Only an operator with a name and a reason closes it.
        let empty = Authority {
            actor: " ".into(),
            reason: "x".into(),
        };
        assert!(matches!(
            l.resolve(&mut v, a.op, Resolution::Applied, empty),
            Err(ResolveError::EmptyAuthority)
        ));
        assert!(matches!(
            l.resolve(&mut v, OpId::new(9), Resolution::Applied, auth()),
            Err(ResolveError::NotOpen(_))
        ));
        l.resolve(&mut v, a.op, Resolution::NotApplied, auth())
            .unwrap();
        assert!(l.authorized());
        assert_eq!(
            outcomes(&v).last(),
            Some(&(1, OutcomeState::ConfirmedNotApplied))
        );
    }

    /// P4 spec D34: an operator who does not know closes the effect as
    /// `AcceptedUnknown`, with a name and a reason.  It restores authority,
    /// and no later reopen visits, re-issues or probes it.
    #[test]
    fn an_operator_may_close_an_unknown_effect_as_accepted_unknown() {
        let e = env();
        let mut v = vessel(&e);
        let (mut l, _) = open(&mut v);
        let a = l
            .release(&mut v, &declared("wire money", Consequence::Irreversible))
            .unwrap();
        drop((l, v));
        let mut v = vessel(&e);
        let (mut l, r) = open(&mut v);
        assert_eq!(r.open, vec![a.op]);
        assert!(!l.authorized());

        let empty = Authority {
            actor: "ops".into(),
            reason: "".into(),
        };
        assert!(matches!(
            l.resolve(&mut v, a.op, Resolution::AcceptedUnknown, empty),
            Err(ResolveError::EmptyAuthority)
        ));
        l.resolve(&mut v, a.op, Resolution::AcceptedUnknown, auth())
            .unwrap();
        assert!(l.authorized(), "authority restored");
        assert_eq!(
            outcomes(&v),
            vec![
                (1, OutcomeState::DispatchAuthorized),
                (1, OutcomeState::OutcomeUnknown),
                (1, OutcomeState::AcceptedUnknown)
            ]
        );
        let Some(Payload::Outcome(last)) = records(&v).pop() else {
            panic!("an outcome last");
        };
        assert_eq!(last.evidence, Some(auth().canon_bytes()), "who and why");
        assert!(matches!(
            l.resolve(&mut v, a.op, Resolution::Applied, auth()),
            Err(ResolveError::NotOpen(_))
        ));

        // A reopen settles nothing and records nothing for it.
        drop((l, v));
        let mut v = vessel(&e);
        let (l, r) = Ledger::open(Box::new(AlwaysPublish), &mut v, no_settle).unwrap();
        assert_eq!(r, Reconciled::default());
        assert!(l.authorized());
        assert_eq!(outcomes(&v).len(), 3);
    }

    #[test]
    fn settled_intents_are_not_visited_again() {
        let e = env();
        let mut v = vessel(&e);
        let (mut l, _) = open(&mut v);
        let a = l
            .release(&mut v, &declared("a", Consequence::Irreversible))
            .unwrap();
        l.record(
            &mut v,
            a.op,
            a.barrier,
            &Answer::NotApplied {
                reason: "no".into(),
            },
        )
        .unwrap();
        drop((l, v));
        let mut v = vessel(&e);
        let (l, r) = Ledger::open(Box::new(AlwaysPublish), &mut v, no_settle).unwrap();
        assert_eq!(r, Reconciled::default());
        assert_eq!(l.next_op(), OpId::new(2));
    }

    // ── P3: held proposals and adoption ─────────────────────────────

    /// A proposal is written like a release (intent and state together),
    /// but its state is `Proposed`, and the ledger never treats it as
    /// released: on reopen it is not visited, not an obligation, and
    /// authority is granted.  Its op id is consumed like any other.
    #[test]
    fn a_proposal_is_durable_held_and_never_an_obligation() {
        let e = env();
        let mut v = vessel(&e);
        let (mut l, _) = open(&mut v);
        let intent_lsn = v.tail().lsn.next();
        let a = l
            .propose(&mut v, &declared("pay 10", Consequence::Irreversible))
            .unwrap();
        assert_eq!(
            a,
            Authorized {
                op: OpId::new(1),
                barrier: Some(BarrierId::new(intent_lsn.get()))
            }
        );
        assert_eq!(records(&v).len(), 2, "one batch: intent and Proposed");
        assert_eq!(outcomes(&v), vec![(1, OutcomeState::Proposed)]);
        assert!(l.authorized(), "a held proposal withholds nothing");
        drop((l, v));

        let mut v = vessel(&e);
        let (l, r) = Ledger::open(Box::new(AlwaysPublish), &mut v, no_settle).unwrap();
        assert_eq!(r, Reconciled::default(), "not visited, not open");
        assert!(l.authorized());
        assert_eq!(l.next_op(), OpId::new(2));
        assert_eq!(
            outcomes(&v),
            vec![(1, OutcomeState::Proposed)],
            "reconcile wrote nothing about it"
        );
    }

    /// Adopting a proposal releases a copy as this Vessel's own: a new op
    /// id and barrier, the child's request bytes unchanged, and the
    /// authority naming the child, its Seal and its op.
    #[test]
    fn adopting_a_proposal_releases_it_as_this_vessels_own() {
        let e = env();
        // The child proposes.
        let mut child = e.host.ensure(ns(1), b"child").unwrap().0;
        let (mut cl, _) = open(&mut child);
        cl.propose(&mut child, &declared("pay 10", Consequence::Irreversible))
            .unwrap();
        let proposal = records(&child)
            .into_iter()
            .find_map(|p| match p {
                Payload::Intent(i) => Some(i),
                _ => None,
            })
            .unwrap();
        let child_id = child.chronicle().id();
        drop((cl, child));

        // The parent adopts it.
        let mut v = vessel(&e);
        let (mut l, _) = open(&mut v);
        l.release(&mut v, &declared("earlier", Consequence::Irreversible))
            .unwrap();
        let from = AdoptedFrom {
            child: child_id,
            seal: Lsn::new(7),
            op: proposal.op,
        };
        let intent_lsn = v.tail().lsn.next();
        let [a] = l
            .adopt(
                &mut v,
                child_id,
                Lsn::new(7),
                std::slice::from_ref(&proposal),
                false,
            )
            .unwrap()[..]
        else {
            panic!("one adopted")
        };
        assert_eq!(a.op, OpId::new(2), "a new op id of the parent's");
        assert_eq!(a.barrier, Some(BarrierId::new(intent_lsn.get())));
        let adopted = records(&v)
            .into_iter()
            .filter_map(|p| match p {
                Payload::Intent(i) if i.op == a.op => Some(i),
                _ => None,
            })
            .next()
            .unwrap();
        assert_eq!(adopted.request, proposal.request);
        assert_eq!(adopted.retry, proposal.retry);
        assert_eq!(adopted.consequence, proposal.consequence);
        assert_eq!(adopted.authority, from.canon_bytes());
        assert_ne!(adopted.authority, proposal.authority);
        assert_eq!(
            outcomes(&v).last(),
            Some(&(2, OutcomeState::DispatchAuthorized)),
            "released, so a sender may act on it"
        );
        // Released and unsettled: an obligation on reopen, unlike the
        // child's proposal.
        drop((l, v));
        let mut v = vessel(&e);
        let (_, r) = open(&mut v);
        assert_eq!(r.open, vec![OpId::new(1), OpId::new(2)]);
    }
}
