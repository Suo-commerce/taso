//! The effect engine: intent before dispatch, outcomes in five states,
//! reconciliation before authority (v0.4 §7.2–7.4).
//!
//! # Dispatch
//!
//! For one Field `Effect` request:
//!
//! 1. No effect authority (an unresolved effect is open) → refused.
//! 2. No adapter for the provider → refused.  The adapter's plan refuses
//!    → refused.  A `Deferrable` plan is refused for now (dispatch at the
//!    next Seal is not built yet).  Nothing is recorded for a refusal.
//! 3. `Intent { op, provider, request, footprint, retry, consequence,
//!    authority, barrier }` is appended and fsynced.  `barrier` is the
//!    intent's own lsn unless the consequence is `NoExternalMutation`.
//! 4. `Outcome(DispatchAuthorized)` is appended and fsynced.
//! 5. The ledger is **published** up to that record ([`Publish`]): shipped
//!    off the node and recorded as the coordinator's shipped anchor.  If
//!    that fails, nothing is sent: `ConfirmedNotApplied` ("ledger not
//!    shipped") is recorded and returned.
//! 6. The adapter sends exactly `plan.request`.
//! 7. The answer is recorded: `ConfirmedApplied` (receipt as evidence),
//!    `ConfirmedNotApplied` (reason), or `OutcomeUnknown`.  An unknown
//!    outcome on a barrier intent withdraws effect authority until it is
//!    reconciled or resolved.
//!
//! A crash anywhere leaves at worst an intent that reconciliation
//! settles.
//!
//! Why step 5: an effect whose authorization exists only on this node
//! cannot be reconciled by another node that takes the Vessel over.  If
//! this node is lost after sending, the new holder must find
//! `DispatchAuthorized` in the shipped chain, under the anchor, and
//! reconcile it, never treat the intent as "never authorized" and lose a
//! real send.
//!
//! # Reconciliation (on open, before any authority)
//!
//! Every intent whose latest outcome is not terminal:
//! - none (crash after the intent) → `ConfirmedNotApplied`: dispatch was
//!   never authorized, so it never happened;
//! - `DispatchAuthorized` / `OutcomeUnknown`, by the intent's retry:
//!   - `ProviderDeduplicated` → publish, re-send the recorded request;
//!     record what the provider says;
//!   - `Queryable` → probe; applied → `ConfirmedApplied`; not applied →
//!     publish, send, record; unknown → stays open;
//!   - `UnsafeToRetry` → `OutcomeUnknown`, stays open: an operator
//!     decides.
//!   - no adapter for its provider any more → stays open.
//!   - a publish that fails before a send → nothing is sent; stays open.
//!
//! An open barrier intent is an obligation; effect authority is granted
//! only when there are none.  [`Effects::resolve`] is the one place a
//! human is in the recovery path by design (v0.4 §14): an operator,
//! with a reason, records what really happened.

use std::collections::{BTreeMap, BTreeSet};

use taso_core::canon::Canonical;
use taso_core::envelope::Stream;
use taso_core::record::{
    Authority, BarrierId, Consequence, Dispatch, IntentRecord, OpId, OutcomeRecord, OutcomeState,
    Payload, RetryPolicy,
};
use taso_field::adapter::{Call, Plan, Probed, Registry, Sent};
use taso_field::protocol::EffectResult;

use taso_core::envelope::{ChronicleId, Epoch};

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
    fn publish(&mut self, _: ChronicleId, _: Epoch, _: &[&Segment], _: Position) -> Result<(), PublishError> {
        Ok(())
    }
}

/// The effect engine of one Vessel.
pub struct Effects {
    registry: Registry,
    publisher: Box<dyn Publish>,
    next_op: u64,
    /// Open barrier intents: effect authority is withheld while any exist.
    open: BTreeSet<OpId>,
}

/// Where a test stops the dispatch sequence, simulating a crash after
/// that step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) enum CrashAfter {
    Intent,
    Authorized,
    Published,
    Send,
}

impl Effects {
    /// Start the engine on an opened Vessel: reconcile its ledger, then
    /// grant effect authority if nothing is left open.  `publisher` ships
    /// the ledger before every send, here and in reconciliation.
    pub fn open<L: Layers>(
        registry: Registry,
        publisher: Box<dyn Publish>,
        vessel: &mut Vessel<L>,
    ) -> Result<(Self, Reconciled), VesselError> {
        let mut e = Self { registry, publisher, next_op: 1, open: BTreeSet::new() };
        let r = e.reconcile(vessel)?;
        Ok((e, r))
    }

    /// True if effects may be dispatched.
    pub fn authorized(&self) -> bool {
        self.open.is_empty()
    }

    /// Open obligations.
    pub fn open_obligations(&self) -> Vec<OpId> {
        self.open.iter().copied().collect()
    }

    /// Run one effect request through the full sequence.
    pub fn dispatch<L: Layers>(
        &mut self,
        vessel: &mut Vessel<L>,
        provider: &str,
        call: Call,
    ) -> Result<EffectResult, VesselError> {
        Ok(self.dispatch_until(vessel, provider, call, None)?.expect("not stopped"))
    }

    pub(crate) fn dispatch_until<L: Layers>(
        &mut self,
        vessel: &mut Vessel<L>,
        provider: &str,
        call: Call,
        stop: Option<CrashAfter>,
    ) -> Result<Option<EffectResult>, VesselError> {
        if !self.authorized() {
            return Ok(Some(refused(format!(
                "no effect authority: {} unresolved effect(s)",
                self.open.len()
            ))));
        }
        let Some(adapter) = self.registry.get_mut(provider) else {
            return Ok(Some(refused(format!("no adapter for provider {provider:?}"))));
        };
        let op = OpId::new(self.next_op);
        let plan = match adapter.plan(op, &call) {
            Ok(p) => p,
            Err(r) => return Ok(Some(refused(r.to_string()))),
        };
        if plan.dispatch == Dispatch::Deferrable {
            return Ok(Some(refused("deferrable dispatch is not supported yet".into())));
        }
        self.next_op += 1;

        // 1. Intent, durable.  Its barrier is its own lsn.
        let lsn = vessel.tail().lsn.next();
        let barrier = (plan.consequence != Consequence::NoExternalMutation)
            .then(|| BarrierId::new(lsn.get()));
        vessel.append(Stream::Effect, Payload::Intent(intent(op, provider, &plan, barrier)))?;
        if stop == Some(CrashAfter::Intent) {
            return Ok(None);
        }
        // 2. Dispatch authorized, durable.
        vessel.append(Stream::Effect, outcome(op, OutcomeState::DispatchAuthorized, None))?;
        if stop == Some(CrashAfter::Authorized) {
            return Ok(None);
        }
        // 3. The authorization goes off the node before the request does.
        if let Err(e) = self.publish(vessel) {
            let reason = format!("ledger not shipped: {e}");
            vessel.append(
                Stream::Effect,
                outcome(op, OutcomeState::ConfirmedNotApplied, Some(reason.clone().into_bytes())),
            )?;
            return Ok(Some(EffectResult::NotApplied { reason }));
        }
        if stop == Some(CrashAfter::Published) {
            return Ok(None);
        }
        // 4. Send exactly the recorded request.
        let adapter = self.registry.get_mut(provider).expect("looked up above");
        let sent = adapter.send(op, &plan);
        if stop == Some(CrashAfter::Send) {
            return Ok(None);
        }
        // 5. Record what the provider said.
        Ok(Some(self.record_sent(vessel, op, barrier, sent)?))
    }

    /// Operator resolution of an open effect: record what really happened.
    /// Refused without an actor and a reason, or for an effect that is not
    /// open.
    pub fn resolve<L: Layers>(
        &mut self,
        vessel: &mut Vessel<L>,
        op: OpId,
        applied: bool,
        authority: Authority,
    ) -> Result<(), ResolveError> {
        if authority.actor.trim().is_empty() || authority.reason.trim().is_empty() {
            return Err(ResolveError::EmptyAuthority);
        }
        if !self.open.contains(&op) {
            return Err(ResolveError::NotOpen(op));
        }
        let state = if applied { OutcomeState::ConfirmedApplied } else { OutcomeState::ConfirmedNotApplied };
        vessel
            .append(Stream::Effect, outcome(op, state, Some(authority.canon_bytes())))
            .map_err(ResolveError::Vessel)?;
        self.open.remove(&op);
        Ok(())
    }

    // ── internals ───────────────────────────────────────────────────

    /// Publish the ledger up to the Vessel's tail.
    fn publish<L: Layers>(&mut self, vessel: &Vessel<L>) -> Result<(), PublishError> {
        let c = vessel.chronicle();
        self.publisher.publish(c.id(), c.epoch(), &c.segments(), c.tail())
    }

    fn record_sent<L: Layers>(
        &mut self,
        vessel: &mut Vessel<L>,
        op: OpId,
        barrier: Option<BarrierId>,
        sent: Sent,
    ) -> Result<EffectResult, VesselError> {
        match sent {
            Sent::Applied { receipt } => {
                vessel.append(Stream::Effect, outcome(op, OutcomeState::ConfirmedApplied, Some(receipt.clone())))?;
                self.open.remove(&op);
                Ok(EffectResult::Applied { receipt })
            }
            Sent::NotApplied { reason } => {
                vessel.append(
                    Stream::Effect,
                    outcome(op, OutcomeState::ConfirmedNotApplied, Some(reason.clone().into_bytes())),
                )?;
                self.open.remove(&op);
                Ok(EffectResult::NotApplied { reason })
            }
            Sent::Unknown => {
                vessel.append(Stream::Effect, outcome(op, OutcomeState::OutcomeUnknown, None))?;
                if barrier.is_some() {
                    self.open.insert(op);
                }
                Ok(EffectResult::Unknown)
            }
        }
    }

    fn reconcile<L: Layers>(&mut self, vessel: &mut Vessel<L>) -> Result<Reconciled, VesselError> {
        let frames = vessel
            .chronicle()
            .frames()
            .map_err(|e| VesselError::Chronicle(ChronicleError::Segment(e)))?;
        let mut intents: BTreeMap<OpId, IntentRecord> = BTreeMap::new();
        let mut latest: BTreeMap<OpId, OutcomeState> = BTreeMap::new();
        for f in frames.iter().filter(|f| f.envelope.stream == Stream::Effect) {
            match Payload::decode(&f.payload)
                .map_err(|error| VesselError::Decode { lsn: f.envelope.lsn, error })?
            {
                Payload::Intent(i) => {
                    self.next_op = self.next_op.max(i.op.get() + 1);
                    intents.insert(i.op, i);
                }
                Payload::Outcome(o) => {
                    latest.insert(o.op, o.state);
                }
                _ => {}
            }
        }

        let mut report = Reconciled::default();
        for (op, i) in intents {
            let state = latest.get(&op).copied();
            if matches!(state, Some(OutcomeState::ConfirmedApplied | OutcomeState::ConfirmedNotApplied)) {
                continue;
            }
            let settled = match state {
                None | Some(OutcomeState::Prepared) => {
                    vessel.append(
                        Stream::Effect,
                        outcome(op, OutcomeState::ConfirmedNotApplied, Some(b"reconcile: never authorized".to_vec())),
                    )?;
                    true
                }
                _ => self.settle(vessel, &i, state)?,
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

    /// Settle one authorized-or-unknown intent.  `true` if it is now
    /// terminal.
    fn settle<L: Layers>(
        &mut self,
        vessel: &mut Vessel<L>,
        i: &IntentRecord,
        state: Option<OutcomeState>,
    ) -> Result<bool, VesselError> {
        let plan = Plan {
            request: i.request.clone(),
            footprint: i.footprint.clone(),
            retry: i.retry.clone(),
            consequence: i.consequence,
            dispatch: i.dispatch,
            authority: i.authority.clone(),
        };
        let mark_unknown = |v: &mut Vessel<L>| -> Result<bool, VesselError> {
            if state != Some(OutcomeState::OutcomeUnknown) {
                v.append(Stream::Effect, outcome(i.op, OutcomeState::OutcomeUnknown, None))?;
            }
            Ok(false)
        };
        if self.registry.get_mut(&i.provider).is_none() {
            return mark_unknown(vessel);
        }
        // Whether this ends in a send; a probe decides for Queryable.
        let must_send = match &i.retry {
            RetryPolicy::ProviderDeduplicated { .. } => None,
            RetryPolicy::Queryable { .. } => {
                let adapter = self.registry.get_mut(&i.provider).expect("checked above");
                match adapter.probe(i.op, &plan) {
                    Probed::Applied { receipt } => Some(Sent::Applied { receipt }),
                    Probed::NotApplied => None,
                    Probed::Unknown => return mark_unknown(vessel),
                }
            }
            RetryPolicy::UnsafeToRetry => return mark_unknown(vessel),
        };
        let sent = match must_send {
            Some(answer) => answer,
            None => {
                // Nothing is sent from a ledger that is not off the node.
                if self.publish(vessel).is_err() {
                    return mark_unknown(vessel);
                }
                let adapter = self.registry.get_mut(&i.provider).expect("checked above");
                adapter.send(i.op, &plan)
            }
        };
        if sent == Sent::Unknown {
            return mark_unknown(vessel);
        }
        self.record_sent(vessel, i.op, i.barrier, sent)?;
        Ok(true)
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

fn refused(reason: String) -> EffectResult {
    EffectResult::Refused { reason }
}

fn intent(op: OpId, provider: &str, plan: &Plan, barrier: Option<BarrierId>) -> IntentRecord {
    IntentRecord {
        op,
        provider: provider.to_string(),
        request: plan.request.clone(),
        footprint: plan.footprint.clone(),
        dispatch: plan.dispatch,
        retry: plan.retry.clone(),
        consequence: plan.consequence,
        authority: plan.authority.clone(),
        barrier,
    }
}

fn outcome(op: OpId, state: OutcomeState, evidence: Option<Vec<u8>>) -> Payload {
    Payload::Outcome(OutcomeRecord { op, state, evidence })
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vessel::tests::{env, ns, Env, FakeLayers};
    use proptest::prelude::*;
    use std::sync::{Arc, Mutex};
    use taso_field::adapter::{Adapter, Fault, FakeProvider, Refusal};

    /// What happened, in order, across the provider and the publisher.
    #[derive(Clone, Debug, PartialEq, Eq)]
    enum Ev {
        /// A publish succeeded up to this lsn.
        Published(taso_core::envelope::Lsn),
        /// The provider was sent this request.
        Sent(Vec<u8>),
    }

    #[derive(Default)]
    struct World {
        timeline: Vec<Ev>,
        /// The next this many publishes fail.
        publish_fails: u32,
    }

    /// A fake provider that survives the Warden "crashing", and the world
    /// it shares with the test publisher.
    #[derive(Clone)]
    struct Shared(Arc<Mutex<FakeProvider>>, Arc<Mutex<World>>);

    /// A publisher that records into the shared world and fails on demand.
    struct TestPublish(Arc<Mutex<World>>);

    impl Publish for TestPublish {
        fn publish(&mut self, _: ChronicleId, _: Epoch, _: &[&Segment], upto: Position) -> Result<(), PublishError> {
            let mut w = self.0.lock().unwrap();
            if w.publish_fails > 0 {
                w.publish_fails -= 1;
                return Err(PublishError("store unavailable".into()));
            }
            w.timeline.push(Ev::Published(upto.lsn));
            Ok(())
        }
    }

    impl Shared {
        fn new(name: &str) -> Self {
            Self(Arc::new(Mutex::new(FakeProvider::new(name))), Arc::default())
        }
        fn publisher(&self) -> Box<dyn Publish> {
            Box::new(TestPublish(self.1.clone()))
        }
        fn fail_publish(&self, n: u32) {
            self.1.lock().unwrap().publish_fails = n;
        }
        fn timeline(&self) -> Vec<Ev> {
            self.1.lock().unwrap().timeline.clone()
        }
        fn fail_next(&self, f: Fault) {
            self.0.lock().unwrap().fail_next(f);
        }
        fn applied(&self, request: &[u8]) -> usize {
            self.0.lock().unwrap().applied(request)
        }
        fn no_duplicates(&self) -> bool {
            self.0.lock().unwrap().no_duplicates()
        }
    }

    impl Adapter for Shared {
        fn provider(&self) -> &str {
            "mail" // every Shared in these tests wraps a provider named "mail"
        }
        fn plan(&self, op: OpId, call: &Call) -> Result<Plan, Refusal> {
            self.0.lock().unwrap().plan(op, call)
        }
        fn send(&mut self, op: OpId, plan: &Plan) -> Sent {
            self.1.lock().unwrap().timeline.push(Ev::Sent(plan.request.clone()));
            self.0.lock().unwrap().send(op, plan)
        }
        fn probe(&mut self, op: OpId, plan: &Plan) -> Probed {
            self.0.lock().unwrap().probe(op, plan)
        }
    }

    fn registry(p: &Shared) -> Registry {
        let mut r = Registry::new();
        r.register(Box::new(p.clone()));
        r
    }

    fn call(op: &str, target: &str) -> Call {
        Call { operation: op.into(), args: target.as_bytes().to_vec() }
    }

    fn vessel(e: &Env) -> Vessel<FakeLayers> {
        e.host.ensure(ns(1), b"u").unwrap().0
    }

    /// Effect records, decoded, in order.
    fn ledger(v: &Vessel<FakeLayers>) -> Vec<Payload> {
        v.chronicle()
            .frames()
            .unwrap()
            .iter()
            .filter(|f| f.envelope.stream == Stream::Effect)
            .map(|f| Payload::decode(&f.payload).unwrap())
            .collect()
    }

    fn states(v: &Vessel<FakeLayers>) -> Vec<OutcomeState> {
        ledger(v)
            .into_iter()
            .filter_map(|p| match p {
                Payload::Outcome(o) => Some(o.state),
                _ => None,
            })
            .collect()
    }

    fn auth() -> Authority {
        Authority { actor: "jarmo".into(), reason: "checked the provider by hand".into() }
    }

    /// Every send came after a successful publish that covered the
    /// `DispatchAuthorized` record of its effect.
    fn sent_only_after_publish(v: &Vessel<FakeLayers>, p: &Shared) -> Result<(), String> {
        let mut op_of: BTreeMap<Vec<u8>, OpId> = BTreeMap::new();
        let mut authorized_at: BTreeMap<OpId, u64> = BTreeMap::new();
        for f in v.chronicle().frames().unwrap() {
            if f.envelope.stream != Stream::Effect {
                continue;
            }
            match Payload::decode(&f.payload).unwrap() {
                Payload::Intent(i) => {
                    op_of.insert(i.request, i.op);
                }
                Payload::Outcome(o) if o.state == OutcomeState::DispatchAuthorized => {
                    authorized_at.entry(o.op).or_insert(f.envelope.lsn.get());
                }
                _ => {}
            }
        }
        let mut published = 0;
        for ev in p.timeline() {
            match ev {
                Ev::Published(l) => published = published.max(l.get()),
                Ev::Sent(req) => {
                    let op = op_of.get(&req).ok_or("a send without an intent")?;
                    let at = authorized_at.get(op).ok_or("a send without an authorization")?;
                    if published < *at {
                        return Err(format!("{:?} sent with the ledger shipped to {published}, authorized at {at}", String::from_utf8_lossy(&req)));
                    }
                }
            }
        }
        Ok(())
    }

    // ── dispatch ────────────────────────────────────────────────────

    #[test]
    fn intent_before_dispatch_then_outcome() {
        let e = env();
        let p = Shared::new("mail");
        let mut v = vessel(&e);
        let (mut fx, r) = Effects::open(registry(&p), p.publisher(), &mut v).unwrap();
        assert_eq!(r, Reconciled::default());
        let intent_lsn = v.tail().lsn.next();

        let res = fx.dispatch(&mut v, "mail", call("send", "bob")).unwrap();
        assert!(matches!(res, EffectResult::Applied { .. }));
        assert_eq!(p.applied(b"send bob"), 1);

        let l = ledger(&v);
        let Payload::Intent(i) = &l[0] else { panic!("intent first") };
        assert_eq!(i.provider, "mail");
        assert_eq!(i.request, b"send bob");
        assert_eq!(i.consequence, Consequence::Irreversible);
        assert_eq!(i.barrier, Some(BarrierId::new(intent_lsn.get())), "barrier = intent's own lsn");
        assert_eq!(states(&v), vec![OutcomeState::DispatchAuthorized, OutcomeState::ConfirmedApplied]);
    }

    #[test]
    fn refusals_record_nothing() {
        let e = env();
        let p = Shared::new("mail");
        let mut v = vessel(&e);
        let (mut fx, _) = Effects::open(registry(&p), p.publisher(), &mut v).unwrap();
        let tail = v.tail();
        for (prov, c) in [("http", call("send", "bob")), ("mail", call("format-disk", "x")), ("mail", call("send", ""))] {
            assert!(matches!(fx.dispatch(&mut v, prov, c).unwrap(), EffectResult::Refused { .. }));
        }
        assert_eq!(v.tail(), tail);
    }

    #[test]
    fn no_mutation_has_no_barrier() {
        let e = env();
        let p = Shared::new("mail");
        let mut v = vessel(&e);
        let (mut fx, _) = Effects::open(registry(&p), p.publisher(), &mut v).unwrap();
        fx.dispatch(&mut v, "mail", call("read", "inbox")).unwrap();
        let Payload::Intent(i) = &ledger(&v)[0] else { panic!() };
        assert_eq!(i.barrier, None);
    }

    #[test]
    fn unknown_outcome_withdraws_authority_until_an_operator_resolves() {
        let e = env();
        let p = Shared::new("mail");
        let mut v = vessel(&e);
        let (mut fx, _) = Effects::open(registry(&p), p.publisher(), &mut v).unwrap();
        p.fail_next(Fault::ReplyLost);
        assert_eq!(fx.dispatch(&mut v, "mail", call("fire", "moon")).unwrap(), EffectResult::Unknown);
        assert!(!fx.authorized());
        assert!(matches!(fx.dispatch(&mut v, "mail", call("send", "bob")).unwrap(), EffectResult::Refused { .. }));
        assert_eq!(p.applied(b"send bob"), 0);

        let op = fx.open_obligations()[0];
        let empty = Authority { actor: "jarmo".into(), reason: " ".into() };
        assert!(matches!(fx.resolve(&mut v, op, true, empty), Err(ResolveError::EmptyAuthority)));
        assert!(matches!(fx.resolve(&mut v, OpId::new(99), true, auth()), Err(ResolveError::NotOpen(_))));
        fx.resolve(&mut v, op, true, auth()).unwrap();
        assert!(fx.authorized());
        let Some(Payload::Outcome(last)) = ledger(&v).pop() else { panic!() };
        assert_eq!(last.state, OutcomeState::ConfirmedApplied);
        assert_eq!(last.evidence, Some(auth().canon_bytes()), "the operator's authority is the evidence");
        assert!(matches!(fx.dispatch(&mut v, "mail", call("send", "bob")).unwrap(), EffectResult::Applied { .. }));
    }

    // ── crash points, then reopen and reconcile ─────────────────────

    /// Dispatch until `stop`, "crash" (drop engine and Vessel), reopen,
    /// reconcile.  Returns the reopened Vessel, engine and report.
    fn crash_and_reopen(
        e: &Env,
        p: &Shared,
        op: &str,
        stop: CrashAfter,
    ) -> (Vessel<FakeLayers>, Effects, Reconciled) {
        let mut v = vessel(e);
        let (mut fx, _) = Effects::open(registry(p), p.publisher(), &mut v).unwrap();
        assert!(fx.dispatch_until(&mut v, "mail", call(op, "x"), Some(stop)).unwrap().is_none());
        drop((fx, v));
        let mut v = vessel(e);
        let (fx, r) = Effects::open(registry(p), p.publisher(), &mut v).unwrap();
        (v, fx, r)
    }

    #[test]
    fn crash_after_intent_never_happened() {
        let e = env();
        let p = Shared::new("mail");
        let (v, fx, r) = crash_and_reopen(&e, &p, "send", CrashAfter::Intent);
        assert_eq!(r.settled, vec![OpId::new(1)]);
        assert_eq!(p.applied(b"send x"), 0);
        assert_eq!(states(&v), vec![OutcomeState::ConfirmedNotApplied]);
        assert!(fx.authorized());
    }

    #[test]
    fn dedup_is_reissued_exactly_once() {
        for stop in [CrashAfter::Authorized, CrashAfter::Send] {
            let e = env();
            let p = Shared::new("mail");
            let (v, fx, r) = crash_and_reopen(&e, &p, "send", stop);
            assert_eq!(r.settled, vec![OpId::new(1)], "{stop:?}");
            assert_eq!(p.applied(b"send x"), 1, "{stop:?}");
            assert_eq!(*states(&v).last().unwrap(), OutcomeState::ConfirmedApplied);
            assert!(fx.authorized());
        }
    }

    #[test]
    fn queryable_is_probed_and_only_sent_if_not_applied() {
        for stop in [CrashAfter::Authorized, CrashAfter::Send] {
            let e = env();
            let p = Shared::new("mail");
            let (_v, fx, r) = crash_and_reopen(&e, &p, "put", stop);
            assert_eq!(r.settled, vec![OpId::new(1)], "{stop:?}");
            assert_eq!(p.applied(b"put x"), 1, "{stop:?}");
            assert!(fx.authorized());
        }
    }

    #[test]
    fn unsafe_stays_open_for_an_operator() {
        let e = env();
        let p = Shared::new("mail");
        let (v, fx, r) = crash_and_reopen(&e, &p, "fire", CrashAfter::Send);
        assert_eq!(r.open, vec![OpId::new(1)]);
        assert_eq!(p.applied(b"fire x"), 1, "never re-sent");
        assert_eq!(*states(&v).last().unwrap(), OutcomeState::OutcomeUnknown);
        assert!(!fx.authorized());
    }

    #[test]
    fn a_vanished_adapter_leaves_the_effect_open() {
        let e = env();
        let p = Shared::new("mail");
        let mut v = vessel(&e);
        let (mut fx, _) = Effects::open(registry(&p), p.publisher(), &mut v).unwrap();
        fx.dispatch_until(&mut v, "mail", call("send", "x"), Some(CrashAfter::Authorized)).unwrap();
        drop((fx, v));
        let mut v = vessel(&e);
        let (fx, r) = Effects::open(Registry::new(), p.publisher(), &mut v).unwrap();
        assert_eq!(r.open, vec![OpId::new(1)]);
        assert!(!fx.authorized());
        assert_eq!(p.applied(b"send x"), 0);
    }

    #[test]
    fn op_ids_continue_after_reopen() {
        let e = env();
        let p = Shared::new("mail");
        let mut v = vessel(&e);
        let (mut fx, _) = Effects::open(registry(&p), p.publisher(), &mut v).unwrap();
        fx.dispatch(&mut v, "mail", call("send", "a")).unwrap();
        fx.dispatch(&mut v, "mail", call("send", "b")).unwrap();
        drop((fx, v));
        let mut v = vessel(&e);
        let (mut fx, _) = Effects::open(registry(&p), p.publisher(), &mut v).unwrap();
        fx.dispatch(&mut v, "mail", call("send", "c")).unwrap();
        let ops: Vec<u64> = ledger(&v)
            .into_iter()
            .filter_map(|x| match x {
                Payload::Intent(i) => Some(i.op.get()),
                _ => None,
            })
            .collect();
        assert_eq!(ops, vec![1, 2, 3]);
    }

    // ── publishing before every send ────────────────────────────────

    #[test]
    fn the_authorization_is_published_before_the_request_is_sent() {
        let e = env();
        let p = Shared::new("mail");
        let mut v = vessel(&e);
        let (mut fx, _) = Effects::open(registry(&p), p.publisher(), &mut v).unwrap();
        fx.dispatch(&mut v, "mail", call("send", "bob")).unwrap();
        fx.dispatch(&mut v, "mail", call("put", "x")).unwrap();
        let t = p.timeline();
        assert!(matches!(t[0], Ev::Published(_)) && t[1] == Ev::Sent(b"send bob".to_vec()), "{t:?}");
        sent_only_after_publish(&v, &p).unwrap();
    }

    /// A publish that fails: nothing is sent, and "not applied" is the
    /// recorded, returned truth.  Authority is unaffected.
    #[test]
    fn a_failed_publish_sends_nothing() {
        let e = env();
        let p = Shared::new("mail");
        let mut v = vessel(&e);
        let (mut fx, _) = Effects::open(registry(&p), p.publisher(), &mut v).unwrap();
        p.fail_publish(1);
        let r = fx.dispatch(&mut v, "mail", call("send", "bob")).unwrap();
        assert!(matches!(&r, EffectResult::NotApplied { reason } if reason.contains("ledger not shipped")), "{r:?}");
        assert_eq!(p.applied(b"send bob"), 0);
        assert!(p.timeline().is_empty());
        assert_eq!(states(&v), vec![OutcomeState::DispatchAuthorized, OutcomeState::ConfirmedNotApplied]);
        assert!(fx.authorized());
        // The next one goes through.
        assert!(matches!(fx.dispatch(&mut v, "mail", call("send", "carol")).unwrap(), EffectResult::Applied { .. }));
        sent_only_after_publish(&v, &p).unwrap();
    }

    /// Reconciliation re-sends only after publishing; if it cannot, the
    /// effect stays open and nothing is sent.
    #[test]
    fn reconcile_publishes_before_it_sends() {
        let e = env();
        let p = Shared::new("mail");
        let mut v = vessel(&e);
        let (mut fx, _) = Effects::open(registry(&p), p.publisher(), &mut v).unwrap();
        fx.dispatch_until(&mut v, "mail", call("send", "x"), Some(CrashAfter::Authorized)).unwrap();
        drop((fx, v));
        // Reopen while the store is down: open, unsent.
        p.fail_publish(1);
        let mut v = vessel(&e);
        let (fx, r) = Effects::open(registry(&p), p.publisher(), &mut v).unwrap();
        assert_eq!(r.open, vec![OpId::new(1)]);
        assert!(!fx.authorized());
        assert_eq!(p.applied(b"send x"), 0);
        drop((fx, v));
        // Reopen with the store back: published, then sent once.
        let mut v = vessel(&e);
        let (fx, r) = Effects::open(registry(&p), p.publisher(), &mut v).unwrap();
        assert_eq!(r.settled, vec![OpId::new(1)]);
        assert!(fx.authorized());
        assert_eq!(p.applied(b"send x"), 1);
        sent_only_after_publish(&v, &p).unwrap();
    }

    /// A crash between the publish and the send: reconcile sends it once.
    #[test]
    fn crash_after_publish_is_sent_once() {
        for op in ["send", "put"] {
            let e = env();
            let p = Shared::new("mail");
            let (v, fx, r) = crash_and_reopen(&e, &p, op, CrashAfter::Published);
            assert_eq!(r.settled, vec![OpId::new(1)], "{op}");
            assert_eq!(p.applied(format!("{op} x").as_bytes()), 1, "{op}");
            assert!(fx.authorized());
            sent_only_after_publish(&v, &p).unwrap();
        }
    }

    // ── property: never a duplicate, never a silent loss ────────────

    #[derive(Clone, Debug)]
    struct Step {
        op: &'static str,
        fault: Fault,
        crash: Option<CrashAfter>,
        /// The next publish fails (the store or the coordinator is down).
        publish_fails: bool,
    }

    fn step() -> impl Strategy<Value = Step> {
        let op = prop_oneof![Just("send"), Just("put"), Just("fire"), Just("read")];
        let fault = prop_oneof![Just(Fault::None), Just(Fault::Lost), Just(Fault::ReplyLost), Just(Fault::Decline)];
        let crash = prop_oneof![
            3 => Just(None),
            1 => Just(Some(CrashAfter::Intent)),
            1 => Just(Some(CrashAfter::Authorized)),
            1 => Just(Some(CrashAfter::Published)),
            1 => Just(Some(CrashAfter::Send)),
        ];
        let publish_fails = prop_oneof![4 => Just(false), 1 => Just(true)];
        (op, fault, crash, publish_fails).prop_map(|(op, fault, crash, publish_fails)| Step { op, fault, crash, publish_fails })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(96))]

        /// Any sequence of effects, provider faults, publish failures and
        /// crashes: no request is ever applied twice, nothing is ever sent
        /// before its authorization is published, and after every
        /// reconciliation each intent is either terminal or an open
        /// obligation.
        #[test]
        fn no_duplicates_and_nothing_silently_lost(steps in proptest::collection::vec(step(), 1..12)) {
            let e = env();
            let p = Shared::new("mail");
            let mut v = vessel(&e);
            let (mut fx, _) = Effects::open(registry(&p), p.publisher(), &mut v).unwrap();
            for (n, s) in steps.iter().enumerate() {
                if !fx.authorized() {
                    // An operator checks the provider and records the truth.
                    for op in fx.open_obligations() {
                        let request = ledger(&v)
                            .into_iter()
                            .find_map(|x| match x {
                                Payload::Intent(i) if i.op == op => Some(i.request),
                                _ => None,
                            })
                            .unwrap();
                        let applied = p.applied(&request) > 0;
                        fx.resolve(&mut v, op, applied, auth()).unwrap();
                    }
                }
                p.fail_next(s.fault);
                p.fail_publish(s.publish_fails as u32);
                let target = format!("t{n}");
                let r = fx.dispatch_until(&mut v, "mail", call(s.op, &target), s.crash).unwrap();
                if r.is_none() {
                    drop((fx, v));
                    v = vessel(&e);
                    let (f, rec) = Effects::open(registry(&p), p.publisher(), &mut v).unwrap();
                    fx = f;
                    prop_assert_eq!(rec.open.clone(), fx.open_obligations());
                }
                prop_assert!(p.no_duplicates(), "a request was applied twice");
                let order = sent_only_after_publish(&v, &p);
                prop_assert!(order.is_ok(), "{:?}", order);
            }
            // Every intent ends terminal, or is an open barrier obligation.
            let mut latest: BTreeMap<OpId, OutcomeState> = BTreeMap::new();
            let mut barrier: BTreeMap<OpId, bool> = BTreeMap::new();
            for x in ledger(&v) {
                match x {
                    Payload::Intent(i) => { barrier.insert(i.op, i.barrier.is_some()); }
                    Payload::Outcome(o) => { latest.insert(o.op, o.state); }
                    _ => {}
                }
            }
            for (op, has_barrier) in barrier {
                let terminal = matches!(
                    latest.get(&op),
                    Some(OutcomeState::ConfirmedApplied | OutcomeState::ConfirmedNotApplied)
                );
                let open = fx.open_obligations().contains(&op);
                prop_assert!(terminal || open || !has_barrier, "op {:?} neither terminal nor open", op);
            }
        }
    }
}
