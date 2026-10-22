//! The effect engine of the reference runner: dispatch over the ledger
//! (v0.4 §7.2–7.4).
//!
//! The record of every effect, and every rule about it that is storage,
//! lives in [`crate::ledger`]: intent before dispatch, the ledger off the
//! node before any send, every answer recorded, reconciliation before
//! authority, operator resolution.  This module is the relay: it knows
//! the providers (adapters), plans, sends and probes, and tells the ledger
//! what happened at each step.
//!
//! # Dispatch
//!
//! For one Field `Effect` request:
//!
//! 1. No effect authority (an unresolved effect is open) → refused.
//! 2. No adapter for the provider → refused.  The adapter's plan refuses
//!    → refused.  A `Deferrable` plan is refused for now (dispatch at the
//!    next Seal is not built yet).  Nothing is recorded for a refusal.
//! 3. The ledger authorizes it ([`Ledger::authorize`]): `Intent` and
//!    `DispatchAuthorized`, durable together.
//! 4. The ledger is shipped ([`Ledger::ship_before_send`]).  If that
//!    fails, nothing is sent: the ledger has recorded
//!    `ConfirmedNotApplied` ("ledger not shipped"), which is returned.
//! 5. The adapter sends exactly `plan.request`.
//! 6. The answer is recorded ([`Ledger::record`]).
//!
//! A crash anywhere leaves at worst an intent that reconciliation
//! settles.
//!
//! # Reconciliation (on open, before any authority)
//!
//! The ledger visits every unsettled intent and settles the never
//! authorized ones itself.  For an authorized or unknown one, by its
//! retry policy:
//! - `ProviderDeduplicated` → ship, re-send the recorded request;
//!   record what the provider says;
//! - `Queryable` → probe; applied → `ConfirmedApplied`; not applied →
//!   ship, send, record; unknown → stays open;
//! - `UnsafeToRetry` → `OutcomeUnknown`, stays open: an operator
//!   decides ([`Effects::resolve`]).
//! - no adapter for its provider any more → stays open.
//! - a ship that fails before a send → nothing is sent; stays open.

use taso_core::record::{Authority, Dispatch, IntentRecord, OpId, OutcomeState, RetryPolicy};
use taso_field::adapter::{Call, Plan, Probed, Registry, Sent};
use taso_field::protocol::EffectResult;

use crate::chronicle::Layers;
use crate::ledger::{Answer, Declared, Ledger};
use crate::vessel::{Vessel, VesselError};

pub use crate::ledger::{Publish, PublishError, Reconciled, ResolveError};

#[cfg(test)]
pub(crate) use crate::ledger::AlwaysPublish;

/// The effect engine of one Vessel.
pub struct Effects {
    registry: Registry,
    ledger: Ledger,
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
        mut registry: Registry,
        publisher: Box<dyn Publish>,
        vessel: &mut Vessel<L>,
    ) -> Result<(Self, Reconciled), VesselError> {
        let (ledger, r) = Ledger::open(publisher, vessel, |l, v, i, s| {
            settle(&mut registry, l, v, i, s)
        })?;
        Ok((Self { registry, ledger }, r))
    }

    /// True if effects may be dispatched.
    pub fn authorized(&self) -> bool {
        self.ledger.authorized()
    }

    /// Open obligations.
    pub fn open_obligations(&self) -> Vec<OpId> {
        self.ledger.open_obligations()
    }

    /// Run one effect request through the full sequence.
    pub fn dispatch<L: Layers>(
        &mut self,
        vessel: &mut Vessel<L>,
        provider: &str,
        call: Call,
    ) -> Result<EffectResult, VesselError> {
        Ok(self
            .dispatch_until(vessel, provider, call, None)?
            .expect("not stopped"))
    }

    pub(crate) fn dispatch_until<L: Layers>(
        &mut self,
        vessel: &mut Vessel<L>,
        provider: &str,
        call: Call,
        stop: Option<CrashAfter>,
    ) -> Result<Option<EffectResult>, VesselError> {
        if !self.ledger.authorized() {
            return Ok(Some(refused(format!(
                "no effect authority: {} unresolved effect(s)",
                self.ledger.open_obligations().len()
            ))));
        }
        let Some(adapter) = self.registry.get_mut(provider) else {
            return Ok(Some(refused(format!(
                "no adapter for provider {provider:?}"
            ))));
        };
        let op = self.ledger.next_op();
        let plan = match adapter.plan(op, &call) {
            Ok(p) => p,
            Err(r) => return Ok(Some(refused(r.to_string()))),
        };
        if plan.dispatch == Dispatch::Deferrable {
            return Ok(Some(refused(
                "deferrable dispatch is not supported yet".into(),
            )));
        }
        let proposed = proposed(provider, &plan);

        let _total = crate::timing::span("effect.total");
        if stop == Some(CrashAfter::Intent) {
            // Tests only: an intent accepted alone, as an older Warden that
            // wrote them apart could leave it.  Recovery must still handle it.
            self.ledger.append_intent_alone(vessel, &proposed)?;
            return Ok(None);
        }
        // 3. Intent and dispatch authorized, durable together.
        let a = self.ledger.release(vessel, &proposed)?;
        debug_assert_eq!(
            a.op, op,
            "the plan was made for the op id the ledger assigned"
        );
        if stop == Some(CrashAfter::Authorized) {
            return Ok(None);
        }
        // 4. The authorization goes off the node before the request does.
        if let Err(reason) = self.ledger.ship_before_send(vessel, &a)? {
            return Ok(Some(EffectResult::NotApplied { reason }));
        }
        if stop == Some(CrashAfter::Published) {
            return Ok(None);
        }
        // 5. Send exactly the recorded request.
        let adapter = self.registry.get_mut(provider).expect("looked up above");
        let t = crate::timing::span("effect.send");
        let sent = adapter.send(a.op, &plan);
        drop(t);
        if stop == Some(CrashAfter::Send) {
            return Ok(None);
        }
        // 6. Record what the provider said.
        let _t = crate::timing::span("effect.outcome");
        let answer = answer(sent);
        self.ledger.record(vessel, a.op, a.barrier, &answer)?;
        Ok(Some(result(answer)))
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
        self.ledger.resolve(vessel, op, applied, authority)
    }
}

/// Settle one authorized-or-unknown intent during reconciliation.  `true`
/// if it is now terminal.
fn settle<L: Layers>(
    registry: &mut Registry,
    ledger: &mut Ledger,
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
    let Some(adapter) = registry.get_mut(&i.provider) else {
        return ledger.mark_unknown(vessel, i.op, state);
    };
    // Whether this ends in a send; a probe decides for Queryable.
    let must_send = match &i.retry {
        RetryPolicy::ProviderDeduplicated { .. } => None,
        RetryPolicy::Queryable { .. } => match adapter.probe(i.op, &plan) {
            Probed::Applied { receipt } => Some(Sent::Applied { receipt }),
            Probed::NotApplied => None,
            Probed::Unknown => return ledger.mark_unknown(vessel, i.op, state),
        },
        RetryPolicy::UnsafeToRetry => return ledger.mark_unknown(vessel, i.op, state),
    };
    let sent = match must_send {
        Some(answer) => answer,
        None => {
            // Nothing is sent from a ledger that is not off the node.
            if ledger.ship(vessel).is_err() {
                return ledger.mark_unknown(vessel, i.op, state);
            }
            adapter.send(i.op, &plan)
        }
    };
    if sent == Sent::Unknown {
        return ledger.mark_unknown(vessel, i.op, state);
    }
    ledger.record(vessel, i.op, i.barrier, &answer(sent))?;
    Ok(true)
}

fn proposed(provider: &str, plan: &Plan) -> Declared {
    Declared {
        provider: provider.to_string(),
        request: plan.request.clone(),
        footprint: plan.footprint.clone(),
        dispatch: plan.dispatch,
        retry: plan.retry.clone(),
        consequence: plan.consequence,
        authority: plan.authority.clone(),
    }
}

fn answer(sent: Sent) -> Answer {
    match sent {
        Sent::Applied { receipt } => Answer::Applied { receipt },
        Sent::NotApplied { reason } => Answer::NotApplied { reason },
        Sent::Unknown => Answer::Unknown,
    }
}

fn result(answer: Answer) -> EffectResult {
    match answer {
        Answer::Applied { receipt } => EffectResult::Applied { receipt },
        Answer::NotApplied { reason } => EffectResult::NotApplied { reason },
        Answer::Unknown => EffectResult::Unknown,
    }
}

fn refused(reason: String) -> EffectResult {
    EffectResult::Refused { reason }
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::segment::{Position, Segment};
    use crate::vessel::tests::{env, ns, Env, FakeLayers};
    use proptest::prelude::*;
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};
    use taso_core::canon::Canonical;
    use taso_core::envelope::{ChronicleId, Epoch, Stream};
    use taso_core::record::{BarrierId, Consequence, Payload};
    use taso_field::adapter::{Adapter, FakeProvider, Fault, Refusal};

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
        fn publish(
            &mut self,
            _: ChronicleId,
            _: Epoch,
            _: &[&Segment],
            upto: Position,
        ) -> Result<(), PublishError> {
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
            Self(
                Arc::new(Mutex::new(FakeProvider::new(name))),
                Arc::default(),
            )
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
            self.1
                .lock()
                .unwrap()
                .timeline
                .push(Ev::Sent(plan.request.clone()));
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
        Call {
            operation: op.into(),
            args: target.as_bytes().to_vec(),
        }
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
        Authority {
            actor: "jarmo".into(),
            reason: "checked the provider by hand".into(),
        }
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
                    let at = authorized_at
                        .get(op)
                        .ok_or("a send without an authorization")?;
                    if published < *at {
                        return Err(format!(
                            "{:?} sent with the ledger shipped to {published}, authorized at {at}",
                            String::from_utf8_lossy(&req)
                        ));
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
        let Payload::Intent(i) = &l[0] else {
            panic!("intent first")
        };
        assert_eq!(i.provider, "mail");
        assert_eq!(i.request, b"send bob");
        assert_eq!(i.consequence, Consequence::Irreversible);
        assert_eq!(
            i.barrier,
            Some(BarrierId::new(intent_lsn.get())),
            "barrier = intent's own lsn"
        );
        assert_eq!(
            states(&v),
            vec![
                OutcomeState::DispatchAuthorized,
                OutcomeState::ConfirmedApplied
            ]
        );
    }

    #[test]
    fn refusals_record_nothing() {
        let e = env();
        let p = Shared::new("mail");
        let mut v = vessel(&e);
        let (mut fx, _) = Effects::open(registry(&p), p.publisher(), &mut v).unwrap();
        let tail = v.tail();
        for (prov, c) in [
            ("http", call("send", "bob")),
            ("mail", call("format-disk", "x")),
            ("mail", call("send", "")),
        ] {
            assert!(matches!(
                fx.dispatch(&mut v, prov, c).unwrap(),
                EffectResult::Refused { .. }
            ));
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
        let Payload::Intent(i) = &ledger(&v)[0] else {
            panic!()
        };
        assert_eq!(i.barrier, None);
    }

    #[test]
    fn unknown_outcome_withdraws_authority_until_an_operator_resolves() {
        let e = env();
        let p = Shared::new("mail");
        let mut v = vessel(&e);
        let (mut fx, _) = Effects::open(registry(&p), p.publisher(), &mut v).unwrap();
        p.fail_next(Fault::ReplyLost);
        assert_eq!(
            fx.dispatch(&mut v, "mail", call("fire", "moon")).unwrap(),
            EffectResult::Unknown
        );
        assert!(!fx.authorized());
        assert!(matches!(
            fx.dispatch(&mut v, "mail", call("send", "bob")).unwrap(),
            EffectResult::Refused { .. }
        ));
        assert_eq!(p.applied(b"send bob"), 0);

        let op = fx.open_obligations()[0];
        let empty = Authority {
            actor: "jarmo".into(),
            reason: " ".into(),
        };
        assert!(matches!(
            fx.resolve(&mut v, op, true, empty),
            Err(ResolveError::EmptyAuthority)
        ));
        assert!(matches!(
            fx.resolve(&mut v, OpId::new(99), true, auth()),
            Err(ResolveError::NotOpen(_))
        ));
        fx.resolve(&mut v, op, true, auth()).unwrap();
        assert!(fx.authorized());
        let Some(Payload::Outcome(last)) = ledger(&v).pop() else {
            panic!()
        };
        assert_eq!(last.state, OutcomeState::ConfirmedApplied);
        assert_eq!(
            last.evidence,
            Some(auth().canon_bytes()),
            "the operator's authority is the evidence"
        );
        assert!(matches!(
            fx.dispatch(&mut v, "mail", call("send", "bob")).unwrap(),
            EffectResult::Applied { .. }
        ));
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
        assert!(fx
            .dispatch_until(&mut v, "mail", call(op, "x"), Some(stop))
            .unwrap()
            .is_none());
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
        fx.dispatch_until(
            &mut v,
            "mail",
            call("send", "x"),
            Some(CrashAfter::Authorized),
        )
        .unwrap();
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
        assert!(
            matches!(t[0], Ev::Published(_)) && t[1] == Ev::Sent(b"send bob".to_vec()),
            "{t:?}"
        );
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
        assert!(
            matches!(&r, EffectResult::NotApplied { reason } if reason.contains("ledger not shipped")),
            "{r:?}"
        );
        assert_eq!(p.applied(b"send bob"), 0);
        assert!(p.timeline().is_empty());
        assert_eq!(
            states(&v),
            vec![
                OutcomeState::DispatchAuthorized,
                OutcomeState::ConfirmedNotApplied
            ]
        );
        assert!(fx.authorized());
        // The next one goes through.
        assert!(matches!(
            fx.dispatch(&mut v, "mail", call("send", "carol")).unwrap(),
            EffectResult::Applied { .. }
        ));
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
        fx.dispatch_until(
            &mut v,
            "mail",
            call("send", "x"),
            Some(CrashAfter::Authorized),
        )
        .unwrap();
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
        let fault = prop_oneof![
            Just(Fault::None),
            Just(Fault::Lost),
            Just(Fault::ReplyLost),
            Just(Fault::Decline)
        ];
        let crash = prop_oneof![
            3 => Just(None),
            1 => Just(Some(CrashAfter::Intent)),
            1 => Just(Some(CrashAfter::Authorized)),
            1 => Just(Some(CrashAfter::Published)),
            1 => Just(Some(CrashAfter::Send)),
        ];
        let publish_fails = prop_oneof![4 => Just(false), 1 => Just(true)];
        (op, fault, crash, publish_fails).prop_map(|(op, fault, crash, publish_fails)| Step {
            op,
            fault,
            crash,
            publish_fails,
        })
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
