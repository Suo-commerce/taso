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
//! 5. The adapter sends exactly `plan.request`.
//! 6. The answer is recorded: `ConfirmedApplied` (receipt as evidence),
//!    `ConfirmedNotApplied` (reason), or `OutcomeUnknown`.  An unknown
//!    outcome on a barrier intent withdraws effect authority until it is
//!    reconciled or resolved.
//!
//! A crash anywhere leaves at worst an intent that reconciliation
//! settles.
//!
//! # Reconciliation (on open, before any authority)
//!
//! Every intent whose latest outcome is not terminal:
//! - none (crash after the intent) → `ConfirmedNotApplied`: dispatch was
//!   never authorized, so it never happened;
//! - `DispatchAuthorized` / `OutcomeUnknown`, by the intent's retry:
//!   - `ProviderDeduplicated` → re-send the recorded request; record what
//!     the provider says;
//!   - `Queryable` → probe; applied → `ConfirmedApplied`; not applied →
//!     send, record; unknown → stays open;
//!   - `UnsafeToRetry` → `OutcomeUnknown`, stays open: an operator
//!     decides.
//!   - no adapter for its provider any more → stays open.
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

use crate::chronicle::{ChronicleError, Layers};
use crate::vessel::{Vessel, VesselError};

/// What reconciliation did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Reconciled {
    /// Intents settled to a terminal outcome now.
    pub settled: Vec<OpId>,
    /// Barrier intents still open: obligations an operator must resolve.
    pub open: Vec<OpId>,
}

/// The effect engine of one Vessel.
pub struct Effects {
    registry: Registry,
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
    Send,
}

impl Effects {
    /// Start the engine on an opened Vessel: reconcile its ledger, then
    /// grant effect authority if nothing is left open.
    pub fn open<L: Layers>(
        registry: Registry,
        vessel: &mut Vessel<L>,
    ) -> Result<(Self, Reconciled), VesselError> {
        let mut e = Self { registry, next_op: 1, open: BTreeSet::new() };
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
        // 3. Send exactly the recorded request.
        let adapter = self.registry.get_mut(provider).expect("looked up above");
        let sent = adapter.send(op, &plan);
        if stop == Some(CrashAfter::Send) {
            return Ok(None);
        }
        // 4. Record what the provider said.
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
            .segment()
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
        let Some(adapter) = self.registry.get_mut(&i.provider) else {
            return mark_unknown(vessel);
        };
        let sent = match &i.retry {
            RetryPolicy::ProviderDeduplicated { .. } => adapter.send(i.op, &plan),
            RetryPolicy::Queryable { .. } => match adapter.probe(i.op, &plan) {
                Probed::Applied { receipt } => Sent::Applied { receipt },
                Probed::NotApplied => adapter.send(i.op, &plan),
                Probed::Unknown => return mark_unknown(vessel),
            },
            RetryPolicy::UnsafeToRetry => return mark_unknown(vessel),
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

    /// A fake provider that survives the Warden "crashing".
    #[derive(Clone)]
    struct Shared(Arc<Mutex<FakeProvider>>);

    impl Shared {
        fn new(name: &str) -> Self {
            Self(Arc::new(Mutex::new(FakeProvider::new(name))))
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
            .segment()
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

    // ── dispatch ────────────────────────────────────────────────────

    #[test]
    fn intent_before_dispatch_then_outcome() {
        let e = env();
        let p = Shared::new("mail");
        let mut v = vessel(&e);
        let (mut fx, r) = Effects::open(registry(&p), &mut v).unwrap();
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
        let (mut fx, _) = Effects::open(registry(&p), &mut v).unwrap();
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
        let (mut fx, _) = Effects::open(registry(&p), &mut v).unwrap();
        fx.dispatch(&mut v, "mail", call("read", "inbox")).unwrap();
        let Payload::Intent(i) = &ledger(&v)[0] else { panic!() };
        assert_eq!(i.barrier, None);
    }

    #[test]
    fn unknown_outcome_withdraws_authority_until_an_operator_resolves() {
        let e = env();
        let p = Shared::new("mail");
        let mut v = vessel(&e);
        let (mut fx, _) = Effects::open(registry(&p), &mut v).unwrap();
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
        let (mut fx, _) = Effects::open(registry(p), &mut v).unwrap();
        assert!(fx.dispatch_until(&mut v, "mail", call(op, "x"), Some(stop)).unwrap().is_none());
        drop((fx, v));
        let mut v = vessel(e);
        let (fx, r) = Effects::open(registry(p), &mut v).unwrap();
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
        let (mut fx, _) = Effects::open(registry(&p), &mut v).unwrap();
        fx.dispatch_until(&mut v, "mail", call("send", "x"), Some(CrashAfter::Authorized)).unwrap();
        drop((fx, v));
        let mut v = vessel(&e);
        let (fx, r) = Effects::open(Registry::new(), &mut v).unwrap();
        assert_eq!(r.open, vec![OpId::new(1)]);
        assert!(!fx.authorized());
        assert_eq!(p.applied(b"send x"), 0);
    }

    #[test]
    fn op_ids_continue_after_reopen() {
        let e = env();
        let p = Shared::new("mail");
        let mut v = vessel(&e);
        let (mut fx, _) = Effects::open(registry(&p), &mut v).unwrap();
        fx.dispatch(&mut v, "mail", call("send", "a")).unwrap();
        fx.dispatch(&mut v, "mail", call("send", "b")).unwrap();
        drop((fx, v));
        let mut v = vessel(&e);
        let (mut fx, _) = Effects::open(registry(&p), &mut v).unwrap();
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

    // ── property: never a duplicate, never a silent loss ────────────

    #[derive(Clone, Debug)]
    struct Step {
        op: &'static str,
        fault: Fault,
        crash: Option<CrashAfter>,
    }

    fn step() -> impl Strategy<Value = Step> {
        let op = prop_oneof![Just("send"), Just("put"), Just("fire"), Just("read")];
        let fault = prop_oneof![Just(Fault::None), Just(Fault::Lost), Just(Fault::ReplyLost), Just(Fault::Decline)];
        let crash = prop_oneof![
            3 => Just(None),
            1 => Just(Some(CrashAfter::Intent)),
            1 => Just(Some(CrashAfter::Authorized)),
            1 => Just(Some(CrashAfter::Send)),
        ];
        (op, fault, crash).prop_map(|(op, fault, crash)| Step { op, fault, crash })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(96))]

        /// Any sequence of effects, provider faults and crashes: no request
        /// is ever applied twice, and after every reconciliation each
        /// intent is either terminal or an open obligation.
        #[test]
        fn no_duplicates_and_nothing_silently_lost(steps in proptest::collection::vec(step(), 1..12)) {
            let e = env();
            let p = Shared::new("mail");
            let mut v = vessel(&e);
            let (mut fx, _) = Effects::open(registry(&p), &mut v).unwrap();
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
                let target = format!("t{n}");
                let r = fx.dispatch_until(&mut v, "mail", call(s.op, &target), s.crash).unwrap();
                if r.is_none() {
                    drop((fx, v));
                    v = vessel(&e);
                    let (f, rec) = Effects::open(registry(&p), &mut v).unwrap();
                    fx = f;
                    prop_assert_eq!(rec.open.clone(), fx.open_obligations());
                }
                prop_assert!(p.no_duplicates(), "a request was applied twice");
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
