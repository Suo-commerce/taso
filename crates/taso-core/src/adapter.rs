//! Effect adapter model and fake provider for crash-point testing (v1.0 §9.3).
//!
//! Models the v0.4 §7.2 dispatch sequence with injectable crash points and
//! a fake provider that counts distinct effects.  Reconciliation after a
//! crash follows §7.2–7.4: `ProviderDeduplicated` → re-dispatch (safe);
//! `Queryable` → query + record; `UnsafeToRetry` → `OutcomeUnknown` +
//! open obligation.
//!
//! Normative references: v0.4 §§7.1–7.6, v1.0 §9.3, §12 P0.

use std::collections::{BTreeMap, HashSet};

use crate::envelope::Stream;
use crate::model::{AppendError, Coordinator, WardenModel};
use crate::record::{
    BarrierId, Consequence, Dispatch, IntentRecord, OpId, OutcomeRecord,
    OutcomeState, Payload, RetryPolicy,
};

// ── CrashPoint ─────────────────────────────────────────────────────

/// Where a crash interrupts the v0.4 §7.2 dispatch sequence.
///
/// Each variant represents a distinct point of failure, used by
/// [`AdapterModel::dispatch_effect`] to simulate a crash at that step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CrashPoint {
    /// Intent recorded, crash before `DispatchAuthorized`.
    AfterIntent,
    /// `DispatchAuthorized` recorded, crash before dispatch.
    AfterDispatchAuth,
    /// Provider never received the request (transport failure).
    DuringDispatchNotReceived,
    /// Provider applied the effect but the adapter crashed before
    /// recording the outcome.
    DuringDispatchReceived,
    /// Dispatch succeeded, crash before `ConfirmedApplied` is recorded.
    AfterDispatch,
}

// ── DispatchError ──────────────────────────────────────────────────

/// Why [`AdapterModel::dispatch_effect`] did not complete.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DispatchError {
    /// The coordinator refused the append.
    Append(AppendError),
    /// A simulated crash interrupted the sequence.
    Crash(CrashPoint),
}

// ── FakeProvider ───────────────────────────────────────────────────

/// An in-memory effect provider for testing.
///
/// Tracks how many times each operation was actually applied and
/// supports all three retry policies: deduplication by key,
/// queryable by probe, and untracked (unsafe-to-retry).
#[derive(Clone, Debug, Default)]
pub struct FakeProvider {
    /// Per-op application count (keyed by `OpId::get()`).
    applied: BTreeMap<u64, usize>,
    /// Idempotency keys that have been seen (`ProviderDeduplicated`).
    dedup_keys: HashSet<Vec<u8>>,
    /// Probes for effects that were applied (`Queryable`).
    query_probes: HashSet<Vec<u8>>,
}

impl FakeProvider {
    /// Create an empty provider.
    pub fn new() -> Self {
        Self::default()
    }

    /// Dispatch with deduplication by key (`ProviderDeduplicated`).
    ///
    /// If `key` has been seen, the effect was already applied — no-op.
    /// Returns `true` in both cases (the provider confirms application).
    pub fn dispatch_dedup(&mut self, op: OpId, key: &[u8]) -> bool {
        if self.dedup_keys.insert(key.to_vec()) {
            // New key — actually apply the effect.
            *self.applied.entry(op.get()).or_insert(0) += 1;
        }
        true
    }

    /// Dispatch a queryable effect (`Queryable`).
    pub fn dispatch_queryable(&mut self, op: OpId, probe: &[u8]) {
        self.query_probes.insert(probe.to_vec());
        *self.applied.entry(op.get()).or_insert(0) += 1;
    }

    /// Dispatch an untracked effect (`UnsafeToRetry`).
    pub fn dispatch_untracked(&mut self, op: OpId) {
        *self.applied.entry(op.get()).or_insert(0) += 1;
    }

    /// Query whether an effect was applied (`Queryable`).
    pub fn query(&self, probe: &[u8]) -> bool {
        self.query_probes.contains(probe)
    }

    /// How many times a specific operation was applied.
    pub fn effect_count(&self, op: OpId) -> usize {
        self.applied.get(&op.get()).copied().unwrap_or(0)
    }

    /// Total effects applied across all operations.
    pub fn total_effects(&self) -> usize {
        self.applied.values().sum()
    }

    /// True if no operation was applied more than once.
    pub fn no_duplicates(&self) -> bool {
        self.applied.values().all(|&c| c <= 1)
    }

    /// Iterator over all operations that have been applied.
    pub fn applied_ops(&self) -> impl Iterator<Item = OpId> + '_ {
        self.applied.keys().map(|&id| OpId::new(id))
    }
}

// ── Obligation ─────────────────────────────────────────────────────

/// An open obligation from an `UnsafeToRetry` intent left in
/// `OutcomeUnknown` after reconciliation (v0.4 §7.4, §14).
///
/// Requires an operator decision before effect authority is granted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Obligation {
    /// The operation with unknown outcome.
    pub op: OpId,
    /// The barrier associated with this intent.
    pub barrier: BarrierId,
}

// ── AdapterModel ───────────────────────────────────────────────────

/// In-memory adapter model for the v0.4 §7.2 dispatch sequence.
///
/// Builds intent and outcome records on [`Stream::Effect`] via a
/// [`WardenModel`], dispatches to a [`FakeProvider`], and supports
/// crash-point injection for property testing.
#[derive(Clone, Debug)]
pub struct AdapterModel {
    next_op: u64,
    next_barrier: u64,
}

impl Default for AdapterModel {
    fn default() -> Self {
        Self::new()
    }
}

impl AdapterModel {
    /// Create a fresh adapter model.
    pub fn new() -> Self {
        Self { next_op: 1, next_barrier: 1 }
    }

    /// Resume from existing state by scanning the coordinator log.
    ///
    /// Sets `next_op` and `next_barrier` past any already-used values.
    pub fn resume(coord: &Coordinator) -> Self {
        let mut max_op = 0u64;
        let mut max_barrier = 0u64;
        for record in coord.log() {
            if record.envelope.stream != Stream::Effect {
                continue;
            }
            if let Payload::Intent(intent) = &record.payload {
                max_op = max_op.max(intent.op.get());
                if let Some(b) = intent.barrier {
                    max_barrier = max_barrier.max(b.get());
                }
            }
            if let Payload::Outcome(outcome) = &record.payload {
                max_op = max_op.max(outcome.op.get());
            }
        }
        Self { next_op: max_op + 1, next_barrier: max_barrier + 1 }
    }

    /// Dispatch an effect following the v0.4 §7.2 sequence.
    ///
    /// 1. Write `Intent` to `Stream::Effect` (barrier set iff
    ///    `consequence ≠ NoExternalMutation`).
    /// 2. Write `Outcome(DispatchAuthorized)`.
    /// 3. Dispatch to the provider.
    /// 4. Write `Outcome(ConfirmedApplied)`.
    ///
    /// An optional `crash_at` interrupts the sequence at the specified
    /// point and returns [`DispatchError::Crash`].
    pub fn dispatch_effect(
        &mut self,
        warden: &mut WardenModel,
        coord: &mut Coordinator,
        provider: &mut FakeProvider,
        footprint: &[u8],
        retry: RetryPolicy,
        consequence: Consequence,
        crash_at: Option<CrashPoint>,
    ) -> Result<OpId, DispatchError> {
        let op = OpId::new(self.next_op);
        self.next_op += 1;

        let barrier = match consequence {
            Consequence::NoExternalMutation => None,
            _ => {
                let b = BarrierId::new(self.next_barrier);
                self.next_barrier += 1;
                Some(b)
            }
        };

        // Step 1: write Intent.
        let intent = IntentRecord {
            op,
            request: Vec::new(),
            footprint: footprint.to_vec(),
            dispatch: Dispatch::Immediate,
            retry: retry.clone(),
            consequence,
            authority: b"model-authority".to_vec(),
            barrier,
        };
        warden
            .append(coord, Stream::Effect, Payload::Intent(intent))
            .map_err(DispatchError::Append)?;

        if crash_at == Some(CrashPoint::AfterIntent) {
            return Err(DispatchError::Crash(CrashPoint::AfterIntent));
        }

        // Step 2: write Outcome(DispatchAuthorized).
        let auth = OutcomeRecord {
            op,
            state: OutcomeState::DispatchAuthorized,
            evidence: None,
        };
        warden
            .append(coord, Stream::Effect, Payload::Outcome(auth))
            .map_err(DispatchError::Append)?;

        if crash_at == Some(CrashPoint::AfterDispatchAuth) {
            return Err(DispatchError::Crash(CrashPoint::AfterDispatchAuth));
        }

        // Step 3: dispatch to provider.
        if crash_at == Some(CrashPoint::DuringDispatchNotReceived) {
            return Err(DispatchError::Crash(
                CrashPoint::DuringDispatchNotReceived,
            ));
        }

        Self::do_dispatch(provider, op, &retry);

        if crash_at == Some(CrashPoint::DuringDispatchReceived) {
            return Err(DispatchError::Crash(
                CrashPoint::DuringDispatchReceived,
            ));
        }

        if crash_at == Some(CrashPoint::AfterDispatch) {
            return Err(DispatchError::Crash(CrashPoint::AfterDispatch));
        }

        // Step 4: write Outcome(ConfirmedApplied).
        let confirmed = OutcomeRecord {
            op,
            state: OutcomeState::ConfirmedApplied,
            evidence: Some(b"provider-receipt".to_vec()),
        };
        warden
            .append(coord, Stream::Effect, Payload::Outcome(confirmed))
            .map_err(DispatchError::Append)?;

        Ok(op)
    }

    /// Reconcile the effect ledger after a crash (v0.4 §7.2).
    ///
    /// Scans the coordinator log for `Stream::Effect` records and
    /// resolves every intent not in a terminal state:
    ///
    /// - No outcome → `ConfirmedNotApplied` (dispatch was never authorized).
    /// - `DispatchAuthorized` or `OutcomeUnknown`:
    ///   - `ProviderDeduplicated` → re-dispatch + `ConfirmedApplied`.
    ///   - `Queryable` → query; if applied → `ConfirmedApplied`;
    ///     if not → dispatch + `ConfirmedApplied`.
    ///   - `UnsafeToRetry` → `OutcomeUnknown` + open obligation.
    ///
    /// Returns the list of open obligations (empty if none).
    pub fn reconcile(
        &self,
        warden: &mut WardenModel,
        coord: &mut Coordinator,
        provider: &mut FakeProvider,
    ) -> Result<Vec<Obligation>, AppendError> {
        // Collect intent info and latest outcome per op.
        // Clone what we need so the coord borrow is released before appends.
        let mut intents: BTreeMap<u64, IntentSnapshot> = BTreeMap::new();
        let mut outcomes: BTreeMap<u64, OutcomeState> = BTreeMap::new();

        for record in coord.log() {
            if record.envelope.stream != Stream::Effect {
                continue;
            }
            match &record.payload {
                Payload::Intent(intent) => {
                    intents.insert(
                        intent.op.get(),
                        IntentSnapshot {
                            op: intent.op,
                            retry: intent.retry.clone(),
                            barrier: intent.barrier,
                        },
                    );
                }
                Payload::Outcome(outcome) => {
                    outcomes.insert(outcome.op.get(), outcome.state);
                }
                _ => {}
            }
        }

        let mut obligations = Vec::new();

        // Process in deterministic op-id order (BTreeMap iterates sorted).
        let ops: Vec<(u64, IntentSnapshot)> = intents.into_iter().collect();

        for (op_id, info) in ops {
            let state = outcomes.get(&op_id).copied();

            match state {
                // Terminal — nothing to do.
                Some(OutcomeState::ConfirmedApplied)
                | Some(OutcomeState::ConfirmedNotApplied) => {}

                // No outcome: dispatch was never authorized.
                None | Some(OutcomeState::Prepared) => {
                    let outcome = OutcomeRecord {
                        op: info.op,
                        state: OutcomeState::ConfirmedNotApplied,
                        evidence: Some(b"reconcile:no-dispatch".to_vec()),
                    };
                    warden.append(
                        coord,
                        Stream::Effect,
                        Payload::Outcome(outcome),
                    )?;
                }

                // Dispatch was authorized or outcome is unknown.
                Some(OutcomeState::DispatchAuthorized)
                | Some(OutcomeState::OutcomeUnknown) => {
                    match &info.retry {
                        RetryPolicy::ProviderDeduplicated { key } => {
                            provider.dispatch_dedup(info.op, key);
                            let outcome = OutcomeRecord {
                                op: info.op,
                                state: OutcomeState::ConfirmedApplied,
                                evidence: Some(
                                    b"reconcile:reissued".to_vec(),
                                ),
                            };
                            warden.append(
                                coord,
                                Stream::Effect,
                                Payload::Outcome(outcome),
                            )?;
                        }
                        RetryPolicy::Queryable { probe } => {
                            if provider.query(probe) {
                                let outcome = OutcomeRecord {
                                    op: info.op,
                                    state: OutcomeState::ConfirmedApplied,
                                    evidence: Some(
                                        b"reconcile:query-applied".to_vec(),
                                    ),
                                };
                                warden.append(
                                    coord,
                                    Stream::Effect,
                                    Payload::Outcome(outcome),
                                )?;
                            } else {
                                provider
                                    .dispatch_queryable(info.op, probe);
                                let outcome = OutcomeRecord {
                                    op: info.op,
                                    state: OutcomeState::ConfirmedApplied,
                                    evidence: Some(
                                        b"reconcile:query-dispatched"
                                            .to_vec(),
                                    ),
                                };
                                warden.append(
                                    coord,
                                    Stream::Effect,
                                    Payload::Outcome(outcome),
                                )?;
                            }
                        }
                        RetryPolicy::UnsafeToRetry => {
                            if state != Some(OutcomeState::OutcomeUnknown) {
                                let outcome = OutcomeRecord {
                                    op: info.op,
                                    state: OutcomeState::OutcomeUnknown,
                                    evidence: None,
                                };
                                warden.append(
                                    coord,
                                    Stream::Effect,
                                    Payload::Outcome(outcome),
                                )?;
                            }
                            if let Some(barrier) = info.barrier {
                                obligations.push(Obligation {
                                    op: info.op,
                                    barrier,
                                });
                            }
                        }
                    }
                }
            }
        }

        Ok(obligations)
    }

    /// Dispatch to the provider based on the retry policy.
    fn do_dispatch(
        provider: &mut FakeProvider,
        op: OpId,
        retry: &RetryPolicy,
    ) {
        match retry {
            RetryPolicy::ProviderDeduplicated { key } => {
                provider.dispatch_dedup(op, key);
            }
            RetryPolicy::Queryable { probe } => {
                provider.dispatch_queryable(op, probe);
            }
            RetryPolicy::UnsafeToRetry => {
                provider.dispatch_untracked(op);
            }
        }
    }
}

/// Snapshot of an intent's reconciliation-relevant fields.
struct IntentSnapshot {
    op: OpId,
    retry: RetryPolicy,
    barrier: Option<BarrierId>,
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::{ChronicleId, Epoch, Lsn};
    use crate::model::WardenId;

    fn cid() -> ChronicleId {
        ChronicleId::from_bytes([1; 16])
    }
    fn warden_a() -> WardenId {
        WardenId::new(1)
    }

    fn setup() -> (Coordinator, WardenModel) {
        let c = Coordinator::new(cid(), warden_a());
        let w = WardenModel::new(warden_a(), cid(), Epoch::FIRST);
        (c, w)
    }

    /// Simulate crash recovery: new WardenModel resumed from coordinator.
    fn recover(coord: &Coordinator) -> WardenModel {
        WardenModel::resume(
            warden_a(),
            cid(),
            coord.ownership().epoch,
            coord.head(),
            Lsn::new(coord.head().lsn.get() + 1),
        )
    }

    fn dedup_retry(key: &[u8]) -> RetryPolicy {
        RetryPolicy::ProviderDeduplicated { key: key.to_vec() }
    }

    fn queryable_retry(probe: &[u8]) -> RetryPolicy {
        RetryPolicy::Queryable { probe: probe.to_vec() }
    }

    const ALL_CRASH_POINTS: [CrashPoint; 5] = [
        CrashPoint::AfterIntent,
        CrashPoint::AfterDispatchAuth,
        CrashPoint::DuringDispatchNotReceived,
        CrashPoint::DuringDispatchReceived,
        CrashPoint::AfterDispatch,
    ];

    // ── Successful dispatch ────────────────────────────────────────

    #[test]
    fn successful_dispatch_records_full_sequence() {
        let (mut coord, mut warden) = setup();
        let mut provider = FakeProvider::new();
        let mut adapter = AdapterModel::new();

        let op = adapter
            .dispatch_effect(
                &mut warden,
                &mut coord,
                &mut provider,
                b"mail:send",
                dedup_retry(b"key-1"),
                Consequence::Irreversible,
                None,
            )
            .unwrap();

        assert_eq!(op, OpId::new(1));
        assert_eq!(provider.effect_count(op), 1);

        // Log: Intent, Outcome(DispatchAuthorized), Outcome(ConfirmedApplied).
        let effects: Vec<_> = coord
            .log()
            .iter()
            .filter(|r| r.envelope.stream == Stream::Effect)
            .collect();
        assert_eq!(effects.len(), 3);

        assert!(matches!(&effects[0].payload, Payload::Intent(_)));
        assert!(matches!(
            &effects[1].payload,
            Payload::Outcome(o) if o.state == OutcomeState::DispatchAuthorized
        ));
        assert!(matches!(
            &effects[2].payload,
            Payload::Outcome(o) if o.state == OutcomeState::ConfirmedApplied
        ));
    }

    #[test]
    fn no_external_mutation_skips_barrier() {
        let (mut coord, mut warden) = setup();
        let mut provider = FakeProvider::new();
        let mut adapter = AdapterModel::new();

        adapter
            .dispatch_effect(
                &mut warden,
                &mut coord,
                &mut provider,
                b"compute:hash",
                dedup_retry(b"key-1"),
                Consequence::NoExternalMutation,
                None,
            )
            .unwrap();

        let intent = coord
            .log()
            .iter()
            .filter(|r| r.envelope.stream == Stream::Effect)
            .find_map(|r| match &r.payload {
                Payload::Intent(i) => Some(i),
                _ => None,
            })
            .unwrap();
        assert!(intent.barrier.is_none());
    }

    // ── One test per crash point ───────────────────────────────────

    #[test]
    fn crash_after_intent() {
        let (mut coord, mut warden) = setup();
        let mut provider = FakeProvider::new();
        let mut adapter = AdapterModel::new();

        let result = adapter.dispatch_effect(
            &mut warden,
            &mut coord,
            &mut provider,
            b"mail:send",
            dedup_retry(b"key-1"),
            Consequence::Irreversible,
            Some(CrashPoint::AfterIntent),
        );
        assert_eq!(
            result,
            Err(DispatchError::Crash(CrashPoint::AfterIntent))
        );
        assert_eq!(provider.effect_count(OpId::new(1)), 0);

        // Recover and reconcile.
        let mut w = recover(&coord);
        let adapter = AdapterModel::resume(&coord);
        let obligations =
            adapter.reconcile(&mut w, &mut coord, &mut provider).unwrap();

        assert!(obligations.is_empty());
        // No dispatch ever happened; reconciled to ConfirmedNotApplied.
        assert_eq!(provider.effect_count(OpId::new(1)), 0);
    }

    #[test]
    fn crash_after_dispatch_auth() {
        let (mut coord, mut warden) = setup();
        let mut provider = FakeProvider::new();
        let mut adapter = AdapterModel::new();

        let result = adapter.dispatch_effect(
            &mut warden,
            &mut coord,
            &mut provider,
            b"mail:send",
            dedup_retry(b"key-1"),
            Consequence::Irreversible,
            Some(CrashPoint::AfterDispatchAuth),
        );
        assert_eq!(
            result,
            Err(DispatchError::Crash(CrashPoint::AfterDispatchAuth))
        );
        assert_eq!(provider.effect_count(OpId::new(1)), 0);

        let mut w = recover(&coord);
        let adapter = AdapterModel::resume(&coord);
        let obligations =
            adapter.reconcile(&mut w, &mut coord, &mut provider).unwrap();

        assert!(obligations.is_empty());
        // Reconcile re-dispatched via dedup key.
        assert_eq!(provider.effect_count(OpId::new(1)), 1);
    }

    #[test]
    fn crash_during_dispatch_not_received() {
        let (mut coord, mut warden) = setup();
        let mut provider = FakeProvider::new();
        let mut adapter = AdapterModel::new();

        let result = adapter.dispatch_effect(
            &mut warden,
            &mut coord,
            &mut provider,
            b"mail:send",
            dedup_retry(b"key-1"),
            Consequence::Irreversible,
            Some(CrashPoint::DuringDispatchNotReceived),
        );
        assert_eq!(
            result,
            Err(DispatchError::Crash(CrashPoint::DuringDispatchNotReceived))
        );
        assert_eq!(provider.effect_count(OpId::new(1)), 0);

        let mut w = recover(&coord);
        let adapter = AdapterModel::resume(&coord);
        let obligations =
            adapter.reconcile(&mut w, &mut coord, &mut provider).unwrap();

        assert!(obligations.is_empty());
        assert_eq!(provider.effect_count(OpId::new(1)), 1);
    }

    #[test]
    fn crash_during_dispatch_received() {
        let (mut coord, mut warden) = setup();
        let mut provider = FakeProvider::new();
        let mut adapter = AdapterModel::new();

        let result = adapter.dispatch_effect(
            &mut warden,
            &mut coord,
            &mut provider,
            b"mail:send",
            dedup_retry(b"key-1"),
            Consequence::Irreversible,
            Some(CrashPoint::DuringDispatchReceived),
        );
        assert_eq!(
            result,
            Err(DispatchError::Crash(CrashPoint::DuringDispatchReceived))
        );
        // Provider received and applied the effect.
        assert_eq!(provider.effect_count(OpId::new(1)), 1);

        let mut w = recover(&coord);
        let adapter = AdapterModel::resume(&coord);
        let obligations =
            adapter.reconcile(&mut w, &mut coord, &mut provider).unwrap();

        assert!(obligations.is_empty());
        // Dedup key prevents duplicate — still exactly 1.
        assert_eq!(provider.effect_count(OpId::new(1)), 1);
    }

    #[test]
    fn crash_after_dispatch() {
        let (mut coord, mut warden) = setup();
        let mut provider = FakeProvider::new();
        let mut adapter = AdapterModel::new();

        let result = adapter.dispatch_effect(
            &mut warden,
            &mut coord,
            &mut provider,
            b"mail:send",
            dedup_retry(b"key-1"),
            Consequence::Irreversible,
            Some(CrashPoint::AfterDispatch),
        );
        assert_eq!(
            result,
            Err(DispatchError::Crash(CrashPoint::AfterDispatch))
        );
        assert_eq!(provider.effect_count(OpId::new(1)), 1);

        let mut w = recover(&coord);
        let adapter = AdapterModel::resume(&coord);
        let obligations =
            adapter.reconcile(&mut w, &mut coord, &mut provider).unwrap();

        assert!(obligations.is_empty());
        assert_eq!(provider.effect_count(OpId::new(1)), 1);
    }

    // ── Mail-duplication trace ─────────────────────────────────────

    /// One email, crash anywhere, recover + re-attempt → exactly 1
    /// provider effect.  This is the spec's primary crash-safety trace
    /// (v0.4 §12 P0, v1.0 §9.3).
    #[test]
    fn mail_duplication_trace() {
        for &crash_at in &ALL_CRASH_POINTS {
            let (mut coord, mut warden) = setup();
            let mut provider = FakeProvider::new();
            let mut adapter = AdapterModel::new();

            // Attempt — crashes.
            let _ = adapter.dispatch_effect(
                &mut warden,
                &mut coord,
                &mut provider,
                b"mail:send",
                dedup_retry(b"mail-001"),
                Consequence::Irreversible,
                Some(crash_at),
            );

            // Recover and reconcile.
            let mut w = recover(&coord);
            let mut adapter = AdapterModel::resume(&coord);
            adapter
                .reconcile(&mut w, &mut coord, &mut provider)
                .unwrap();

            // Re-attempt with the same dedup key.
            adapter
                .dispatch_effect(
                    &mut w,
                    &mut coord,
                    &mut provider,
                    b"mail:send",
                    dedup_retry(b"mail-001"),
                    Consequence::Irreversible,
                    None,
                )
                .unwrap();

            assert_eq!(
                provider.total_effects(),
                1,
                "crash at {crash_at:?}: expected exactly 1 effect, got {}",
                provider.total_effects(),
            );
        }
    }

    // ── Dispatch-authorization check ───────────────────────────────

    /// Every provider effect has a prior intent in the log (v0.4 §7.1,
    /// §12 P0).
    #[test]
    fn every_provider_effect_has_a_prior_intent() {
        let (mut coord, mut warden) = setup();
        let mut provider = FakeProvider::new();
        let mut adapter = AdapterModel::new();

        for i in 0..5 {
            adapter
                .dispatch_effect(
                    &mut warden,
                    &mut coord,
                    &mut provider,
                    format!("effect-{i}").as_bytes(),
                    dedup_retry(format!("key-{i}").as_bytes()),
                    Consequence::Irreversible,
                    None,
                )
                .unwrap();
        }

        // Collect op ids with intents in the log.
        let intents_in_log: HashSet<u64> = coord
            .log()
            .iter()
            .filter(|r| r.envelope.stream == Stream::Effect)
            .filter_map(|r| match &r.payload {
                Payload::Intent(i) => Some(i.op.get()),
                _ => None,
            })
            .collect();

        // Every applied op must have a prior intent.
        for op in provider.applied_ops() {
            assert!(
                intents_in_log.contains(&op.get()),
                "op {} dispatched without a prior intent",
                op.get(),
            );
        }
    }

    // ── Queryable reconciliation ───────────────────────────────────

    #[test]
    fn queryable_crash_received_reconciles_via_query() {
        let (mut coord, mut warden) = setup();
        let mut provider = FakeProvider::new();
        let mut adapter = AdapterModel::new();

        let result = adapter.dispatch_effect(
            &mut warden,
            &mut coord,
            &mut provider,
            b"api:call",
            queryable_retry(b"probe-1"),
            Consequence::Irreversible,
            Some(CrashPoint::DuringDispatchReceived),
        );
        assert!(result.is_err());
        assert_eq!(provider.effect_count(OpId::new(1)), 1);
        assert!(provider.query(b"probe-1"));

        let mut w = recover(&coord);
        let adapter = AdapterModel::resume(&coord);
        let obligations =
            adapter.reconcile(&mut w, &mut coord, &mut provider).unwrap();

        assert!(obligations.is_empty());
        // Query found the effect; no duplicate dispatch.
        assert_eq!(provider.effect_count(OpId::new(1)), 1);
    }

    #[test]
    fn queryable_crash_not_received_reconciles_via_dispatch() {
        let (mut coord, mut warden) = setup();
        let mut provider = FakeProvider::new();
        let mut adapter = AdapterModel::new();

        let result = adapter.dispatch_effect(
            &mut warden,
            &mut coord,
            &mut provider,
            b"api:call",
            queryable_retry(b"probe-1"),
            Consequence::Irreversible,
            Some(CrashPoint::DuringDispatchNotReceived),
        );
        assert!(result.is_err());
        assert_eq!(provider.effect_count(OpId::new(1)), 0);
        assert!(!provider.query(b"probe-1"));

        let mut w = recover(&coord);
        let adapter = AdapterModel::resume(&coord);
        let obligations =
            adapter.reconcile(&mut w, &mut coord, &mut provider).unwrap();

        assert!(obligations.is_empty());
        // Query found nothing; reconcile dispatched.
        assert_eq!(provider.effect_count(OpId::new(1)), 1);
    }

    // ── UnsafeToRetry reconciliation ───────────────────────────────

    #[test]
    fn unsafe_crash_received_leaves_obligation() {
        let (mut coord, mut warden) = setup();
        let mut provider = FakeProvider::new();
        let mut adapter = AdapterModel::new();

        let result = adapter.dispatch_effect(
            &mut warden,
            &mut coord,
            &mut provider,
            b"payment:charge",
            RetryPolicy::UnsafeToRetry,
            Consequence::Irreversible,
            Some(CrashPoint::DuringDispatchReceived),
        );
        assert!(result.is_err());
        assert_eq!(provider.effect_count(OpId::new(1)), 1);

        let mut w = recover(&coord);
        let adapter = AdapterModel::resume(&coord);
        let obligations =
            adapter.reconcile(&mut w, &mut coord, &mut provider).unwrap();

        assert_eq!(obligations.len(), 1);
        assert_eq!(obligations[0].op, OpId::new(1));
        assert_eq!(obligations[0].barrier, BarrierId::new(1));
        // Provider was NOT re-dispatched — still exactly 1.
        assert_eq!(provider.effect_count(OpId::new(1)), 1);
    }

    // ── Property test ──────────────────────────────────────────────

    mod prop {
        use super::*;
        use proptest::prelude::*;

        fn crash_strategy() -> impl Strategy<Value = Option<CrashPoint>> {
            prop_oneof![
                5 => Just(None),
                1 => Just(Some(CrashPoint::AfterIntent)),
                1 => Just(Some(CrashPoint::AfterDispatchAuth)),
                1 => Just(Some(CrashPoint::DuringDispatchNotReceived)),
                1 => Just(Some(CrashPoint::DuringDispatchReceived)),
                1 => Just(Some(CrashPoint::AfterDispatch)),
            ]
        }

        proptest! {
            #![proptest_config(ProptestConfig {
                cases: 10_000,
                ..ProptestConfig::default()
            })]

            /// 10k random crash schedules → zero duplicate provider
            /// effects (v0.4 §12 P0, v1.0 §9.3).
            #[test]
            fn no_duplicate_effects(
                schedule in proptest::collection::vec(
                    crash_strategy(), 1..100,
                )
            ) {
                let mut coord = Coordinator::new(cid(), warden_a());
                let mut warden =
                    WardenModel::new(warden_a(), cid(), Epoch::FIRST);
                let mut provider = FakeProvider::new();
                let mut adapter = AdapterModel::new();

                for (i, crash_at) in schedule.iter().enumerate() {
                    let key = format!("key-{i}").into_bytes();
                    let result = adapter.dispatch_effect(
                        &mut warden,
                        &mut coord,
                        &mut provider,
                        format!("effect-{i}").as_bytes(),
                        dedup_retry(&key),
                        Consequence::Irreversible,
                        *crash_at,
                    );

                    if result.is_err() {
                        warden = recover(&coord);
                        adapter = AdapterModel::resume(&coord);
                        adapter
                            .reconcile(
                                &mut warden,
                                &mut coord,
                                &mut provider,
                            )
                            .unwrap();
                    }
                }

                // No operation was applied more than once.
                prop_assert!(
                    provider.no_duplicates(),
                    "duplicate effects detected after {} operations",
                    schedule.len(),
                );

                // Every accepted record verifies.
                for r in coord.log() {
                    prop_assert!(
                        r.verify(),
                        "record at lsn {} failed verify",
                        r.envelope.lsn.get(),
                    );
                }

                // Chain is linked.
                let log = coord.log();
                for i in 1..log.len() {
                    prop_assert_eq!(
                        log[i].envelope.prev,
                        log[i - 1].envelope.hash,
                        "chain break between lsn {} and {}",
                        log[i - 1].envelope.lsn.get(),
                        log[i].envelope.lsn.get(),
                    );
                }
            }
        }
    }
}
