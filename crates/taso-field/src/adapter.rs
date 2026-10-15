//! Adapters: the Warden's knowledge of each effect provider (v0.4 §7.1).
//!
//! A tool in a Vessel asks for an effect with a provider name, an
//! operation and opaque arguments.  The adapter for that provider — code
//! running in the Warden, outside the Vessel — decides everything else:
//! the exact request it will send, the canonical footprint, how it can be
//! retried, its consequence, whether it may be deferred, and which
//! authority permits it.  Whatever a tool writes into its arguments about
//! itself is ignored, because nothing here reads it as a claim.  A
//! provider with no adapter is refused before dispatch; it is never
//! treated as "unknown, probably fine".
//!
//! # Contract
//!
//! - [`Adapter::plan`] is pure and deterministic: the same `(op, call)`
//!   always gives the same [`Plan`], and planning has no side effects.  A
//!   refusal happens here, before anything is recorded.
//! - The [`Plan`] is made after the operation id is assigned, so a
//!   `ProviderDeduplicated` key can be derived from the op id and stays
//!   the same on every re-issue.
//! - [`Adapter::send`] sends exactly `plan.request` and reports what the
//!   provider said; a lost reply is [`Sent::Unknown`], never a guess.
//! - [`Adapter::probe`] answers, for a `Queryable` plan, whether the
//!   effect happened.  It must not cause it.
//! - Credentials live inside the adapter.  `plan.request` and
//!   `plan.authority` name them, never contain them.
//!
//! `plan.request` must be durable before dispatch so that a
//! `ProviderDeduplicated` intent can be re-issued after a crash with the
//! same bytes (v0.4 §7.2); where it is recorded is the dispatch engine's
//! concern.
//!
//! Normative references: v0.4 §7.1–7.3, §7.6.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use taso_core::record::{Consequence, Dispatch, OpId, RetryPolicy};

// ── Types ───────────────────────────────────────────────────────────

/// What a tool asked for, as it arrived through the Field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Call {
    /// The operation name.
    pub operation: String,
    /// Its arguments, opaque.
    pub args: Vec<u8>,
}

/// Everything the adapter decided about one effect.  The intent record is
/// built from this, never from the call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Plan {
    /// The exact request [`Adapter::send`] will send, in the adapter's own
    /// normalised form.
    pub request: Vec<u8>,
    /// The canonical set of resources it touches (v0.4 §7.4 conflict
    /// domain).
    pub footprint: Vec<u8>,
    /// How it can be retried after a crash.
    pub retry: RetryPolicy,
    /// What it does to the world.
    pub consequence: Consequence,
    /// Now, or at the next Seal.
    pub dispatch: Dispatch,
    /// Which credential or lease permits it (a name, not a secret).
    pub authority: Vec<u8>,
}

/// Why an adapter refused a call before anything was recorded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The provider has no such operation.
    UnknownOperation(String),
    /// The arguments are not valid for the operation.
    BadArgs(String),
    /// The adapter's own policy forbids it.
    Policy(String),
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownOperation(op) => write!(f, "unknown operation {op:?}"),
            Self::BadArgs(why) => write!(f, "bad arguments: {why}"),
            Self::Policy(why) => write!(f, "refused by policy: {why}"),
        }
    }
}

/// What the provider said to a send.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Sent {
    /// It happened.
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

/// What a probe found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Probed {
    /// The effect happened.
    Applied {
        /// Provider receipt, opaque.
        receipt: Vec<u8>,
    },
    /// The effect did not happen.
    NotApplied,
    /// The provider could not say.
    Unknown,
}

/// One effect provider, seen from the Warden.
pub trait Adapter: Send {
    /// The provider name this adapter serves, as a Field request names it.
    fn provider(&self) -> &str;

    /// Decide everything about `call` as operation `op`, or refuse.  Pure
    /// and deterministic.
    fn plan(&self, op: OpId, call: &Call) -> Result<Plan, Refusal>;

    /// Send `plan.request` and report what the provider said.
    fn send(&mut self, op: OpId, plan: &Plan) -> Sent;

    /// For a `Queryable` plan: did the effect happen?  Must not cause it.
    fn probe(&mut self, op: OpId, plan: &Plan) -> Probed;
}

// ── Registry ────────────────────────────────────────────────────────

/// The adapters a Warden has, by provider name.  A provider not here is
/// refused.
#[derive(Default)]
pub struct Registry {
    adapters: BTreeMap<String, Box<dyn Adapter>>,
}

impl Registry {
    /// An empty registry: every effect is refused.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an adapter.  Returns `false`, and keeps the existing one, if its
    /// provider is already registered: replacing an adapter is a
    /// deployment decision, not a runtime one.
    pub fn register(&mut self, adapter: Box<dyn Adapter>) -> bool {
        let name = adapter.provider().to_string();
        if self.adapters.contains_key(&name) {
            return false;
        }
        self.adapters.insert(name, adapter);
        true
    }

    /// The adapter for `provider`, matched exactly.
    pub fn get_mut(&mut self, provider: &str) -> Option<&mut (dyn Adapter + 'static)> {
        self.adapters.get_mut(provider).map(|a| a.as_mut())
    }

    /// Registered provider names.
    pub fn providers(&self) -> impl Iterator<Item = &str> {
        self.adapters.keys().map(String::as_str)
    }
}

// ── Fake provider ───────────────────────────────────────────────────

/// What the fake provider does on its next `send`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    /// Behave.
    None,
    /// The request never arrives: nothing happens, the reply is lost.
    Lost,
    /// The effect happens, but the reply is lost.
    ReplyLost,
    /// The provider declines.
    Decline,
}

/// An in-process provider for tests, covering every retry policy and
/// consequence (the real-provider counterpart of the P0 model's fake):
///
/// | operation | consequence        | retry                         |
/// |-----------|--------------------|-------------------------------|
/// | `send`    | Irreversible       | ProviderDeduplicated by op    |
/// | `put`     | Irreversible       | Queryable by op               |
/// | `del`     | Irreversible       | ProviderDeduplicated by op    |
/// | `fire`    | Irreversible       | UnsafeToRetry                 |
/// | `read`    | NoExternalMutation | ProviderDeduplicated by op    |
///
/// It counts how many times each request was *applied*, so a test can
/// assert that nothing ever happened twice.
#[derive(Debug)]
pub struct FakeProvider {
    name: String,
    applied: BTreeMap<Vec<u8>, usize>,
    dedup: BTreeSet<Vec<u8>>,
    next_fault: Fault,
}

impl FakeProvider {
    /// A fake provider named `name`.
    pub fn new(name: &str) -> Self {
        Self { name: name.to_string(), applied: BTreeMap::new(), dedup: BTreeSet::new(), next_fault: Fault::None }
    }

    /// Make the next `send` misbehave.
    pub fn fail_next(&mut self, fault: Fault) {
        self.next_fault = fault;
    }

    /// How many times `request` was applied.
    pub fn applied(&self, request: &[u8]) -> usize {
        self.applied.get(request).copied().unwrap_or(0)
    }

    /// True if no request was applied more than once.
    pub fn no_duplicates(&self) -> bool {
        self.applied.values().all(|&n| n <= 1)
    }

    fn key(op: OpId) -> Vec<u8> {
        format!("fake-{}", op.get()).into_bytes()
    }

    fn apply(&mut self, plan: &Plan) {
        if let RetryPolicy::ProviderDeduplicated { key } = &plan.retry {
            if !self.dedup.insert(key.clone()) {
                return; // seen this key: the provider does not apply it again
            }
        }
        *self.applied.entry(plan.request.clone()).or_insert(0) += 1;
    }
}

impl Adapter for FakeProvider {
    fn provider(&self) -> &str {
        &self.name
    }

    fn plan(&self, op: OpId, call: &Call) -> Result<Plan, Refusal> {
        let target = std::str::from_utf8(&call.args)
            .map_err(|_| Refusal::BadArgs("target is not UTF-8".into()))?;
        if target.is_empty() {
            return Err(Refusal::BadArgs("empty target".into()));
        }
        let (consequence, retry) = match call.operation.as_str() {
            "send" | "del" => (
                Consequence::Irreversible,
                RetryPolicy::ProviderDeduplicated { key: Self::key(op) },
            ),
            "put" => (Consequence::Irreversible, RetryPolicy::Queryable { probe: Self::key(op) }),
            "fire" => (Consequence::Irreversible, RetryPolicy::UnsafeToRetry),
            "read" => (
                Consequence::NoExternalMutation,
                RetryPolicy::ProviderDeduplicated { key: Self::key(op) },
            ),
            other => return Err(Refusal::UnknownOperation(other.to_string())),
        };
        Ok(Plan {
            request: format!("{} {target}", call.operation).into_bytes(),
            footprint: format!("{}:{target}", self.name).into_bytes(),
            retry,
            consequence,
            dispatch: Dispatch::Immediate,
            authority: format!("{}-credential", self.name).into_bytes(),
        })
    }

    fn send(&mut self, op: OpId, plan: &Plan) -> Sent {
        match std::mem::replace(&mut self.next_fault, Fault::None) {
            Fault::Lost => Sent::Unknown,
            Fault::Decline => Sent::NotApplied { reason: "declined".into() },
            Fault::ReplyLost => {
                self.apply(plan);
                Sent::Unknown
            }
            Fault::None => {
                self.apply(plan);
                Sent::Applied { receipt: Self::key(op) }
            }
        }
    }

    fn probe(&mut self, op: OpId, plan: &Plan) -> Probed {
        match &plan.retry {
            RetryPolicy::Queryable { .. } if self.applied(&plan.request) > 0 => {
                Probed::Applied { receipt: Self::key(op) }
            }
            RetryPolicy::Queryable { .. } => Probed::NotApplied,
            _ => Probed::Unknown,
        }
    }
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn call(op: &str, args: &str) -> Call {
        Call { operation: op.into(), args: args.as_bytes().to_vec() }
    }

    #[test]
    fn plan_is_deterministic_and_ignores_what_the_tool_claims() {
        let p = FakeProvider::new("mail");
        let a = p.plan(OpId::new(1), &call("fire", "bob")).unwrap();
        assert_eq!(a, p.plan(OpId::new(1), &call("fire", "bob")).unwrap());
        assert_eq!(a.consequence, Consequence::Irreversible);
        assert_eq!(a.retry, RetryPolicy::UnsafeToRetry);
        // The operation decides; there is no way to say "this is harmless".
        let claimed = p.plan(OpId::new(1), &call("fire", "bob {\"consequence\":\"none\"}")).unwrap();
        assert_eq!(claimed.consequence, Consequence::Irreversible);
    }

    #[test]
    fn dedup_key_is_derived_from_the_op_and_stable() {
        let p = FakeProvider::new("mail");
        let a = p.plan(OpId::new(7), &call("send", "bob")).unwrap();
        let b = p.plan(OpId::new(7), &call("send", "bob")).unwrap();
        let c = p.plan(OpId::new(8), &call("send", "bob")).unwrap();
        assert_eq!(a.retry, b.retry);
        assert_ne!(a.retry, c.retry);
    }

    #[test]
    fn refusals_happen_at_planning() {
        let p = FakeProvider::new("mail");
        assert!(matches!(p.plan(OpId::new(1), &call("format-disk", "x")), Err(Refusal::UnknownOperation(_))));
        assert!(matches!(p.plan(OpId::new(1), &call("send", "")), Err(Refusal::BadArgs(_))));
        let bad = Call { operation: "send".into(), args: vec![0xFF] };
        assert!(matches!(p.plan(OpId::new(1), &bad), Err(Refusal::BadArgs(_))));
    }

    #[test]
    fn deduplicated_resend_is_applied_once() {
        let mut p = FakeProvider::new("mail");
        let plan = p.plan(OpId::new(1), &call("send", "bob")).unwrap();
        p.fail_next(Fault::ReplyLost);
        assert_eq!(p.send(OpId::new(1), &plan), Sent::Unknown);
        // The reconciler re-issues the same plan.
        assert!(matches!(p.send(OpId::new(1), &plan), Sent::Applied { .. }));
        assert_eq!(p.applied(&plan.request), 1);
        assert!(p.no_duplicates());
    }

    #[test]
    fn probe_tells_queryable_effects_apart_without_causing_them() {
        let mut p = FakeProvider::new("store");
        let plan = p.plan(OpId::new(3), &call("put", "k")).unwrap();
        assert_eq!(p.probe(OpId::new(3), &plan), Probed::NotApplied);
        assert_eq!(p.applied(&plan.request), 0, "probing did not apply it");
        p.fail_next(Fault::ReplyLost);
        assert_eq!(p.send(OpId::new(3), &plan), Sent::Unknown);
        assert!(matches!(p.probe(OpId::new(3), &plan), Probed::Applied { .. }));
        // Not queryable: the probe cannot say.
        let fire = p.plan(OpId::new(4), &call("fire", "k")).unwrap();
        assert_eq!(p.probe(OpId::new(4), &fire), Probed::Unknown);
    }

    #[test]
    fn unsafe_resend_would_duplicate_which_is_why_it_is_never_retried() {
        let mut p = FakeProvider::new("rocket");
        let plan = p.plan(OpId::new(1), &call("fire", "moon")).unwrap();
        p.fail_next(Fault::ReplyLost);
        assert_eq!(p.send(OpId::new(1), &plan), Sent::Unknown);
        p.send(OpId::new(1), &plan);
        assert!(!p.no_duplicates(), "the fake shows the harm a blind retry does");
    }

    #[test]
    fn lost_and_declined_sends_apply_nothing() {
        let mut p = FakeProvider::new("mail");
        let plan = p.plan(OpId::new(1), &call("send", "bob")).unwrap();
        p.fail_next(Fault::Lost);
        assert_eq!(p.send(OpId::new(1), &plan), Sent::Unknown);
        p.fail_next(Fault::Decline);
        assert!(matches!(p.send(OpId::new(1), &plan), Sent::NotApplied { .. }));
        assert_eq!(p.applied(&plan.request), 0);
    }

    #[test]
    fn registry_matches_exactly_and_never_replaces() {
        let mut r = Registry::new();
        assert!(r.register(Box::new(FakeProvider::new("mail"))));
        assert!(!r.register(Box::new(FakeProvider::new("mail"))));
        assert!(r.get_mut("mail").is_some());
        assert!(r.get_mut("Mail").is_none());
        assert!(r.get_mut("mail ").is_none());
        assert!(r.get_mut("http").is_none());
        assert_eq!(r.providers().collect::<Vec<_>>(), vec!["mail"]);
    }
}
