# The Sender's Contract

Taso records, releases and holds.  It never sends.

A **sender** (or **relay**) is whoever reads the released effects from a
Vessel's outbox and acts on them in the outside world — sending the
e-mail, calling the API, writing to the store.  Taso does not know who
this is, does not hold its credentials, and does not depend on it being
present.  The sender is a peer of the agent, sitting outside the
Vessel, reading the Field protocol's `Open` list and reporting back
through `Outcome`.

This document is the contract between Taso and any sender.  It replaces
the `Adapter` trait that was removed in P3 and is normative for anyone
building a relay.

## What Taso provides

1. **Released effects.**  `Request::Open` returns every released intent
   whose outcome has not been terminally settled.  Each carries:
   - `op`: the operation id the sender uses to report back.
   - `provider`: a namespace (`"mail"`, `"http"`, `"git"`, …) —
     meaningful to the sender, opaque to Taso.
   - `request`: the exact bytes to send, durable with the intent, so
     they can be re-sent byte for byte after a crash.
   - `retry`: the retry policy — how the sender may safely re-issue the
     request.
   - `consequence` and `authority`: what it does to the world and what
     permits it, as declared — what a sender needs to decide how to act.
   - `unknown`: true if this effect was acted on in a previous
     incarnation whose outcome was lost (the reconciler recorded
     `OutcomeUnknown`).  The sender must not blindly re-send; the
     retry policy says what is safe.

2. **The durability guarantee.**  Every intent listed by `Open` has been
   shipped to remote storage before it was made visible: a release
   before it is answered, an adoption by promotion after it is recorded
   (until that ship succeeds its ops are not listed).  So whoever takes
   the Vessel over knows of everything a sender may have acted on, and
   lists it as `unknown`; nothing listed is ever listed again as fresh.
   A crash of the local node does not lose it.

3. **The outbox invariant.**  An effect appears in `Open` exactly from
   the moment it is released and shipped until a terminal outcome is
   recorded.  No
   effect is ever released twice with the same `op`.

## What the sender must do

### 1. Send exactly what was released

The sender sends `request` to the provider named by `provider`.  It
does not rewrite, reinterpret or enrich it.  The request bytes are the
caller's declaration, recorded durably as they were declared; the
sender is a transport, not a policy layer.

### 2. Report what happened

For every effect it acts on, the sender reports one of:

- **Applied** `{ receipt }`: the effect happened.  The receipt is opaque
  provider evidence (an HTTP response, a transaction id, a message id).
- **NotApplied** `{ reason }`: the effect did not happen.
  Taso records `ConfirmedNotApplied`.
- **Unknown**: no answer, or an ambiguous one.  Taso records
  `OutcomeUnknown` — the effect is still open until the sender or an
  operator resolves it.

The sender reports through `Request::Outcome { op, result }`.
A report for an unknown `op` is refused and nothing is recorded.

### 3. Respect the retry policy

The `retry` field on each released effect tells the sender how to
handle a crash or lost reply:

| Policy                  | What it means                                    |
|-------------------------|--------------------------------------------------|
| `ProviderDeduplicated`  | The provider deduplicates by `key`.  Re-sending   |
|                         | the same `key` is safe: it will be applied at     |
|                         | most once.                                        |
| `Queryable`             | The provider can be asked whether the effect       |
|                         | happened, without causing it.  The sender probes  |
|                         | with `probe` before re-sending.                   |
| `UnsafeToRetry`         | Re-sending may duplicate.  On `Unknown`, the      |
|                         | sender does **not** re-send; it reports `Unknown`  |
|                         | and an operator resolves it.                      |

After a crash, the `Open` list presents every unsettled effect again.
The sender uses the retry policy to decide what is safe.  An effect
marked `unknown: true` was already acted on in a previous incarnation;
the sender must follow the policy, not assume it can start over.

### 4. One send per effect

The sender sends each `op` at most once per incarnation (unless the
retry policy explicitly permits re-sending).  If the reply is lost,
the sender reports `Unknown`; it does not guess.  A report of
`Applied` or `NotApplied` is terminal and may not be revised.

### 5. Respect consequence

The `consequence` field on the declaration describes what the effect
does to the world:

| Consequence            | What it means to the sender                     |
|------------------------|--------------------------------------------------|
| `Irreversible`         | Once applied, it cannot be undone.  The sender    |
|                        | treats a lost reply as `Unknown`, never `Applied`.|
| `NoExternalMutation`   | A read or query: applying it twice is harmless.   |
|                        | The sender may re-send freely.                    |

### 6. Credentials are the sender's

Taso records the `authority` field (which credential or lease the caller
declared) but does not hold any secret.  The sender is responsible for
its own credentials: where they live, how they are rotated, and that
they match what `authority` names.

## What the sender must not do

1. **Apply an effect Taso did not release.**  The `Open` list is the
   only source of truth.  An effect not on it was never released, was
   already settled, or was held as a proposal.

2. **Send for a held Vessel.**  A Vessel in `Hold` mode never has
   anything on its `Open` list.  Its effects are proposals, visible
   only to its parent through `ReadLog::proposals`.  Only the parent's
   promotion can turn them into released effects in the parent's own
   outbox.

3. **Retry an `UnsafeToRetry` effect after `Unknown`.**  This is the
   one case where duplicating in the outside world is possible.  The
   sender reports `Unknown` and waits for an operator.

4. **Modify the request bytes.**  The request was declared by the
   caller, recorded by Taso, and is the sender's only input.  Adding
   headers, wrapping it in another format, or changing encoding breaks
   the deduplication key and the authority chain.

## The no-trace property

A fork's effects are held as proposals.  If the parent promotes a
different fork (or no fork), those proposals are never adopted, never
released, and never appear on any `Open` list.  No sender ever sees
them.  The futures you don't choose never touched the outside world.

This property is verified by the no-trace gate
(`scripts/p3-no-trace.sh`): N forks, one promoted, the parent's
released effects are exactly that child's — and only that child's.

The agent may ask for forks and the promotion itself, over the Field
(`Fork { seal }`, `Promote { child, seal }`; decision D1).  These are
requests: the Warden picks the child's uid slot from the Vessel's
config entry (`"forks": {"slots": [...]}`, one child per slot), the
child always holds, and only one child is promoted per fork point.  A
sender is not involved in either; it only ever sees the adopted
effects, on the parent's `Open` list, like any other.

## Building a relay

A minimal relay is a loop:

```
loop:
    effects = field.open()
    for e in effects:
        if e.unknown:
            handle per e.retry  # probe, or report Unknown
        else:
            result = send(e.provider, e.request)
            field.outcome(e.op, result)
    sleep(interval)
```

The relay runs beside the agent, not inside it: the agent declares
effects through the Field, the relay reads what was released and acts
on them.  A relay that is down does not stop the agent or lose its
effects; it catches up on restart.  Multiple relays for different
provider namespaces may run concurrently, each handling its own slice of
the outbox.

A reference relay is provided in `scripts/p3-relay.py`.
