# Taso specs

The documents the code cites. Module docs refer to them as "v0.4 §n" and
"v1.0 §n".

| Document | Status | What it is |
|---|---|---|
| [v1.0-build-plan.md](v1.0-build-plan.md) | Frozen for implementation | Phases, gates, Phase 1 architecture (runc + ZFS), Template genesis, crates |
| [v0.4-primitives.md](v0.4-primitives.md) | Normative for the primitives (v1.0 §2) | Template, Vessel, Field, Chronicle, Warden, Seal, effect ledger, Navigator, rebirth and fencing |
| [phase4-blocklog-plan.md](phase4-blocklog-plan.md) | Plan, gated | The Chronicle block log; supersedes v1.0 §6 and amends v1.0 §1 and §3 (its §9) |

Precedence when they disagree: the Phase 4 plan's §9 amendments, then
v1.0, then v0.4 for anything v1.0 does not restate.

## Where the code goes beyond or differs from the specs

The specs are frozen; these are the decisions made while building. Each
is the code's behaviour and should be read as an amendment. Numbers refer
to the decision lists in the session handoffs.

### Deviations (the code is stricter than the text)

1. **Navigator: strict "open at S"** (decision 12). v0.4 §7.4 reads as "a
   barrier after `S.ledger_pos` must be accounted for". The code also
   treats a barrier whose intent is at or before S but whose terminal
   outcome is not as unsettled at S. That is the "applied, but S does not
   know" case, where resuming would repeat an effect. Unresolved outcomes
   are `Insufficient(MissingOutcome)`.

### Additions (mechanisms the specs leave open)

2. **Intent records carry `provider` and the exact `request`** (decision
   10, payload domain v2). v0.4 §4 `Intent` has neither; re-issue after a
   crash needs both. Requests may hold user data and live in the
   retention-locked ledger.
3. **Lineage and identity** (decisions 6–9). Lsn 1 of every Chronicle is
   a `Lineage` record (`Void | Fork | Succession`, a namespace, the ledger
   position). Vessels are found or born by `vessel_id(namespace,
   subject)`. Succession (moving data to another identity) is manual,
   refused without an actor and a reason, and recorded on both sides.
4. **Publish before send** (decisions 13–16). Before an effect dispatches,
   the ledger up to its authorization is shipped off the node and the
   coordinator's **shipped anchor** is advanced to it; if that fails, the
   effect is `ConfirmedNotApplied`. This extends v0.4 §7.2 between steps 2
   and 3, so a new holder after a crash always finds the authorization.
5. **Packs** (decision 13). The log and `fs` streams leave the node as
   content-keyed packs, one per Seal (log section + `fs` stream), verified
   against the shipped anchor on read. v1.0 §3's "`zfs send -i` → Garage"
   is the `fs` section of a Seal pack.
6. **Gap records** (decision 18). A Warden that takes a Chronicle over
   keeps only what was shipped and anchored and writes a `Gap` record for
   the accepted records it lacks. History is never rewritten. This is how
   v0.4 §8.4–8.5's "sealed prefix" is realised when the prefix extends past
   what was shipped.
7. **FsShipped records** (decision 19). A Seal's `fs` section is used only
   once an `FsShipped` record in the hash chain names it, with the plain
   stream's length and BLAKE3. A Phase 1 bridge: in the block log, records
   carry chunk hashes.
8. **Phase 1 seals every quiescent turn** (decision 11), and a Seal is
   refused if the WAL or journal moved during it (v1.0 §3's `-wal` rule,
   checked by `lstat` only).

### Amendments already applied from the Phase 4 plan

9. **Btrfs is not the fallback** (Phase 4 plan §9.1). If ZFS is
   unavailable, Phase 4 is brought forward.
