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

9. **Intent and DispatchAuthorized are written together** (2026-10-16).
   v0.4 §7.2 lists them as two durable steps. The Warden writes both in
   one segment write and one coordinator CAS (`Coord::append_batch`, all
   or none): nothing happens between them, and a crash leaves both
   accepted or neither, never a sendable state without its intent.
   Recovery still handles an intent accepted alone.

10. **Rebirth takes ownership before it reads anything** (2026-10-16).
    v0.4 §8.4 fetches the sealed prefix, then opens at a new epoch. The
    code transfers first, so a previous holder that is still alive can
    no longer move the shipped anchor while it is being read.
11. **"Byte-identical to the last Seal" (v1.0 §1, P2 exit gate) means the
    last *anchored, named* Seal** (2026-10-16). Seal records past it may
    be in the log without a shipped `fs` section; they are reported as
    missing layers and their state is lost (v0.4 §8.5).

13. **Takeover is the operator's call** (2026-10-16). The daemon takes a
    Vessel that another Warden holds only when its configuration says
    `"takeover": true`; otherwise it refuses to start it. Taking over
    fences the other holder (v0.4 §8.2), and whether that holder is dead
    is not something one node can know. A Vessel this Warden already
    holds is opened (or reborn, if its local state is gone) without asking.
14. **Seal snapshots are batched** (2026-10-16). Concurrent Seals on a
    node share one ZFS channel program per pool: each snapshot and its
    `taso:seal` binding are set in the same transaction group, so a
    snapshot is never visible unbound (as with `zfs snapshot -o`). The
    program reports each snapshot's guid and txg; only a program that
    fails is checked against `zfs list`. Measured at p64: Seal p95 283 →
    132 ms, bounded below by the storage's txg sync.
15. **A failed Seal publish does not undo the Seal** (2026-10-16). The
    Seal record is accepted and its layer exists; if shipping it or
    advancing the shipped anchor fails, the failure is counted and the
    next Seal's publish ships from the last named section, so nothing is
    skipped for good. Until then the Seal is not anchored, and a rebirth
    starts from the last one that is (amendment 11).
16. **Coordinator writes are group-committed** (2026-10-16). Requests that
    arrive while a commit is in flight share one transaction and one
    fsync. Each is still checked on its own against the state the ones
    before it left, so no answer changes; a group that fails to commit
    answers every accepted request "outcome unknown", never a refusal.

17. **Segments roll and shipped ones are pruned behind a Checkpoint**
    (2026-10-16). A Chronicle rolls to a new segment file at 64 MiB.
    After a Seal is published, the Warden appends a Checkpoint record
    (Ctl, tag 9) and removes the oldest closed segment files whose every
    record is at or below the shipped anchor, keeping the newest two.
    The Checkpoint carries what readers need from the records before it:
    lineage, transcript and effect positions, the last Seal (turn and
    ledger position), the last FsShipped, open effects with their latest
    state, and the next op id. Readers start from the newest Checkpoint.
    A log whose first local segment is not genesis opens only if that
    segment begins at or below the shipped anchor and a Checkpoint is
    present; the full history stays in the packs. Layers of Seals whose
    records were pruned are kept, not judged again.
18. **The TurnEnd reply goes out before the Seal is published**
    (2026-10-16). The Seal is accepted before the reply, as before; the
    publish (shipping its packs and advancing the shipped anchor) runs
    after the reply is sent and before the next request is read, so it
    is off the agent's turn latency. A failed publish is handled as in
    amendment 15.

19. **A Seal before a gap stays navigable** (2026-10-16). The Navigator
    accepts a jump in lsn only at a Gap record on `ctl` that names the
    record before it and its own `prev` (the rule of the segment joints).
    Nothing lost in a gap authorized a sent effect (it is shipped and
    anchored before the send), so a Seal before the gap is judged as
    usual: an outcome lost in the gap is `MissingOutcome` until the new
    holder reconciles it. No new reason is added to v0.4 §6. A cut
    position or `ledger_pos` inside a gap is not present and is
    `IncompleteState(CutInvalid)`; the first Seal after a gap is
    `Unverified`, as before.

20. **Each Vessel has its own uid range** (2026-10-17). A Vessel's entry
    names a `uid_slot`; its user namespace maps ids 0..65536 to
    `host_uid_base + slot·65536`, and the daemon refuses two Vessels on a
    node with the same slot or a range that does not fit in 32 bits.
    Vessels on one node can no longer read each other's files or signal
    each other's processes through a shared host id. The dataset's files
    are owned by host ids in the range and `zfs send` keeps them, so the
    slot belongs to the Vessel, not to the node: it is the same on every
    node the Vessel runs on. A fork or succession into another slot needs
    its files moved into its range first (not yet built).

### Amendments already applied from the Phase 4 plan

12. **Btrfs is not the fallback** (Phase 4 plan §9.1). If ZFS is
   unavailable, Phase 4 is brought forward.
