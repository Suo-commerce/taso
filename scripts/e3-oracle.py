#!/usr/bin/env python3
"""e3-oracle.py: E3-2 of P5 B2 (one-pager Taso_onepager_p5_b2_e3 rev. 4;
plan P5-17, P5-18; spec rev. 33, D92 and D93).

The round's answer key, kept on / (never on the device that is cut).  The
harness (e3-crash.sh) writes it as the round runs, from what it asked and
what the Warden replied over the Field; after the rebirth `check` grades
what the harness gathered from the reborn Warden.  The oracle replays the
*promised* history as a model of rows: it never reads the Vessel between
the last acknowledgement and the cut, and never asks the production
replay to grade itself.

The model (P5-18): `write` adds --rows rows to the current turn (the
parent's keyed "T", a fork's child's "cT": taso-sim --step writes the
child with tag 1); an acknowledged `seal` fixes the parent's rows as that
Seal's content; `fork` starts the child from the parent's newest Seal; a
child's `seal` fixes the child's; an acknowledged `promote` makes the
parent the child at its newest Seal (C7: the parent's own writes since the
fork are replaced) and the Warden adds an adoption Seal with that content.
An operation in flight at the cut may have landed or not; if it landed it
is whole.

  e3-oracle.py new R.json --sequence "write seal fork" --point boundary:2 --mode drop [--rows N]
  e3-oracle.py requested    R.json OP [who=child] [k=v ...]
  e3-oracle.py acknowledged R.json OP [who=child] [seal=LSN turn=T child=NAME rows=N ...]
  e3-oracle.py cut          R.json --swap-ms N [--missed | --held NAME]
  e3-oracle.py check        R.json --after A.json     one line; exit 0 pass, 1 fail, 2 missed
  e3-oracle.py selftest

A.json (gathered from the reborn Warden by e3-crash.sh; "opened" is whether
the reborn Warden opened the Vessel, "not_run" its own word why not):
  {"seals": [{"lsn": L, "birth": bool, "export_ok": bool, "rows": {"1": 8, "c2": 8}}],   the parent's Seals
   "forks": ["child name", ...], "report": "the Warden's and taso-blkd's stderr after rebirth",
   "resume_turn": T|null, "resume_why": "why no resume turn was taken"|null,
   "acks_after_error": N, "opened": bool, "not_run": "…"|null,
   "log_inode": {"before": I, "after": I|null}|null}     (compact.written only)

At a hold the point is exact, so three windows are graded exactly
(E3-3c's open item, accepted 2026-10-28; D96): `seal.recorded`, the Seal
held before its record was committed is never listed after rebirth (its
layer destroyed at open); `fork.branched`, the child held before its
Lineage record is never run; `compact.written`, the log taso-blkd reopens
is the one from before the held compaction (same inode: the rename never
happened).

Line 3 checks that a retained Seal is reachable (it exports), not its bytes:
a Seal's export differs between runs (a fresh mkfs per round, inode times),
so a healthy run's hash is no baseline (found writing E3-3b, 2026-10-27).

A takeover round (E3-4, one-pager rev. 6; spec D97) adds to A.json
  "takeover": {"owner": {...}, "shipped_lsn": L, "child": {...}|null,
               "thaw": {"acks": N, "replies": [...], "fenced": "…"|null},
               "packs": {"added": [...], "changed": [...], "gone": [...]},
               "after_thaw": A.json of a third Warden that rebuilt from the store}
and is graded on what the new Warden B holds: line 1 by the shipped anchor
(an acknowledged Seal not yet shipped may be absent, its span named by
B's rebirth line), line F (the old Warden acknowledges nothing after its
takeover and names the refusal), H1 (a third Warden rebuilds the same
Seals from the store after the old Warden woke), H2 (a pack no record
names: a note), H3 (a named pack whose bytes changed: §11.3's limit, a
FAIL), and 5a (a forked child either runs on B or is refused by name).
"""
import copy, json, os, re, sys, time

OPS = ("write", "seal", "fork", "promote", "effect")


def load(p):
    with open(p) as f:
        return json.load(f)


def save(p, r):
    with open(p + ".tmp", "w") as f:
        json.dump(r, f, indent=1, sort_keys=True)
    os.replace(p + ".tmp", p)


def kv(args):
    d = {}
    for a in args:
        k, _, v = a.partition("=")
        d[k] = int(v) if re.fullmatch(r"-?\d+", v) else v
    return d


def new(path, seq, point, mode, rows):
    seq = seq.split()
    bad = [op for op in seq if op not in OPS]
    if bad:
        raise SystemExit(f"unknown op(s) {bad}; the vocabulary is {' '.join(OPS)} (P5-18)")
    save(path, {"sequence": seq, "point": point, "mode": mode, "rows": rows, "events": [], "cut": None})


def event(path, kind, op, d):
    r = load(path)
    if r["cut"] is not None:
        raise SystemExit("the cut is recorded; nothing is requested or acknowledged after it")
    r["events"].append({"t": time.clock_gettime(time.CLOCK_MONOTONIC), "kind": kind, "op": op,
                        "who": d.pop("who", "parent"), "d": d})
    save(path, r)


def cut(path, swap_ms, missed, held=None):
    """`held`: the cut came while the process waited at the hold NAME
    (E3-3c), an exact point, so it can never be missed."""
    if missed and held:
        raise SystemExit(f"a cut at the hold {held} cannot be missed")
    r = load(path)
    r["cut"] = {"swap_ms": swap_ms, "missed": missed, "held": held}
    save(path, r)


# ── the model: replay what was promised ────────────────────────────────
def model(r):
    """Expected content of every acknowledged Seal, the alternatives an
    in-flight operation allows, and the facts the five lines need."""
    rows = r["rows"]
    parent, last_parent_seal, child, child_seal = {}, {}, None, None
    m = {"seals": {}, "acked_turns": {}, "adoption": None, "writes_after_seal": 0,
         "last_turn": 0, "inflight": None, "forked": False, "promoted": False}
    reqs = [e for e in r["events"] if e["kind"] == "requested"]
    acks = [e for e in r["events"] if e["kind"] == "acknowledged"]
    if len(reqs) > len(acks):
        m["inflight"] = reqs[-1]
    for e in acks:
        op, who, d = e["op"], e["who"], e["d"]
        if op == "write" and who == "parent":
            k = str(d["turn"]); parent[k] = parent.get(k, 0) + d.get("rows", rows)
            m["writes_after_seal"] += 1
        elif op == "write":
            k = "c%d" % d["turn"]; child[k] = child.get(k, 0) + d.get("rows", rows)
        elif op == "seal" and who == "parent" and d.get("seal"):
            m["seals"][d["seal"]] = copy.deepcopy(parent); m["acked_turns"][d["seal"]] = d["turn"]
            last_parent_seal = copy.deepcopy(parent); m["writes_after_seal"] = 0
            m["last_turn"] = max(m["last_turn"], d["turn"])
        elif op == "seal" and d.get("seal"):
            child_seal = (copy.deepcopy(child), d["turn"])
        elif op == "fork":
            child = copy.deepcopy(last_parent_seal); m["forked"] = True
        elif op == "promote" and child_seal:
            parent = copy.deepcopy(child_seal[0]); last_parent_seal = copy.deepcopy(parent)
            m["adoption"] = (copy.deepcopy(parent), child_seal[1]); m["promoted"] = True
            m["writes_after_seal"] = 0; m["last_turn"] = max(m["last_turn"], child_seal[1])
    m["parent_now"], m["child_seal"] = parent, child_seal
    return m


# ── the five lines ──────────────────────────────────────────────────────
def check(r, a):
    m, fails, notes = model(r), [], []
    listed = {s["lsn"]: s for s in a.get("seals", []) if not s.get("birth")}
    report = a.get("report", "")
    infl = m["inflight"]
    infl_op = infl["op"] if infl and infl["who"] == "parent" else None
    held = (r.get("cut") or {}).get("held")
    retained_turn = m["last_turn"]
    # E3-4: graded on the Warden that took the Vessel over, by what was shipped (D97).
    tk, t = r["point"].startswith("takeover:"), a.get("takeover")
    if tk and not t:
        return ["harness: a takeover round with no takeover facts gathered"], notes
    shipped = t["shipped_lsn"] if tk else None
    lost_unshipped = []
    # 1. every acknowledged Seal listed, its rows as promised (after a takeover: every shipped one)
    for lsn, exp in m["seals"].items():
        s = listed.get(lsn)
        if s is None and tk and lsn > shipped:
            lost_unshipped.append(lsn)   # D97: acknowledged, not shipped; it lived only on the old node
        elif s is None:
            fails.append(f"1: acknowledged Seal lsn {lsn} (turn {m['acked_turns'][lsn]}) is not listed after rebirth")
        elif s.get("rows", {}) != exp:
            stray = sorted(k for k in s.get("rows", {}) if k.startswith("c") and k not in exp)
            fails.append(f"{'4' if stray else '1'}: Seal lsn {lsn} holds {s.get('rows')}, promised {exp}"
                         + (f" (the child's turn(s) {stray} in a parent Seal before any promotion)" if stray else ""))
    if tk:
        # The turn the agent may resume after is the last Seal the new Warden holds (D97).
        retained_turn = max([m["acked_turns"][l] for l in m["seals"] if l in listed], default=0)
        if lost_unshipped and not re.search(r"reborn at epoch \d+ from anchor lsn \d+, records \d+\.\.=\d+ lost", report):
            fails.append(f"1 (D97): acknowledged Seal(s) lsn {lost_unshipped}, past the shipped anchor {shipped}, are absent "
                         "and the new Warden does not name the span it lost (its Gap record, D93 (i))")
        elif lost_unshipped:
            notes.append(f"acknowledged Seal(s) lsn {lost_unshipped} not shipped: lost with the old node, named (D97)")
    # Seals listed and never acknowledged: the adoption, an in-flight Seal that landed, or nothing allowed
    extra = {l: s for l, s in listed.items() if l not in m["seals"]}
    unsealed = m["writes_after_seal"]
    if m["adoption"]:
        hit = [l for l, s in extra.items() if s.get("rows", {}) == m["adoption"][0]]
        if not hit:
            fails.append(f"1: the acknowledged promotion's adoption Seal is missing (promised {m['adoption'][0]}; C7, one crash rule)")
        else:
            extra.pop(hit[0])
    for l, s in extra.items():
        rows = s.get("rows", {})
        if held == "seal.recorded" and infl_op == "seal":
            fails.append(f"2 (seal.recorded): Seal lsn {l} is listed, but it was held before its record was "
                         "committed: its layer must be destroyed at open (D96, orphan)")
            continue
        if infl_op == "seal" and rows == m["parent_now"]:
            notes.append(f"in-flight Seal lsn {l} landed whole"); unsealed = 0; retained_turn = max(retained_turn, infl["d"].get("turn", retained_turn + 1) if infl["d"] else retained_turn + 1)
        elif infl_op == "promote" and m["child_seal"] and rows == m["child_seal"][0]:
            notes.append(f"in-flight promotion landed whole (adoption Seal lsn {l})"); unsealed = 0; retained_turn = max(retained_turn, m["child_seal"][1])
        elif infl_op in ("seal", "promote"):
            fails.append(f"{'2' if infl_op == 'seal' else '4'}: in-flight {infl_op} left Seal lsn {l} not whole: {rows}")
        else:
            fails.append(f"2: Seal lsn {l} is listed and was never requested: {rows}")
    # 1b (D92, D93 (i)): acknowledged writes after the last retained Seal are discarded by the reset, and named
    # — as blocks of the Vessel's filesystem.  The Chronicle count in the reset line does not name them: a
    # SQLite write adds no Chronicle record, and the Warden appends housekeeping after a Seal anyway
    # (taso-test 2026-10-28, [seal write]: "lsn 6 reset to the Seal at lsn 5: 1 record(s)" with the write unnamed).
    m_blocks = re.search(r"(\d+) block\(s\) of the Vessel's filesystem discarded", report)
    # Not after a takeover: the old node's unsealed writes were never shipped and died with it (class (iii), D97).
    if unsealed and not tk and not (m_blocks and int(m_blocks.group(1)) > 0):
        fails.append(f"1: {unsealed} acknowledged write(s) after the last retained Seal were discarded by the rollback "
                     "and the report does not name them as blocks (D92, D93 (i); the store knows the count)")
    # 2. a child nobody asked for
    if a.get("forks") and not m["forked"] and infl_op != "fork":
        fails.append(f"2: child(ren) {a['forks']} listed and no fork was requested")
    elif a.get("forks") and held == "fork.branched":
        fails.append(f"2 (fork.branched): child(ren) {a['forks']} ran, but the fork was held before its Lineage "
                     "record: an interrupted fork, never a child (D96)")
    # 3. retained Seals reachable
    for lsn in m["seals"]:
        if lsn in listed and not listed[lsn].get("export_ok", False):
            fails.append(f"3: retained Seal lsn {lsn} does not export")
    # 5. D93: what the Warden can know, named; class (iii) as the reconciliation
    # The reborn Warden opened and ran the Vessel; without it the lines above
    # graded taso-blkd's layers, not a reborn Vessel (F2, 2026-10-28).  A
    # gather that did not look (`opened` absent) is not judged here.
    if a.get("opened") is False:
        fails.append(f"5: the reborn Warden did not run the Vessel: {a.get('not_run') or 'no reason printed'}")
    if not tk and not re.search(r"taso-blkd: recovered ", report):   # a takeover's taso-blkd starts a new log
        fails.append("5: taso-blkd printed no recovery line")
    if infl_op == "effect" and not re.search(r"effects \(\w+\) reconciled: ", report):
        fails.append("5: an effect was in flight and the Warden printed no reconcile line (D93 (ii))")
    if a.get("resume_turn") is not None and a["resume_turn"] != retained_turn:
        fails.append(f"5 (iii): the agent resumes after turn {a['resume_turn']}, the last retained Seal is turn {retained_turn}")
    elif a.get("resume_turn") is None and a.get("resume_why"):
        # Not graded yet: the harness has never found the reborn agent's turn
        # (E3-3c, open).  Said on the result line, so a silent skip cannot pass for a check.
        notes.append("5 (iii) not checked: " + a["resume_why"][:160])
    if held == "compact.written":
        li = a.get("log_inode") or {}
        if li.get("before") is None or li.get("after") is None:
            fails.append(f"5 (compact.written): the log's inode was not looked at ({li or 'nothing gathered'}), so which log was reopened is unknown")
        elif li["after"] != li["before"]:
            fails.append(f"5 (compact.written): the reopened log is inode {li['after']}, not {li['before']}: the compaction's "
                         "new log became the log, though its rename was held and never made")
    if tk:
        # F: the old Warden, woken, believes it holds the Vessel; the coordinator refuses its old epoch.
        th = t.get("thaw") or {}
        if th.get("acks", 0):
            fails.append(f"F: after its takeover the old Warden acknowledged {th['acks']} op(s): {th.get('replies')}")
        if not th.get("fenced"):
            fails.append(f"F: the old Warden's output names no refusal (stale epoch) after it woke; its replies: {th.get('replies')}")
        # H: the store after the old Warden's late writes (§0.4, §11.3).
        pk = t.get("packs") or {}
        if pk.get("added"):
            notes.append(f"H2: {len(pk['added'])} pack(s) of the old Warden's in the store, named by no accepted record")
        if pk.get("changed"):
            fails.append(f"H3 (§11.3's limit reached): named pack(s) whose bytes changed after the takeover: {pk['changed']}")
        if pk.get("gone"):
            fails.append(f"H: pack(s) gone from the store after the takeover: {pk['gone']}")
        c = t.get("after_thaw") or {}
        if "skipped" in c:
            notes.append("H1 not checked: " + c["skipped"])
        elif c.get("opened") is not True:
            fails.append(f"H1: after the old Warden woke, a third Warden could not rebuild the Vessel from the store: {c.get('not_run') or 'no reason printed'}")
        else:
            cl = {x["lsn"]: x.get("rows", {}) for x in c.get("seals", []) if not x.get("birth")}
            bl = {l: x.get("rows", {}) for l, x in listed.items()}
            if cl != bl:
                fails.append(f"H1: rebuilt from the store after the old Warden woke, the Seals are {cl}, not the new Warden's {bl}")
        # 5a: a fork is reborn where its parent's Seal is (P3 option c), a node the parent was reborn on included.
        ch = t.get("child")
        if ch and not ch.get("ran") and not ch.get("refused"):
            fails.append(f"5a: the child {ch['subject']} neither ran on the new Warden nor was refused by name")
        elif ch and not ch.get("ran"):
            notes.append(f"5a: the new Warden refused the child: {ch['refused'][:120]}")
    if r["mode"] == "error":
        # taso-blkd names the failure that poisoned the store, once, with its error
        # ("the store is poisoned: seal failed: ... Input/output error"); the Warden's
        # own append errors name EIO or EROFS.
        if not re.search(r"the store is poisoned: .*(EIO|EROFS|Input/output error|Read-only file system|os error \d+)|EIO|EROFS|Input/output error|Read-only file system", report):
            fails.append("5: error mode, and no report names the error")
        if a.get("acks_after_error", 0):
            fails.append(f"5: {a['acks_after_error']} durable acknowledgement(s) after the store saw the error")
    return fails, notes


def do_check(path, after):
    r, a = load(path), load(after)
    if r["cut"] is None:
        raise SystemExit("no cut recorded for this round")
    head = f"[{' '.join(r['sequence'])}] {r['point']} {r['mode']} swap={r['cut']['swap_ms']}ms"
    if r["cut"]["missed"]:
        print(f"MISSED  {head}: the intended point was observably missed; not covered")
        return 2
    fails, notes = check(r, a)
    print(("PASS    " if not fails else "FAIL    ") + head + (f" ({'; '.join(notes)})" if notes else ""))
    for f in fails:
        print("        " + f)
    return 1 if fails else 0


# ── selftest ──────────────────────────────────────────────────────────
def selftest():
    import tempfile
    R = os.path.join(tempfile.mkdtemp(), "r.json")
    B = "taso-blkd: recovered 1: 40 records, 9 groups, 0 bytes cut (full)\n"
    RESET = B + "v: state at lsn 12 reset to the Seal at lsn 9: 2 record(s) after the Seal stay in the log; 17 block(s) of the Vessel's filesystem discarded\n"

    def rnd(steps, inflight=None, mode="drop"):
        new(R, " ".join(s[0] for s in steps) + (" " + inflight[0] if inflight else ""), "boundary:x", mode, 8)
        for op, d in steps:
            event(R, "requested", op, dict(d)); event(R, "acknowledged", op, dict(d))
        if inflight:
            event(R, "requested", inflight[0], dict(inflight[1]))
        cut(R, 22, False)
        return load(R)

    def S(lsn, rows, ok=True): return {"lsn": lsn, "rows": rows, "export_ok": ok}
    W = lambda t, **k: ("write", {"turn": t, **k})
    SL = lambda l, t, **k: ("seal", {"seal": l, "turn": t, **k})
    ws = rnd([W(1), SL(9, 1)])
    sw = rnd([SL(9, 1), W(2)])
    fk = [W(1), SL(9, 1), ("fork", {"child": "c"}), W(2, who="child"), SL(5, 2, who="child")]
    pr = rnd(fk + [("promote", {"child": "c"})])
    cases = [
        ("1 pass", ws, {"seals": [S(9, {"1": 8})], "report": B, "resume_turn": 1}, 0),
        ("1 fail: Seal missing", ws, {"seals": [], "report": B, "resume_turn": 0}, 1),
        ("1 fail: Seal not whole", ws, {"seals": [S(9, {"1": 5})], "report": B, "resume_turn": 1}, 1),
        ("1b pass: reset named", sw, {"seals": [S(9, {})], "report": RESET, "resume_turn": 1}, 0),
        ("1b fail: write discarded silently", sw, {"seals": [S(9, {})], "report": B + "v: state at its last Seal (lsn 9): nothing reset", "resume_turn": 1}, 1),
        ("1b fail: a Chronicle record named, the blocks not (today's Warden)", sw, {"seals": [S(9, {})], "report": B + "v: state at lsn 6 reset to the Seal at lsn 5: 1 record(s) after the Seal stay in the log", "resume_turn": 1}, 1),
        ("2 pass: in-flight Seal landed whole", rnd([W(1)], ("seal", {"turn": 1})), {"seals": [S(9, {"1": 8})], "report": B, "resume_turn": 1}, 0),
        ("2 pass: in-flight Seal absent", rnd([W(1)], ("seal", {"turn": 1})), {"seals": [], "report": RESET, "resume_turn": 0}, 0),
        ("2 fail: in-flight Seal half", rnd([W(1)], ("seal", {"turn": 1})), {"seals": [S(9, {"1": 3})], "report": RESET, "resume_turn": 1}, 1),
        ("2 fail: a Seal nobody asked for", rnd([("effect", {})]), {"seals": [S(9, {})], "report": B, "resume_turn": 0}, 1),
        ("2 fail: a child nobody asked for", ws, {"seals": [S(9, {"1": 8})], "forks": ["x"], "report": B, "resume_turn": 1}, 1),
        ("3 fail: retained Seal does not export", ws, {"seals": [S(9, {"1": 8}, ok=False)], "report": B, "resume_turn": 1}, 1),
        ("4 pass: fork isolated", rnd(fk + [SL(14, 2)]), {"seals": [S(9, {"1": 8}), S(14, {"1": 8})], "forks": ["c"], "report": B, "resume_turn": 2}, 0),
        ("4 fail: child's turn in the parent", rnd(fk + [SL(14, 2)]), {"seals": [S(9, {"1": 8}), S(14, {"1": 8, "c2": 8})], "forks": ["c"], "report": B, "resume_turn": 2}, 1),
        ("4 pass: promotion adopted whole", pr, {"seals": [S(9, {"1": 8}), S(16, {"1": 8, "c2": 8})], "forks": ["c"], "report": B, "resume_turn": 2}, 0),
        ("4 fail: acknowledged promotion not adopted", pr, {"seals": [S(9, {"1": 8})], "forks": ["c"], "report": B, "resume_turn": 2}, 1),
        ("4 pass: in-flight promotion absent", rnd(fk, ("promote", {"child": "c"})), {"seals": [S(9, {"1": 8})], "forks": ["c"], "report": B, "resume_turn": 1}, 0),
        ("4 fail: in-flight promotion half", rnd(fk, ("promote", {"child": "c"})), {"seals": [S(9, {"1": 8}), S(16, {"1": 8, "c2": 3})], "forks": ["c"], "report": B, "resume_turn": 2}, 1),
        ("5 pass: effect in flight, reconciled", rnd([W(1), SL(9, 1)], ("effect", {})), {"seals": [S(9, {"1": 8})], "report": B + "v: effects (Dispatch) reconciled: Reconciled { settled: [OpId(1)], open: [] }", "resume_turn": 1}, 0),
        ("5 fail: effect in flight, no reconcile line", rnd([W(1), SL(9, 1)], ("effect", {})), {"seals": [S(9, {"1": 8})], "report": B, "resume_turn": 1}, 1),
        ("5 pass: the reborn Warden opened the Vessel", ws, {"seals": [S(9, {"1": 8})], "report": B, "resume_turn": 1, "opened": True}, 0),
        ("5 fail: the reborn Warden did not open the Vessel (F1)", ws, {"seals": [S(9, {"1": 8})], "report": B, "resume_turn": 1, "opened": False, "not_run": "chronicle: layer: taso-blkd: map: L3 still has layers on top of it"}, 1),
        ("5 (iii) fail: resumes after the wrong turn", ws, {"seals": [S(9, {"1": 8})], "report": B, "resume_turn": 0}, 1),
        ("5 fail: no recovery line", ws, {"seals": [S(9, {"1": 8})], "report": "", "resume_turn": 1}, 1),
        ("5 error pass", rnd([W(1), SL(9, 1)], mode="error"), {"seals": [S(9, {"1": 8})], "report": B + "write: Read-only file system; store poisoned", "resume_turn": 1, "acks_after_error": 0}, 0),
        ("5 error fail: an ack after the error", rnd([W(1), SL(9, 1)], mode="error"), {"seals": [S(9, {"1": 8})], "report": B + "EIO", "resume_turn": 1, "acks_after_error": 1}, 1),
    ]
    bad = 0
    for name, r, a, want in cases:
        fails, _ = check(r, a)
        got = 1 if fails else 0
        bad += got != want
        print(f"{'OK ' if got == want else 'BAD'}  {name}" + ("" if got == want else f" — got {'fail' if got else 'pass'}: {fails}"))
    import io, contextlib
    # E3-3c: a cut at a hold is graded as any cut; the Seal in flight at
    # seal.recorded may be absent, the one acknowledged before seal.shipped may not.
    held = [
        ("hold pass: seal.recorded, in-flight Seal absent", "seal.recorded", [W(1)], ("seal", {"turn": 1}), {"seals": [], "report": RESET, "resume_turn": 0}, 0),
        ("hold pass: seal.shipped, acknowledged Seal kept", "seal.shipped", [W(1), SL(9, 1)], None, {"seals": [S(9, {"1": 8})], "report": B, "resume_turn": 1}, 0),
        ("hold fail: seal.shipped, acknowledged Seal lost", "seal.shipped", [W(1), SL(9, 1)], None, {"seals": [], "report": RESET, "resume_turn": 0}, 1),
        # The exact checks: what "landed or not" allowed elsewhere, a hold settles.
        ("hold fail: seal.recorded, the held Seal listed whole", "seal.recorded", [W(1)], ("seal", {"turn": 1}), {"seals": [S(9, {"1": 8})], "report": B, "resume_turn": 1}, 1),
        ("hold pass: fork.branched, no child ran", "fork.branched", [W(1), SL(9, 1)], ("fork", {}), {"seals": [S(9, {"1": 8})], "report": B, "resume_turn": 1}, 0),
        ("hold fail: fork.branched, the held child ran", "fork.branched", [W(1), SL(9, 1)], ("fork", {}), {"seals": [S(9, {"1": 8})], "forks": ["c"], "report": B, "resume_turn": 1}, 1),
        ("hold pass: compact.written, the old log reopened", "compact.written", [W(1), SL(9, 1)], None, {"seals": [S(9, {"1": 8})], "report": B, "resume_turn": 1, "log_inode": {"before": 12, "after": 12}}, 0),
        ("hold fail: compact.written, the new log reopened", "compact.written", [W(1), SL(9, 1)], None, {"seals": [S(9, {"1": 8})], "report": B, "resume_turn": 1, "log_inode": {"before": 12, "after": 13}}, 1),
        ("hold fail: compact.written, the log not looked at", "compact.written", [W(1), SL(9, 1)], None, {"seals": [S(9, {"1": 8})], "report": B, "resume_turn": 1, "log_inode": {"before": 12, "after": None}}, 1),
    ]
    # E3-4: graded on the new Warden B, by the shipped anchor (D97), then F, H and 5a.
    REB = "v: reborn at epoch 2 from anchor lsn 9\n"
    LOST = "v: reborn at epoch 2 from anchor lsn 5, records 6..=9 lost\n"
    def TK(shipped=9, acks=0, fenced="chronicle: Fenced", added=(), changed=(), gone=(), c=None, child=None):
        return {"owner": {"holder": 1, "epoch": 1}, "shipped_lsn": shipped, "child": child,
                "thaw": {"acks": acks, "replies": ["seal: {}", "effect: {}"], "fenced": fenced},
                "packs": {"added": list(added), "changed": list(changed), "gone": list(gone)},
                "after_thaw": c if c is not None else {"seals": [S(9, {"1": 8})], "opened": True}}
    def tkr(steps, inflight=None):
        rnd(steps, inflight); r = load(R); r["point"] = "takeover:2"; save(R, r); return load(R)
    B9 = {"seals": [S(9, {"1": 8})], "report": REB, "resume_turn": 1, "opened": True}
    takeover = [
        ("tk pass: the shipped Seal on B", B9, TK(), 0),
        ("tk fail: the shipped Seal not on B", {"seals": [], "report": REB, "resume_turn": 0, "opened": True}, TK(c={"seals": [], "opened": True}), 1),
        ("tk pass: acknowledged, not shipped, absent, the span named", {"seals": [], "report": LOST, "resume_turn": 0, "opened": True}, TK(shipped=5, c={"seals": [], "opened": True}), 0),
        ("tk fail: acknowledged, not shipped, absent, unnamed", {"seals": [], "report": REB, "resume_turn": 0, "opened": True}, TK(shipped=5, c={"seals": [], "opened": True}), 1),
        ("tk fail F: the old Warden acknowledged after its takeover", B9, TK(acks=1), 1),
        ("tk fail F: the old Warden's refusal not named", B9, TK(fenced=None), 1),
        ("tk pass H2: a pack no record names (a note)", B9, TK(added=["./v/pack/12-5-0"]), 0),
        ("tk fail H3: a named pack's bytes changed", B9, TK(changed=["./v/pack/9-5-9"]), 1),
        ("tk fail H: a pack gone", B9, TK(gone=["./v/pack/9-5-9"]), 1),
        ("tk fail H1: no third Warden could rebuild", B9, TK(c={"seals": [], "opened": False, "not_run": "chain: digest mismatch"}), 1),
        ("tk fail H1: rebuilt, other Seals", B9, TK(c={"seals": [S(9, {"1": 5})], "opened": True}), 1),
        ("tk fail 5a: the child neither ran nor was refused", B9, TK(child={"subject": "c", "ran": False, "refused": None}), 1),
        ("tk pass 5a: the child refused by name", B9, TK(child={"subject": "c", "ran": False, "refused": "a fork is reborn only where its parent's Seal is"}), 0),
        ("tk fail: no takeover facts gathered", B9, None, 1),
    ]
    for name, a, t, want in takeover:
        r = tkr([W(1), SL(9, 1)])
        fails, _ = check(r, dict(a, **({"takeover": t} if t else {})))
        got = 1 if fails else 0
        bad += got != want
        print(f"{'OK ' if got == want else 'BAD'}  {name}" + ("" if got == want else f" — got {'fail' if got else 'pass'}: {fails}"))
    for name, hn, steps, infl, a, want in held:
        rnd(steps, infl)
        r = load(R); r["point"] = "hold:" + hn; save(R, r)
        cut(R, 30, False, hn)
        a = dict(a, acks_after_error=0); save(R + ".a", a)
        with contextlib.redirect_stdout(io.StringIO()) as out:
            got = do_check(R, R + ".a")
        ok = got == want and f"hold:{hn}" in out.getvalue() and load(R)["cut"]["held"] == hn
        bad += not ok
        print(f"{'OK ' if ok else 'BAD'}  {name}" + ("" if ok else f" — got {got}: {out.getvalue().strip()}"))
    try:
        cut(R, 30, True, "seal.recorded"); refused = False
    except SystemExit:
        refused = True
    bad += not refused
    print(f"{'OK ' if refused else 'BAD'}  a held cut cannot be missed")
    new(R, "write seal", "timing:2+25", "drop", 8); cut(R, 25, True)
    with contextlib.redirect_stdout(io.StringIO()):
        a = R + ".a"; save(a, {}); missed = do_check(R, a)
    bad += missed != 2
    print(f"{'OK ' if missed == 2 else 'BAD'}  missed point is MISSED, never covered")
    total = len(cases) + len(takeover) + len(held) + 2
    print(f"selftest: {total - bad}/{total} OK")
    return 1 if bad else 0


def main(argv):
    if not argv:
        print(__doc__); return 2
    cmd, rest = argv[0], argv[1:]
    if cmd == "selftest":
        return selftest()
    if cmd == "new":
        o = dict(zip(rest[1::2], rest[2::2]))
        return new(rest[0], o["--sequence"], o["--point"], o["--mode"], int(o.get("--rows", 8))) or 0
    if cmd in ("requested", "acknowledged"):
        return event(rest[0], cmd, rest[1], kv(rest[2:])) or 0
    if cmd == "cut":
        held = rest[rest.index("--held") + 1] if "--held" in rest else None
        return cut(rest[0], int(rest[rest.index("--swap-ms") + 1]), "--missed" in rest, held) or 0
    if cmd == "check":
        return do_check(rest[0], rest[rest.index("--after") + 1])
    print(__doc__); return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
