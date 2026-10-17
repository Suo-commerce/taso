#!/usr/bin/env python3
"""Judge one gate-p2 round from both nodes' logs (taso-logcheck JSON).

    logjudge.py <A's log.json> <B's log.json>

What the coordinator recorded at the takeover is the authority: its
sealed_prefix is the last record A had accepted when B took over.

- If B's log holds that record, nothing was lost: B's log must have no Gap
  record, and B's first Seal must be Clean.
- Otherwise records were lost.  B's log must have exactly one Gap record,
  written in B's epoch right after the lost range, naming as `resumes` the
  coordinator's record (lsn and hash) and as `kept` a record both logs hold
  with that hash.  Every lost record must exist in A's log (they were
  accepted, then never shipped) and none in B's, and B's first Seal after
  the Gap must be Unverified, naming the same range.

Prints one line of JSON: {"ok", "lost", "why"}.
"""
import json
import sys


def judge(a, b):
    sp = b["ownership"]["sealed_prefix"]
    epoch = b["ownership"]["epoch"]
    af = {f["lsn"]: f for f in a["frames"]}
    bf = {f["lsn"]: f for f in b["frames"]}
    gaps = [f for f in b["frames"] if f["kind"] == "gap"]
    new_seals = [f for f in b["frames"] if f["kind"] == "seal" and f["epoch"] == epoch]

    if sp["lsn"] in bf and bf[sp["lsn"]]["hash"] == sp["hash"]:
        if gaps:
            return False, 0, f"nothing was lost, yet B's log has a Gap record at lsn {gaps[0]['lsn']}"
        if not new_seals:
            return False, 0, "B took no Seal"
        s = new_seals[0]
        if s["verdict"] != "clean":
            return False, 0, f"nothing was lost, yet B's first Seal (lsn {s['lsn']}) is {s['verdict']}: {s['reason']}"
        return True, 0, ""

    if len(gaps) != 1:
        return False, None, f"records after lsn {sp['lsn']} are not in B's log, and B has {len(gaps)} Gap records"
    g = gaps[0]
    kept, resumes = g["kept"], g["resumes"]
    lost = resumes - kept
    checks = [
        (g["resumes"] == sp["lsn"] and g["resumes_hash"] == sp["hash"],
         f"the Gap names resumes {resumes}, the coordinator's head at takeover was {sp['lsn']}"),
        (g["lsn"] == resumes + 1 and g["prev"] == g["resumes_hash"] and g["epoch"] == epoch,
         "the Gap record is not B's record right after the lost range"),
        (bf.get(kept, {}).get("hash") == g["kept_hash"] and af.get(kept, {}).get("hash") == g["kept_hash"],
         f"the kept record {kept} is not the same in both logs"),
        (all(l in af for l in range(kept + 1, resumes + 1)) and af[resumes]["hash"] == g["resumes_hash"],
         f"the lost records {kept + 1}..{resumes} are not all in A's log"),
        (not any(l in bf for l in range(kept + 1, resumes + 1)),
         f"B's log holds records inside the lost range {kept + 1}..{resumes}"),
    ]
    for ok, why in checks:
        if not ok:
            return False, lost, why
    after = [s for s in new_seals if s["lsn"] > g["lsn"]]
    if not after:
        return False, lost, "B took no Seal after the Gap"
    s = after[0]
    named = f"records {kept + 1}..{resumes}"
    if s["verdict"] != "unverified" or named not in s["reason"]:
        return False, lost, f"B's first Seal after the Gap is {s['verdict']} ({s['reason']!r}), not unverified naming {named}"
    return True, lost, ""


def main():
    a = json.load(open(sys.argv[1]))
    b = json.load(open(sys.argv[2]))
    ok, lost, why = judge(a, b)
    print(json.dumps({"ok": ok, "lost": lost, "why": why}))


if __name__ == "__main__":
    main()
