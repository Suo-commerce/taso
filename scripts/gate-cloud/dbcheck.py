#!/usr/bin/env python3
"""Check the agent's SQLite database inside one Seal snapshot (gate-p2).

    dbcheck.py <dataset>@<snapshot> <sealed turn> <txns per turn> <rows per txn>

The snapshot's state.db (and its -wal, if any) are copied to a temporary
directory and opened there, so SQLite applies the WAL exactly as the agent
would on resume; the snapshot itself is never touched.

Passes if PRAGMA integrity_check is "ok" and the table holds exactly turns
1..<sealed turn>, each with <txns> x <rows> rows: no transaction of a later
turn, none cut in half, none missing.  Prints one line of JSON.
"""
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile


def main():
    snap, turn, txns, rows = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
    ds, name = snap.split("@", 1)
    mount = subprocess.run(["zfs", "get", "-H", "-o", "value", "mountpoint", ds],
                           check=True, capture_output=True, text=True).stdout.strip()
    src = os.path.join(mount, ".zfs", "snapshot", name)
    out = {"snapshot": snap, "sealed_turn": turn}
    with tempfile.TemporaryDirectory() as d:
        if not os.path.exists(os.path.join(src, "state.db")):
            out.update(ok=False, why="no state.db in the snapshot")
            print(json.dumps(out))
            return
        for f in ("state.db", "state.db-wal"):
            if os.path.exists(os.path.join(src, f)):
                shutil.copy2(os.path.join(src, f), d)
        c = sqlite3.connect(os.path.join(d, "state.db"))
        integrity = c.execute("PRAGMA integrity_check").fetchone()[0]
        per_turn = dict(c.execute("SELECT turn, count(*) FROM events GROUP BY turn").fetchall())
        c.close()
    want = {t: txns * rows for t in range(1, turn + 1)}
    out.update(integrity=integrity, rows=sum(per_turn.values()), turns=len(per_turn))
    if integrity != "ok":
        out.update(ok=False, why=f"integrity_check: {integrity}")
    elif per_turn != want:
        bad = {t: n for t, n in per_turn.items() if want.get(t) != n}
        missing = [t for t in want if t not in per_turn]
        out.update(ok=False, why=f"rows per turn differ from {txns}x{rows} for turns 1..{turn}: "
                                 f"unexpected {bad}, missing {missing[:5]}")
    else:
        out.update(ok=True)
    print(json.dumps(out))


main()
