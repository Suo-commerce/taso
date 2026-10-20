#!/usr/bin/env python3
"""Check the agent's SQLite database inside one Seal (gate-p2, gate-p2-blk).

    dbcheck.py <dataset>@<snapshot> <sealed turn> <txns per turn> <rows per txn>
    dbcheck.py <directory>          <sealed turn> <txns per turn> <rows per txn>

The first form is a ZFS snapshot (read through .zfs/snapshot); the second
any directory holding the Seal's files, such as a block-log Seal forked to
a branch and mounted read-only.  An argument naming an existing directory
is the second form; anything else must be <dataset>@<snapshot>.

The Seal's state.db (and its -wal, if any) are copied to a temporary
directory and opened there, so SQLite applies the WAL exactly as the agent
would on resume; the Seal itself is never touched.

Passes if PRAGMA integrity_check is "ok" and the table holds exactly turns
1..<sealed turn>, each with <txns> x <rows> rows: no transaction of a later
turn, none cut in half, none missing.  Prints one line of JSON with "ok".
"""
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile


def seal_dir(arg):
    """The directory holding the Seal's files, and how it was named."""
    if os.path.isdir(arg):
        return arg, {"directory": arg}
    if "@" not in arg:
        raise SystemExit(f"dbcheck.py: {arg} is neither a directory nor <dataset>@<snapshot>")
    ds, name = arg.split("@", 1)
    mount = subprocess.run(["zfs", "get", "-H", "-o", "value", "mountpoint", ds],
                           check=True, capture_output=True, text=True).stdout.strip()
    return os.path.join(mount, ".zfs", "snapshot", name), {"snapshot": arg}


def check(src, turn, txns, rows):
    """The JSON fields for the database under src."""
    out = {"sealed_turn": turn}
    if not os.path.exists(os.path.join(src, "state.db")):
        out.update(ok=False, why="no state.db in the Seal")
        return out
    with tempfile.TemporaryDirectory() as d:
        for f in ("state.db", "state.db-wal"):
            if os.path.exists(os.path.join(src, f)):
                shutil.copy2(os.path.join(src, f), d)
        c = sqlite3.connect(os.path.join(d, "state.db"))
        try:
            integrity = c.execute("PRAGMA integrity_check").fetchone()[0]
            per_turn = dict(c.execute("SELECT turn, count(*) FROM events GROUP BY turn").fetchall())
        except sqlite3.DatabaseError as e:
            out.update(ok=False, why=f"sqlite: {e}")
            return out
        finally:
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
    return out


def main():
    if len(sys.argv) != 5:
        raise SystemExit(__doc__.strip().split("\n\n")[1])
    src, named = seal_dir(sys.argv[1])
    turn, txns, rows = int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
    out = dict(named)
    out.update(check(src, turn, txns, rows))
    print(json.dumps(out))


if __name__ == "__main__":
    main()
