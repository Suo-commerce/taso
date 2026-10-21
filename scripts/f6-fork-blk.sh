#!/usr/bin/env bash
# F6 step 3d (fencing review F6; plan in Taso_handoff_2026-10-21 §3): the
# daemon forks a Vessel into another uid slot on the Chronicle block log
# and runs its agent over the parent's files through an idmapped /work.
# The first time a forked Vessel runs under taso-wardend, end to end.
#
# One machine: the installed taso-blkd (/run/taso/blk.sock, node-setup.sh
# vessel-blk), a coordinator of this script's own, packs to a local
# directory, runc with Landlock, the stand-in agent taso-sim.
#
#   phase 1  the parent, born in slot 1, runs $PARENT_TURNS turns, each
#            sealed; the Warden exits when the agent is done
#   phase 2  the child, an entry with "fork": {"parent": ..., "seal":
#            "last"} in slot 2 (the parent is not run), runs $CHILD_TURNS
#            turns over the parent's files
#   phase 3  a new Warden with both entries (parent slot 1, child slot 2):
#            the source guard is seeded from the pool and the local logs
#            (F6 step 3b), each runs $AGAIN_TURNS more turns
#
# Rows, predictions written before the first run (2026-10-21):
#   R1 forked     phase 2's log: "Forked from \"parent\" at Seal lsn L",
#                 L the parent's last accepted Seal
#   R2 idmapped   phase 2's log: "its files are its lineage's range
#                 (265536): /work is idmapped"; the Warden exits 0
#   R3 log        the child's log is whole: lsns 1.. consecutive, every
#                 prev the hash before, ending at the coordinator's head,
#                 no Gap, every Seal Clean, a turn sealed (which parent and
#                 Seal it was forked from is R1: taso-logcheck shows kinds)
#   R4 parent     the parent untouched by phase 2: its holder, epoch and
#                 head as before, and its last Seal exported block for
#                 block the same before and after
#   R5 disk       on a read-only mount of the child's last Seal: every
#                 file's uid and gid (but root's) in the parent's range
#                 265536..+65536, none in the child's 331072..+65536
#   R6 data       SQLite integrity "ok" on that mount, and the parent's
#                 rows are all there with the child's added
#   R7 restart    phase 3: neither Vessel refused (no "is not run"), both
#                 opened, both seal new turns, the child idmapped again;
#                 the Warden exits 0
#   TURNS         not a pass or fail: what the child's agent was told it
#                 resumes after, against the parent's last turn.  A fork's
#                 own Chronicle has only its birth Seal, and Hello reports
#                 that as no turn: the child is expected to start again at
#                 turn 1 over the parent's turns.  Whether a fork continues
#                 its parent's turn count is a decision, not a test.
#
# Usage (root on a node with runc, cargo, python3, ublk and the installed
# taso-blkd; node-setup.sh vessel-blk):
#   scripts/f6-fork-blk.sh
#
# Environment: PARENT_TURNS (3)  CHILD_TURNS (3)  AGAIN_TURNS (2)
#              LANDLOCK (1)  OUT (/root/taso-f6-fork-<time>)  KEEP (0)
#
# Touches, and nothing else: $WORK (/var/tmp/taso-f6fork.*: coordinator,
# state, spool, mounts, packs, rootfs, configs); in the installed block log,
# branches named f6fork-<run>/... and their Seals (dropped at the end unless
# KEEP=1); /dev/ublkb* devices for those; $OUT (results, kept).

set -euo pipefail

PARENT_TURNS=${PARENT_TURNS:-3}
CHILD_TURNS=${CHILD_TURNS:-3}
AGAIN_TURNS=${AGAIN_TURNS:-2}
LANDLOCK=${LANDLOCK:-1}
KEEP=${KEEP:-0}
OUT=${OUT:-/root/taso-f6-fork-$(date +%Y%m%d-%H%M%S)}
RUN=$(date +%Y%m%d%H%M%S)-$$
BLK_SOCK=/run/taso/blk.sock
BASE=200000
RANGE=65536
A=$((BASE + 1 * RANGE))   # slot 1: the parent, and the lineage's disk range
B=$((BASE + 2 * RANGE))   # slot 2: the child
NS=7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a

die() { echo "error: $*" >&2; exit 2; }
[ "$(id -u)" = 0 ] || die "run as root"
for t in runc ldd python3 cargo sha256sum; do command -v "$t" >/dev/null || die "$t is missing"; done
[ -S "$BLK_SOCK" ] || die "no taso-blkd on $BLK_SOCK (scripts/gate-cloud/node-setup.sh vessel-blk)"

cd "$(dirname "$0")/.."
echo "== building (release)"
cargo build --release -q -p taso-warden -p taso-sim -p taso-landlock --bins
for b in taso-wardend taso-logcheck taso-sim taso-landlock taso-coordd; do
    [ -x "target/release/$b" ] || die "target/release/$b was not built"
done
BIN=$PWD/target/release

mkdir -p "$OUT"
WORK=$(mktemp -d /var/tmp/taso-f6fork.XXXXXX)
chmod 755 "$WORK"
trap 'rm -rf "$WORK"' EXIT   # until the full cleanup below is in place
ROOT="f6fork-$RUN"
mkdir -p "$WORK/mnt" "$WORK/spool" "$WORK/state" "$WORK/run" "$WORK/store" "$WORK/scratch"

# ── the block log's socket ────────────────────────────────────────────
cat > "$WORK/blkcmd.py" <<'PY'
import socket, sys
s = socket.socket(socket.AF_UNIX); s.settimeout(120); s.connect(sys.argv[1])
s.sendall((" ".join(sys.argv[2:]) + "\n").encode())
a = s.makefile().readline().strip()
if a == "ok": sys.exit(0)
if a.startswith("ok "): print(a[3:]); sys.exit(0)
print(a, file=sys.stderr); sys.exit(1)
PY
blk() { python3 "$WORK/blkcmd.py" "$BLK_SOCK" "$@"; }

# Every branch under $ROOT, its Seals and root Seal, dropped newest first
# (what is still stood on is reported, not fatal).
drop_root() {
    local names pair b seals first parent s
    names=$(blk names 2>/dev/null) || return 0
    for pair in $names; do
        [[ "$pair" == "$ROOT/"* ]] || continue
        b=${pair#*:}
        seals=$(blk seals "$b" 2>&1) || { echo "  seals $b: $seals" >&2; seals=; }
        first=${seals%% *}; first=${first%%:*}
        parent=; [ -n "$first" ] && parent=$(blk info "$first" 2>/dev/null | tr ' ' '\n' | sed -n 's/^parent=//p')
        blk drop "$b" >/dev/null 2>&1 || echo "  drop branch $b refused" >&2
        for s in $(echo "$seals" | tr ' ' '\n' | tac); do
            blk drop "${s%%:*}" >/dev/null 2>&1 || echo "  drop Seal ${s%%:*} refused" >&2
        done
        if [ -n "$parent" ] && [ "$parent" != "-" ]; then
            blk drop "$parent" >/dev/null 2>&1 || true
        fi
    done
    return 0
}

COORD_PID=
SCRATCH_BRANCH=
cleanup() {
    local rc=$?
    set +e
    if [ -d "$WORK/run/runc" ]; then
        for c in $(runc --root "$WORK/run/runc" list -q 2>/dev/null); do runc --root "$WORK/run/runc" delete --force "$c" 2>/dev/null; done
    fi
    mountpoint -q "$WORK/scratch" && { umount "$WORK/scratch" 2>/dev/null || umount -l "$WORK/scratch"; }
    [ -n "$SCRATCH_BRANCH" ] && blk drop "$SCRATCH_BRANCH" >/dev/null 2>&1
    awk -v r="$WORK/mnt" '$5 == r || index($5, r "/") == 1 {print length($5), $5}' /proc/self/mountinfo \
        | sort -rn | cut -d' ' -f2- | while read -r m; do umount "$m" 2>/dev/null || umount -l "$m" 2>/dev/null; done
    [ -n "$COORD_PID" ] && kill "$COORD_PID" 2>/dev/null
    if [ "$KEEP" = 1 ]; then
        echo "kept (KEEP=1): $WORK, branches under $ROOT in the block log"
    else
        drop_root
        rm -rf "$WORK"
    fi
    exit $rc
}
trap cleanup EXIT

# ── rootfs ────────────────────────────────────────────────────────────
ROOTFS=$WORK/rootfs
copy_with_libs() {
    install -D -m 755 "$1" "$ROOTFS$2"
    ldd "$1" | grep -o '/[^ ]*' | while read -r lib; do install -D -m 755 "$lib" "$ROOTFS$lib"; done
}
copy_with_libs "$BIN/taso-sim" /usr/bin/taso-sim
copy_with_libs "$BIN/taso-landlock" /usr/lib/taso/landlock
mkdir -p "$ROOTFS"/{proc,dev,sys,tmp,work,run/taso}
: > "$ROOTFS/run/taso/field.sock"

# ── coordinator ───────────────────────────────────────────────────────
SOCK=$WORK/coord.sock
"$BIN/taso-coordd" "$WORK/coord.redb" "$SOCK" 2>"$OUT/coordd.err" &
COORD_PID=$!
for _ in $(seq 100); do [ -S "$SOCK" ] && break; sleep 0.05; done
[ -S "$SOCK" ] || die "taso-coordd did not start; see $OUT/coordd.err"

# config <out> <turns> <entry JSON>...: one Warden (1) over the installed
# block log, every Vessel under $ROOT.
config() {
    local out=$1 turns=$2; shift 2
    python3 - "$out" "$turns" "$@" <<PY
import json, sys
out, turns, entries = sys.argv[1], sys.argv[2], [json.loads(e) for e in sys.argv[3:]]
json.dump({
    "warden": 1,
    "coordinator": {"remote": "$SOCK"},
    "storage": {"blk": {"socket": "$BLK_SOCK", "mounts": "$WORK/mnt", "spool": "$WORK/spool"}},
    "root": "$ROOT",
    "state_dir": "$WORK/state",
    "store": "$WORK/store",
    "prefix": "vessels",
    "run_dir": "$WORK/run",
    "runtime": {
        "rootfs": "$ROOTFS",
        "host_uid_base": $BASE,
        "landlock_shim": "/usr/lib/taso/landlock" if "$LANDLOCK" == "1" else None,
        "args": ["/usr/bin/taso-sim", "--turns", turns, "--txns", "2", "--rows", "4",
                 "--turn-sleep-ms", "50", "--stats", "/work/sim-stats.json"],
        "memory_bytes": 268435456,
        "pids": 64,
    },
    "vessels": [dict(namespace="$NS", **e) for e in entries],
}, open(out, "w"), indent=1)
PY
}
PARENT='{"subject": "parent", "uid_slot": 1}'
CHILD='{"subject": "child", "uid_slot": 2, "fork": {"parent": "parent", "seal": "last"}}'

wardend() {   # $1 phase name, $2 config: runs to the end; prints the exit status
    local rc=0
    timeout 600 "$BIN/taso-wardend" "$2" >"$OUT/$1.out" 2>"$OUT/$1.err" || rc=$?
    echo "$rc"
}
dataset_of() {   # $1 log, $2 subject -> the dataset the daemon logged
    { grep -o "\] $2: dataset [^ ]*\$" "$1" || true; } | head -1 | sed 's/.*: dataset //'
}
logcheck() {   # $1 vessel id hex, $2 out file
    "$BIN/taso-logcheck" "$SOCK" "$WORK/state" "$1" >"$2"
}
last_seal() {   # $1 logcheck json -> "<lsn> <turn>" of the last accepted Seal
    python3 -c '
import json, sys
j = json.load(open(sys.argv[1])); h = j["head"]["lsn"]
s = [f for f in j["frames"] if f["kind"] == "seal" and f["lsn"] <= h][-1]
print(s["lsn"], s.get("turn", 0))' "$1"
}
export_hash() {   # $1 Seal layer id -> sha256 of its full export
    blk export "$1" - "$WORK/export.img" >/dev/null
    sha256sum "$WORK/export.img" | cut -d' ' -f1
    rm -f "$WORK/export.img"
}
seal_layer() {   # $1 dataset (branch name), $2 Seal lsn -> its layer id
    local b; b=$(blk find "$1")
    blk seals "$b" | tr ' ' '\n' | while IFS=: read -r layer tag; do
        l=$(python3 -c "import sys; print(int.from_bytes(bytes.fromhex(sys.argv[1][:16]), 'little'))" "$tag")
        [ "$l" = "$2" ] && { echo "$layer"; break; }
    done
}
declare -A ROW
row() { ROW[$1]=$2; printf '  %-9s %s\n' "$1" "$2"; }

echo "== one machine: installed taso-blkd, coordinator $SOCK, packs to $WORK/store, Landlock $LANDLOCK"
echo "== uid slots: parent 1 ($A), child 2 ($B)"

# ── phase 1: the parent ───────────────────────────────────────────────
config "$WORK/p1.json" "$PARENT_TURNS" "$PARENT"
rc=$(wardend phase1 "$WORK/p1.json")
[ "$rc" = 0 ] || { echo "phase 1: the Warden exited $rc; its log:" >&2; tail -15 "$OUT/phase1.err" | sed 's/^/    /' >&2; exit 1; }
PDS=$(dataset_of "$OUT/phase1.err" parent)
[ -n "$PDS" ] || die "phase 1 logged no dataset for the parent"
PID_HEX=${PDS##*/v-}
logcheck "$PID_HEX" "$OUT/parent-before.json"
read -r P_LSN P_TURN < <(last_seal "$OUT/parent-before.json")
P_LAYER=$(seal_layer "$PDS" "$P_LSN")
[ -n "$P_LAYER" ] || die "the parent's Seal at lsn $P_LSN has no layer in the block log"
P_EXPORT=$(export_hash "$P_LAYER")
echo "== phase 1: parent $PDS, last Seal lsn $P_LSN (turn $P_TURN)"

# ── phase 2: the child, forked ────────────────────────────────────────
config "$WORK/p2.json" "$CHILD_TURNS" "$CHILD"
rc2=$(wardend phase2 "$WORK/p2.json")
CDS=$(dataset_of "$OUT/phase2.err" child)
CID_HEX=${CDS##*/v-}
echo "== phase 2: the Warden exited $rc2; child ${CDS:-(no dataset logged)}"

grep -q "child: Forked from \"parent\" at Seal lsn $P_LSN\$" "$OUT/phase2.err" && row R1 PASS || row R1 "FAIL ($(grep -o 'child: Forked.*\|cannot fork.*' "$OUT/phase2.err" | head -1))"
if [ "$rc2" = 0 ] && grep -q "child: its files are its lineage's range ($A): /work is idmapped" "$OUT/phase2.err"; then
    row R2 PASS
else
    row R2 "FAIL (exit $rc2; $(grep -c 'idmapped' "$OUT/phase2.err" || true) idmapped line(s))"
fi
if [ -z "$CDS" ]; then
    echo "phase 2 made no child; its log:" >&2; tail -15 "$OUT/phase2.err" | sed 's/^/    /' >&2
    exit 1
fi

logcheck "$CID_HEX" "$OUT/child.json"
r3=$(python3 - "$OUT/child.json" "$PID_HEX" "$P_LSN" <<'PY'
import json, sys
j = json.load(open(sys.argv[1])); parent, plsn = sys.argv[2], int(sys.argv[3])
fr = j["frames"]; why = []
if not fr or fr[0]["lsn"] != 1: why.append("does not start at lsn 1")
for a, b in zip(fr, fr[1:]):
    if b["lsn"] != a["lsn"] + 1 or b["prev"] != a["hash"]:
        why.append(f"breaks at lsn {b['lsn']}"); break
if fr and (fr[-1]["lsn"] != j["head"]["lsn"] or fr[-1]["hash"] != j["head"]["hash"]):
    why.append(f"ends at {fr[-1]['lsn']}, the head is {j['head']['lsn']}")
if any(f["kind"] == "gap" for f in fr): why.append("has a Gap")
bad = [f["lsn"] for f in fr if f["kind"] == "seal" and f.get("verdict") != "clean"]
if bad: why.append(f"Seals not Clean at {bad}")
seals = [f for f in fr if f["kind"] == "seal"]
if len(seals) < 2: why.append(f"{len(seals)} Seal(s): no turn sealed")
print("PASS" if not why else "FAIL (" + "; ".join(why) + ")")
PY
)
row R3 "$r3"

logcheck "$PID_HEX" "$OUT/parent-after.json"
r4=$(python3 - "$OUT/parent-before.json" "$OUT/parent-after.json" <<'PY'
import json, sys
a, b = (json.load(open(p)) for p in sys.argv[1:])
k = lambda j: (j["ownership"]["holder"], j["ownership"]["epoch"], j["head"]["lsn"], j["head"]["hash"])
print("same" if k(a) == k(b) else f"changed: {k(a)} -> {k(b)}")
PY
)
P_EXPORT_AFTER=$(export_hash "$P_LAYER")
if [ "$r4" = same ] && [ "$P_EXPORT" = "$P_EXPORT_AFTER" ]; then row R4 PASS; else row R4 "FAIL (ownership/head: $r4; export equal: $([ "$P_EXPORT" = "$P_EXPORT_AFTER" ] && echo yes || echo no))"; fi

# The child's last Seal, forked to a scratch branch and mounted read-only:
# the bytes as they are on disk, no idmapping.
read -r C_LSN _ < <(last_seal "$OUT/child.json")
C_LAYER=$(seal_layer "$CDS" "$C_LSN")
out=$(blk fork "$C_LAYER" "$ROOT/scratch")
SCRATCH_BRANCH=${out%% *}; dev=${out#* }
mount -o ro,noload "$dev" "$WORK/scratch"
r5=$(python3 - "$WORK/scratch" "$A" "$B" "$RANGE" <<'PY'
import os, sys
root, a, b, n = sys.argv[1], *map(int, sys.argv[2:])
seen, foreign, mine = 0, [], []
for d, dirs, files in os.walk(root):
    for x in [d] + [os.path.join(d, f) for f in files]:
        st = os.lstat(x)
        for i in (st.st_uid, st.st_gid):
            if i == 0: continue
            seen += 1
            if b <= i < b + n: mine.append(x)
            elif not a <= i < a + n: foreign.append((x, i))
if seen == 0: print("FAIL (no file owned by anyone but root)")
elif mine: print(f"FAIL ({len(mine)} owned in the child's own range, e.g. {mine[0]})")
elif foreign: print(f"FAIL ({len(foreign)} outside the parent's range, e.g. {foreign[0]})")
else: print(f"PASS ({seen} owner ids, all in the parent's range)")
PY
)
row R5 "$r5"
r6=$(python3 - "$WORK/scratch" "$P_TURN" <<'PY'
import os, shutil, sqlite3, sys, tempfile
src, pturn = sys.argv[1], int(sys.argv[2])
if not os.path.exists(os.path.join(src, "state.db")):
    print("FAIL (no state.db)"); sys.exit()
with tempfile.TemporaryDirectory() as d:
    for f in ("state.db", "state.db-wal"):
        if os.path.exists(os.path.join(src, f)): shutil.copy2(os.path.join(src, f), d)
    c = sqlite3.connect(os.path.join(d, "state.db"))
    ok = c.execute("PRAGMA integrity_check").fetchone()[0]
    rows = c.execute("SELECT count(*) FROM events").fetchone()[0]
    c.close()
parent_rows = pturn * 2 * 4
if ok != "ok": print(f"FAIL (integrity: {ok})")
elif rows <= parent_rows: print(f"FAIL ({rows} rows: the parent's {parent_rows} and nothing of the child's)")
else: print(f"PASS ({rows} rows: the parent's {parent_rows} and the child's {rows - parent_rows})")
PY
)
row R6 "$r6"
umount "$WORK/scratch"; blk drop "$SCRATCH_BRANCH" >/dev/null 2>&1 || echo "  drop scratch refused" >&2; SCRATCH_BRANCH=

resumed=$(python3 -c "import json,sys; j=json.load(open(sys.argv[1])); print(j['resumed_after'], j['turns'])" "$WORK/mnt/$CDS/sim-stats.json" 2>/dev/null || echo "unknown")
row TURNS "DECISION: the parent's last turn is $P_TURN; the child was told it resumes after: $resumed"

# ── phase 3: a new Warden with both ───────────────────────────────────
config "$WORK/p3.json" "$AGAIN_TURNS" "$PARENT" "$CHILD"
rc3=$(wardend phase3 "$WORK/p3.json")
logcheck "$PID_HEX" "$OUT/parent-3.json"
logcheck "$CID_HEX" "$OUT/child-3.json"
r7=$(python3 - "$OUT/parent-after.json" "$OUT/parent-3.json" "$OUT/child.json" "$OUT/child-3.json" <<'PY'
import json, sys
pa, pb, ca, cb = (json.load(open(p)) for p in sys.argv[1:])
n = lambda j: sum(1 for f in j["frames"] if f["kind"] == "seal")
why = []
if n(pb) <= n(pa): why.append("the parent sealed nothing new")
if n(cb) <= n(ca): why.append("the child sealed nothing new")
print("; ".join(why))
PY
)
refusals=$(grep -c "is not run" "$OUT/phase3.err" || true)
idm=$(grep -c "child: its files are its lineage's range ($A): /work is idmapped" "$OUT/phase3.err" || true)
if [ "$rc3" = 0 ] && [ "$refusals" = 0 ] && [ "$idm" -ge 1 ] && [ -z "$r7" ]; then
    row R7 PASS
else
    row R7 "FAIL (exit $rc3; $refusals refusal(s); $idm idmapped line(s); ${r7:-sealed both})"
fi

# ── summary ───────────────────────────────────────────────────────────
fails=0
for r in R1 R2 R3 R4 R5 R6 R7; do [[ "${ROW[$r]}" == PASS* ]] || fails=$((fails + 1)); done
{
    echo "f6-fork-blk $RUN: $((7 - fails))/7 rows passed"
    for r in R1 R2 R3 R4 R5 R6 R7 TURNS; do printf '%-6s %s\n' "$r" "${ROW[$r]}"; done
} | tee "$OUT/summary.txt"
echo "== results in $OUT"
[ "$fails" = 0 ]
