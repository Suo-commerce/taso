#!/usr/bin/env bash
# The rebuild on the same node, on a real block device (P4 spec rev. 38,
# D99; design Taso_design_layers_lost, file 3): the Warden's start finds a
# Vessel whose files on this node are behind its log, and rebuilds it here
# from the store.
#
# One Warden, one Vessel (taso-sim, a SQLite database, every turn sealed
# and published), this script's own taso-blkd on a log under $WORK, its
# own coordinator, packs to a local directory.
#
#   run 1   turns 1 to 3.  The block log's length is noted (after a flush:
#           a group's end).
#   run 2   turns 4 to 6.  Seals 1 to 6 are shipped.
#   damage  taso-blkd is stopped and its log cut back to the noted length,
#           as its start leaves it after a record no longer verifies: the
#           Seal layers of turns 4 to 6 are gone from the node.  The
#           Vessel's own log in the state directory is whole.
#   run 3   two more turns.  The Warden must say the Vessel is behind,
#           rebuild it (receive the sections of Seals 4 to 6), tell the
#           agent turn 6, give it turn 6's files, keep the state directory
#           it had beside the new one, and ship Seals 7 and 8.
#   run 4   one more turn: a start with nothing behind says nothing.
#
# On a Warden without the rebuild (before file 3), run 3 has no "BEHIND
# ITS LOG" line and the agent is told turn 6 over the files of turn 3.
#
# Not reached here: the three other openers (the decider's open, a waiting
# verifier, the purge at the TTL), and a loss of Seals that were never
# shipped (a real Warden publishes every Seal; the unit tests in blk.rs
# have that case).
#
# Usage (root; needs runc, cargo, python3, ublk):
#   scripts/rebuild-here.sh
# Environment: OUT (/root/taso-rebuild-here-<time>)  KEEP (0)  LANDLOCK (1)
#
# Touches: $WORK (/var/tmp/taso-rebuild.*): its own block log, coordinator,
# store, state and mounts; /dev/ublkb* devices of its own taso-blkd.
# Never the node's installed taso-blkd or /var/lib/taso.

set -euo pipefail

KEEP=${KEEP:-0}
LANDLOCK=${LANDLOCK:-1}
OUT=${OUT:-/root/taso-rebuild-here-$(date +%Y%m%d-%H%M%S)}
RUN=$(date +%Y%m%d%H%M%S)-$$

die() { echo "error: $*" >&2; exit 2; }
[ "$(id -u)" = 0 ] || die "run as root"
for t in runc ldd python3 cargo truncate stat; do command -v "$t" >/dev/null || die "$t is missing"; done

cd "$(dirname "$0")/.."
echo "== building (release)"
cargo build --release -q -p taso-warden -p taso-sim -p taso-landlock --bins
cargo build --release -q -p taso-blk --bin taso-blkd
for b in taso-wardend taso-logcheck taso-sim taso-landlock taso-blkd taso-coordd; do
    [ -x "target/release/$b" ] || die "target/release/$b was not built"
done
BIN=$PWD/target/release

mkdir -p "$OUT"
WORK=$(mktemp -d /var/tmp/taso-rebuild.XXXXXX)
chmod 755 "$WORK"
mkdir -p "$WORK"/{mnt,spool,state,run,bin,store}
ROOT="rebuild-here-$RUN"
LOG=$WORK/blk.log
BSOCK=$WORK/blk.sock
SOCK=$WORK/coord.sock

cat > "$WORK/bin/blkcmd.py" <<'PY'
import socket, sys
s = socket.socket(socket.AF_UNIX); s.settimeout(120); s.connect(sys.argv[1])
s.sendall((" ".join(sys.argv[2:]) + "\n").encode())
a = s.makefile().readline().strip()
if a == "ok": sys.exit(0)
if a.startswith("ok "): print(a[3:]); sys.exit(0)
print(a, file=sys.stderr); sys.exit(1)
PY
blk() { python3 "$WORK/bin/blkcmd.py" "$BSOCK" "$@"; }

umount_under() {   # everything under the mount root, innermost first
    awk -v r="$WORK/mnt" '$5 == r || index($5, r "/") == 1 {print length($5), $5}' /proc/self/mountinfo \
        | sort -rn | cut -d' ' -f2- | while read -r m; do umount "$m" 2>/dev/null || umount -l "$m" 2>/dev/null; done
    true
}

COORD_PID=
BLKD_PID=
start_blkd() {
    "$BIN/taso-blkd" "$LOG" "$BSOCK" 2>>"$OUT/blkd.err" &
    BLKD_PID=$!
    for _ in $(seq 200); do blk names >/dev/null 2>&1 && return 0; kill -0 "$BLKD_PID" 2>/dev/null || break; sleep 0.05; done
    echo "taso-blkd did not start; its output:" >&2; tail -5 "$OUT/blkd.err" | sed 's/^/    /' >&2
    return 1
}
stop_blkd() {
    blk quit >/dev/null 2>&1 || true
    for _ in $(seq 200); do kill -0 "$BLKD_PID" 2>/dev/null || break; sleep 0.05; done
    kill "$BLKD_PID" 2>/dev/null || true
    wait "$BLKD_PID" 2>/dev/null || true
    BLKD_PID=
    rm -f "$BSOCK"
}
cleanup() {
    local rc=$?
    set +e
    [ -d "$WORK/run/runc" ] && for c in $(runc --root "$WORK/run/runc" list -q 2>/dev/null); do runc --root "$WORK/run/runc" delete --force "$c" 2>/dev/null; done
    umount_under
    [ -n "$BLKD_PID" ] && stop_blkd
    [ -n "$COORD_PID" ] && kill "$COORD_PID" 2>/dev/null
    if [ "$KEEP" = 1 ]; then echo "kept (KEEP=1): $WORK"; else rm -rf "$WORK"; fi
    exit $rc
}
trap cleanup EXIT

# ── rootfs, coordinator, block log ────────────────────────────────────
ROOTFS=$WORK/rootfs
copy_with_libs() {
    install -D -m 755 "$1" "$ROOTFS$2"
    ldd "$1" | grep -o '/[^ ]*' | while read -r lib; do install -D -m 755 "$lib" "$ROOTFS$lib"; done
}
copy_with_libs "$BIN/taso-sim" /usr/bin/taso-sim
copy_with_libs "$BIN/taso-landlock" /usr/lib/taso/landlock
mkdir -p "$ROOTFS"/{proc,dev,sys,tmp,work,run/taso}
: > "$ROOTFS/run/taso/field.sock"

"$BIN/taso-coordd" "$WORK/coord.redb" "$SOCK" 2>"$OUT/coordd.err" &
COORD_PID=$!
for _ in $(seq 100); do [ -S "$SOCK" ] && break; sleep 0.05; done
[ -S "$SOCK" ] || die "taso-coordd did not start; see $OUT/coordd.err"
start_blkd || die "see $OUT/blkd.err"

SUBJECT="rebuild-here-$RUN"
config() {   # $1 turns, $2 out file
    python3 - "$1" "$2" <<PY
import json, sys
turns, out = sys.argv[1:]
json.dump({
    "warden": 1,
    "coordinator": {"remote": "$SOCK"},
    "storage": {"blk": {"socket": "$BSOCK", "mounts": "$WORK/mnt", "spool": "$WORK/spool"}},
    "root": "$ROOT",
    "state_dir": "$WORK/state",
    "store": "$WORK/store",
    "prefix": "vessels",
    "run_dir": "$WORK/run",
    "runtime": {
        "rootfs": "$ROOTFS",
        "host_uid_base": 200000,
        "landlock_shim": "/usr/lib/taso/landlock" if "$LANDLOCK" == "1" else None,
        "args": ["/usr/bin/taso-sim", "--turns", turns, "--txns", "2", "--rows", "4",
                 "--stats", "/work/sim-stats.json"],
        "memory_bytes": 268435456,
        "pids": 64,
    },
    "vessels": [{"namespace": "7a" * 16, "subject": "$SUBJECT", "uid_slot": 0}],
}, open(out, "w"), indent=1)
PY
}

# ── checks ────────────────────────────────────────────────────────────
CHECKS=0
FAILS=0
check() {   # $1 what, $2 0 for a pass
    CHECKS=$((CHECKS + 1))
    if [ "$2" = 0 ]; then echo "  ok    $1"; else FAILS=$((FAILS + 1)); echo "  FAIL  $1"; fi
}
warden() {   # $1 run number, $2 turns: the Warden runs the Vessel to the end of its agent
    config "$2" "$WORK/run-$1.json"
    local rc=0
    timeout 300 "$BIN/taso-wardend" "$WORK/run-$1.json" >"$OUT/run-$1.out" 2>"$OUT/run-$1.err" || rc=$?
    echo "$rc"
}
DS=
ID=
names() {   # the Vessel's dataset and id, as the Warden logged them
    DS=$({ grep -o ': dataset [^ ]*$' "$OUT/run-1.err" 2>/dev/null || true; } | head -1 | sed 's/: dataset //')
    ID=${DS##*/v-}
}
logcheck() { "$BIN/taso-logcheck" "$SOCK" "$WORK/state" "$ID" 2>>"$OUT/logcheck.err"; }
shipped_turn() {   # the newest turn whose Seal is shipped, 0 if none
    logcheck | python3 -c "
import json, sys
j = json.load(sys.stdin); s = j['shipped']['lsn']
print(max([f.get('turn', 0) for f in j['frames'] if f['kind'] == 'seal' and f['lsn'] <= s] or [0]))" 2>/dev/null || echo 0
}
resumed() {   # what the agent of the last run was told
    python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['resumed_after'])" "$WORK/mnt/$DS/sim-stats.json" 2>/dev/null || echo none
}
layers() {   # how many Seal layers the Vessel's dataset has on the block log
    local b; b=$(blk find "$DS" 2>/dev/null) || { echo 0; return; }
    blk seals "$b" 2>/dev/null | wc -w
}

echo "== run 1: turns 1 to 3"
rc=$(warden 1 3)
names
[ -n "$DS" ] || { echo "run 1 named no dataset; the Warden's log:" >&2; tail -8 "$OUT/run-1.err" | sed 's/^/    /' >&2; exit 1; }
check "run 1: the Warden exits 0 (it said $rc)" "$([ "$rc" = 0 ]; echo $?)"
t=$(shipped_turn); check "run 1: the Seal of turn 3 is shipped (newest shipped turn: $t)" "$([ "$t" = 3 ]; echo $?)"
blk flush >/dev/null
LEN_3=$(stat -c %s "$LOG")
L3=$(layers)
echo "  the block log is $LEN_3 bytes; the dataset has $L3 Seal layers"

echo "== run 2: turns 4 to 6"
rc=$(warden 2 3)
check "run 2: the Warden exits 0 (it said $rc)" "$([ "$rc" = 0 ]; echo $?)"
t=$(shipped_turn); check "run 2: the Seal of turn 6 is shipped (newest shipped turn: $t)" "$([ "$t" = 6 ]; echo $?)"
r=$(resumed); check "run 2: the agent was told turn 3 (it was told $r)" "$([ "$r" = 3 ]; echo $?)"
L6=$(layers)

echo "== damage: the block log is cut back to its length after turn 3"
umount_under
stop_blkd
LEN_6=$(stat -c %s "$LOG")
truncate -s "$LEN_3" "$LOG"
start_blkd || { echo "taso-blkd does not start on the cut log" >&2; exit 1; }
REC=$(blk recovered 2>&1 || true)
LC=$(layers)
echo "  $LEN_6 -> $LEN_3 bytes; taso-blkd's start: $REC"
echo "  Seal layers of the dataset: $L3 after turn 3, $L6 after turn 6, $LC after the cut"
check "the cut took Seal layers away ($L6 before, $LC after)" "$([ "$LC" -lt "$L6" ]; echo $?)"
check "the Vessel's own log still holds the Seal of turn 6" "$([ "$(shipped_turn)" = 6 ]; echo $?)"

echo "== run 3: the Warden starts the Vessel on the damaged node; two more turns"
rc=$(warden 3 2)
check "run 3: the Warden says the Vessel is behind its log" "$(grep -q 'BEHIND ITS LOG on this node' "$OUT/run-3.err"; echo $?)"
check "run 3: the Warden says it rebuilt the Vessel here" "$(grep -q 'rebuilt here: ' "$OUT/run-3.err"; echo $?)"
# D93: what the rebuild discarded is named as blocks, in the rebuilt line.
check "run 3: the rebuilt line names the blocks of the filesystem it discarded" "$(grep 'rebuilt here: ' "$OUT/run-3.err" | grep -qE "[0-9]+ block\(s\) of the Vessel's filesystem discarded"; echo $?)"
# And no ordinary reset line after it, which would read as a second reset.
check "run 3: no line about a reset to the last Seal after the rebuild" "$(! grep -qE ': state at lsn [0-9]+ reset to the Seal|: state at its last Seal' "$OUT/run-3.err"; echo $?)"
check "run 3: the Warden exits 0 (it said $rc)" "$([ "$rc" = 0 ]; echo $?)"
r=$(resumed); check "run 3: the agent was told turn 6 (it was told $r)" "$([ "$r" = 6 ]; echo $?)"
dbv=$(python3 scripts/gate-cloud/dbcheck.py "$WORK/mnt/$DS" 8 2 4 2>&1 || true)
echo "$dbv" >"$OUT/db-3.json"
check "run 3: the database holds turns 1 to 8 whole (the files were turn 6's)" "$(python3 -c 'import json,sys; sys.exit(0 if json.loads(sys.argv[1]).get("ok") else 1)' "$dbv" 2>/dev/null; echo $?)"
t=$(shipped_turn); check "run 3: the Seal of turn 8 is shipped (newest shipped turn: $t)" "$([ "$t" = 8 ]; echo $?)"
kept=$(find "$WORK/state" -maxdepth 1 -name "$ID.superseded-*" -type d | wc -l)
check "run 3: the state directory the Vessel had is kept beside the new one ($kept found)" "$([ "$kept" = 1 ]; echo $?)"
grep -E 'BEHIND ITS LOG|rebuilt here: ' "$OUT/run-3.err" | sed 's/^/    /' || true

echo "== run 4: a start with nothing behind; one more turn"
rc=$(warden 4 1)
check "run 4: the Warden exits 0 (it said $rc)" "$([ "$rc" = 0 ]; echo $?)"
check "run 4: the Warden does not say the Vessel is behind" "$(! grep -q 'BEHIND ITS LOG' "$OUT/run-4.err"; echo $?)"
r=$(resumed); check "run 4: the agent was told turn 8 (it was told $r)" "$([ "$r" = 8 ]; echo $?)"
kept=$(find "$WORK/state" -maxdepth 1 -name "$ID.superseded-*" -type d | wc -l)
check "run 4: nothing more was kept aside ($kept found)" "$([ "$kept" = 1 ]; echo $?)"

if [ "$FAILS" != 0 ]; then
    echo "the Warden's log of run 3:"; tail -15 "$OUT/run-3.err" | sed 's/^/    /'
fi
echo "results in $OUT"
if [ "$FAILS" = 0 ]; then
    echo "REBUILD HERE PASS: $CHECKS checks"
else
    echo "REBUILD HERE FAIL: $FAILS of $CHECKS checks failed"
    exit 1
fi
