#!/usr/bin/env bash
# P2 exit gate (v1.0 §1), rehearsal on one machine: two "nodes" (two
# Warden daemons with their own root dataset and state) share one pool, one
# store directory and one coordinator (taso-coordd, which outlives them).
#
#   1. reborn on node B < 30 s p95
#   2. dataset byte-identical to the last (anchored, named) Seal
#   3. old Warden refused 20/20
#   4. ledger tail intact: the agent on B resumes after the last sealed turn
#
# Each of $N rounds uses a fresh Vessel:
#   a. node A (Warden 1) runs taso-sim, a turn every $SLEEP_MS ms, each
#      sealed and published;
#   b. after $RUN_S s, A's Warden is frozen (SIGSTOP): from the outside it
#      is dead, but it still believes it holds the Vessel;
#   c. node B (Warden 2, "takeover": true) starts: fences A (new epoch),
#      rebuilds the Vessel from the store up to the shipped anchor, and runs
#      the agent, which must resume right after the last sealed turn;
#      timed from the freeze to B's "reborn" log line;
#   d. A is thawed (SIGCONT): its next append must be refused (Fenced),
#      which ends A's agent; then A is SIGKILLed;
#   e. the last Seal both nodes have is compared: same snapshot guid, and
#      the same bytes (a hash over every file in the snapshot).
#
# On one machine this proves the function, not the timing: the gate number
# needs two nodes on local NVMe, with the store in Garage and the
# coordinator reached over the network.
#
# Usage (root; needs runc, ZFS, cargo, python3):
#   TASO_ZFS_DATASET=tasotest/vessel scripts/gate-p2.sh
#
# Environment: N (20)  RUN_S (3)  SLEEP_MS (100)  LANDLOCK (1)
#              OUT (/root/taso-gate-p2-<time>)  KEEP (0)

set -euo pipefail

: "${TASO_ZFS_DATASET:?set TASO_ZFS_DATASET to a dataset the gate may use}"
N=${N:-20}
RUN_S=${RUN_S:-3}
SLEEP_MS=${SLEEP_MS:-100}
LANDLOCK=${LANDLOCK:-1}
KEEP=${KEEP:-0}
OUT=${OUT:-/root/taso-gate-p2-$(date +%Y%m%d-%H%M%S)}

[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 2; }
for t in zfs runc ldd python3 cargo; do
    command -v "$t" >/dev/null || { echo "$t is missing" >&2; exit 2; }
done

cd "$(dirname "$0")/.."
echo "== building (release)"
cargo build --release -q -p taso-warden -p taso-sim -p taso-landlock
BIN=$PWD/target/release

mkdir -p "$OUT"
WORK=$(mktemp -d /var/tmp/taso-p2.XXXXXX)
chmod 755 "$WORK"
BASE="$TASO_ZFS_DATASET/gate-p2-$$"
zfs create "$BASE"
zfs create "$BASE/a"
zfs create "$BASE/b"
COORD_PID=
cleanup() {
    [ -n "$COORD_PID" ] && kill "$COORD_PID" 2>/dev/null || true
    for d in "$WORK"/a/run/runc "$WORK"/b/run/runc; do
        [ -d "$d" ] && for c in $(runc --root "$d" list -q 2>/dev/null); do
            runc --root "$d" delete --force "$c" 2>/dev/null || true
        done
    done
    if [ "$KEEP" = 1 ]; then
        echo "kept: dataset $BASE, work dir $WORK"
    else
        zfs destroy -R "$BASE" 2>/dev/null || true
        rm -rf "$WORK"
    fi
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
[ -S "$SOCK" ] || { echo "taso-coordd did not start" >&2; exit 1; }

config() {   # $1 node, $2 warden, $3 takeover, $4 subject, $5 turns, $6 out file
    python3 - "$@" <<PY
import json, sys
node, warden, takeover, subject, turns, out = sys.argv[1:]
json.dump({
    "warden": int(warden),
    "coordinator": {"remote": "$SOCK"},
    "root": "$BASE/" + node,
    "state_dir": "$WORK/" + node + "/state",
    "store": "$WORK/store",
    "run_dir": "$WORK/" + node + "/run",
    "runtime": {
        "rootfs": "$ROOTFS",
        "host_uid_base": 200000,
        "landlock_shim": "/usr/lib/taso/landlock" if "$LANDLOCK" == "1" else None,
        "args": ["/usr/bin/taso-sim", "--turns", turns, "--txns", "2", "--rows", "4",
                 "--turn-sleep-ms", "$SLEEP_MS", "--stats", "/work/sim-stats.json"],
        "memory_bytes": 268435456,
        "pids": 64,
    },
    "vessels": [{"namespace": "7a" * 16, "subject": subject, "takeover": takeover == "true", "uid_slot": 0}],
}, open(out, "w"), indent=1)
PY
}

vessel_ds() {   # $1 daemon stderr -> the Vessel's dataset, as the daemon logged it
    grep -o ': dataset [^ ]*$' "$1" | head -1 | sed 's/: dataset //'
}

snap_hash() {   # $1 snapshot name -> hash of every file's path and bytes
    local ds=${1%@*} snap=${1#*@} m
    m=$(zfs get -H -o value mountpoint "$ds")
    (cd "$m/.zfs/snapshot/$snap" && find . -type f -print0 | sort -z | xargs -0 sha256sum | sha256sum | cut -d' ' -f1)
}

: > "$OUT/rounds.tsv"
for k in $(seq 1 "$N"); do
    subject="gate-p2-$k"
    config a 1 false "$subject" 100000 "$WORK/a-$k.json"
    config b 2 true "$subject" 5 "$WORK/b-$k.json"

    "$BIN/taso-wardend" "$WORK/a-$k.json" >"$OUT/a-$k.out" 2>"$OUT/a-$k.err" &
    A=$!
    sleep "$RUN_S"
    kill -STOP "$A"
    t0=$(date +%s.%N)

    "$BIN/taso-wardend" "$WORK/b-$k.json" >"$OUT/b-$k.out" 2>"$OUT/b-$k.err" &
    B=$!
    reborn=
    for _ in $(seq 1200); do
        if grep -q "reborn at epoch" "$OUT/b-$k.err" 2>/dev/null; then reborn=$(date +%s.%N); break; fi
        kill -0 "$B" 2>/dev/null || break
        sleep 0.025
    done
    secs=nan
    [ -n "$reborn" ] && secs=$(python3 -c "print('%.3f' % ($reborn - $t0))")

    # The old Warden wakes up believing it still holds the Vessel.
    kill -CONT "$A"
    for _ in $(seq 400); do kill -0 "$A" 2>/dev/null || break; sleep 0.025; done
    kill -KILL "$A" 2>/dev/null || true
    wait "$A" 2>/dev/null || true
    wait "$B" || true
    refused=0
    grep -q "Fenced" "$OUT/a-$k.err" && refused=1

    # The last Seal both nodes have: same guid, same bytes.
    dsa=$(vessel_ds "$OUT/a-$k.err"); dsb=$(vessel_ds "$OUT/b-$k.err")
    last=$(comm -12 <(zfs list -H -t snapshot -o name -d 1 "$dsa" | sed 's/.*@//' | grep '^taso-seal-' | sort) \
                    <(zfs list -H -t snapshot -o name -d 1 "$dsb" | sed 's/.*@//' | grep '^taso-seal-' | sort) | tail -1)
    same=0
    if [ -n "$last" ]; then
        ga=$(zfs get -H -p -o value guid "$dsa@$last"); gb=$(zfs get -H -p -o value guid "$dsb@$last")
        ha=$(snap_hash "$dsa@$last"); hb=$(snap_hash "$dsb@$last")
        [ "$ga" = "$gb" ] && [ "$ha" = "$hb" ] && same=1
    fi
    resumed=$(python3 -c "import json;s=json.load(open('$(zfs get -H -o value mountpoint "$dsb")/sim-stats.json'));print(s['resumed_after'])" 2>/dev/null || echo none)
    how=$(grep -o 'reborn at epoch.*' "$OUT/b-$k.err" | tail -1 || true)
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$k" "$secs" "$refused" "$same" "${last:-none}" "$resumed" | tee -a "$OUT/rounds.tsv"
    echo "  $how"
    if [ "$resumed" = none ] || [ "$resumed" = None ]; then
        echo "  B did not resume; its log:"; sed 's/^/    /' "$OUT/b-$k.err" | tail -8; sed 's/^/    /' "$OUT/b-$k.out"
    fi
    # Leave the next round a clean slate on both nodes.
    zfs destroy -R "$dsa" 2>/dev/null || true
    zfs destroy -R "$dsb" 2>/dev/null || true
done

python3 - "$OUT/rounds.tsv" "$N" <<'PY' | tee "$OUT/summary.txt"
import math, sys
rows = [l.rstrip("\n").split("\t") for l in open(sys.argv[1]) if l.strip()]
n = int(sys.argv[2])
secs = sorted(float(r[1]) for r in rows if r[1] != "nan")
def q(v, x):
    return v[min(len(v) - 1, max(0, math.ceil(len(v) * x) - 1))] if v else float("nan")
reborn = len(secs)
refused = sum(int(r[2]) for r in rows)
same = sum(int(r[3]) for r in rows)
resumed = sum(1 for r in rows if r[5] not in ("none", "None"))
print(f"P2 gate rehearsal (one machine), {n} rounds")
print(f"1. reborn: {reborn}/{n}, p50 {q(secs, .5):.2f} s, p95 {q(secs, .95):.2f} s (< 30) -> {'PASS' if reborn == n and q(secs, .95) < 30 else 'FAIL'}")
print(f"2. last common Seal identical (guid and bytes): {same}/{n} -> {'PASS' if same == n else 'FAIL'}")
print(f"3. old Warden refused: {refused}/{n} -> {'PASS' if refused == n else 'FAIL'}")
print(f"4. agent on B resumed after a sealed turn: {resumed}/{n} -> {'PASS' if resumed == n else 'FAIL'}")
PY
echo "results in $OUT"
