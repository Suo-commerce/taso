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
# Two modes:
#
#   one machine  (B_HOST unset) both nodes here, a local store directory,
#                taso-coordd started by the script.  Proves the function.
#   two nodes    (B_HOST=root@<taso-b private ip>) node A is this machine,
#                node B is reached over ssh; both use the hub's coordinator
#                (/run/taso/coord.sock, set up by gate-cloud/node-setup.sh)
#                and Garage (/root/taso-s3.env on both).  This is the gate.
#                B gets this machine's binaries and rootfs (same OS), so
#                both run exactly the same build.  B's log streams back
#                over ssh, so the rebirth time is measured on one clock.
#
# Usage (root; needs runc, ZFS, cargo, python3):
#   TASO_ZFS_DATASET=tasotest/vessel scripts/gate-p2.sh                # one machine
#   TASO_ZFS_DATASET=taso/vessel B_HOST=root@10.0.0.3 scripts/gate-p2.sh   # gate
#
# Environment: N (20)  RUN_S (3)  SLEEP_MS (100)  LANDLOCK (1)  B_HOST
#              OUT (/root/taso-gate-p2-<time>)  KEEP (0)

set -euo pipefail

: "${TASO_ZFS_DATASET:?set TASO_ZFS_DATASET to a dataset the gate may use}"
N=${N:-20}
RUN_S=${RUN_S:-3}
SLEEP_MS=${SLEEP_MS:-100}
LANDLOCK=${LANDLOCK:-1}
KEEP=${KEEP:-0}
B_HOST=${B_HOST:-}
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

# Run a command string on node B: over ssh (one shared connection), or here.
SSH=(ssh -o BatchMode=yes -o ControlMaster=auto -o "ControlPath=/tmp/taso-p2-ssh-%C" -o ControlPersist=900)
on_b() {
    if [ -n "$B_HOST" ]; then "${SSH[@]}" "$B_HOST" "$1"; else bash -c "$1"; fi
}
if [ -n "$B_HOST" ]; then
    on_b "true" || { echo "cannot ssh to $B_HOST (needs a key from this node)" >&2; exit 2; }
    on_b "zfs list $TASO_ZFS_DATASET >/dev/null && command -v runc >/dev/null && test -S /run/taso/coord.sock && test -f /root/taso-s3.env" \
        || { echo "$B_HOST is not set up (run gate-cloud/node-setup.sh vessel there)" >&2; exit 2; }
    [ -S /run/taso/coord.sock ] && [ -f /root/taso-s3.env ] || { echo "this node is not set up" >&2; exit 2; }
    on_b "mkdir -p $WORK && chmod 755 $WORK"
fi
zfs create "$BASE"
zfs create "$BASE/a"
on_b "zfs create -p $BASE/b"

COORD_PID=
cleanup() {
    [ -n "$COORD_PID" ] && kill "$COORD_PID" 2>/dev/null || true
    local clean_runc='for d in '"$WORK"'/a/run/runc '"$WORK"'/b/run/runc; do
        [ -d "$d" ] && for c in $(runc --root "$d" list -q 2>/dev/null); do runc --root "$d" delete --force "$c" 2>/dev/null || true; done
    done'
    bash -c "$clean_runc"
    [ -n "$B_HOST" ] && on_b "$clean_runc" || true
    if [ "$KEEP" = 1 ]; then
        echo "kept: dataset $BASE, work dir $WORK (on both nodes)"
    else
        zfs destroy -R "$BASE" 2>/dev/null || true
        rm -rf "$WORK"
        if [ -n "$B_HOST" ]; then on_b "zfs destroy -R $BASE 2>/dev/null; rm -rf $WORK" || true; fi
    fi
    [ -n "$B_HOST" ] && "${SSH[@]}" -O exit "$B_HOST" 2>/dev/null || true
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
mkdir -p "$WORK/bin"
cp "$BIN/taso-wardend" "$WORK/bin/"
if [ -n "$B_HOST" ]; then
    echo "== copying binaries and rootfs to $B_HOST"
    tar -C "$WORK" -cf - bin rootfs | on_b "tar -C $WORK -xf -"
fi

# ── coordinator and store ─────────────────────────────────────────────
if [ -n "$B_HOST" ]; then
    SOCK=/run/taso/coord.sock
    # shellcheck disable=SC1091
    set -a; . /root/taso-s3.env; set +a
    secret_cmd="umask 077; . /root/taso-s3.env; printf %s \"\$TASO_S3_SECRET\" > $WORK/s3.secret"
    bash -c "$secret_cmd"; on_b "$secret_cmd"
    STORE_JSON=$(python3 -c "import json; print(json.dumps({'s3': {'endpoint': '$TASO_S3_ENDPOINT', 'bucket': '$TASO_S3_BUCKET', 'access_key_id': '$TASO_S3_KEY_ID', 'secret_key_file': '$WORK/s3.secret'}}))")
    PREFIX="gate-p2-$$"
    MODE="two nodes, A here, B $B_HOST, coordinator and Garage on the hub"
else
    SOCK=$WORK/coord.sock
    "$BIN/taso-coordd" "$WORK/coord.redb" "$SOCK" 2>"$OUT/coordd.err" &
    COORD_PID=$!
    for _ in $(seq 100); do [ -S "$SOCK" ] && break; sleep 0.05; done
    [ -S "$SOCK" ] || { echo "taso-coordd did not start" >&2; exit 1; }
    STORE_JSON="\"$WORK/store\""
    PREFIX="vessels"
    MODE="one machine"
fi
echo "== $MODE"

config() {   # $1 node, $2 warden, $3 takeover, $4 subject, $5 turns, $6 out file
    python3 - "$@" <<PY
import json, sys
node, warden, takeover, subject, turns, out = sys.argv[1:]
json.dump({
    "warden": int(warden),
    "coordinator": {"remote": "$SOCK"},
    "root": "$BASE/" + node,
    "state_dir": "$WORK/" + node + "/state",
    "store": json.loads('$STORE_JSON'),
    "prefix": "$PREFIX",
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
    [ -n "$B_HOST" ] && on_b "cat > $WORK/b-$k.json" < "$WORK/b-$k.json"

    "$WORK/bin/taso-wardend" "$WORK/a-$k.json" >"$OUT/a-$k.out" 2>"$OUT/a-$k.err" &
    A=$!
    sleep "$RUN_S"
    kill -STOP "$A"
    t0=$(date +%s.%N)

    # B's stdout and stderr stream here (over ssh in two-node mode).
    on_b "exec $WORK/bin/taso-wardend $WORK/b-$k.json" >"$OUT/b-$k.out" 2>"$OUT/b-$k.err" &
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
    seals='zfs list -H -t snapshot -o name -d 1 DS | sed "s/.*@//" | grep "^taso-seal-" | sort'
    last=$(comm -12 <(bash -c "${seals/DS/$dsa}") <(on_b "${seals/DS/$dsb}") | tail -1)
    same=0
    if [ -n "$last" ]; then
        ga=$(zfs get -H -p -o value guid "$dsa@$last"); gb=$(on_b "zfs get -H -p -o value guid $dsb@$last")
        ha=$(snap_hash "$dsa@$last"); hb=$(on_b "$(declare -f snap_hash); snap_hash $dsb@$last")
        [ "$ga" = "$gb" ] && [ "$ha" = "$hb" ] && same=1
    fi
    resumed=$(on_b "cat \$(zfs get -H -o value mountpoint $dsb)/sim-stats.json" 2>/dev/null \
        | python3 -c "import json,sys; print(json.load(sys.stdin)['resumed_after'])" 2>/dev/null || echo none)
    how=$(grep -o 'reborn at epoch.*' "$OUT/b-$k.err" | tail -1 || true)
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$k" "$secs" "$refused" "$same" "${last:-none}" "$resumed" | tee -a "$OUT/rounds.tsv"
    echo "  $how"
    if [ "$resumed" = none ] || [ "$resumed" = None ]; then
        echo "  B did not resume; its log:"; sed 's/^/    /' "$OUT/b-$k.err" | tail -8; sed 's/^/    /' "$OUT/b-$k.out"
    fi
    # Leave the next round a clean slate on both nodes.
    zfs destroy -R "$dsa" 2>/dev/null || true
    on_b "zfs destroy -R $dsb 2>/dev/null" || true
done

python3 - "$OUT/rounds.tsv" "$N" "$MODE" <<'PY' | tee "$OUT/summary.txt"
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
print(f"P2 gate ({sys.argv[3]}), {n} rounds")
print(f"1. reborn: {reborn}/{n}, p50 {q(secs, .5):.2f} s, p95 {q(secs, .95):.2f} s (< 30) -> {'PASS' if reborn == n and q(secs, .95) < 30 else 'FAIL'}")
print(f"2. last common Seal identical (guid and bytes): {same}/{n} -> {'PASS' if same == n else 'FAIL'}")
print(f"3. old Warden refused: {refused}/{n} -> {'PASS' if refused == n else 'FAIL'}")
print(f"4. agent on B resumed after a sealed turn: {resumed}/{n} -> {'PASS' if resumed == n else 'FAIL'}")
PY
echo "results in $OUT"
