#!/usr/bin/env bash
# P1 exit gate (v1.0 §1): Phase 1 runtime, runc + ZFS, at p64.
#
#   1. 0 SIGBUS over $RUNS runs
#   2. p95 write latency <= 1.5 x bare (same disk, same concurrency, no Warden)
#   3. Seal p95 < 50 ms at p64
#
# The gate names Hermes's state.db.  Until the Hermes image exists the agent
# is taso-sim: SQLite in WAL mode on the Vessel's dataset, $TXNS transactions
# of $ROWS rows per turn, a transcript entry and a quiescent TurnEnd per turn
# (the Warden seals and publishes there).  The result says which agent ran.
#
# What it does, for each run:
#   bare    $P taso-sim --bare at once, each on its own ZFS dataset, as root
#           on the host: the same writes with no Warden, no container.
#   warden  taso-wardend with $P Vessels (fresh subjects each run), each
#           running taso-sim under runc (+ the Landlock shim if LANDLOCK=1);
#           every Seal is published (a local store directory, or Garage
#           with HUB=1).
# Then it pools every commit latency (bare and warden separately) and every
# seal.total sample across runs, and prints the three gate lines.
#
# A SIGBUS kills the agent; the daemon reports that Vessel's agent as
# failed.  Every failed agent is counted and its stderr kept, so a failure
# for another reason is visible, not hidden in the SIGBUS count.
#
# Usage (root, on the gate machine; needs runc, ZFS, cargo):
#   TASO_ZFS_DATASET=tank/taso scripts/gate-p1.sh
#
# Environment:
#   RUNS (10)  P (64)  TURNS (20)  TXNS (4)  ROWS (8)  ROW_BYTES (512)
#   SYNC (normal)       SQLite synchronous= for both bare and warden
#   LANDLOCK (1)        run the agent through taso-landlock
#   BATCHED (1)         batched Seal snapshots
#   HUB (0)             1: the hub's coordinator (/run/taso/coord.sock) and
#                       Garage (/root/taso-s3.env), as on the gate machines
#                       (gate-cloud/node-setup.sh); 0: an in-process
#                       coordinator and a local store directory
#   OUT (/root/taso-gate-p1-<time>)   results directory (kept)
#   KEEP (0)            keep the datasets and work dir for inspection

set -euo pipefail

: "${TASO_ZFS_DATASET:?set TASO_ZFS_DATASET to a dataset the gate may use}"
RUNS=${RUNS:-10}
P=${P:-64}
TURNS=${TURNS:-20}
TXNS=${TXNS:-4}
ROWS=${ROWS:-8}
ROW_BYTES=${ROW_BYTES:-512}
SYNC=${SYNC:-normal}
LANDLOCK=${LANDLOCK:-1}
BATCHED=${BATCHED:-1}
HUB=${HUB:-0}
KEEP=${KEEP:-0}
OUT=${OUT:-/root/taso-gate-p1-$(date +%Y%m%d-%H%M%S)}
# Subjects are new on every run: with the hub's coordinator, Vessels of an
# earlier run are still registered (and held by whichever Warden ended them).
RUN=$(date +%Y%m%d%H%M%S)-$$
# A Vessel that ran clean, as taso-wardend reports it (bin/taso-wardend.rs).
export VESSEL_OK=' 0 publish failures, [0-9]+ segments pruned, 0 prune failures, agent ok$'

[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 2; }
for t in zfs runc ldd python3 cargo; do
    command -v "$t" >/dev/null || { echo "$t is missing" >&2; exit 2; }
done

cd "$(dirname "$0")/.."
echo "== building (release)"
cargo build --release -q -p taso-warden -p taso-sim -p taso-landlock
BIN=$PWD/target/release

mkdir -p "$OUT"
WORK=$(mktemp -d /var/tmp/taso-p1.XXXXXX)
chmod 755 "$WORK"
BASE="$TASO_ZFS_DATASET/gate-p1-$$"
zfs create "$BASE"
cleanup() {
    if [ "$KEEP" = 1 ]; then
        echo "kept: dataset $BASE, work dir $WORK"
    else
        zfs destroy -R "$BASE" 2>/dev/null || true
        rm -rf "$WORK"
    fi
}
trap cleanup EXIT

SIM_ARGS=(--turns "$TURNS" --txns "$TXNS" --rows "$ROWS" --row-bytes "$ROW_BYTES" --synchronous "$SYNC")

if [ "$HUB" = 1 ]; then
    [ -S /run/taso/coord.sock ] && [ -f /root/taso-s3.env ] || { echo "HUB=1 needs /run/taso/coord.sock and /root/taso-s3.env" >&2; exit 2; }
    # shellcheck disable=SC1091
    set -a; . /root/taso-s3.env; set +a
    (umask 077; printf %s "$TASO_S3_SECRET" > "$WORK/s3.secret")
    COORD_JSON='{"remote": "/run/taso/coord.sock"}'
    STORE_JSON=$(python3 -c "import json; print(json.dumps({'s3': {'endpoint': '$TASO_S3_ENDPOINT', 'bucket': '$TASO_S3_BUCKET', 'access_key_id': '$TASO_S3_KEY_ID', 'secret_key_file': '$WORK/s3.secret'}}))")
    PREFIX="gate-p1-$$"
else
    COORD_JSON="{\"local\": \"$WORK/coord.redb\"}"
    STORE_JSON="\"$WORK/store\""
    PREFIX="vessels"
fi

# ── rootfs: taso-sim, taso-landlock and their libraries ───────────────
ROOTFS=$WORK/rootfs
copy_with_libs() {   # $1 = binary on the host, $2 = path in the rootfs
    install -D -m 755 "$1" "$ROOTFS$2"
    ldd "$1" | grep -o '/[^ ]*' | while read -r lib; do
        install -D -m 755 "$lib" "$ROOTFS$lib"
    done
}
copy_with_libs "$BIN/taso-sim" /usr/bin/taso-sim
copy_with_libs "$BIN/taso-landlock" /usr/lib/taso/landlock
mkdir -p "$ROOTFS"/{proc,dev,sys,tmp,work,run/taso}
: > "$ROOTFS/run/taso/field.sock"

mount_of() { zfs get -H -o value mountpoint "$1"; }

# ── bare ──────────────────────────────────────────────────────────────
run_bare() {   # $1 = run number
    local r=$1 ds pids=()
    ds="$BASE/bare-$r"
    zfs create "$ds"
    local m; m=$(mount_of "$ds")
    for i in $(seq 1 "$P"); do
        "$BIN/taso-sim" --bare "${SIM_ARGS[@]}" --db "$m/v$i.db" \
            --stats "$m/v$i.json" --samples "$m/v$i.samples" >/dev/null 2>"$OUT/bare-$r-v$i.err" &
        pids+=($!)
    done
    local failed=0
    for p in "${pids[@]}"; do wait "$p" || failed=$((failed + 1)); done
    cat "$m"/v*.samples >> "$OUT/bare.samples"
    echo "bare run $r: $failed failed"
    zfs destroy -r "$ds"
}

# ── warden ────────────────────────────────────────────────────────────
run_warden() {   # $1 = run number
    local r=$1 root="$BASE/w-$r" cfg="$WORK/w-$r.json"
    zfs create "$root"
    python3 - "$cfg" "$r" <<PY
import json, sys
cfg, r = sys.argv[1], sys.argv[2]
args = ["/usr/bin/taso-sim"] + "${SIM_ARGS[*]}".split() + ["--samples", "/work/samples", "--turn-samples", "/work/turn-samples", "--stats", "/work/sim-stats.json"]
json.dump({
    "warden": 1,
    "coordinator": json.loads('$COORD_JSON'),
    "root": "$root",
    "state_dir": "$WORK/w-$r/state",
    "store": json.loads('$STORE_JSON'),
    "prefix": "$PREFIX",
    "run_dir": "$WORK/w-$r/run",
    "batched_snapshots": "$BATCHED" == "1",
    "runtime": {
        "rootfs": "$ROOTFS",
        "host_uid_base": 200000,
        "landlock_shim": "/usr/lib/taso/landlock" if "$LANDLOCK" == "1" else None,
        "args": args,
        "memory_bytes": 268435456,
        "pids": 64,
    },
    "vessels": [{"namespace": "70" * 16, "subject": f"gate-p1-$RUN-r{r}-v{i}", "uid_slot": i} for i in range($P)],
}, open(cfg, "w"), indent=1)
PY
    local rc=0
    TASO_TIMING_RAW="$OUT/warden-$r.spans" "$BIN/taso-wardend" "$cfg" \
        >"$OUT/warden-$r.out" 2>"$OUT/warden-$r.err" || rc=$?
    for ds in $(zfs list -H -o name -d 1 "$root" | tail -n +2); do
        local m; m=$(mount_of "$ds")
        [ -f "$m/samples" ] && cat "$m/samples" >> "$OUT/warden.samples"
        [ -f "$m/turn-samples" ] && cat "$m/turn-samples" >> "$OUT/turn.samples"
        [ -f "$m/sim-stats.json" ] && cp "$m/sim-stats.json" "$OUT/warden-$r-${ds##*/}.json"
    done
    # One line per Vessel (taso-wardend's report); ok means every Seal
    # published, no prune failed, and the agent exited successfully.
    local ok; ok=$(grep -cE "$VESSEL_OK" "$OUT/warden-$r.out" || true)
    echo "warden run $r: exit $rc, $ok of $P Vessels ok"
    grep -vE "$VESSEL_OK" "$OUT/warden-$r.out" | grep -E "^gate-p1-" | head -5 || true
}

: > "$OUT/bare.samples"
: > "$OUT/warden.samples"
: > "$OUT/turn.samples"
for r in $(seq 1 "$RUNS"); do
    run_bare "$r"
    run_warden "$r"
done

# ── the gate ──────────────────────────────────────────────────────────
python3 - "$OUT" "$RUNS" "$P" "$TURNS" "$TXNS" "$ROWS" "$ROW_BYTES" "$SYNC" "$LANDLOCK" "$BATCHED" <<'PY' | tee "$OUT/summary.txt"
import glob, json, os, re, sys
out, runs, p, turns, txns, rows, row_bytes, sync, landlock, batched = sys.argv[1:]

def q(v, x):
    v = sorted(v)
    return v[min(len(v) - 1, max(0, int(-(-len(v) * x // 1)) - 1))] if v else float("nan")

def load(name):
    return [int(l) / 1000 for l in open(os.path.join(out, name)) if l.strip()]

bare, warden, turn = load("bare.samples"), load("warden.samples"), load("turn.samples")
seals, publish = [], []
for f in glob.glob(os.path.join(out, "warden-*.spans")):
    for l in open(f):
        name, us = l.split()
        if name == "seal.total":
            seals.append(int(us) / 1000)
        elif name == "publish.total":
            publish.append(int(us) / 1000)
failed = sigbus = 0
for f in glob.glob(os.path.join(out, "warden-*.out")):
    lines = [l for l in open(f) if l.startswith("gate-p1-")]
    failed += int(p) - sum(1 for l in lines if re.search(os.environ["VESSEL_OK"], l.rstrip()))
for f in glob.glob(os.path.join(out, "warden-*.err")) + glob.glob(os.path.join(out, "bare-*.err")):
    text = open(f, errors="replace").read()
    sigbus += len(re.findall(r"SIGBUS|signal: 7|Bus error", text))
expected = int(runs) * int(p) * int(turns) * int(txns)

print(f"P1 gate, agent taso-sim (stand-in for Hermes state.db): {runs} runs x p{p}, {turns} turns of "
      f"{txns} txns x {rows} rows x {row_bytes} B, synchronous={sync}, landlock={landlock}, batched={batched}")
print(f"commits: bare {len(bare)}, warden {len(warden)} (expected {expected} each)")
print(f"{'':10} {'p50 ms':>9} {'p95 ms':>9} {'p99 ms':>9} {'max ms':>9}")
for name, v in [("bare", bare), ("warden", warden), ("seal", seals), ("publish", publish), ("turn pause", turn)]:
    print(f"{name:10} {q(v, .5):9.3f} {q(v, .95):9.3f} {q(v, .99):9.3f} {q(v, 1):9.3f}")
print("(seal: snapshot + record; publish: ship + anchor; turn pause: the agent's TurnEnd round trip, both and the socket)")
ratio = q(warden, .95) / q(bare, .95) if bare and warden else float("nan")
ok1 = sigbus == 0 and failed == 0
ok2 = ratio <= 1.5 and len(warden) == expected
ok3 = q(seals, .95) < 50
print(f"1. SIGBUS: {sigbus} (failed agents: {failed}) -> {'PASS' if ok1 else 'FAIL'}")
print(f"2. write p95 warden/bare: {ratio:.2f} (<= 1.5) -> {'PASS' if ok2 else 'FAIL'}")
print(f"3. Seal p95: {q(seals, .95):.1f} ms (< 50) -> {'PASS' if ok3 else 'FAIL'}")
PY
if [ "$HUB" = 1 ]; then where="hub coordinator over the network, Garage store"; else where="in-process coordinator, local store directory"; fi
echo "coordinator and store: $where" | tee -a "$OUT/summary.txt"
echo "results in $OUT"
