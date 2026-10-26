#!/usr/bin/env bash
# bench/p5/bench.sh: the P5 harness, first piece (Taso_plan_p5 §3 B1, H0's
# first question: work per durable byte).  The same workload through
# taso-wardend on either storage, one machine, one table.
#
#   sudo bench/p5/bench.sh zfs [P] [TURNS] [RUNS]     (from the repository root)
#   sudo bench/p5/bench.sh blk [P] [TURNS] [RUNS]
#
# Defaults P=1, TURNS=10, RUNS=1: the smallest run that proves the harness
# measures what it says.  The §3 rows are the same script at P=8 and P=64.
#
# The workload is gate-p1's (the Phase 1 gate): P Vessels, each running
# taso-sim under runc — SQLite in WAL mode on the Vessel's dataset, TXNS
# transactions of ROWS rows of ROW_BYTES per turn, a quiescent TurnEnd per
# turn at which the Warden seals and publishes.  What is measured, per
# Vessel and pooled:
#   commit       taso-sim's SQLite commit latency inside the Vessel (the
#                agent's write, acknowledged by SQLite: durable to the
#                extent synchronous=$SYNC makes it)
#   turn pause   the agent's TurnEnd round trip: the time the agent waits
#                for the Warden to seal — the durable acknowledgement as
#                the agent sees it (H0's "acknowledgement latency")
#   seal, publish, and every span the Warden recorded (TASO_TIMING_RAW)
#   durable turns/s and commits/s over the Warden's wall time, CPU time
#                of the Warden process (user+sys) per turn
# The result is one table, printed and written to $OUT/table.md with the
# host, the commit, the storage and the durability contract's reference,
# plus the raw samples beside it.  Nothing is compared or judged here: the
# storage rule (§3) is applied to the tables by hand, in the plan.
#
# Storage:
#   zfs  Vessel roots are new datasets under $TASO_ZFS_DATASET (default
#        taso/vessel, A1's; tasotest/vessel on taso-test), destroyed after.
#   blk  a fresh taso-blkd on its own log under $DIR (which A1 puts on the
#        measured drive through /var/lib/taso-blk), mounts under /mnt/p5-bench,
#        stopped after.  After the Warden exits its mounts are gone, so each
#        Vessel's samples are read by attaching its branch read-only through
#        the daemon (find, attach, mount -o ro, umount, detach).
# Both: an in-process coordinator (redb) and a local pack store under $DIR,
# as gate-p1 with HUB=0 — the coordinator and the store are not what is
# measured here.
#
# Environment (gate-p1's): TXNS (4) ROWS (8) ROW_BYTES (512) SYNC (normal)
# LANDLOCK (1) BATCHED (1) TASO_ZFS_DATASET; OUT (results directory,
# default /root/taso-p5-bench-<storage>-<time>, kept); KEEP=1 keeps the
# work directory and datasets.
#
# Touches, and nothing else: $DIR = /var/lib/taso-blk/p5-bench (removed at
# start, removed at the end unless KEEP), $OUT, the datasets or the log
# above, /run/taso-p5-bench-blk.sock, /mnt/p5-bench, runc containers under
# $DIR/run.  Needs root, cargo in PATH (run as root, not through sudo
# without -i), runc, python3, and zfs or ublk.

set -euo pipefail

STORAGE=${1:-}
P=${2:-1}
TURNS=${3:-10}
RUNS=${4:-1}
[[ "$STORAGE" == zfs || "$STORAGE" == blk ]] || { echo "usage: $0 zfs|blk [P] [TURNS] [RUNS]" >&2; exit 64; }
TXNS=${TXNS:-4}; ROWS=${ROWS:-8}; ROW_BYTES=${ROW_BYTES:-512}; SYNC=${SYNC:-normal}
LANDLOCK=${LANDLOCK:-1}; BATCHED=${BATCHED:-1}; KEEP=${KEEP:-0}
ZFS_PARENT=${TASO_ZFS_DATASET:-taso/vessel}
DIR=/var/lib/taso-blk/p5-bench
BLK_SOCK=/run/taso-p5-bench-blk.sock
MNT=/mnt/p5-bench
STAMP=$(date +%Y%m%d-%H%M%S)
OUT=${OUT:-/root/taso-p5-bench-$STORAGE-$STAMP}
RUN=$STAMP-$$
export VESSEL_OK=' 0 publish failures, [0-9]+ segments pruned, 0 prune failures, agent ok$'

die() { printf 'ABORT: %s\n' "$*" >&2; exit 2; }
say() { printf '== %s\n' "$*"; }
BLKD_PID=; ZFS_BASE=

mounts_under() {
    awk -v root="$MNT" '$5 == root || index($5, root "/") == 1 { print length($5), $5 }' /proc/self/mountinfo | sort -rn | cut -d' ' -f2-
}
blk() { # blk CMD... -> answer (the daemon's protocol, as blk-contract.sh)
    local answer
    answer=$(python3 -c '
import socket, sys
s = socket.socket(socket.AF_UNIX); s.settimeout(120); s.connect(sys.argv[1])
s.sendall((" ".join(sys.argv[2:]) + "\n").encode()); print(s.makefile().readline().strip())' "$BLK_SOCK" "$@") || die "taso-blkd did not answer: $*"
    case "$answer" in "ok") ;; "ok "*) printf '%s\n' "${answer#ok }" ;; *) die "taso-blkd: $* -> $answer" ;; esac
}
cleanup() {
    local rc=$?
    set +e
    while read -r m; do [[ -n "$m" ]] && { fsfreeze -u "$m" 2>/dev/null; umount "$m" || umount -l "$m"; }; done < <(mounts_under)
    if [[ -n "$BLKD_PID" ]] && kill -0 "$BLKD_PID" 2>/dev/null; then (blk quit) >/dev/null 2>&1 || kill "$BLKD_PID"; wait "$BLKD_PID" 2>/dev/null; fi
    if [[ "$KEEP" = 1 ]]; then
        echo "kept: $DIR${ZFS_BASE:+, dataset $ZFS_BASE}"
    else
        [[ -z "$ZFS_BASE" ]] || zfs destroy -R "$ZFS_BASE" 2>/dev/null
        rm -rf "$DIR"
    fi
    exit "$rc"
}
trap cleanup EXIT

# ---- preflight ----------------------------------------------------------------
[[ $EUID -eq 0 ]] || die "run as root"
[[ -f Cargo.toml && -d crates/taso-warden && -d bench/p5 ]] || die "run from the repository root"
for t in runc ldd python3 cargo; do command -v "$t" >/dev/null || die "$t is missing"; done
if [[ "$STORAGE" == zfs ]]; then
    command -v zfs >/dev/null || die "zfs is missing"
    zfs list -H -o name "$ZFS_PARENT" >/dev/null 2>&1 || die "no dataset $ZFS_PARENT (set TASO_ZFS_DATASET)"
else
    modprobe ublk_drv; [[ -c /dev/ublk-control ]] || die "/dev/ublk-control missing"
    [[ ! -S "$BLK_SOCK" ]] || die "$BLK_SOCK exists: another run's daemon? (pgrep -x taso-blkd)"
    mkdir -p "$MNT"; [[ -z "$(mounts_under)" ]] || die "something is already mounted under $MNT"
fi
[[ -d /var/lib/taso-blk ]] || mkdir -p /var/lib/taso-blk
[[ "$(findmnt -no FSTYPE -T /var/lib/taso-blk)" != tmpfs ]] || die "/var/lib/taso-blk is on tmpfs"
HOST_NOTE="/var/lib/taso-blk on $(findmnt -no SOURCE,FSTYPE -T /var/lib/taso-blk)"

say "building (release)"
cargo build --release -q -p taso-warden -p taso-sim -p taso-landlock
[[ "$STORAGE" == zfs ]] || cargo build --release -q -p taso-blk
BIN=$PWD/target/release
for b in taso-wardend taso-sim taso-landlock; do [[ -x "$BIN/$b" ]] || die "$BIN/$b was not built"; done
[[ "$STORAGE" == zfs || -x "$BIN/taso-blkd" ]] || die "$BIN/taso-blkd was not built"

rm -rf "$DIR"; mkdir -p "$DIR/store" "$DIR/state" "$DIR/run" "$OUT"; chmod 755 "$DIR"

# the rootfs: taso-sim, the Landlock shim and their libraries (gate-p1)
ROOTFS=$DIR/rootfs
copy_with_libs() {
    install -D -m 755 "$1" "$ROOTFS$2"
    ldd "$1" | grep -o '/[^ ]*' | while read -r lib; do install -D -m 755 "$lib" "$ROOTFS$lib"; done
}
copy_with_libs "$BIN/taso-sim" /usr/bin/taso-sim
copy_with_libs "$BIN/taso-landlock" /usr/lib/taso/landlock
mkdir -p "$ROOTFS"/{proc,dev,sys,tmp,work,run/taso}; : >"$ROOTFS/run/taso/field.sock"

# the storage
if [[ "$STORAGE" == zfs ]]; then
    ZFS_BASE="$ZFS_PARENT/p5-bench-$$"
    zfs create "$ZFS_BASE"
    STORAGE_JSON='"zfs"'
else
    "$BIN/taso-blkd" "$DIR/blk.log" "$BLK_SOCK" 2>>"$DIR/blkd.err" &
    BLKD_PID=$!
    for _ in $(seq 100); do [[ -S "$BLK_SOCK" ]] && break; sleep 0.1; done
    [[ -S "$BLK_SOCK" ]] || die "taso-blkd socket did not appear; see $DIR/blkd.err"
    mkdir -p "$DIR/spool"
    STORAGE_JSON=$(printf '{"blk": {"socket": "%s", "mounts": "%s", "spool": "%s"}}' "$BLK_SOCK" "$MNT" "$DIR/spool")
fi
SIM_ARGS="--turns $TURNS --txns $TXNS --rows $ROWS --row-bytes $ROW_BYTES --synchronous $SYNC"

# ---- one run: the Warden with P Vessels -------------------------------------------
run_warden() { # run_warden R
    local r=$1
    local root cfg="$DIR/w-$r.json" rc=0
    if [[ "$STORAGE" == zfs ]]; then root="$ZFS_BASE/w-$r"; zfs create "$root"; else root="p5bench/w$r"; fi
    python3 - "$cfg" "$r" "$root" <<PY
import json, sys
cfg, r, root = sys.argv[1:4]
args = ["/usr/bin/taso-sim"] + "$SIM_ARGS".split() + ["--samples", "/work/samples", "--turn-samples", "/work/turn-samples", "--stats", "/work/sim-stats.json"]
json.dump({
    "warden": 1,
    "coordinator": {"local": "$DIR/coord.redb"},
    "root": root,
    "storage": json.loads('$STORAGE_JSON'),
    "state_dir": "$DIR/state/w-%s" % r,
    "store": "$DIR/store",
    "prefix": "vessels",
    "run_dir": "$DIR/run/w-%s" % r,
    "batched_snapshots": "$BATCHED" == "1",
    "runtime": {
        "rootfs": "$ROOTFS",
        "host_uid_base": 200000,
        "landlock_shim": "/usr/lib/taso/landlock" if "$LANDLOCK" == "1" else None,
        "args": args,
        "memory_bytes": 268435456,
        "pids": 64,
    },
    "vessels": [{"namespace": "75" * 16, "subject": "p5-bench-$RUN-r%s-v%d" % (r, i), "uid_slot": i} for i in range($P)],
}, open(cfg, "w"), indent=1)
PY
    # The Warden, timed: wall time, and its CPU time and peak RSS from the
    # kernel's rusage of the child (no /usr/bin/time on a stock Ubuntu).
    TASO_TIMING_RAW="$OUT/warden-$r.spans" python3 - "$BIN/taso-wardend" "$cfg" "$OUT/warden-$r" <<'PY' || rc=$?
import resource, subprocess, sys, time
bin, cfg, out = sys.argv[1:4]
t0 = time.time()
rc = subprocess.run([bin, cfg], stdout=open(out + ".out", "w"), stderr=open(out + ".err", "w")).returncode
t1 = time.time()
ru = resource.getrusage(resource.RUSAGE_CHILDREN)
open(out + ".wall", "w").write("%f %f\n" % (t0, t1))
open(out + ".time", "w").write("%f %f %d\n" % (ru.ru_utime, ru.ru_stime, ru.ru_maxrss))
sys.exit(rc)
PY
    # the samples each Vessel wrote to its /work
    if [[ "$STORAGE" == zfs ]]; then
        for ds in $(zfs list -H -o name -d 1 "$root" | tail -n +2); do
            collect "$(zfs get -H -o value mountpoint "$ds")" "$r" "${ds##*/}"
        done
    else
        local ds branch dev at="$MNT/.p5-read"
        mkdir -p "$at"
        for ds in $(grep -o "\] p5-bench-$RUN-r$r-v[0-9]*: dataset [^ ]*\$" "$OUT/warden-$r.err" | sed 's/.*: dataset //' | sort -u); do
            branch=$(blk find "$ds"); dev=$(blk attach "$branch")
            for _ in $(seq 50); do [[ -b "$dev" ]] && break; sleep 0.1; done
            mount -o ro "$dev" "$at"
            collect "$at" "$r" "${ds##*/}"
            umount "$at"; blk detach "$branch" >/dev/null
        done
        rmdir "$at"
    fi
    local ok; ok=$(grep -cE "$VESSEL_OK" "$OUT/warden-$r.out" || true)
    echo "warden run $r: exit $rc, $ok of $P Vessels ok, $(awk '{printf "user %.2fs sys %.2fs rss %d KiB", $1, $2, $3}' "$OUT/warden-$r.time")"
    grep -vE "$VESSEL_OK" "$OUT/warden-$r.out" | grep -E "^p5-bench-" | head -5 || true
}
collect() { # collect MOUNT R NAME
    [[ -f "$1/samples" ]] && cat "$1/samples" >>"$OUT/commit.samples"
    [[ -f "$1/turn-samples" ]] && cat "$1/turn-samples" >>"$OUT/turn.samples"
    [[ -f "$1/sim-stats.json" ]] && cp "$1/sim-stats.json" "$OUT/sim-$2-$3.json"
    return 0
}

say "$STORAGE: $RUNS run(s) x P=$P, $TURNS turns of $TXNS txns x $ROWS rows x $ROW_BYTES B, synchronous=$SYNC, landlock=$LANDLOCK, batched=$BATCHED"
: >"$OUT/commit.samples"; : >"$OUT/turn.samples"
for r in $(seq 1 "$RUNS"); do run_warden "$r"; done

# ---- the table -----------------------------------------------------------------
python3 - "$OUT" "$STORAGE" "$RUNS" "$P" "$TURNS" "$TXNS" "$ROWS" "$ROW_BYTES" "$SYNC" "$LANDLOCK" "$BATCHED" \
    "$(hostname)" "$(uname -r)" "$(git rev-parse --short HEAD 2>/dev/null || echo ?)" "$HOST_NOTE" "${ZFS_BASE:-$DIR/blk.log}" <<'PY' | tee "$OUT/table.md"
import glob, os, re, sys
out, storage, runs, p, turns, txns, rows, row_bytes, sync, landlock, batched, host, kernel, commit, note, where = sys.argv[1:]
runs, p, turns, txns = int(runs), int(p), int(turns), int(txns)
def q(v, x):
    v = sorted(v)
    return v[min(len(v) - 1, max(0, int(-(-len(v) * x // 1)) - 1))] if v else float("nan")
def load(name): return [int(l) / 1000 for l in open(os.path.join(out, name)) if l.strip()]
commits, turn = load("commit.samples"), load("turn.samples")
spans = {}
for f in glob.glob(os.path.join(out, "warden-*.spans")):
    for l in open(f):
        name, us = l.split(); spans.setdefault(name, []).append(int(us) / 1000)
wall = sum(float(b) - float(a) for a, b in (open(f).read().split() for f in glob.glob(os.path.join(out, "warden-*.wall"))))
cpu = sum(float(open(f).read().split()[0]) + float(open(f).read().split()[1]) for f in glob.glob(os.path.join(out, "warden-*.time")))
rss = max((int(open(f).read().split()[2]) for f in glob.glob(os.path.join(out, "warden-*.time"))), default=0)
ok = sum(len(re.findall(os.environ["VESSEL_OK"], open(f).read(), re.M)) for f in glob.glob(os.path.join(out, "warden-*.out")))
expected_commits = runs * p * turns * txns
expected_turns = runs * p * turns
print(f"# P5 bench — {storage}, P={p}, {host}")
print()
print(f"- host {host}, kernel {kernel}, taso {commit}; {note}; data at {where}")
print(f"- durability contract: claude/Taso_finding_p5_a2_facts_2026-10-26.md §1 (this host's row)")
print(f"- workload: gate-p1's taso-sim, {runs} run(s) x P={p}, {turns} turns of {txns} txns x {rows} rows x {row_bytes} B, synchronous={sync}, landlock={landlock}, batched={batched}; in-process coordinator, local store")
print(f"- Vessels ok {ok} of {runs * p}; commits {len(commits)} of {expected_commits} expected; turns {len(turn)} of {expected_turns}")
print()
print(f"| what | n | p50 ms | p95 ms | p99 ms | max ms |")
print(f"| --- | ---: | ---: | ---: | ---: | ---: |")
for name, v in [("commit (SQLite, in the Vessel)", commits), ("turn pause (TurnEnd round trip = durable ack)", turn),
                ("seal.total", spans.get("seal.total", [])), ("publish.total", spans.get("publish.total", []))]:
    print(f"| {name} | {len(v)} | {q(v, .5):.3f} | {q(v, .95):.3f} | {q(v, .99):.3f} | {q(v, 1):.3f} |")
print()
print(f"| rate | value |")
print(f"| --- | ---: |")
print(f"| Warden wall time, all runs | {wall:.1f} s |")
print(f"| durable turns / s (Seals acknowledged) | {len(turn) / wall if wall else 0:.1f} |")
print(f"| commits / s | {len(commits) / wall if wall else 0:.1f} |")
print(f"| Warden CPU (user+sys) | {cpu:.2f} s = {cpu / len(turn) * 1000 if turn else 0:.1f} ms per turn |")
print(f"| Warden max RSS | {rss / 1024:.0f} MiB |")
print()
print("| span | n | p50 ms | p95 ms | max ms |")
print("| --- | ---: | ---: | ---: | ---: |")
for name in sorted(spans):
    v = spans[name]; print(f"| {name} | {len(v)} | {q(v, .5):.1f} | {q(v, .95):.1f} | {q(v, 1):.1f} |")
PY
echo "results in $OUT"
