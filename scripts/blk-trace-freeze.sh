#!/usr/bin/env bash
# blk-trace-freeze.sh: the kernel's view of one freeze on a block-log branch
# (P5 lever 3b, 2026-10-26): every request's issue and completion, from
# blktrace, so that what the device sees (blk-freeze-probe.sh run 4: 17 ms
# busy of a 44 ms freeze after 4 MiB dirty, no journal) is set against
# what the kernel sends and when.
#
#   sudo scripts/blk-trace-freeze.sh [DIRTY_KIB] [QUEUES] [THREADS]   (default 4096, 1, 1)
#
# THREADS: taso-blkd --threads N, serving threads per queue.  Run 2 showed
# four queues change nothing (one submitting CPU, one hardware queue, one
# of our threads got all thirteen requests).  Prediction for 4 threads on
# one queue: the eight 512 KiB writes complete spread over ~4 ms instead
# of one burst at 7.7 (the store's mutex still serialises ~0.44 ms each).
#
# QUEUES: taso-blkd --queues N (run 2, lever 3b: run 1 traced 13 requests
# in flight served one after another on one queue, 7.7 ms for eight
# 512 KiB writes; prediction for 4 queues: that phase under 3 ms, the
# flush unchanged).
#
# Its own taso-blkd, one branch, ext4 without a journal (the Warden's
# mkfs); DIRTY_KIB written and closed; blktrace started on the device;
# fsfreeze -f; blktrace stopped; thaw.  Printed: the timeline of D (issued
# to us) and C (completed) events with the number in flight after each,
# then: requests, the maximum in flight, the device-busy time (any request
# outstanding), the idle gaps over 1 ms and where they sit, and the
# freeze's wall time.
#
# Predictions (before the run):
#   T1  requests are issued with at most 1-2 in flight: ext4's write-back
#       waits for each before the next (the device serves one at a time,
#       so the kernel's plug sees no reason to batch)
#   T2  the idle gaps are between the write-back's batches and around the
#       flush requests, each a few ms, and sum to the 27 ms unaccounted
#   If instead many requests are in flight, the serial handler is the
#   limit and lever 3b is concurrency in the queue thread.
#
# Touches, and nothing else: /var/lib/taso-blk/trace.log, .err, .ckpt
# (removed), /run/taso-blk-trace.sock, /mnt/blk-trace, one ublk device,
# /var/lib/taso-blk/trace-<time>/ (blktrace output and the parsed
# timeline, kept).  Needs blktrace (apt: blktrace).

set -euo pipefail
DIRTY=${1:-4096}
QUEUES=${2:-1}
THREADS=${3:-1}
DIR=/var/lib/taso-blk
LOG=$DIR/trace.log; ERR=$DIR/trace.err
SOCK=/run/taso-blk-trace.sock
MNT=/mnt/blk-trace
OUT=$DIR/trace-$(date +%Y%m%d-%H%M%S)
BLKD=target/release/taso-blkd
DAEMON_PID=; TRACE_PID=

die() { printf 'ABORT: %s\n' "$*" >&2; exit 2; }
blk() {
    local answer
    answer=$(python3 -c '
import socket, sys
s = socket.socket(socket.AF_UNIX); s.settimeout(60); s.connect(sys.argv[1])
s.sendall((" ".join(sys.argv[2:]) + "\n").encode()); print(s.makefile().readline().strip())' "$SOCK" "$@") || die "taso-blkd did not answer: $*"
    case "$answer" in "ok") ;; "ok "*) printf '%s\n' "${answer#ok }" ;; *) die "taso-blkd: $* -> $answer" ;; esac
}
cleanup() {
    local rc=$?
    set +e
    [[ -n "$TRACE_PID" ]] && kill "$TRACE_PID" 2>/dev/null
    mountpoint -q "$MNT" && { fsfreeze -u "$MNT" 2>/dev/null; umount "$MNT"; }
    if [[ -n "$DAEMON_PID" ]] && kill -0 "$DAEMON_PID" 2>/dev/null; then (blk quit) >/dev/null 2>&1 || kill "$DAEMON_PID"; wait "$DAEMON_PID" 2>/dev/null; fi
    rm -f "$LOG" "$LOG.ckpt"; rmdir "$MNT" 2>/dev/null
    exit "$rc"
}
trap cleanup EXIT

[[ $EUID -eq 0 ]] || die "run as root"
[[ -f Cargo.toml && -d crates/taso-blk ]] || die "run from the repository root"
for c in blktrace blkparse mkfs.ext4 fsfreeze python3; do command -v "$c" >/dev/null || die "$c missing (apt-get install -y blktrace)"; done
modprobe ublk_drv; [[ -c /dev/ublk-control ]] || die "/dev/ublk-control missing"
[[ ! -S "$SOCK" ]] || die "$SOCK exists"
mkdir -p "$DIR" "$MNT" "$OUT"; ! mountpoint -q "$MNT" || die "$MNT is mounted"
command -v cargo >/dev/null || PATH=/root/.cargo/bin:$PATH
cargo build -q --release -p taso-blk
rm -f "$LOG" "$ERR" "$LOG.ckpt"
"$BLKD" "$LOG" "$SOCK" --size-gib 8 --compact-pct 0 --queues "$QUEUES" --threads "$THREADS" 2>>"$ERR" &
DAEMON_PID=$!
for _ in $(seq 100); do [[ -S "$SOCK" ]] && break; sleep 0.1; done
[[ -S "$SOCK" ]] || die "taso-blkd socket did not appear; see $ERR"
ROOT=$(blk root)
read -r _ DEV <<<"$(blk fork "$ROOT" trace)"
for _ in $(seq 50); do [[ -b "$DEV" ]] && break; sleep 0.1; done
[[ -b "$DEV" ]] || die "device did not appear"
mkfs.ext4 -q -F -O ^has_journal -E nodiscard "$DEV"
mount -o discard "$DEV" "$MNT"
for _ in $(seq 600); do pgrep -x ext4lazyinit >/dev/null || break; sleep 1; done
sync -f "$MNT"

python3 - "$MNT" "$DIRTY" <<'PY'
import os, sys
with open(os.path.join(sys.argv[1], "dirty.bin"), "wb") as f: f.write(os.urandom(int(sys.argv[2]) << 10))
PY
blktrace -d "$DEV" -o trace -D "$OUT" &
TRACE_PID=$!
sleep 0.5
t0=$(date +%s.%N); fsfreeze -f "$MNT"; t1=$(date +%s.%N)
sleep 0.2
kill -INT "$TRACE_PID"; wait "$TRACE_PID" 2>/dev/null || true; TRACE_PID=
fsfreeze -u "$MNT"
echo "block log ops (count:total_us:store_us:bytes): $(blk stats | tr ' ' '\n' | grep '^op_' | tr '\n' ' ')"
blkparse -i "$OUT/trace" -f '%T.%9t %a %d %S %N\n' 2>/dev/null >"$OUT/events.txt" || blkparse -i "$OUT/trace" >"$OUT/events.txt"
echo "queues $QUEUES, threads $THREADS; freeze after $DIRTY KiB dirty: $(python3 -c "print('%.1f ms' % (($t1 - $t0) * 1000))")  device $DEV  events in $OUT/events.txt"
python3 - "$OUT/events.txt" <<'PY'
import sys
ev = []
for ln in open(sys.argv[1]):
    p = ln.split()
    if len(p) < 3 or p[1] not in ("D", "C"): continue
    try: ev.append((float(p[0]), p[1], p[2], int(p[3]) if len(p) > 3 and p[3].isdigit() else 0, int(p[4]) if len(p) > 4 and p[4].isdigit() else 0))
    except ValueError: continue
if not ev: print("no D/C events parsed; see the file"); sys.exit()
ev.sort(); t0 = ev[0][0]
inflight, maxin, busy, last, gaps = 0, 0, 0.0, None, []
print("  t(ms)   ev  dir   sector   bytes  in-flight")
for t, a, d, sec, nb in ev:
    if a == "D":
        if inflight == 0 and last is not None and t - last > 0.001: gaps.append((last - t0, t - last))
        inflight += 1; maxin = max(maxin, inflight)
        if inflight == 1: start = t
    else:
        inflight = max(0, inflight - 1)
        if inflight == 0: busy += t - start; last = t
    print("  %7.2f  %s  %-4s %8d %7d  %d" % ((t - t0) * 1000, a, d, sec, nb, inflight))
n = sum(1 for e in ev if e[1] == "D")
print("requests %d; max in flight %d; device busy %.1f ms of %.1f ms traced; idle gaps over 1 ms: %d, %s" % (
    n, maxin, busy * 1000, (ev[-1][0] - t0) * 1000, len(gaps), ", ".join("%.1f ms at %.1f" % (g * 1000, at * 1000) for at, g in gaps)))
PY
