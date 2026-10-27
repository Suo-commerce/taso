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
TASO_BLKD_OPLOG="$OUT/oplog.txt" "$BLKD" "$LOG" "$SOCK" --size-gib 8 --compact-pct 0 --queues "$QUEUES" --threads "$THREADS" 2>>"$ERR" &
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
# MARK: CLOCK_MONOTONIC (the op log's clock) just before the freeze, so the
# split below takes only the freeze's own ops, not mkfs's and the mount's
# (run 2 on taso-p5, 2026-10-26, matched the op log from its start).
MARK=$(python3 -c 'import time; print(time.monotonic_ns())')
t0=$(date +%s.%N); fsfreeze -f "$MNT"; t1=$(date +%s.%N)
sleep 0.2
kill -INT "$TRACE_PID"; wait "$TRACE_PID" 2>/dev/null || true; TRACE_PID=
fsfreeze -u "$MNT"
echo "block log ops (count:total_us:store_us:bytes): $(blk stats | tr ' ' '\n' | grep '^op_' | tr '\n' ' ')"
# %5T.%9t is seconds since the trace's start.  blkparse has no absolute
# form (run 2 on taso-p5, 2026-10-26: -t left the times relative, 38
# minutes from the op log's CLOCK_MONOTONIC), so the split below aligns
# the two clocks itself.  The file is written before anything reads it
# (run 1 read it first and found no file).
blkparse -i "$OUT/trace" -f '%T.%9t %a %d %S %N\n' 2>/dev/null >"$OUT/events.txt" || blkparse -i "$OUT/trace" >"$OUT/events.txt"
# Where a request's time goes: the kernel's D -> our handler's start (the
# queue), the handler, our end -> the kernel's C (the completion).  Only
# the ops after MARK (the freeze's own); matched per kind in order.  The
# clocks are anchored at the batch's first request: its queue is 0 by
# construction and every other queue is relative to it, so the queue
# column is a lower bound and handler + complete are exact.  Prediction
# (before run 3): the writes' completion gap grows along the batch (each
# completed only when the batch's last handler returns); the flush's
# completion gap ~6 ms.  Run 2 already showed every write of the batch
# completing within 0.02 ms of the others, 7.6 ms after issue.
python3 - "$OUT/events.txt" "$OUT/oplog.txt" "$MARK" <<'PY' | tee -a "$OUT/gaps.txt"
import sys
try:
    ev = [l.split() for l in open(sys.argv[1]) if len(l.split()) > 4 and l.split()[1] in ("D", "C")]
    mark = int(sys.argv[3])
    # op bytes start end [copy wait store] (the three parts since b061969; older logs have four fields)
    ops = [l.split() for l in open(sys.argv[2]) if len(l.split()) in (4, 7) and int(l.split()[2]) >= mark]
except (OSError, ValueError) as e:
    print("no gap analysis: %s" % e); sys.exit()
if not ev:
    print("no gap analysis: blkparse gave no events"); sys.exit()
if not ops:
    print("no gap analysis: no op after the freeze mark in the op log"); sys.exit()
kind = {"W": "write", "WM": "write", "WS": "write", "WSM": "write", "WFS": "write", "FN": "flush", "F": "flush", "R": "read", "RM": "read", "D": "discard"}
issued = {}
rows = []
for t, a, d, sec, nb in ((float(e[0]), e[1], e[2], e[3], e[4]) for e in ev):
    k = kind.get(d)
    if k is None: continue
    if a == "D": issued.setdefault(k, []).append((t, int(nb) if nb.isdigit() else 0))
    else:
        q = issued.get(k, [])
        if q:
            ti, nbi = q.pop(0); rows.append((k, nbi, ti, t))
# our ops, per kind in order
mine = {}
for o in ops:
    parts = tuple(int(x) / 1e6 for x in o[4:7]) if len(o) == 7 else (float('nan'),) * 3
    mine.setdefault(o[0], []).append((int(o[2]) / 1e9, int(o[3]) / 1e9, parts))
# Anchor: the earliest issued request against the earliest op after the mark.
first_issue = min((ti for k, nb, ti, tc in rows), default=None)
first_op = min((s0 for q in mine.values() for s0, s1, parts in q), default=None)
if first_issue is None or first_op is None:
    print("no gap analysis: nothing to match"); sys.exit()
off = first_op - first_issue
print("  clocks anchored at the first request (its queue is 0 by construction; queue is a lower bound)")
print("  %-8s %7s %9s %9s %9s %9s %7s %7s %7s" % ("op", "KiB", "queue ms", "handler", "complete", "D->C", "copy", "wait", "store"))
for k, nb, ti, tc in rows:
    m = mine.get(k)
    if not m: continue
    s0, s1, (cp, wt, st) = m.pop(0)
    s0 -= off; s1 -= off
    print("  %-8s %7d %9.2f %9.2f %9.2f %9.2f %7.2f %7.2f %7.2f" % (k, nb // 1024, (s0 - ti) * 1000, (s1 - s0) * 1000, (tc - s1) * 1000, (tc - ti) * 1000, cp, wt, st))
PY
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
        # Busy only when this completion empties the queue; a completion
        # with nothing in flight (issued before the trace started) added a
        # stale start (run 1: "busy 35.4 ms of 22.1 ms traced").
        if inflight == 1: busy += t - start; last = t
        inflight = max(0, inflight - 1)
    print("  %7.2f  %s  %-4s %8d %7d  %d" % ((t - t0) * 1000, a, d, sec, nb, inflight))
n = sum(1 for e in ev if e[1] == "D")
print("requests %d; max in flight %d; device busy %.1f ms of %.1f ms traced; idle gaps over 1 ms: %d, %s" % (
    n, maxin, busy * 1000, (ev[-1][0] - t0) * 1000, len(gaps), ", ".join("%.1f ms at %.1f" % (g * 1000, at * 1000) for at, g in gaps)))
PY
