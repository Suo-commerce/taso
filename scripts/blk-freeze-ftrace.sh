#!/usr/bin/env bash
# blk-freeze-ftrace.sh: where a freeze's time goes inside the kernel (P5
# lever 3, 2026-10-26): blk-trace-freeze.sh saw the device busy 22 ms of
# a 53 ms freeze after 4 MiB dirty.  The kernel's function graph of
# freeze_super, on a block-log branch and on a loop device, prints every
# call under the freeze with its duration; the lines over 1 ms are the
# answer.
#
#   sudo scripts/blk-freeze-ftrace.sh [DIRTY_KIB]      (default 4096)
#
# Each device: ext4 without a journal (the Warden's mkfs), lazy init
# waited out, one warm-up freeze/thaw, then DIRTY_KIB written and closed,
# ftrace armed (function_graph on freeze_super, depth 5, tails on), the
# freeze, ftrace stopped, the thaw.  Printed: the freeze's wall time, and
# the graph's lines whose duration is 1 ms or more, in call order and
# indentation (a closing line "} /* name */" is that call's total).
#
# Predictions (before the run):
#   F1  branch: sync_filesystem (the write-back and its wait) is most of
#       the freeze; inside it, the wait for the device's flush is the
#       13 ms the trace saw, and the write-back's own submission under
#       10 ms
#   F2  the remaining 20-30 ms are in one place, not spread: either the
#       freeze's second sync pass, or sb_wait_write (waiting for writers),
#       or blkdev_issue_flush
#   F3  loop shows the same shape with a shorter flush
#
# Touches, and nothing else: /sys/kernel/tracing (current_tracer,
# set_graph_function, max_graph_depth, options/funcgraph-tail, tracing_on,
# trace: all put back to nop/empty at the end), /var/lib/taso-blk/
# ftrace.log, .err, .ckpt, ftrace-loop.img (removed), /run/taso-blk-
# ftrace.sock, /mnt/blk-ftrace, one ublk device, one loop device,
# /var/lib/taso-blk/ftrace-<time>/ (the graphs, kept).

set -euo pipefail
DIRTY=${1:-4096}
DIR=/var/lib/taso-blk
LOG=$DIR/ftrace.log; ERR=$DIR/ftrace.err; IMG=$DIR/ftrace-loop.img
SOCK=/run/taso-blk-ftrace.sock
MNT=/mnt/blk-ftrace
OUT=$DIR/ftrace-$(date +%Y%m%d-%H%M%S)
T=/sys/kernel/tracing
BLKD=target/release/taso-blkd
DAEMON_PID=; LOOP=

die() { printf 'ABORT: %s\n' "$*" >&2; exit 2; }
blk() {
    local answer
    answer=$(python3 -c '
import socket, sys
s = socket.socket(socket.AF_UNIX); s.settimeout(60); s.connect(sys.argv[1])
s.sendall((" ".join(sys.argv[2:]) + "\n").encode()); print(s.makefile().readline().strip())' "$SOCK" "$@") || die "taso-blkd did not answer: $*"
    case "$answer" in "ok") ;; "ok "*) printf '%s\n' "${answer#ok }" ;; *) die "taso-blkd: $* -> $answer" ;; esac
}
ftrace_off() {
    echo 0 >"$T/tracing_on" 2>/dev/null; echo nop >"$T/current_tracer" 2>/dev/null
    echo >"$T/set_graph_function" 2>/dev/null; echo 0 >"$T/max_graph_depth" 2>/dev/null
}
cleanup() {
    local rc=$?
    set +e
    ftrace_off
    mountpoint -q "$MNT" && { fsfreeze -u "$MNT" 2>/dev/null; umount "$MNT"; }
    [[ -n "$LOOP" ]] && losetup -d "$LOOP"; rm -f "$IMG"
    if [[ -n "$DAEMON_PID" ]] && kill -0 "$DAEMON_PID" 2>/dev/null; then (blk quit) >/dev/null 2>&1 || kill "$DAEMON_PID"; wait "$DAEMON_PID" 2>/dev/null; fi
    rm -f "$LOG" "$LOG.ckpt"; rmdir "$MNT" 2>/dev/null
    exit "$rc"
}
trap cleanup EXIT

[[ $EUID -eq 0 ]] || die "run as root"
[[ -f Cargo.toml && -d crates/taso-blk ]] || die "run from the repository root"
[[ -d "$T" ]] || die "$T missing (tracefs)"
for c in mkfs.ext4 fsfreeze losetup python3; do command -v "$c" >/dev/null || die "$c missing"; done
grep -qw function_graph "$T/available_tracers" || die "function_graph tracer not available"
modprobe ublk_drv; [[ -c /dev/ublk-control ]] || die "/dev/ublk-control missing"
[[ ! -S "$SOCK" ]] || die "$SOCK exists"
mkdir -p "$DIR" "$MNT" "$OUT"; ! mountpoint -q "$MNT" || die "$MNT is mounted"
command -v cargo >/dev/null || PATH=/root/.cargo/bin:$PATH
cargo build -q --release -p taso-blk

# measure LABEL DEV: mkfs, mount, warm up, dirty, trace one freeze
measure() {
    local label=$1 dev=$2 t0 t1
    mkfs.ext4 -q -F -O ^has_journal -E nodiscard "$dev"
    mount -o discard "$dev" "$MNT"
    for _ in $(seq 600); do pgrep -x ext4lazyinit >/dev/null || break; sleep 1; done
    sync -f "$MNT"; fsfreeze -f "$MNT"; fsfreeze -u "$MNT"
    python3 - "$MNT" "$DIRTY" <<'PY'
import os, sys
with open(os.path.join(sys.argv[1], "dirty.bin"), "wb") as f: f.write(os.urandom(int(sys.argv[2]) << 10))
PY
    ftrace_off
    echo freeze_super >"$T/set_graph_function"
    echo 5 >"$T/max_graph_depth"
    echo 1 >"$T/options/funcgraph-tail"
    echo function_graph >"$T/current_tracer"
    echo >"$T/trace"
    echo 1 >"$T/tracing_on"
    t0=$(date +%s%N); fsfreeze -f "$MNT"; t1=$(date +%s%N)
    echo 0 >"$T/tracing_on"
    cat "$T/trace" >"$OUT/$label.txt"
    ftrace_off
    fsfreeze -u "$MNT"
    echo "== $label: freeze after $DIRTY KiB dirty: $(( (t1 - t0) / 1000 )) us wall (graph in $OUT/$label.txt)"
    python3 - "$OUT/$label.txt" <<'PY'
import re, sys
big = []
for ln in open(sys.argv[1]):
    m = re.search(r'\|\s+([\d.]+) us\s+\|(.*)$', ln)
    if not m: continue
    us = float(m.group(1))
    if us >= 1000: big.append((us, m.group(2).rstrip()))
if not big: print("  no call of 1 ms or more in the graph (is freeze_super traced on this kernel?)")
for us, body in big: print("  %8.1f ms |%s" % (us / 1000, body))
PY
    umount "$MNT"
}

rm -f "$LOG" "$ERR" "$LOG.ckpt"
"$BLKD" "$LOG" "$SOCK" --size-gib 8 --compact-pct 0 2>>"$ERR" &
DAEMON_PID=$!
for _ in $(seq 100); do [[ -S "$SOCK" ]] && break; sleep 0.1; done
[[ -S "$SOCK" ]] || die "taso-blkd socket did not appear; see $ERR"
ROOT=$(blk root)
read -r _ DEV <<<"$(blk fork "$ROOT" ftrace)"
for _ in $(seq 50); do [[ -b "$DEV" ]] && break; sleep 0.1; done
[[ -b "$DEV" ]] || die "device did not appear"
measure branch "$DEV"

truncate -s 8G "$IMG"
LOOP=$(losetup -f --show --sector-size 4096 "$IMG")
measure loop "$LOOP"
