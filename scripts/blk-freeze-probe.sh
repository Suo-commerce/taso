#!/usr/bin/env bash
# blk-freeze-probe.sh: what an ext4 freeze costs on a block-log branch, and
# why (P5 B1: seal.freeze measured 37 ms p50 at P=1 on taso-test,
# 2026-10-26, while seal.log and seal.thaw were 1-2 ms).
#
#   sudo scripts/blk-freeze-probe.sh        (from the repository root)
#
# Run 1 (2026-10-26, taso-test): an idle freeze costs ~2 ms on a branch,
# lazy init on or off, and ~1.5 ms on loop; a freeze after one 1 MiB file
# costs 15-32 ms on a branch and 9-20 ms on loop.  The cost is the dirty
# data written back through the device at the freeze, not the freeze.
# Run 2 asks how that write-back goes: dirty sizes from 64 KiB to 4 MiB on
# a branch (lazy init done) and on loop, with the kernel's request count
# and bytes for the device around each freeze (/sys/block/<dev>/stat:
# writes completed, sectors written), so the size of the requests the
# kernel sends is known.  First the idle cycles as before (N, default 20).
#
# Predictions for run 2 (before the run):
#   Q1  freeze time grows about linearly with the dirty size, on both
#   Q2  the branch costs more per MiB than loop (the ublk round trip and the
#       log's own write per request); if that factor is under 2 the device
#       is not the problem and the Seal's cost is the write-back as such
#   Q3  requests are large (p50 well over 64 KiB per request, i.e. the
#       kernel merges pages); if they come as 4 KiB each, the block-log
#       device's reported limits are making ext4 write a page at a time
#       and that is the first thing to fix
#
# Touches, and nothing else:
#   /var/lib/taso-blk/freeze.log, .log.ckpt, .err  (removed at start and end)
#   /var/lib/taso-blk/freeze-loop.img  (sparse 8 GiB, removed at the end)
#   /run/taso-blk-freeze.sock  (its own taso-blkd)
#   /mnt/blk-freeze  (mounted, unmounted), one loop device, the
#   /dev/ublkb* devices its taso-blkd creates
# Prints the report; also saved to /var/lib/taso-blk/freeze-report.txt.

set -euo pipefail

DIR=/var/lib/taso-blk
LOG=$DIR/freeze.log
ERR=$DIR/freeze.err
SOCK=/run/taso-blk-freeze.sock
IMG=$DIR/freeze-loop.img
MNT=/mnt/blk-freeze
REPORT=$DIR/freeze-report.txt
BLKD=target/release/taso-blkd
N=${N:-20}

DAEMON_PID=; LOOP=

say() { printf '== %s\n' "$*" | tee -a "$REPORT"; }
out() { printf '%s\n' "$*" | tee -a "$REPORT"; }
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
    mountpoint -q "$MNT" && { fsfreeze -u "$MNT" 2>/dev/null; umount "$MNT"; }
    [[ -n "$LOOP" ]] && losetup -d "$LOOP"
    rm -f "$IMG"
    if [[ -n "$DAEMON_PID" ]] && kill -0 "$DAEMON_PID" 2>/dev/null; then (blk quit) >/dev/null 2>&1 || kill "$DAEMON_PID"; wait "$DAEMON_PID" 2>/dev/null; fi
    rm -f "$LOG" "$LOG.ckpt"
    rmdir "$MNT" 2>/dev/null
    exit "$rc"
}
trap cleanup EXIT

# measure LABEL DEV: N idle freeze/thaw cycles, then one freeze after each
# dirty size, with the device's write requests and bytes around it
measure() {
    local label=$1 dev=$2
    python3 - "$MNT" "$N" "$label" "$(basename "$dev")" <<'PY' | tee -a "$REPORT"
import os, subprocess, sys, time
mnt, n, label, dev = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
def ms(cmd):
    t = time.perf_counter(); subprocess.run(cmd, check=True); return (time.perf_counter() - t) * 1000
def p50(v): v = sorted(v); return v[len(v) // 2]
def stat():  # writes completed, sectors written (512 B)
    f = open("/sys/block/%s/stat" % dev).read().split(); return int(f[4]), int(f[6])
fr, th, sy = [], [], []
for _ in range(n):
    sy.append(ms(["sync", "-f", mnt]))
    fr.append(ms(["fsfreeze", "-f", mnt])); th.append(ms(["fsfreeze", "-u", mnt]))
print("  %-28s idle: freeze p50 %5.1f max %5.1f   thaw p50 %4.1f   syncfs p50 %4.1f ms" % (label, p50(fr), max(fr), p50(th), p50(sy)))
for kib in (64, 256, 1024, 4096):
    with open(os.path.join(mnt, "dirty.bin"), "wb") as f: f.write(os.urandom(kib << 10))
    w0, s0 = stat()
    t = ms(["fsfreeze", "-f", mnt])
    w1, s1 = stat()
    subprocess.run(["fsfreeze", "-u", mnt], check=True)
    os.unlink(os.path.join(mnt, "dirty.bin")); subprocess.run(["sync", "-f", mnt], check=True)
    reqs, kb = w1 - w0, (s1 - s0) // 2
    print("  %-28s dirty %5d KiB: freeze %6.1f ms  %4d write requests, %6d KiB written, %5.0f KiB/request, %6.1f MiB/s"
          % (label, kib, t, reqs, kb, kb / reqs if reqs else 0, (kb / 1024) / (t / 1000) if t else 0))
PY
}
limits() { # limits DEV -> the queue limits that shape write-back requests
    local n f; n=$(basename "$1")
    for f in logical_block_size physical_block_size minimum_io_size optimal_io_size max_sectors_kb max_segments; do
        printf '%s=%s ' "$f" "$(cat "/sys/block/$n/queue/$f")"
    done
}
lazy_wait() { # wait until no ext4lazyinit thread is running (it exits when done)
    for _ in $(seq 600); do pgrep -x ext4lazyinit >/dev/null || return 0; sleep 1; done
    out "  (ext4lazyinit still running after 10 minutes)"
}

[[ $EUID -eq 0 ]] || die "run as root"
[[ -f Cargo.toml && -d crates/taso-blk ]] || die "run from the repository root"
for c in mkfs.ext4 fsfreeze losetup mount sync python3; do command -v "$c" >/dev/null || die "$c missing"; done
modprobe ublk_drv; [[ -c /dev/ublk-control ]] || die "/dev/ublk-control missing"
[[ ! -S "$SOCK" ]] || die "$SOCK exists: another run? (pgrep -af 'taso-blkd.*freeze')"
[[ ! -e "$IMG" ]] || die "$IMG exists from an earlier run"
mkdir -p "$DIR" "$MNT"; ! mountpoint -q "$MNT" || die "$MNT is already a mount point"
command -v cargo >/dev/null || PATH=/root/.cargo/bin:$PATH
cargo build -q --release -p taso-blk
[[ -x "$BLKD" ]] || die "no taso-blkd at $BLKD"

: >"$REPORT"
out "blk-freeze-probe $(date -Is); $(hostname); kernel $(uname -r); taso $(git rev-parse --short HEAD 2>/dev/null || echo ?); N=$N"
rm -f "$LOG" "$ERR" "$LOG.ckpt"
"$BLKD" "$LOG" "$SOCK" --size-gib 8 --compact-pct 0 2>>"$ERR" &
DAEMON_PID=$!
for _ in $(seq 100); do [[ -S "$SOCK" ]] && break; sleep 0.1; done
[[ -S "$SOCK" ]] || die "taso-blkd socket did not appear; see $ERR"
ROOT=$(blk root)
branch_dev() { # branch_dev NAME -> device
    local dev
    read -r _ dev <<<"$(blk fork "$ROOT" "$1")"
    for _ in $(seq 50); do [[ -b "$dev" ]] && break; sleep 0.1; done
    [[ -b "$dev" ]] || die "device for $1 did not appear"
    echo "$dev"
}

say "branch: mkfs as the Warden, lazy init waited out"
DEV_A=$(branch_dev freeze-a)
mkfs.ext4 -q -F -E nodiscard "$DEV_A"
mount -o discard "$DEV_A" "$MNT"
lazy_wait
out "  device $DEV_A: $(limits "$DEV_A")"
measure "branch" "$DEV_A"
umount "$MNT"

say "loop: mkfs as the Warden, lazy init waited out"
truncate -s 8G "$IMG"
LOOP=$(losetup -f --show --sector-size 4096 "$IMG")
mkfs.ext4 -q -F -E nodiscard "$LOOP"
mount -o discard "$LOOP" "$MNT"
lazy_wait
out "  device $LOOP: $(limits "$LOOP")"
measure "loop" "$LOOP"
umount "$MNT"

say "report saved to $REPORT"
