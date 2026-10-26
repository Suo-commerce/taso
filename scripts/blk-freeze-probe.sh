#!/usr/bin/env bash
# blk-freeze-probe.sh: what an ext4 freeze costs on a block-log branch, and
# why (P5 B1: seal.freeze measured 37 ms p50 at P=1 on taso-test,
# 2026-10-26, while seal.log and seal.thaw were 1-2 ms).
#
#   sudo scripts/blk-freeze-probe.sh        (from the repository root)
#
# Four filesystems, each frozen and thawed N times (default 20) with
# nothing dirty, then once more after writing and closing a 1 MiB file:
#   A  ext4 on a fresh branch, mkfs as the Warden does it (lazy inode-table
#      init on: a kernel thread keeps zeroing inode tables after mkfs)
#   B  the same filesystem after ext4lazyinit has finished (waited for)
#   C  ext4 on a second branch, mkfs with lazy_itable_init=0,lazy_journal_init=0
#   D  ext4 on a loop device, mkfs as the Warden does it (the kernel path
#      without the block log, for comparison)
# Printed per case: fsfreeze -f p50/max ms, fsfreeze -u p50/max ms, and
# syncfs alone (sync -f) p50 ms; the last line names the cause the numbers
# support.
#
# Predictions (2026-10-26, before the first run):
#   P1  A: freeze p50 about 37 ms (the Warden's number)
#   P2  B and C: freeze p50 under 5 ms (lazy init was the cost)
#   P3  D: freeze p50 under 3 ms
#   P4  the freeze after a 1 MiB write costs a few ms more than idle, on
#       every case (the dirty data, flushed through the device)
# If B stays at A's level, lazy init is not it and the cost is in the
# freeze path through ublk itself (then: C against D says whether it is
# the device).
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

# measure LABEL: N freeze/thaw cycles idle, then one after a 1 MiB write
measure() {
    local label=$1
    python3 - "$MNT" "$N" "$label" <<'PY' | tee -a "$REPORT"
import os, subprocess, sys, time
mnt, n, label = sys.argv[1], int(sys.argv[2]), sys.argv[3]
def ms(cmd):
    t = time.perf_counter(); subprocess.run(cmd, check=True); return (time.perf_counter() - t) * 1000
def p50(v): v = sorted(v); return v[len(v) // 2]
fr, th, sy = [], [], []
for _ in range(n):
    sy.append(ms(["sync", "-f", mnt]))
    fr.append(ms(["fsfreeze", "-f", mnt])); th.append(ms(["fsfreeze", "-u", mnt]))
with open(os.path.join(mnt, "dirty.bin"), "wb") as f: f.write(os.urandom(1 << 20))
dirty = ms(["fsfreeze", "-f", mnt]); subprocess.run(["fsfreeze", "-u", mnt], check=True)
os.unlink(os.path.join(mnt, "dirty.bin"))
print("  %-44s freeze p50 %6.1f max %6.1f   thaw p50 %5.1f   syncfs p50 %5.1f   freeze after 1 MiB %6.1f  ms" % (label, p50(fr), max(fr), p50(th), p50(sy), dirty))
PY
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

say "A: branch, mkfs as the Warden (lazy init on), measured at once"
DEV_A=$(branch_dev freeze-a)
mkfs.ext4 -q -F -E nodiscard "$DEV_A"
mount -o discard "$DEV_A" "$MNT"
out "  ext4lazyinit running: $(pgrep -x ext4lazyinit >/dev/null && echo yes || echo no)"
measure "A fresh, lazy init on"

say "B: the same filesystem after ext4lazyinit finished"
lazy_wait
out "  ext4lazyinit running: $(pgrep -x ext4lazyinit >/dev/null && echo yes || echo no)"
measure "B same fs, lazy init done"
umount "$MNT"

say "C: branch, mkfs with lazy_itable_init=0,lazy_journal_init=0"
DEV_C=$(branch_dev freeze-c)
mkfs.ext4 -q -F -E nodiscard,lazy_itable_init=0,lazy_journal_init=0 "$DEV_C"
mount -o discard "$DEV_C" "$MNT"
measure "C fresh, lazy init off"
umount "$MNT"

say "D: loop device, mkfs as the Warden"
truncate -s 8G "$IMG"
LOOP=$(losetup -f --show --sector-size 4096 "$IMG")
mkfs.ext4 -q -F -E nodiscard "$LOOP"
mount -o discard "$LOOP" "$MNT"
measure "D loop, lazy init on, at once"
lazy_wait
measure "D loop, lazy init done"
umount "$MNT"

say "report saved to $REPORT"
