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
# Run 2 (taso-test): the requests the kernel sends are merged (13-25 per
# freeze, up to 167 KiB each) and the branch moves them as fast as loop.
# Run 4 (lever 3): the block log's own per-operation times (taso-blkd
# stats op_*: count:total_us:store_us:bytes) around each freeze - how long
# a write request takes in the process and how much of it inside the
# store's lock.  Prediction (before the run): the store's share is under
# 10% and the request's time is the ublk round trip and the kernel's copy.
# Run 3 (lever 2, the metal): how many BARRIERS one freeze sends - the
# block log's sync count (taso-blkd stats: syncs, now one per group
# commit round) and the device's flush requests (/sys/block/<dev>/stat,
# field 17: flush requests completed, kernel 5.5+), around each freeze,
# idle and after each dirty size; and the same freeze with ext4 mounted
# data=writeback (metadata journalled, data not ordered before it) and
# with the journal off (tune2fs -O ^has_journal), to see how many barriers
# each mode needs.  Lever 2 chooses a Vessel's mount mode by this table.
#
# Predictions for run 3 (before the run, 2026-10-26):
#   R1  an idle freeze sends 1 flush; a dirty one 2-4 (data write-back,
#       the journal's commit with its own flush/FUA)
#   R2  data=writeback saves none (the barriers are the journal's, not
#       the data's) or one
#   R3  no journal: 1 flush per freeze whatever the dirty size, and the
#       freeze after 4 MiB at the write-back's cost alone
#   R4  on taso-p5 (1 ms flush) a dirty freeze costs barriers x ~1 ms plus
#       the bytes at ~1 GB/s: 4 MiB under 10 ms when alone
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
# dirty size, with the device's write requests, flush requests (barriers)
# and the block log's syncs around it
measure() {
    local label=$1 dev=$2
    python3 - "$MNT" "$N" "$label" "$(basename "$dev")" "$SOCK" <<'PY' | tee -a "$REPORT"
import os, socket, subprocess, sys, time
mnt, n, label, dev, sock = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5]
def ms(cmd):
    t = time.perf_counter(); subprocess.run(cmd, check=True); return (time.perf_counter() - t) * 1000
def p50(v): v = sorted(v); return v[len(v) // 2]
def stat():  # writes completed, sectors written, flush requests completed (field 17, 0 if absent)
    f = open("/sys/block/%s/stat" % dev).read().split()
    return int(f[4]), int(f[6]), int(f[16]) if len(f) > 16 else 0
def stats():  # the block log's stats line as a dict, or {} on a loop device
    if dev.startswith("loop"): return {}
    s = socket.socket(socket.AF_UNIX); s.connect(sock); s.sendall(b"stats\n")
    line = s.makefile().readline(); s.close()
    return dict(kv.split("=", 1) for kv in line.split()[1:] if "=" in kv)
def syncs(): return int(stats().get("syncs", -1))
def ops(st):  # op name -> (count, total_us, store_us, bytes)
    return {k[3:]: tuple(int(x) for x in v.split(":")) for k, v in st.items() if k.startswith("op_")}
def ops_line(a, b):  # what the device did between two stats readings
    out = []
    for k in ("write", "flush", "read"):
        if k not in a or k not in b: continue
        n = b[k][0] - a[k][0]
        if n == 0: continue
        tot, sto, by = b[k][1] - a[k][1], b[k][2] - a[k][2], b[k][3] - a[k][3]
        out.append("%s %d x %.2f ms (%.2f in store%s)" % (k, n, tot / n / 1000, sto / n / 1000, ", %d KiB" % (by // 1024) if by else ""))
    return "; ".join(out)
fr, th, fl, sy = [], [], [], []
for _ in range(n):
    subprocess.run(["sync", "-f", mnt], check=True)
    f0 = stat()[2]; s0 = syncs()
    fr.append(ms(["fsfreeze", "-f", mnt])); fl.append(stat()[2] - f0); sy.append(syncs() - s0)
    th.append(ms(["fsfreeze", "-u", mnt]))
print("  %-30s idle: freeze p50 %5.1f max %5.1f ms  thaw p50 %4.1f  flush requests/freeze %d  log syncs/freeze %d" % (label, p50(fr), max(fr), p50(th), p50(fl), p50(sy)))
for kib in (64, 1024, 4096):
    with open(os.path.join(mnt, "dirty.bin"), "wb") as f: f.write(os.urandom(kib << 10))
    w0, s0, f0 = stat(); st0 = stats(); y0 = int(st0.get("syncs", -1))
    t = ms(["fsfreeze", "-f", mnt])
    w1, s1, f1 = stat(); st1 = stats(); y1 = int(st1.get("syncs", -1))
    subprocess.run(["fsfreeze", "-u", mnt], check=True)
    os.unlink(os.path.join(mnt, "dirty.bin")); subprocess.run(["sync", "-f", mnt], check=True)
    reqs, kb = w1 - w0, (s1 - s0) // 2
    print("  %-30s dirty %5d KiB: freeze %6.1f ms  %3d writes, %6d KiB, %3d flush requests, %3d log syncs" % (label, kib, t, reqs, kb, f1 - f0, y1 - y0))
    if st0: print("  %-30s   in the block log: %s" % ("", ops_line(ops(st0), ops(st1))))
PY
}
limits() { # limits DEV (kept for a later run) -> the queue limits that shape write-back requests
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
for c in mkfs.ext4 tune2fs dumpe2fs fsfreeze losetup mount sync python3; do command -v "$c" >/dev/null || die "$c missing"; done
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

case_branch() { # case_branch NAME LABEL MKFS_EXTRA MOUNT_OPTS [TUNE]
    local name=$1 label=$2 extra=$3 opts=$4 tune=${5:-} dev
    say "$label"
    dev=$(branch_dev "$name")
    mkfs.ext4 -q -F -E "nodiscard${extra:+,$extra}" "$dev"
    [[ -z "$tune" ]] || tune2fs -O "$tune" "$dev" >/dev/null
    mount -o "$opts" "$dev" "$MNT"
    lazy_wait
    out "  mount: $(findmnt -no OPTIONS "$MNT"); journal: $(dumpe2fs -h "$dev" 2>/dev/null | grep -c has_journal)"
    measure "$label" "$dev"
    umount "$MNT"
}
case_branch freeze-a "branch, ordered (the Warden's mount)" "" "discard"
case_branch freeze-b "branch, data=writeback" "" "discard,data=writeback"
case_branch freeze-c "branch, no journal" "" "discard" "^has_journal"

say "loop, ordered, for comparison"
truncate -s 8G "$IMG"
LOOP=$(losetup -f --show --sector-size 4096 "$IMG")
mkfs.ext4 -q -F -E nodiscard "$LOOP"
mount -o discard "$LOOP" "$MNT"
lazy_wait
measure "loop, ordered" "$LOOP"
umount "$MNT"

say "report saved to $REPORT"
