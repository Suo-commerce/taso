#!/usr/bin/env bash
# blk-thin-probe.sh: why does xfstests generic/347 exhaust its thin pool
# differently on our device than on a loop device?
#
# Builds generic/347's device-mapper stack (a 500 MiB thin pool with 512 KiB
# blocks and a 5000 MiB thin volume, metadata and data as linear slices of
# one device) twice: on one of our devices and on a loop device with 4 KiB
# sectors.  For each it prints what every layer reports (discard and
# write-zeroes limits, block sizes, rotational), then formats the thin
# volume as xfstests does and prints how many pool blocks are in use after
# creating the pool, after mkfs.ext4, and after mounting (-o discard) and
# waiting 15 s (ext4 initialises inode tables in the background after
# mount).  Prediction: if the counts differ, the difference is what tips
# generic/347 over on our device.
#
#   scripts/blk-thin-probe.sh                 (from the repository root, as root)
#
# Touches, and nothing else:
#   /var/lib/taso-blk/probe.log, probe.err, probe.log.ckpt (removed at start)
#   /var/lib/taso-blk/probe-loop.img       (sparse 8 GiB, removed at the end)
#   /run/taso-blk-probe.sock
#   /mnt/blk-probe                         (mounted, then unmounted)
#   device-mapper devices probe-{meta,data,pool,vol}-{ours,loop} (removed)
#   one /dev/ublkb* device the daemon creates, one loop device
# Prints the report; also saved to /var/lib/taso-blk/probe-report.txt.
#
# PROBE_NO_DM=1 skips the device-mapper steps (to try the rest of the script
# on a machine without device-mapper); PROBE_BLKD=path runs that daemon
# instead of building one; PROBE_NO_UBLK=1 skips the ublk module check.

set -euo pipefail

DIR=/var/lib/taso-blk
LOG=$DIR/probe.log
ERR=$DIR/probe.err
SOCK=/run/taso-blk-probe.sock
IMG=$DIR/probe-loop.img
MNT=/mnt/blk-probe
REPORT=$DIR/probe-report.txt
BLKD=${PROBE_BLKD:-target/release/taso-blkd}

# generic/347's numbers (common/dmthin _dmthin_init), in 512-byte sectors.
DATA_SECTORS=$((500 * 1024 * 1024 / 512))
VIRT_SECTORS=$((10 * DATA_SECTORS))
CLUSTER=1024
LOW_WATER=$((204800 / CLUSTER))
META_SECTORS=$((48 * DATA_SECTORS / CLUSTER))
[[ $META_SECTORS -ge 4096 ]] || META_SECTORS=4096
META_OFFSET=10240
DATA_OFFSET=$((META_OFFSET + META_SECTORS))

DAEMON_PID=
LOOP=
DM_MADE=()

say() { printf '== %s\n' "$*" | tee -a "$REPORT"; }
out() { printf '%s\n' "$*" | tee -a "$REPORT"; }
die() { printf 'ABORT: %s\n' "$*" >&2; exit 2; }

blk() {
    local answer
    answer=$(python3 -c '
import socket, sys
s = socket.socket(socket.AF_UNIX)
s.settimeout(60)
s.connect(sys.argv[1])
s.sendall((" ".join(sys.argv[2:]) + "\n").encode())
print(s.makefile().readline().strip())
' "$SOCK" "$@") || die "daemon did not answer: $*"
    case "$answer" in
        "ok") ;;
        "ok "*) printf '%s\n' "${answer#ok }" ;;
        *) die "daemon: $* -> $answer" ;;
    esac
}

cleanup() {
    local rc=$?
    set +e
    mountpoint -q "$MNT" && umount "$MNT"
    # Remove what this run made, newest first (the volume before its pool).
    for ((i = ${#DM_MADE[@]} - 1; i >= 0; i--)); do
        dmsetup remove "${DM_MADE[$i]}" 2>/dev/null || dmsetup remove --retry "${DM_MADE[$i]}"
    done
    [[ -n "$LOOP" ]] && losetup -d "$LOOP"
    rm -f "$IMG"
    if [[ -n "$DAEMON_PID" ]] && kill -0 "$DAEMON_PID" 2>/dev/null; then
        (blk quit) >/dev/null 2>&1 || kill "$DAEMON_PID"
        wait "$DAEMON_PID" 2>/dev/null
    fi
    exit "$rc"
}
trap cleanup EXIT

dm_create() { # dm_create NAME TABLE
    dmsetup create "$1" --table "$2"
    DM_MADE+=("$1")
    udevadm settle 2>/dev/null || true
}

# What a block device reports, one line.
limits() { # limits LABEL DEVICE
    local q
    q=/sys/block/$(basename "$(readlink -f "$2")")/queue
    out "$(printf '  %-12s %-16s lbs=%s pbs=%s min_io=%s opt_io=%s rot=%s disc_gran=%s disc_max=%s wz_max=%s' \
        "$1" "$(readlink -f "$2")" \
        "$(cat "$q/logical_block_size")" "$(cat "$q/physical_block_size")" \
        "$(cat "$q/minimum_io_size")" "$(cat "$q/optimal_io_size")" "$(cat "$q/rotational")" \
        "$(cat "$q/discard_granularity")" "$(cat "$q/discard_max_bytes")" \
        "$(cat "$q/write_zeroes_max_bytes" 2>/dev/null || echo -)")"
}

# Used and total pool data blocks: "used/total".
pool_used() { dmsetup status "$1" | awk '{ print $6 }'; }

probe() { # probe TAG DEVICE
    local tag=$1 dev=$2
    local meta=probe-meta-$tag data=probe-data-$tag pool=probe-pool-$tag vol=probe-vol-$tag
    say "$tag: $dev"
    limits device "$dev"
    if [[ "${PROBE_NO_DM:-}" == 1 ]]; then
        out "  (device-mapper steps skipped: PROBE_NO_DM=1)"
        return 0
    fi
    dm_create "$meta" "0 $META_SECTORS linear $dev $META_OFFSET"
    dm_create "$data" "0 $DATA_SECTORS linear $dev $DATA_OFFSET"
    dd if=/dev/zero of="/dev/mapper/$meta" bs=4096 count=1 conv=fsync status=none
    dm_create "$pool" "0 $DATA_SECTORS thin-pool /dev/mapper/$meta /dev/mapper/$data $CLUSTER $LOW_WATER"
    dmsetup message "$pool" 0 "create_thin 1"
    dm_create "$vol" "0 $VIRT_SECTORS thin /dev/mapper/$pool 1"
    limits data "/dev/mapper/$data"
    limits pool "/dev/mapper/$pool"
    limits volume "/dev/mapper/$vol"
    out "  pool blocks used (of 512 KiB) after creating the volume: $(pool_used "$pool")"

    mkfs.ext4 -F "/dev/mapper/$vol" >"$DIR/probe-mkfs-$tag.txt" 2>&1
    out "  after mkfs.ext4:                     $(pool_used "$pool")"
    out "  mkfs: $(grep -iE 'discard|zero' "$DIR/probe-mkfs-$tag.txt" | tr '\n' ' ' || true)"
    out "  groups with inode table marked zeroed: $(dumpe2fs "/dev/mapper/$vol" 2>/dev/null | grep -c ITABLE_ZEROED || true) of $(dumpe2fs "/dev/mapper/$vol" 2>/dev/null | grep -c '^Group ' || true)"

    mount -o discard "/dev/mapper/$vol" "$MNT"
    [[ "$(findmnt -n -o SOURCE --mountpoint "$MNT")" == "/dev/mapper/$vol" || "$(findmnt -n -o SOURCE --mountpoint "$MNT")" == "$(readlink -f "/dev/mapper/$vol")" ]] \
        || die "$MNT is not mounted from /dev/mapper/$vol"
    out "  right after mount:                   $(pool_used "$pool")"
    sleep 15
    out "  15 s after mount:                    $(pool_used "$pool")"
    umount "$MNT"
    out "  after unmount:                       $(pool_used "$pool")"
    out "  after: groups with inode table zeroed: $(dumpe2fs "/dev/mapper/$vol" 2>/dev/null | grep -c ITABLE_ZEROED || true)"

    for ((i = ${#DM_MADE[@]} - 1; i >= 0; i--)); do
        dmsetup remove --retry "${DM_MADE[$i]}"
    done
    DM_MADE=()
}

# ---- preflight ---------------------------------------------------------------
[[ $EUID -eq 0 ]] || die "run as root"
[[ -f Cargo.toml && -d crates/taso-blk ]] || die "run from the repository root"
if [[ "${PROBE_NO_UBLK:-}" != 1 ]]; then
    modprobe ublk_drv
    [[ -c /dev/ublk-control ]] || die "/dev/ublk-control missing"
fi
if [[ "${PROBE_NO_DM:-}" != 1 ]]; then
    command -v dmsetup >/dev/null || die "dmsetup missing (apt-get install dmsetup)"
    modprobe dm_thin_pool 2>/dev/null || true
    dmsetup targets | grep -q '^thin-pool' || die "the kernel has no dm thin-pool target"
    [[ -z "$(dmsetup ls | grep -E '^probe-' || true)" ]] || die "probe-* device-mapper devices exist from an earlier run (dmsetup ls)"
fi
[[ ! -S "$SOCK" ]] || die "$SOCK exists: another run's daemon? (pgrep -x taso-blkd)"
[[ ! -e "$IMG" ]] || die "$IMG exists from an earlier run (losetup -a; then remove it)"
mkdir -p "$DIR" "$MNT"
! mountpoint -q "$MNT" || die "$MNT is already a mount point"

if [[ -z "${PROBE_BLKD:-}" ]]; then
    command -v cargo >/dev/null || PATH=/root/.cargo/bin:$PATH
    cargo build -q --release -p taso-blk
fi
[[ -x "$BLKD" ]] || die "no daemon at $BLKD"

: >"$REPORT"
out "blk-thin-probe $(date -Is); kernel $(uname -r); taso $(git rev-parse --short HEAD 2>/dev/null || echo ?)"
out "generic/347 stack: data ${DATA_SECTORS} sectors (500 MiB), blocks ${CLUSTER} sectors (512 KiB), volume ${VIRT_SECTORS} sectors, metadata ${META_SECTORS} sectors at ${META_OFFSET}"

rm -f "$LOG" "$ERR" "$LOG.ckpt"
"$BLKD" "$LOG" "$SOCK" --size-gib 8 --compact-pct 0 2>>"$ERR" &
DAEMON_PID=$!
for _ in $(seq 100); do [[ -S "$SOCK" ]] && break; sleep 0.1; done
[[ -S "$SOCK" ]] || die "daemon socket did not appear; see $ERR"
ROOT=$(blk root)
read -r _ OURS <<<"$(blk fork "$ROOT" probe-ours)"
for _ in $(seq 50); do [[ -b "$OURS" ]] && break; sleep 0.1; done
[[ -b "$OURS" ]] || die "device $OURS did not appear"

truncate -s 8G "$IMG"
LOOP=$(losetup -f --show --sector-size 4096 "$IMG")

probe ours "$OURS"
probe loop "$LOOP"

out ""
out "report saved: $REPORT"
