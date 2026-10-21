#!/usr/bin/env bash
# blk-contract.sh: what taso-blkd's device tells Linux about itself,
# measured (the device contract, Taso_contract_device_2026-10-20, §6).
#
# The contract's tables were read from the code; this fills their
# "measured" column.  On one of our devices and, for comparison, on a loop
# device with 4 KiB sectors:
#   1. every limit the device reports (/sys/block/<dev>/queue)
#   2. what mkfs.ext4 makes of it (block size, RAID stride / stripe width)
#   3. ext4's mb_max_linear_groups, mounted with the device marked
#      non-rotational and again marked rotational, its own value put back
#      after (the candidate mechanism for xfstests generic/223 and /347,
#      contract §5.2 (a))
#   4. ours only: the daemon's fdatasync count before and after 100 small
#      writes, each followed by fsync (flushes reach the store, §2)
#
# Predictions (written before the first run, 2026-10-21):
#   C1  ours: logical 4096, physical 4096, minimum_io 4096, optimal_io 4096,
#       max_hw_sectors_kb 512, write_cache "write back", fua 1, rotational 0,
#       discard_granularity 4096
#   C2  mkfs.ext4 on ours: block size 4096, no RAID stride or stripe width
#   C3  mb_max_linear_groups: 0 when not rotational, non-zero when
#       rotational; on ours and on loop alike
#   C4  syncs rise by at least 100 over the 100 fsyncs
#
#   scripts/blk-contract.sh          (as root, from the repository root)
#
# Touches, and nothing else:
#   /var/lib/taso-blk/contract.log, .log.ckpt, .err (removed at start and end)
#   /var/lib/taso-blk/contract-loop.img  (sparse 8 GiB, removed at the end)
#   /run/taso-blk-contract.sock          (its own daemon; the installed one
#                                         at /run/taso/blk.sock is not used)
#   /mnt/blk-contract                    (mounted, unmounted)
#   one /dev/ublkb* device its daemon creates, one loop device
# Prints the report; also saved to /var/lib/taso-blk/contract-report.txt.
#
# CONTRACT_NO_UBLK=1 measures the loop device only (a machine without
# ublk, to try the script); CONTRACT_BLKD=path runs that daemon instead of
# building one.

set -euo pipefail

DIR=/var/lib/taso-blk
LOG=$DIR/contract.log
ERR=$DIR/contract.err
SOCK=/run/taso-blk-contract.sock
IMG=$DIR/contract-loop.img
MNT=/mnt/blk-contract
REPORT=$DIR/contract-report.txt
BLKD=${CONTRACT_BLKD:-target/release/taso-blkd}
NO_UBLK=${CONTRACT_NO_UBLK:-0}

DAEMON_PID=
LOOP=
MISSES=0

say() { printf '== %s\n' "$*" | tee -a "$REPORT"; }
out() { printf '%s\n' "$*" | tee -a "$REPORT"; }
die() { printf 'ABORT: %s\n' "$*" >&2; exit 2; }
check() { # check NAME GOT WANT
    if [[ "$2" == "$3" ]]; then
        out "  $1 = $2"
    else
        out "  $1 = $2   MISSED (predicted $3)"
        MISSES=$((MISSES + 1))
    fi
}

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
    [[ -n "$LOOP" ]] && losetup -d "$LOOP"
    rm -f "$IMG"
    if [[ -n "$DAEMON_PID" ]] && kill -0 "$DAEMON_PID" 2>/dev/null; then
        (blk quit) >/dev/null 2>&1 || kill "$DAEMON_PID"
        wait "$DAEMON_PID" 2>/dev/null
    fi
    rm -f "$LOG" "$LOG.ckpt"
    rmdir "$MNT" 2>/dev/null
    exit "$rc"
}
trap cleanup EXIT

q() { cat "/sys/block/$1/queue/$2" 2>/dev/null || echo -; }

# 1. Every limit, as Linux shows it.
limits() { # limits DEVNAME
    local f
    for f in logical_block_size physical_block_size minimum_io_size optimal_io_size \
        max_hw_sectors_kb max_sectors_kb write_cache fua rotational nr_requests \
        discard_granularity discard_max_bytes write_zeroes_max_bytes; do
        out "  $f = $(q "$1" "$f")"
    done
}

# 2 and 3.  mkfs, then mb_max_linear_groups with the device marked
# non-rotational and marked rotational; its own value is put back after.
# (Both settings explicitly: a loop device may start as either, and an
# "as is" reading compared with itself proves nothing.)
linear_at() { # linear_at DEVPATH NAME ROTATIONAL
    echo "$3" >"/sys/block/$2/queue/rotational"
    [[ "$(q "$2" rotational)" == "$3" ]] || die "$2: rotational did not take $3"
    mount -o discard "$1" "$MNT"
    cat "/sys/fs/ext4/$2/mb_max_linear_groups" 2>/dev/null || echo -
    umount "$MNT"
}
ext4() { # ext4 DEVPATH: sets STRIPE, LINEAR_0, LINEAR_1
    local dev=$1 name rot0
    name=$(basename "$(readlink -f "$dev")")
    mkfs.ext4 -q -F "$dev"
    out "  mkfs.ext4: $(dumpe2fs -h "$dev" 2>/dev/null | grep -E '^(Block size|RAID stride|RAID stripe width):' | tr -s ' ' | tr '\n' ';' | sed 's/;$//')"
    if dumpe2fs -h "$dev" 2>/dev/null | grep -qE '^RAID (stride|stripe width):'; then
        STRIPE=yes
    else
        STRIPE=no
    fi
    rot0=$(q "$name" rotational)
    LINEAR_0=$(linear_at "$dev" "$name" 0)
    LINEAR_1=$(linear_at "$dev" "$name" 1)
    echo "$rot0" >"/sys/block/$name/queue/rotational"
    out "  mb_max_linear_groups: $LINEAR_0 non-rotational, $LINEAR_1 rotational (device's own: rotational $rot0, put back)"
}

# ---- preflight ---------------------------------------------------------------
[[ $EUID -eq 0 ]] || die "run as root"
[[ -f Cargo.toml && -d crates/taso-blk ]] || die "run from the repository root"
for c in mkfs.ext4 dumpe2fs losetup mount python3; do command -v "$c" >/dev/null || die "$c missing"; done
if [[ "$NO_UBLK" != 1 ]]; then
    modprobe ublk_drv
    [[ -c /dev/ublk-control ]] || die "/dev/ublk-control missing"
fi
[[ ! -S "$SOCK" ]] || die "$SOCK exists: another run's daemon? (pgrep -af 'taso-blkd.*contract')"
[[ ! -e "$IMG" ]] || die "$IMG exists from an earlier run (losetup -a; then remove it)"
mkdir -p "$DIR" "$MNT"
! mountpoint -q "$MNT" || die "$MNT is already a mount point"

if [[ "$NO_UBLK" != 1 && -z "${CONTRACT_BLKD:-}" ]]; then
    command -v cargo >/dev/null || PATH=/root/.cargo/bin:$PATH
    cargo build -q --release -p taso-blk
fi
[[ "$NO_UBLK" == 1 || -x "$BLKD" ]] || die "no daemon at $BLKD"

: >"$REPORT"
out "blk-contract $(date -Is); kernel $(uname -r); taso $(git rev-parse --short HEAD 2>/dev/null || echo ?)"

# ---- ours --------------------------------------------------------------------
if [[ "$NO_UBLK" != 1 ]]; then
    rm -f "$LOG" "$ERR" "$LOG.ckpt"
    "$BLKD" "$LOG" "$SOCK" --size-gib 8 --compact-pct 0 2>>"$ERR" &
    DAEMON_PID=$!
    for _ in $(seq 100); do [[ -S "$SOCK" ]] && break; sleep 0.1; done
    [[ -S "$SOCK" ]] || die "daemon socket did not appear; see $ERR"
    ROOT=$(blk root)
    read -r _ OURS <<<"$(blk fork "$ROOT" contract-ours)"
    for _ in $(seq 50); do [[ -b "$OURS" ]] && break; sleep 0.1; done
    [[ -b "$OURS" ]] || die "device $OURS did not appear"
    N=$(basename "$OURS")

    say "ours: $OURS (1. limits)"
    limits "$N"
    say "ours: C1, against the declared values"
    check logical_block_size "$(q "$N" logical_block_size)" 4096
    check physical_block_size "$(q "$N" physical_block_size)" 4096
    check minimum_io_size "$(q "$N" minimum_io_size)" 4096
    check optimal_io_size "$(q "$N" optimal_io_size)" 4096
    check max_hw_sectors_kb "$(q "$N" max_hw_sectors_kb)" 512
    check write_cache "$(q "$N" write_cache)" "write back"
    check fua "$(q "$N" fua)" 1
    check rotational "$(q "$N" rotational)" 0
    check discard_granularity "$(q "$N" discard_granularity)" 4096

    say "ours: 2. and 3. ext4"
    ext4 "$OURS"
    check "C2 RAID stride/stripe set" "$STRIPE" no
    OURS_LINEAR=("$LINEAR_0" "$LINEAR_1")

    say "ours: 4. flushes reach the store"
    mount -o discard "$OURS" "$MNT"
    before=$(blk stats | tr ' ' '\n' | sed -n 's/^syncs=//p')
    for i in $(seq 100); do
        dd if=/dev/urandom of="$MNT/f$i" bs=4k count=1 conv=fsync status=none
    done
    after=$(blk stats | tr ' ' '\n' | sed -n 's/^syncs=//p')
    umount "$MNT"
    out "  syncs: $before before, $after after 100 fsyncs (+$((after - before)))"
    check "C4 syncs rose by >= 100" "$([[ $((after - before)) -ge 100 ]] && echo yes || echo no)" yes
fi

# ---- loop, for comparison ----------------------------------------------------
truncate -s 8G "$IMG"
LOOP=$(losetup -f --show --sector-size 4096 "$IMG")
L=$(basename "$LOOP")
say "loop: $LOOP, 4 KiB sectors (1. limits)"
limits "$L"
say "loop: 2. and 3. ext4"
ext4 "$LOOP"

say "C3: mb_max_linear_groups, 0 as non-rotational, non-zero rotational"
nonzero() { [[ "$1" =~ ^[0-9]+$ && "$1" != 0 ]] && echo yes || echo no; }
check "loop non-rotational" "$LINEAR_0" 0
check "loop rotational, non-zero" "$(nonzero "$LINEAR_1")" yes
if [[ "$NO_UBLK" != 1 ]]; then
    check "ours non-rotational" "${OURS_LINEAR[0]}" 0
    check "ours rotational, non-zero" "$(nonzero "${OURS_LINEAR[1]}")" yes
fi

say "$MISSES missed"
[[ $MISSES == 0 ]] || exit 1
