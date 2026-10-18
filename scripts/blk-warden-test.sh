#!/usr/bin/env bash
# blk-warden-test.sh: the Warden's BlkPool on real devices (adoption step 4).
#
# Starts taso-blkd on a fresh log, runs the ignored test
# crates/taso-warden/tests/blk_device.rs against it (Vessels born, sealed,
# forked and reopened on ublk devices with ext4), then stops the daemon.
#
#   sudo scripts/blk-warden-test.sh            (from the repository root)
#
# Touches, and nothing else:
#   /var/lib/taso-blk/warden.log, warden.err   (removed at start, kept after)
#   /run/taso-blk-warden.sock
#   /mnt/blk-warden and mounts under it        (all unmounted at the end)
#   the /dev/ublkb* devices the daemon creates for this run
#
# BLK_WARDEN_NO_UBLK=1 skips the ublk module check (to try the script's
# own paths on a machine without ublk; the test then fails at the first
# device, and the cleanup is what is being tried).

set -euo pipefail

DIR=/var/lib/taso-blk
LOG=$DIR/warden.log
ERR=$DIR/warden.err
SOCK=/run/taso-blk-warden.sock
MNT=/mnt/blk-warden
BLKD=target/release/taso-blkd

DAEMON_PID=

say() { printf '== %s\n' "$*"; }
die() { printf 'ABORT: %s\n' "$*" >&2; exit 2; }

# Mount points under $MNT, innermost first.
mounts_under() {
    awk -v root="$MNT" '$5 == root || index($5, root "/") == 1 { print length($5), $5 }' /proc/self/mountinfo \
        | sort -rn | cut -d' ' -f2-
}

cleanup() {
    local rc=$?
    set +e
    while read -r m; do
        [[ -n "$m" ]] || continue
        fsfreeze -u "$m" 2>/dev/null
        umount "$m" || umount -l "$m"
    done < <(mounts_under)
    if [[ -n "$DAEMON_PID" ]] && kill -0 "$DAEMON_PID" 2>/dev/null; then
        python3 -c '
import socket, sys
s = socket.socket(socket.AF_UNIX); s.settimeout(30); s.connect(sys.argv[1])
s.sendall(b"quit\n"); s.makefile().readline()' "$SOCK" 2>/dev/null || kill "$DAEMON_PID"
        wait "$DAEMON_PID" 2>/dev/null
    fi
    left=$(mounts_under | wc -l)
    [[ "$left" -eq 0 ]] || echo "WARNING: $left mounts left under $MNT"
    exit "$rc"
}
trap cleanup EXIT

[[ $EUID -eq 0 ]] || die "run as root"
[[ -f Cargo.toml && -d crates/taso-warden ]] || die "run from the repository root"
if [[ "${BLK_WARDEN_NO_UBLK:-}" != 1 ]]; then
    modprobe ublk_drv
    [[ -c /dev/ublk-control ]] || die "/dev/ublk-control missing"
fi
mkdir -p "$DIR" "$MNT"
[[ -z "$(mounts_under)" ]] || die "something is already mounted under $MNT"
[[ ! -S "$SOCK" ]] || die "$SOCK exists: another run's daemon? (pgrep -x taso-blkd)"

say "building"
cargo build -q --release -p taso-blk
cargo test -q -p taso-warden --test blk_device --no-run

rm -f "$LOG" "$ERR"
"$BLKD" "$LOG" "$SOCK" 2>>"$ERR" &
DAEMON_PID=$!
for _ in $(seq 100); do [[ -S "$SOCK" ]] && break; sleep 0.1; done
[[ -S "$SOCK" ]] || die "daemon socket did not appear; see $ERR"
say "taso-blkd on $SOCK, log $LOG; mounts under $MNT"

status=0
TASO_BLK_SOCKET=$SOCK TASO_BLK_MOUNTS=$MNT \
    cargo test -q -p taso-warden --test blk_device -- --ignored --test-threads=1 || status=$?

if [[ $status -eq 0 ]]; then
    echo "BLKPOOL PASS: Vessels born, sealed, forked and reopened on real devices"
else
    echo "BLKPOOL FAIL (test exit $status; daemon log: $ERR)"
    exit 1
fi
