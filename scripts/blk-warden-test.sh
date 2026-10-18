#!/usr/bin/env bash
# blk-warden-test.sh: the Warden's BlkPool on real devices (adoption step 4).
#
# Starts two taso-blkd on fresh logs (node A and node B), runs the ignored
# tests in crates/taso-warden/tests/blk_device.rs against them (Vessels
# born, sealed, forked, reopened and rolled back on ublk devices with ext4;
# a Vessel and its fork reborn on node B from shipped packs), then stops
# the daemons.
#
#   sudo scripts/blk-warden-test.sh            (from the repository root)
#
# Touches, and nothing else:
#   /var/lib/taso-blk/warden.log, warden.err, warden-b.log, warden-b.err
#                                              (removed at start, kept after)
#   /run/taso-blk-warden.sock, /run/taso-blk-warden-b.sock
#   /mnt/blk-warden and mounts under it        (all unmounted at the end)
#   the /dev/ublkb* devices the daemon creates for this run
#
# Packs go to a local directory, or to S3 when TASO_BLK_S3_ENDPOINT,
# TASO_BLK_S3_REGION, TASO_BLK_S3_BUCKET, TASO_BLK_S3_ACCESS_KEY_ID and
# TASO_BLK_S3_SECRET_KEY_FILE are set in the environment (passed through).
#
# BLK_WARDEN_NO_UBLK=1 skips the ublk module check (to try the script's
# own paths on a machine without ublk; the test then fails at the first
# device, and the cleanup is what is being tried).

set -euo pipefail

DIR=/var/lib/taso-blk
LOG=$DIR/warden.log
ERR=$DIR/warden.err
SOCK=/run/taso-blk-warden.sock
LOG_B=$DIR/warden-b.log
ERR_B=$DIR/warden-b.err
SOCK_B=/run/taso-blk-warden-b.sock
MNT=/mnt/blk-warden
BLKD=target/release/taso-blkd

DAEMON_PID=
DAEMON_B_PID=

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
    for pair in "$DAEMON_PID:$SOCK" "$DAEMON_B_PID:$SOCK_B"; do
        pid=${pair%%:*} sock=${pair#*:}
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            python3 -c '
import socket, sys
s = socket.socket(socket.AF_UNIX); s.settimeout(30); s.connect(sys.argv[1])
s.sendall(b"quit\n"); s.makefile().readline()' "$sock" 2>/dev/null || kill "$pid"
            wait "$pid" 2>/dev/null
        fi
    done
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
[[ ! -S "$SOCK_B" ]] || die "$SOCK_B exists: another run's daemon? (pgrep -x taso-blkd)"

say "building"
cargo build -q --release -p taso-blk
cargo test -q -p taso-warden --test blk_device --no-run

rm -f "$LOG" "$ERR" "$LOG_B" "$ERR_B"
"$BLKD" "$LOG" "$SOCK" 2>>"$ERR" &
DAEMON_PID=$!
"$BLKD" "$LOG_B" "$SOCK_B" 2>>"$ERR_B" &
DAEMON_B_PID=$!
for _ in $(seq 100); do [[ -S "$SOCK" && -S "$SOCK_B" ]] && break; sleep 0.1; done
[[ -S "$SOCK" ]] || die "daemon socket did not appear; see $ERR"
[[ -S "$SOCK_B" ]] || die "node B daemon socket did not appear; see $ERR_B"
say "node A: taso-blkd on $SOCK (log $LOG); node B: $SOCK_B (log $LOG_B); mounts under $MNT"

status=0
TASO_BLK_SOCKET=$SOCK TASO_BLK_SOCKET_B=$SOCK_B TASO_BLK_MOUNTS=$MNT \
    cargo test -q -p taso-warden --test blk_device -- --ignored --test-threads=1 || status=$?

if [[ $status -eq 0 ]]; then
    echo "BLKPOOL PASS: Vessels born, sealed, forked, reopened and rolled back on real devices; reborn on node B from packs"
else
    echo "BLKPOOL FAIL (test exit $status; daemon logs: $ERR, $ERR_B)"
    exit 1
fi
