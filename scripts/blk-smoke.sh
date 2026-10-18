#!/usr/bin/env bash
# blk-smoke.sh: end-to-end smoke test of taso-blkd (block log spike).
#
# Proves the I/O path through real ublk devices: ext4 on a branch, a Seal
# taken under fsfreeze, a fork of that Seal seeing the sealed bytes while
# the branch moves on, fsck clean on both, and everything still there
# after the daemon is restarted on the same log.
#
#   sudo scripts/blk-smoke.sh [path/to/taso-blkd]     (default target/release/taso-blkd)
#
# Touches, and nothing else:
#   /var/lib/taso-blk/smoke.log, smoke.err   (removed at start, kept after)
#   /run/taso-blk-smoke.sock
#   /mnt/blk-b1, /mnt/blk-b2                 (mounted, then unmounted)
#   the /dev/ublkb* devices the daemon creates for this run
#
# Device paths come only from the daemon's answers.  Prints PASS/FAIL per
# check; exit 0 only if every check passed.
#
# BLK_SMOKE_NO_UBLK=1 skips the ublk module check; it exists to test this
# script with a stand-in daemon on a machine without ublk.

set -euo pipefail

BLKD=${1:-target/release/taso-blkd}
DIR=/var/lib/taso-blk
LOG=$DIR/smoke.log
ERR=$DIR/smoke.err
SOCK=/run/taso-blk-smoke.sock
M1=/mnt/blk-b1
M2=/mnt/blk-b2

DAEMON_PID=
FAILS=0

say()  { printf '== %s\n' "$*"; }
die()  { printf 'ABORT: %s\n' "$*" >&2; exit 2; }
check() { # check NAME EXPECTED ACTUAL
    if [[ "$2" == "$3" ]]; then
        printf 'PASS  %s\n' "$1"
    else
        printf 'FAIL  %s: expected [%s], got [%s]\n' "$1" "$2" "$3"
        FAILS=$((FAILS + 1))
    fi
}

# One command to the daemon; prints the answer without "ok"; aborts on "err".
blk() {
    local answer
    answer=$(python3 -c '
import socket, sys
s = socket.socket(socket.AF_UNIX)
s.settimeout(30)
s.connect(sys.argv[1])
s.sendall((" ".join(sys.argv[2:]) + "\n").encode())
print(s.makefile().readline().strip())
' "$SOCK" "$@") || die "daemon did not answer: $*"
    case "$answer" in
        "ok")    ;;
        "ok "*)  printf '%s\n' "${answer#ok }" ;;
        *)       die "daemon: $* -> $answer" ;;
    esac
}

start_daemon() {
    "$BLKD" "$LOG" "$SOCK" 2>>"$ERR" &
    DAEMON_PID=$!
    for _ in $(seq 50); do
        [[ -S "$SOCK" ]] && return 0
        kill -0 "$DAEMON_PID" 2>/dev/null || die "daemon exited; see $ERR"
        sleep 0.1
    done
    die "daemon socket did not appear in 5 s"
}

stop_daemon() {
    blk quit >/dev/null
    wait "$DAEMON_PID" || die "daemon exited with an error; see $ERR"
    DAEMON_PID=
}

wait_dev() {
    for _ in $(seq 50); do
        [[ -b "$1" ]] && return 0
        sleep 0.1
    done
    die "device $1 did not appear in 5 s"
}

# e2fsck's exit code, read-only (0 = clean).
fsck_rc() {
    local rc=0
    e2fsck -fn "$1" >/dev/null 2>&1 || rc=$?
    echo "$rc"
}

# Mount $1 on $2 and confirm the mount really is that device.
mount_on() {
    mount "${@:3}" "$1" "$2"
    [[ "$(findmnt -n -o SOURCE --mountpoint "$2")" == "$1" ]] || die "$2 is not mounted from $1"
}

cleanup() {
    local rc=$?
    set +e
    fsfreeze -u "$M1" 2>/dev/null
    mountpoint -q "$M2" && umount "$M2"
    mountpoint -q "$M1" && umount "$M1"
    if [[ -n "$DAEMON_PID" ]] && kill -0 "$DAEMON_PID" 2>/dev/null; then
        # In a subshell, so a failed answer cannot exit this trap early.
        (blk quit) >/dev/null 2>&1 || kill "$DAEMON_PID"
        wait "$DAEMON_PID" 2>/dev/null
    fi
    exit "$rc"
}
trap cleanup EXIT

# ---- preflight -------------------------------------------------------------
[[ $EUID -eq 0 ]] || die "run as root"
[[ -x "$BLKD" ]] || die "no daemon at $BLKD (cargo build --release -p taso-blk)"
if [[ "${BLK_SMOKE_NO_UBLK:-}" != 1 ]]; then
    modprobe ublk_drv
    [[ -c /dev/ublk-control ]] || die "/dev/ublk-control missing"
fi
for m in "$M1" "$M2"; do
    mkdir -p "$m"
    ! mountpoint -q "$m" || die "$m is already a mount point"
done
[[ ! -S "$SOCK" ]] || die "$SOCK exists: another smoke run's daemon? (pgrep -x taso-blkd)"
mkdir -p "$DIR"
rm -f "$LOG" "$ERR"

# ---- run 1: write, seal, fork ----------------------------------------------
say "run 1: daemon $BLKD, log $LOG"
start_daemon

ROOT=$(blk root)
read -r BR1 DEV1 <<<"$(blk fork "$ROOT")"
say "root $ROOT; branch $BR1 on $DEV1"
wait_dev "$DEV1"

mkfs.ext4 -q -F -E nodiscard "$DEV1"
mount_on "$DEV1" "$M1"
echo hello >"$M1/a"
sync

fsfreeze -f "$M1"
SEAL=$(blk seal "$BR1")
fsfreeze -u "$M1"
say "sealed $BR1 as $SEAL"

echo changed >"$M1/a"
sync

read -r BR2 DEV2 <<<"$(blk fork "$SEAL")"
say "fork of $SEAL: branch $BR2 on $DEV2"
wait_dev "$DEV2"
mount_on "$DEV2" "$M2"

check "fork sees the sealed bytes" hello "$(cat "$M2/a")"
check "branch moved on after the seal" changed "$(cat "$M1/a")"

echo forked >"$M2/b"
sync
check "a write in the fork stays out of the branch" absent "$([[ -e $M1/b ]] && echo present || echo absent)"

say "stats: $(blk stats)"
umount "$M2"
umount "$M1"
check "fsck $BR1 ($DEV1)" 0 "$(fsck_rc "$DEV1")"
check "fsck $BR2 ($DEV2)" 0 "$(fsck_rc "$DEV2")"
stop_daemon

# ---- run 2: restart on the same log ----------------------------------------
say "run 2: restart on the same log"
start_daemon
check "clean quit leaves nothing to cut" "0 bytes cut" "$(grep -o '[0-9]* bytes cut' "$ERR" | tail -n 1)"

DEV1=$(blk attach "$BR1")
DEV2=$(blk attach "$BR2")
say "reattached $BR1 on $DEV1, $BR2 on $DEV2"
wait_dev "$DEV1"
wait_dev "$DEV2"
check "fsck $BR1 after restart" 0 "$(fsck_rc "$DEV1")"
check "fsck $BR2 after restart" 0 "$(fsck_rc "$DEV2")"

mount_on "$DEV1" "$M1" -o ro
mount_on "$DEV2" "$M2" -o ro
check "branch after restart" changed "$(cat "$M1/a")"
check "fork after restart" hello "$(cat "$M2/a")"
check "fork's own file after restart" forked "$(cat "$M2/b")"
umount "$M2"
umount "$M1"

say "stats: $(blk stats)"
stop_daemon

echo
if [[ $FAILS -eq 0 ]]; then
    echo "ALL PASS"
else
    echo "$FAILS FAILED (daemon log: $ERR)"
    exit 1
fi
