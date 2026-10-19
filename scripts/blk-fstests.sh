#!/usr/bin/env bash
# blk-fstests.sh: correctness of the block-log device under real filesystem
# workloads (Phase 4 gate: "fsx/xfstests clean on ext4-over-ublk").
#
#   sudo scripts/blk-fstests.sh setup           install xfstests and what it needs
#   sudo scripts/blk-fstests.sh run [TESTS]     run everything (from the repo root)
#
# TESTS are xfstests arguments; the default is "-g quick" (about one to two
# hours).  Example for a short first try:  run generic/001 generic/013 ext4/001
#
# run, in order:
#   1 raw     fio writes with checksums to a raw device (4 KiB and 128 KiB,
#             two jobs at once), then discard and write-zeroes over random
#             data; then every block overwritten with other data while the
#             log is compacted twice, and once more when quiet; read back
#             and checked, then again after a daemon restart.
#   2 fsx     fsx on ext4 on our device: buffered with mmap, then O_DIRECT.
#   3 xfstests the TESTS with TEST_DEV and SCRATCH_DEV on our devices.
#   4 recheck every test that failed in 3 runs again on our devices, and on
#             loop devices (same size, 4 KiB sectors like ours) as the baseline.
#             A test failing on ours twice and passing on loop is OURS; one
#             passing the second time on ours is FLAKY; one failing on loop
#             too is not about our device (kernel, tools, environment).
# The daemon compacts by itself during 2 to 4 when garbage passes
# FST_COMPACT_PCT per cent of the log (default 25; 0 turns it off) and
# FST_COMPACT_MIN_MIB (default 256); the summary counts the compactions.
# Without compaction the log grows by everything written: the raw and fsx
# phases alone write more than 15 GiB.
# Exit 0 only if raw and fsx passed, no compaction failed, and no test is
# OURS.
#
# setup touches, and nothing else:
#   apt packages: automake bc e2fsprogs fio gawk gcc git libacl1-dev
#     libaio-dev libcap-dev libgdbm-dev libgdbm-compat-dev libtool
#     libtool-bin liburing-dev make psmisc python3 sed uuid-dev uuid-runtime
#     xfsprogs xfslibs-dev acl attr quota sqlite3 pkg-config, and, when the
#     archive has them: dbench dump indent keyutils linux-headers-$(uname -r)
#   /var/lib/taso-blk/xfstests   (xfstests v2026.05.17, built in place)
#   users fsgqa (with home), fsgqa2, 123456-fsgqa and group fsgqa, if missing
#   GNU coreutils in place of uutils, if the system has uutils (Ubuntu 25.10
#   and later): the compiler packages build-essential pulls in (gcc g++ make
#   libc6-dev dpkg-dev, those installed) marked manually installed, so no
#   autoremove takes them; then apt installs coreutils-from-gnu and removes
#   coreutils-from-uutils and build-essential (only a bundle; 26.04 makes it
#   depend on uutils), allowed with --allow-remove-essential; then the pin
#   /etc/apt/preferences.d/taso-gnu-coreutils so upgrades keep it.  Refused
#   (nothing changed) if apt would remove anything else.  Checked after:
#   ls reports GNU coreutils, and gcc still compiles.
# run touches, and nothing else:
#   /var/lib/taso-blk/fst.log, fst.err, fst.log.ckpt, fst.log.compact*
#                                       (removed at start, kept after)
#   /var/lib/taso-blk/fst-loop-test.img, fst-loop-scratch.img (removed at end)
#   /var/lib/taso-blk/fstests/<time>/   (results: summary.txt, the logs, the
#                                        daemon's log and the kernel's lines
#                                        from the run: daemon.err, dmesg.txt)
#   /run/taso-blk-fst.sock
#   /mnt/blk-fst and mounts under it    (all unmounted at the end)
#   the /dev/ublkb* devices the daemon creates, two loop devices in step 4
#
# Disk: xfstests writes a lot, and the log grows until a compaction.
# The run refuses to start with less than FST_MIN_FREE_GIB (default 20)
# free under /var/lib/taso-blk, and stops xfstests if it falls below
# FST_STOP_FREE_GIB (default 5).  The log's size and garbage are in the
# summary: they are measurements for compaction.
#
# ext4 is mounted -o discard everywhere (fsx, and MOUNT_OPTIONS for
# xfstests), as the Warden mounts Vessels: without it ext4 never tells the
# device which blocks it freed, and live data grows toward the device size.
#
# xfstests is written against GNU coreutils; with uutils (Ubuntu 26.04's
# default) 271 of the quick tests failed on an unsupported option before
# testing anything (taso-test, 2026-10-18).  run refuses without GNU
# coreutils; setup installs them.
#
# FST_IO_KIB=N runs the daemon with --io-kib N (largest request; it sets
# the I/O sizes the device reports, which mkfs.ext4 turns into stripe
# geometry).  FST_MKFS_OPTIONS passes mkfs options to xfstests
# (MKFS_OPTIONS), e.g. "-E stride=128,stripe_width=128".
#
# FST_ROTATIONAL=0|1 sets the rotational flag of our two devices, and
# FST_LOOP_ROTATIONAL=0|1 that of the loop devices, for the run (to test
# whether ext4's allocation on non-rotational devices decides a result).
#
# FST_ONLY_XFSTESTS=1 skips raw and fsx, to look into single tests (with
# FST_COMPACT_PCT=0 for one without compaction); the verdict then says
# partial.
#
# FST_NO_UBLK=1 skips the ublk module check, and FST_BLKD=path runs that
# daemon instead of building one (both to try the script's own paths with a
# stand-in daemon on a machine without ublk).

set -euo pipefail

DIR=/var/lib/taso-blk
XFS=$DIR/xfstests
XFS_TAG=v2026.05.17
XFS_COMMIT=ffc8bad17e5b2f56e48dbac43f7c5ae8ac368fe5
XFS_URLS=(https://git.kernel.org/pub/scm/fs/xfs/xfstests-dev.git https://github.com/kdave/xfstests.git)
LOG=$DIR/fst.log
ERR=$DIR/fst.err
SOCK=/run/taso-blk-fst.sock
MNT=/mnt/blk-fst
LOOP_TEST_IMG=$DIR/fst-loop-test.img
LOOP_SCRATCH_IMG=$DIR/fst-loop-scratch.img
BLKD=${FST_BLKD:-target/release/taso-blkd}
SIZE_GIB=8
MIN_FREE=${FST_MIN_FREE_GIB:-20}
COMPACT_PCT=${FST_COMPACT_PCT:-25}
IO_KIB=${FST_IO_KIB:-}
COMPACT_MIN=${FST_COMPACT_MIN_MIB:-256}
STOP_FREE=${FST_STOP_FREE_GIB:-5}

say() { printf '== %s\n' "$*"; }
die() { printf 'ABORT: %s\n' "$*" >&2; exit 2; }

# True if the core tools are GNU coreutils (xfstests' scripts assume them).
# shellcheck disable=SC2012  # ls --version, not a listing
coreutils_version() { ls --version 2>/dev/null | head -n 1; }
gnu_coreutils() { coreutils_version | grep -q 'GNU coreutils'; }

mode=${1:-}
[[ "$mode" == setup || "$mode" == run ]] || { echo "usage: $0 setup | run [xfstests arguments]" >&2; exit 64; }
shift
[[ $EUID -eq 0 ]] || die "run as root"

# ---- setup -----------------------------------------------------------------
if [[ "$mode" == setup ]]; then
    export DEBIAN_FRONTEND=noninteractive
    say "installing packages"
    apt-get update -q
    apt-get install -y -q automake bc e2fsprogs fio gawk gcc git libacl1-dev \
        libaio-dev libcap-dev libgdbm-dev libgdbm-compat-dev libtool \
        libtool-bin liburing-dev make psmisc python3 sed uuid-dev uuid-runtime \
        xfsprogs xfslibs-dev acl attr quota sqlite3 pkg-config
    for p in dbench dump indent keyutils "linux-headers-$(uname -r)"; do
        apt-get install -y -q "$p" >/dev/null 2>&1 && echo "installed $p" \
            || echo "not installed: $p (optional; tests needing it will not run)"
    done

    if ! gnu_coreutils; then
        say "GNU coreutils in place of $(coreutils_version)"
        swap=(coreutils-from-gnu coreutils-from-uutils-)
        removes=$(apt-get install -s "${swap[@]}" | sed -n 's/^Remv \([^ ]*\).*/\1/p' \
            | grep -vx -e coreutils-from-uutils -e build-essential || true)
        [[ -z "$removes" ]] || die "the coreutils swap would also remove: $removes (nothing changed; decide by hand)"
        keep=()
        for p in gcc g++ make libc6-dev dpkg-dev; do
            dpkg-query -W -f='${Status}' "$p" 2>/dev/null | grep -q 'install ok installed' && keep+=("$p")
        done
        [[ ${#keep[@]} -eq 0 ]] || apt-mark manual "${keep[@]}"
        apt-get install -y -q --allow-remove-essential "${swap[@]}"
        printf 'Package: coreutils-from-uutils\nPin: release a=*\nPin-Priority: -10\n' >/etc/apt/preferences.d/taso-gnu-coreutils
        hash -r
        gnu_coreutils || die "coreutils-from-gnu installed, but ls still reports: $(coreutils_version)"
        echo 'int main(void) { return 0; }' | gcc -x c - -o /dev/null || die "gcc no longer compiles after the coreutils swap"
        echo "now: $(coreutils_version); gcc compiles; kept as manually installed: ${keep[*]}"
    fi

    if [[ ! -d "$XFS/.git" ]]; then
        mkdir -p "$DIR"
        cloned=
        for url in "${XFS_URLS[@]}"; do
            say "cloning xfstests $XFS_TAG from $url"
            if git -c advice.detachedHead=false clone -q --depth 1 --branch "$XFS_TAG" "$url" "$XFS"; then cloned=1; break; fi
            rm -rf "$XFS"
        done
        [[ -n "$cloned" ]] || die "could not clone xfstests"
    fi
    got=$(git -C "$XFS" rev-parse HEAD)
    [[ "$got" == "$XFS_COMMIT" ]] || die "xfstests at $got, expected $XFS_COMMIT ($XFS_TAG); remove $XFS and run setup again"

    say "building xfstests"
    make -C "$XFS" -j"$(nproc)" >"$DIR/xfstests-build.log" 2>&1 \
        || die "xfstests build failed; see $DIR/xfstests-build.log"

    say "test users"
    getent passwd fsgqa >/dev/null || useradd -m fsgqa
    getent group fsgqa >/dev/null || groupadd fsgqa
    getent passwd fsgqa2 >/dev/null || useradd fsgqa2
    getent passwd 123456-fsgqa >/dev/null || useradd 123456-fsgqa \
        || echo "could not add 123456-fsgqa (optional)"

    [[ -x "$XFS/check" && -x "$XFS/ltp/fsx" ]] || die "build finished but check or ltp/fsx is missing"
    echo "SETUP DONE: xfstests $XFS_TAG in $XFS"
    exit 0
fi

# ---- run: helpers ------------------------------------------------------------
TESTS=("$@")
[[ ${#TESTS[@]} -gt 0 ]] || TESTS=(-g quick)

DAEMON_PID=
DMESG_START=0
CHECK_PID=
WATCH_PID=
LOOPS=()
FAILS=0
RES=

check() { # check NAME EXPECTED ACTUAL
    if [[ "$2" == "$3" ]]; then
        printf 'PASS  %s\n' "$1" | tee -a "$RES/summary.txt"
    else
        printf 'FAIL  %s: expected [%s], got [%s]\n' "$1" "$2" "$3" | tee -a "$RES/summary.txt"
        FAILS=$((FAILS + 1))
    fi
}

# One command to the daemon; prints its whole answer line.
blk_raw() {
    python3 -c '
import socket, sys
s = socket.socket(socket.AF_UNIX)
s.settimeout(600)
s.connect(sys.argv[1])
s.sendall((" ".join(sys.argv[2:]) + "\n").encode())
print(s.makefile().readline().strip())
' "$SOCK" "$@"
}

# One command to the daemon; prints the answer without "ok"; aborts on "err".
blk() {
    local answer
    answer=$(blk_raw "$@") || die "daemon did not answer: $*"
    case "$answer" in
        "ok")    ;;
        "ok "*)  printf '%s\n' "${answer#ok }" ;;
        *)       die "daemon: $* -> $answer" ;;
    esac
}

start_daemon() {
    "$BLKD" "$LOG" "$SOCK" --size-gib "$SIZE_GIB" ${IO_KIB:+--io-kib "$IO_KIB"} \
        --compact-pct "$COMPACT_PCT" --compact-min-mib "$COMPACT_MIN" 2>>"$ERR" &
    DAEMON_PID=$!
    for _ in $(seq 100); do
        [[ -S "$SOCK" ]] && return 0
        kill -0 "$DAEMON_PID" 2>/dev/null || die "daemon exited; see $ERR"
        sleep 0.1
    done
    die "daemon socket did not appear in 10 s"
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

# A block device's rotational flag (what it tells the kernel it is), read
# and set through sysfs.  Device-mapper devices made on it later inherit it.
rotational() { cat "/sys/block/$(basename "$1")/queue/rotational"; }
set_rotational() { # set_rotational DEVICE 0|1
    [[ "$2" == 0 || "$2" == 1 ]] || die "rotational must be 0 or 1, not $2"
    echo "$2" >"/sys/block/$(basename "$1")/queue/rotational"
    [[ "$(rotational "$1")" == "$2" ]] || die "$1 did not take rotational=$2"
}

free_gib() { df --output=avail -BG "$DIR" | tail -n 1 | tr -dc 0-9; }

# Mount points under $MNT, innermost first.
mounts_under() {
    awk -v root="$MNT" '$5 == root || index($5, root "/") == 1 { print length($5), $5 }' /proc/self/mountinfo \
        | sort -rn | cut -d' ' -f2-
}

unmount_all() {
    local m
    while read -r m; do
        [[ -n "$m" ]] || continue
        umount "$m" || umount -l "$m"
    done < <(mounts_under)
}

# The daemon's counters, and the live bytes (log minus garbage) in MiB.
note_stats() {
    local st log garbage
    st=$(blk stats)
    log=$(tr ' ' '\n' <<<"$st" | sed -n 's/^log_bytes=//p')
    garbage=$(tr ' ' '\n' <<<"$st" | sed -n 's/^garbage_bytes=//p')
    echo "live $(( (${log:-0} - ${garbage:-0}) >> 20 )) MiB, log $(( ${log:-0} >> 20 )) MiB ($1): $st" | tee -a "$RES/summary.txt"
}

# Keep the evidence with the results: the daemon's log and the kernel's
# lines from this run (the next run starts both afresh).
keep_evidence() {
    [[ -n "$RES" && -d "$RES" ]] || return 0
    [[ -f "$ERR" ]] && cp "$ERR" "$RES/daemon.err"
    dmesg 2>/dev/null | tail -n +"$((DMESG_START + 1))" >"$RES/dmesg.txt"
}

cleanup() {
    local rc=$?
    set +e
    [[ -n "$WATCH_PID" ]] && kill "$WATCH_PID" 2>/dev/null
    if [[ -n "$CHECK_PID" ]] && kill -0 "$CHECK_PID" 2>/dev/null; then
        kill -TERM -- "-$CHECK_PID" 2>/dev/null
        wait "$CHECK_PID" 2>/dev/null
    fi
    unmount_all
    for l in "${LOOPS[@]}"; do losetup -d "$l"; done
    rm -f "$LOOP_TEST_IMG" "$LOOP_SCRATCH_IMG"
    if [[ -n "$DAEMON_PID" ]] && kill -0 "$DAEMON_PID" 2>/dev/null; then
        (blk quit) >/dev/null 2>&1 || kill "$DAEMON_PID"
        wait "$DAEMON_PID" 2>/dev/null
    fi
    left=$(mounts_under | wc -l)
    [[ "$left" -eq 0 ]] || echo "WARNING: $left mounts left under $MNT"
    keep_evidence
    exit "$rc"
}
trap cleanup EXIT

# Run xfstests on TEST/SCRATCH devices; the failed tests go to $4.
#   xfstests NAME TEST_DEV SCRATCH_DEV FAILED_FILE TEST...
xfstests() {
    local name=$1 tdev=$2 sdev=$3 failed=$4
    shift 4
    local cfg=$RES/$name.config out=$RES/$name.out
    mkdir -p "$MNT/test" "$MNT/scratch" "$RES/$name"
    cat >"$cfg" <<EOF
export FSTYP=ext4
export TEST_DEV=$tdev
export TEST_DIR=$MNT/test
export SCRATCH_DEV=$sdev
export SCRATCH_MNT=$MNT/scratch
export MOUNT_OPTIONS="-o discard"
export TEST_FS_MOUNT_OPTS="-o discard"
EOF
    # Only when given: unset, xfstests keeps its own default.
    [[ -z "${FST_MKFS_OPTIONS:-}" ]] || printf 'export MKFS_OPTIONS="%s"\n' "$FST_MKFS_OPTIONS" >>"$cfg"
    mkfs.ext4 -q -F "$tdev"
    say "xfstests ($name): $* (output in $out)"
    # In its own session (setsid execs in place: its pid is the session's
    # and the process group's), so the disk watch and cleanup can stop it all.
    ( cd "$XFS" && HOST_OPTIONS=$cfg RESULT_BASE=$RES/$name exec setsid ./check "$@" ) >"$out" 2>&1 &
    CHECK_PID=$!
    echo "$CHECK_PID" >"$RES/.check-pid"
    local rc=0
    wait "$CHECK_PID" || rc=$?
    CHECK_PID=
    rm -f "$RES/.check-pid"
    unmount_all
    grep -E '^(Ran|Not run|Failures|Passed all)' "$out" | sed "s/^/  $name: /" | tee -a "$RES/summary.txt" || true
    local n_ran n_notrun n_failed
    n_ran=$({ grep '^Ran:' "$out" || true; } | tail -n 1 | wc -w)
    n_notrun=$({ grep '^Not run:' "$out" || true; } | tail -n 1 | wc -w)
    n_failed=$({ grep '^Failures:' "$out" || true; } | tail -n 1 | wc -w)
    # Each count includes its label's words ("Ran:", "Not run:", "Failures:").
    n_ran=$(( n_ran > 0 ? n_ran - 1 : 0 )); n_notrun=$(( n_notrun > 1 ? n_notrun - 2 : 0 )); n_failed=$(( n_failed > 0 ? n_failed - 1 : 0 ))
    echo "  $name: $((n_ran - n_notrun - n_failed)) passed, $n_failed failed, $n_notrun not run (of $n_ran)" | tee -a "$RES/summary.txt"
    local unknown
    unknown=$(sed -n 's/ - unknown test, ignored$//p' "$out" | tr '\n' ' ')
    if [[ -n "$unknown" ]]; then
        echo "  $name: unknown tests, not run: $unknown" | tee -a "$RES/summary.txt"
        FAILS=$((FAILS + 1))
    fi
    { grep '^Failures:' "$out" || true; } | tail -n 1 | sed 's/^Failures: *//' | tr ' ' '\n' | sed '/^$/d' >"$failed"
    if ! grep -qE '^(Failures|Passed all)' "$out"; then
        echo "  $name: check ended without a summary (exit $rc); see $out" | tee -a "$RES/summary.txt"
        return 1
    fi
}

# ---- run: preflight ------------------------------------------------------------
[[ -f Cargo.toml && -d crates/taso-blk ]] || die "run from the repository root"
# sudo resets PATH; rustup installs cargo under the invoking user's home.
if [[ -z "${FST_BLKD:-}" ]] && ! command -v cargo >/dev/null; then
    for c in "${SUDO_USER:+$(getent passwd "$SUDO_USER" | cut -d: -f6)/.cargo/bin}" /root/.cargo/bin; do
        [[ -n "$c" && -x "$c/cargo" ]] && { PATH=$c:$PATH; break; }
    done
    command -v cargo >/dev/null || die "cargo not found (not in PATH, ~/.cargo/bin or /root/.cargo/bin)"
fi
[[ -x "$XFS/check" && -x "$XFS/ltp/fsx" ]] || die "xfstests not built in $XFS: run '$0 setup' first"
gnu_coreutils || die "the core tools are $(coreutils_version), not GNU coreutils, which xfstests assumes: run '$0 setup' (it switches to coreutils-from-gnu)"
if [[ "${FST_NO_UBLK:-}" != 1 ]]; then
    modprobe ublk_drv
    [[ -c /dev/ublk-control ]] || die "/dev/ublk-control missing"
fi
mkdir -p "$DIR" "$MNT"
[[ -z "$(mounts_under)" ]] || die "something is already mounted under $MNT"
[[ ! -S "$SOCK" ]] || die "$SOCK exists: another run's daemon? (pgrep -x taso-blkd)"
[[ ! -e "$LOOP_TEST_IMG" && ! -e "$LOOP_SCRATCH_IMG" ]] || die "loop images from an earlier run exist in $DIR (losetup -a; then remove them)"
# The previous run's log is this script's own, and no daemon holds it (the
# socket check above): removed before the space check, not after.
rm -f "$LOG" "$ERR" "$LOG.ckpt" "$LOG.compact" "$LOG.compact.ckpt"
free=$(free_gib)
[[ "$free" -ge "$MIN_FREE" ]] || die "only $free GiB free under $DIR (want $MIN_FREE; FST_MIN_FREE_GIB overrides)"

DMESG_START=$(dmesg 2>/dev/null | wc -l)
RES=$DIR/fstests/$(date +%Y%m%d-%H%M%S)
mkdir -p "$RES"
{
    echo "blk-fstests $(date -Is)"
    echo "kernel $(uname -r); taso $(git rev-parse --short HEAD 2>/dev/null || echo ?); xfstests $XFS_TAG"
    echo "tests: ${TESTS[*]}; devices ${SIZE_GIB} GiB; $free GiB free at start"
    echo "automatic compaction at ${COMPACT_PCT}% garbage and ${COMPACT_MIN} MiB (0%: off)"
    echo "device I/O size ${IO_KIB:-daemon default} KiB; mkfs options for xfstests: ${FST_MKFS_OPTIONS:-none}"
} | tee "$RES/summary.txt"

if [[ -z "${FST_BLKD:-}" ]]; then
    say "building taso-blkd"
    cargo build -q --release -p taso-blk
fi
[[ -x "$BLKD" ]] || die "no daemon at $BLKD"

rm -f "$LOG" "$ERR" "$LOG.ckpt"
start_daemon
ROOT=$(blk root)

# The disk watch, for the whole run: below FST_STOP_FREE_GIB it stops what
# is writing (xfstests, fio, fsx) before the log fills the disk.  A full
# disk poisons the store, which then refuses every write (correct, but the
# rest of the run would test nothing).
( while sleep 5; do
      # Once tripped it stays tripped: every writer that starts later in the
      # run is stopped too, until the run ends at its next disk check.
      if [[ -e "$RES/.disk-stop" || "$(free_gib)" -lt "$STOP_FREE" ]]; then
          [[ -e "$RES/.disk-stop" ]] || echo "disk below $STOP_FREE GiB free: stopping the run" | tee -a "$RES/summary.txt"
          touch "$RES/.disk-stop"
          pid=$(cat "$RES/.check-pid" 2>/dev/null || true)
          [[ -n "$pid" ]] && kill -TERM -- "-$pid" 2>/dev/null
          pkill -TERM -P $$ -x fio 2>/dev/null
          pkill -TERM -P $$ -x fsx 2>/dev/null
      fi
  done ) &
WATCH_PID=$!
disk_stopped() { [[ -e "$RES/.disk-stop" ]] && die "stopped: disk below $STOP_FREE GiB free (see $RES/summary.txt)"; return 0; }

if [[ "${FST_ONLY_XFSTESTS:-}" == 1 ]]; then
    echo "raw and fsx skipped (FST_ONLY_XFSTESTS=1): not a full result" | tee -a "$RES/summary.txt"
else

# ---- 1 raw -------------------------------------------------------------------
say "1 raw: fio with checksums, discard, write-zeroes"
read -r RAW RAWDEV <<<"$(blk fork "$ROOT" fst-raw)"
wait_dev "$RAWDEV"
fio_raw() { # fio_raw NAME SEED EXTRA... : the same two jobs; the seed picks the data
    fio --output="$RES/fio-$1.txt" --ioengine=libaio --direct=1 --iodepth=32 \
        --rw=randwrite --verify=crc32c --verify_fatal=1 --verify_state_save=0 --randrepeat=1 --randseed="$2" \
        --filename="$RAWDEV" \
        --name=small --bs=4k --offset=0 --size=1g \
        --name=large --bs=128k --offset=1g --size=2g "${@:3}"
}
# A compaction now; waits while the daemon's own one is running.
compact_now() {
    local answer
    for _ in $(seq 600); do
        answer=$(blk_raw compact) || die "daemon did not answer: compact"
        case "$answer" in
            "ok "*) printf '%s\n' "${answer#ok }"; return 0 ;;
            *"already running"*) sleep 1 ;;
            *) die "daemon: compact -> $answer" ;;
        esac
    done
    die "compact: the daemon's compaction still running after 600 s"
}
garbage() { blk stats | tr ' ' '\n' | sed -n 's/^garbage_bytes=//p'; }
rc=0; fio_raw write 4242 || rc=$?
check "raw: fio write and verify (4k and 128k, iodepth 32)" 0 "$rc"
disk_stopped
head -c $((256 << 20)) /dev/urandom | dd of="$RAWDEV" bs=1M seek=3072 oflag=direct status=none
blkdiscard -o $((3 << 30)) -l $((128 << 20)) "$RAWDEV"
blkdiscard -z -o $(((3 << 30) + (128 << 20))) -l $((128 << 20)) "$RAWDEV"
zeros() { cmp -s -n $((256 << 20)) -i $((3 << 30)):0 "$RAWDEV" /dev/zero && echo zeros || echo "not zeros"; }
check "raw: discard and write-zeroes read back as zeros" zeros "$(zeros)"
note_stats "after raw writes"

# Every block of the fio range again, with other data (another seed), while
# two compactions run: a stale block from before would fail the checksums.
( sleep 2; compact_now >"$RES/compact-1.txt"; sleep 2; compact_now >"$RES/compact-2.txt" ) 2>"$RES/compact-err.txt" &
COMPACT_PID=$!
rc=0; fio_raw overwrite 777 || rc=$?
crc=0; wait "$COMPACT_PID" || crc=$?
check "raw: fio overwrite and verify while compacting" 0 "$rc"
check "raw: two compactions under load answered ok" 0 "$crc"
echo "compactions under load: $(cat "$RES/compact-1.txt" 2>/dev/null) | $(cat "$RES/compact-2.txt" 2>/dev/null)" | tee -a "$RES/summary.txt"
note_stats "after the overwrite"
echo "compaction when quiet: $(compact_now)" | tee -a "$RES/summary.txt"
check "raw: no garbage after a quiet compaction" 0 "$(garbage)"
check "raw: zeros after compactions" zeros "$(zeros)"
blk detach "$RAW" >/dev/null
stop_daemon
start_daemon
check "raw: restart after a clean quit cuts nothing" "0 bytes cut" "$(grep -o '[0-9]* bytes cut' "$ERR" | tail -n 1)"
RAWDEV=$(blk attach "$RAW")
wait_dev "$RAWDEV"
rc=0; fio_raw verify 777 --verify_only || rc=$?
check "raw: fio verify after restart" 0 "$rc"
check "raw: zeros after restart" zeros "$(zeros)"
blk drop "$RAW" >/dev/null
disk_stopped

# ---- 2 fsx -------------------------------------------------------------------
say "2 fsx on ext4 on our device"
read -r FSXB FSXDEV <<<"$(blk fork "$ROOT" fst-fsx)"
wait_dev "$FSXDEV"
mkfs.ext4 -q -F "$FSXDEV"
mkdir -p "$MNT/fsx"
mount -o discard "$FSXDEV" "$MNT/fsx"
[[ "$(findmnt -n -o SOURCE --mountpoint "$MNT/fsx")" == "$FSXDEV" ]] || die "$MNT/fsx is not mounted from $FSXDEV"
rc=0; "$XFS/ltp/fsx" -q -N 200000 -S 1 -l $((64 << 20)) -o $((1 << 20)) "$MNT/fsx/buffered" >"$RES/fsx-buffered.txt" 2>&1 || rc=$?
check "fsx: 200000 ops, buffered and mmap" 0 "$rc"
rc=0; "$XFS/ltp/fsx" -q -Z -R -W -r 4096 -w 4096 -t 4096 -N 100000 -S 2 -l $((64 << 20)) -o $((1 << 20)) \
    "$MNT/fsx/direct" >"$RES/fsx-direct.txt" 2>&1 || rc=$?
check "fsx: 100000 ops, O_DIRECT" 0 "$rc"
umount "$MNT/fsx"
rc=0; e2fsck -fn "$FSXDEV" >"$RES/fsx-fsck.txt" 2>&1 || rc=$?
check "fsx: fsck clean" 0 "$rc"
note_stats "after fsx"
blk drop "$FSXB" >/dev/null
disk_stopped
fi

# ---- 3 xfstests on our devices -------------------------------------------------
read -r TB TDEV <<<"$(blk fork "$ROOT" fst-test)"
read -r SB SDEV <<<"$(blk fork "$ROOT" fst-scratch)"
wait_dev "$TDEV"
wait_dev "$SDEV"
if [[ -n "${FST_ROTATIONAL:-}" ]]; then
    set_rotational "$TDEV" "$FST_ROTATIONAL"
    set_rotational "$SDEV" "$FST_ROTATIONAL"
fi
echo "our devices: TEST $TDEV ($TB), SCRATCH $SDEV ($SB), rotational $(rotational "$TDEV")/$(rotational "$SDEV")" | tee -a "$RES/summary.txt"

rc=0; xfstests ours "$TDEV" "$SDEV" "$RES/failed-ours.txt" "${TESTS[@]}" || rc=$?
[[ $rc -eq 0 ]] || FAILS=$((FAILS + 1))
note_stats "after xfstests"
[[ ! -e "$RES/.disk-stop" ]] || FAILS=$((FAILS + 1))

# ---- 4 recheck failures: ours again, and loop ------------------------------------
mapfile -t FAILED <"$RES/failed-ours.txt"
OURS=() FLAKY=() BOTH=()
if [[ ${#FAILED[@]} -gt 0 && ! -e "$RES/.disk-stop" ]]; then
    say "4 recheck: ${#FAILED[@]} failed tests, again on ours, then on loop"
    xfstests ours-again "$TDEV" "$SDEV" "$RES/failed-ours-again.txt" "${FAILED[@]}" || true
    blk detach "$TB" >/dev/null
    blk detach "$SB" >/dev/null

    truncate -s "${SIZE_GIB}G" "$LOOP_TEST_IMG" "$LOOP_SCRATCH_IMG"
    LT=$(losetup -f --show --sector-size 4096 "$LOOP_TEST_IMG"); LOOPS+=("$LT")
    LS=$(losetup -f --show --sector-size 4096 "$LOOP_SCRATCH_IMG"); LOOPS+=("$LS")
    if [[ -n "${FST_LOOP_ROTATIONAL:-}" ]]; then
        set_rotational "$LT" "$FST_LOOP_ROTATIONAL"
        set_rotational "$LS" "$FST_LOOP_ROTATIONAL"
    fi
    echo "loop devices: TEST $LT, SCRATCH $LS (4096-byte sectors), rotational $(rotational "$LT")/$(rotational "$LS")" | tee -a "$RES/summary.txt"
    xfstests loop "$LT" "$LS" "$RES/failed-loop.txt" "${FAILED[@]}" || true
    for l in "${LOOPS[@]}"; do losetup -d "$l"; done
    LOOPS=()
    rm -f "$LOOP_TEST_IMG" "$LOOP_SCRATCH_IMG"

    for t in "${FAILED[@]}"; do
        if grep -qx "$t" "$RES/failed-loop.txt"; then BOTH+=("$t")
        elif grep -qx "$t" "$RES/failed-ours-again.txt"; then OURS+=("$t")
        else FLAKY+=("$t")
        fi
    done
fi

{
    echo
    echo "failed on ours, passed on loop (OURS):   ${OURS[*]:-none}"
    echo "failed once on ours, then passed (FLAKY): ${FLAKY[*]:-none}"
    echo "failed on loop too (not the device):      ${BOTH[*]:-none}"
    echo "log $(du -h --apparent-size "$LOG" 2>/dev/null | cut -f1); $(free_gib) GiB free at the end"
    echo "automatic compactions: $(grep -c '^taso-blkd: compacted:' "$ERR" || true) done, $(grep -c '^taso-blkd: compaction:' "$ERR" || true) failed, $(grep -c '^taso-blkd: compaction waits:' "$ERR" || true) times short of room"
} | tee -a "$RES/summary.txt"
if grep -q '^taso-blkd: compaction:' "$ERR"; then
    grep '^taso-blkd: compaction:' "$ERR" | tee -a "$RES/summary.txt"
    FAILS=$((FAILS + 1))
fi
[[ ${#OURS[@]} -eq 0 ]] || FAILS=$((FAILS + 1))

unmount_all
stop_daemon

echo
if [[ $FAILS -eq 0 ]]; then
    if [[ "${FST_ONLY_XFSTESTS:-}" == 1 ]]; then
        echo "FSTESTS PASS, partial: raw and fsx skipped (results: $RES)"
    else
        echo "FSTESTS PASS (results: $RES)"
    fi
else
    echo "FSTESTS FAIL: $FAILS problems (results: $RES/summary.txt; daemon log: $ERR)"
    exit 1
fi
