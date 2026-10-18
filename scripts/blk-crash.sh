#!/usr/bin/env bash
# blk-crash.sh: K1 of the block log spike, correctness under crash.
#
# Each round: start taso-blkd on the same log, attach the branch, mount
# (ext4 replays its journal), unmount, fsck must be clean, mount again and
# check every file whose fsync returned before the last crash.  Then run a
# writer (create / replace / delete, each made durable with fsync of the
# file and the directory) and kill -9 the daemon at a random moment.
# A last restart checks the final crash, then the daemon quits cleanly.
#
#   sudo scripts/blk-crash.sh [ROUNDS] [path/to/taso-blkd]   (default 10, target/release/taso-blkd)
#
# Touches, and nothing else:
#   /var/lib/taso-blk/crash.log, crash.err, crash.manifest, crash-helper.py
#                                            (removed at start, kept after)
#   /run/taso-blk-crash.sock
#   /mnt/blk-crash                           (mounted, then unmounted)
#   the /dev/ublkb* devices the daemon creates for this run
#
# The manifest (on /, not on the device) holds an intent line before each
# operation and a done line after its fsyncs returned.  A done operation
# must survive; the one operation in flight at the kill may show its old
# or its new state, nothing else.  Replace and create go through a
# temporary name and rename, so neither can be torn.
#
# What a kill -9 does not test: log writes the daemon issued but had not
# yet synced survive here in the page cache; a power cut would lose them.
# The store's unit tests cover that (the log cut at every byte).
#
# Also reported: control devices left behind by killed daemons.
#
# BLK_CRASH_NO_UBLK=1 skips the ublk module check; it exists to test this
# script with a stand-in daemon on a machine without ublk.

set -euo pipefail

ROUNDS=${1:-10}
BLKD=${2:-target/release/taso-blkd}
DIR=/var/lib/taso-blk
LOG=$DIR/crash.log
ERR=$DIR/crash.err
MAN=$DIR/crash.manifest
HELPER=$DIR/crash-helper.py
SOCK=/run/taso-blk-crash.sock
MNT=/mnt/blk-crash

DAEMON_PID=
WRITER_PID=
FAILS=0

say()  { printf '== %s\n' "$*"; }
die()  { printf 'ABORT: %s\n' "$*" >&2; exit 2; }
fail() { printf 'FAIL  %s\n' "$*"; FAILS=$((FAILS + 1)); }

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
    rm -f "$SOCK"    # a killed daemon leaves its socket; wait for the new one
    "$BLKD" "$LOG" "$SOCK" 2>>"$ERR" &
    DAEMON_PID=$!
    for _ in $(seq 100); do
        [[ -S "$SOCK" ]] && return 0
        kill -0 "$DAEMON_PID" 2>/dev/null || die "daemon exited; see $ERR"
        sleep 0.1
    done
    die "daemon socket did not appear in 10 s"
}

wait_dev() {
    for _ in $(seq 50); do
        [[ -b "$1" ]] && return 0
        sleep 0.1
    done
    die "device $1 did not appear in 5 s"
}

mount_on() {
    mount "$1" "$MNT"
    [[ "$(findmnt -n -o SOURCE --mountpoint "$MNT")" == "$1" ]] || die "$MNT is not mounted from $1"
}

unmount() {
    mountpoint -q "$MNT" || return 0
    umount "$MNT" 2>/dev/null || umount -l "$MNT"
}

# Wait up to $2 s for pid $1 to exit.
wait_exit() {
    for _ in $(seq $(($2 * 10))); do
        kill -0 "$1" 2>/dev/null || { wait "$1" 2>/dev/null || true; return 0; }
        sleep 0.1
    done
    return 1
}

control_devices() { find /dev -maxdepth 1 -name 'ublkc*' 2>/dev/null | wc -l; }

cleanup() {
    local rc=$?
    set +e
    [[ -n "$WRITER_PID" ]] && kill "$WRITER_PID" 2>/dev/null && wait_exit "$WRITER_PID" 10
    unmount
    if [[ -n "$DAEMON_PID" ]] && kill -0 "$DAEMON_PID" 2>/dev/null; then
        (blk quit) >/dev/null 2>&1 || kill "$DAEMON_PID"
        wait_exit "$DAEMON_PID" 10
    fi
    exit "$rc"
}
trap cleanup EXIT

# ---- preflight -------------------------------------------------------------
[[ $EUID -eq 0 ]] || die "run as root"
[[ "$ROUNDS" =~ ^[1-9][0-9]*$ ]] || die "ROUNDS must be a positive number"
[[ -x "$BLKD" ]] || die "no daemon at $BLKD (cargo build --release -p taso-blk)"
if [[ "${BLK_CRASH_NO_UBLK:-}" != 1 ]]; then
    modprobe ublk_drv
    [[ -c /dev/ublk-control ]] || die "/dev/ublk-control missing"
fi
mkdir -p "$MNT"
! mountpoint -q "$MNT" || die "$MNT is already a mount point"
mkdir -p "$DIR"
rm -f "$LOG" "$ERR" "$MAN" "$HELPER"

cat >"$HELPER" <<'PY'
"""crash helper: `write MNT MANIFEST ROUND` or `verify MNT MANIFEST`."""
import hashlib, os, random, sys

BUDGET = 256 << 20   # live file bytes the writer keeps on the device, at most

def digest(b): return hashlib.blake2b(b, digest_size=16).hexdigest()

def state_of(path):
    try:
        with open(path, "rb") as f: return digest(f.read())
    except FileNotFoundError: return "-"

def load(man):
    """Durable state, and the one operation in flight (if any) per gap."""
    state, pending = {}, {}
    with open(man) as f:
        for line in f:
            w = line.split()
            if not w: continue
            if w[0] == "I":    # I seq op name new-hash old-hash
                pending[w[1]] = (w[3], w[4], w[5])
            elif w[0] == "D":  # D seq
                name, new, _ = pending.pop(w[1])
                state[name] = new
            elif w[0] == "R":  # R name hash: in-flight operation resolved after a crash
                for tag in [t for t, p in pending.items() if p[0] == w[1]]:
                    del pending[tag]
                state[w[1]] = w[2]
    return state, pending

def write(mnt, man, rnd):
    state, pending = load(man)
    assert not pending, "verify must run before write"
    live = [n for n, h in state.items() if h != "-"]
    sizes = {n: os.path.getsize(os.path.join(mnt, n)) for n in live}
    out = open(man, "a")
    dfd = os.open(mnt, os.O_RDONLY | os.O_DIRECTORY)
    seq = 0
    while True:
        seq += 1
        tag = f"{rnd}.{seq}"
        r = random.random()
        if live and (r < 0.15 or sum(sizes.values()) > BUDGET):
            op, name = "delete", random.choice(live)
        elif live and r < 0.45:
            op, name = "replace", random.choice(live)
        else:
            op, name = "create", f"f{rnd}_{seq}"
        old = state.get(name, "-")
        data = b"" if op == "delete" else os.urandom(random.choice([4096, 12288, 65536, 262144]) - random.randrange(4096))
        new = "-" if op == "delete" else digest(data)
        out.write(f"I {tag} {op} {name} {new} {old}\n"); out.flush()
        path = os.path.join(mnt, name)
        if op == "delete":
            os.unlink(path)
        else:
            tmp = os.path.join(mnt, ".tmp")
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
            view = memoryview(data)
            while view:                   # write() may be short; write it all
                view = view[os.write(fd, view):]
            os.fsync(fd); os.close(fd)
            os.rename(tmp, path)
        os.fsync(dfd)
        out.write(f"D {tag}\n"); out.flush()
        state[name] = new
        if op == "delete": sizes.pop(name, None)
        else: sizes[name] = len(data)
        live = list(sizes)

def verify(mnt, man):
    state, pending = load(man)
    bad = 0
    in_flight = {p[0] for p in pending.values()}
    for name, want in sorted(state.items()):
        if name in in_flight: continue   # checked below: old or new state
        got = state_of(os.path.join(mnt, name))
        if got != want:
            print(f"FAIL  {name}: fsynced state {want}, found {got}"); bad += 1
    resolved = []
    for tag, (name, new, old) in pending.items():
        got = state_of(os.path.join(mnt, name))
        if got not in (new, old):
            print(f"FAIL  {name}: in flight at the kill, found {got}, neither old {old} nor new {new}"); bad += 1
        resolved.append(f"R {name} {got}\n")
    with open(man, "a") as f: f.writelines(resolved)
    files = sum(1 for h in state.values() if h != "-")
    gone = sum(1 for h in state.values() if h == "-")
    print(f"checked {files} files present, {gone} deleted absent, {len(pending)} in flight")
    sys.exit(1 if bad else 0)

if __name__ == "__main__":
    mode, mnt, man = sys.argv[1:4]
    if mode == "write":
        try: write(mnt, man, sys.argv[4])
        except OSError as e: print(f"writer stopped: {e.strerror}")
    else:
        verify(mnt, man)
PY
touch "$MAN"

say "K1: $ROUNDS rounds, daemon $BLKD, log $LOG"
CTRL_BEFORE=$(control_devices)

# Restart, recover, attach, journal replay, fsck, check the manifest.
recover_and_check() {
    start_daemon
    say "  $(grep -o 'recovered.*' "$ERR" | tail -n 1)"
    DEV=$(blk attach "$BR")
    wait_dev "$DEV"
    if ! mount "$DEV" "$MNT"; then
        fail "round $1: the branch does not mount after the crash"
        die "K1 FAIL: cannot continue (daemon log: $ERR)"
    fi
    unmount
    local rc=0
    e2fsck -fn "$DEV" >/dev/null 2>&1 || rc=$?
    [[ $rc -eq 0 ]] || fail "round $1: fsck after journal replay exit $rc (see: e2fsck -fn $DEV)"
    mount_on "$DEV"
    local out
    if out=$(python3 "$HELPER" verify "$MNT" "$MAN"); then
        say "  $out"
    else
        printf '%s\n' "$out"
        fail "round $1: files lost or wrong after the crash"
    fi
}

start_daemon
ROOT=$(blk root)
read -r BR DEV <<<"$(blk fork "$ROOT")"
wait_dev "$DEV"
mkfs.ext4 -q -F -E nodiscard "$DEV"
mount_on "$DEV"
say "branch $BR on $DEV"

for r in $(seq "$ROUNDS"); do
    if [[ $r -gt 1 ]]; then
        recover_and_check "$r"
    fi
    python3 "$HELPER" write "$MNT" "$MAN" "$r" &
    WRITER_PID=$!
    delay=$((RANDOM % 7000 + 1000))
    sleep "$((delay / 1000)).$(printf '%03d' $((delay % 1000)))"
    kill -9 "$DAEMON_PID"
    wait "$DAEMON_PID" 2>/dev/null || true
    DAEMON_PID=
    wait_exit "$WRITER_PID" 30 || die "writer still running 30 s after the kill (stuck in I/O?): ps -o stat,wchan -p $WRITER_PID"
    WRITER_PID=
    unmount
    done_ops=$(grep -c '^D' "$MAN" || true)
    say "round $r: killed after ${delay} ms; $done_ops operations durable so far; control devices left: $(( $(control_devices) - CTRL_BEFORE ))"
done

say "final check after the last crash"
recover_and_check final
unmount
say "stats: $(blk stats)"
blk quit >/dev/null
wait_exit "$DAEMON_PID" 10 || die "daemon did not exit after quit"
DAEMON_PID=

echo
say "control devices left behind by killed daemons: $(( $(control_devices) - CTRL_BEFORE ))"
if [[ $FAILS -eq 0 ]]; then
    echo "K1 PASS: $ROUNDS crashes, every fsynced operation survived, fsck clean every round"
else
    echo "K1 FAIL: $FAILS failures (daemon log: $ERR, manifest: $MAN)"
    exit 1
fi
