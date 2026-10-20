#!/usr/bin/env bash
# P2 gate on the block log (plan S2, 2026-10-20): the six lines of
# gate-p2.sh with the Chronicle block log (taso-blkd, ext4 on ublk) as the
# storage instead of ZFS.  gate-p2.sh is unchanged; this is its sibling.
#
#   1. reborn on node B < 30 s p95
#   2. the last common Seal identical on both nodes: the full export of the
#      Seal, block for block (sha256 of `export <seal> -`), and every file's
#      path and bytes on a read-only mount of a fork of it
#   3. old Warden refused 20/20                  (n/a with KILL=power)
#   4. ledger tail intact: the agent on B resumes after the last sealed turn
#   5. losses reported in ctl (logcheck + logjudge, against the coordinator)
#   6. no partial transaction at the last common Seal (dbcheck on the mount)
#
# Each of $N rounds uses a fresh Vessel: node A (Warden 1) runs taso-sim, a
# turn every $SLEEP_MS ms, each sealed and published; after $RUN_S s A is
# killed; node B (Warden 2) starts with a takeover naming exactly A's
# ownership as read just before the kill ("takeover": {"holder", "epoch"},
# fencing review F2), fences A, rebuilds the Vessel from the store and runs
# the agent, which must resume right after the last sealed turn; timed from
# the kill to B's "reborn" line, on the driver's clock.
#
# Nodes: A_HOST and B_HOST are each empty (this machine) or root@<host>
# (ssh, key from this machine).  The driver is wherever this runs; it must
# outlive A, so with KILL=power it is B or a third machine.
#
#   one machine   A_HOST and B_HOST empty.  Node A is this machine's
#                 installed taso-blkd (/run/taso/blk.sock, node-setup.sh
#                 vessel-blk); node B is a second taso-blkd this script
#                 starts on a fresh log under $WORK.  The coordinator is
#                 the script's own (the installed one maps root to Warden 1
#                 only, and B is Warden 2).  Packs to a local directory, or
#                 to S3 if TASO_BLK_S3_* are set.  Stage S2.1.
#   two nodes     A_HOST and/or B_HOST set.  Each node's installed
#                 taso-blkd and /run/taso/coord.sock (node-setup.sh coord +
#                 vessel-blk); packs to S3 (TASO_BLK_S3_* required).
#                 Stages S2.2, S2.3, S2.5.
#
# KILL=stop   (default) A's Warden is frozen (SIGSTOP) and thawed after the
#             rebirth: its next append must be refused (Fenced).
# KILL=power  A's machine stops instantly (`echo o > /proc/sysrq-trigger`:
#             power off without sync; needs A_HOST).  After B's rebirth the
#             script waits until A answers ssh again — start it in the
#             provider's console — then A's taso-blkd recovery lines are
#             saved (S2.4) and the A-side checks (lines 2, 5) run.
#
# Usage (root on the driver; needs runc, cargo, python3, ublk here when a
# node is local):
#   scripts/gate-p2-blk.sh                                         # one machine
#   B_HOST=root@10.x.y.z scripts/gate-p2-blk.sh                    # A here, B there
#   A_HOST=root@10.x.y.z KILL=power N=5 scripts/gate-p2-blk.sh     # driver on B
#
# Environment: N (20; 5 with KILL=power)  RUN_S (3)  MIN_TURNS (1)  SLEEP_MS (100)
#              LANDLOCK (1)  KILL (stop|power)  A_HOST  B_HOST
#              OUT (/root/taso-gate-p2blk-<time>)  KEEP (0)
#              TASO_BLK_S3_ENDPOINT, _REGION, _BUCKET, _ACCESS_KEY_ID,
#              _SECRET_KEY_FILE (/root/s3-secret; copied to the nodes'
#              $WORK, never printed)
#
# Touches: $WORK (/var/tmp/taso-p2blk.*) on every node; branches named
# gate-p2blk-<run>/... and their Seals in each node's block log (dropped
# per round unless KEEP=1); /dev/ublkb* devices for those; with KILL=power,
# A's kernel.sysrq for the run (not persistent) and A's power.

set -euo pipefail

N=${N:-}
RUN_S=${RUN_S:-3}
MIN_TURNS=${MIN_TURNS:-1}   # A is killed only once this many turn Seals are shipped and anchored
SLEEP_MS=${SLEEP_MS:-100}
LANDLOCK=${LANDLOCK:-1}
KILL=${KILL:-stop}
KEEP=${KEEP:-0}
A_HOST=${A_HOST:-}
B_HOST=${B_HOST:-}
OUT=${OUT:-/root/taso-gate-p2blk-$(date +%Y%m%d-%H%M%S)}
RUN=$(date +%Y%m%d%H%M%S)-$$
SECRET_FILE=${TASO_BLK_S3_SECRET_KEY_FILE:-/root/s3-secret}

die() { echo "error: $*" >&2; exit 2; }
[ "$(id -u)" = 0 ] || die "run as root"
case "$KILL" in stop) : "${N:=20}" ;; power) : "${N:=5}"; [ -n "$A_HOST" ] || die "KILL=power needs A_HOST (the driver must survive A)" ;; *) die "KILL must be stop or power" ;; esac
for t in runc ldd python3 cargo sha256sum; do command -v "$t" >/dev/null || die "$t is missing"; done

cd "$(dirname "$0")/.."
echo "== building (release)"
# (--bin narrows the targets of every package named, so taso-blkd gets
# its own command.)
cargo build --release -q -p taso-warden -p taso-sim -p taso-landlock --bins
cargo build --release -q -p taso-blk --bin taso-blkd
for b in taso-wardend taso-logcheck taso-sim taso-landlock taso-blkd taso-coordd; do
    [ -x "target/release/$b" ] || die "target/release/$b was not built"
done
BIN=$PWD/target/release

mkdir -p "$OUT"
WORK=$(mktemp -d /var/tmp/taso-p2blk.XXXXXX)
chmod 755 "$WORK"
# Until the full cleanup below is in place: a preflight failure leaves
# nothing behind here (the nodes' copies are made after their checks).
trap 'rm -rf "$WORK"' EXIT
ROOT="gate-p2blk-$RUN"

# ── nodes ─────────────────────────────────────────────────────────────
SSH=(ssh -o BatchMode=yes -o ControlMaster=auto -o "ControlPath=/tmp/taso-p2blk-ssh-%C" -o ControlPersist=900 -o ServerAliveInterval=5 -o ServerAliveCountMax=2)
host_of() { if [ "$1" = a ]; then echo "$A_HOST"; else echo "$B_HOST"; fi; }
on() {   # $1 a|b, $2 command string: over ssh, or here
    local h; h=$(host_of "$1")
    if [ -n "$h" ]; then "${SSH[@]}" "$h" "$2"; else bash -c "$2"; fi
}
to() {   # $1 a|b, $2 local file, $3 remote path: copy (or nothing if local and same path)
    local h; h=$(host_of "$1")
    if [ -n "$h" ]; then "${SSH[@]}" "$h" "cat > $3" < "$2"; elif [ "$2" != "$3" ]; then cp "$2" "$3"; fi
}
umount_under() {   # $1 a|b: unmount everything under the node's mount root, innermost first
    on "$1" "awk -v r=$WORK/$1/mnt '\$5 == r || index(\$5, r \"/\") == 1 {print length(\$5), \$5}' /proc/self/mountinfo | sort -rn | cut -d' ' -f2- | while read -r m; do umount \"\$m\" 2>/dev/null || umount -l \"\$m\" 2>/dev/null; done; true"
}
ssh_reset() {   # drop a dead master connection (after a power cut)
    local h; h=$(host_of "$1"); [ -n "$h" ] && "${SSH[@]}" -O exit "$h" 2>/dev/null || true
}
for n in a b; do
    h=$(host_of "$n")
    [ -n "$h" ] && { on "$n" true || die "cannot ssh to $h (needs a key from this machine)"; }
done
ONE_MACHINE=0
[ -z "$A_HOST" ] && [ -z "$B_HOST" ] && ONE_MACHINE=1

# Per node: the daemon socket, the mount root, the spool, the state dir.
SOCK_A=/run/taso/blk.sock
if [ "$ONE_MACHINE" = 1 ]; then SOCK_B=$WORK/b-blk.sock; else SOCK_B=/run/taso/blk.sock; fi
sock_of() { if [ "$1" = a ]; then echo "$SOCK_A"; else echo "$SOCK_B"; fi; }
for n in a b; do on "$n" "command -v runc >/dev/null" || die "node $n: runc missing"; done
on a "test -S $SOCK_A" || die "node A: no taso-blkd on $SOCK_A (node-setup.sh vessel-blk)"
if [ "$ONE_MACHINE" = 0 ]; then
    on b "test -S $SOCK_B" || die "node B: no taso-blkd on $SOCK_B (node-setup.sh vessel-blk)"
    for n in a b; do on "$n" "test -S /run/taso/coord.sock" || die "node $n: no coordinator at /run/taso/coord.sock (node-setup.sh)"; done
    [ -n "${TASO_BLK_S3_ENDPOINT:-}" ] && [ -n "${TASO_BLK_S3_BUCKET:-}" ] && [ -n "${TASO_BLK_S3_ACCESS_KEY_ID:-}" ] && [ -f "$SECRET_FILE" ] \
        || die "two nodes need TASO_BLK_S3_ENDPOINT, _BUCKET, _ACCESS_KEY_ID and the secret in $SECRET_FILE"
fi
for n in a b; do
    on "$n" "mkdir -p $WORK/$n/mnt $WORK/$n/spool $WORK/$n/state $WORK/$n/run $WORK/bin && chmod 755 $WORK"
done

COORD_PID=
BLKD_B_PID=
cleanup() {
    local rc=$?
    set +e
    [ -n "$COORD_PID" ] && kill "$COORD_PID" 2>/dev/null
    for n in a b; do
        on "$n" 'for d in '"$WORK"'/'"$n"'/run/runc; do [ -d "$d" ] && for c in $(runc --root "$d" list -q 2>/dev/null); do runc --root "$d" delete --force "$c" 2>/dev/null; done; done; true' 2>/dev/null
        umount_under "$n" 2>/dev/null
    done
    if [ "$KEEP" = 1 ]; then
        echo "kept: work dir $WORK on every node, branches under $ROOT in the block logs"
    else
        drop_root a; drop_root b
        [ -n "$BLKD_B_PID" ] && { blk b quit >/dev/null 2>&1; sleep 0.5; kill "$BLKD_B_PID" 2>/dev/null; }
        for n in a b; do on "$n" "rm -rf $WORK" 2>/dev/null; done
    fi
    for n in a b; do ssh_reset "$n"; done
    exit $rc
}
trap cleanup EXIT

# ── the daemon's socket, from the driver ──────────────────────────────
cat > "$WORK/bin/blkcmd.py" <<'PY'
import socket, sys
s = socket.socket(socket.AF_UNIX); s.settimeout(120); s.connect(sys.argv[1])
s.sendall((" ".join(sys.argv[2:]) + "\n").encode())
a = s.makefile().readline().strip()
if a == "ok": sys.exit(0)
if a.startswith("ok "): print(a[3:]); sys.exit(0)
print(a, file=sys.stderr); sys.exit(1)
PY
blk() {   # $1 a|b, then the command: prints the answer after "ok ", fails on "err"
    local n=$1; shift
    on "$n" "python3 $WORK/bin/blkcmd.py $(sock_of "$n") $*"
}
# Every branch named under $ROOT on node $1, its Seals and root Seal, dropped
# (newest first; what is still stood on is reported, not fatal).
drop_root() {
    local n=$1 names b seals s first parent
    names=$(blk "$n" names 2>/dev/null) || return 0
    for pair in $names; do
        [[ "$pair" == "$ROOT/"* ]] || continue
        b=${pair#*:}
        seals=$(blk "$n" seals "$b" 2>&1) || { echo "  node $n: seals $b: $seals" >&2; seals=; }
        first=${seals%% *}; first=${first%%:*}
        parent=; [ -n "$first" ] && parent=$(blk "$n" info "$first" 2>/dev/null | tr ' ' '\n' | sed -n 's/^parent=//p')
        blk "$n" drop "$b" >/dev/null 2>&1 || echo "  node $n: drop branch $b refused" >&2
        for s in $(echo "$seals" | tr ' ' '\n' | tac); do
            blk "$n" drop "${s%%:*}" >/dev/null 2>&1 || echo "  node $n: drop Seal ${s%%:*} refused" >&2
        done
        if [ -n "$parent" ] && [ "$parent" != "-" ]; then
            blk "$n" drop "$parent" >/dev/null 2>&1 || true
        fi
    done
    return 0
}

# ── rootfs and binaries ───────────────────────────────────────────────
ROOTFS=$WORK/rootfs
copy_with_libs() {
    install -D -m 755 "$1" "$ROOTFS$2"
    ldd "$1" | grep -o '/[^ ]*' | while read -r lib; do install -D -m 755 "$lib" "$ROOTFS$lib"; done
}
copy_with_libs "$BIN/taso-sim" /usr/bin/taso-sim
copy_with_libs "$BIN/taso-landlock" /usr/lib/taso/landlock
mkdir -p "$ROOTFS"/{proc,dev,sys,tmp,work,run/taso}
: > "$ROOTFS/run/taso/field.sock"
cp "$BIN/taso-wardend" "$BIN/taso-logcheck" "$BIN/taso-blkd" scripts/gate-cloud/dbcheck.py scripts/gate-cloud/logjudge.py "$WORK/bin/"
for n in a b; do
    [ -n "$(host_of "$n")" ] || continue
    echo "== copying binaries and rootfs to node $n"
    tar -C "$WORK" -cf - bin rootfs | on "$n" "tar -C $WORK -xf -"
done

# ── coordinator and store ─────────────────────────────────────────────
if [ "$ONE_MACHINE" = 1 ]; then
    SOCK=$WORK/coord.sock
    "$BIN/taso-coordd" "$WORK/coord.redb" "$SOCK" 2>"$OUT/coordd.err" &
    COORD_PID=$!
    for _ in $(seq 100); do [ -S "$SOCK" ] && break; sleep 0.05; done
    [ -S "$SOCK" ] || die "taso-coordd did not start"
    "$WORK/bin/taso-blkd" "$WORK/b-blk.log" "$SOCK_B" 2>"$OUT/blkd-b.err" &
    BLKD_B_PID=$!
    for _ in $(seq 100); do [ -S "$SOCK_B" ] && break; sleep 0.05; done
    [ -S "$SOCK_B" ] || die "node B's taso-blkd did not start; see $OUT/blkd-b.err"
    MODE="one machine (A: installed taso-blkd, B: $SOCK_B)"
else
    SOCK=/run/taso/coord.sock
    MODE="nodes A=${A_HOST:-here} B=${B_HOST:-here}, kill=$KILL"
fi
if [ -n "${TASO_BLK_S3_ENDPOINT:-}" ]; then
    for n in a b; do
        on "$n" "umask 077; cat > $WORK/s3.secret" < "$SECRET_FILE"
    done
    STORE_JSON=$(python3 -c "import json,os; print(json.dumps({'s3': {'endpoint': os.environ['TASO_BLK_S3_ENDPOINT'], 'region': os.environ.get('TASO_BLK_S3_REGION', 'garage'), 'bucket': os.environ['TASO_BLK_S3_BUCKET'], 'access_key_id': os.environ['TASO_BLK_S3_ACCESS_KEY_ID'], 'secret_key_file': '$WORK/s3.secret'}}))")
    PREFIX="gate-p2blk-$RUN"
    MODE="$MODE, packs to $TASO_BLK_S3_ENDPOINT/$TASO_BLK_S3_BUCKET"
else
    STORE_JSON="\"$WORK/store\""
    PREFIX="vessels"
    MODE="$MODE, packs to $WORK/store"
fi
echo "== $MODE"
if [ "$KILL" = power ]; then
    v=$(on a "sysctl -n kernel.sysrq")
    if [ "$v" != 1 ] && [ $((v & 128)) = 0 ]; then
        echo "== node A: kernel.sysrq=$v does not allow power-off; setting 1 for this run (not persistent)"
        on a "sysctl -q -w kernel.sysrq=1"
    fi
fi

config() {   # $1 node, $2 warden, $3 takeover ("" or <holder>@<epoch>), $4 subject, $5 turns, $6 out file
    python3 - "$@" <<PY
import json, sys
node, warden, takeover, subject, turns, out = sys.argv[1:]
takeover = {"holder": int(takeover.split("@")[0]), "epoch": int(takeover.split("@")[1])} if takeover else None
json.dump({
    "warden": int(warden),
    "coordinator": {"remote": "$SOCK"},
    "storage": {"blk": {"socket": "$(sock_of "$1")", "mounts": "$WORK/" + node + "/mnt", "spool": "$WORK/" + node + "/spool"}},
    "root": "$ROOT/" + node,
    "state_dir": "$WORK/" + node + "/state",
    "store": json.loads('$STORE_JSON'),
    "prefix": "$PREFIX",
    "run_dir": "$WORK/" + node + "/run",
    "runtime": {
        "rootfs": "$ROOTFS",
        "host_uid_base": 200000,
        "landlock_shim": "/usr/lib/taso/landlock" if "$LANDLOCK" == "1" else None,
        "args": ["/usr/bin/taso-sim", "--turns", turns, "--txns", "2", "--rows", "4",
                 "--turn-sleep-ms", "$SLEEP_MS", "--stats", "/work/sim-stats.json"],
        "memory_bytes": 268435456,
        "pids": 64,
    },
    "vessels": [{"namespace": "7a" * 16, "subject": subject, "takeover": takeover, "uid_slot": 0}],
}, open(out, "w"), indent=1)
PY
}

vessel_ds() {   # $1 daemon stderr -> the Vessel's dataset (branch name), as the daemon logged it
    grep -o ': dataset [^ ]*$' "$1" | head -1 | sed 's/: dataset //'
}
tag_lsn() {   # $1 tag (hex: lsn little-endian 8 bytes, hash 32) -> lsn
    python3 -c "import sys; print(int.from_bytes(bytes.fromhex(sys.argv[1][:16]), 'little'))" "$1"
}
# The live branch named $2 on node $1 (prints the layer id).
branch_of() {
    blk "$1" find "$2"
}
# The Seals of branch id $2 on node $1, "<seal>:<tag>" per line, oldest first.
seals_of() {
    blk "$1" seals "$2" | tr ' ' '\n'
}
# The Seal of node $1's branch id $2 whose tag is $3 (prints the layer id).
seal_by_tag() {
    seals_of "$1" "$2" | awk -F: -v t="$3" '$2 == t {print $1; exit}'
}
# The full export of Seal $2 on node $1, hashed.
export_hash() {
    on "$1" "python3 $WORK/bin/blkcmd.py $(sock_of "$1") export $2 - $WORK/$1/export.img >/dev/null && sha256sum $WORK/$1/export.img | cut -d' ' -f1; rm -f $WORK/$1/export.img"
}
# Fork Seal $2 on node $1 to a scratch branch, mount it read-only at
# $WORK/$1/scratch; prints the branch id.  scratch_done unmounts and drops.
scratch_mount() {
    local out b dev
    out=$(blk "$1" fork "$2" "$ROOT/scratch-$1-$3")
    b=${out%% *}; dev=${out#* }
    on "$1" "mkdir -p $WORK/$1/scratch && mount -o ro,noload $dev $WORK/$1/scratch"
    echo "$b"
}
scratch_done() {   # $1 node, $2 branch id
    on "$1" "umount $WORK/$1/scratch 2>/dev/null || umount -l $WORK/$1/scratch 2>/dev/null; true"
    blk "$1" drop "$2" >/dev/null 2>&1 || echo "  node $1: drop scratch $2 refused" >&2
}
files_hash() {   # $1 node -> hash of every file's path and bytes on the scratch mount
    on "$1" "cd $WORK/$1/scratch && find . -type f -print0 | sort -z | xargs -0 sha256sum | sha256sum | cut -d' ' -f1"
}

: > "$OUT/rounds.tsv"
for k in $(seq 1 "$N"); do
    subject="gate-p2blk-$RUN-$k"
    config a 1 "" "$subject" 100000 "$WORK/a-$k.json"
    to a "$WORK/a-$k.json" "$WORK/a-$k.json"

    # A's Warden runs on node A, detached, its output in $WORK there.
    A_PID=$(on a "nohup $WORK/bin/taso-wardend $WORK/a-$k.json >$WORK/a-$k.out 2>$WORK/a-$k.err </dev/null & echo \$!")
    sleep "$RUN_S"
    if ! on a "kill -0 $A_PID" 2>/dev/null; then
        echo "round $k: A's Warden exited before the kill; its log:" >&2
        on a "tail -8 $WORK/a-$k.err" | sed 's/^/    /' >&2
        exit 1
    fi
    # A is killed only once at least MIN_TURNS turn Seals are shipped and
    # anchored (with packs over the internet, RUN_S alone may cover only
    # the birth Seal, and then there is nothing to resume after).
    dsa=$(on a "grep -o ': dataset [^ ]*$' $WORK/a-$k.err | head -1 | sed 's/: dataset //'")
    id=${dsa##*/v-}
    turns=0
    for _ in $(seq 120); do
        turns=$(on a "$WORK/bin/taso-logcheck $SOCK $WORK/a/state $id" 2>/dev/null \
            | python3 -c "import json,sys; j=json.load(sys.stdin); s=j['shipped']['lsn']; print(sum(1 for f in j['frames'] if f['kind'] == 'seal' and f.get('turn', 0) >= 1 and f['lsn'] <= s))" 2>/dev/null || echo 0)
        [ "$turns" -ge "$MIN_TURNS" ] && break
        on a "kill -0 $A_PID" 2>/dev/null || break
        sleep 0.5
    done
    [ "$turns" -ge "$MIN_TURNS" ] || { echo "round $k: A shipped only $turns turn Seal(s) in $((RUN_S + 60)) s (MIN_TURNS=$MIN_TURNS); its log:" >&2; on a "tail -5 $WORK/a-$k.err" | sed 's/^/    /' >&2; exit 1; }
    # B takes over exactly the ownership A holds now, as an operator
    # would read it with taso-logcheck (the holder cannot change before
    # the kill: only a takeover moves it).
    owner=$(on a "$WORK/bin/taso-logcheck $SOCK $WORK/a/state $id" 2>/dev/null \
        | python3 -c "import json,sys; o=json.load(sys.stdin)['ownership']; print('%d@%d' % (o['holder'], o['epoch']))") \
        || { echo "round $k: could not read A's ownership of $id" >&2; exit 1; }
    config b 2 "$owner" "$subject" 5 "$WORK/b-$k.json"
    to b "$WORK/b-$k.json" "$WORK/b-$k.json"
    if [ "$KILL" = stop ]; then
        on a "kill -STOP $A_PID"
    else
        # Power off without sync.  The ssh command dies with the machine.
        on a "echo o > /proc/sysrq-trigger" 2>/dev/null || true
    fi
    t0=$(date +%s.%N)

    # B's stdout and stderr stream here (over ssh if B is remote).
    on b "exec $WORK/bin/taso-wardend $WORK/b-$k.json" >"$OUT/b-$k.out" 2>"$OUT/b-$k.err" &
    B=$!
    reborn=
    for _ in $(seq 1200); do
        if grep -q "reborn at epoch" "$OUT/b-$k.err" 2>/dev/null; then reborn=$(date +%s.%N); break; fi
        kill -0 "$B" 2>/dev/null || break
        sleep 0.025
    done
    secs=nan
    [ -n "$reborn" ] && secs=$(python3 -c "print('%.3f' % ($reborn - $t0))")
    wait "$B" || true

    refused=na
    if [ "$KILL" = stop ]; then
        # The old Warden wakes up believing it still holds the Vessel.
        on a "kill -CONT $A_PID"
        for _ in $(seq 400); do on a "kill -0 $A_PID" 2>/dev/null || break; sleep 0.025; done
        on a "kill -KILL $A_PID 2>/dev/null; true"
        refused=0
        on a "grep -q Fenced $WORK/a-$k.err" && refused=1
    else
        ssh_reset a
        echo "  round $k: node A is off.  Start it in the provider's console; waiting for ssh..."
        until on a true 2>/dev/null; do sleep 5; done
        echo "  node A is back ($(on a 'uptime -s'))"
        # S2.4: A's own log after the cut, as its daemon reported at boot.
        on a "systemctl is-active -q taso-blkd || systemctl start taso-blkd; sleep 1; journalctl -u taso-blkd -b --no-pager -o cat" >"$OUT/a-$k.recovery.txt" 2>&1 || true
        echo "  A's taso-blkd at boot: $(tail -3 "$OUT/a-$k.recovery.txt" | tr '\n' ' ')"
    fi
    on a "cat $WORK/a-$k.err" >"$OUT/a-$k.err" 2>/dev/null || : >"$OUT/a-$k.err"
    on a "cat $WORK/a-$k.out" >"$OUT/a-$k.out" 2>/dev/null || : >"$OUT/a-$k.out"

    # The last Seal both nodes have: same tag (lsn + hash of the Seal
    # record), then the same bytes two ways.
    dsa=$(vessel_ds "$OUT/a-$k.err"); dsb=$(vessel_ds "$OUT/b-$k.err")
    ba_id=$(branch_of a "$dsa" 2>"$OUT/blk-$k.err") || { ba_id=; echo "  node A: find $dsa: $(cat "$OUT/blk-$k.err")"; }
    bb_id=$(branch_of b "$dsb" 2>"$OUT/blk-$k.err") || { bb_id=; echo "  node B: find $dsb: $(cat "$OUT/blk-$k.err")"; }
    tags_a=; tags_b=
    [ -n "$ba_id" ] && { tags_a=$(seals_of a "$ba_id" 2>"$OUT/blk-$k.err" | cut -d: -f2 | sort) || echo "  node A: seals $ba_id: $(cat "$OUT/blk-$k.err")"; }
    [ -n "$bb_id" ] && { tags_b=$(seals_of b "$bb_id" 2>"$OUT/blk-$k.err" | cut -d: -f2 | sort) || echo "  node B: seals $bb_id: $(cat "$OUT/blk-$k.err")"; }
    last_tag=; last=none
    for t in $(comm -12 <(echo "$tags_a") <(echo "$tags_b")); do
        [ -n "$t" ] || continue
        l=$(tag_lsn "$t")
        if [ "$last" = none ] || [ "$l" -gt "$last" ]; then last=$l; last_tag=$t; fi
    done
    same=0 blockeq=0 fileeq=0 dbok=0
    if [ -n "$last_tag" ]; then
        sa=$(seal_by_tag a "$ba_id" "$last_tag"); sb=$(seal_by_tag b "$bb_id" "$last_tag")
        ea=$(export_hash a "$sa"); eb=$(export_hash b "$sb")
        [ -n "$ea" ] && [ "$ea" = "$eb" ] && blockeq=1
        ba=$(scratch_mount a "$sa" "$k"); bb=$(scratch_mount b "$sb" "$k")
        fa=$(files_hash a); fb=$(files_hash b)
        [ -n "$fa" ] && [ "$fa" = "$fb" ] && fileeq=1
        [ "$blockeq" = 1 ] && [ "$fileeq" = 1 ] && same=1
        scratch_a=$ba; scratch_b=$bb
    fi

    # Losses reported in ctl: both logs, read as files, judged against what
    # the coordinator recorded at the takeover.
    id=${dsb##*/v-}
    on a "$WORK/bin/taso-logcheck $SOCK $WORK/a/state $id" >"$OUT/a-$k.log.json" 2>>"$OUT/a-$k.err" || echo '{}' >"$OUT/a-$k.log.json"
    on b "$WORK/bin/taso-logcheck $SOCK $WORK/b/state $id" >"$OUT/b-$k.log.json" 2>>"$OUT/b-$k.err" || echo '{}' >"$OUT/b-$k.log.json"
    logv=$(python3 "$WORK/bin/logjudge.py" "$OUT/a-$k.log.json" "$OUT/b-$k.log.json" 2>&1 || echo '{"ok": false, "lost": null, "why": "logjudge failed"}')
    echo "$logv" >"$OUT/judge-$k.json"
    logok=$(python3 -c 'import json,sys; v=json.loads(sys.argv[1]); print(1 if v.get("ok") else 0)' "$logv" 2>/dev/null || echo 0)
    lost=$(python3 -c 'import json,sys; print(json.loads(sys.argv[1]).get("lost"))' "$logv" 2>/dev/null || echo None)
    # No partial transaction: the database at the last common Seal holds
    # exactly the sealed turns, whole (dbcheck.py on B's read-only mount).
    if [ -n "$last_tag" ]; then
        turn=$(python3 -c 'import json,sys
b=json.load(open(sys.argv[1])); l=int(sys.argv[2])
print(next(f["turn"] for f in b["frames"] if f["lsn"] == l and f["kind"] == "seal"))' "$OUT/b-$k.log.json" "$last" 2>/dev/null || echo none)
        if [ "$turn" != none ]; then
            dbv=$(on b "python3 $WORK/bin/dbcheck.py $WORK/b/scratch $turn 2 4" 2>&1 || true)
            echo "$dbv" >"$OUT/db-$k.json"
            dbok=$(python3 -c 'import json,sys; print(1 if json.loads(sys.argv[1]).get("ok") else 0)' "$dbv" 2>/dev/null || echo 0)
        else
            echo '{"ok": false, "why": "the last common Seal is not in B'"'"'s log"}' >"$OUT/db-$k.json"
        fi
        scratch_done a "$scratch_a"; scratch_done b "$scratch_b"
    fi
    resumed=$(on b "cat $WORK/b/mnt/$dsb/sim-stats.json" 2>/dev/null \
        | python3 -c "import json,sys; print(json.load(sys.stdin)['resumed_after'])" 2>/dev/null || echo none)
    how=$(grep -o 'reborn at epoch.*' "$OUT/b-$k.err" | tail -1 || true)
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$k" "$secs" "$refused" "$same" "$last" "$resumed" "$logok" "$lost" "$dbok" "$blockeq" "$fileeq" | tee -a "$OUT/rounds.tsv"
    echo "  $how"
    [ "$same" = 1 ] || echo "  Seal compare: blocks equal=$blockeq files equal=$fileeq (last common lsn $last)"
    [ "$logok" = 1 ] || echo "  log check failed: $(cat "$OUT/judge-$k.json")"
    [ "$dbok" = 1 ] || echo "  database check failed: $(cat "$OUT/db-$k.json" 2>/dev/null || echo 'no common Seal')"
    if [ "$resumed" = none ] || [ "$resumed" = None ]; then
        echo "  B did not resume; its log:"; sed 's/^/    /' "$OUT/b-$k.err" | tail -8; sed 's/^/    /' "$OUT/b-$k.out"
    fi
    # Leave the next round a clean slate on both nodes.
    if [ "$KEEP" != 1 ]; then
        umount_under a; umount_under b
        drop_root a; drop_root b
    fi
done

python3 - "$OUT/rounds.tsv" "$N" "$MODE" "$KILL" <<'PY' | tee "$OUT/summary.txt"
import math, sys
rows = [l.rstrip("\n").split("\t") for l in open(sys.argv[1]) if l.strip()]
n = int(sys.argv[2]); kill = sys.argv[4]
secs = sorted(float(r[1]) for r in rows if r[1] != "nan")
def q(v, x):
    return v[min(len(v) - 1, max(0, math.ceil(len(v) * x) - 1))] if v else float("nan")
reborn = len(secs)
same = sum(int(r[3]) for r in rows)
blockeq = sum(int(r[9]) for r in rows); fileeq = sum(int(r[10]) for r in rows)
resumed = sum(1 for r in rows if r[5] not in ("none", "None"))
print(f"P2 gate on the block log ({sys.argv[3]}), {n} rounds")
print(f"1. reborn: {reborn}/{n}, p50 {q(secs, .5):.2f} s, p95 {q(secs, .95):.2f} s (< 30) -> {'PASS' if reborn == n and q(secs, .95) < 30 else 'FAIL'}")
print(f"2. last common Seal identical: blocks {blockeq}/{n}, files {fileeq}/{n} -> {'PASS' if same == n else 'FAIL'}")
if kill == "stop":
    refused = sum(1 for r in rows if r[2] == "1")
    print(f"3. old Warden refused: {refused}/{n} -> {'PASS' if refused == n else 'FAIL'}")
else:
    print("3. old Warden refused: n/a (KILL=power: A was off; its return is F1/F2 territory)")
print(f"4. agent on B resumed after a sealed turn: {resumed}/{n} -> {'PASS' if resumed == n else 'FAIL'}")
logok = sum(int(r[6]) for r in rows)
lossy = sum(1 for r in rows if r[7] not in ("None", "0"))
dbok = sum(int(r[8]) for r in rows)
print(f"5. losses reported in ctl (Gap + Unverified first Seal, against the coordinator): {logok}/{n}, {lossy} rounds lost records -> {'PASS' if logok == n else 'FAIL'}")
print(f"6. no partial transaction at the last common Seal (integrity_check, whole turns): {dbok}/{n} -> {'PASS' if dbok == n else 'FAIL'}")
PY
echo "results in $OUT"
