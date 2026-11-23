#!/usr/bin/env bash
# p3-review.sh: a reviewer sees, approves and denies what a held Vessel
# asks for, end to end under taso-wardend (design
# Taso_design_proposals_inbox §1, §1b, §1c, §1f; docs/relay.md "The
# reviewer").
#
#   scripts/p3-review.sh     (as root, from the repository root; needs
#                             runc, ublk, cargo, python3)
#
# One Warden, one coordinator, a fresh taso-blkd on its own log.  One
# Vessel P that holds ("effects": "hold") and may fork twice.  Its agent
# and its forks' agents are p3-review-agent.py: they do what this script
# tells them, a command at a time, so every step is the same on every
# run.  The reviewer is taso-ctl on the Warden's decider socket; the
# sender is p3-review-agent.py on each Vessel's sender socket.
#
# A  a root Vessel that holds
#    1  three actions asked for: each held
#    2  the reviewer lists three, none sealed; an approval is refused
#    3  after the turn's Seal: three listed, sealed, the exact requests
#    4  approve the first: taken; again: taken before, nothing written
#    5  the sender is offered that one only, and reports it
#    6  the agent reads its receipt
#    7  deny the second: its agent reads the reason; it cannot be
#       approved afterwards, nor the approved one denied
#    8  the third stays held until it is denied too
# B  a fork whose agent goes before its sender has answered (§1f)
#    9  P forks; the fork asks for an action, seals, the reviewer
#       approves it, the fork's agent exits
#   10  the Warden keeps the fork's sender socket open and says so
#   11  P's promotion of the fork is refused: it still waits
#   12  the fork's sender is offered the action and reports it
#   13  now P promotes the fork, and is started again on its files
# C  a Warden that is killed while a fork waits (§1f)
#   14  P forks again; that fork asks, seals, is approved; the Warden
#       is SIGKILLed before any sender came
#   15  the next Warden runs the fork again for its sender only: no
#       agent, the action listed as unknown
#   16  its sender reports; the fork's run ends by itself
#   17  P promotes it
#   18  P's agent exits and the Warden ends by itself, exit 0: nothing
#       is left waiting
#
# Touches, and nothing else: a work directory under /var/tmp (removed at
# the end; KEEP=1 keeps it), /run/taso-review-<pid>-blk.sock,
# /mnt/taso-review-<pid> and the mounts under it (unmounted at the end),
# the /dev/ublkb* devices its taso-blkd makes, OUT (results, kept).
#
# Environment: LANDLOCK (1)  KEEP (0)  OUT (/root/taso-gate-review-<time>)
#
# Exit 0 only if every check passed.

set -euo pipefail
trap 'echo "FAILED at line $LINENO (exit $?)" >&2' ERR

LANDLOCK=${LANDLOCK:-1}
KEEP=${KEEP:-0}
OUT=${OUT:-/root/taso-gate-review-$(date +%Y%m%d-%H%M%S)}
RUN=$(date +%Y%m%d%H%M%S)-$$

[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 2; }
for t in runc ldd python3 cargo; do
    command -v "$t" >/dev/null || { echo "$t is missing" >&2; exit 2; }
done

cd "$(dirname "$0")/.."
echo "== building (release)"
cargo build --release -q -p taso-warden -p taso-landlock
cargo build --release -q -p taso-blk --bin taso-blkd   # alone: see release-gate.sh
BIN=$PWD/target/release
modprobe ublk_drv
[ -c /dev/ublk-control ] || { echo "/dev/ublk-control missing (ublk_drv)" >&2; exit 2; }

mkdir -p "$OUT"
WORK=$(mktemp -d /var/tmp/taso-review.XXXXXX)
chmod 755 "$WORK"
BASE="review/gate-$$"
SOCK=$WORK/coord.sock
BLK_SOCK=/run/taso-review-$$-blk.sock
MNT=/mnt/taso-review-$$
AGENT=$PWD/scripts/p3-review-agent.py
HAND="python3 $AGENT"
CFG=$WORK/warden.json
SEEN=$OUT/nonces.txt
: > "$SEEN"

blk() {
    python3 - "$BLK_SOCK" "$@" <<'PY'
import socket, sys
s = socket.socket(socket.AF_UNIX); s.settimeout(120); s.connect(sys.argv[1])
s.sendall((" ".join(sys.argv[2:]) + "\n").encode())
line = s.makefile().readline().strip()
print(line)
sys.exit(0 if line.startswith("ok") else 1)
PY
}

mounts_under() {
    awk -v root="$MNT" '$5 == root || index($5, root "/") == 1 { print length($5), $5 }' /proc/self/mountinfo \
        | sort -rn | cut -d' ' -f2-
}

kill_runc() {
    [ -d "$WORK/run/runc" ] || return 0
    for c in $(runc --root "$WORK/run/runc" list -q 2>/dev/null); do
        runc --root "$WORK/run/runc" delete --force "$c" 2>/dev/null || true
    done
}

cleanup() {
    [ -n "${WPID:-}" ] && kill -KILL "$WPID" 2>/dev/null || true
    [ -n "${COORD_PID:-}" ] && kill "$COORD_PID" 2>/dev/null || true
    kill_runc
    while read -r m; do
        [ -n "$m" ] || continue
        fsfreeze -u "$m" 2>/dev/null || true
        umount "$m" 2>/dev/null || umount -l "$m" 2>/dev/null || true
    done < <(mounts_under)
    if [ -n "${BLKD_PID:-}" ] && kill -0 "$BLKD_PID" 2>/dev/null; then
        (blk quit) >/dev/null 2>&1 || kill "$BLKD_PID"
        wait "$BLKD_PID" 2>/dev/null || true
    fi
    left=$(mounts_under | wc -l)
    [ "$left" -eq 0 ] || echo "WARNING: $left mounts left under $MNT"
    rmdir "$MNT" 2>/dev/null || true
    if [ "$KEEP" = 1 ]; then
        echo "kept: work dir $WORK (its block log: $WORK/blk.log)"
    else
        rm -rf "$WORK"
    fi
}
trap cleanup EXIT

# ── rootfs (as p3-no-trace.sh) ────────────────────────────────────────
ROOTFS=$WORK/rootfs
copy_with_libs() {
    install -D -m 755 "$1" "$ROOTFS$2"
    local libs lib
    libs=$(ldd "$1" 2>/dev/null | grep -o '/[^ ]*' || true)
    for lib in $libs; do
        [ -f "$lib" ] && install -D -m 755 "$lib" "$ROOTFS$lib"
    done
}
PY3=$(command -v python3)
copy_with_libs "$PY3" /usr/bin/python3
copy_with_libs "$BIN/taso-landlock" /usr/lib/taso/landlock
mkdir -p "$ROOTFS"/{proc,dev,sys,tmp,work,run/taso}
: > "$ROOTFS/run/taso/field.sock"
install -m 755 scripts/p3-relay.py "$ROOTFS/usr/bin/p3-relay.py"
install -m 755 "$AGENT" "$ROOTFS/usr/bin/p3-review-agent.py"
PY_LIB=$(python3 -c 'import sys, os; print(os.path.dirname(os.__file__))')
if [ -d "$PY_LIB" ]; then
    mkdir -p "$ROOTFS$(dirname "$PY_LIB")"
    cp -a "$PY_LIB" "$ROOTFS$PY_LIB"
fi
_so_libs=$(find "$ROOTFS$PY_LIB" -name '*.so' -exec ldd {} + 2>/dev/null \
    | grep -o '/[^ ]*' | sort -u || true)
for lib in $_so_libs; do
    [ -f "$ROOTFS$lib" ] || install -D -m 755 "$lib" "$ROOTFS$lib" 2>/dev/null || true
done

mkdir -p "$WORK/bin"
cp "$BIN/taso-wardend" "$BIN/taso-ctl" "$WORK/bin/"

# ── the block log, the coordinator ────────────────────────────────────
[ ! -S "$BLK_SOCK" ] || { echo "$BLK_SOCK exists: another run's daemon?" >&2; exit 2; }
mkdir -p "$MNT" "$WORK/spool"
[ -z "$(mounts_under)" ] || { echo "something is already mounted under $MNT" >&2; exit 2; }
"$BIN/taso-blkd" "$WORK/blk.log" "$BLK_SOCK" 2>"$OUT/blkd.err" &
BLKD_PID=$!
for _ in $(seq 100); do [ -S "$BLK_SOCK" ] && break; sleep 0.1; done
[ -S "$BLK_SOCK" ] || { echo "taso-blkd did not start; see $OUT/blkd.err" >&2; exit 1; }
"$BIN/taso-coordd" "$WORK/coord.redb" "$SOCK" 2>"$OUT/coordd.err" &
COORD_PID=$!
for _ in $(seq 100); do [ -S "$SOCK" ] && break; sleep 0.05; done
[ -S "$SOCK" ] || { echo "taso-coordd did not start" >&2; exit 1; }
echo "== taso-blkd and the coordinator are up"

# ── the Warden's config: P holds, and may fork into slots 1 and 2 ─────
NS="7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b"
P="rv-$RUN"
F1="$P-fork-1"
F2="$P-fork-2"
# write_config <file> <the "vessels" array, JSON>
write_config() {
    python3 - "$1" "$2" "$SOCK" "$BASE" "$WORK" "$ROOTFS" "$LANDLOCK" "$BLK_SOCK" "$MNT" <<'PY'
import json, sys
out, vessels, sock, base, work, rootfs, landlock, blk_sock, mnt = sys.argv[1:10]
rt = {
    "rootfs": rootfs,
    "host_uid_base": 200000,
    "args": ["/usr/bin/python3", "/usr/bin/p3-review-agent.py", "agent"],
    "memory_bytes": 268435456,
    "pids": 64,
}
if landlock == "1":
    rt["landlock_shim"] = "/usr/lib/taso/landlock"
json.dump({
    "warden": 1,
    "coordinator": {"remote": sock},
    "storage": {"blk": {"socket": blk_sock, "mounts": mnt, "spool": f"{work}/spool"}},
    "root": base,
    "state_dir": f"{work}/state",
    "store": f"{work}/store",
    "prefix": "vessels",
    "run_dir": f"{work}/run",
    "runtime": rt,
    "vessels": json.loads(vessels),
}, open(out, "w"), indent=1)
PY
}
write_config "$CFG" "[{\"namespace\": \"$NS\", \"subject\": \"$P\", \"uid_slot\": 0, \"effects\": \"hold\", \"forks\": {\"slots\": [1, 2]}}]"

# ── helpers ───────────────────────────────────────────────────────────
CHECKS=0
FAILS=0
ok()   { CHECKS=$((CHECKS + 1)); echo "  PASS $1"; }
bad()  { CHECKS=$((CHECKS + 1)); FAILS=$((FAILS + 1)); echo "  FAIL $1"; [ -z "${2:-}" ] || echo "       got: $2"; }
# check <what> <got> <python expression over d (the JSON in got), L (its
# lines, each as JSON) or s (its text)>
check() {
    if python3 - "$2" "$3" <<'PY'
import json, sys
s = sys.argv[1]
try:
    d = json.loads(s)
except ValueError:
    d = None
try:
    L = [json.loads(l) for l in s.splitlines() if l.strip()]
except ValueError:
    L = None
try:
    sys.exit(0 if eval(sys.argv[2], {"d": d, "L": L, "s": s}) else 1)
except Exception as e:
    print(f"       ({type(e).__name__}: {e})")
    sys.exit(1)
PY
    then ok "$1"; else bad "$1" "$2"; fi
}
# j <json> <python expression over d>: its value
j() { python3 -c 'import json,sys; d=json.loads(sys.argv[1]); print(eval(sys.argv[2], {"d": d}))' "$1" "$2"; }

die() {
    echo "STOPPED: $1" >&2
    echo "-- the Warden's last lines ($WLOG):" >&2
    tail -25 "$WLOG" >&2 || true
    exit 1
}

# wait_log <pattern (fixed string)> [seconds]
wait_log() {
    local n=$(( ${2:-60} * 10 ))
    for _ in $(seq "$n"); do
        grep -qF -- "$1" "$WLOG" 2>/dev/null && return 0
        sleep 0.1
    done
    return 1
}

# starts_of <subject>: how often this Warden has started it so far
starts_of() { grep -cF "] $1: dataset " "$WLOG" 2>/dev/null || true; }
# ds_of <subject> [n]: its dataset at its n-th start (1) under this
# Warden, once it is mounted
ds_of() {
    local ds="" n=${2:-1}
    for _ in $(seq 900); do
        ds=$(grep -F "] $1: dataset " "$WLOG" 2>/dev/null | sed -n "${n}p" | sed 's/.*: dataset //' || true)
        [ -n "$ds" ] && mountpoint -q "$MNT/$ds" && { echo "$ds"; return 0; }
        sleep 0.1
    done
    return 1
}
id_of()   { echo "${1##*/v-}"; }                    # dataset -> Vessel id (hex)
host_of() { local id; id=$(id_of "$1"); echo "vessel-taso-${id:0:7}"; }
sender_sock() { echo "$WORK/run/senders/$(id_of "$1").sock"; }

# hello <dataset>: the nonce of a new agent process of that Vessel
hello() { $HAND hello --dir "$MNT/$1" --host "$(host_of "$1")" --seen "$SEEN"; }
# tell <dataset> <nonce> <command json> [more args to cmd]
tell() { local ds=$1 nonce=$2 js=$3; shift 3; $HAND cmd --dir "$MNT/$ds" --nonce "$nonce" --json "$js" "$@"; }
ctl()  { "$WORK/bin/taso-ctl" "$@" --config "$CFG" 2>>"$OUT/ctl.err" || true; }

start_warden() {   # $1: the log's name; then: environment for it (NAME=value ...)
    WLOG=$OUT/warden-$1.err
    shift
    env "$@" "$WORK/bin/taso-wardend" "$CFG" >"${WLOG%.err}.out" 2>"$WLOG" &
    WPID=$!
}
# warden_ends <what>: the Warden ends by itself within 60 s, exit 0
warden_ends() {
    local ended="" rc=0
    for _ in $(seq 600); do
        kill -0 "$WPID" 2>/dev/null || { ended=1; break; }
        sleep 0.1
    done
    if [ -n "$ended" ]; then
        wait "$WPID" || rc=$?
        WPID=""
        if [ "$rc" = 0 ]; then ok "$1"; else bad "$1" "exit $rc: $(tail -3 "$WLOG")"; fi
    else
        bad "$1" "still running after 60 s: $(tail -3 "$WLOG")"
    fi
}

# ── A: a root Vessel that holds ───────────────────────────────────────
echo "== A: a root Vessel that holds"
start_warden 1
PDS=$(ds_of "$P") || die "P never started"
PN=$(hello "$PDS") || die "P's agent never said hello"
echo "   P is $PDS"

R=$(tell "$PDS" "$PN" '{"do":"effect","call":1,"request":"GET https://example.org/a"}')
check "1  the first action is held" "$R" 'd["result"] == "Held"'
OPA=$(j "$R" 'd["op"]')
R=$(tell "$PDS" "$PN" '{"do":"effect","call":2,"request":"GET https://example.org/b"}')
OPB=$(j "$R" 'd["op"]')
R=$(tell "$PDS" "$PN" '{"do":"effect","call":3,"request":"GET https://example.org/c"}')
check "1  the third action is held" "$R" 'd["result"] == "Held"'
OPC=$(j "$R" 'd["op"]')

L=$(ctl proposals "$P")
check "2  the reviewer lists three, none sealed" "$L" \
    'len(L) == 4 and all(not x["sealed"] for x in L[:3]) and L[3]["held"] == 3'
R=$(ctl approve "$P" "$OPA")
check "2  an action whose turn has not ended is not approved" "$R" \
    '"refused" in d and "approved" not in d'

R=$(tell "$PDS" "$PN" '{"do":"turn_end"}')
check "3  the turn is sealed" "$R" 'd["type"] == "TurnEnd" and d["sealed"] is not None'
L=$(ctl proposals "$P")
check "3  three listed, sealed, with the exact requests" "$L" \
    '[x["request_text"] for x in L[:3]] == ["GET https://example.org/" + c for c in "abc"] and all(x["sealed"] for x in L[:3])'

R=$(ctl approve "$P" "$OPA")
check "4  the first is approved" "$R" 'd.get("approved") is True and d["before"] is False'
R=$(ctl approve "$P" "$OPA")
check "4  approved again: taken before" "$R" 'd.get("approved") is True and d["before"] is True'
L=$(ctl proposals "$P")
check "4  two are still held" "$L" 'L[-1]["held"] == 2'

R=$($HAND sender --socket "$(sender_sock "$PDS")" --receipt "page a") || die "P's sender failed"
check "5  the sender is offered the approved action only" "$R" \
    "[(e['op'], e['request'], e['unknown']) for e in d['effects']] == [($OPA, 'GET https://example.org/a', False)]"
check "5  its report is taken" "$R" 'd["outcomes"][0]["refused"] is None'
R=$(tell "$PDS" "$PN" "{\"do\":\"result\",\"op\":$OPA}")
check "6  the agent reads the receipt" "$R" 'd["state"] == "Applied" and d["receipt"] == "page a"'

R=$(ctl deny "$P" "$OPB" not on the allowlist)
check "7  the second is denied" "$R" 'd.get("denied") is True and d["before"] is False'
R=$(tell "$PDS" "$PN" "{\"do\":\"result\",\"op\":$OPB}")
check "7  its agent reads the reason" "$R" \
    'd["state"] == "NotApplied" and "denied" in d["reason"] and "not on the allowlist" in d["reason"]'
R=$(ctl approve "$P" "$OPB")
check "7  a denied action is not approved" "$R" '"refused" in d'
R=$(ctl deny "$P" "$OPA" too late)
check "7  an approved action is not denied" "$R" '"refused" in d'

R=$(tell "$PDS" "$PN" "{\"do\":\"result\",\"op\":$OPC}")
check "8  the third is still held" "$R" 'd["state"] == "Held"'
R=$(ctl deny "$P" "$OPC" not needed)
check "8  and is denied" "$R" 'd.get("denied") is True'
L=$(ctl proposals "$P")
check "8  nothing is held any more" "$L" 'len(L) == 1 and L[-1]["held"] == 0'
R=$(tell "$PDS" "$PN" '{"do":"turn_end"}')
check "8  the next turn is sealed" "$R" 'd["sealed"] is not None'

# fork <parent dataset> <parent nonce>: ask until the Seal is shipped
fork() {
    local r=""
    for _ in $(seq 100); do
        r=$(tell "$1" "$2" '{"do":"fork"}') || return 1
        [ "$(j "$r" 'd["result"]')" = Forked ] && { echo "$r"; return 0; }
        sleep 0.2
    done
    echo "$r"
}

# ── B: a fork whose agent goes before its sender has answered ─────────
echo "== B: a fork whose agent goes before its sender has answered"
R=$(fork "$PDS" "$PN") || die "P's agent did not answer the fork"
check "9  P forks" "$R" "d['result'] == 'Forked' and d['child'] == '$F1'"
F1DS=$(ds_of "$F1") || die "the first fork never started"
F1N=$(hello "$F1DS") || die "the first fork's agent never said hello"
echo "   the fork is $F1DS"
R=$(tell "$F1DS" "$F1N" '{"do":"effect","call":1,"request":"GET https://example.org/f1"}')
check "9  the fork's action is held" "$R" 'd["result"] == "Held"'
OPF1=$(j "$R" 'd["op"]')
tell "$F1DS" "$F1N" '{"do":"write","path":"made-by-fork-1","text":"fork 1 was here\n"}' >/dev/null
R=$(tell "$F1DS" "$F1N" '{"do":"turn_end"}')
check "9  the fork's turn is sealed" "$R" 'd["sealed"] is not None'
R=$(ctl approve "$F1" "$OPF1")
check "9  the reviewer approves the fork's action" "$R" 'd.get("approved") is True'
R=$(tell "$F1DS" "$F1N" "{\"do\":\"result\",\"op\":$OPF1}")
check "9  the fork's agent sees it on its way" "$R" 'd["state"] == "Pending"'
tell "$F1DS" "$F1N" '{"do":"exit","code":0}' >/dev/null

if wait_log "] $F1: its agent is gone and 1 released action(s) have no outcome yet" 60; then
    ok "10 the Warden keeps the fork open for its sender, and says so"
else
    bad "10 the Warden keeps the fork open for its sender, and says so" "$(grep -F "] $F1:" "$WLOG" | tail -5)"
fi
R=$(tell "$PDS" "$PN" "{\"do\":\"promote\",\"child\":\"$F1\"}")
check "11 the promotion of a waiting fork is refused" "$R" \
    "d['result'] == 'Refused' and 'still waits for its sender' in d['reason'] and '(op $OPF1)' in d['reason']"

R=$($HAND sender --socket "$(sender_sock "$F1DS")" --receipt "page f1") || die "the first fork's sender failed"
check "12 the fork's sender is offered the action" "$R" \
    "[(e['op'], e['request'], e['unknown']) for e in d['effects']] == [($OPF1, 'GET https://example.org/f1', False)]"
check "12 its report is taken" "$R" 'd["outcomes"][0]["refused"] is None and d["outcomes"][0]["type"] == "Outcome"'

# promote <child>: ask until taken (the fork's run ends just after its
# sender's report); the answer, or the Warden's line, whichever is seen
# first (P is started again on the fork's files, the answer's file with it).
promote() {
    local r=""
    for _ in $(seq 50); do
        r=$(tell "$PDS" "$PN" "{\"do\":\"promote\",\"child\":\"$1\"}" \
                --or-log "$WLOG" --pattern "] $P: promoted \"$1\" at Seal") || return 1
        case "$r" in *'"Refused"'*) sleep 0.2 ;; *) echo "$r"; return 0 ;; esac
    done
    echo "$r"
}
STARTS=$(starts_of "$P")
R=$(promote "$F1") || die "P's agent did not answer the promotion"
check "13 P promotes the answered fork" "$R" 'd.get("from_log") or d.get("result") == "Promoted"'
PDS=$(ds_of "$P" $((STARTS + 1))) || die "P was not started again after the promotion"
PN=$(hello "$PDS") || die "P's agent never said hello after the promotion"
check "13 P runs on the fork's files" "$(cat "$MNT/$PDS/made-by-fork-1" 2>&1)" 's.strip() == "fork 1 was here"'

# ── C: a Warden that is killed while a fork waits ─────────────────────
echo "== C: a Warden that is killed while a fork waits"
R=$(fork "$PDS" "$PN") || die "P's agent did not answer the second fork"
check "14 P forks again" "$R" "d['result'] == 'Forked' and d['child'] == '$F2'"
F2DS=$(ds_of "$F2") || die "the second fork never started"
F2N=$(hello "$F2DS") || die "the second fork's agent never said hello"
echo "   the fork is $F2DS"
R=$(tell "$F2DS" "$F2N" '{"do":"effect","call":1,"request":"GET https://example.org/f2"}')
OPF2=$(j "$R" 'd["op"]')
tell "$F2DS" "$F2N" '{"do":"write","path":"made-by-fork-2","text":"fork 2 was here\n"}' >/dev/null
R=$(tell "$F2DS" "$F2N" '{"do":"turn_end"}')
check "14 the second fork's turn is sealed" "$R" 'd["sealed"] is not None'
R=$(ctl approve "$F2" "$OPF2")
check "14 the reviewer approves its action" "$R" 'd.get("approved") is True'
tell "$F2DS" "$F2N" '{"do":"sleep"}' >/dev/null
kill -KILL "$WPID"; wait "$WPID" 2>/dev/null || true
kill_runc
echo "   the Warden is killed; no sender had come"

start_warden 2
if wait_log "] $P: its fork \"$F2\" still waits for its sender's answer to 1 released action(s) (op $OPF2): running it again for its sender only" 90; then
    ok "15 the next Warden finds the waiting fork at P's start"
else
    bad "15 the next Warden finds the waiting fork at P's start" "$(grep -F "] $P:" "$WLOG" | tail -5)"
fi
if wait_log "] $F2: here for its sender only: 1 released action(s) have no outcome yet" 90; then
    ok "15 the fork is run for its sender only"
else
    bad "15 the fork is run for its sender only" "$(grep -F "] $F2:" "$WLOG" | tail -5)"
fi
wait_log "] $F2: its agent is gone and 1 released action(s)" 60 || true
R=$($HAND sender --socket "$(sender_sock "$F2DS")" --receipt "page f2") || die "the second fork's sender failed"
check "15 its sender is offered the action, as unknown" "$R" \
    "[(e['op'], e['request'], e['unknown']) for e in d['effects']] == [($OPF2, 'GET https://example.org/f2', True)]"
check "16 its report is taken" "$R" 'd["outcomes"][0]["refused"] is None and d["outcomes"][0]["type"] == "Outcome"'
if wait_log "] $F2: its sender's socket is closed: 0 released action(s) still without an outcome" 60; then
    ok "16 the fork's run ends by itself"
else
    bad "16 the fork's run ends by itself" "$(grep -F "] $F2:" "$WLOG" | tail -5)"
fi
if grep -F "] $F2: agent exited" "$WLOG" >/dev/null; then
    bad "16 no agent was run for it" "$(grep -F "] $F2: agent exited" "$WLOG")"
else
    ok "16 no agent was run for it"
fi

PDS=$(ds_of "$P") || die "P did not start under the second Warden"
PN=$(hello "$PDS") || die "P's agent never said hello under the second Warden"
STARTS=$(starts_of "$P")
R=$(promote "$F2") || die "P's agent did not answer the second promotion"
check "17 P promotes the fork" "$R" 'd.get("from_log") or d.get("result") == "Promoted"'
PDS=$(ds_of "$P" $((STARTS + 1))) || die "P was not started again after the second promotion"
PN=$(hello "$PDS") || die "P's agent never said hello after the second promotion"
check "17 P runs on the second fork's files" "$(cat "$MNT/$PDS/made-by-fork-2" 2>&1)" 's.strip() == "fork 2 was here"'

tell "$PDS" "$PN" '{"do":"exit","code":0}' >/dev/null
warden_ends "18 the Warden ends by itself, exit 0"

# ── D: the Warden is killed in the middle of a decision ───────────────
# One Vessel a round, one held and sealed action.  The Warden runs with
# a hold (taso_core::hold, E3-3c) at the named place, the reviewer
# decides, and the Warden is SIGKILLed while it stands there:
#   effect.approved   the approval is recorded on the node, not shipped
#   ledger.shipped    the approval is shipped, the reviewer not answered
#   effect.denied     the denial is recorded, the reviewer not answered
# The next Warden must leave one consistent story, whichever side of the
# kill the record fell on: the reviewer asks again and is answered; an
# approved action is offered to the sender exactly once and the agent
# reads its receipt; a denied one is never offered and the agent reads
# the reason; nothing stays held.
echo "== D: the Warden is killed in the middle of a decision"
mkdir -p "$WORK/hold"
round() {   # round <n> <hold> <approve|deny>
    local n=$1 hold=$2 what=$3 v="rk-$1-$RUN" ds nonce r op l
    CFG=$WORK/warden-d$n.json
    write_config "$CFG" "[{\"namespace\": \"$NS\", \"subject\": \"$v\", \"uid_slot\": $((4 + n)), \"effects\": \"hold\"}]"
    rm -f "$WORK/hold/$hold".*
    start_warden "d$n-a" "TASO_E3_HOLD=$hold" "TASO_E3_HOLD_DIR=$WORK/hold"
    ds=$(ds_of "$v") || die "round $n: the Vessel never started"
    nonce=$(hello "$ds") || die "round $n: its agent never said hello"
    r=$(tell "$ds" "$nonce" "{\"do\":\"effect\",\"call\":1,\"request\":\"GET https://example.org/k$n\"}")
    op=$(j "$r" 'd["op"]')
    r=$(tell "$ds" "$nonce" '{"do":"turn_end"}')
    check "D$n the action is held and sealed" "$r" 'd["sealed"] is not None'
    : > "$WORK/hold/$hold.arm"
    if [ "$what" = approve ]; then ctl approve "$v" "$op" >"$OUT/d$n-first.txt" &
    else ctl deny "$v" "$op" not wanted >"$OUT/d$n-first.txt" & fi
    local cpid=$!
    local held=""
    for _ in $(seq 300); do [ -e "$WORK/hold/$hold.held" ] && { held=1; break; }; sleep 0.1; done
    if [ -n "$held" ]; then ok "D$n the Warden stands at $hold"; else bad "D$n the Warden stands at $hold" "$(tail -3 "$WLOG")"; fi
    kill -KILL "$WPID"; wait "$WPID" 2>/dev/null || true
    kill "$cpid" 2>/dev/null || true; wait "$cpid" 2>/dev/null || true
    kill_runc
    check "D$n the reviewer was not answered" "$(cat "$OUT/d$n-first.txt")" '"approved" not in s and "denied" not in s'

    start_warden "d$n-b"
    ds=$(ds_of "$v") || die "round $n: the Vessel did not start again"
    nonce=$(hello "$ds") || die "round $n: its agent never said hello again"
    if [ "$what" = approve ]; then
        r=$(ctl approve "$v" "$op")
        check "D$n asked again, the approval is answered" "$r" 'd.get("approved") is True'
        r=$($HAND sender --socket "$(sender_sock "$ds")" --receipt "page k$n") || die "round $n: the sender failed"
        check "D$n the sender is offered it exactly once" "$r" \
            "[(e['op'], e['request']) for e in d['effects']] == [($op, 'GET https://example.org/k$n')]"
        check "D$n its report is taken" "$r" 'd["outcomes"][0]["refused"] is None'
        r=$(tell "$ds" "$nonce" "{\"do\":\"result\",\"op\":$op}")
        check "D$n the agent reads the receipt" "$r" "d['state'] == 'Applied' and d['receipt'] == 'page k$n'"
        r=$($HAND sender --socket "$(sender_sock "$ds")" --receipt "again") || die "round $n: the sender failed"
        check "D$n it is not offered a second time" "$r" 'd["effects"] == []'
    else
        r=$(ctl deny "$v" "$op" not wanted)
        check "D$n asked again, the denial is answered" "$r" 'd.get("denied") is True'
        r=$(tell "$ds" "$nonce" "{\"do\":\"result\",\"op\":$op}")
        check "D$n the agent reads the reason" "$r" 'd["state"] == "NotApplied" and "denied" in d["reason"]'
        r=$($HAND sender --socket "$(sender_sock "$ds")" --receipt "never") || die "round $n: the sender failed"
        check "D$n the sender is offered nothing" "$r" 'd["effects"] == []'
        r=$(ctl approve "$v" "$op")
        check "D$n it cannot be approved afterwards" "$r" '"refused" in d'
    fi
    l=$(ctl proposals "$v")
    check "D$n nothing stays held" "$l" 'L[-1]["held"] == 0'
    tell "$ds" "$nonce" '{"do":"exit","code":0}' >/dev/null
    warden_ends "D$n the Warden ends by itself, exit 0"
}
round 1 effect.approved approve
round 2 ledger.shipped approve
round 3 effect.denied deny

echo "results in $OUT"
if [ "$FAILS" = 0 ]; then
    echo "P3 REVIEW PASS: $CHECKS checks" | tee "$OUT/summary.txt"
else
    echo "P3 REVIEW FAIL: $FAILS of $CHECKS checks failed" | tee "$OUT/summary.txt"
    exit 1
fi
