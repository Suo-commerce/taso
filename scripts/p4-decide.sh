#!/usr/bin/env bash
# p4-decide.sh: verdicts through the decider socket, under taso-wardend
# (P4 files 8d, 9 and 10; spec rev. 24 §5.1-5.3, §5.7, D72-D80).
#
#   scripts/p4-decide.sh zfs     (as root, from the repository root; not
#                                 through sudo, which drops cargo from PATH)
#   scripts/p4-decide.sh blk
#
# zfs: Vessel roots are new datasets under $P4B_ZFS_PARENT (default
#      tasotest/vessel): p4d-n1.  It must not exist; it is destroyed at the
#      end (only it, with everything under it).
# blk: a fresh taso-blkd on its own log; dataset p4d/n1 in it.
#
# One machine, node 1 (Warden 1), one coordinator and store.  V, the
# verifier Template, is made by taso-genesis as in p4-verify.sh.  First
# ten Vessels (p, f, h, s, c, k, x, y, pa, pf) each run two turns, nominate, and are
# attempted (one daemon run each).  Then the daemon runs in the
# background with k alone, as a long-running "keeper": the decider socket
# is up, k's session takes the verdicts on k (between its agent's
# requests), and the other five, not running, are opened here for theirs
# (D74).  The failpoint daemons (case 9) keep a second keeper, q, with no
# Candidate.  taso-decide is the caller, as root (peer uid 0).
#
# Cases (each prints its prediction before it runs, then PASS or FAIL):
#   1  V from a directory                          taso-genesis, ready
#   2  eight Vessels attempted                     p h s c k x y pass, f exits 7
#   3  pending                                     eight Candidates, one attempt each
#   4  sanction p (open here)                      Committed, finished into its
#                                                  Template; again: the same
#   5  f: sanction, never, hold                    Refused AttemptNotPassed,
#                                                  ClosedNever, Refused Closed
#   6  h: hold, then sanction                      Held, Committed
#   7  s: stale facts                              Refused StaleFacts
#   8  k on its running session                    Committed, not opened here;
#                                                  k keeps sealing turns
#   9  verdict.after_submitted (s), verdict.in_check (c): stop; the same
#      request sent again to a daemon without the failpoint commits
#  11  sanction.after_commit_accept (x), sanction.before_ready_accept (y):
#      committed, not finished; the next open finishes each once
#  12  a Vessel born from p's Template             Born from Template, exit 0
#  14  taso-ctl explain on p, f, p's Template,    every check holds; the
#      pa and V                                    decisions as recorded
#  13  taso-policy --once on pa (passes), pf (3)   Committed, ClosedNever; a
#                                                  dry run sends nothing
#  10  the coordinator log (last)                  the records each Vessel's
#                                                  verdicts and finishes accepted
#
# Touches, and nothing else:
#   /var/lib/taso-p4d/<mode>                 (removed at start, kept after)
#   /run/taso-p4d-<mode>-coord.sock
#   zfs: $P4B_ZFS_PARENT/p4d-n1              (created, destroyed at the end)
#   blk: /run/taso-p4d-blk.sock, /mnt/p4d and mounts under it (unmounted at
#        the end), the /dev/ublkb* devices taso-blkd creates for this run
#   runc containers under /var/lib/taso-p4d/<mode>/run1/runc (deleted)
#
# Exit 0 only if every check passed.

set -euo pipefail

MODE=${1:-}
[[ "$MODE" == zfs || "$MODE" == blk ]] || { echo "usage: $0 zfs|blk" >&2; exit 2; }

W=/var/lib/taso-p4d/$MODE
SOCK=/run/taso-p4d-$MODE-coord.sock
PARENT=${P4B_ZFS_PARENT:-tasotest/vessel}
BLK_SOCK=/run/taso-p4d-blk.sock
MNT=/mnt/p4d
LANDLOCK=${LANDLOCK:-1}
TURNS=2
BASE=200000            # runtime.host_uid_base of both nodes
TSLOT=9                # runtime.template_slot of both nodes
NS=7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d

COORD_PID=
DPID=
BLKD_PID=
ZFS_MADE=()
PASS=0
FAIL=0

say() { printf '\n== %s\n' "$*"; }
die() { printf 'ABORT: %s\n' "$*" >&2; exit 2; }

root_of() { # node -> its root dataset
    if [[ $MODE == zfs ]]; then echo "$PARENT/p4d-n$1"; else echo "p4d/n$1"; fi
}

mounts_under() {
    awk -v root="$MNT" '$5 == root || index($5, root "/") == 1 { print length($5), $5 }' /proc/self/mountinfo \
        | sort -rn | cut -d' ' -f2-
}

# One taso-blkd command; prints the answer, fails unless it starts "ok".
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

cleanup() {
    local rc=$?
    set +e
    for n in 1; do
        if [[ -d "$W/run$n/runc" ]]; then
            for c in $(runc --root "$W/run$n/runc" list -q 2>/dev/null); do
                runc --root "$W/run$n/runc" delete --force "$c" 2>/dev/null
            done
        fi
    done
    if [[ -n "$DPID" ]] && kill -0 "$DPID" 2>/dev/null; then
        kill -TERM "$DPID"; wait "$DPID" 2>/dev/null
    fi
    if [[ -n "$COORD_PID" ]] && kill -0 "$COORD_PID" 2>/dev/null; then
        kill "$COORD_PID"; wait "$COORD_PID" 2>/dev/null
    fi
    if [[ $MODE == zfs ]]; then
        for ds in "${ZFS_MADE[@]}"; do
            # -R: the Vessels are clones of the layer's snapshot, all
            # inside this root.
            zfs destroy -R "$ds" || echo "WARNING: could not destroy $ds"
        done
    else
        while read -r m; do
            [[ -n "$m" ]] || continue
            fsfreeze -u "$m" 2>/dev/null
            umount "$m" || umount -l "$m"
        done < <(mounts_under)
        if [[ -n "$BLKD_PID" ]] && kill -0 "$BLKD_PID" 2>/dev/null; then
            blk quit >/dev/null 2>&1 || kill "$BLKD_PID"
            wait "$BLKD_PID" 2>/dev/null
        fi
        left=$(mounts_under | wc -l)
        [[ "$left" -eq 0 ]] || echo "WARNING: $left mounts left under $MNT"
    fi
    rm -f "$SOCK"
    exit "$rc"
}
trap cleanup EXIT

# ── Checks before anything is touched ───────────────────────────────

[[ $EUID -eq 0 ]] || die "run as root"
[[ -f Cargo.toml && -d crates/taso-warden ]] || die "run from the repository root"
for t in runc ldd python3 cargo; do command -v "$t" >/dev/null || die "$t is missing"; done
[[ ! -S "$SOCK" ]] || die "$SOCK exists: another run's coordinator? (pgrep -x taso-coordd)"
if [[ $MODE == zfs ]]; then
    zfs list -H -o name "$PARENT" >/dev/null || die "no dataset $PARENT (set P4B_ZFS_PARENT)"
    for n in 1; do
        if zfs list -H -o name "$(root_of $n)" >/dev/null 2>&1; then
            die "$(root_of $n) exists (left by a previous run?): zfs destroy -R $(root_of $n)"
        fi
    done
else
    modprobe ublk_drv
    [[ -c /dev/ublk-control ]] || die "/dev/ublk-control missing"
    [[ ! -S "$BLK_SOCK" ]] || die "$BLK_SOCK exists: another run's daemon? (pgrep -x taso-blkd)"
    mkdir -p "$MNT"
    [[ -z "$(mounts_under)" ]] || die "something is already mounted under $MNT"
fi

say "building"
cargo build -q --release -p taso-warden -p taso-sim -p taso-landlock --bins
[[ $MODE == blk ]] && cargo build -q --release -p taso-blk
BIN=$PWD/target/release
for b in taso-wardend taso-genesis taso-coordd taso-logcheck taso-sim taso-landlock taso-decide taso-policy taso-ctl; do
    [[ -x "$BIN/$b" ]] || die "$BIN/$b was not built"
done
[[ $MODE == zfs ]] || [[ -x "$BIN/taso-blkd" ]] || die "$BIN/taso-blkd was not built"

rm -rf "$W"
mkdir -p "$W/store" "$W/src" "$W/out"
chmod 755 /var/lib/taso-p4d "$W"

# ── rootfs: the stand-in agent and the Landlock shim ────────────────

ROOTFS=$W/rootfs
copy_with_libs() {
    install -D -m 755 "$1" "$ROOTFS$2"
    ldd "$1" | grep -o '/[^ ]*' | while read -r lib; do install -D -m 755 "$lib" "$ROOTFS$lib"; done
}
copy_with_libs "$BIN/taso-sim" /usr/bin/taso-sim
copy_with_libs "$BIN/taso-landlock" /usr/lib/taso/landlock
mkdir -p "$ROOTFS"/{proc,dev,sys,tmp,work,run/taso}
: >"$ROOTFS/run/taso/field.sock"

# ── Storage, coordinator ────────────────────────────────────────────

if [[ $MODE == zfs ]]; then
    for n in 1; do
        zfs create "$(root_of $n)"
        ZFS_MADE+=("$(root_of $n)")
    done
else
    "$BIN/taso-blkd" "$W/blk.log" "$BLK_SOCK" 2>>"$W/blkd.err" &
    BLKD_PID=$!
    for _ in $(seq 100); do [[ -S "$BLK_SOCK" ]] && break; sleep 0.1; done
    [[ -S "$BLK_SOCK" ]] || die "taso-blkd socket did not appear; see $W/blkd.err"
    mkdir -p "$W/spool"
fi

printf '{"store": "%s", "prefix": "p4d"}\n' "$W/store" >"$W/store.json"
"$BIN/taso-coordd" "$W/coord.redb" "$SOCK" --store-config "$W/store.json" 2>>"$W/coordd.err" &
COORD_PID=$!
for _ in $(seq 100); do [[ -S "$SOCK" ]] && break; sleep 0.1; done
[[ -S "$SOCK" ]] || die "taso-coordd socket did not appear; see $W/coordd.err"

for n in 1; do mkdir -p "$W/state$n" "$W/run$n"; done

# The two classification maps (D58) and a verifier config (D57; opaque
# to nomination, file 7 reads it).
cat >"$W/map1.toml" <<'EOF2'
version = 1
[[rule]]
glob = "**"
class = "Source"
[[rule]]
glob = "scratch/"
class = "Scratch"
EOF2
cat >"$W/map2.toml" <<'EOF2'
version = 1
[[rule]]
glob = "nothing-here/"
class = "Source"
EOF2
printf 'entry = ["/bin/check"]\n' >"$W/vconf.toml"

# config NODE OUT ENTRY_JSON...: node NODE's Warden config with these
# Vessels (namespace $NS added), every one running taso-sim for $TURNS
# turns unless its entry says otherwise; node N classifies with map N.
config() {
    local node=$1 out=$2; shift 2
    python3 - "$node" "$out" "$@" <<PY
import json, sys
node, out, entries = int(sys.argv[1]), sys.argv[2], [json.loads(e) for e in sys.argv[3:]]
storage = "zfs" if "$MODE" == "zfs" else {"blk": {"socket": "$BLK_SOCK", "mounts": "$MNT", "spool": "$W/spool"}}
root = "$PARENT/p4d-n%d" % node if "$MODE" == "zfs" else "p4d/n%d" % node
json.dump({
    "warden": node,
    "coordinator": {"remote": "$SOCK"},
    "storage": storage,
    "root": root,
    "state_dir": "$W/state%d" % node,
    "store": "$W/store",
    "prefix": "p4d",
    "run_dir": "$W/run%d" % node,
    "sanction": {"classmap": "$W/map%d.toml" % node, "allowed_exclude": ["Scratch"]},
    "runtime": {
        "rootfs": "$ROOTFS",
        "host_uid_base": $BASE,
        "template_slot": $TSLOT,
        "landlock_shim": "/usr/lib/taso/landlock" if "$LANDLOCK" == "1" else None,
        "args": ["/usr/bin/taso-sim", "--turns", "$TURNS", "--txns", "2", "--rows", "4",
                 "--turn-sleep-ms", "50", "--stats", "/work/sim-stats.json"],
        "memory_bytes": 268435456,
        "pids": 64,
    },
    "vessels": [dict(namespace="$NS", **e) for e in entries],
}, open(out, "w"), indent=1)
PY
}

# Node 1's config for taso-genesis: the same node, no Vessels.
config 1 "$W/genesis1.json"

say "storage $MODE; coordinator $SOCK; work directory $W"

# ── Helpers ─────────────────────────────────────────────────────────

# tree DIR [VARIANT]: the same files every time, owned by root (slot 0),
# with fixed times.
tree() {
    local d=$1 v=${2:-}
    mkdir -p "$d/app/lib" "$d/etc"
    printf "print('hello')\n" >"$d/app/main.py"
    printf 'X = 1\n' >"$d/app/lib/util.py"
    printf 'debug = false\n' >"$d/etc/app.toml"
    [[ -z "$v" ]] || printf '%s\n' "$v" >"$d/app/variant-$v.py"
    chown -R 0:0 "$d"
    chmod 755 "$d" "$d/app" "$d/app/lib" "$d/etc"
    find "$d" -type f -exec chmod 644 {} +
    find "$d" -mindepth 1 ! -type d -exec touch -h -d @1700000000 {} +
    find "$d" -depth -type d -exec touch -d @1600000000 {} +
}

cat >"$W/map.toml" <<'EOF'
version = 1
[[rule]]
glob = "**"
class = "Source"
EOF

# genesis CASE DIR: a Template from DIR on node 1; prints its id.
genesis() {
    local rc=0
    "$BIN/taso-genesis" "$W/genesis1.json" --from "$2" --best-effort --classmap "$W/map.toml" \
        --actor p4d --reason "file 8d on taso-test" >"$W/out/$1.json" 2>"$W/out/$1.err" || rc=$?
    [[ $rc == 0 ]] || return 1
    python3 -c 'import json,sys; v=json.load(open(sys.argv[1])); print(v["template_id"] if v.get("outcome")=="ready" else "")' "$W/out/$1.json"
}

# wardend CASE NODE CONFIG [ENV=VALUE...]: run node NODE's Warden to the
# end; stdout and stderr to $W/out/CASE.{out,err}; exit status to RC.
wardend() {
    local case=$1 node=$2 cfg=$3; shift 3
    RC=0
    env "$@" timeout 600 "$BIN/taso-wardend" "$cfg" >"$W/out/$case.out" 2>"$W/out/$case.err" || RC=$?
}

expect() { # expect WHAT TEST...: PASS if the test command succeeds
    local what=$1; shift
    WHY=
    if "$@"; then
        PASS=$((PASS + 1)); echo "  PASS  $what"
    else
        FAIL=$((FAIL + 1)); echo "  FAIL  $what${WHY:+ ($WHY)}"
    fi
}

# is GOT WANT: equal; on a difference, the FAIL line says both.
is() { [[ "$1" == "$2" ]] || { WHY="got '$1', want '$2'"; return 1; }; }
count() { grep -c -- "$2" "$W/out/$1" || true; }   # count FILE PATTERN

# vessel SUBJECT SLOT [EXTRA_JSON_FIELDS]: an entry with V as its
# verifier and $W/vconf-SUBJECT.toml as its verifier config.
vessel() {
    printf '{"subject": "%s", "uid_slot": %s, "verifier": {"template": "%s", "config": "%s", "version": 1}%s}' \
        "$1" "$2" "$V" "$W/vconf-$1.toml" "${3:+, $3}"
}

# vconf SUBJECT SCRIPT [EXTRA_TOML]: SUBJECT's verifier runs `sh -c SCRIPT`.
vconf() {
    python3 - "$W/vconf-$1.toml" "$2" "${3:-}" <<'PY'
import json, sys
path, script, extra = sys.argv[1:4]
open(path, "w").write("version = 1\nentry = [\"/bin/sh\", \"-c\", %s]\n%s" % (json.dumps(script), extra))
PY
}

# sim TURNS [NOMINATE...]: a Vessel's own runtime running taso-sim for
# TURNS turns, then asking once per argument (classes, comma-separated).
sim() {
    local turns=$1; shift
    python3 - "$turns" "$@" <<'PY'
import json, sys
args = ["/usr/bin/taso-sim", "--turns", sys.argv[1], "--txns", "2", "--rows", "4",
        "--turn-sleep-ms", "50", "--stats", "/work/sim-stats.json"]
for n in sys.argv[2:]:
    args += ["--nominate", n]
print('"runtime": ' + json.dumps({"args": args}))
PY
}

# The dataset the daemon logged for SUBJECT in case CASE ("" if none).
dataset_of() {
    { grep -o "\] $2: dataset [^ ]*\$" "$W/out/$1.err" || true; } | head -1 | sed 's/.*: dataset //'
}

# lc NODE ID: taso-logcheck of Vessel ID's local log on NODE.
lc() { "$BIN/taso-logcheck" "$SOCK" "$W/state$1" "$2"; }

# The ownership of Vessel ID as node NODE's log check reads it: "holder epoch".
owner_of() {
    lc "$1" "$2" | python3 -c 'import json,sys; o=json.load(sys.stdin)["ownership"]; print(o["holder"], o["epoch"])'
}


# The Candidates the coordinator log holds for Vessel ID (read on NODE):
# "<accepted records> <content holds>".
coordlog_of() {
    lc "$1" "$2" | python3 -c '
import json, sys
c = json.load(sys.stdin).get("coordlog") or {}
print(c.get("accepted", 0), sum(1 for h in c.get("holds", []) if h.startswith("content:")))'
}

# The answer node NODE's daemon logged for SUBJECT's nominations by KIND
# (Agent or Config) in case CASE: one line each.
answers() { # answers CASE SUBJECT KIND
    { grep -o "\] $2: nomination ($3): .*\$" "$W/out/$1.err" || true; } | sed 's/.*: nomination ([A-Za-z]*): //'
}

# The contract records in Vessel ID's local log on NODE.
contracts_of() {
    lc "$1" "$2" | python3 -c '
import json, sys
print(sum(1 for f in json.load(sys.stdin)["frames"] if f["kind"] == "contract"))'
}

# The candidate id in a "Nominated { candidate: \"<hex>\" }" answer.
cand() { sed -n 's/^Nominated { candidate: "\([0-9a-f]*\)" }$/\1/p'; }

# The newest Seal's lsn in Vessel ID's local log on NODE.
last_seal() {
    lc "$1" "$2" | python3 -c '
import json, sys
s = [f["lsn"] for f in json.load(sys.stdin)["frames"] if f["kind"] == "seal"]
print(s[-1] if s else 0)'
}


# The attempt lines node 1's daemon logged for SUBJECT in case CASE.
attempt_lines() { # attempt_lines CASE SUBJECT
    { grep -o "\] $2: attempt .*\$" "$W/out/$1.err" || true; } | sed "s/.*\] $2: //"
}

# How SUBJECT's attempt finished in case CASE ("" if it did not).
finished() { # finished CASE SUBJECT
    attempt_lines "$1" "$2" | sed -n 's/^attempt [0-9a-f]*: finished \(.*\), [0-9]* bytes of output$/\1/p'
}

# Datasets an attempt's /candidate left under node 1's root.
candidates_left() {
    local r; r=$(root_of 1)
    if [[ $MODE == zfs ]]; then
        zfs list -H -o name -r "$r" | grep -c "^$r/a-" || true
    else
        blk names | tr ' ' '\n' | grep -c "^$r/a-" || true
    fi
}

# The verifier image: the host's sh, cat and sleep with their libraries,
# and the mount targets.
verifier_tree() {
    local d=$1 b lib
    mkdir -p "$d"/{proc,dev,sys,tmp,candidate,bin}
    for b in sh cat sleep; do
        local host; host=$(readlink -f "$(command -v "$b")")
        install -D -m 755 "$host" "$d/bin/$b"
        ldd "$host" | grep -o '/[^ ]*' | while read -r lib; do install -D -m 755 "$lib" "$d$lib"; done
    done
    chown -hR 0:0 "$d"
}

# ── 1. V ────────────────────────────────────────────────────────────

say "1. V, the verifier Template, from a directory (predict: taso-genesis exit 0, ready)"
verifier_tree "$W/src/v"
V=$(genesis 1-v "$W/src/v" || true)
expect "V ready" bash -c "[[ '$V' =~ ^[0-9a-f]{32}$ ]]"
[[ -n "$V" ]] || die "no V: see $W/out/1-v.err"

# ── 2. Six Vessels attempted ────────────────────────────────────────

say "2. p h s c k x y pa: a verifier that passes, f: one that exits 7, pf: 3 (predict: each run exit 0; each one attempt finished as said)"
declare -A ID SLOT=([p]=1 [f]=2 [h]=3 [s]=4 [c]=5 [k]=6 [x]=10 [y]=11 [pa]=13 [pf]=14)
for v in p f h s c k x y pa pf; do
    case $v in
        f) vconf "$v" 'exit 7' ;;
        pf) vconf "$v" 'exit 3' ;;
        *) vconf "$v" 'exit 0' ;;
    esac
    config 1 "$W/$v.json" "$(vessel "$v" "${SLOT[$v]}" "$(sim "$TURNS" Scratch)")"
    wardend "2-$v" 1 "$W/$v.json"
    expect "$v: exit 0" is "$RC" 0
    want="Exit { code: 0 }"; [[ $v == f ]] && want="Exit { code: 7 }"; [[ $v == pf ]] && want="Exit { code: 3 }"
    expect "$v: finished $want" is "$(finished "2-$v" "$v")" "$want"
    ds=$(dataset_of "2-$v" "$v")
    ID[$v]=${ds##*/v-}
    [[ "${ID[$v]}" =~ ^[0-9a-f]{32}$ ]] || die "no dataset for $v: see $W/out/2-$v.err"
done

# ── The daemon in the background, with the keeper ───────────────────

# The keeper's own runtime: turns every second, long enough for every
# case; the daemon is stopped with SIGTERM.
KEEP='"runtime": {"args": ["/usr/bin/taso-sim", "--turns", "100000", "--txns", "1", "--rows", "1", "--turn-sleep-ms", "1000", "--stats", "/work/sim-stats.json"]}'
config 1 "$W/keep.json" "$(vessel k "${SLOT[k]}" "$KEEP")"
# A second keeper, q, for the failpoint daemons (case 9): no Candidate.
config 1 "$W/keep-q.json" "$(vessel q 7 "$KEEP")"
DSOCK=$W/run1/decide/decide.sock

# sealed_after KEEPER_ID LSN: wait until the keeper's log has a Seal past
# LSN (its agent runs); fails after 60 s.
sealed_after() {
    for _ in $(seq 300); do
        [[ "$(last_seal 1 "$1")" -gt "$2" ]] && return 0
        kill -0 "$DPID" 2>/dev/null || return 1
        sleep 0.2
    done
    return 1
}

# daemon CASE CONFIG KEEPER [ENV=VALUE...]: start node 1's Warden with
# CONFIG's keeper; wait for the decider socket and for the keeper's agent
# to have sealed a turn.
daemon() {
    local case=$1 cfg=$2 keeper=$3; shift 3
    local before=0 kid
    env "$@" "$BIN/taso-wardend" "$cfg" >"$W/out/$case.out" 2>"$W/out/$case.err" &
    DPID=$!
    for _ in $(seq 300); do
        kid=$(dataset_of "$case" "$keeper"); kid=${kid##*/v-}
        [[ -S "$DSOCK" && "$kid" =~ ^[0-9a-f]{32}$ ]] && break
        kill -0 "$DPID" 2>/dev/null || die "taso-wardend exited early; see $W/out/$case.err"
        sleep 0.2
    done
    [[ "$kid" =~ ^[0-9a-f]{32}$ ]] || die "the keeper $keeper did not start; see $W/out/$case.err"
    [[ "$keeper" == k ]] && before=$(last_seal 1 "$kid")
    sealed_after "$kid" "$before" || die "the keeper $keeper sealed no turn; see $W/out/$case.err"
}

stop_daemon() {
    kill -TERM "$DPID"; wait "$DPID" 2>/dev/null || true
    DPID=
}

# decide CASE ARGS...: taso-decide; its JSON to $W/out/CASE.json, exit
# status to DRC.
decide() {
    local case=$1; shift
    DRC=0
    timeout 120 "$BIN/taso-decide" "$W/keep.json" "$@" >"$W/out/$case.json" 2>"$W/out/$case.err" || DRC=$?
}

# jf CASE KEY: a top-level field of CASE's JSON ("" if absent).
jf() {
    python3 -c 'import json,sys; v=json.load(open(sys.argv[1])); print(v.get(sys.argv[2], ""))' "$W/out/$1.json" "$2"
}

# The pending items of Vessel ID in CASE's listing: "<candidate> <attempt>"
# per attempt.
pending_of() { # pending_of CASE ID
    python3 -c '
import json, sys
for i in json.load(open(sys.argv[1]))["pending"]:
    if i["chronicle"] == sys.argv[2]:
        for a in i["attempts"]:
            print(i["candidate_id"], a["attempt_id"])' "$W/out/$1.json" "$2"
}

# verdict CASE VESSEL DECISION [OPTIONS...]: a verdict on VESSEL's
# Candidate and attempt, as listed in case 3.
verdict() {
    local case=$1 v=$2 d=$3; shift 3
    decide "$case" verdict "${CAND[$v]}" "${ATT[$v]}" "$d" --actor p4d --reason "file 8d" "$@"
}

# finished_sanction CASE ID TID: how often the daemon logged Vessel ID's
# sanction finished into Template TID (file 9).
finished_sanction() { count "$1.err" "\] $2: sanction of Candidate [0-9a-f]*: Template $3 ready, sanction completed$"; }

# opened CASE ID: how often the daemon opened Vessel ID for the decider.
opened() { count "$1.err" "\] $2: opened here for the decider (D74)$"; }

say "the daemon with the keeper k (predict: the decider socket appears; k seals a turn)"
daemon 3-daemon "$W/keep.json" k
expect "decider socket" test -S "$DSOCK"

# ── 3. Pending ──────────────────────────────────────────────────────

say "3. pending (predict: ten Candidates, one finished attempt each)"
decide 3-pending pending
expect "taso-decide exit 0" is "$DRC" 0
declare -A CAND ATT
for v in p f h s c k x y pa pf; do
    expect "$v: one attempt" is "$(pending_of 3-pending "${ID[$v]}" | wc -l)" 1
    read -r CAND[$v] ATT[$v] < <(pending_of 3-pending "${ID[$v]}") || true
done
expect "ten items" is "$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))["pending"]))' "$W/out/3-pending.json")" 10

# ── 4. p: sanction ──────────────────────────────────────────────────

say "4. sanction p, not running (predict: Committed with a template_id; sent again: the same; opened here once per verdict, twice; the sanction finished into that Template once (file 9); p no longer pending)"
verdict 4-p p sanction
expect "Committed" is "$(jf 4-p answer)" Committed
TID=$(jf 4-p template_id)
expect "a template_id" bash -c "[[ '$TID' =~ ^[0-9a-f]{32}$ ]]"
decide 4-p-again resend "$(jf 4-p request)"
expect "again: Committed" is "$(jf 4-p-again answer)" Committed
expect "again: the same template_id" is "$(jf 4-p-again template_id)" "$TID"
expect "opened here twice (once per verdict)" is "$(opened 3-daemon "${ID[p]}")" 2
expect "finished into its Template once" is "$(finished_sanction 3-daemon "${ID[p]}" "$TID")" 1
decide 4-pending pending
expect "p no longer pending" is "$(pending_of 4-pending "${ID[p]}" | wc -l)" 0

# ── 5. f: the failed attempt ────────────────────────────────────────

say "5. f exits 7 (predict: sanction Refused AttemptNotPassed, the same again; never ClosedNever, the same again; a new hold Refused Closed)"
verdict 5-f-s f sanction
expect "sanction: Refused" is "$(jf 5-f-s answer)" Refused
expect "rule AttemptNotPassed" is "$(jf 5-f-s rule)" AttemptNotPassed
decide 5-f-s-again resend "$(jf 5-f-s request)"
expect "again: Refused AttemptNotPassed" is "$(jf 5-f-s-again answer) $(jf 5-f-s-again rule)" "Refused AttemptNotPassed"
verdict 5-f-n f never --never "exits 7"
expect "never: ClosedNever" is "$(jf 5-f-n answer)" ClosedNever
decide 5-f-n-again resend "$(jf 5-f-n request)"
expect "again: ClosedNever" is "$(jf 5-f-n-again answer)" ClosedNever
verdict 5-f-h f hold --like "$(jf 5-f-s request)"
expect "hold after the close: Refused Closed" is "$(jf 5-f-h answer) $(jf 5-f-h rule)" "Refused Closed"
decide 5-pending pending
expect "f no longer pending" is "$(pending_of 5-pending "${ID[f]}" | wc -l)" 0

# ── 6. h: hold, then sanction ───────────────────────────────────────

say "6. h (predict: hold Held, still pending; sanction Committed, finished into its Template)"
verdict 6-h-h h hold
expect "Held" is "$(jf 6-h-h answer)" Held
decide 6-pending pending
expect "still pending" is "$(pending_of 6-pending "${ID[h]}" | wc -l)" 1
verdict 6-h-s h sanction
expect "Committed" is "$(jf 6-h-s answer)" Committed
expect "finished into its Template" is "$(finished_sanction 3-daemon "${ID[h]}" "$(jf 6-h-s template_id)")" 1

# ── 7. s: stale facts ───────────────────────────────────────────────

say "7. s with facts not its Candidate's (predict: Refused StaleFacts; still pending)"
verdict 7-s s sanction --facts-hash 0000000000000000000000000000000000000000000000000000000000000000
expect "Refused StaleFacts" is "$(jf 7-s answer) $(jf 7-s rule)" "Refused StaleFacts"
decide 7-pending pending
expect "still pending" is "$(pending_of 7-pending "${ID[s]}" | wc -l)" 1

# ── 8. k: on its running session ────────────────────────────────────

say "8. sanction k while its agent runs (predict: Committed; finished into its Template on its session; k not opened here; its session logged the verdict; k seals another turn)"
verdict 8-k k sanction
expect "Committed" is "$(jf 8-k answer)" Committed
expect "finished on its session" is "$(finished_sanction 3-daemon "${ID[k]}" "$(jf 8-k template_id)")" 1
expect "k not opened here" is "$(opened 3-daemon "${ID[k]}")" 0
expect "the verdict logged for k" is "$(count 3-daemon.err "\] ${ID[k]}: verdict [0-9a-f]* on Candidate ${CAND[k]} from uid 0 pid [0-9]*: Committed")" 1
expect "k seals a turn after its sanction" sealed_after "${ID[k]}" "$(last_seal 1 "${ID[k]}")"
stop_daemon

# ── 9. Failpoints ───────────────────────────────────────────────────

say "9a. verdict.after_submitted on s (predict: an error, the Candidate not committed; sent again to a daemon without it: Committed)"
daemon 9a-daemon "$W/keep-q.json" q TASO_FAILPOINT=verdict.after_submitted
verdict 9a-s s sanction
expect "taso-decide exit 1" is "$DRC" 1
expect "stopped at the failpoint" bash -c "grep -q 'stopped at failpoint verdict.after_submitted' '$W/out/9a-s.json'"
REQ_S=$(jf 9a-s request)
stop_daemon

say "9b. verdict.in_check on c (predict: an error, the Candidate not committed)"
daemon 9b-daemon "$W/keep-q.json" q TASO_FAILPOINT=verdict.in_check
verdict 9b-c c sanction
expect "taso-decide exit 1" is "$DRC" 1
expect "stopped at the failpoint" bash -c "grep -q 'stopped at failpoint verdict.in_check' '$W/out/9b-c.json'"
REQ_C=$(jf 9b-c request)
stop_daemon

say "9c. both requests sent again, no failpoint (predict: Committed each; nothing left pending)"
daemon 9c-daemon "$W/keep-q.json" q
decide 9c-s resend "$REQ_S"
expect "s: Committed" is "$(jf 9c-s answer)" Committed
decide 9c-c resend "$REQ_C"
expect "c: Committed" is "$(jf 9c-c answer)" Committed
decide 9c-pending pending
expect "s and c finished" is "$(( $(finished_sanction 9c-daemon "${ID[s]}" "$(jf 9c-s template_id)") + $(finished_sanction 9c-daemon "${ID[c]}" "$(jf 9c-c template_id)") ))" 2
expect "only x, y, pa and pf pending" is "$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))["pending"]))' "$W/out/9c-pending.json")" 4
stop_daemon

# ── 11. A sanction's finish stopped (file 9) ────────────────────────

say "11a. sanction.after_commit_accept on x (predict: Committed; the finish not run; the sanction stays committed)"
daemon 11a-daemon "$W/keep-q.json" q TASO_FAILPOINT=sanction.after_commit_accept
verdict 11a-x x sanction
expect "Committed" is "$(jf 11a-x answer)" Committed
TX=$(jf 11a-x template_id)
expect "stopped after the commit" is "$(count 11a-daemon.err "\] ${ID[x]}: stopped at failpoint sanction.after_commit_accept")" 1
expect "not finished" is "$(finished_sanction 11a-daemon "${ID[x]}" "$TX")" 0
stop_daemon

say "11b. sanction.before_ready_accept on y (predict: Committed; the finish stopped before TemplateReady is accepted)"
daemon 11b-daemon "$W/keep-q.json" q TASO_FAILPOINT=sanction.before_ready_accept
verdict 11b-y y sanction
expect "Committed" is "$(jf 11b-y answer)" Committed
TY=$(jf 11b-y template_id)
expect "not finished at the failpoint" is "$(count 11b-daemon.err "\] ${ID[y]}: sanction of Candidate [0-9a-f]*: Template $TY not finished: .*stopped at failpoint sanction.before_ready_accept")" 1
stop_daemon

say "11c. the same requests again, no failpoint (predict: Committed each, the same template_ids; both finished when opened (the restart rule), once each)"
daemon 11c-daemon "$W/keep-q.json" q
decide 11c-x resend "$(jf 11a-x request)"
expect "x: Committed, the same Template" is "$(jf 11c-x answer) $(jf 11c-x template_id)" "Committed $TX"
decide 11c-y resend "$(jf 11b-y request)"
expect "y: Committed, the same Template" is "$(jf 11c-y answer) $(jf 11c-y template_id)" "Committed $TY"
expect "x finished" is "$(finished_sanction 11c-daemon "${ID[x]}" "$TX")" 1
expect "y finished" is "$(finished_sanction 11c-daemon "${ID[y]}" "$TY")" 1
stop_daemon

# ── 12. A Vessel born from a sanctioned Template ────────────────────

say "12. b, born from p's Template (predict: exit 0; 'Born from Template' p's; its turns sealed)"
config 1 "$W/b.json" "$(printf '{"subject": "b", "uid_slot": 12, "template": "%s", %s}' "$TID" "$(sim 1)")"
wardend 12-b 1 "$W/b.json"
expect "exit 0" is "$RC" 0
expect "born from p's Template" is "$(count 12-b.err "\] b: Born from Template $TID")" 1

# ── 13. taso-policy, the default caller (file 10) ───────────────

cat >"$W/policy.toml" <<'EOF2'
version = 1
actor = "taso-policy"
default = "hold"

[[rule]]
name = "no secrets"
decision = "never"
reason = "a secret is in the input"
when = { input_secret = { min = 1 } }

[[rule]]
name = "failed"
decision = "never"
when = { outcome = { in = ["fail", "timeout", "output_limit"] } }

[[rule]]
name = "passed"
decision = "sanction"
when = { outcome = "pass", input_unknown = 0, input_unsupported = 0 }
EOF2

# policy CASE ARGS...: taso-policy --once; its lines to $W/out/CASE.jsonl,
# exit status to PRC.
policy() {
    local case=$1; shift
    PRC=0
    timeout 300 "$BIN/taso-policy" "$W/keep.json" "$W/policy.toml" --once "$@" \
        >"$W/out/$case.jsonl" 2>"$W/out/$case.err" || PRC=$?
}

# pl CASE FIELD [ID]: FIELD of the pass line, or of Vessel ID's line.
pl() {
    python3 -c '
import json, sys
for l in open(sys.argv[1]):
    v = json.loads(l)
    if (sys.argv[3] and v.get("chronicle") == sys.argv[3]) or (not sys.argv[3] and "pass" in v):
        print(v.get(sys.argv[2], ""))' "$W/out/$1.jsonl" "$2" "${3:-}" | head -1
}

say "13. taso-policy --once (predict: a dry run decides pa sanction and pf never and sends nothing; then pa Committed by rule passed and finished into its Template, pf ClosedNever by rule failed; a second pass finds nothing pending)"
daemon 13-daemon "$W/keep-q.json" q
policy 13-dry --dry-run
expect "dry run: exit 0" is "$PRC" 0
expect "dry run: two pending, nothing sent" is "$(pl 13-dry pending) $(pl 13-dry sent)" "2 0"
expect "dry run: pa sanction, pf never" is "$(pl 13-dry decision "${ID[pa]}") $(pl 13-dry decision "${ID[pf]}")" "sanction never"
policy 13-once
expect "exit 0" is "$PRC" 0
expect "pa: Committed by rule passed" is "$(pl 13-once answer "${ID[pa]}") $(pl 13-once rule "${ID[pa]}")" "Committed passed"
expect "pf: ClosedNever by rule failed" is "$(pl 13-once answer "${ID[pf]}") $(pl 13-once rule "${ID[pf]}")" "ClosedNever failed"
expect "pa finished into its Template" is "$(finished_sanction 13-daemon "${ID[pa]}" "$(pl 13-once template_id "${ID[pa]}")")" 1
policy 13-again
expect "again: nothing pending" is "$(pl 13-again pending)" 0
stop_daemon

# ── 14. taso-ctl explain (file 12) ──────────────────────────────

# explain CASE ID: taso-ctl explain; its JSON to $W/out/CASE.json, exit to XRC.
explain() {
    XRC=0
    timeout 120 "$BIN/taso-ctl" "$W/keep.json" explain "$2" >"$W/out/$1.json" 2>"$W/out/$1.err" || XRC=$?
}
# xj CASE EXPR: a Python expression over the explanation `e` and its `checks`.
xj() {
    python3 -c 'import json,sys; v=json.load(open(sys.argv[1])); e=v.get("explain",{}); checks=v.get("checks",{}); print(eval(sys.argv[2]))' "$W/out/$1.json" "$2"
}

say "14. taso-ctl explain, from the coordinator log alone (predict: exit 0, no failed check, each time; p sanctioned into its Template, completed; f never, 'exits 7'; p's Template born from p's Candidate; pa decided by taso-policy with a policy digest; V a genesis with no track record)"
explain 14-p "${ID[p]}"
expect "p: exit 0, every check held" is "$XRC $(xj 14-p 'len(checks["failed"])')" "0 0"
expect "p: sanctioned, completed" is "$(xj 14-p 'e["candidates"][0]["outcome"]["sanctioned"]["completed"]')" True
expect "p: its Template is the one committed" is "$(xj 14-p 'e["candidates"][0]["outcome"]["sanctioned"]["template_id"]')" "$TID"
explain 14-f "${ID[f]}"
expect "f: exit 0, every check held" is "$XRC $(xj 14-f 'len(checks["failed"])')" "0 0"
expect "f: never, 'exits 7'" is "$(xj 14-f 'e["candidates"][0]["outcome"]["never"]["reason"]')" "exits 7"
explain 14-t "$TID"
expect "p's Template: exit 0, every check held" is "$XRC $(xj 14-t 'len(checks["failed"])')" "0 0"
expect "p's Template born from p's Candidate" is "$(xj 14-t 'e["born_from"]["sanction"]["candidate_id"]')" "${CAND[p]}"
explain 14-pa "${ID[pa]}"
expect "pa: decided by taso-policy, with a policy digest" is "$XRC $(xj 14-pa '[x["actor"] for x in e["candidates"][0]["verdicts"]][0]') $(xj 14-pa 'len(e["candidates"][0]["verdicts"][0]["policy_digest"] or "")')" "0 taso-policy 64"
explain 14-v "$V"
expect "V: a genesis, no track record" is "$XRC $(xj 14-v '"no track record" in e["born_from"]["genesis"]["note"]')" "0 True"

# ── 10. The coordinator log ─────────────────────────────────────────

say "10. accepted records per Vessel (predict: p 6, f 7, h 7, s 7, c 6, k 6, x 6, y 6, pa 6, pf 5: each sanction's SanctionCompleted included)"
declare -A WANT=([p]=6 [f]=7 [h]=7 [s]=7 [c]=6 [k]=6 [x]=6 [y]=6 [pa]=6 [pf]=5)
for v in p f h s c k x y pa pf; do
    expect "$v: ${WANT[$v]} accepted" is "$(coordlog_of 1 "${ID[$v]}" | cut -d' ' -f1)" "${WANT[$v]}"
done

# ── Result ──────────────────────────────────────────────────────────

echo
if [[ $FAIL -eq 0 ]]; then
    echo "P4 DECIDE ($MODE) PASS: $PASS checks"
    exit 0
else
    echo "P4 DECIDE ($MODE) FAIL: $FAIL of $((PASS + FAIL)) checks failed; logs in $W/out"
    exit 1
fi
