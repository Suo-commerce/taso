#!/usr/bin/env bash
# p4-verify.sh: verification attempts on real storage, under taso-wardend
# (P4 file 7d; spec rev. 20 §3.4, D64-D70).
#
#   scripts/p4-verify.sh zfs     (as root, from the repository root; not
#                                 through sudo, which drops cargo from PATH)
#   scripts/p4-verify.sh blk
#
# zfs: Vessel roots are new datasets under $P4B_ZFS_PARENT (default
#      tasotest/vessel): p4v-n1, p4v-n2.  They must not exist; they are
#      destroyed at the end (only these two, with everything under them).
# blk: a fresh taso-blkd on its own log; datasets p4v/n1, p4v/n2 in it.
#
# One machine, node 1 (Warden 1), one coordinator and store.  V, the
# verifier Template, is made by taso-genesis from a directory holding the
# host's sh, cat and sleep with their libraries and the mount targets
# (proc, dev, sys, tmp, candidate).  Each Vessel runs taso-sim, whose
# agent nominates its newest Seal; the daemon then attempts it with the
# Vessel's own vconf, a shell script run inside V over /candidate.
#
# Cases (each prints its prediction before it runs, then PASS or FAIL):
#   1  V from a directory                         taso-genesis, ready
#   2  a verifier that reads the Candidate        Exit { code: 0 }
#   3  one that fails                             Exit { code: 7 }
#   4  /candidate is read-only                    Exit { code: 0 }
#   5  isolation: no TASO_*, no socket, no net    Exit { code: 0 }
#   6  past its wall time                         Timeout
#   7  past its output bound                      OutputLimit
#   8  a vconf that is not one                    LaunchFailed
#   9  the three verify failpoints                stop; the next start
#                                                 closes or starts it
#  10  no /candidate dataset is left              none under the root
#
# Touches, and nothing else:
#   /var/lib/taso-p4v/<mode>                 (removed at start, kept after)
#   /run/taso-p4v-<mode>-coord.sock
#   zfs: $P4B_ZFS_PARENT/p4v-n1, p4v-n2      (created, destroyed at the end)
#   blk: /run/taso-p4v-blk.sock, /mnt/p4v and mounts under it (unmounted at
#        the end), the /dev/ublkb* devices taso-blkd creates for this run
#   runc containers under /var/lib/taso-p4v/<mode>/run<n>/runc (deleted)
#
# Exit 0 only if every check passed.

set -euo pipefail

MODE=${1:-}
[[ "$MODE" == zfs || "$MODE" == blk ]] || { echo "usage: $0 zfs|blk" >&2; exit 2; }

W=/var/lib/taso-p4v/$MODE
SOCK=/run/taso-p4v-$MODE-coord.sock
PARENT=${P4B_ZFS_PARENT:-tasotest/vessel}
BLK_SOCK=/run/taso-p4v-blk.sock
MNT=/mnt/p4v
LANDLOCK=${LANDLOCK:-1}
TURNS=2
BASE=200000            # runtime.host_uid_base of both nodes
TSLOT=9                # runtime.template_slot of both nodes
NS=7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d

COORD_PID=
BLKD_PID=
ZFS_MADE=()
PASS=0
FAIL=0

say() { printf '\n== %s\n' "$*"; }
die() { printf 'ABORT: %s\n' "$*" >&2; exit 2; }

root_of() { # node -> its root dataset
    if [[ $MODE == zfs ]]; then echo "$PARENT/p4v-n$1"; else echo "p4v/n$1"; fi
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
    for n in 1 2; do
        if [[ -d "$W/run$n/runc" ]]; then
            for c in $(runc --root "$W/run$n/runc" list -q 2>/dev/null); do
                runc --root "$W/run$n/runc" delete --force "$c" 2>/dev/null
            done
        fi
    done
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
    for n in 1 2; do
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
for b in taso-wardend taso-genesis taso-coordd taso-logcheck taso-sim taso-landlock; do
    [[ -x "$BIN/$b" ]] || die "$BIN/$b was not built"
done
[[ $MODE == zfs ]] || [[ -x "$BIN/taso-blkd" ]] || die "$BIN/taso-blkd was not built"

rm -rf "$W"
mkdir -p "$W/store" "$W/src" "$W/out"
chmod 755 /var/lib/taso-p4v "$W"

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
    for n in 1 2; do
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

printf '{"store": "%s", "prefix": "p4v"}\n' "$W/store" >"$W/store.json"
"$BIN/taso-coordd" "$W/coord.redb" "$SOCK" --store-config "$W/store.json" 2>>"$W/coordd.err" &
COORD_PID=$!
for _ in $(seq 100); do [[ -S "$SOCK" ]] && break; sleep 0.1; done
[[ -S "$SOCK" ]] || die "taso-coordd socket did not appear; see $W/coordd.err"

for n in 1 2; do mkdir -p "$W/state$n" "$W/run$n"; done

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
root = "$PARENT/p4v-n%d" % node if "$MODE" == "zfs" else "p4v/n%d" % node
json.dump({
    "warden": node,
    "coordinator": {"remote": "$SOCK"},
    "storage": storage,
    "root": root,
    "state_dir": "$W/state%d" % node,
    "store": "$W/store",
    "prefix": "p4v",
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
        --actor p4v --reason "file 7d on taso-test" >"$W/out/$1.json" 2>"$W/out/$1.err" || rc=$?
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
    if "$@"; then
        PASS=$((PASS + 1)); echo "  PASS  $what"
    else
        FAIL=$((FAIL + 1)); echo "  FAIL  $what"
    fi
}

is() { [[ "$1" == "$2" ]]; }
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

# attempted CASE SUBJECT SLOT SCRIPT [EXTRA_TOML]: SUBJECT runs $TURNS
# turns, its agent nominates, the daemon attempts it.
attempted() {
    vconf "$2" "$4" "${5:-}"
    config 1 "$W/$2.json" "$(vessel "$2" "$3" "$(sim "$TURNS" Scratch)")"
    wardend "$1" 1 "$W/$2.json"
}

# ── 2–8. Attempts and how they end ──────────────────────────────────

say "2. a verifier that reads the Candidate (predict: exit 0; one attempt started and finished 'Exit { code: 0 }'; three records accepted: Candidate, VerificationStarted, VerificationFinished)"
attempted 2-p p 1 'test -s /candidate/state.db && cat /candidate/state.db >/dev/null && echo read'
expect "exit 0" is "$RC" 0
expect "started" is "$(attempt_lines 2-p p | grep -c ': started$')" 1
expect "finished Exit { code: 0 }" is "$(finished 2-p p)" "Exit { code: 0 }"
DS=$(dataset_of 2-p p)
expect "three records accepted" is "$(coordlog_of 1 "${DS##*/v-}" | cut -d' ' -f1)" 3

say "3. a verifier that fails (predict: 'Exit { code: 7 }')"
attempted 3-f f 2 'exit 7'
expect "exit 0" is "$RC" 0
expect "finished Exit { code: 7 }" is "$(finished 3-f f)" "Exit { code: 7 }"

say "4. /candidate is read-only (predict: writing fails, 'Exit { code: 0 }')"
attempted 4-w w 3 'if : > /candidate/x 2>/dev/null; then exit 9; fi; exit 0'
expect "finished Exit { code: 0 }" is "$(finished 4-w w)" "Exit { code: 0 }"

say "5. isolation: no TASO_* environment, no /run/taso, only lo in /proc/net/dev (predict: 'Exit { code: 0 }')"
attempted 5-i i 4 '[ -z "$TASO_FIELD" ] || exit 9; [ ! -e /run/taso ] || exit 8; n=0; while read l; do n=$((n+1)); done < /proc/net/dev; [ "$n" -le 3 ] || exit 7; exit 0'
expect "finished Exit { code: 0 }" is "$(finished 5-i i)" "Exit { code: 0 }"

say "6. past its wall time, wall_seconds = 3 (predict: 'Timeout')"
attempted 6-t t 5 'exec /bin/sleep 60' 'wall_seconds = 3
'
expect "finished Timeout" is "$(finished 6-t t)" "Timeout"

say "7. past its output bound, output_bound = 100 (predict: 'OutputLimit', 100 bytes of output)"
attempted 7-o o 6 'while :; do echo xxxxxxxx; done' 'output_bound = 100
'
expect "finished OutputLimit" is "$(finished 7-o o)" "OutputLimit"
expect "100 bytes of output" is "$(attempt_lines 7-o o | grep -c 'finished OutputLimit, 100 bytes of output$')" 1

say "8. a vconf that is not one (predict: 'LaunchFailed')"
vconf l 'exit 0'
printf 'version = 2\nentry = ["/bin/sh"]\n' >"$W/vconf-l.toml"
config 1 "$W/l.json" "$(vessel l 7 "$(sim "$TURNS" Scratch)")"
wardend 8-l 1 "$W/l.json"
expect "finished LaunchFailed" is "$(finished 8-l l)" "LaunchFailed"

# ── 9. Failpoints ───────────────────────────────────────────────────

say "9a. verify.before_started_accept (predict: the attempt not started; the next start starts it and it finishes 'Exit { code: 0 }')"
vconf fa 'exit 0'
config 1 "$W/fa.json" "$(vessel fa 10 "$(sim "$TURNS" Scratch)")"
wardend 9a-stop 1 "$W/fa.json" TASO_FAILPOINT=verify.before_started_accept
expect "not started at the failpoint" is "$(count 9a-stop.err 'fa: Candidate [0-9a-f]*: its attempt was not started: stopped at failpoint verify.before_started_accept')" 1
expect "nothing finished" is "$(finished 9a-stop fa)" ""
config 1 "$W/fa-again.json" "$(vessel fa 10 "$(sim 1)")"
wardend 9a-again 1 "$W/fa-again.json"
expect "the next start: started" is "$(attempt_lines 9a-again fa | grep -c ': started$')" 1
expect "the next start: finished Exit { code: 0 }" is "$(finished 9a-again fa)" "Exit { code: 0 }"

say "9b. verify.mid_run (predict: stopped, the attempt stays open; the next start closes it 'interrupted', destroys its /candidate and does not attempt again)"
vconf fb 'exec /bin/sleep 5'
config 1 "$W/fb.json" "$(vessel fb 11 "$(sim "$TURNS" Scratch)")"
wardend 9b-stop 1 "$W/fb.json" TASO_FAILPOINT=verify.mid_run
expect "stopped mid-run, stays open" is "$(attempt_lines 9b-stop fb | grep -c 'stopped at failpoint verify.mid_run; it stays open')" 1
config 1 "$W/fb-again.json" "$(vessel fb 11 "$(sim 1)")"
wardend 9b-again 1 "$W/fb-again.json"
expect "the next start: interrupted" is "$(attempt_lines 9b-again fb | grep -c 'interrupted (it was open at this start)$')" 1
expect "its /candidate destroyed" is "$(attempt_lines 9b-again fb | grep -c 'destroyed its /candidate dataset')" 1
expect "not attempted again" is "$(attempt_lines 9b-again fb | grep -c ': started$')" 0

say "9c. verify.before_finished_accept (predict: the result not accepted; the next start closes it 'interrupted' and destroys its /candidate)"
vconf fc 'exit 0'
config 1 "$W/fc.json" "$(vessel fc 12 "$(sim "$TURNS" Scratch)")"
wardend 9c-stop 1 "$W/fc.json" TASO_FAILPOINT=verify.before_finished_accept
expect "ended, record not accepted" is "$(attempt_lines 9c-stop fc | grep -c 'ended Exit { code: 0 } but its record was not accepted')" 1
config 1 "$W/fc-again.json" "$(vessel fc 12 "$(sim 1)")"
wardend 9c-again 1 "$W/fc-again.json"
expect "the next start: interrupted" is "$(attempt_lines 9c-again fc | grep -c 'interrupted (it was open at this start)$')" 1
expect "its /candidate destroyed" is "$(attempt_lines 9c-again fc | grep -c 'destroyed its /candidate dataset')" 1

# ── 10. Nothing left ────────────────────────────────────────────────

say "10. no attempt's /candidate dataset is left (predict: none under node 1's root)"
expect "no a- datasets" is "$(candidates_left)" 0

# ── Result ──────────────────────────────────────────────────────────

echo
if [[ $FAIL -eq 0 ]]; then
    echo "P4 VERIFY ($MODE) PASS: $PASS checks"
    exit 0
else
    echo "P4 VERIFY ($MODE) FAIL: $FAIL of $((PASS + FAIL)) checks failed; logs in $W/out"
    exit 1
fi
