#!/usr/bin/env bash
# p4-purge.sh: purge at TTL on real storage, under taso-wardend (P4 file
# 11; spec rev. 25 §6.3, §6.4, §6.7, D81).
#
#   scripts/p4-purge.sh zfs     (as root, from the repository root; not
#                                through sudo, which drops cargo from PATH)
#   scripts/p4-purge.sh blk
#
# zfs: Vessel roots are new datasets under $P4B_ZFS_PARENT (default
#      tasotest/vessel): p4u-n1.  It must not exist; it is destroyed at the
#      end (only it, with everything under it).
# blk: a fresh taso-blkd on its own log; dataset p4u/n1 in it.
#
# One machine, node 1 (Warden 1), one coordinator and store.  Four Vessels
# run two turns each without a TTL: d1, d2, d3, and s, whose agent
# nominates and whose verifier (V, as in p4-verify.sh) passes.  Then the
# daemon runs with a keeper Vessel q and "purge": {"ttl_seconds": 30,
# "recheck_seconds": 2}: every TTL starts at that daemon's first pass; s is
# sanctioned at once (taso-decide), so it is kept; q is running, so it is
# checked after its run; d1-d3 are purged.  The first such daemon stops
# every purge at purge.before_complete; the next one finishes them.
#
# Cases (each prints its prediction before it runs, then PASS or FAIL):
#   1  V from a directory                          taso-genesis, ready
#   2  four Vessels run, s attempted               exit 0; s Exit { code: 0 }
#   3  the daemon with a TTL, failpoint            s sanctioned; d1-d3 stopped
#      purge.before_complete                       at the failpoint, retired
#   4  the daemon again, keeper q2                 d1-d3 and q PurgeComplete;
#                                                  s and q2 never purged
#   5  what is left of a purged Vessel             no fs pack, a replacement
#                                                  per item; no dataset; its
#                                                  start refused "purged at lsn"
#   6  the sanctioned Vessel                       its dataset; not retired
#
# Touches, and nothing else:
#   /var/lib/taso-p4u/<mode>                 (removed at start, kept after)
#   /run/taso-p4u-<mode>-coord.sock
#   zfs: $P4B_ZFS_PARENT/p4u-n1              (created, destroyed at the end)
#   blk: /run/taso-p4u-blk.sock, /mnt/p4u and mounts under it (unmounted at
#        the end), the /dev/ublkb* devices taso-blkd creates for this run
#   runc containers under /var/lib/taso-p4u/<mode>/run1/runc (deleted)
#
# Exit 0 only if every check passed.

set -euo pipefail

MODE=${1:-}
[[ "$MODE" == zfs || "$MODE" == blk ]] || { echo "usage: $0 zfs|blk" >&2; exit 2; }

W=/var/lib/taso-p4u/$MODE
SOCK=/run/taso-p4u-$MODE-coord.sock
PARENT=${P4B_ZFS_PARENT:-tasotest/vessel}
BLK_SOCK=/run/taso-p4u-blk.sock
MNT=/mnt/p4u
LANDLOCK=${LANDLOCK:-1}
TURNS=2
BASE=200000            # runtime.host_uid_base of both nodes
TSLOT=9                # runtime.template_slot of both nodes
NS=7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d

COORD_PID=
PURGE=
DPID=
BLKD_PID=
ZFS_MADE=()
PASS=0
FAIL=0

say() { printf '\n== %s\n' "$*"; }
die() { printf 'ABORT: %s\n' "$*" >&2; exit 2; }

root_of() { # node -> its root dataset
    if [[ $MODE == zfs ]]; then echo "$PARENT/p4u-n$1"; else echo "p4u/n$1"; fi
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
for b in taso-wardend taso-genesis taso-coordd taso-logcheck taso-sim taso-landlock taso-decide taso-policy; do
    [[ -x "$BIN/$b" ]] || die "$BIN/$b was not built"
done
[[ $MODE == zfs ]] || [[ -x "$BIN/taso-blkd" ]] || die "$BIN/taso-blkd was not built"

rm -rf "$W"
mkdir -p "$W/store" "$W/src" "$W/out"
chmod 755 /var/lib/taso-p4u "$W"

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

printf '{"store": "%s", "prefix": "p4u"}\n' "$W/store" >"$W/store.json"
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
root = "$PARENT/p4u-n%d" % node if "$MODE" == "zfs" else "p4u/n%d" % node
json.dump({
    "warden": node,
    "coordinator": {"remote": "$SOCK"},
    "storage": storage,
    "root": root,
    "state_dir": "$W/state%d" % node,
    "store": "$W/store",
    "prefix": "p4u",
    "run_dir": "$W/run%d" % node,
    "sanction": {"classmap": "$W/map%d.toml" % node, "allowed_exclude": ["Scratch"]},
    "purge": json.loads("""$PURGE""") if """$PURGE""" else None,
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
        --actor p4u --reason "file 11 on taso-test" >"$W/out/$1.json" 2>"$W/out/$1.err" || rc=$?
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

# ── 2. Four Vessels, no TTL yet ─────────────────────────────────────

say "2. d1 d2 d3 run two turns, s two turns and nominates (predict: each run exit 0; s attempted 'Exit { code: 0 }')"
declare -A ID SLOT=([d1]=1 [d2]=2 [d3]=3 [s]=4)
for v in d1 d2 d3; do
    config 1 "$W/$v.json" "$(printf '{"subject": "%s", "uid_slot": %s}' "$v" "${SLOT[$v]}")"
    wardend "2-$v" 1 "$W/$v.json"
    expect "$v: exit 0" is "$RC" 0
done
vconf s 'exit 0'
config 1 "$W/s.json" "$(vessel s "${SLOT[s]}" "$(sim "$TURNS" Scratch)")"
wardend 2-s 1 "$W/s.json"
expect "s: exit 0" is "$RC" 0
expect "s: finished Exit { code: 0 }" is "$(finished 2-s s)" "Exit { code: 0 }"
for v in d1 d2 d3 s; do
    ds=$(dataset_of "2-$v" "$v"); ID[$v]=${ds##*/v-}
    [[ "${ID[$v]}" =~ ^[0-9a-f]{32}$ ]] || die "no dataset for $v: see $W/out/2-$v.err"
done

# ── The daemon with a TTL ───────────────────────────────────────────

PURGE='{"ttl_seconds": 30, "recheck_seconds": 2}'
KEEP='"runtime": {"args": ["/usr/bin/taso-sim", "--turns", "100000", "--txns", "1", "--rows", "1", "--turn-sleep-ms", "1000", "--stats", "/work/sim-stats.json"]}'
config 1 "$W/keep-q.json" "$(vessel q 7 "$KEEP")"
config 1 "$W/keep-q2.json" "$(vessel q2 8 "$KEEP")"
DSOCK=$W/run1/decide/decide.sock

# daemon CASE CONFIG KEEPER [ENV=VALUE...]: node 1's Warden with CONFIG's
# keeper, in the background; waits for the decider socket and the
# keeper's dataset.
daemon() {
    local case=$1 cfg=$2 keeper=$3; shift 3
    env "$@" "$BIN/taso-wardend" "$cfg" >"$W/out/$case.out" 2>"$W/out/$case.err" &
    DPID=$!
    for _ in $(seq 300); do
        [[ -S "$DSOCK" && -n "$(dataset_of "$case" "$keeper")" ]] && return 0
        kill -0 "$DPID" 2>/dev/null || die "taso-wardend exited early; see $W/out/$case.err"
        sleep 0.2
    done
    die "the decider socket or q did not appear; see $W/out/$case.err"
}

stop_daemon() {
    kill -TERM "$DPID"; wait "$DPID" 2>/dev/null || true
    DPID=
}

# purge_lines CASE ID PATTERN: how often the daemon logged PATTERN for
# Vessel ID's purge.
purge_lines() { count "$1.err" "\] $2: purge: $3"; }

# wait_for CASE ID PATTERN SECONDS: until the daemon has logged it.
wait_for() {
    for _ in $(seq $(( $4 * 5 ))); do
        [[ "$(purge_lines "$1" "$2" "$3")" -gt 0 ]] && return 0
        sleep 0.2
    done
    return 1
}

# fs_packs ID: the packs of Vessel ID in the store with an fs section
# (named <end>-<base>-<to>, to not 0).
fs_packs() { ls "$W/store/p4u/$1/pack" 2>/dev/null | grep -vc -- '-0$' || true; }
# replacements ID: its log-only packs that replace one (<end>-<base>-0,
# base not 0 or end > base... any -0 name).
log_packs() { ls "$W/store/p4u/$1/pack" 2>/dev/null | grep -c -- '-0$' || true; }

dataset_exists() { # dataset_exists ID: yes|no
    local ds; ds="$(root_of 1)/v-$1"
    if [[ $MODE == zfs ]]; then
        zfs list -H -o name "$ds" >/dev/null 2>&1 && echo yes || echo no
    else
        blk names | tr ' ' '\n' | grep -qx "$ds" && echo yes || echo no
    fi
}

retired() { # retired ID: true|false, as taso-logcheck reads the coordinator
    lc 1 "$1" | python3 -c 'import json,sys; v=json.load(sys.stdin); print(str((v.get("coordlog") or {}).get("retired", False)).lower())'
}

say "3. the daemon with a TTL of 30 s, TASO_FAILPOINT=purge.before_complete (predict: s sanctioned before its TTL passes; q checked after its run; d1-d3 each stopped at the failpoint within 90 s)"
for v in d1 d2 d3 s; do expect "$v: fs packs before" bash -c "[[ $(fs_packs "${ID[$v]}") -ge 1 ]]"; done
daemon 3-daemon "$W/keep-q.json" q TASO_FAILPOINT=purge.before_complete
timeout 120 "$BIN/taso-decide" "$W/keep-q.json" pending >"$W/out/3-pending.json"
read -r CS AS < <(python3 -c '
import json, sys
for i in json.load(open(sys.argv[1]))["pending"]:
    if i["chronicle"] == sys.argv[2]:
        print(i["candidate_id"], i["attempts"][-1]["attempt_id"])' "$W/out/3-pending.json" "${ID[s]}") || true
timeout 120 "$BIN/taso-decide" "$W/keep-q.json" verdict "$CS" "$AS" sanction --actor p4u --reason "file 11" >"$W/out/3-s.json" || true
expect "s: Committed" is "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("answer",""))' "$W/out/3-s.json")" Committed
for v in d1 d2 d3; do
    expect "$v: stopped at purge.before_complete" wait_for 3-daemon "${ID[$v]}" "stopped: stopped at failpoint purge.before_complete" 90
done
QID=$(dataset_of 3-daemon q); QID=${QID##*/v-}
expect "q: running, checked after its run" bash -c "[[ $(purge_lines 3-daemon "$QID" 'it is running') -ge 1 ]]"
expect "s: never purged" is "$(purge_lines 3-daemon "${ID[s]}" '')" 0
stop_daemon
for v in d1 d2 d3; do expect "$v: retired" is "$(retired "${ID[$v]}")" true; done

say "4. the daemon again with a new keeper q2, no failpoint (predict: d1-d3 'purge: Complete' each, within 30 s; q, past its TTL and no longer running, purged too; s and q2 never purged)"
daemon 4-daemon "$W/keep-q2.json" q2
for v in d1 d2 d3; do
    expect "$v: PurgeComplete" wait_for 4-daemon "${ID[$v]}" "Complete" 30
done
expect "q: PurgeComplete" wait_for 4-daemon "$QID" "Complete" 30
Q2ID=$(dataset_of 4-daemon q2); Q2ID=${Q2ID##*/v-}
expect "s: never purged" is "$(purge_lines 4-daemon "${ID[s]}" '')" 0
expect "q2: never purged" is "$(purge_lines 4-daemon "$Q2ID" 'Complete')" 0
stop_daemon

say "5. what is left of d1-d3 (predict: no fs pack, one log-only pack per item; no dataset; a start of d1 refused 'purged at lsn')"
for v in d1 d2 d3; do
    items=$({ grep -o "\] ${ID[$v]}: purge: Complete { items: [0-9]*" "$W/out/4-daemon.err" || true; } | head -1 | sed 's/.*items: //')
    expect "$v: no fs pack" is "$(fs_packs "${ID[$v]}")" 0
    expect "$v: a replacement per item ($items)" bash -c "[[ -n '$items' && $(log_packs "${ID[$v]}") -ge '$items' ]]"
    expect "$v: no dataset" is "$(dataset_exists "${ID[$v]}")" no
done
wardend 5-d1 1 "$W/d1.json"
expect "d1: start refused, purged" is "$(count 5-d1.err 'purged at lsn [0-9]*')" 1

say "6. the sanctioned Vessel s (predict: its dataset stays; not retired)"
expect "s: dataset" is "$(dataset_exists "${ID[s]}")" yes
expect "s: not retired" is "$(retired "${ID[s]}")" false

# ── Result ──────────────────────────────────────────────────────────

echo
if [[ $FAIL -eq 0 ]]; then
    echo "P4 PURGE ($MODE) PASS: $PASS checks"
    exit 0
else
    echo "P4 PURGE ($MODE) FAIL: $FAIL of $((PASS + FAIL)) checks failed; logs in $W/out"
    exit 1
fi
