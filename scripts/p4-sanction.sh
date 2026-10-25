#!/usr/bin/env bash
# p4-sanction.sh: the P4 gate (plan §3, file 13; spec rev. 28 §10.2, D84),
# on real storage, under taso-wardend.
#
#   scripts/p4-sanction.sh blk     (the gate: the block log; as root, from
#   scripts/p4-sanction.sh zfs      the repository root, not through sudo)
#
# zfs: Vessel roots are new datasets under $P4B_ZFS_PARENT (default
#      tasotest/vessel): p4g-n1, p4g-n2.  They must not exist; they are
#      destroyed at the end (only these two, with everything under them).
# blk: a fresh taso-blkd on its own log; datasets p4g/n1, p4g/n2 in it.
#
# Two nodes (Wardens 1 and 2), one coordinator and store.  T(0) and V
# (the verifier) by taso-genesis.  Ten Vessels v0..v9 born from T(0) on
# node 1, each two turns, each agent nominating its newest Seal dropping
# Scratch, each attempted by its own verifier:
#
#   v0  writes scratch/cache.db; passes            -> sanctioned: T(1)
#   v1  exit 1;  v2 exit 2;  v8 exit 5              -> Never ("failed")
#   v3  past its wall time (Timeout)                -> Never ("failed")
#   v9  past its output bound (OutputLimit)         -> Never ("failed")
#   v4  writes secret.key; passes                   -> Never ("no secrets");
#                                                      a direct Sanction is
#                                                      Refused HardRules
#   v5  a vconf that is not one (LaunchFailed)      -> Hold (the default)
#   v6  tries to write /candidate; exit 4 if it cannot
#                                                   -> Never ("failed")
#   v7  writes blob.db (Unknown)                    -> nomination refused
#
# Then node 1's daemon with a keeper q and "purge": {"ttl_seconds": 60,
# "recheck_seconds": 2}: the hostile caller (a Sanction against the hard
# rules, stale facts; no decider socket in an agent's bundle), then
# taso-policy --once, then the nine unsanctioned Vessels purged at their
# TTL.  Then the checks of plan §3: T(1)'s definition and content, the
# purges, the reconstruction by taso-ctl explain, a second genesis, and
# T(1) restored on node 2, which never held v0 (D84).
#
# Touches, and nothing else:
#   /var/lib/taso-p4g/<mode>                 (removed at start, kept after)
#   /run/taso-p4g-<mode>-coord.sock
#   zfs: $P4B_ZFS_PARENT/p4g-n1, p4g-n2      (created, destroyed at the end)
#   blk: /run/taso-p4g-blk.sock, /mnt/p4g and mounts under it (unmounted at
#        the end), the /dev/ublkb* devices taso-blkd creates for this run
#   runc containers under /var/lib/taso-p4g/<mode>/run<n>/runc (deleted)
#
# Exit 0 only if every check passed.

set -euo pipefail

MODE=${1:-}
[[ "$MODE" == zfs || "$MODE" == blk ]] || { echo "usage: $0 zfs|blk" >&2; exit 2; }

W=/var/lib/taso-p4g/$MODE
SOCK=/run/taso-p4g-$MODE-coord.sock
PARENT=${P4B_ZFS_PARENT:-tasotest/vessel}
BLK_SOCK=/run/taso-p4g-blk.sock
MNT=/mnt/p4g
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
    if [[ $MODE == zfs ]]; then echo "$PARENT/p4g-n$1"; else echo "p4g/n$1"; fi
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
for b in taso-wardend taso-genesis taso-coordd taso-logcheck taso-sim taso-landlock taso-decide taso-policy taso-ctl; do
    [[ -x "$BIN/$b" ]] || die "$BIN/$b was not built"
done
[[ $MODE == zfs ]] || [[ -x "$BIN/taso-blkd" ]] || die "$BIN/taso-blkd was not built"

rm -rf "$W"
mkdir -p "$W/store" "$W/src" "$W/out"
chmod 755 /var/lib/taso-p4g "$W"

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

printf '{"store": "%s", "prefix": "p4g"}\n' "$W/store" >"$W/store.json"
"$BIN/taso-coordd" "$W/coord.redb" "$SOCK" --store-config "$W/store.json" 2>>"$W/coordd.err" &
COORD_PID=$!
for _ in $(seq 100); do [[ -S "$SOCK" ]] && break; sleep 0.1; done
[[ -S "$SOCK" ]] || die "taso-coordd socket did not appear; see $W/coordd.err"

for n in 1 2; do mkdir -p "$W/state$n" "$W/run$n"; done

# The two classification maps (D58) and a verifier config (D57; opaque
# to nomination, file 7 reads it).
# The gate's classification map (D58), the same on both nodes: everything
# Source, but scratch/ Scratch, secret.key* Secret, and blob.db*, on which
# two rules of equal weight disagree, Unknown (§8: the most specific
# matching rules must agree).
for n in 1 2; do
cat >"$W/map$n.toml" <<'EOF2'
version = 1
[[rule]]
glob = "**"
class = "Source"
[[rule]]
glob = "scratch/"
class = "Scratch"
[[rule]]
glob = "scratch/**"
class = "Scratch"
[[rule]]
glob = "secret.key*"
class = "Secret"
[[rule]]
glob = "blob.db*"
class = "Source"
[[rule]]
glob = "blob.db*"
class = "Config"
EOF2
done
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
root = "$PARENT/p4g-n%d" % node if "$MODE" == "zfs" else "p4g/n%d" % node
json.dump({
    "warden": node,
    "coordinator": {"remote": "$SOCK"},
    "storage": storage,
    "root": root,
    "state_dir": "$W/state%d" % node,
    "store": "$W/store",
    "prefix": "p4g",
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
    mkdir -p "$d/scratch"
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
        --actor p4g --reason "the P4 gate on taso-test" >"$W/out/$1.json" 2>"$W/out/$1.err" || rc=$?
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

# ── 1. T(0), V ──────────────────────────────────────────────────────

say "1. T(0) and V by taso-genesis (predict: ready, each)"
tree "$W/src/t0"
T0=$(genesis 1-t0 "$W/src/t0" || true)
expect "T(0) ready" bash -c "[[ '$T0' =~ ^[0-9a-f]{32}$ ]]"
verifier_tree "$W/src/v"
V=$(genesis 1-v "$W/src/v" || true)
expect "V ready" bash -c "[[ '$V' =~ ^[0-9a-f]{32}$ ]]"
[[ -n "$T0" && -n "$V" ]] || die "no T(0) or V: see $W/out/1-*.err"

# gsim TURNS DB [NOMINATE...]: taso-sim writing its database at DB.
gsim() {
    local turns=$1 db=$2; shift 2
    python3 - "$turns" "$db" "$@" <<'PY'
import json, sys
args = ["/usr/bin/taso-sim", "--turns", sys.argv[1], "--txns", "2", "--rows", "4",
        "--turn-sleep-ms", "50", "--db", sys.argv[2], "--stats", "/work/sim-stats.json"]
for n in sys.argv[3:]:
    args += ["--nominate", n]
print('"runtime": ' + json.dumps({"args": args}))
PY
}

# born NAME SLOT TEMPLATE RUNTIME: an entry born from TEMPLATE, V its verifier.
born() {
    printf '{"subject": "%s", "uid_slot": %s, "template": "%s", "verifier": {"template": "%s", "config": "%s", "version": 1}, %s}' \
        "$1" "$2" "$3" "$V" "$W/vconf-$1.toml" "$4"
}

# fs_names ID: the packs of Vessel ID in the store with an fs section:
# named <end>-<base>-<to>, each 20 digits, <to> not all zeros.
fs_names() { ls "$W/store/p4g/$1/pack" 2>/dev/null | awk -F- 'NF == 3 && $3 !~ /^0+$/' || true; }
fs_packs() { fs_names "$1" | wc -l; }
# replaced ID FILE: how many of the fs packs named in FILE have their
# log-only replacement <end>-<base>-00000000000000000000 in the store.
replaced() {
    local n k=0
    while read -r n; do
        [[ -e "$W/store/p4g/$1/pack/${n%-*}-00000000000000000000" ]] && k=$((k + 1))
    done <"$2"
    echo "$k"
}
dataset_exists() { # dataset_exists ID: yes|no, on node 1
    local ds; ds="$(root_of 1)/v-$1"
    if [[ $MODE == zfs ]]; then
        zfs list -H -o name "$ds" >/dev/null 2>&1 && echo yes || echo no
    else
        # `names` answers "ok <name>:<layer> ...".
        blk names | tr ' ' '\n' | grep -q "^$ds:" && echo yes || echo no
    fi
}

# ── 2. Ten Vessels from T(0) ────────────────────────────────────────

declare -A ID WANT_ATTEMPT DB=([v0]=/work/scratch/cache.db [v4]=/work/secret.key [v7]=/work/blob.db)
vconf v0 'test -s /candidate/app/main.py'
vconf v1 'exit 1'
vconf v2 'exit 2'
vconf v3 'exec /bin/sleep 60' 'wall_seconds = 3
'
vconf v4 'exit 0'
printf 'version = 2\nentry = ["/bin/sh"]\n' >"$W/vconf-v5.toml"
vconf v6 'if (echo x > /candidate/x) 2>/dev/null; then exit 0; fi; exit 4'
vconf v7 'exit 0'
vconf v8 'exit 5'
vconf v9 'while :; do echo xxxxxxxx; done' 'output_bound = 100
'
WANT_ATTEMPT=([v0]="Exit { code: 0 }" [v1]="Exit { code: 1 }" [v2]="Exit { code: 2 }" [v3]="Timeout"
    [v4]="Exit { code: 0 }" [v5]="LaunchFailed" [v6]="Exit { code: 4 }" [v8]="Exit { code: 5 }" [v9]="OutputLimit")
say "2. v0..v9 born from T(0) on node 1, two turns each, each agent nominates dropping Scratch (predict: exit 0 each; 'Born from Template' T(0); v7 refused 'Walk(UnknownPaths)'; every other one attempted as listed)"
# Each Vessel's uid_slot: 1..8, then 10 and 11. Slot 9 is the Template
# range ($TSLOT), which the Warden refuses for any Vessel (D53).
SLOTS=(1 2 3 4 5 6 7 8 10 11)
for sl in "${SLOTS[@]}" 15; do [[ $sl != "$TSLOT" ]] || die "uid_slot $sl is the Template range"; done
for i in 0 1 2 3 4 5 6 7 8 9; do
    v=v$i
    config 1 "$W/$v.json" "$(born "$v" "${SLOTS[$i]}" "$T0" "$(gsim 2 "${DB[$v]:-/work/state.db}" Scratch)")"
    wardend "2-$v" 1 "$W/$v.json"
    expect "$v: exit 0" is "$RC" 0
    expect "$v: born from T(0)" is "$(count "2-$v.err" "\] $v: Born from Template $T0")" 1
    ds=$(dataset_of "2-$v" "$v"); ID[$v]=${ds##*/v-}
    [[ "${ID[$v]}" =~ ^[0-9a-f]{32}$ ]] || die "no dataset for $v: see $W/out/2-$v.err"
    if [[ $v == v7 ]]; then
        expect "v7: nomination refused Walk(UnknownPaths)" is "$(answers 2-v7 v7 Agent)" 'Refused { reason: "Walk(UnknownPaths)" }'
    else
        expect "$v: attempt finished ${WANT_ATTEMPT[$v]}" is "$(finished "2-$v" "$v")" "${WANT_ATTEMPT[$v]}"
    fi
done

say "2b. the ten from one layer (predict: every Lineage names T(0) and the same layer key, each holds it)"
lineage_of() { # lineage_of ID: "<origin> <template_id> <layer_key> <held>"
    lc 1 "$1" | python3 -c '
import json, sys
v = json.load(sys.stdin)
l = [f for f in v["frames"] if f["kind"] == "lineage"][0]
held = ("content:" + l.get("layer_key", "")) in (v.get("coordlog") or {}).get("holds", [])
print(l["origin"], l.get("template_id", ""), l.get("layer_key", ""), held)'
}
L0=$(lineage_of "${ID[v0]}" | cut -d' ' -f3)
for i in 0 1 2 3 4 5 6 7 8 9; do
    expect "v$i: from T(0)'s layer, held" is "$(lineage_of "${ID[v$i]}")" "template $T0 $L0 True"
done

# ── 3. The daemon: the hostile caller, the policy, the TTL ──────────

PURGE='{"ttl_seconds": 60, "recheck_seconds": 2}'
KEEP='"runtime": {"args": ["/usr/bin/taso-sim", "--turns", "100000", "--txns", "1", "--rows", "1", "--turn-sleep-ms", "1000", "--stats", "/work/sim-stats.json"]}'
vconf q 'exit 0'
config 1 "$W/keep.json" "$(vessel q 15 "$KEEP")"
DSOCK=$W/run1/decide/decide.sock
for i in 0 1 2 3 4 5 6 7 8 9; do fs_names "${ID[v$i]}" >"$W/out/fs-before-v$i"; done

say "3. node 1's daemon with a keeper and a TTL of 60 s (predict: the decider socket; q running)"
env "$BIN/taso-wardend" "$W/keep.json" >"$W/out/3-daemon.out" 2>"$W/out/3-daemon.err" &
DPID=$!
for _ in $(seq 300); do
    [[ -S "$DSOCK" && -n "$(dataset_of 3-daemon q)" ]] && break
    kill -0 "$DPID" 2>/dev/null || die "taso-wardend exited early; see $W/out/3-daemon.err"
    sleep 0.2
done
expect "decider socket" test -S "$DSOCK"

decide() { # decide CASE ARGS...
    DRC=0
    timeout 120 "$BIN/taso-decide" "$W/keep.json" "${@:2}" >"$W/out/$1.json" 2>"$W/out/$1.err" || DRC=$?
}
jf() { python3 -c 'import json,sys; v=json.load(open(sys.argv[1])); print(v.get(sys.argv[2], ""))' "$W/out/$1.json" "$2"; }
decide 3-pending pending
declare -A CAND ATT
for i in 0 1 2 3 4 5 6 8 9; do
    read -r CAND[v$i] ATT[v$i] < <(python3 -c '
import json, sys
for i in json.load(open(sys.argv[1]))["pending"]:
    if i["chronicle"] == sys.argv[2]:
        print(i["candidate_id"], i["attempts"][-1]["attempt_id"])' "$W/out/3-pending.json" "${ID[v$i]}") || true
done
expect "nine Candidates pending (v7 has none)" is "$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))["pending"]))' "$W/out/3-pending.json")" 9

say "3a. the hostile caller (predict: a Sanction of v4, whose input holds a secret, Refused HardRules; a Sanction of v1 with facts not its own Refused StaleFacts; no agent bundle names a decider socket)"
decide 3a-v4 verdict "${CAND[v4]}" "${ATT[v4]}" sanction --actor hostile --reason "the gate"
expect "v4: Refused HardRules" is "$(jf 3a-v4 answer) $(jf 3a-v4 rule)" "Refused HardRules"
decide 3a-v1 verdict "${CAND[v1]}" "${ATT[v1]}" sanction --actor hostile --reason "the gate" \
    --facts-hash 0000000000000000000000000000000000000000000000000000000000000000
expect "v1: Refused StaleFacts" is "$(jf 3a-v1 answer) $(jf 3a-v1 rule)" "Refused StaleFacts"
bundles=$(find "$W/run1" -name config.json 2>/dev/null | wc -l)
expect "q's bundle is there to look at" bash -c "[[ $bundles -ge 1 ]]"
expect "no agent bundle names a decider socket" is "$(find "$W/run1" -name config.json -exec grep -l 'decide' {} + 2>/dev/null | wc -l)" 0

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

pl() { # pl FIELD ID: FIELD of Vessel ID's line in 3b's output
    python3 -c '
import json, sys
for l in open(sys.argv[1]):
    v = json.loads(l)
    if v.get("chronicle") == sys.argv[3]:
        print(v.get(sys.argv[2], "")); break' "$W/out/3b.jsonl" "$1" "$2"
}
say "3b. taso-policy --once (predict: v0 Committed by 'passed'; v4 ClosedNever by 'no secrets'; v1 v2 v3 v6 v8 v9 ClosedNever by 'failed'; v5 Held by the default)"
PRC=0
timeout 300 "$BIN/taso-policy" "$W/keep.json" "$W/policy.toml" --once >"$W/out/3b.jsonl" 2>"$W/out/3b.err" || PRC=$?
expect "exit 0" is "$PRC" 0
expect "v0: Committed by passed" is "$(pl answer "${ID[v0]}") $(pl rule "${ID[v0]}")" "Committed passed"
T1=$(pl template_id "${ID[v0]}")
expect "v4: ClosedNever by no secrets" is "$(pl answer "${ID[v4]}") $(pl rule "${ID[v4]}")" "ClosedNever no secrets"
for i in 1 2 3 6 8 9; do
    expect "v$i: ClosedNever by failed" is "$(pl answer "${ID[v$i]}") $(pl rule "${ID[v$i]}")" "ClosedNever failed"
done
expect "v5: Held by the default" is "$(pl answer "${ID[v5]}") $(pl rule "${ID[v5]}")" "Held default"
expect "T(1) finished, once" is "$(count 3-daemon.err "\] ${ID[v0]}: sanction of Candidate [0-9a-f]*: Template $T1 ready, sanction completed$")" 1

say "3c. the TTL (predict: v1..v9, not sanctioned, purged complete within 120 s; v0 and q never purged)"
wait_purged() { # wait_purged ID SECONDS
    for _ in $(seq $(( $2 * 5 ))); do
        [[ "$(count 3-daemon.err "\] $1: purge: Complete")" -gt 0 ]] && return 0
        sleep 0.2
    done
    return 1
}
for i in 1 2 3 4 5 6 7 8 9; do
    expect "v$i: purged" wait_purged "${ID[v$i]}" 120
done
QID=$(dataset_of 3-daemon q); QID=${QID##*/v-}
expect "v0 never purged" is "$(count 3-daemon.err "\] ${ID[v0]}: purge:")" 0
expect "q never purged" is "$(count 3-daemon.err "\] $QID: purge: Complete")" 0
kill -TERM "$DPID"; wait "$DPID" 2>/dev/null || true; DPID=

# ── 4. T(1) ─────────────────────────────────────────────────────────

xp() { # xp CASE ID: taso-ctl explain to $W/out/CASE.json; exit to XRC
    XRC=0
    timeout 120 "$BIN/taso-ctl" "$W/keep.json" explain "$2" >"$W/out/$1.json" 2>"$W/out/$1.err" || XRC=$?
}
xj() { # xj CASE EXPR over the explanation e and its checks
    python3 -c 'import json,sys,re; v=json.load(open(sys.argv[1])); e=v.get("explain",{}); checks=v.get("checks",{}); print(eval(sys.argv[2]))' "$W/out/$1.json" "$2"
}
say "4. T(1) (predict: explain holds every check; born from v0's Candidate; its layer is v0's verified artifact, by key; v0's exclusion dropped its Scratch entries)"
xp 4-t1 "$T1"
expect "T(1): explained, every check held" is "$XRC $(xj 4-t1 'len(checks["failed"])')" "0 0"
expect "T(1): born from v0's Candidate" is "$(xj 4-t1 'e["born_from"]["sanction"]["candidate_id"]')" "${CAND[v0]}"
xp 4-v0 "${ID[v0]}"
expect "T(1): its layer is v0's artifact" is "$(xj 4-t1 'e["layer"]')" "$(xj 4-v0 'e["candidates"][0]["nomination"]["artifact_key"]')"
expect "v0: Scratch entries were dropped" bash -c "[[ $(xj 4-v0 'int(re.search(r"scratch: (\d+)", e["candidates"][0]["nomination"]["excluded"]).group(1))') -ge 1 ]]"

# ── 5. The nine purged ──────────────────────────────────────────────

say "5. v1..v9 (predict: no fs pack, each of the fs packs each had replaced by its log-only pack; no dataset; their history explained with every check held; v1's start refused 'purged at lsn'; v0 untouched)"
for i in 1 2 3 4 5 6 7 8 9; do
    v=v$i
    before=$(wc -l <"$W/out/fs-before-$v")
    expect "$v: no fs pack" is "$(fs_packs "${ID[$v]}")" 0
    expect "$v: its $before fs packs replaced" is "$(replaced "${ID[$v]}" "$W/out/fs-before-$v")" "$before"
    expect "$v: no dataset" is "$(dataset_exists "${ID[$v]}")" no
    xp "5-$v" "${ID[$v]}"
    expect "$v: explained, every check held, purge complete" is "$XRC $(xj "5-$v" 'len(checks["failed"])') $(xj "5-$v" 'e["retired"] and e["purge"]["end"]["complete"]["items_replaced"] == e["purge"]["replaced"]')" "0 0 True"
done
wardend 5-v1 1 "$W/v1.json"
expect "v1: start refused, purged" is "$(count 5-v1.out '^v1: .*purged at lsn [0-9]*')" 1
expect "v0: its dataset" is "$(dataset_exists "${ID[v0]}")" yes
expect "v0: its fs packs all there" is "$(fs_packs "${ID[v0]}")" "$(wc -l <"$W/out/fs-before-v0")"

# ── 6. Reconstruction ───────────────────────────────────────────────

say "6. each of the ten decisions from accepted records alone (predict: v0 sanctioned into T(1), completed; v4 never 'a secret is in the input', its hostile Sanction recorded Refused HardRules; v1 v2 v3 v6 v8 v9 never by rule failed; v5 held, then closed by the purge; v7 no Candidate)"
expect "v0: sanctioned into T(1), completed" is "$(xj 4-v0 'e["candidates"][0]["outcome"]["sanctioned"]["template_id"], e["candidates"][0]["outcome"]["sanctioned"]["completed"]')" "('$T1', True)"
expect "v4: never, a secret" is "$(xj 5-v4 'e["candidates"][0]["outcome"]["never"]["reason"]')" "a secret is in the input"
expect "v4: the hostile Sanction refused HardRules" is "$(xj 5-v4 '[x["recorded"] for x in e["candidates"][0]["verdicts"] if x["recorded"] != "submitted"]')" "[{'refused': 'HardRules'}]"
for i in 1 2 3 6 8 9; do
    expect "v$i: never, by rule failed" is "$(xj "5-v$i" 'e["candidates"][0]["outcome"]["never"]["reason"], e["candidates"][0]["verdicts"][-1]["reason"]')" "('failed', 'rule failed')"
done
expect "v5: held, then closed by the purge" is "$(xj 5-v5 'e["candidates"][0]["outcome"], [x.get("decision") for x in e["candidates"][0]["verdicts"]]')" "('closed by the purge', ['hold'])"
expect "v7: no Candidate" is "$(xj 5-v7 'len(e["candidates"])')" 0

# ── 7. A second genesis ─────────────────────────────────────────────

say "7. a second genesis, from another tree (predict: ready; another Template id; a root: no parent, no track record)"
tree "$W/src/t2" second
T2=$(genesis 7-t2 "$W/src/t2" || true)
expect "ready, another root" bash -c "[[ '$T2' =~ ^[0-9a-f]{32}$ && '$T2' != '$T0' ]]"
xp 7-t2 "$T2"
expect "a genesis: no parent, no track record" is "$XRC $(xj 7-t2 'e["parent_template"] is None and "no track record" in e["born_from"]["genesis"]["note"]')" "0 True"

# ── 8. T(1) on an empty node ────────────────────────────────────────

say "8. b2 born from T(1) on node 2, which never held v0 (predict: exit 0; 'Born from Template' T(1), its layer built there from the artifact; b2 nominated with nothing dropped and its verifier finds T(1)'s files without v0's scratch database: 'Exit { code: 0 }')"
vconf b2 'test -s /candidate/app/main.py && ! test -e /candidate/scratch/cache.db'
config 2 "$W/b2.json" "$(born b2 1 "$T1" "$(gsim 1 /work/state.db "")")"
wardend 8-b2 2 "$W/b2.json"
expect "exit 0" is "$RC" 0
expect "born from T(1) on node 2" is "$(count 8-b2.err "\] b2: Born from Template $T1")" 1
expect "its verifier: Exit { code: 0 }" is "$(finished 8-b2 b2)" "Exit { code: 0 }"

# ── Result ──────────────────────────────────────────────────────────

echo
if [[ $FAIL -eq 0 ]]; then
    echo "P4 GATE ($MODE) PASS: $PASS checks"
    exit 0
else
    echo "P4 GATE ($MODE) FAIL: $FAIL of $((PASS + FAIL)) checks failed; logs in $W/out"
    exit 1
fi
