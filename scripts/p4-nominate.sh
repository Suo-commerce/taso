#!/usr/bin/env bash
# p4-nominate.sh: nomination on real storage, under taso-wardend (P4 file
# 6d; spec rev. 19 §3.1, §4.1, §4.3, D57-D63).
#
#   scripts/p4-nominate.sh zfs     (as root, from the repository root; not
#                                   through sudo, which drops cargo from PATH)
#   scripts/p4-nominate.sh blk
#
# zfs: Vessel roots are new datasets under $P4B_ZFS_PARENT (default
#      tasotest/vessel): p4n-n1, p4n-n2.  They must not exist; they are
#      destroyed at the end (only these two, with everything under them).
# blk: a fresh taso-blkd on its own log; datasets p4n/n1, p4n/n2 in it.
#
# One machine, two "nodes" (Warden 1 and 2), sharing one coordinator and
# one store.  T(0), the verifier Template every requirement names, is made
# by taso-genesis on node 1.  Node 1 classifies with a map whose catch-all
# is Source and whose scratch/ is Scratch; node 2 with a map that names
# nothing the agent writes (so everything is Unknown).  Vessels run
# taso-sim under runc; a Vessel's agent asks with --nominate after its
# turns, and a "candidate" entry nominates at the start.
#
# Cases (each prints its prediction before it runs, then PASS or FAIL):
#   1  T(0) from a directory                       taso-genesis, ready
#   2  the agent nominates its newest Seal         Nominated, held
#   3  again after two more turns                  a second Candidate
#   4  the same Seal by the "candidate" entry      Duplicate (another kind)
#      and with another exclusion                  Nominated
#   5  an exclusion outside the allowed set        refused BadExclude
#   6  node 2's map: everything Unknown            refused Walk(UnknownPaths)
#   7  the five nominate failpoints                stop, nothing accepted;
#                                                  the rerun is Nominated
#   8  a "candidate" without "verifier"            the config is refused
#
# Touches, and nothing else:
#   /var/lib/taso-p4n/<mode>                 (removed at start, kept after)
#   /run/taso-p4n-<mode>-coord.sock
#   zfs: $P4B_ZFS_PARENT/p4n-n1, p4n-n2      (created, destroyed at the end)
#   blk: /run/taso-p4n-blk.sock, /mnt/p4n and mounts under it (unmounted at
#        the end), the /dev/ublkb* devices taso-blkd creates for this run
#   runc containers under /var/lib/taso-p4n/<mode>/run<n>/runc (deleted)
#
# Exit 0 only if every check passed.

set -euo pipefail

MODE=${1:-}
[[ "$MODE" == zfs || "$MODE" == blk ]] || { echo "usage: $0 zfs|blk" >&2; exit 2; }

W=/var/lib/taso-p4n/$MODE
SOCK=/run/taso-p4n-$MODE-coord.sock
PARENT=${P4B_ZFS_PARENT:-tasotest/vessel}
BLK_SOCK=/run/taso-p4n-blk.sock
MNT=/mnt/p4n
LANDLOCK=${LANDLOCK:-1}
TURNS=2
BASE=200000            # runtime.host_uid_base of both nodes
TSLOT=9                # runtime.template_slot of both nodes
NS=6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c

COORD_PID=
BLKD_PID=
ZFS_MADE=()
PASS=0
FAIL=0

say() { printf '\n== %s\n' "$*"; }
die() { printf 'ABORT: %s\n' "$*" >&2; exit 2; }

root_of() { # node -> its root dataset
    if [[ $MODE == zfs ]]; then echo "$PARENT/p4n-n$1"; else echo "p4n/n$1"; fi
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
chmod 755 /var/lib/taso-p4n "$W"

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

printf '{"store": "%s", "prefix": "p4n"}\n' "$W/store" >"$W/store.json"
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
root = "$PARENT/p4n-n%d" % node if "$MODE" == "zfs" else "p4n/n%d" % node
json.dump({
    "warden": node,
    "coordinator": {"remote": "$SOCK"},
    "storage": storage,
    "root": root,
    "state_dir": "$W/state%d" % node,
    "store": "$W/store",
    "prefix": "p4n",
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
        --actor p4n --reason "file 6d on taso-test" >"$W/out/$1.json" 2>"$W/out/$1.err" || rc=$?
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

# vessel SUBJECT SLOT [EXTRA_JSON_FIELDS]: an entry with T(0) as its
# verifier.
vessel() {
    printf '{"subject": "%s", "uid_slot": %s, "verifier": {"template": "%s", "config": "%s", "version": 1}%s}' \
        "$1" "$2" "$T0" "$W/vconf.toml" "${3:+, $3}"
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

# ── 1. T(0) ─────────────────────────────────────────────────────────

say "1. T(0) from a directory on node 1, the verifier Template (predict: taso-genesis exit 0, ready)"
tree "$W/src/t0"
T0=$(genesis 1-t0 "$W/src/t0" || true)
expect "T(0) ready" bash -c "[[ '$T0' =~ ^[0-9a-f]{32}$ ]]"
[[ -n "$T0" ]] || die "no T(0): see $W/out/1-t0.err"

# ── 2. The agent nominates ──────────────────────────────────────────

config 1 "$W/n1.json" "$(vessel n1 1 "$(sim "$TURNS" Scratch)")"
say "2. n1 runs $TURNS turns, then its agent nominates the newest Seal dropping Scratch (predict: exit 0; one 'Nominated'; the daemon attempts it (D68; this vconf has no version, so 'LaunchFailed'), so the coordinator log holds three accepted records for n1 (Candidate, VerificationStarted, VerificationFinished) and, the attempt finished, four content objects: the artifact, the classmap, the vconf and one manifest, since nothing of class Scratch is there and the output manifest is the input's)"
wardend 2-n1 1 "$W/n1.json"
expect "exit 0" is "$RC" 0
A2=$(answers 2-n1 n1 Agent)
expect "the agent's nomination: Nominated" is "$(printf '%s\n' "$A2" | grep -c '^Nominated')" 1
C2=$(printf '%s\n' "$A2" | cand)
expect "a candidate id" bash -c "[[ '$C2' =~ ^[0-9a-f]{64}$ ]]"
DS=$(dataset_of 2-n1 n1); N1=${DS##*/v-}
expect "its attempt finished LaunchFailed" is "$(count 2-n1.err '\] n1: attempt [0-9a-f]*: finished LaunchFailed')" 1
expect "three accepted records, four content objects held" is "$(coordlog_of 1 "$N1")" "3 4"
expect "the three records are in n1's own log" is "$(contracts_of 1 "$N1")" 3

# ── 3. Again, two turns later ───────────────────────────────────────

say "3. n1 again: $TURNS more turns, the agent nominates its new newest Seal (predict: exit 0; Nominated, another candidate id, attempted; six accepted records)"
wardend 3-n1 1 "$W/n1.json"
expect "exit 0" is "$RC" 0
C3=$(answers 3-n1 n1 Agent | cand)
expect "Nominated, another Candidate" bash -c "[[ '$C3' =~ ^[0-9a-f]{64}$ && '$C3' != '$C2' ]]"
expect "six accepted records" is "$(coordlog_of 1 "$N1" | cut -d' ' -f1)" 6
L3=$(last_seal 1 "$N1")

# ── 4. The entry's candidate ────────────────────────────────────────

config 1 "$W/n1-cand.json" "$(vessel n1 1 "\"candidate\": {\"seal\": $L3, \"exclude\": [\"Scratch\"]}, $(sim 1)")"
say "4. n1's entry nominates the Seal at lsn $L3 dropping Scratch, the one its agent nominated (predict: 'Refused { reason: \"Duplicate\" }', recorded once; then without the exclusion: Nominated, a third Candidate)"
wardend 4-dup 1 "$W/n1-cand.json"
expect "exit 0" is "$RC" 0
expect "the entry's nomination refused Duplicate" is "$(answers 4-dup n1 Config)" 'Refused { reason: "Duplicate" }'
expect "accepted: two Candidates with their attempts, and the refusal" is "$(coordlog_of 1 "$N1" | cut -d' ' -f1)" 7
config 1 "$W/n1-all.json" "$(vessel n1 1 "\"candidate\": {\"seal\": $L3, \"exclude\": []}, $(sim 1)")"
wardend 4-all 1 "$W/n1-all.json"
expect "exit 0" is "$RC" 0
C4=$(answers 4-all n1 Config | cand)
expect "Nominated, a third Candidate" bash -c "[[ '$C4' =~ ^[0-9a-f]{64}$ && '$C4' != '$C2' && '$C4' != '$C3' ]]"

# ── 5. An exclusion outside the allowed set ─────────────────────────

config 1 "$W/n2.json" "$(vessel n2 2 "$(sim "$TURNS" Source Source)")"
say "5. n2's agent asks to drop Source, twice (predict: exit 0; 'Refused { reason: \"BadExclude\" }' both times; one record accepted)"
wardend 5-n2 1 "$W/n2.json"
expect "exit 0" is "$RC" 0
expect "refused BadExclude twice" is "$(answers 5-n2 n2 Agent | grep -c '^Refused { reason: "BadExclude" }$')" 2
DS=$(dataset_of 5-n2 n2)
expect "one record accepted (the refusal)" is "$(coordlog_of 1 "${DS##*/v-}" | cut -d' ' -f1)" 1

# ── 6. Node 2's map ─────────────────────────────────────────────────

config 2 "$W/u.json" "$(vessel u 3 "$(sim "$TURNS" Scratch)")"
say "6. on node 2, whose map names nothing the agent writes (predict: exit 0; 'Refused { reason: \"Walk(UnknownPaths)\" }')"
wardend 6-u 2 "$W/u.json"
expect "exit 0" is "$RC" 0
expect "refused Walk(UnknownPaths)" is "$(answers 6-u u Agent)" 'Refused { reason: "Walk(UnknownPaths)" }'

# ── 7. Failpoints ───────────────────────────────────────────────────

say "7. the five nominate failpoints, each on its own Vessel's newest Seal by its entry (predict: exit 0 and 'Retry' naming the failpoint, nothing accepted; the rerun of the same Seal: Nominated and attempted, three accepted records)"
i=0
for fp in nominate.after_input_manifest nominate.after_output_manifest nominate.after_artifact_put \
          nominate.after_announce nominate.before_accept; do
    i=$((i + 1))
    config 1 "$W/f$i.json" "$(vessel "f$i" $((9 + i)) "$(sim "$TURNS")")"
    wardend "7-f$i" 1 "$W/f$i.json"
    DS=$(dataset_of "7-f$i" "f$i"); FI=${DS##*/v-}
    L=$(last_seal 1 "$FI")
    config 1 "$W/f$i-c.json" "$(vessel "f$i" $((9 + i)) "\"candidate\": {\"seal\": $L, \"exclude\": [\"Scratch\"]}, $(sim 1)")"
    wardend "7-f$i-stop" 1 "$W/f$i-c.json" "TASO_FAILPOINT=$fp"
    expect "$fp: exit 0" is "$RC" 0
    expect "$fp: Retry at the failpoint" is "$(answers "7-f$i-stop" "f$i" Config | grep -c "^Retry.*failpoint $fp")" 1
    expect "$fp: nothing accepted" is "$(coordlog_of 1 "$FI" | cut -d' ' -f1)" 0
    wardend "7-f$i-rerun" 1 "$W/f$i-c.json"
    expect "$fp: rerun exit 0" is "$RC" 0
    expect "$fp: rerun Nominated" is "$(answers "7-f$i-rerun" "f$i" Config | grep -c '^Nominated')" 1
    expect "$fp: three accepted records" is "$(coordlog_of 1 "$FI" | cut -d' ' -f1)" 3
done

# ── 8. A candidate without a verifier ───────────────────────────────

config 1 "$W/bad.json" '{"subject": "bad", "uid_slot": 20, "candidate": {"seal": "last"}}'
say "8. a \"candidate\" entry without \"verifier\" (predict: the config is refused, exit 2)"
wardend 8-bad 1 "$W/bad.json"
expect "exit 2" is "$RC" 2
expect "the refusal names what it needs" is "$(count 8-bad.err 'needs its "verifier"')" 1

# ── Result ──────────────────────────────────────────────────────────

echo
if [[ $FAIL -eq 0 ]]; then
    echo "P4 NOMINATE ($MODE) PASS: $PASS checks"
    exit 0
else
    echo "P4 NOMINATE ($MODE) FAIL: $FAIL of $((PASS + FAIL)) checks failed; logs in $W/out"
    exit 1
fi
