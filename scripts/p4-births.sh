#!/usr/bin/env bash
# p4-births.sh: Vessels born from a Template on real storage, under
# taso-wardend (P4 file 5h; spec rev. 18 §5.5, §5.6, §10.2, D50-D56).
#
#   sudo scripts/p4-births.sh zfs     (from the repository root)
#   sudo scripts/p4-births.sh blk
#
# zfs: Vessel roots are new datasets under $P4B_ZFS_PARENT (default
#      tasotest/vessel): p4b-n1, p4b-n2.  They must not exist; they are
#      destroyed at the end (only these two, with everything under them).
# blk: a fresh taso-blkd on its own log; datasets p4b/n1, p4b/n2 in it.
#
# One machine, two "nodes" (Warden 1 and 2): each its own root, state and
# run directory, sharing one coordinator (taso-coordd --store-config) and
# one store.  T(0) is made by taso-genesis on node 1 from a directory.
# Vessels run the stand-in agent taso-sim under runc (Landlock on unless
# LANDLOCK=0), each in its own uid slot; the Template range is slot 9.
#
# Cases (each prints its prediction before it runs, then PASS or FAIL):
#   1  T(0) from a directory                     taso-genesis, ready
#   2  10 Vessels from T(0) on node 1            one layer built, ten births
#   3  the same 10 again                         opened, nothing born again
#   4  the three birth failpoints                stop, then the rerun finishes
#   5  the four layer failpoints                 a Template each; stop, rerun
#   6  rebirth of one Vessel on node 2           the layer received first
#   7  an entry in the Template slot             the config is refused
#
# Touches, and nothing else:
#   /var/lib/taso-p4b/<mode>                 (removed at start, kept after)
#   /run/taso-p4b-<mode>-coord.sock
#   zfs: $P4B_ZFS_PARENT/p4b-n1, p4b-n2      (created, destroyed at the end)
#   blk: /run/taso-p4b-blk.sock, /mnt/p4b and mounts under it (unmounted at
#        the end), the /dev/ublkb* devices taso-blkd creates for this run
#   runc containers under /var/lib/taso-p4b/<mode>/run<n>/runc (deleted)
#
# Exit 0 only if every check passed.

set -euo pipefail

MODE=${1:-}
[[ "$MODE" == zfs || "$MODE" == blk ]] || { echo "usage: $0 zfs|blk" >&2; exit 2; }

W=/var/lib/taso-p4b/$MODE
SOCK=/run/taso-p4b-$MODE-coord.sock
PARENT=${P4B_ZFS_PARENT:-tasotest/vessel}
BLK_SOCK=/run/taso-p4b-blk.sock
MNT=/mnt/p4b
LANDLOCK=${LANDLOCK:-1}
TURNS=2
BASE=200000            # runtime.host_uid_base of both nodes
SLOT=65536
TSLOT=9                # runtime.template_slot of both nodes
TBASE=$((BASE + TSLOT * SLOT))
NS=5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b
WARDEN1=cccc13deaa40ef3ac092018c13911028   # Warden 1's Chronicle (D55, pinned)

COORD_PID=
BLKD_PID=
ZFS_MADE=()
PASS=0
FAIL=0

say() { printf '\n== %s\n' "$*"; }
die() { printf 'ABORT: %s\n' "$*" >&2; exit 2; }

root_of() { # node -> its root dataset
    if [[ $MODE == zfs ]]; then echo "$PARENT/p4b-n$1"; else echo "p4b/n$1"; fi
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
chmod 755 /var/lib/taso-p4b "$W"

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

printf '{"store": "%s", "prefix": "p4b"}\n' "$W/store" >"$W/store.json"
"$BIN/taso-coordd" "$W/coord.redb" "$SOCK" --store-config "$W/store.json" 2>>"$W/coordd.err" &
COORD_PID=$!
for _ in $(seq 100); do [[ -S "$SOCK" ]] && break; sleep 0.1; done
[[ -S "$SOCK" ]] || die "taso-coordd socket did not appear; see $W/coordd.err"

for n in 1 2; do mkdir -p "$W/state$n" "$W/run$n"; done

# config NODE OUT ENTRY_JSON...: node NODE's Warden config with these
# Vessels (namespace $NS added), every one running taso-sim for $TURNS
# turns.
config() {
    local node=$1 out=$2; shift 2
    python3 - "$node" "$out" "$@" <<PY
import json, sys
node, out, entries = int(sys.argv[1]), sys.argv[2], [json.loads(e) for e in sys.argv[3:]]
storage = "zfs" if "$MODE" == "zfs" else {"blk": {"socket": "$BLK_SOCK", "mounts": "$MNT", "spool": "$W/spool"}}
root = "$PARENT/p4b-n%d" % node if "$MODE" == "zfs" else "p4b/n%d" % node
json.dump({
    "warden": node,
    "coordinator": {"remote": "$SOCK"},
    "storage": storage,
    "root": root,
    "state_dir": "$W/state%d" % node,
    "store": "$W/store",
    "prefix": "p4b",
    "run_dir": "$W/run%d" % node,
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

say "storage $MODE; coordinator $SOCK; work directory $W; Template range slot $TSLOT ($TBASE)"

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
        --actor p4b --reason "file 5h on taso-test" >"$W/out/$1.json" 2>"$W/out/$1.err" || rc=$?
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

entry() { # entry SUBJECT SLOT TEMPLATE [EXTRA_JSON_FIELDS]
    printf '{"subject": "%s", "uid_slot": %s, "template": "%s"%s}' "$1" "$2" "$3" "${4:+, $4}"
}

# The dataset the daemon logged for SUBJECT in case CASE ("" if none).
dataset_of() {
    { grep -o "\] $2: dataset [^ ]*\$" "$W/out/$1.err" || true; } | head -1 | sed 's/.*: dataset //'
}

# lc NODE ID: taso-logcheck of Vessel ID's local log on NODE.
lc() { "$BIN/taso-logcheck" "$SOCK" "$W/state$1" "$2"; }

# judge NODE ID TEMPLATE LAYER [SEALS_AT_LEAST]: the Vessel's Chronicle is
# a Template birth: one Lineage at lsn 1 naming TEMPLATE and LAYER, its
# Birth accepted, the layer object held, consecutive, no Gap, every Seal
# Clean and at least SEALS Seals, its first fs section an increment on
# the layer (base origin = TEMPLATE, lsn 1, LAYER).  Prints "ok" or why.
cat >"$W/judge.py" <<'PY'
import json, sys
tid, layer, want = sys.argv[1], sys.argv[2], int(sys.argv[3])
j = json.load(sys.stdin)
fr = j["frames"]
why = []
lin = [f for f in fr if f["kind"] == "lineage"]
if len(lin) != 1 or fr[0]["kind"] != "lineage":
    why.append("%d Lineage frames" % len(lin))
else:
    l = lin[0]
    if l.get("origin") != "template":
        why.append("origin %s" % l.get("origin"))
    if l.get("template_id") != tid:
        why.append("another Template")
    if l.get("layer_key") != layer:
        why.append("another layer")
cl = j.get("coordlog") or {}
if cl.get("birth") != "accepted":
    why.append("Birth %s" % cl.get("birth"))
if "content:" + layer not in cl.get("holds", []):
    why.append("the layer is not held")
for a, b in zip(fr, fr[1:]):
    if b["lsn"] != a["lsn"] + 1 or b["prev"] != a["hash"]:
        why.append("breaks at lsn %d" % b["lsn"])
        break
if any(f["kind"] == "gap" for f in fr):
    why.append("a Gap")
seals = [f for f in fr if f["kind"] == "seal"]
bad = [f["lsn"] for f in seals if f.get("verdict") != "clean"]
if bad:
    why.append("Seals not Clean at %s" % bad)
if len(seals) < want:
    why.append("%d Seals, fewer than %d" % (len(seals), want))
fs = [f for f in fr if f["kind"] == "fs_shipped"]
if want > 0:
    if not fs:
        why.append("no fs section shipped")
    else:
        got = (fs[0].get("base"), fs[0].get("base_chronicle"), fs[0].get("base_seal"), fs[0].get("base_hash"))
        if got != ("origin", tid, 1, layer):
            why.append("first fs base %s" % (got,))
print("ok" if not why else "; ".join(why))
PY
judge() {
    lc "$1" "$2" | python3 "$W/judge.py" "$3" "$4" "${5:-0}"
}

# The number of LayerShipped records node NODE's Warden Chronicle carries.
shipped_by() {
    local n=$1 d id total=0 c
    for d in "$W/state$n/warden"/*; do
        [[ -d "$d" ]] || continue
        id=${d##*/}
        c=$("$BIN/taso-logcheck" "$SOCK" "$W/state$n/warden" "$id" | python3 -c '
import json, sys
print(sum(1 for f in json.load(sys.stdin)["frames"] if f["kind"] == "contract"))')
        total=$((total + c))
    done
    echo "$total"
}

# Layer datasets (t-) and builds (tb-) under node N's root.
layers_on() { # layers_on NODE PREFIX
    local r; r=$(root_of "$1")
    if [[ $MODE == zfs ]]; then
        zfs list -H -o name -r "$r" | grep -c "^$r/$2-" || true
    else
        blk names | tr ' ' '\n' | grep -c "^$r/$2-" || true
    fi
}

# The ownership of Vessel ID as node NODE's log check reads it: "holder epoch".
owner_of() {
    lc "$1" "$2" | python3 -c 'import json,sys; o=json.load(sys.stdin)["ownership"]; print(o["holder"], o["epoch"])'
}

# ── 1. T(0) ─────────────────────────────────────────────────────────

say "1. T(0) from a directory on node 1 (predict: taso-genesis exit 0, ready)"
tree "$W/src/t0"
T0=$(genesis 1-t0 "$W/src/t0" || true)
expect "T(0) ready" bash -c "[[ '$T0' =~ ^[0-9a-f]{32}$ ]]"
[[ -n "$T0" ]] || die "no T(0): see $W/out/1-t0.err"

# ── 2. Ten Vessels from T(0) ────────────────────────────────────────

SLOTS=(1 2 3 4 5 6 7 8 10 11)   # 9 is the Template range
TEN=()
for i in "${!SLOTS[@]}"; do
    TEN+=("$(entry "v$((i + 1))" "${SLOTS[$i]}" "$T0")")
done
config 1 "$W/ten.json" "${TEN[@]}"

say "2. ten Vessels from T(0) on node 1 (predict: exit 0; the layer built once; ten 'Born from Template', each /work idmapped over $TBASE; each Chronicle a Template birth with its Birth accepted and the layer held, $TURNS turns sealed Clean, its first fs section on the layer; one LayerShipped from Warden 1; one t- dataset, no tb-)"
wardend 2-ten 1 "$W/ten.json"
expect "exit 0" is "$RC" 0
expect "the layer built once" is "$(count 2-ten.err 'built the layer')" 1
expect "ten births from T(0)" is "$(count 2-ten.err "Born from Template $T0")" 10
expect "ten /work idmapped over the Template range" is "$(count 2-ten.err "its files are its lineage's range ($TBASE): /work is idmapped")" 10
LAYER=$(grep -o 'built the layer [0-9a-f]*' "$W/out/2-ten.err" | head -1 | awk '{print $4}')
expect "the layer key logged" bash -c "[[ '$LAYER' =~ ^[0-9a-f]{64}$ ]]"
IDS=()
ALL_OK=0
for i in $(seq 1 10); do
    ds=$(dataset_of 2-ten "v$i")
    id=${ds##*/v-}
    IDS+=("$id")
    verdict=$(judge 1 "$id" "$T0" "$LAYER" "$((TURNS + 1))" 2>&1 || true)
    if [[ "$verdict" == ok ]]; then ALL_OK=$((ALL_OK + 1)); else echo "        v$i: $verdict"; fi
done
expect "ten Chronicles are Template births, Birth accepted, layer held, sealed, first fs on the layer" is "$ALL_OK" 10
expect "one LayerShipped, from Warden 1" is "$(shipped_by 1)" 1
expect "Warden 1's Chronicle is the pinned one" test -d "$W/state1/warden/$WARDEN1"
expect "node 1: one layer dataset, no build left" is "$(layers_on 1 t) $(layers_on 1 tb)" "1 0"

# ── 3. The same ten again ───────────────────────────────────────────

say "3. the same ten again (predict: exit 0; nothing built or born; still one Lineage each, Birth accepted)"
wardend 3-again 1 "$W/ten.json"
expect "exit 0" is "$RC" 0
expect "nothing built" is "$(count 3-again.err 'built the layer')" 0
expect "nothing born" is "$(count 3-again.err 'Born from Template')" 0
ALL_OK=0
for id in "${IDS[@]}"; do
    [[ "$(judge 1 "$id" "$T0" "$LAYER" "$((2 * TURNS + 1))" 2>&1 || true)" == ok ]] && ALL_OK=$((ALL_OK + 1))
done
expect "ten Chronicles still Template births with more turns sealed" is "$ALL_OK" 10
expect "still one LayerShipped" is "$(shipped_by 1)" 1

# ── 4. Birth failpoints ─────────────────────────────────────────────

say "4. birth failpoints (predict: exit 1, 'failpoint <name>' refused the start, no agent ran; the rerun exits 0 with one Lineage and the Birth accepted)"
i=0
for fp in birth.after_clone birth.after_lineage_append birth.before_accept; do
    i=$((i + 1))
    config 1 "$W/fb$i.json" "$(entry "fb$i" $((11 + i)) "$T0")"
    wardend "4-fb$i" 1 "$W/fb$i.json" "TASO_FAILPOINT=$fp"
    expect "$fp: exit 1" is "$RC" 1
    expect "$fp: the start refused at the failpoint" is "$(count "4-fb$i.out" "fb$i: refused: .*failpoint $fp")" 1
    expect "$fp: no agent ran" is "$(count "4-fb$i.err" "fb$i: dataset ")" 0
    wardend "4-fb$i-rerun" 1 "$W/fb$i.json"
    expect "$fp: rerun exit 0" is "$RC" 0
    ds=$(dataset_of "4-fb$i-rerun" "fb$i")
    expect "$fp: rerun is a whole Template birth" is "$(judge 1 "${ds##*/v-}" "$T0" "$LAYER" "$((TURNS + 1))" 2>&1 || true)" ok
done
expect "still one LayerShipped" is "$(shipped_by 1)" 1

# ── 5. Layer failpoints ─────────────────────────────────────────────

say "5. layer failpoints, a new Template each (predict: exit 1, refused at the failpoint, no Vessel state made; the rerun exits 0 with a whole Template birth; one more LayerShipped each; no build left)"
i=0
for fp in layer.after_build_put layer.before_shipped_accept layer.after_shipped_accept layer.after_receive; do
    i=$((i + 1))
    tree "$W/src/tl$i" "tl$i"
    T=$(genesis "5-t$i" "$W/src/tl$i" || true)
    expect "$fp: its Template ready" bash -c "[[ '$T' =~ ^[0-9a-f]{32}$ ]]"
    config 1 "$W/fl$i.json" "$(entry "fl$i" $((14 + i)) "$T")"
    wardend "5-fl$i" 1 "$W/fl$i.json" "TASO_FAILPOINT=$fp"
    expect "$fp: exit 1" is "$RC" 1
    expect "$fp: the start refused at the failpoint" is "$(count "5-fl$i.out" "fl$i: refused: .*failpoint $fp")" 1
    expect "$fp: no Vessel dataset logged" is "$(count "5-fl$i.err" "fl$i: dataset ")" 0
    wardend "5-fl$i-rerun" 1 "$W/fl$i.json"
    expect "$fp: rerun exit 0" is "$RC" 0
    ds=$(dataset_of "5-fl$i-rerun" "fl$i")
    key=$(lc 1 "${ds##*/v-}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["frames"][0].get("layer_key",""))' 2>/dev/null || true)
    expect "$fp: rerun is a whole Template birth" is "$(judge 1 "${ds##*/v-}" "$T" "$key" "$((TURNS + 1))" 2>&1 || true)" ok
    expect "$fp: LayerShipped count $((1 + i))" is "$(shipped_by 1)" "$((1 + i))"
    expect "$fp: no build left" is "$(layers_on 1 tb)" 0
done
case_fp=layer.after_build_put
expect "$case_fp: the rerun destroyed the build the stop left" is "$(count 5-fl1-rerun.err 'an interrupted run left')" 1
expect "layer.before_shipped_accept: the rerun reused the checked layer" is "$(count 5-fl2-rerun.err 'reusing the layer')" 1

# ── 6. Rebirth on node 2 ────────────────────────────────────────────

V1=${IDS[0]}
read -r H1 E1 < <(owner_of 1 "$V1")
config 2 "$W/reborn.json" "$(entry v1 1 "$T0" "\"takeover\": {\"holder\": $H1, \"epoch\": $E1}")"
say "6. node 1 lost for v1 (held by Warden $H1 at epoch $E1); node 2 takes it over (predict: no layer on node 2 before; exit 0; reborn over the layer received there (no build, no LayerShipped from node 2); the same Lineage, Birth accepted; /work idmapped over $TBASE; more turns sealed)"
expect "node 2 has no layer before" is "$(layers_on 2 t)" 0
wardend 6-reborn 2 "$W/reborn.json"
expect "exit 0" is "$RC" 0
expect "reborn" is "$(count 6-reborn.err 'v1: reborn at epoch')" 1
expect "nothing built on node 2" is "$(count 6-reborn.err 'built the layer')" 0
expect "node 2 received the layer: one t- dataset, no build" is "$(layers_on 2 t) $(layers_on 2 tb)" "1 0"
expect "no LayerShipped from node 2" is "$(shipped_by 2)" 0
expect "/work idmapped over the Template range" is "$(count 6-reborn.err "v1: its files are its lineage's range ($TBASE): /work is idmapped")" 1
expect "node 2 holds v1 now" is "$(owner_of 2 "$V1" | cut -d' ' -f1)" 2
R6=$(lc 2 "$V1" | python3 -c '
import json, sys
tid, layer = sys.argv[1], sys.argv[2]
j = json.load(sys.stdin); fr = j["frames"]; why = []
l = fr[0]
if (l["kind"], l.get("origin"), l.get("template_id"), l.get("layer_key")) != ("lineage", "template", tid, layer): why.append("Lineage")
if (j.get("coordlog") or {}).get("birth") != "accepted": why.append("Birth")
seals = [f for f in fr if f["kind"] == "seal"]
first_gap = next((f["lsn"] for f in fr if f["kind"] == "gap"), None)
after = [s for s in seals if first_gap is None or s["lsn"] > first_gap]
if not any(s["epoch"] == j["ownership"]["epoch"] for s in seals): why.append("no Seal in the new epoch")
print("ok" if not why else "; ".join(why))' "$T0" "$LAYER" 2>&1 || true)
expect "the same Lineage, Birth accepted, a Seal sealed in node 2's epoch" is "$R6" ok

# ── 7. An entry in the Template slot ────────────────────────────────

say "7. an entry in uid slot $TSLOT (predict: the config is refused, exit 2, nothing started)"
config 1 "$W/slot.json" "$(entry v-slot "$TSLOT" "$T0")"
wardend 7-slot 1 "$W/slot.json"
expect "exit 2" is "$RC" 2
expect "the Template range named in the refusal" is "$(count 7-slot.err "uid_slot $TSLOT")" 1

# ── Result ──────────────────────────────────────────────────────────

echo
if [[ $FAIL -eq 0 ]]; then
    echo "P4 BIRTHS ($MODE) PASS: $PASS checks"
    exit 0
else
    echo "P4 BIRTHS ($MODE) FAIL: $FAIL of $((PASS + FAIL)) checks failed; logs in $W/out"
    exit 1
fi
