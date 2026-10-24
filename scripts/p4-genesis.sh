#!/usr/bin/env bash
# p4-genesis.sh: taso-genesis on real storage (P4 file 4c; spec rev. 14 §7,
# D40-D48).
#
#   sudo scripts/p4-genesis.sh zfs     (from the repository root)
#   sudo scripts/p4-genesis.sh blk
#
# zfs: Vessel roots are new datasets under $P4G_ZFS_PARENT (default
#      tasotest/vessel): p4g-n1 .. p4g-n4.  They must not exist; they are
#      destroyed at the end (only these four, with everything under them).
# blk: a fresh taso-blkd on its own log; datasets p4g/n1 .. p4g/n4 in it.
#
# Each run has its own coordinator (taso-coordd with --store-config), store,
# state directories and Warden configs (warden ids 1-4, one "node" each, all
# on this machine; a lost node is its state directory removed).
#
# Touches, and nothing else:
#   /var/lib/taso-p4g/<mode>                 (removed at start, kept after)
#   /run/taso-p4g-<mode>-coord.sock
#   zfs: $P4G_ZFS_PARENT/p4g-n1 .. p4g-n4    (created, destroyed at the end)
#   blk: /run/taso-p4g-blk.sock, /mnt/p4g and mounts under it (unmounted at
#        the end), the /dev/ublkb* devices taso-blkd creates for this run
#
# Every case prints its prediction before it runs, then PASS or FAIL.
# Exit 0 only if every case passed.

set -euo pipefail

MODE=${1:-}
[[ "$MODE" == zfs || "$MODE" == blk ]] || { echo "usage: $0 zfs|blk" >&2; exit 2; }

W=/var/lib/taso-p4g/$MODE
SOCK=/run/taso-p4g-$MODE-coord.sock
PARENT=${P4G_ZFS_PARENT:-tasotest/vessel}
BLK_SOCK=/run/taso-p4g-blk.sock
MNT=/mnt/p4g
G=target/release/taso-genesis
COORDD=target/release/taso-coordd
LOGCHECK=target/release/taso-logcheck
BLKD=target/release/taso-blkd
BASE=200000            # runtime.host_uid_base of every node
SLOT=65536

COORD_PID=
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
    if [[ -n "$COORD_PID" ]] && kill -0 "$COORD_PID" 2>/dev/null; then
        kill "$COORD_PID"; wait "$COORD_PID" 2>/dev/null
    fi
    if [[ $MODE == zfs ]]; then
        for ds in "${ZFS_MADE[@]}"; do
            zfs destroy -r "$ds" || echo "WARNING: could not destroy $ds"
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
[[ ! -S "$SOCK" ]] || die "$SOCK exists: another run's coordinator? (pgrep -x taso-coordd)"
if [[ $MODE == zfs ]]; then
    zfs list -H -o name "$PARENT" >/dev/null || die "no dataset $PARENT (set P4G_ZFS_PARENT)"
    for n in 1 2 3 4; do
        if zfs list -H -o name "$(root_of $n)" >/dev/null 2>&1; then
            die "$(root_of $n) exists (left by a previous run?): zfs destroy -r $(root_of $n)"
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
cargo build -q --release -p taso-warden --bin taso-genesis --bin taso-coordd --bin taso-logcheck
[[ $MODE == blk ]] && cargo build -q --release -p taso-blk

rm -rf "$W"
mkdir -p "$W/store" "$W/src"

# ── Storage, coordinator, node configs ──────────────────────────────

if [[ $MODE == zfs ]]; then
    for n in 1 2 3 4; do
        zfs create "$(root_of $n)"
        ZFS_MADE+=("$(root_of $n)")
    done
    STORAGE='"zfs"'
else
    "$BLKD" "$W/blk.log" "$BLK_SOCK" 2>>"$W/blkd.err" &
    BLKD_PID=$!
    for _ in $(seq 100); do [[ -S "$BLK_SOCK" ]] && break; sleep 0.1; done
    [[ -S "$BLK_SOCK" ]] || die "taso-blkd socket did not appear; see $W/blkd.err"
    mkdir -p "$W/spool"
    STORAGE="{\"blk\": {\"socket\": \"$BLK_SOCK\", \"mounts\": \"$MNT\", \"spool\": \"$W/spool\"}}"
fi

printf '{"store": "%s", "prefix": "p4g"}\n' "$W/store" >"$W/store.json"
"$COORDD" "$W/coord.redb" "$SOCK" --store-config "$W/store.json" 2>>"$W/coordd.err" &
COORD_PID=$!
for _ in $(seq 100); do [[ -S "$SOCK" ]] && break; sleep 0.1; done
[[ -S "$SOCK" ]] || die "taso-coordd socket did not appear; see $W/coordd.err"

for n in 1 2 3 4; do
    mkdir -p "$W/state$n" "$W/run$n"
    cat >"$W/node$n.json" <<EOF
{
  "warden": $n,
  "coordinator": { "remote": "$SOCK" },
  "root": "$(root_of $n)",
  "state_dir": "$W/state$n",
  "run_dir": "$W/run$n",
  "store": "$W/store",
  "prefix": "p4g",
  "storage": $STORAGE,
  "runtime": { "host_uid_base": $BASE },
  "vessels": []
}
EOF
done

cat >"$W/map.toml" <<'EOF'
version = 1
[[rule]]
glob = "**"
class = "Source"
[[rule]]
glob = "etc/"
class = "Config"
[[rule]]
glob = "hooks/"
class = "Hook"
[[rule]]
glob = "**/*.key"
class = "Secret"
[[rule]]
glob = "odd/"
class = "Source"
[[rule]]
glob = "odd/"
class = "Scratch"
EOF

say "storage $MODE; coordinator $SOCK; work directory $W"

# ── Trees ───────────────────────────────────────────────────────────

# tree DIR OWNER [VARIANT]: the same files every time, owned by OWNER, with
# fixed times, so equal trees give equal artifacts.  Only the paths made
# here are chowned and chmodded (an ext4 lost+found is left as it is).
tree() {
    local d=$1 o=$2 v=${3:-}
    mkdir -p "$d/app/lib" "$d/etc"
    printf "print('hello')\n" >"$d/app/main.py"
    printf 'X = 1\n' >"$d/app/lib/util.py"
    printf 'debug = false\n' >"$d/etc/app.toml"
    ln -sfn app/main.py "$d/main"
    local paths=("$d" "$d/app" "$d/app/lib" "$d/etc" "$d/app/main.py" "$d/app/lib/util.py" "$d/etc/app.toml")
    if [[ -n "$v" ]]; then
        printf '%s\n' "$v" >"$d/app/variant-$v.py"
        paths+=("$d/app/variant-$v.py")
    fi
    chown -h "$o:$o" "${paths[@]}" "$d/main"
    chmod 755 "$d" "$d/app" "$d/app/lib" "$d/etc"
    chmod 644 "$d/app/main.py" "$d/app/lib/util.py" "$d/etc/app.toml"
    [[ -z "$v" ]] || chmod 644 "$d/app/variant-$v.py"
    settle "$d"
}

# Fixed times: files and links first, then directories deepest first.
settle() {
    find "$1" -mindepth 1 ! -type d -exec touch -h -d @1700000000 {} +
    find "$1" -depth -type d -exec touch -d @1600000000 {} +
}

# ── Running and judging ─────────────────────────────────────────────

# g CASE NODE [ENV=VALUE...] -- ARGS...: run taso-genesis as node NODE;
# stdout to $W/out/CASE.json, stderr to $W/out/CASE.err, exit status to RC.
mkdir -p "$W/out"
g() {
    local case=$1 node=$2; shift 2
    local envs=()
    while [[ $# -gt 0 && "$1" != -- ]]; do envs+=("$1"); shift; done
    shift
    RC=0
    env "${envs[@]}" "$G" "$W/node$node.json" "$@" >"$W/out/$case.json" 2>"$W/out/$case.err" || RC=$?
}

jf() { # jf CASE KEY: a field of the report ("" if absent)
    python3 - "$W/out/$1.json" "$2" <<'PY'
import json, sys
try:
    v = json.load(open(sys.argv[1]))
except Exception:
    print(""); sys.exit(0)
x = v.get(sys.argv[2])
print("" if x is None else (str(x).lower() if isinstance(x, bool) else x))
PY
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
has() { grep -q -- "$2" "$W/out/$1.err"; }

GENRUN=(--classmap "$W/map.toml" --actor p4g --reason "file 4c on taso-test")

# The genesis id of a run that printed nothing: its log directory's name.
gid_of_node() {
    local d
    for d in "$W/state$1/genesis"/*; do
        d=${d##*/}
        [[ "$d" =~ ^[0-9a-f]{32}$ ]] && { echo "$d"; return 0; }
    done
    return 1
}

# The genesis Chronicle's local log on NODE, as taso-logcheck sees it.
frames() { # frames NODE ID -> "kinds" e.g. "contract contract contract"
    "$LOGCHECK" "$SOCK" "$W/state$1/genesis" "$2" | python3 -c '
import json, sys
v = json.load(sys.stdin)
print(" ".join(f["kind"] for f in v["frames"]))'
}

# Scratch datasets left on the storage, and Seal views.
scratches() {
    if [[ $MODE == zfs ]]; then
        zfs list -H -o name -r "${ZFS_MADE[@]}" | grep -c '/genesis-' || true
    else
        blk names | tr ' ' '\n' | grep -c '/genesis-' || true
    fi
}
views() {
    if [[ $MODE == zfs ]]; then echo 0; else blk names | tr ' ' '\n' | grep -c '\.view-' || true; fi
}

# ── 1. A directory becomes a Template ───────────────────────────────

say "1. ready from a directory (predict: exit 0, ready, layer = source_key, cleaned; rerun the same; log = 3 contract records, no lineage)"
tree "$W/src/a" 0
g 1-ready 1 -- --from "$W/src/a" --best-effort "${GENRUN[@]}"
expect "exit 0" is "$RC" 0
expect "outcome ready" is "$(jf 1-ready outcome)" ready
expect "template_id = genesis_id" is "$(jf 1-ready template_id)" "$(jf 1-ready genesis_id)"
expect "layer = source_key (nothing excluded: the same bytes)" is "$(jf 1-ready layer)" "$(jf 1-ready source_key)"
expect "cleaned" is "$(jf 1-ready cleaned)" true
ID1=$(jf 1-ready genesis_id)
SRC1=$(jf 1-ready source_key)
expect "log: GenesisStarted, TemplateReady, GenesisCleanedUp; no Lineage" is "$(frames 1 "$ID1")" "contract contract contract"
g 1-again 1 -- --from "$W/src/a" --best-effort "${GENRUN[@]}"
expect "rerun: exit 0" is "$RC" 0
expect "rerun: the same Template" is "$(jf 1-again template_id)" "$ID1"
expect "rerun: nothing new in the log" is "$(frames 1 "$ID1")" "contract contract contract"
g 1-noflag 1 -- --from "$W/src/a" "${GENRUN[@]}"
expect "a directory without --best-effort: exit 1, SourceNotImmutable" \
    bash -c "[[ $RC == 1 ]] && grep -q SourceNotImmutable '$W/out/1-noflag.err'"

# ── 2. Refusals ─────────────────────────────────────────────────────

refusal() { # refusal CASE REASON [EXTRA ARGS]: tree $W/src/CASE was made
    local c=$1 want=$2; shift 2
    g "2-$c" 1 -- --from "$W/src/$c" --best-effort "${GENRUN[@]}" "$@"
    expect "$c: exit 3" is "$RC" 3
    expect "$c: refused $want" is "$(jf "2-$c" reason)" "$want"
    expect "$c: input manifest named" bash -c "[[ -n '$(jf "2-$c" input_manifest_key)' ]]"
    expect "$c: no cleanup (no scratch was made)" is "$(jf "2-$c" cleaned)" false
}

say "2. refusals (predict: exit 3 with the reason; no scratch made)"
tree "$W/src/secret" 0 secret; printf -- '-----\n' >"$W/src/secret/app/server.key"; settle "$W/src/secret"
refusal secret SecretPaths
tree "$W/src/unknown" 0 unknown; mkdir -p "$W/src/unknown/odd"; printf '?\n' >"$W/src/unknown/odd/x"; settle "$W/src/unknown"
refusal unknown UnknownPaths
tree "$W/src/hook" 0 hook; mkdir -p "$W/src/hook/hooks"; printf '#!/bin/sh\n' >"$W/src/hook/hooks/pre-commit"; settle "$W/src/hook"
refusal hook HookNotWaived
tree "$W/src/fifo" 0 fifo; mkfifo "$W/src/fifo/app/pipe"; settle "$W/src/fifo"
refusal fifo Unsupported
tree "$W/src/lf" 0 lf; mkdir "$W/src/lf/lost+found"; chmod 755 "$W/src/lf/lost+found"; settle "$W/src/lf"
refusal lf ReservedMismatch
g 2-waived 1 -- --from "$W/src/hook" --best-effort "${GENRUN[@]}" --hook-waiver "reviewed by hand"
expect "hook with --hook-waiver: exit 0, ready" bash -c "[[ $RC == 0 && '$(jf 2-waived outcome)' == ready ]]"
expect "no scratch left after refusals and readies" is "$(scratches)" 0

# ── 3. Every failpoint, rerun on the same node ──────────────────────

say "3. failpoints (predict: exit 9 at the point; the rerun exits 0, ready, cleaned; the leftover scratch reported where one was made)"
i=0
for fp in genesis.after_source_put genesis.before_started_accept genesis.after_started_accept \
          genesis.after_materialise genesis.after_artifact_put genesis.before_ready_accept \
          genesis.after_ready_accept genesis.before_cleanup; do
    i=$((i + 1))
    tree "$W/src/fp$i" 0 "fp$i"
    g "3-fp$i" 1 "TASO_FAILPOINT=$fp" -- --from "$W/src/fp$i" --best-effort "${GENRUN[@]}"
    expect "$fp: exit 9" is "$RC" 9
    g "3-fp$i-rerun" 1 -- --from "$W/src/fp$i" --best-effort "${GENRUN[@]}"
    expect "$fp: rerun exit 0, ready, cleaned" \
        bash -c "[[ $RC == 0 && '$(jf "3-fp$i-rerun" outcome)' == ready && '$(jf "3-fp$i-rerun" cleaned)' == true ]]"
    case $fp in
        genesis.after_materialise|genesis.after_artifact_put|genesis.before_ready_accept)
            expect "$fp: leftover scratch destroyed and reported" has "3-fp$i-rerun" "an interrupted run left";;
    esac
done
expect "no scratch left after the failpoints" is "$(scratches)" 0

# ── 4. Lost replies ─────────────────────────────────────────────────

say "4. lost replies (predict: exit 9 after the accept; the rerun finds it accepted and finishes: 0, or 3 for the refusal)"
for rec in GenesisStarted TemplateReady GenesisCleanedUp; do
    tree "$W/src/lr-$rec" 0 "lr$rec"
    g "4-$rec" 1 "TASO_LOSE_REPLY=$rec" -- --from "$W/src/lr-$rec" --best-effort "${GENRUN[@]}"
    expect "$rec: exit 9" is "$RC" 9
    g "4-$rec-rerun" 1 -- --from "$W/src/lr-$rec" --best-effort "${GENRUN[@]}"
    expect "$rec: rerun exit 0, ready, cleaned" \
        bash -c "[[ $RC == 0 && '$(jf "4-$rec-rerun" outcome)' == ready && '$(jf "4-$rec-rerun" cleaned)' == true ]]"
    expect "$rec: log has exactly 3 records" is "$(frames 1 "$(jf "4-$rec-rerun" genesis_id)")" "contract contract contract"
done
tree "$W/src/lr-ref" 0 lrref; printf -- '-----\n' >"$W/src/lr-ref/app/server.key"; settle "$W/src/lr-ref"
g 4-refused 1 TASO_LOSE_REPLY=GenesisRefused -- --from "$W/src/lr-ref" --best-effort "${GENRUN[@]}"
expect "GenesisRefused: exit 9" is "$RC" 9
g 4-refused-rerun 1 -- --from "$W/src/lr-ref" --best-effort "${GENRUN[@]}"
expect "GenesisRefused: rerun exit 3, SecretPaths" \
    bash -c "[[ $RC == 3 && '$(jf 4-refused-rerun reason)' == SecretPaths ]]"

# ── 5. A lost node; resume by id with the source gone (D42, D48) ────

say "5. node 3 lost after materialising, source deleted; node 2 --resume (predict: exit 0, ready, takeover and resume reported; node 3's scratch is left)"
tree "$W/src/lost" 0 lost
g 5-lost 3 TASO_FAILPOINT=genesis.after_materialise -- --from "$W/src/lost" --best-effort "${GENRUN[@]}"
expect "node 3: exit 9" is "$RC" 9
ID5=$(gid_of_node 3 || true)
rm -rf "$W/state3" "$W/src/lost"
g 5-resume 2 -- --resume "$ID5"
expect "node 2 --resume: exit 0, ready, cleaned" \
    bash -c "[[ $RC == 0 && '$(jf 5-resume outcome)' == ready && '$(jf 5-resume cleaned)' == true ]]"
expect "the same genesis" is "$(jf 5-resume template_id)" "$ID5"
expect "takeover reported (authority GenesisStarted)" has 5-resume "authority GenesisStarted"
expect "resume reported" has 5-resume "resumed by id"
expect "node 2 rebuilt the log from the packs: 3 records" is "$(frames 2 "$ID5")" "contract contract contract"
expect "exactly one scratch left: the lost node's" is "$(scratches)" 1

# ── 6. Takeover before GenesisStarted (D42) ─────────────────────────

say "6. node 4 lost after its claim, before GenesisStarted is accepted; node 2 runs the same inputs (predict: exit 0, takeover with authority Genesis)"
tree "$W/src/pre" 0 pre
g 6-pre 4 TASO_FAILPOINT=genesis.before_started_accept -- --from "$W/src/pre" --best-effort "${GENRUN[@]}"
expect "node 4: exit 9" is "$RC" 9
ID6=$(gid_of_node 4 || true)
rm -rf "$W/state4"
g 6-resume 2 -- --resume "$ID6"
expect "--resume before GenesisStarted: exit 1, nothing to resume" \
    bash -c "[[ $RC == 1 ]] && grep -q 'nothing to resume' '$W/out/6-resume.err'"
g 6-takeover 2 -- --from "$W/src/pre" --best-effort "${GENRUN[@]}"
expect "node 2: exit 0, ready" bash -c "[[ $RC == 0 && '$(jf 6-takeover outcome)' == ready ]]"
expect "takeover reported (authority Genesis)" has 6-takeover "authority Genesis)"
g 7-nothing 2 -- --resume 00000000000000000000000000000000
expect "--resume of an unknown id: exit 1, nothing to resume" \
    bash -c "[[ $RC == 1 ]] && grep -q 'nothing to resume' '$W/out/7-nothing.err'"

# ── 8. A Vessel's Seal as the source (D44) ──────────────────────────

# make_seal NAME OWNER LOSTFOUND_OWNER: a dataset in node 1's root holding
# the good tree, its top directory owned OWNER:OWNER as the P3 runtime
# leaves it, sealed at lsn 5.  On the block log ext4 makes lost+found
# (0:0); LOSTFOUND_OWNER chowns it ("-" leaves it as mkfs made it).
make_seal() {
    local name=$1 owner=$2 lf=$3 ds dir
    ds="$(root_of 1)/$name"
    local hash
    hash=$(printf '05%.0s' $(seq 32))
    if [[ $MODE == zfs ]]; then
        zfs create "$ds"
        dir=$(zfs get -H -o value mountpoint "$ds")
        tree "$dir" "$((BASE + 2 * SLOT))"
        chown "$owner:$owner" "$dir"
        settle "$dir"
        zfs snapshot -o "taso:seal=$hash" "$ds@taso-seal-$(printf '%020d' 5)"
    else
        local rootseal branch dev
        rootseal=$(blk root | cut -d' ' -f2)
        read -r _ branch dev < <(blk fork "$rootseal" "$ds")
        mkfs.ext4 -q -F -E nodiscard "$dev"
        dir="$MNT/$ds"
        mkdir -p "$dir"
        mount -o discard "$dev" "$dir"
        tree "$dir" "$((BASE + 2 * SLOT))"
        chown "$owner:$owner" "$dir"
        [[ "$lf" == - ]] || chown "$lf:$lf" "$dir/lost+found"
        settle "$dir"
        sync
        umount "$dir"
        blk detach "$branch" >/dev/null
        blk seal "$branch" "0500000000000000$hash" >/dev/null
    fi
    echo "$ds"
}

say "8. a Vessel's Seal (predict below per storage)"
SB=$((BASE + 2 * SLOT))
if [[ $MODE == zfs ]]; then
    echo "   predict: top dir owned by a slot base: exit 0, and the source artifact is the directory's of case 1 (same files, slots 0); top dir 0:0: exit 1, base cannot be told"
    DS=$(make_seal v-seal "$SB" -)
    g 8-seal 1 -- --from "$DS@5" "${GENRUN[@]}"
    expect "Seal: exit 0, ready" bash -c "[[ $RC == 0 && '$(jf 8-seal outcome)' == ready ]]"
    expect "Seal: source_key = case 1's" is "$(jf 8-seal source_key)" "$SRC1"
else
    echo "   predict: lost+found left 0:0 as ext4 makes it (as the P3 runtime leaves it today): exit 3, ReservedMismatch (finding);"
    echo "            lost+found chowned to the slot base too: exit 0, ready; top dir 0:0: exit 1, base cannot be told"
    DS=$(make_seal v-seal "$SB" -)
    g 8-seal 1 -- --from "$DS@5" "${GENRUN[@]}"
    expect "Seal, lost+found 0:0: exit 3, ReservedMismatch" \
        bash -c "[[ $RC == 3 && '$(jf 8-seal reason)' == ReservedMismatch ]]"
    DS=$(make_seal v-seal-lf "$SB" "$SB")
    g 8-seal-lf 1 -- --from "$DS@5" "${GENRUN[@]}"
    expect "Seal, lost+found at the slot base: exit 0, ready" \
        bash -c "[[ $RC == 0 && '$(jf 8-seal-lf outcome)' == ready ]]"
fi
DS=$(make_seal v-fresh 0 -)
g 8-fresh 1 -- --from "$DS@5" "${GENRUN[@]}"
expect "Seal with top dir 0:0: exit 1, base cannot be told" \
    bash -c "[[ $RC == 1 ]] && grep -q 'cannot be told' '$W/out/8-fresh.err'"
expect "no Seal view left behind" is "$(views)" 0
expect "still exactly one scratch: the lost node's" is "$(scratches)" 1

# ── Result ──────────────────────────────────────────────────────────

echo
if [[ $FAIL -eq 0 ]]; then
    echo "P4 GENESIS ($MODE) PASS: $PASS checks"
    exit 0
else
    echo "P4 GENESIS ($MODE) FAIL: $FAIL of $((PASS + FAIL)) checks failed; reports and stderr in $W/out"
    exit 1
fi
