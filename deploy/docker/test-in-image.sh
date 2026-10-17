#!/usr/bin/env bash
# D2 (plan: claude/Taso_plan_k8s_docker_2026-10-17.md §6): does Taso work
# *inside* the taso-wardend image?  Runs on a host with the ZFS pool, Docker
# and the image built (deploy/docker/Dockerfile, target wardend).
#
#   TASO_ZFS_DATASET=tasotest/vessel deploy/docker/test-in-image.sh
#
# Rows (each PASS or FAIL in the summary; the script goes on after a FAIL):
#   1. glibc      the host builds the test binaries; the image must run them
#                 (image glibc >= host glibc)
#   2. zfs        the image's ZFS userland and the host's kernel module report
#                 the same version
#   3. warden     taso-warden node tests in the image: snapshots, batched
#                 snapshots (zfs program), receive/clone, rollback, Chronicle
#                 and Vessel on ZFS, rebirth, runc isolation, sweep
#   4. landlock   taso-landlock under runc, in the image
#   5. daemon     the daemon end to end (taso-sim), in the image
#   6. mounts     a dataset the Warden mounts inside its container is visible
#                 on the host at the same path (rshared bind of the pool)
#   7. agents     killing the Warden container ends its agents (they live in
#                 its pid namespace): item B without systemd
#
# The node tests are the repository's own (`--ignored`), built on the host
# and run in the image with the repository mounted at the same path, so their
# compiled-in paths resolve.  Each works in its own child dataset of
# $TASO_ZFS_DATASET and destroys it.
#
# Environment: TASO_ZFS_DATASET (required)  IMAGE (taso-wardend)
#              OUT (/root/taso-d2-<time>)
set -uo pipefail

: "${TASO_ZFS_DATASET:?set TASO_ZFS_DATASET to a dataset these tests may use, e.g. tasotest/vessel}"
IMAGE=${IMAGE:-taso-wardend}
OUT=${OUT:-/root/taso-d2-$(date +%Y%m%d-%H%M%S)}
ROOT=$(git rev-parse --show-toplevel)
POOL=${TASO_ZFS_DATASET%%/*}
POOL_MOUNT=$(zfs get -H -o value mountpoint "$POOL")
mkdir -p "$OUT"
cd "$ROOT"

declare -A RESULT
pass() { RESULT[$1]="PASS${2:+  ($2)}"; echo "== $1: PASS${2:+ ($2)}"; }
fail() { RESULT[$1]="FAIL  ($2)"; echo "== $1: FAIL ($2)"; }

# A container like the Warden's: privileged, /dev/zfs, the pool's mountpoint
# bound rshared, the repository at its own path (read-only).
in_image() {
    docker run --rm --privileged --device /dev/zfs \
        --mount "type=bind,source=$POOL_MOUNT,target=$POOL_MOUNT,bind-propagation=rshared" \
        -v "$ROOT:$ROOT:ro" -e TASO_ZFS_DATASET -e RUST_BACKTRACE=1 \
        "$@"
}

echo "image $IMAGE, dataset $TASO_ZFS_DATASET (pool $POOL at $POOL_MOUNT), output $OUT"
docker image inspect "$IMAGE" >/dev/null || { echo "no image $IMAGE: build it first (deploy/docker/Dockerfile, target wardend)"; exit 2; }

# ── 1. glibc ──────────────────────────────────────────────────────────
host_glibc=$(ldd --version | head -1 | grep -o '[0-9]\+\.[0-9]\+$')
image_glibc=$(docker run --rm --entrypoint ldd "$IMAGE" --version | head -1 | grep -o '[0-9]\+\.[0-9]\+$')
if [ "$(printf '%s\n%s\n' "$host_glibc" "$image_glibc" | sort -V | head -1)" = "$host_glibc" ]; then
    pass glibc "host $host_glibc, image $image_glibc"
else
    fail glibc "host $host_glibc is newer than the image's $image_glibc: build the tests in the image instead"
fi

# ── 2. zfs userland vs module ─────────────────────────────────────────
in_image --entrypoint zfs "$IMAGE" version >"$OUT/zfs-version.txt" 2>&1
user=$(grep -o '^zfs-[0-9.]*' "$OUT/zfs-version.txt" | head -1 | sed 's/^zfs-//')
kmod=$(grep -o '^zfs-kmod-[0-9.]*' "$OUT/zfs-version.txt" | head -1 | sed 's/^zfs-kmod-//')
if [ -n "$user" ] && [ "$user" = "$kmod" ]; then
    pass zfs "userland $user = module $kmod"
else
    fail zfs "userland '${user:-?}', module '${kmod:-?}': see $OUT/zfs-version.txt"
fi

# ── test binaries (built on the host) ─────────────────────────────────
echo "building test binaries"
cargo build -q --bins -p taso-sim -p taso-landlock
exes() {   # $1 = package, $2 = target name
    cargo test -q -p "$1" --no-run --message-format=json 2>/dev/null \
        | python3 -c 'import json,sys
for l in sys.stdin:
    m = json.loads(l)
    if m.get("reason") == "compiler-artifact" and m.get("profile", {}).get("test") and m["target"]["name"] == sys.argv[1] and m.get("executable"):
        print(m["executable"])' "$2"
}
WARDEN=$(exes taso-warden taso_warden)
LANDLOCK=$(exes taso-landlock under_runc)
DAEMON=$(exes taso-sim daemon_on_node)

run_tests() {   # $1 = row, $2 = executable, rest = test filter args
    local row=$1 exe=$2; shift 2
    if [ -z "$exe" ]; then fail "$row" "test binary not found"; return; fi
    if in_image --entrypoint "$exe" "$IMAGE" --ignored --test-threads=1 --nocapture "$@" >"$OUT/$row.log" 2>&1; then
        pass "$row" "$(grep -o '[0-9]* passed' "$OUT/$row.log" | tail -1)"
    else
        fail "$row" "$(grep -E 'test result|panicked' "$OUT/$row.log" | tail -2 | tr '\n' ' ') see $OUT/$row.log"
    fi
}

# ── 3–5. node tests in the image ──────────────────────────────────────
# Left out: bench:: (timings belong on gate hardware, not in a function
# check) and s3:: (needs a running Garage; the store is not what D2 asks).
run_tests warden "$WARDEN" --skip bench:: --skip s3::
run_tests landlock "$LANDLOCK"
run_tests daemon "$DAEMON"

# ── 6–7. a Warden container, its mounts and its agents ────────────────
DS="$TASO_ZFS_DATASET/d2-$$"
NAME="taso-d2-$$"
WORK=$(mktemp -d)
cleanup() {
    docker rm -f "$NAME" >/dev/null 2>&1
    zfs destroy -r "$DS" 2>/dev/null
    rm -rf "$WORK"
}
trap cleanup EXIT

# An agent rootfs: taso-sim and the Landlock shim with their libraries.
R=$WORK/rootfs
cp_libs() { install -D -m 755 "$1" "$R$2"; ldd "$1" | grep -o '/[^ ]*' | while read -r l; do install -D -m 755 "$l" "$R$l"; done; }
cp_libs "$ROOT/target/debug/taso-sim" /usr/bin/taso-sim
cp_libs "$ROOT/target/debug/taso-landlock" /usr/lib/taso/landlock
mkdir -p "$R"/{proc,dev,sys,tmp,work,run/taso} && : >"$R/run/taso/field.sock"
chmod 755 "$WORK"

zfs create "$DS"
cat >"$WORK/wardend.json" <<EOF
{
  "warden": 1,
  "coordinator": { "local": "/var/lib/taso/coord.redb" },
  "root": "$DS",
  "state_dir": "/var/lib/taso/state",
  "store": "/var/lib/taso/store",
  "run_dir": "/run/taso",
  "runtime": {
    "rootfs": "/srv/taso/rootfs",
    "host_uid_base": 200000,
    "landlock_shim": "/usr/lib/taso/landlock",
    "args": ["/usr/bin/taso-sim", "--turns", "100000", "--turn-sleep-ms", "100", "--txns", "1", "--rows", "1"],
    "memory_bytes": 268435456,
    "pids": 64
  },
  "vessels": [ { "namespace": "0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d", "subject": "d2-$$", "uid_slot": 9 } ]
}
EOF
docker run -d --name "$NAME" --privileged --device /dev/zfs \
    --mount "type=bind,source=$POOL_MOUNT,target=$POOL_MOUNT,bind-propagation=rshared" \
    -v "$R:/srv/taso/rootfs:ro" -v "$WORK/wardend.json:/etc/taso/wardend.json:ro" \
    "$IMAGE" >/dev/null

# Wait for the agent: a taso-sim process on the host, inside the container's
# pid namespace (its parent chain leads to the container's init).
agent=""
for _ in $(seq 1 100); do
    agent=$(pgrep -f "^/usr/bin/taso-sim --turns 100000" | head -1)
    [ -n "$agent" ] && break
    sleep 0.2
done
docker logs "$NAME" >"$OUT/container.log" 2>&1

# 6. the Vessel's dataset, mounted by zfs inside the container, seen from the host
vds=$(zfs list -H -o name -r "$DS" | grep '/v-' | head -1)
mnt=${vds:+$(zfs get -H -o value mountpoint "$vds")}
if [ -z "$agent" ]; then
    fail mounts "the agent never started: see $OUT/container.log"
elif [ -n "$mnt" ] && findmnt -n "$mnt" >/dev/null && [ -n "$(ls -A "$mnt" 2>/dev/null)" ]; then
    pass mounts "$mnt is mounted on the host with the agent's files"
else
    fail mounts "dataset '${vds:-none}' at '${mnt:-?}' is not mounted on the host (or empty): mount propagation"
fi

# 7. kill the container like a crash; its agents must go with it
if [ -z "$agent" ]; then
    fail agents "the agent never started: see $OUT/container.log"
else
    docker kill "$NAME" >/dev/null
    left=""
    for _ in $(seq 1 50); do
        left=$(pgrep -f "^/usr/bin/taso-sim --turns 100000")
        [ -z "$left" ] && break
        sleep 0.1
    done
    if [ -z "$left" ]; then
        pass agents "agent pid $agent ended with the container"
    else
        fail agents "agent pids $left outlived the container"
        kill -9 $left 2>/dev/null
    fi
fi

# ── summary ───────────────────────────────────────────────────────────
{
    echo
    echo "D2: Taso inside $IMAGE ($(date -u +%FT%TZ), $(uname -r))"
    for row in glibc zfs warden landlock daemon mounts agents; do
        printf '  %-9s %s\n' "$row" "${RESULT[$row]:-not run}"
    done
} | tee "$OUT/summary.txt"
