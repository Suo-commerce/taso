#!/usr/bin/env bash
# Tests deploy/docker/compose.yaml as written: both images built by compose,
# taso-coordd serving the Warden over the shared socket, state kept across
# a second `up`, and a prompt stop.  Runs on a host with the ZFS pool,
# Docker and Docker Compose (D2 checks the Warden image itself:
# deploy/docker/test-in-image.sh).
#
#   TASO_ZFS_DATASET=tasotest/vessel deploy/docker/compose-test.sh
#
# Rows (each PASS or FAIL in the summary; the script goes on after a FAIL):
#   1. compose    Docker Compose >= 2.23.1 (inline configs) and the file
#                 validates
#   2. coordd     the coordd image builds, taso-coordd starts and its socket
#                 is there (healthy) before the Warden starts
#   3. birth      `up`: the Warden runs the Vessel through coordd's socket:
#                 Birth, its Seals published, agent ok, exit 0
#   4. persisted  a second `up` on the same volumes: the coordinator and the
#                 Warden's state survived; the Vessel is Opened (not born
#                 again) and runs ok
#   5. stop       `stop` of coordd takes < 5 s (it runs under an init)
#
# Environment: TASO_ZFS_DATASET (required)  OUT (/root/taso-compose-<time>)
set -uo pipefail

: "${TASO_ZFS_DATASET:?set TASO_ZFS_DATASET to a dataset this test may use, e.g. tasotest/vessel}"
OUT=${OUT:-/root/taso-compose-$(date +%Y%m%d-%H%M%S)}
cd "$(dirname "$0")/../.." || exit 2
ROOT=$PWD
mkdir -p "$OUT"
for t in docker zfs cargo ldd; do command -v "$t" >/dev/null || { echo "$t is missing" >&2; exit 2; }; done

declare -A RESULT
pass() { RESULT[$1]="PASS${2:+  ($2)}"; echo "== $1: PASS${2:+ ($2)}"; }
fail() { RESULT[$1]="FAIL  ($2)"; echo "== $1: FAIL ($2)"; }

POOL=${TASO_ZFS_DATASET%%/*}
export TASO_POOL_MOUNT; TASO_POOL_MOUNT=$(zfs get -H -o value mountpoint "$POOL")
export TASO_DATASET="$TASO_ZFS_DATASET/compose-$$"
export TASO_SUBJECT="compose-$$"
WORK=$(mktemp -d /var/tmp/taso-compose.XXXXXX)
chmod 755 "$WORK"
export TASO_ROOTFS=$WORK/rootfs
PROJECT="taso-ct-$$"
DC=(docker compose -p "$PROJECT" -f deploy/docker/compose.yaml)
cleanup() {
    "${DC[@]}" down -v --remove-orphans >/dev/null 2>&1
    zfs destroy -r "$TASO_DATASET" 2>/dev/null
    rm -rf "$WORK"
}
trap cleanup EXIT

# ── 1. compose ────────────────────────────────────────────────────────
v=$(docker compose version --short 2>/dev/null)
if [ -z "$v" ]; then
    fail compose "no docker compose: apt-get install -y docker-compose-v2"
    v=0
fi
if [ "$(printf '%s\n%s\n' 2.23.1 "${v#v}" | sort -V | head -1)" = 2.23.1 ] && [ "$v" != 0 ]; then
    if "${DC[@]}" config >"$OUT/config.yaml" 2>"$OUT/config.err"; then
        pass compose "Docker Compose $v; the file validates"
    else
        fail compose "the file does not validate: $(head -3 "$OUT/config.err" | tr '\n' ' ')"
    fi
elif [ "$v" != 0 ]; then
    fail compose "Docker Compose $v is older than 2.23.1 (inline configs)"
fi

# ── the agent rootfs (taso-sim and the Landlock shim) ─────────────────
echo "== building the agent (release)"
cargo build --release -q -p taso-sim -p taso-landlock || { echo "build failed" >&2; exit 2; }
copy_with_libs() { install -D -m 755 "$1" "$TASO_ROOTFS$2"; ldd "$1" | grep -o '/[^ ]*' | while read -r l; do install -D -m 755 "$l" "$TASO_ROOTFS$l"; done; }
copy_with_libs "$ROOT/target/release/taso-sim" /usr/bin/taso-sim
copy_with_libs "$ROOT/target/release/taso-landlock" /usr/lib/taso/landlock
mkdir -p "$TASO_ROOTFS"/{proc,dev,sys,tmp,work,run/taso}
: >"$TASO_ROOTFS/run/taso/field.sock"
zfs create "$TASO_DATASET"

# ── 2. coordd ─────────────────────────────────────────────────────────
echo "== building the images (compose build)"
if ! "${DC[@]}" build >"$OUT/build.log" 2>&1; then
    fail coordd "compose build failed: see $OUT/build.log"
fi
"${DC[@]}" up -d coordd >"$OUT/coordd-up.log" 2>&1
healthy() { [ "$(docker inspect -f '{{.State.Health.Status}}' "$("${DC[@]}" ps -q coordd)" 2>/dev/null)" = healthy ]; }
ok=""
for _ in $(seq 1 60); do healthy && { ok=1; break; }; sleep 0.5; done
"${DC[@]}" logs coordd >"$OUT/coordd.log" 2>&1
if [ -n "$ok" ] && grep -q "taso-coordd: serving /var/lib/taso/coord.redb on /run/taso/coord.sock" "$OUT/coordd.log"; then
    [ -z "${RESULT[coordd]:-}" ] && pass coordd "built; serving /var/lib/taso/coord.redb on /run/taso/coord.sock; healthy"
else
    fail coordd "not healthy in 30 s: $(tail -3 "$OUT/coordd.log" | tr '\n' ' ')"
fi

# ── 3. birth ──────────────────────────────────────────────────────────
OK_LINE=" 0 publish failures, [0-9]+ segments pruned, 0 prune failures, agent ok$"
run_up() {   # $1 = log name; the Warden's exit status
    "${DC[@]}" up --no-build --exit-code-from wardend wardend >"$OUT/$1.log" 2>&1
    local code=$?
    "${DC[@]}" logs --no-log-prefix wardend >"$OUT/$1-wardend.log" 2>&1
    return $code
}
run_up up-1; code=$?
line=$(grep -E "^$TASO_SUBJECT: " "$OUT/up-1-wardend.log" | tail -1)
if [ "$code" = 0 ] && echo "$line" | grep -qE "^$TASO_SUBJECT: Birth, .*$OK_LINE"; then
    pass birth "$line"
else
    fail birth "exit $code, '${line:-no report line}': see $OUT/up-1-wardend.log"
fi

# ── 4. persisted ──────────────────────────────────────────────────────
"${DC[@]}" up -d coordd >/dev/null 2>&1
run_up up-2; code=$?
line=$(grep -E "^$TASO_SUBJECT: " "$OUT/up-2-wardend.log" | tail -1)
if [ "$code" = 0 ] && echo "$line" | grep -qE "^$TASO_SUBJECT: Open, .*$OK_LINE"; then
    pass persisted "$line"
else
    fail persisted "exit $code, '${line:-no report line}': see $OUT/up-2-wardend.log"
fi

# ── 5. stop ───────────────────────────────────────────────────────────
"${DC[@]}" up -d coordd >/dev/null 2>&1
t0=$(date +%s%N)
"${DC[@]}" stop coordd >/dev/null 2>&1
ms=$(( ($(date +%s%N) - t0) / 1000000 ))
if [ "$ms" -lt 5000 ]; then
    pass stop "coordd stopped in $ms ms"
else
    fail stop "coordd took $ms ms to stop (no init?)"
fi

# ── summary ───────────────────────────────────────────────────────────
{
    echo
    echo "compose test ($(date -u +%FT%TZ), $(uname -r), Docker Compose ${v:-?})"
    for row in compose coordd birth persisted stop; do
        printf '  %-10s %s\n' "$row" "${RESULT[$row]:-not run}"
    done
    echo "results in $OUT"
} | tee "$OUT/summary.txt"
