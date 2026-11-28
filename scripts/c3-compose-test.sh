#!/usr/bin/env bash
# scripts/c3-compose-test.sh: C3-d, the containers tested on one host
# (deploy/docker/compose.yaml; the v0.1 plan of 2026-11-15).
#
#   sudo scripts/c3-compose-test.sh            from the repository root
#
# Builds the images, unpacks the demo agent, and runs the stack in
# deploy/docker on a fresh TASO_DATA (default /var/lib/taso-c3; an earlier
# run's is moved aside, never deleted).  Graded, in order:
#
#   1 born, seals, forks   `compose up`: the Warden ends with `demo` and
#                          `demo-fork-2` each "21 Seals published ... agent
#                          ok", and exits 0.  The devices taso-blkd makes
#                          after its start appear in the Warden's container
#                          (C3-a), or nothing would mount.
#   2 a clean stop         `compose stop`: taso-blkd logs "quit (SIGTERM)"
#                          (C3-h) and exits 0; no ublk device left on the
#                          host, nothing of ublk mounted.
#   3 the Seals intact     `compose up` again on the same TASO_DATA:
#                          taso-blkd starts "from the checkpoint"; once the
#                          Warden has ended, `taso-ctl explain` of both
#                          Vessels holds every check.  Then 2's checks.
#   4 the Warden killed    a long-running Vessel (TASO_WARDEN_CONFIG, C3-j);
#      and started again   once its agent runs, `docker kill` of the
#                          Warden's container: within 10 s no taso-sim is
#                          left on the host.  Then the Warden is started
#                          again, as Kubernetes restarts a container: it
#                          must reopen the long Vessel (its agent runs),
#                          and if a device was still held 3 s after the
#                          kill (the kill landed in a Seal's freeze) it
#                          must say it thawed what the dead one left
#                          frozen (C3-n).  Then 2's checks.
#   5 a killed taso-blkd   the long Vessel again; the Warden stopped (its
#                          devices stay attached, unmounted), then
#                          taso-blkd's container killed (SIGKILL: its
#                          devices stay in the kernel).  taso-blkd started
#                          again must log "removed N leftover devices"
#                          (N >= 1) and leave none (C3-m: its records on
#                          the host).  Then 2's checks.
#
# Devices on the host before the run (another taso-blkd's leftovers, from
# before this test) are listed in the summary and not counted: the checks
# grade what this run leaves.
#
# Recorded, not graded: the second run's Warden lines, image sizes.
# Exit 0 PASS, 1 FAIL, 2 HARNESS (a setup step failed: no grade).
#
# Refuses to start if /dev/ublk-control is missing, rcu_expedited is not 1
# (the host's job, C3-b: the README's two lines), a taso-blkd, taso-wardend
# or taso-sim already runs (stop the host's own taso-blkd.service first),
# or compose project "taso" has containers.  Touches: TASO_DATA (and its
# moved-aside predecessors), OUT, the images taso-{blkd,wardend}:dev and
# taso-agent-demo:c3, compose project "taso" (removed at the end with its
# volume).  Env: TASO_DATA, OUT (/root/c3-compose/<time>).

set -Eeuo pipefail

die() { printf 'REFUSED: %s\n' "$*" >&2; exit 2; }
say() { printf '== %s %s\n' "$(date +%H:%M:%S)" "$*" | tee -a "$OUT/summary.txt"; }

[[ $EUID -eq 0 ]] || die "run as root"
[[ -f deploy/docker/compose.yaml ]] || die "run from the repository root"
for t in docker python3 findmnt pgrep timeout; do command -v "$t" >/dev/null || die "$t is missing"; done
docker compose version >/dev/null 2>&1 || die "docker compose is missing"
[[ -c /dev/ublk-control ]] || die "/dev/ublk-control missing: the host loads ublk_drv (modprobe ublk_drv)"
[[ "$(cat /sys/kernel/rcu_expedited 2>/dev/null)" == 1 ]] || die "rcu_expedited is not 1: the host sets it (echo 1 > /sys/kernel/rcu_expedited)"
[[ -f /sys/fs/cgroup/cgroup.controllers ]] || die "cgroup v2 is needed"
if pgrep -a -x 'taso-blkd|taso-wardend|taso-sim'; then die "the above already run: not ours to share"; fi

export TASO_DATA=${TASO_DATA:-/var/lib/taso-c3}
unset TASO_WARDEN_CONFIG   # steps 1-3 run the demo, warden.json; step 4 sets it
COMPOSE=(docker compose -f deploy/docker/compose.yaml -p taso)
[[ -z "$("${COMPOSE[@]}" ps -a -q 2>/dev/null)" ]] || die "compose project \"taso\" has containers (docker compose -p taso ps -a)"
OUT=${OUT:-/root/c3-compose/$(date +%Y%m%d-%H%M%S)}
mkdir -p "$OUT"
: >"$OUT/summary.txt"
COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo '?')

VERDICT=0
grade() { # grade WHAT ok|fail [DETAIL]
    if [[ "$2" == ok ]]; then say "PASS  $1"; else say "FAIL  $1${3:+: $3}"; VERDICT=1; fi
}
harness() { say "HARNESS  $*"; save_logs harness; down_all; exit 2; }
# save_logs TAG: both containers' logs, before a teardown removes them.
save_logs() {
    "${COMPOSE[@]}" logs --no-color blkd >"$OUT/$1-blkd.log" 2>&1 || true
    "${COMPOSE[@]}" logs --no-color wardend >"$OUT/$1-wardend.log" 2>&1 || true
}
down_all() { "${COMPOSE[@]}" down -v >>"$OUT/compose.txt" 2>&1 || true; }

ublk_devices() { ls /dev/ublkb* /dev/ublkc* 2>/dev/null | sort || true; }

# leftovers TAG: no ublk device on the host but those before the run
# (BEFORE), nothing of ublk mounted.
leftovers() {
    local devs mnts
    devs=$(comm -13 <(printf '%s\n' "$BEFORE") <(ublk_devices) | grep . | tr '\n' ' ' || true)
    mnts=$(findmnt -rn -o SOURCE,TARGET | grep ublk || true)
    printf '%s\n%s\n' "devices: ${devs:-none}" "mounts: ${mnts:-none}" >"$OUT/$1-leftovers.txt"
    [[ -z "$devs" ]] && grade "$1: no ublk device left" ok || grade "$1: no ublk device left" fail "$devs"
    [[ -z "$mnts" ]] && grade "$1: nothing of ublk mounted" ok || grade "$1: nothing of ublk mounted" fail "$mnts"
}

# watch_devices TAG SECONDS: once a second, into TAG-devices.txt, each
# busy /dev/ublkb* (an exclusive open fails), every process whose mount
# namespace lists a ublk mount, every open descriptor that pins a mount
# namespace (a namespace with no process left in it stays alive through
# one), nsfs mounts on the host (the same, through a bind), and any
# taso-sim alive.  Ends when no device is busy (0) or after SECONDS (1).
watch_devices() {
    local f="$OUT/$1-devices.txt" i busy
    for i in $(seq "$2"); do
        busy=$(python3 -I - <<'PY'
import glob, os
for d in sorted(glob.glob("/dev/ublkb*")):
    try: os.close(os.open(d, os.O_RDONLY | os.O_EXCL))
    except OSError as e: print(os.path.basename(d), e.strerror)
PY
)
        {
            echo "--- +${i}s $(date +%T)"
            echo "${busy:-all free}"
            if [[ -n "$busy" ]]; then
                for m in $(grep -l ublkb /proc/[0-9]*/mountinfo 2>/dev/null); do
                    p=${m#/proc/}; p=${p%/mountinfo}
                    echo "  ublk mount in the namespace of: $p $(cat /proc/"$p"/comm 2>/dev/null) $(readlink /proc/"$p"/ns/mnt 2>/dev/null) ($(grep -o 'ublkb[0-9]*' "$m" 2>/dev/null | sort -u | tr '\n' ' '))"
                done | head -n 8
                for l in /proc/[0-9]*/fd/*; do
                    t=$(readlink "$l" 2>/dev/null) || continue
                    [[ "$t" == mnt:* ]] || continue
                    p=${l#/proc/}; p=${p%%/*}
                    echo "  a descriptor pins $t: $p $(cat /proc/"$p"/comm 2>/dev/null)"
                done | head -n 8
                findmnt -rn -t nsfs -o TARGET,SOURCE 2>/dev/null | sed 's/^/  nsfs mount: /' | head -n 8
                pgrep -a -x taso-sim | sed 's/^/  taso-sim alive: /' || true
            fi
        } >>"$f"
        [[ -z "$busy" ]] && { echo "$i" >"$f.free"; return 0; }
        sleep 1
    done
    return 1
}

# stop TAG: stop the stack (the Warden first, then taso-blkd by SIGTERM),
# keep both logs and taso-blkd's exit, grade the clean quit and the host.
stop() {
    local blkd rc
    blkd=$("${COMPOSE[@]}" ps -a -q blkd)
    "${COMPOSE[@]}" stop >>"$OUT/compose.txt" 2>&1
    "${COMPOSE[@]}" logs --no-color blkd >"$OUT/$1-blkd.log" 2>&1
    "${COMPOSE[@]}" logs --no-color wardend >"$OUT/$1-wardend.log" 2>&1
    rc=$(docker inspect -f '{{.State.ExitCode}}' "$blkd")
    grep -q 'taso-blkd: quit (SIGTERM)' "$OUT/$1-blkd.log" && [[ "$rc" == 0 ]] \
        && grade "$1: taso-blkd quit on SIGTERM, exit 0" ok \
        || grade "$1: taso-blkd quit on SIGTERM, exit 0" fail "exit $rc; $(tail -n 2 "$OUT/$1-blkd.log" | tr '\n' ' ')"
    "${COMPOSE[@]}" down >>"$OUT/compose.txt" 2>&1
    leftovers "$1"
}

# warden_ended TAG SECONDS: wait for the Warden's container to exit; its code.
warden_ended() {
    local id
    id=$("${COMPOSE[@]}" ps -a -q wardend)
    [[ -n "$id" ]] || harness "$1: no Warden container"
    timeout "$2" docker wait "$id" 2>/dev/null || echo timeout
}

say "C3-d at $COMMIT: TASO_DATA=$TASO_DATA, results in $OUT"
BEFORE=$(ublk_devices)
[[ -z "$BEFORE" ]] || say "ublk devices on the host before the run, not counted: $(echo $BEFORE)"

# ── setup ────────────────────────────────────────────────────────────
if [[ -e "$TASO_DATA" ]]; then mv "$TASO_DATA" "$TASO_DATA-$(date +%Y%m%d-%H%M%S)"; say "the earlier TASO_DATA moved aside"; fi
mkdir -p "$TASO_DATA/agent" "$TASO_DATA/blk" "$TASO_DATA/warden"
say "building the images (build log: $OUT/build.txt)"
"${COMPOSE[@]}" build >"$OUT/build.txt" 2>&1 || harness "compose build failed (tail $OUT/build.txt)"
docker build -f deploy/docker/Dockerfile --target agent-demo -t taso-agent-demo:c3 . >>"$OUT/build.txt" 2>&1 \
    || harness "the agent-demo image did not build"
docker rm -f taso-agent-demo-c3 >/dev/null 2>&1 || true
docker create --name taso-agent-demo-c3 taso-agent-demo:c3 >/dev/null || harness "docker create of the demo agent"
docker export taso-agent-demo-c3 | tar -x -C "$TASO_DATA/agent" || harness "unpacking the demo agent"
docker rm taso-agent-demo-c3 >/dev/null
docker images --format '{{.Repository}}:{{.Tag}} {{.Size}}' | grep -E '^taso-(blkd|wardend):dev|^taso-agent-demo:c3' >"$OUT/images.txt" || true

# ── 1 born, seals, forks ─────────────────────────────────────────────
say "1: compose up, the demo (20 turns, a fork, 20 turns)"
"${COMPOSE[@]}" up -d >>"$OUT/compose.txt" 2>&1 || harness "1: compose up failed"
rc=$(warden_ended 1 600)
"${COMPOSE[@]}" logs --no-color --no-log-prefix wardend >"$OUT/1-wardend.log" 2>&1
[[ "$rc" == 0 ]] && grade "1: the Warden ended, exit 0" ok || grade "1: the Warden ended, exit 0" fail "$rc"
for v in demo demo-fork-2; do
    line=$(grep -E "^$v: .* Seals published" "$OUT/1-wardend.log" | tail -n 1 || true)
    [[ "$line" =~ \ 21\ Seals\ published,\ 0\ publish\ failures.*agent\ ok$ ]] \
        && grade "1: $v, 21 Seals, agent ok" ok || grade "1: $v, 21 Seals, agent ok" fail "${line:-no line}"
done
declare -A ID
for v in demo demo-fork-2; do
    ds=$(grep -o "\] $v: dataset [^ ]*\$" "$OUT/1-wardend.log" | head -n 1 | sed 's/.*: dataset //' || true)
    ID[$v]=${ds##*/v-}
    [[ "${ID[$v]}" =~ ^[0-9a-f]{32}$ ]] || { ID[$v]=; say "1: no dataset line for $v in the Warden's log (step 3 cannot explain it)"; }
done
stop 2

# ── 3 the Seals intact ───────────────────────────────────────────────
say "3: compose up again on the same TASO_DATA"
"${COMPOSE[@]}" up -d >>"$OUT/compose.txt" 2>&1 || harness "3: compose up failed"
rc=$(warden_ended 3 600)
"${COMPOSE[@]}" logs --no-color --no-log-prefix blkd >"$OUT/3-blkd-start.log" 2>&1
grep -q 'recovered .*from the checkpoint at record' "$OUT/3-blkd-start.log" \
    && grade "3: taso-blkd started from the checkpoint" ok \
    || grade "3: taso-blkd started from the checkpoint" fail "$(grep 'recovered' "$OUT/3-blkd-start.log" || echo 'no recovered line')"
say "3: the second run's Warden ended: $rc (recorded)"
# explain opens the Warden's local coordinator, which a running Warden holds.
[[ "$rc" == timeout ]] && "${COMPOSE[@]}" stop wardend >>"$OUT/compose.txt" 2>&1
for v in demo demo-fork-2; do
    [[ -n "${ID[$v]}" ]] || { grade "3: explain $v, every check holds" fail "no id (step 1)"; continue; }
    xrc=0
    "${COMPOSE[@]}" run --rm --no-deps -T --entrypoint taso-ctl wardend \
        /etc/taso/wardend.json explain "${ID[$v]}" >"$OUT/3-explain-$v.json" 2>"$OUT/3-explain-$v.err" || xrc=$?
    failed=$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1])).get("checks",{}).get("failed","?"))' \
        "$OUT/3-explain-$v.json" 2>/dev/null || echo '?')
    [[ "$xrc" == 0 && "$failed" == "[]" ]] && grade "3: explain $v, every check holds" ok \
        || grade "3: explain $v, every check holds" fail "exit $xrc, failed $failed"
done
stop 3

# ── 4 the Warden killed ──────────────────────────────────────────────
say "4: a long-running Vessel, then docker kill of the Warden's container"
python3 -I - deploy/docker/warden.json "$OUT/long.json" <<'PY'
import json, sys
c = json.load(open(sys.argv[1]))
c["vessels"] = [{"namespace": "c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3", "subject": "c3-long", "uid_slot": 3,
                 "runtime": {"args": ["/usr/bin/taso-sim", "--turns", "100000", "--txns", "4", "--rows", "8",
                                      "--row-bytes", "256", "--synchronous", "normal"]}}]
json.dump(c, open(sys.argv[2], "w"), indent=1)
PY
export TASO_WARDEN_CONFIG=$OUT/long.json
"${COMPOSE[@]}" up -d >>"$OUT/compose.txt" 2>&1 || harness "4: compose up failed"
for _ in $(seq 120); do pgrep -x taso-sim >/dev/null && break; sleep 1; done
pgrep -x taso-sim >/dev/null || harness "4: the long Vessel's agent never ran (see compose logs wardend)"
sleep 5
before=$(pgrep -c -x taso-sim || true)
docker kill "$("${COMPOSE[@]}" ps -q wardend)" >>"$OUT/compose.txt" 2>&1 || harness "4: docker kill failed"
for _ in $(seq 10); do pgrep -x taso-sim >/dev/null || break; sleep 1; done
left=$(pgrep -a -x taso-sim || true)
[[ -z "$left" ]] && grade "4: the killed Warden's agents ended within 10 s ($before running before)" ok \
    || grade "4: the killed Warden's agents ended within 10 s" fail "$left"
# A device still held 3 s after the kill is a file system the dead Warden
# left frozen (the kill landed in a Seal's freeze): teardown alone takes
# under a second.  Recorded before the restart, which mounts it.
watch_devices 4 3 || true
held=yes
[[ -f "$OUT/4-devices.txt.free" ]] && held=no
say "4: a dead Warden's device still held 3 s after the kill: $held (4-devices.txt)"
"${COMPOSE[@]}" up -d wardend >>"$OUT/compose.txt" 2>&1 || harness "4: the Warden did not start again"
sleep 2
for _ in $(seq 120); do pgrep -x taso-sim >/dev/null && break; sleep 1; done
"${COMPOSE[@]}" logs --no-color --no-log-prefix wardend >"$OUT/4-wardend-again.log" 2>&1
pgrep -x taso-sim >/dev/null && grade "4: the Warden started again reopened the long Vessel" ok \
    || grade "4: the Warden started again reopened the long Vessel" fail "$(tail -n 3 "$OUT/4-wardend-again.log" | tr '\n' ' ')"
released=$(grep -c 'left frozen by a dead incarnation' "$OUT/4-wardend-again.log" || true)
if [[ "$held" == yes ]]; then
    [[ "$released" -ge 1 ]] && grade "4: it thawed what the dead Warden left frozen ($released)" ok \
        || grade "4: it thawed what the dead Warden left frozen" fail "a device was held, no release logged"
else
    say "4: no device held at the restart (the kill missed a freeze); released $released (recorded)"
fi

# ── 5 a killed taso-blkd ────────────────────────────────────────────
say "5: the long Vessel again; the Warden stopped, then taso-blkd killed"
"${COMPOSE[@]}" up -d >>"$OUT/compose.txt" 2>&1 || harness "5: compose up failed"
for _ in $(seq 120); do pgrep -x taso-sim >/dev/null && break; sleep 1; done
pgrep -x taso-sim >/dev/null || harness "5: the long Vessel's agent never ran"
sleep 3
# Stopped, not killed: step 4 tests the kill; here the devices are to stay
# attached and free, whatever moment the stop lands on.
"${COMPOSE[@]}" stop wardend >>"$OUT/compose.txt" 2>&1 || harness "5: stopping the Warden failed"
# Its devices free (no opener) before taso-blkd dies: a device still
# mounted when its server dies would wait in the kernel's delete.
say "5: the Warden stopped at $(date +%T); waiting for its devices (up to 60 s, $OUT/5-devices.txt)"
watch_devices 5 60 || harness "5: the stopped Warden's devices stayed busy for 60 s (see 5-devices.txt)"
say "5: its devices free after $(cat "$OUT/5-devices.txt.free") s"
made=$(comm -13 <(printf '%s\n' "$BEFORE") <(ublk_devices) | grep -c ublkc || true)
[[ "$made" -ge 1 ]] || harness "5: the stopped Warden left no device attached: nothing for a killed taso-blkd to leave"
docker kill "$("${COMPOSE[@]}" ps -q blkd)" >>"$OUT/compose.txt" 2>&1 || harness "5: docker kill of taso-blkd failed"
sleep 1
"${COMPOSE[@]}" logs --no-color blkd >"$OUT/5-blkd-killed.log" 2>&1
say "5: taso-blkd killed with $made device(s) of this run in the kernel"
"${COMPOSE[@]}" rm -f blkd >>"$OUT/compose.txt" 2>&1
"${COMPOSE[@]}" up -d blkd >>"$OUT/compose.txt" 2>&1 || harness "5: taso-blkd did not start again"
for _ in $(seq 60); do "${COMPOSE[@]}" logs --no-color blkd 2>/dev/null | grep -q 'taso-blkd: serving' && break; sleep 1; done
"${COMPOSE[@]}" logs --no-color blkd >"$OUT/5-blkd-again.log" 2>&1
n=$(grep -o 'removed [0-9]* leftover devices' "$OUT/5-blkd-again.log" | grep -o '[0-9]*' | head -n 1 || true)
[[ "${n:-0}" -ge 1 ]] && grade "5: taso-blkd started again removed the killed one's devices ($n)" ok \
    || grade "5: taso-blkd started again removed the killed one's devices" fail "$(grep -E 'removed|reload|leftover' "$OUT/5-blkd-again.log" | head -n 3 | tr '\n' ' ')"
stop 5

down_all
total=$([[ $VERDICT == 0 ]] && echo PASS || echo FAIL)
say "C3-d $total at $COMMIT (results in $OUT)"
exit "$VERDICT"
