#!/usr/bin/env bash
# K2 end to end (design: claude/Taso_design_k2_2026-10-17.md, file 7):
# taso-wardend runs Vessels from a real Kubernetes API server on real ZFS
# and runc, and writes their status back.
#
# The API server is envtest's (etcd + kube-apiserver, Kubernetes 1.35, on
# 127.0.0.1, token auth): a real API server with the real CRD validation,
# field selectors and status subresource, without a cluster.  The Warden
# runs on this host, as the DaemonSet pod would on a node.
#
# Rows (each PASS or FAIL in the summary; the script goes on after a FAIL):
#   1. crd        the Vessel CRD applies; a resource changing its uidSlot is
#                 refused by the API server (CEL)
#   2. running    the good Vessels (two namespaces) reach Running, their
#                 agents run and seal turns (snapshots on their datasets)
#   3. refused    D1 (tenant of another namespace, an unmapped namespace),
#                 D2 (rootfs through a symlink out of rootfs_dir), D3 (a
#                 takeover for a Vessel nobody holds: the source passes it
#                 on, the daemon refuses it, 2026-10-21), limits, Landlock
#                 off, a uid slot already bound: each Refused with its
#                 reason; nothing runs for them
#   4. elsewhere  a Vessel of another node: no status, nothing runs
#   5. deleted    a deleted Vessel's agent is stopped and not started again;
#                 the others run on
#   6. kept       a running Vessel edited past a limit runs on, with the
#                 same agent process, and its status says why
#   6b. fork      a Vessel with spec.fork {parent: runner} reaches Running
#                 with its own agent, its dataset a clone of one of
#                 runner's Seal snapshots; the API server fixes fork once
#                 set (a change and a late add are refused by CEL)
#   6c. forks     (P3 file 11) a Vessel with spec.forks {slots: [7, 8]}
#                 whose agent asks for 3 forks over the Field: the Warden
#                 makes asker-fork-7 and -8 (clones of one of its Seal
#                 snapshots) and runs each to the end; their agents' own
#                 asks are refused ("may not fork"), the parent's third and
#                 every later one too ("no fork slot left"); a newcomer
#                 asking for slot 8 is Refused (the guard binds a fork slot
#                 to its child); a fork slot equal to the Vessel's own
#                 uidSlot is refused by the API server (CEL)
#   7. sigterm    SIGTERM: the Warden stops every agent and exits 0; the last
#                 status of each says it was stopped
#   8. slots      a new Warden keeps every uid slot with the Vessel whose
#                 files its range owns: runner runs again on slot 1, the
#                 newcomer asking for it stays refused (the guard is seeded
#                 from the pool; before, the smaller Vessel id won)
#   9. resumed    that new Warden opens the Vessels again (Open, no second
#                 birth Seal): the state is rolled back to a Seal past the
#                 birth Seal and the agent runs again
#
# Usage (root, on a node with runc, ZFS and cargo; downloads envtest once):
#   TASO_ZFS_DATASET=tasotest/vessel scripts/k2-e2e.sh
#
# Environment: TASO_ZFS_DATASET (required)  OUT (/root/taso-k2-e2e-<time>)
#              ENVTEST_DIR (/root/.cache/taso-envtest)  KEEP (0)
set -uo pipefail

: "${TASO_ZFS_DATASET:?set TASO_ZFS_DATASET to a dataset this test may use, e.g. tasotest/vessel}"
OUT=${OUT:-/root/taso-k2-e2e-$(date +%Y%m%d-%H%M%S)}
ENVTEST_DIR=${ENVTEST_DIR:-/root/.cache/taso-envtest}
ENVTEST_VERSION=v1.35.0
KEEP=${KEEP:-0}
PORT=16443
NODE=e2e-node
TA=0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e   # tenant of team-a
TB=0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f   # tenant of team-b

[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 2; }
for t in zfs runc cargo curl openssl python3 ldd pgrep; do
    command -v "$t" >/dev/null || { echo "$t is missing" >&2; exit 2; }
done
cd "$(dirname "$0")/.." || exit 2
ROOT=$PWD
mkdir -p "$OUT"

declare -A RESULT
pass() { RESULT[$1]="PASS${2:+  ($2)}"; echo "== $1: PASS${2:+ ($2)}"; }
fail() { RESULT[$1]="FAIL  ($2)"; echo "== $1: FAIL ($2)"; }
# wait_for <seconds> <command...>: until the command succeeds.
wait_for() {
    local end=$((SECONDS + $1)); shift
    until "$@" >/dev/null 2>&1; do
        [ "$SECONDS" -ge "$end" ] && return 1
        sleep 0.5
    done
}

# ── envtest: etcd + kube-apiserver ────────────────────────────────────
B=$ENVTEST_DIR/controller-tools/envtest
if [ ! -x "$B/kube-apiserver" ]; then
    echo "== downloading envtest $ENVTEST_VERSION"
    mkdir -p "$ENVTEST_DIR"
    curl -fsSL -o "$ENVTEST_DIR/envtest.tgz" \
        "https://github.com/kubernetes-sigs/controller-tools/releases/download/envtest-$ENVTEST_VERSION/envtest-$ENVTEST_VERSION-linux-amd64.tar.gz" \
        && tar -C "$ENVTEST_DIR" -xzf "$ENVTEST_DIR/envtest.tgz" \
        || { echo "envtest download failed" >&2; exit 2; }
fi

WORK=$(mktemp -d /var/tmp/taso-k2e2e.XXXXXX)
chmod 755 "$WORK"
API=$WORK/api
mkdir -p "$API/certs"
BASE="$TASO_ZFS_DATASET/k2e2e-$$"
ETCD_PID="" APISERVER_PID="" WARDEN_PID=""
cleanup() {
    [ -n "$WARDEN_PID" ] && kill -KILL "$WARDEN_PID" 2>/dev/null
    for c in $(runc --root "$WORK/run/runc" list -q 2>/dev/null); do runc --root "$WORK/run/runc" delete --force "$c" 2>/dev/null; done
    [ -n "$APISERVER_PID" ] && kill "$APISERVER_PID" 2>/dev/null
    [ -n "$ETCD_PID" ] && kill "$ETCD_PID" 2>/dev/null
    wait 2>/dev/null
    if [ "$KEEP" = 1 ]; then
        echo "kept: dataset $BASE, work dir $WORK"
    else
        zfs destroy -r "$BASE" 2>/dev/null
        rm -rf "$WORK"
    fi
}
trap cleanup EXIT

openssl genrsa -out "$API/sa.key" 2048 2>/dev/null
openssl rsa -in "$API/sa.key" -pubout -out "$API/sa.pub" 2>/dev/null
TOKEN=$(openssl rand -hex 24)
echo "$TOKEN,admin,1,system:masters" > "$API/tokens.csv"
printf %s "$TOKEN" > "$API/token"
chmod 600 "$API/token" "$API/tokens.csv"
"$B/etcd" --data-dir "$API/etcd" --listen-client-urls http://127.0.0.1:12379 --advertise-client-urls http://127.0.0.1:12379 \
    --listen-peer-urls http://127.0.0.1:12380 >"$OUT/etcd.log" 2>&1 &
ETCD_PID=$!
sleep 2
"$B/kube-apiserver" --etcd-servers=http://127.0.0.1:12379 --cert-dir="$API/certs" --secure-port=$PORT --bind-address=127.0.0.1 \
    --service-account-issuer=https://taso.local --service-account-key-file="$API/sa.pub" --service-account-signing-key-file="$API/sa.key" \
    --token-auth-file="$API/tokens.csv" --authorization-mode=RBAC --service-cluster-ip-range=10.96.0.0/16 >"$OUT/apiserver.log" 2>&1 &
APISERVER_PID=$!
CA=$API/certs/apiserver.crt
K() { "$B/kubectl" --server=https://127.0.0.1:$PORT --token="$TOKEN" --certificate-authority="$CA" "$@"; }
wait_for 60 K get --raw /readyz || { echo "the API server did not come up: see $OUT/apiserver.log" >&2; exit 2; }
echo "== API server ready (envtest $ENVTEST_VERSION)"

# ── 1. the CRD ────────────────────────────────────────────────────────
K apply -f deploy/k8s/vessel-crd.yaml >"$OUT/crd.log" 2>&1
wait_for 30 K get vessels -A
for ns in team-a team-b team-c; do K create namespace "$ns" >/dev/null; done

# ── binaries and the agent's rootfs ───────────────────────────────────
echo "== building (release)"
cargo build --release -q -p taso-warden -p taso-sim -p taso-landlock || { echo "build failed" >&2; exit 2; }
BIN=$ROOT/target/release
RD=$WORK/rootfs                      # the node's rootfs_dir
R=$RD/sim                            # the agent image
copy_with_libs() { install -D -m 755 "$1" "$R$2"; ldd "$1" | grep -o '/[^ ]*' | while read -r l; do install -D -m 755 "$l" "$R$l"; done; }
copy_with_libs "$BIN/taso-sim" /usr/bin/taso-sim
copy_with_libs "$BIN/taso-landlock" /usr/lib/taso/landlock
mkdir -p "$R"/{proc,dev,sys,tmp,work,run/taso}
: >"$R/run/taso/field.sock"
mkdir -p "$WORK/outside"
ln -s "$WORK/outside" "$RD/escape"    # D2: a symlink out of rootfs_dir

# vessel <ns> <name> <tenant> <slot> <sleep-ms> [extra spec yaml...]
# Each agent sleeps a different number of ms per turn, so its process is
# found by its command line.
vessel() {
    local ns=$1 name=$2 tenant=$3 slot=$4 ms=$5; shift 5
    # Set here, not as a default inside the heredoc: there its quotes are
    # removed and the args become YAML integers (refused by the CRD).
    local args=${ARGS_OF:-}
    [ -n "$args" ] || args='[/usr/bin/taso-sim, --turns, "1000000", --turn-sleep-ms, "'"$ms"'", --txns, "1", --rows, "1"]'
    cat <<EOF
apiVersion: taso.suocommerce.com/v1alpha1
kind: Vessel
metadata: { namespace: $ns, name: $name }
spec:
  tenant: "$tenant"
  subject: $name
  uidSlot: $slot
  node: ${NODE_OF:-$NODE}
  rootfs: { path: ${ROOTFS_OF:-$R} }
  args: $args
EOF
    for extra in "$@"; do echo "  $extra"; done
}
agent() { pgrep -f "^/usr/bin/taso-sim --turns 1000000 --turn-sleep-ms $1 "; }
phase() { K get vessel -n "$1" "$2" -o jsonpath='{.status.phase}'; }
message() { K get vessel -n "$1" "$2" -o jsonpath='{.status.message}'; }
is_phase() { [ "$(phase "$1" "$2")" = "$3" ]; }

{
    vessel team-a runner  $TA 1 101; echo ---
    vessel team-b runner-b $TB 2 102; echo ---
    vessel team-a doomed  $TA 3 103; echo ---
    vessel team-a editme  $TA 4 104; echo ---
    # Refused:
    vessel team-a wrong-tenant $TB 10 110; echo ---
    vessel team-c unmapped     $TA 11 111; echo ---
    vessel team-a takeover     $TA 12 112 "takeover: { holder: 9, epoch: 3 }"; echo ---
    ROOTFS_OF=$RD/escape vessel team-a escape $TA 13 113; echo ---
    vessel team-a bigmem       $TA 14 114 "resources: { memory: 8Gi }"; echo ---
    vessel team-a no-landlock  $TA 15 115 "landlock: false"; echo ---
    NODE_OF=other-node vessel team-a elsewhere $TA 17 117
} >"$WORK/vessels.yaml"
K apply -f "$WORK/vessels.yaml" >"$OUT/vessels.log" 2>&1

# The API server's own fence: uidSlot is fixed once set.
if K patch vessel -n team-a runner --type merge -p '{"spec":{"uidSlot":5}}' >"$OUT/crd-immutable.log" 2>&1; then
    fail crd "a uidSlot change was accepted by the API server"
elif grep -q "uidSlot is fixed once set" "$OUT/crd-immutable.log"; then
    pass crd "applied; a uidSlot change is refused by CEL"
else
    fail crd "a uidSlot change failed for another reason: see $OUT/crd-immutable.log"
fi

# ── the Warden ────────────────────────────────────────────────────────
zfs create "$BASE"
CONFIG=$WORK/wardend.json
cat >"$CONFIG" <<EOF
{
  "warden": 1,
  "coordinator": { "local": "$WORK/coord.redb" },
  "storage": "zfs",
  "root": "$BASE",
  "state_dir": "$WORK/state",
  "store": "$WORK/store",
  "run_dir": "$WORK/run",
  "runtime": {
    "host_uid_base": 200000,
    "landlock_shim": "/usr/lib/taso/landlock",
    "memory_bytes": 268435456
  },
  "source": { "kubernetes": {
    "node": "$NODE",
    "tenants": { "team-a": "$TA", "team-b": "$TB" },
    "rootfs_dir": "$RD",
    "max_memory_bytes": 1073741824,
    "max_pids": 256,
    "api": { "url": "https://127.0.0.1:$PORT", "token_file": "$API/token", "ca_file": "$CA" }
  } }
}
EOF
start_warden() {   # $1 = log name
    "$BIN/taso-wardend" "$CONFIG" >"$OUT/$1.log" 2>&1 &
    WARDEN_PID=$!
}
start_warden warden-1

# ── 2. running ────────────────────────────────────────────────────────
good=(team-a/runner team-b/runner-b team-a/doomed team-a/editme)
running_ok=1
for v in "${good[@]}"; do
    wait_for 60 is_phase "${v%/*}" "${v#*/}" Running || { running_ok=0; fail running "$v is $(phase "${v%/*}" "${v#*/}"): $(message "${v%/*}" "${v#*/}")"; break; }
done
if [ "$running_ok" = 1 ]; then
    for ms in 101 102 103 104; do
        wait_for 30 agent $ms || { running_ok=0; fail running "no agent process for turn sleep $ms ms"; break; }
    done
fi
if [ "$running_ok" = 1 ]; then
    # Each good Vessel has its own dataset, and its agent seals turns there.
    sealed() { [ "$(zfs list -H -t snapshot -o name -r "$BASE" | grep -c '@taso-seal-')" -ge $((4 * 4)) ]; }
    if wait_for 60 sealed; then
        n=$(zfs list -H -o name -r "$BASE" | grep -c '/v-')
        holder=$(K get vessel -n team-a runner -o jsonpath='{.status.holder}')
        if [ "$n" = 4 ] && [ "$holder" = 1 ]; then
            pass running "4 Vessels in 2 namespaces Running (holder 1), 4 datasets, sealing turns"
        else
            fail running "$n Vessel datasets (want 4), holder '$holder' (want 1)"
        fi
    else
        fail running "the agents did not seal 3 turns each: $(zfs list -H -t snapshot -o name -r "$BASE" | grep -c '@taso-seal-') Seal snapshots"
    fi
fi

# ── 3. refused ────────────────────────────────────────────────────────
# A newcomer on runner's uid slot, once runner holds it (created together,
# the guard would give the slot to the smaller Vessel id, either of them).
vessel team-b clash $TB 1 116 | K apply -f - >>"$OUT/vessels.log" 2>&1
refused_ok=1
check_refused() {   # ns name reason-part sleep-ms
    # One kubectl call reads phase and message so a daemon-level restart
    # (Restart::Always) cannot flip the status between two reads.
    is_refused_with() {
        local pm; pm=$(K get vessel -n "$1" "$2" -o 'jsonpath={.status.phase} {.status.message}' 2>/dev/null) || return 1
        [[ "$pm" == "Refused "* ]] && [[ "$pm" == *"$3"* ]]
    }
    if ! wait_for 20 is_refused_with "$1" "$2" "$3"; then
        refused_ok=0; fail refused "$1/$2 is '$(phase "$1" "$2")': $(message "$1" "$2")"; return
    fi
    if agent "$4" >/dev/null; then refused_ok=0; fail refused "$1/$2 is refused but its agent runs"; fi
}
check_refused team-a wrong-tenant 'not the tenant of namespace "team-a"' 110
[ "$refused_ok" = 1 ] && check_refused team-c unmapped 'not mapped to a tenant' 111
# D3: the reason is the daemon's, so the source passed the takeover on.
[ "$refused_ok" = 1 ] && check_refused team-a takeover 'nobody holds the Vessel' 112
[ "$refused_ok" = 1 ] && check_refused team-a escape 'not inside this node' 113
[ "$refused_ok" = 1 ] && check_refused team-a bigmem 'this node allows 1 to 1073741824' 114
[ "$refused_ok" = 1 ] && check_refused team-a no-landlock 'does not allow agents without Landlock' 115
[ "$refused_ok" = 1 ] && check_refused team-b clash 'uid_slot 1 is bound to another Vessel' 116
[ "$refused_ok" = 1 ] && pass refused "D1 x2, D2 symlink escape, D3 takeover of an unheld Vessel (by the daemon), memory, Landlock off, a bound uid slot: each Refused with its reason, none ran"
[ -n "$(ls -A "$WORK/outside")" ] && fail refused "something was written through the escaping symlink"

# ── 4. elsewhere ──────────────────────────────────────────────────────
if [ -z "$(K get vessel -n team-a elsewhere -o jsonpath='{.status}')" ] && ! agent 117 >/dev/null; then
    pass elsewhere "another node's Vessel: no status, no agent"
else
    fail elsewhere "status '$(K get vessel -n team-a elsewhere -o jsonpath='{.status}')', agent $(agent 117 || echo none)"
fi

# ── 5. deleted ────────────────────────────────────────────────────────
if agent 103 >/dev/null; then
    K delete vessel -n team-a doomed >/dev/null
    gone() { ! agent 103; }
    if wait_for 20 gone; then
        sleep 6   # past the first restart backoffs
        if agent 103 >/dev/null; then
            fail deleted "the deleted Vessel's agent was started again"
        elif agent 101 >/dev/null && agent 102 >/dev/null && agent 104 >/dev/null; then
            pass deleted "its agent stopped and stayed stopped; the other three run on"
        else
            fail deleted "another agent stopped with it"
        fi
    else
        fail deleted "the deleted Vessel's agent still runs after 20 s"
    fi
else
    fail deleted "the Vessel to delete was not running"
fi

# ── 6. kept ───────────────────────────────────────────────────────────
before=$(agent 104 | head -1)
if [ -n "$before" ]; then
    K patch vessel -n team-a editme --type merge -p '{"spec":{"resources":{"pids":9999}}}' >/dev/null
    says_kept() { case "$(message team-a editme)" in *"running its last good spec"*"at most 256"*) return 0 ;; *) return 1 ;; esac; }
    if wait_for 20 says_kept; then
        sleep 3
        after=$(agent 104 | head -1)
        if [ "$after" = "$before" ] && is_phase team-a editme Running; then
            pass kept "refused edit: same agent process ($before), Running, status says why"
        else
            fail kept "agent $before -> ${after:-none}, phase $(phase team-a editme)"
        fi
    else
        fail kept "status message: $(message team-a editme)"
    fi
else
    fail kept "the Vessel to edit was not running"
fi

# ── 6b. fork ──────────────────────────────────────────────────────────
vessel team-a runner-fork $TA 5 105 "fork: { parent: runner, seal: last }" | K apply -f - >>"$OUT/vessels.log" 2>&1
if wait_for 60 is_phase team-a runner-fork Running && wait_for 30 agent 105; then
    ds_of() { grep -o "\] $1: dataset [^ ]*\$" "$OUT/warden-1.log" | head -1 | sed 's/.*: dataset //'; }
    pds=$(ds_of runner); cds=$(ds_of runner-fork)
    origin=$(zfs get -H -o value origin "$cds" 2>/dev/null)
    changed=0; added=0
    K patch vessel -n team-a runner-fork --type merge -p '{"spec":{"fork":{"parent":"editme"}}}' >"$OUT/crd-fork-change.log" 2>&1 && changed=1
    K patch vessel -n team-a editme --type merge -p '{"spec":{"fork":{"parent":"runner"}}}' >"$OUT/crd-fork-add.log" 2>&1 && added=1
    if [ -n "$pds" ] && [[ "$origin" == "$pds@taso-seal-"* ]] && [ "$changed" = 0 ] && [ "$added" = 0 ] \
        && grep -q "fork is fixed once set" "$OUT/crd-fork-change.log" && grep -q "fork is fixed once set" "$OUT/crd-fork-add.log"; then
        pass fork "runner-fork Running, its dataset a clone of ${origin#"$BASE"/}; fork fixed once set (a change and a late add refused)"
    else
        fail fork "origin '$origin' (runner's dataset '$pds'); change accepted=$changed, late add accepted=$added; see $OUT/crd-fork-*.log"
    fi
else
    fail fork "runner-fork is $(phase team-a runner-fork): $(message team-a runner-fork)"
fi

# ── 6c. forks asked for over the Field ────────────────────────────────
# Two turns, then three asks; restarted (always), each later run asks again.
ARGS_OF='[/usr/bin/taso-sim, --turns, "2", --turn-sleep-ms, "106", --txns, "1", --rows, "1", --forks, "3"]' \
    vessel team-a asker $TA 6 106 "forks: { slots: [7, 8] }" | K apply -f - >>"$OUT/vessels.log" 2>&1
forked() { grep -q "\] asker: forked \"asker-fork-$1\" (uid slot $1) at Seal lsn [0-9]* on its agent's request" "$OUT/warden-1.log"; }
child_done() { grep -q "\] asker-fork-$1: agent exited ok" "$OUT/warden-1.log"; }
mount_of() { zfs get -H -o value mountpoint "$1"; }
if wait_for 60 forked 7 && wait_for 30 forked 8 && wait_for 60 child_done 7 && wait_for 60 child_done 8; then
    ds_of() { grep -o "\] $1: dataset [^ ]*\$" "$OUT/warden-1.log" | head -1 | sed 's/.*: dataset //'; }
    pds=$(ds_of asker); why=""
    for slot in 7 8; do
        cds=$(ds_of "asker-fork-$slot")
        origin=$(zfs get -H -o value origin "$cds" 2>/dev/null)
        [[ "$origin" == "$pds@taso-seal-"* ]] || why="$why; asker-fork-$slot's origin '$origin'"
        python3 - "$(mount_of "$cds")/sim-stats.json" >/dev/null 2>&1 <<'PY' || why="$why; asker-fork-$slot's own asks were not all refused (may not fork)"
import json, sys
f = json.load(open(sys.argv[1]))["forks"]
sys.exit(0 if len(f) == 3 and all("may not fork" in x.get("refused", "") for x in f) else 1)
PY
    done
    # A later run of the parent: every ask refused, the quota is spent.
    spent() { python3 - "$(mount_of "$pds")/sim-stats.json" <<'PY'
import json, sys
try: f = json.load(open(sys.argv[1]))["forks"]
except (OSError, ValueError, KeyError): sys.exit(1)
sys.exit(0 if len(f) == 3 and all("no fork slot left" in x.get("refused", "") for x in f) else 1)
PY
    }
    wait_for 30 spent || why="$why; no later run of asker saw 'no fork slot left'"
    vessel team-b squatter $TB 8 118 | K apply -f - >>"$OUT/vessels.log" 2>&1
    squatted() { local pm; pm=$(K get vessel -n team-b squatter -o 'jsonpath={.status.phase} {.status.message}' 2>/dev/null) || return 1; [[ "$pm" == "Refused "*"uid_slot 8 is bound to another Vessel"* ]]; }
    wait_for 20 squatted || why="$why; squatter is '$(phase team-b squatter)': $(message team-b squatter)"
    agent 118 >/dev/null && why="$why; squatter's agent runs"
    if K patch vessel -n team-a asker --type merge -p '{"spec":{"forks":{"slots":[6]}}}' >"$OUT/crd-forks-own.log" 2>&1; then
        why="$why; a fork slot equal to uidSlot was accepted"
    elif ! grep -q "a fork slot cannot be the Vessel's own uidSlot" "$OUT/crd-forks-own.log"; then
        why="$why; the own-slot patch failed for another reason: see $OUT/crd-forks-own.log"
    fi
    if [ -z "$why" ]; then
        pass forks "asker-fork-7 and -8 made from asker's Seal and ran to the end; their asks and the spent quota refused; slot 8 refused to a newcomer; own slot refused by CEL"
    else
        fail forks "${why#; }"
    fi
else
    fail forks "the forks were not made or did not finish: $(grep -c 'asker' "$OUT/warden-1.log") asker line(s) in $OUT/warden-1.log"
fi

# ── 7. sigterm ────────────────────────────────────────────────────────
kill -TERM "$WARDEN_PID"
code=""
for _ in $(seq 1 60); do
    if ! kill -0 "$WARDEN_PID" 2>/dev/null; then wait "$WARDEN_PID"; code=$?; break; fi
    sleep 0.5
done
WARDEN_PID_DONE=$WARDEN_PID
WARDEN_PID=""
left=$(pgrep -f "^/usr/bin/taso-sim --turns 1000000" | tr '\n' ' ')
if [ -z "$code" ]; then
    fail sigterm "the Warden did not exit within 30 s of SIGTERM"
    kill -KILL "$WARDEN_PID_DONE" 2>/dev/null
elif [ "$code" != 0 ]; then
    fail sigterm "exit status $code: see $OUT/warden-1.log"
elif [ -n "$left" ]; then
    fail sigterm "agents left running: $left"
else
    stopped_ok=1
    for v in team-a/runner team-b/runner-b; do
        is_phase "${v%/*}" "${v#*/}" Exited && [ "$(message "${v%/*}" "${v#*/}")" = "stopped on request" ] || { stopped_ok=0; fail sigterm "$v: $(phase "${v%/*}" "${v#*/}"): $(message "${v%/*}" "${v#*/}")"; break; }
    done
    # editme's refused edit still stands, so its message keeps saying so.
    [ "$stopped_ok" = 1 ] && ! is_phase team-a editme Exited && { stopped_ok=0; fail sigterm "team-a/editme: $(phase team-a editme)"; }
    [ "$stopped_ok" = 1 ] && pass sigterm "exit 0, no agent left, statuses Exited: stopped on request"
fi

# ── 8. resumed ────────────────────────────────────────────────────────
# A new Warden on the same node: Open, rolled back to the last Seal, and
# the agent resumes after its last sealed turn.  The editme Vessel is put
# back within the limits first, so it runs again too.
K patch vessel -n team-a editme --type merge -p '{"spec":{"resources":{"pids":64}}}' >/dev/null
start_warden warden-2
if wait_for 60 is_phase team-a runner Running && wait_for 30 agent 101; then
    # 8. slots: the newcomer on runner's slot stays refused, and never ran.
    sleep 3
    m=$(message team-b clash)
    if is_phase team-b clash Refused && case "$m" in *"uid_slot 1 is bound to another Vessel"*) true ;; *) false ;; esac && ! agent 116 >/dev/null; then
        pass slots "after the restart runner keeps slot 1; clash stays Refused: $m"
    else
        fail slots "clash: $(phase team-b clash): $m; agent: $(agent 116 || echo none)"
    fi
    kill -TERM "$WARDEN_PID"
    for _ in $(seq 1 60); do kill -0 "$WARDEN_PID" 2>/dev/null || break; sleep 0.5; done
    wait "$WARDEN_PID" 2>/dev/null
    WARDEN_PID=""
    start=$(K get vessel -n team-a runner -o jsonpath='{.status.start}')
    rolled=$(K get vessel -n team-a runner -o jsonpath='{.status.settled.rolledBackTo}')
    birth=$(K get vessel -n team-a runner -o jsonpath='{.status.settled.birthSeal}')
    if [ "$start" = Open ] && [ -n "$rolled" ] && [ "$rolled" -gt 2 ] && [ -z "$birth" ]; then
        pass resumed "start Open, no new birth Seal, rolled back to the Seal at lsn $rolled, ran again"
    else
        fail resumed "start '$start', rolledBackTo '$rolled'"
    fi
else
    fail slots "runner did not run again: $(phase team-a runner): $(message team-a runner)"
    fail resumed "runner did not run again"
fi

# ── summary ───────────────────────────────────────────────────────────
K get vessels -A -o custom-columns='NS:.metadata.namespace,NAME:.metadata.name,NODE:.spec.node,PHASE:.status.phase,START:.status.start,MESSAGE:.status.message' >"$OUT/vessels-final.txt" 2>&1
{
    echo
    echo "K2 end to end ($(date -u +%FT%TZ), $(uname -r), envtest $ENVTEST_VERSION)"
    for row in crd running refused elsewhere deleted kept fork forks sigterm slots resumed; do
        printf '  %-10s %s\n' "$row" "${RESULT[$row]:-not run}"
    done
    echo "results in $OUT"
} | tee "$OUT/summary.txt"
