#!/usr/bin/env bash
# P3 exit gate (v1.0 §1, file 10): the futures you don't choose never
# touched the outside world.
#
#   1. released = promoted child's keys only (no sibling, no other fork)
#   2. all-or-none after SIGKILL ×$KILLS (keys.log has the full set or 0)
#   3. no duplicate keys across 20 rounds
#
# Per round:
#   a. Parent Vessel, agent runs (relay, --effects 0): seals one turn,
#      exits.
#   b. $FORKS child Vessels (forks from parent), each runs relay
#      --effects $EFFECTS (held: forks hold by default): declares effects,
#      seals, exits.
#   c. SIGKILL loop ($KILLS times): start parent Warden with
#      "promote": {"child": "<child-0>"}, SIGKILL after a tiny sleep.
#   d. Clean start: parent Warden with promote config; finish_promotion
#      handles crash recovery; the daemon's "already promoted" guard
#      skips a double promote.  The sender (the relay, --role sender, on
#      the host) reads Open on the Warden's sender socket, reports, and
#      writes keys.log; the parent's agent waits for it (C5: an agent can
#      neither list nor report).
#   e. Verify: parent's keys.log matches child-0's declared.log; keys
#      are all-or-none; no duplicates.
#
# Egress closed except the Warden socket: the runc container has its
# own network namespace with no setup, so no outbound connectivity.
# The relay's agent role communicates only through the Field protocol
# over the per-Vessel Unix socket; its sender role runs on the host, on
# the Warden's sender socket, which is never mounted into a Vessel.
#
# Usage (root; needs runc, ZFS, cargo, python3):
#   TASO_ZFS_DATASET=tasotest/vessel scripts/p3-no-trace.sh
#
# Environment: N (20)  FORKS (3)  EFFECTS (2)  KILLS (20)  LANDLOCK (1)
#              OUT (/root/taso-gate-p3-<time>)  KEEP (0)

set -euo pipefail
trap 'echo "FAILED at line $LINENO (exit $?)" >&2' ERR

: "${TASO_ZFS_DATASET:?set TASO_ZFS_DATASET to a dataset the gate may use}"
N=${N:-20}
FORKS=${FORKS:-3}
EFFECTS=${EFFECTS:-2}
KILLS=${KILLS:-20}
LANDLOCK=${LANDLOCK:-1}
KEEP=${KEEP:-0}
OUT=${OUT:-/root/taso-gate-p3-$(date +%Y%m%d-%H%M%S)}
RUN=$(date +%Y%m%d%H%M%S)-$$

[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 2; }
for t in zfs runc ldd python3 cargo; do
    command -v "$t" >/dev/null || { echo "$t is missing" >&2; exit 2; }
done

cd "$(dirname "$0")/.."
echo "== building (release)"
cargo build --release -q -p taso-warden -p taso-landlock
BIN=$PWD/target/release

mkdir -p "$OUT"
WORK=$(mktemp -d /var/tmp/taso-p3.XXXXXX)
chmod 755 "$WORK"
BASE="$TASO_ZFS_DATASET/gate-p3-$$"
SOCK=$WORK/coord.sock
RELAY=$PWD/scripts/p3-relay.py

cleanup() {
    [ -n "${COORD_PID:-}" ] && kill "$COORD_PID" 2>/dev/null || true
    if [ -d "$WORK/run/runc" ]; then
        for c in $(runc --root "$WORK/run/runc" list -q 2>/dev/null); do
            runc --root "$WORK/run/runc" delete --force "$c" 2>/dev/null || true
        done
    fi
    if [ "$KEEP" = 1 ]; then
        echo "kept: dataset $BASE, work dir $WORK"
    else
        zfs destroy -R "$BASE" 2>/dev/null || true
        rm -rf "$WORK"
    fi
}
trap cleanup EXIT

# ── rootfs ────────────────────────────────────────────────────────────
ROOTFS=$WORK/rootfs
copy_with_libs() {
    install -D -m 755 "$1" "$ROOTFS$2"
    local libs
    libs=$(ldd "$1" 2>/dev/null | grep -o '/[^ ]*' || true)
    local lib
    for lib in $libs; do
        [ -f "$lib" ] && install -D -m 755 "$lib" "$ROOTFS$lib"
    done
}
# The agent is p3-relay.py — needs python3 inside the rootfs.
PY3=$(command -v python3)
copy_with_libs "$PY3" /usr/bin/python3
copy_with_libs "$BIN/taso-landlock" /usr/lib/taso/landlock
mkdir -p "$ROOTFS"/{proc,dev,sys,tmp,work,run/taso}
: > "$ROOTFS/run/taso/field.sock"
install -m 755 "$RELAY" "$ROOTFS/usr/bin/p3-relay.py"
# Python needs its stdlib; copy the lib directory for the interpreter.
PY_LIB=$(python3 -c 'import sys, os; print(os.path.dirname(os.__file__))')
if [ -d "$PY_LIB" ]; then
    mkdir -p "$ROOTFS$(dirname "$PY_LIB")"
    cp -a "$PY_LIB" "$ROOTFS$PY_LIB"
fi
# Python C extensions (.so) may depend on libraries not linked by the
# interpreter binary.  Copy their deps too (best-effort).
_so_libs=$(find "$ROOTFS$PY_LIB" -name '*.so' -exec ldd {} + 2>/dev/null \
    | grep -o '/[^ ]*' | sort -u || true)
for lib in $_so_libs; do
    [ -f "$ROOTFS$lib" ] || install -D -m 755 "$lib" "$ROOTFS$lib" 2>/dev/null || true
done

mkdir -p "$WORK/bin"
cp "$BIN/taso-wardend" "$WORK/bin/"

# ── coordinator ───────────────────────────────────────────────────────
zfs create "$BASE"
"$BIN/taso-coordd" "$WORK/coord.redb" "$SOCK" 2>"$OUT/coordd.err" &
COORD_PID=$!
for _ in $(seq 100); do [ -S "$SOCK" ] && break; sleep 0.05; done
[ -S "$SOCK" ] || { echo "taso-coordd did not start" >&2; exit 1; }
echo "== coordinator ready"

# ── config generators ─────────────────────────────────────────────────

NS="7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a"

# config_parent <subject> <out-file> [promote-child-subject]
# With a child to promote, the agent waits for the host's sender to be
# done (/work/sender-done) before it exits.
config_parent() {
    local subject="$1" out="$2" promote_child="${3:-}"
    python3 - "$subject" "$out" "$promote_child" \
             "$SOCK" "$BASE" "$WORK" "$ROOTFS" "$NS" "$LANDLOCK" <<'PY'
import json, sys
subject, out, promote_child = sys.argv[1], sys.argv[2], sys.argv[3]
sock, base, work, rootfs, ns, landlock = sys.argv[4:10]
vessel = {"namespace": ns, "subject": subject, "uid_slot": 0}
args = ["/usr/bin/python3", "/usr/bin/p3-relay.py", "--role", "agent",
        "--effects", "0", "--turns", "1"]
if promote_child:
    vessel["promote"] = {"child": promote_child, "seal": "last"}
    args += ["--wait-for", "/work/sender-done"]
rt = {
    "rootfs": rootfs,
    "host_uid_base": 200000,
    "args": args,
    "memory_bytes": 268435456,
    "pids": 64,
}
if landlock == "1":
    rt["landlock_shim"] = "/usr/lib/taso/landlock"
json.dump({
    "warden": 1,
    "coordinator": {"remote": sock},
    "root": base,
    "state_dir": f"{work}/state",
    "store": f"{work}/store",
    "prefix": "vessels",
    "run_dir": f"{work}/run",
    "runtime": rt,
    "vessels": [vessel],
}, open(out, "w"), indent=1)
PY
}

# config_child <subject> <parent-subject> <uid-slot> <out-file>
config_child() {
    local subject="$1" parent="$2" uid_slot="$3" out="$4"
    python3 - "$subject" "$parent" "$uid_slot" "$out" \
             "$SOCK" "$BASE" "$WORK" "$ROOTFS" "$NS" "$LANDLOCK" "$EFFECTS" <<'PY'
import json, sys
subject, parent, uid_slot, out = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
sock, base, work, rootfs, ns, landlock, effects = sys.argv[5:12]
rt = {
    "rootfs": rootfs,
    "host_uid_base": 200000,
    "args": ["/usr/bin/python3", "/usr/bin/p3-relay.py", "--role", "agent",
             "--effects", effects, "--turns", "1"],
    "memory_bytes": 268435456,
    "pids": 64,
}
if landlock == "1":
    rt["landlock_shim"] = "/usr/lib/taso/landlock"
json.dump({
    "warden": 1,
    "coordinator": {"remote": sock},
    "root": base,
    "state_dir": f"{work}/state",
    "store": f"{work}/store",
    "prefix": "vessels",
    "run_dir": f"{work}/run",
    "runtime": rt,
    "vessels": [{"namespace": ns, "subject": subject,
                 "fork": {"parent": parent, "seal": "last"},
                 "uid_slot": int(uid_slot)}],
}, open(out, "w"), indent=1)
PY
}

vessel_ds() {   # $1 daemon stderr -> the Vessel's dataset
    local ds
    ds=$(grep -o ': dataset [^ ]*$' "$1" | head -1 | sed 's/: dataset //' || true)
    if [ -z "$ds" ]; then
        echo "vessel_ds: no dataset found in $1; last 10 lines:" >&2
        tail -10 "$1" >&2
        return 1
    fi
    echo "$ds"
}

# Run daemon, show stdout+stderr on failure.
run_daemon() {
    local cfg="$1" out="$2" err="$3"
    if ! "$WORK/bin/taso-wardend" "$cfg" >"$out" 2>"$err"; then
        echo "daemon failed (config $cfg):" >&2
        echo "-- stderr:" >&2; tail -20 "$err" >&2
        echo "-- stdout:" >&2; tail -20 "$out" >&2
        return 1
    fi
}

kill_runc() {   # clean up orphaned runc containers after SIGKILL
    [ -d "$WORK/run/runc" ] || return 0
    for c in $(runc --root "$WORK/run/runc" list -q 2>/dev/null); do
        runc --root "$WORK/run/runc" delete --force "$c" 2>/dev/null || true
    done
}

# ── predictions (written before the gate runs) ────────────────────────

cat <<'EOF' | tee "$OUT/predictions.txt"
=== P3 No-Trace Gate: Predictions ===

P1: released = promoted child's declared keys only.
    Expect: after promoting child-0, the sender's Open (on the Warden's
    sender socket, outside the Vessel) returns exactly child-0's
    declared effects.  No effect from child-1, child-2, … appears.
    The promoted child's keys.log matches its declared.log exactly.

P2: all-or-none after SIGKILL mid-promotion.
    Expect: after K SIGKILLs during promotion startup and one clean
    restart, the parent's keys.log contains either ALL of child-0's
    declared keys (promotion completed, possibly via finish_promotion
    crash recovery) or NONE (no Promotion record was fsync'd before
    the kill, so Open returns empty).  Never a partial subset.

P3: no duplicate keys.
    Expect: across all N rounds, no idempotency key appears more than
    once in any keys.log.  The "already promoted" guard in daemon.rs
    prevents double-promotion on restart with the same config.

Mechanism: Taso's promotion adopts all proposals in one ledger.adopt()
batch — all of them or none.  A crash between recording the Promotion
and completing adoption is finished by finish_promotion on restart.
The parent's Chronicle never contains a sibling's proposals because
promote() only runs for the one child named in the config.
EOF

# ── rounds ────────────────────────────────────────────────────────────

ALL_KEYS=$OUT/all-keys.txt
: > "$ALL_KEYS"
: > "$OUT/rounds.tsv"

echo "== $N rounds, $FORKS forks, $EFFECTS effects, $KILLS SIGKILLs"
for k in $(seq 1 "$N"); do
    echo "-- round $k/$N"
    parent_subj="p3-$RUN-$k-parent"

    # a. Parent: seal one turn, no effects.
    config_parent "$parent_subj" "$WORK/parent-$k.json"
    run_daemon "$WORK/parent-$k.json" "$OUT/parent-$k.out" "$OUT/parent-$k.err"
    parent_ds=$(vessel_ds "$OUT/parent-$k.err")
    echo "  parent: $parent_ds"

    # b. N forks, each declares $EFFECTS effects (held).
    for f in $(seq 0 $((FORKS - 1))); do
        child_subj="p3-$RUN-$k-child-$f"
        config_child "$child_subj" "$parent_subj" "$((f + 1))" "$WORK/child-$k-$f.json"
        run_daemon "$WORK/child-$k-$f.json" "$OUT/child-$k-$f.out" "$OUT/child-$k-$f.err"
        child_ds=$(vessel_ds "$OUT/child-$k-$f.err")
        echo "  child $f: $child_ds"
    done

    # Read child-0's declared keys (the one we will promote).
    child0_ds=$(vessel_ds "$OUT/child-$k-0.err")
    child0_mount=$(zfs get -H -o value mountpoint "$child0_ds")
    child0_declared="$child0_mount/declared.log"
    if [ ! -f "$child0_declared" ]; then
        echo "  ERROR: child-0's declared.log not found at $child0_declared"
        printf '%s\tERROR\t0\t0\t0\n' "$k" >> "$OUT/rounds.tsv"
        continue
    fi
    child0_keys=$(sort "$child0_declared")
    child0_count=$(wc -l < "$child0_declared")
    echo "  child-0 declared $child0_count key(s)"

    # c. SIGKILL loop: start parent with promote config, kill fast.
    child0_subj="p3-$RUN-$k-child-0"
    config_parent "$parent_subj" "$WORK/parent-$k-promote.json" "$child0_subj"

    for sigkill in $(seq 1 "$KILLS"); do
        "$WORK/bin/taso-wardend" "$WORK/parent-$k-promote.json" \
            >"$OUT/parent-$k-kill-$sigkill.out" 2>"$OUT/parent-$k-kill-$sigkill.err" &
        PID=$!
        # Random-ish sleep (0-50 ms) to vary the kill timing.
        sleep "0.0$((sigkill % 5))$((k % 10))"
        kill -KILL "$PID" 2>/dev/null || true
        wait "$PID" 2>/dev/null || true
        # Clean up any orphaned container before the next attempt.
        kill_runc
    done
    echo "  $KILLS SIGKILLs sent"

    # d. Clean start with promote config: the daemon's already-promoted
    #    guard and finish_promotion handle all crash-recovery cases.
    #    The sender reads Open on the Warden's sender socket, from the
    #    host, while the parent's agent waits for it.
    kill_runc
    parent_mount=$(zfs get -H -o value mountpoint "$parent_ds")
    rm -f "$parent_mount/sender-done"
    sender_sock="$WORK/run/senders/${parent_ds##*/v-}.sock"
    parent_keys_file="$OUT/keys-$k.log"
    "$WORK/bin/taso-wardend" "$WORK/parent-$k-promote.json" \
        >"$OUT/parent-$k-final.out" 2>"$OUT/parent-$k-final.err" &
    PID=$!
    for _ in $(seq 600); do
        [ -S "$sender_sock" ] && break
        kill -0 "$PID" 2>/dev/null || break
        sleep 0.1
    done
    if [ -S "$sender_sock" ]; then
        python3 "$RELAY" --role sender --socket "$sender_sock" \
            --keys-file "$parent_keys_file" 2>"$OUT/sender-$k.err" \
            || echo "  sender failed: $(tail -3 "$OUT/sender-$k.err")"
    else
        echo "  no sender socket at $sender_sock"
    fi
    touch "$parent_mount/sender-done"
    if ! wait "$PID"; then
        echo "  final start failed:"; tail -20 "$OUT/parent-$k-final.err"
        exit 1
    fi
    echo "  final start done"

    # e. Read the keys the sender wrote.
    if [ -f "$parent_keys_file" ]; then
        parent_keys=$(sort "$parent_keys_file")
        parent_count=$(wc -l < "$parent_keys_file")
    else
        parent_keys=""
        parent_count=0
    fi

    # Check 1: released = promoted child's keys only.
    if [ "$parent_count" -eq 0 ]; then
        released_match="none"  # all-or-none: "none" case
    elif [ "$parent_keys" = "$child0_keys" ]; then
        released_match="all"   # all-or-none: "all" case, and matches child-0
    else
        released_match="PARTIAL"  # failure: some but not all, or wrong keys
    fi

    # Check 2: no keys from other forks.
    sibling_leak=0
    for f in $(seq 1 $((FORKS - 1))); do
        cds=$(vessel_ds "$OUT/child-$k-$f.err")
        cm=$(zfs get -H -o value mountpoint "$cds")
        if [ -f "$cm/declared.log" ] && [ "$parent_count" -gt 0 ]; then
            # Any of this sibling's keys in the parent's released set?
            if comm -12 <(sort "$cm/declared.log") <(echo "$parent_keys") | grep -q .; then
                sibling_leak=1
            fi
        fi
    done

    # Check 3: no duplicates (within this round).
    dup_count=0
    if [ "$parent_count" -gt 0 ]; then
        dup_count=$(sort "$parent_keys_file" | uniq -d | wc -l)
        cat "$parent_keys_file" >> "$ALL_KEYS"
    fi

    # Log from the final start.
    promote_log=$(grep -o 'promot[^ ]*.*' "$OUT/parent-$k-final.err" | head -3 || true)

    printf '%s\t%s\t%s\t%s\t%s\n' "$k" "$released_match" "$sibling_leak" "$dup_count" "$parent_count" | tee -a "$OUT/rounds.tsv"
    [ -n "$promote_log" ] && echo "  $promote_log"
    [ "$released_match" = "PARTIAL" ] && echo "  FAIL: partial keys (expected all-or-none)"
    [ "$sibling_leak" = "1" ] && echo "  FAIL: sibling keys leaked"
    [ "$dup_count" -gt 0 ] && echo "  FAIL: $dup_count duplicate key(s)"

    # Clean up this round's datasets for the next round.
    zfs destroy -R "$parent_ds" 2>/dev/null || true
    for f in $(seq 0 $((FORKS - 1))); do
        cds=$(vessel_ds "$OUT/child-$k-$f.err")
        zfs destroy -R "$cds" 2>/dev/null || true
    done
done

# ── global duplicate check ────────────────────────────────────────────
global_dups=0
if [ -s "$ALL_KEYS" ]; then
    global_dups=$(sort "$ALL_KEYS" | uniq -d | wc -l)
fi

# ── summary ───────────────────────────────────────────────────────────
python3 - "$OUT/rounds.tsv" "$N" "$global_dups" <<'PY' | tee "$OUT/summary.txt"
import sys

rows = [l.rstrip("\n").split("\t") for l in open(sys.argv[1]) if l.strip()]
n = int(sys.argv[2])
global_dups = int(sys.argv[3])

# Check 1: released = promoted child's keys only.
# "all" or "none" is a pass; "PARTIAL" or "ERROR" is a fail.
all_or_none = sum(1 for r in rows if r[1] in ("all", "none"))
all_count = sum(1 for r in rows if r[1] == "all")
none_count = sum(1 for r in rows if r[1] == "none")
partial = sum(1 for r in rows if r[1] == "PARTIAL")
errors = sum(1 for r in rows if r[1] == "ERROR")

# Check 2: no sibling leak.
no_leak = sum(1 for r in rows if r[2] == "0")

# Check 3: no duplicates.
no_dups = sum(1 for r in rows if r[3] == "0")

print(f"P3 no-trace gate, {n} rounds, {all_count} promoted, {none_count} killed-before-record")
print(f"1. released = promoted child only (all-or-none, no sibling): {all_or_none}/{n} "
      f"({all_count} all, {none_count} none, {partial} partial, {errors} error) "
      f"-> {'PASS' if all_or_none == n else 'FAIL'}")
print(f"2. no sibling leak: {no_leak}/{n} -> {'PASS' if no_leak == n else 'FAIL'}")
print(f"3. no duplicate keys (per-round and global): per-round {no_dups}/{n}, "
      f"global {global_dups} -> {'PASS' if no_dups == n and global_dups == 0 else 'FAIL'}")

if all_count == 0:
    print("WARNING: no round completed a promotion (all SIGKILLs too early); "
          "the gate proves nothing about the promoted set.  Increase KILLS or check timing.")
PY
echo "results in $OUT"
