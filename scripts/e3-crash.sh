#!/usr/bin/env bash
# e3-crash.sh: E3-3b of P5 B2, the crash round (one-pager
# Taso_onepager_p5_b2_e3 rev. 4; plan P5-17, P5-18; spec rev. 33, D92, D93).
#
#   sudo scripts/e3-crash.sh list  [--subset]                 the manifest and its count; runs nothing
#   sudo scripts/e3-crash.sh round "SEQ" POINT MODE           one round, e.g. round "write seal" boundary:2 drop
#   sudo scripts/e3-crash.sh run   [--subset] [--limit N]     every round of the manifest, results tee'd
#
# From the repository root, as root, on a host E3-1's `check` passes on.
#
# One round (protocol 1-6 of the one-pager):
#  1 a fresh dm-flakey device (scripts/e3-device.sh) over a file under
#    $WORK, ext4 on it, mounted at $WORK/d: the block log, the coordinator,
#    the pack store and the Chronicle segments live there and nowhere else.
#    taso-blkd and taso-wardend start on it; one Vessel, its agent taso-sim
#    --step (E3-3a), synchronous=full so an acknowledged write is durable.
#  2 the harness drives the agent one operation at a time and writes the
#    oracle (scripts/e3-oracle.py, E3-2) on / from the Field's replies.  A
#    `fork` includes its child fixture: the child writes once (tag 1),
#    seals once and exits.  A `promote` ends the parent's run (C7); the
#    harness waits for the Warden to start it again.
#  3 at the point the table is swapped (drop, or error) without syncing
#    the filesystem above (E3-1).
#  4 the Warden and taso-blkd are killed -9; `e3-device.sh image` tears
#    the rest down, proven, and copies the backing raw before any mount.
#  5 a copy of that image is mounted at the same path; taso-blkd and the
#    Warden start on it; every agent that comes up is told `exit`.
#  6 the harness reads the reborn parent's Seals through taso-blkd (each
#    exported, forked, mounted read-only, its rows counted), the Warden's
#    and taso-blkd's reports and the resume turn, and the oracle grades.
#
# Points: boundary:k (after op k's reply, before op k+1; k = the length is
# after the last op); timing:k+D (op k sent, the swap D ms later, on `seal`
# only; MISSED, never covered, if the reply was already there).  Holds
# inside one operation (TASO_E3_HOLD) are E3-3c, not this file.
#
# The model's preconditions (P5-18, C7/M7): at most one fork and one
# promote; a promote needs a fork before it and no parent `seal` between
# them (a promotion is refused once the parent moved past the fork Seal).
# The per-merge subset (E3-c): every pair at every point, triples that
# contain seal or promote, error mode on pairs.
#
# Predicted (2026-10-27, from reading the code): a round whose parent wrote
# after its last retained Seal FAILs line 1: the rollback discards those
# blocks, and the Warden's reset line counts Chronicle records only, so it
# says "nothing reset" (D93 (i)).
#
# Touches, and nothing else: $WORK (default /var/lib/taso-e3: rootfs,
# images, results), $RUN (/run/taso-e3-crash: runc state, sockets), /mnt/e3,
# the dm device e3crash and its loop, a second loop for the rebirth copy,
# the ublk devices of this run's taso-blkd.  Refuses to start if any of
# these is in use, or if any taso-sim runs.  Every wait is bounded; a
# teardown that fails is a HARNESS line, never a pass.  Env: E3_WORK,
# E3_SIZE_MIB (2048), E3_ROWS (8), E3_STEP_MS (25), KEEP_FAILS (3: images
# of the newest failing rounds kept).

set -Eeuo pipefail
# An unguarded failure says where it was; set -e alone ends the script silently
# (taso-test, 2026-10-27: three rounds stopped at a bad `tr`, with nothing printed).
trap 'printf "ABORT: line %s: %s\n" "$LINENO" "$BASH_COMMAND" >&2' ERR

WORK=${E3_WORK:-/var/lib/taso-e3}
RUN=/run/taso-e3-crash
D=$WORK/d
MNT=/mnt/e3
DEVNAME=e3crash
SIZE_MIB=${E3_SIZE_MIB:-2048}
ROWS=${E3_ROWS:-8}
STEP_MS=${E3_STEP_MS:-10}   # a Seal takes ~40 ms on taso-test: 25 put three of four delays past it (111 MISSED of 220)
KEEP_FAILS=${KEEP_FAILS:-3}
DEVSH=$PWD/scripts/e3-device.sh
ORACLE=$PWD/scripts/e3-oracle.py
BIN=$PWD/target/release
SOCK=$RUN/blk.sock

die() { printf 'ABORT: %s\n' "$*" >&2; exit 2; }
say() { printf '== %s\n' "$*"; }
oracle() { python3 -I "$ORACLE" "$@"; }

# ── the manifest ──────────────────────────────────────────────────────
manifest() { # manifest [--subset] -> lines "SEQ|POINT|MODE"
    python3 -I - "${1:-}" "$STEP_MS" <<'PY'
import itertools, sys
subset, step = sys.argv[1] == "--subset", int(sys.argv[2])
OPS = ["write", "seal", "fork", "promote", "effect"]
def valid(seq):
    if seq.count("fork") > 1 or seq.count("promote") > 1:
        return False
    if "promote" in seq:
        p = seq.index("promote")
        if "fork" not in seq[:p]:
            return False
        if "seal" in seq[seq.index("fork") + 1:p]:
            return False   # M7: the parent moved past the fork Seal
    return True
for n in (2, 3):
    for seq in itertools.product(OPS, repeat=n):
        if not valid(seq) or (subset and n == 3 and not ({"seal", "promote"} & set(seq))):
            continue
        s = " ".join(seq)
        for k in range(1, n + 1):
            print(f"{s}|boundary:{k}|drop")
        for k, op in enumerate(seq, 1):
            if op == "seal":
                for d in range(0, 4 * step, step):
                    print(f"{s}|timing:{k}+{d}|drop")
        if n == 2 or not subset:
            print(f"{s}|boundary:{n}|error")
PY
}

if [[ "${1:-}" == list ]]; then
    m=$(manifest "${2:-}")
    printf '%s\n' "$m"
    printf '%s\n' "$m" | python3 -I -c '
import sys, collections
rows = [l.strip().split("|") for l in sys.stdin if l.strip()]
by = collections.Counter(r[1].split(":")[0] + "/" + r[2] for r in rows)
print(f"# {len(rows)} rounds over {len({r[0] for r in rows})} sequences: " + ", ".join(f"{k} {v}" for k, v in sorted(by.items())))'
    exit 0
fi

# ── preflight, build, rootfs ──────────────────────────────────────────
[[ $EUID -eq 0 ]] || die "run as root"
[[ -f Cargo.toml && -x scripts/e3-device.sh && -f scripts/e3-oracle.py ]] || die "run from the repository root (with E3-1 and E3-2)"
for t in runc python3 cargo dmsetup losetup mkfs.ext4 fuser findmnt stat pgrep nsenter; do command -v "$t" >/dev/null || die "$t is missing"; done
mountpoint -q "$D" 2>/dev/null && die "$D is mounted: another round? (umount it)"
dmsetup info "$DEVNAME" >/dev/null 2>&1 && die "the dm device $DEVNAME exists: an earlier round? (scripts/e3-device.sh down $DEVNAME)"
[[ ! -S "$SOCK" ]] || die "$SOCK exists: a taso-blkd of an earlier round? (pgrep -af taso-blkd)"
pgrep -x taso-sim >/dev/null && die "a taso-sim runs (a bench or an earlier round); E3 tells agents apart by pid and needs none but its own"
"$DEVSH" check >/dev/null 2>&1 || die "scripts/e3-device.sh check does not pass here; run it for the reason"
mkdir -p "$WORK" "$RUN" "$MNT"
[[ "$(findmnt -no FSTYPE -T "$WORK")" != tmpfs ]] || die "$WORK is on tmpfs; the images need a disk"

say "building (release)"
cargo build --release -q -p taso-warden -p taso-sim -p taso-landlock -p taso-blk
for b in taso-wardend taso-sim taso-landlock taso-blkd; do [[ -x "$BIN/$b" ]] || die "$BIN/$b was not built"; done
ROOTFS=$WORK/rootfs
rm -rf "$ROOTFS"
copy_with_libs() {
    install -D -m 755 "$1" "$ROOTFS$2"
    ldd "$1" | grep -o '/[^ ]*' | while read -r lib; do install -D -m 755 "$lib" "$ROOTFS$lib"; done
}
copy_with_libs "$BIN/taso-sim" /usr/bin/taso-sim
copy_with_libs "$BIN/taso-landlock" /usr/lib/taso/landlock
mkdir -p "$ROOTFS"/{proc,dev,sys,tmp,work,run/taso}; : >"$ROOTFS/run/taso/field.sock"

# ── helpers ───────────────────────────────────────────────────────────
# The helpers that keep state set globals (AGENT, REPLY) rather than print:
# a $(...) would run them in a subshell and drop KNOWN and NEXT.
WARDEN_PID=; BLKD_PID=; LOOP2=; KNOWN=" "; AGENT=; REPLY=; WHY=
declare -A NEXT

blk_raw() {
    python3 -I -c '
import socket, sys
s = socket.socket(socket.AF_UNIX); s.settimeout(120); s.connect(sys.argv[1])
s.sendall((" ".join(sys.argv[2:]) + "\n").encode()); print(s.makefile().readline().strip())' "$SOCK" "$@"
}
blk() { local a; a=$(blk_raw "$@") || return 1; case "$a" in ok) ;; "ok "*) printf '%s\n' "${a#ok }" ;; *) echo "taso-blkd: $* -> $a" >&2; return 1 ;; esac; }
jget() { # jget JSON a.b -> the value ("" if absent; JSON for objects and lists)
    python3 -I -c '
import json, sys
v = json.loads(sys.argv[1]) if sys.argv[1].strip() else None
for k in sys.argv[2].split("."):
    v = v.get(k) if isinstance(v, dict) else None
print("" if v is None else json.dumps(v) if isinstance(v, (dict, list)) else v)' "$1" "$2"
}

# The next taso-sim not yet KNOWN whose step channel is ready -> AGENT (its host pid).
wait_agent() { # wait_agent SECONDS
    local deadline=$((SECONDS + $1)) p
    while ((SECONDS < deadline)); do
        for p in $(pgrep -x taso-sim || true); do
            [[ "$KNOWN" == *" $p "* ]] && continue
            if [[ -f /proc/$p/root/tmp/e3/ready ]]; then KNOWN="$KNOWN$p "; NEXT[$p]=1; AGENT=$p; return 0; fi
        done
        sleep 0.05
    done
    return 1
}
ready_turn() { local t; t=$(jget "$(cat /proc/"$1"/root/tmp/e3/ready)" resumed_after); echo "${t:-0}"; }
send() { # send PID OP: the op file, whole; no wait
    # Created inside the agent's user namespace: its /tmp is a tmpfs of
    # that namespace, and a new file there must have an owner the namespace
    # can name.  Host uid 0 is not one (the container maps 0..65535 to the
    # Vessel's range), so root's create fails EOVERFLOW ("Value too large")
    # while root's reads and unlinks work (taso-test, 2026-10-27; the
    # kernel's rule, reproduced by hand).  nsenter -U as the namespace's
    # root creates it as the agent itself would.
    local n=${NEXT[$1]} dir=/proc/$1/root/tmp/e3
    printf '%s\n' "$2" | nsenter -t "$1" -U -S 0 -G 0 -- sh -c "cat >'$dir/.op.$n' && mv '$dir/.op.$n' '$dir/op.$n'"
}
reply() { # reply PID SECONDS -> REPLY, the reply to the last op sent; fails (WHY says) on a timeout or the agent gone
    local p=$1 n=${NEXT[$1]} deadline=$((SECONDS + $2))
    local f=/proc/$1/root/tmp/e3/reply.$n
    while ((SECONDS < deadline)); do
        # Taken: read, then removed (the agent waits for its last reply to go, E3-3a).
        if [[ -f "$f" ]]; then NEXT[$p]=$((n + 1)); REPLY=$(cat "$f"); rm -f "$f"; return 0; fi
        # Alive by /proc, not by kill -0: a signal to an agent in its own user
        # namespace may be refused while it lives (taso-test, 2026-10-27:
        # every first reply was given up on at 0 s).
        [[ -d /proc/$p ]] || { WHY="the agent (pid $p) is gone"; return 1; }
        sleep 0.01
    done
    WHY="no reply in $2 s (agent pid $p alive)"
    return 1
}
step() { REPLY=; WHY="the op file could not be written"; send "$1" "$2" && reply "$1" "${3:-120}"; }   # -> REPLY

teardown() { # every piece of a round, guarded
    set +e
    [[ -n "$WARDEN_PID" ]] && kill -9 "$WARDEN_PID" 2>/dev/null; WARDEN_PID=
    [[ -n "$BLKD_PID" ]] && { kill -9 "$BLKD_PID" 2>/dev/null; wait "$BLKD_PID" 2>/dev/null; }; BLKD_PID=
    for c in $(runc --root "$RUN/run/runc" list -q 2>/dev/null); do runc --root "$RUN/run/runc" delete --force "$c" 2>/dev/null; done
    for m in $(awk -v r="$MNT" '$5 == r || index($5, r "/") == 1 { print length($5), $5 }' /proc/self/mountinfo | sort -rn | cut -d' ' -f2-); do
        [[ "$m" == "$MNT" ]] || umount "$m" 2>/dev/null || umount -l "$m" 2>/dev/null
    done
    mountpoint -q "$D" && { umount "$D" 2>/dev/null || umount -l "$D"; }
    [[ -n "$LOOP2" ]] && losetup -d "$LOOP2" 2>/dev/null; LOOP2=
    # And every loop over a file of ours, remembered or not (the leak above).
    for l in $(losetup -j "$WORK/rebirth.img" 2>/dev/null | cut -d: -f1; losetup -a 2>/dev/null | grep -F "$WORK/" | cut -d: -f1); do losetup -d "$l" 2>/dev/null; done
    dmsetup info "$DEVNAME" >/dev/null 2>&1 && "$DEVSH" down "$DEVNAME" >/dev/null 2>&1
    rm -f "$WORK/dev.img" "$WORK/rebirth.img" "$SOCK"
    rm -rf "$RUN/run" "$RUN/read"
    KNOWN=" "
    set -e
}
trap 'teardown' EXIT

config() { # config SUBJECT -> $RUN/w.json
    python3 -I - "$1" "$D" "$RUN" "$MNT" "$ROOTFS" "$SOCK" "$ROWS" >"$RUN/w.json" <<'PY'
import json, sys
subject, d, run, mnt, rootfs, sock, rows = sys.argv[1:]
print(json.dumps({
    "warden": 1, "coordinator": {"local": d + "/coord.redb"}, "root": "e3/r",
    "storage": {"blk": {"socket": sock, "mounts": mnt, "spool": d + "/spool"}},
    "state_dir": d + "/state", "store": d + "/store", "prefix": "vessels", "run_dir": run + "/run",
    "batched_snapshots": True,
    "runtime": {"rootfs": rootfs, "host_uid_base": 200000, "landlock_shim": "/usr/lib/taso/landlock",
                "args": ["/usr/bin/taso-sim", "--step", "/tmp/e3", "--rows", rows, "--row-bytes", "512",
                         "--synchronous", "full", "--db", "/work/state.db", "--stats", "/work/sim-stats.json"],
                "memory_bytes": 268435456, "pids": 64},
    "vessels": [{"namespace": "e3" * 16, "subject": subject, "uid_slot": 1, "forks": {"slots": [2]}}],
}, indent=1))
PY
}
start_stack() { # start_stack TAG: taso-blkd and the Warden on $D; logs $R/*-TAG.err
    # A killed taso-blkd leaves its socket file; the Warden must wait for the
    # new one to *answer*, not for the file (taso-test 2026-10-28: six rounds
    # lost that race, "taso-blkd socket: Connection refused").
    rm -f "$SOCK"
    "$BIN/taso-blkd" "$D/blk.log" "$SOCK" 2>>"$R/blkd-$1.err" & BLKD_PID=$!
    local i; for i in $(seq 600); do blk_raw stats >/dev/null 2>&1 && break; sleep 0.1; done
    blk_raw stats >/dev/null 2>&1 || return 1
    "$BIN/taso-wardend" "$RUN/w.json" >"$R/warden-$1.out" 2>"$R/warden-$1.err" & WARDEN_PID=$!
}

# ── one round ─────────────────────────────────────────────────────────
round() { # round "SEQ" POINT MODE -> the oracle's line on stdout; the round's files in $R
    local seq=$1 point=$2 mode=$3 subject O="$R/r.json"
    subject="e3-$(date +%s%N | tail -c 9)"
    local kind=${point%%:*} at=${point#*:} k delay=0 P C child="" turn rep lsn ms missed="" acks_err=0 ct cr
    k=${at%%+*}; [[ "$at" == *+* ]] && delay=${at#*+}
    local -a ops; read -ra ops <<<"$seq"
    local tag="[$seq] $point $mode"
    oracle new "$O" --sequence "$seq" --point "$point" --mode "$mode" --rows "$ROWS"
    # 1. the device, the stack, the agent
    "$DEVSH" make "$DEVNAME" "$WORK/dev.img" "$SIZE_MIB" >/dev/null || { echo "HARNESS $tag: make"; return; }
    mkfs.ext4 -q -F "/dev/mapper/$DEVNAME" && mkdir -p "$D" && mount -o errors=remount-ro "/dev/mapper/$DEVNAME" "$D" \
        || { echo "HARNESS $tag: mkfs or mount of the device"; return; }
    mkdir -p "$D/store" "$D/state" "$D/spool" "$RUN/run"
    config "$subject" || { echo "HARNESS $tag: config"; return; }
    start_stack 1 || { echo "HARNESS $tag: taso-blkd did not start"; return; }
    wait_agent 120 || { echo "HARNESS $tag: no agent came up (see $R/warden-1.err)"; return; }; P=$AGENT
    turn=$(( $(ready_turn "$P") + 1 ))
    # 2. the operations, to the point
    local i=0 op
    for op in "${ops[@]}"; do
        i=$((i + 1))
        if [[ "$kind" == timing && $i == "$k" ]]; then
            oracle requested "$O" "$op" turn="$turn"
            send "$P" "$op"; sleep "$(python3 -I -c "print($delay / 1000)")"
            [[ -f /proc/$P/root/tmp/e3/reply.${NEXT[$P]} ]] && missed=--missed
            break
        fi
        case "$op" in
            write)
                oracle requested "$O" write turn="$turn"
                step "$P" write || { echo "HARNESS $tag: write got no reply: $WHY"; return; }; rep=$REPLY
                oracle acknowledged "$O" write turn="$(jget "$rep" turn)" rows="$(jget "$rep" rows)" ;;
            seal)
                oracle requested "$O" seal turn="$turn"
                step "$P" seal || { echo "HARNESS $tag: seal got no reply: $WHY"; return; }; rep=$REPLY
                lsn=$(jget "$rep" sealed)
                oracle acknowledged "$O" seal turn="$(jget "$rep" turn)" ${lsn:+seal=$lsn}
                turn=$(( $(jget "$rep" turn) + 1 )) ;;
            effect)
                oracle requested "$O" effect
                step "$P" effect || { echo "HARNESS $tag: effect got no reply: $WHY"; return; }; rep=$REPLY
                oracle acknowledged "$O" effect key="$(jget "$rep" key)" ;;
            fork)
                oracle requested "$O" fork
                step "$P" fork || { echo "HARNESS $tag: fork got no reply: $WHY"; return; }; rep=$REPLY
                child=$(jget "$rep" child)
                [[ -n "$child" ]] || { echo "REFUSED $tag: the fork was refused: $(jget "$rep" refused)"; return; }
                oracle acknowledged "$O" fork child="$child"
                # the child fixture: one write (tag 1), one seal, exit
                wait_agent 120 || { echo "HARNESS $tag: the child's agent did not come up"; return; }; C=$AGENT
                ct=$(( $(ready_turn "$C") + 1 ))
                oracle requested "$O" write who=child turn="$ct"
                step "$C" "write 1" || { echo "HARNESS $tag: the child's write got no reply: $WHY"; return; }; cr=$REPLY
                oracle acknowledged "$O" write who=child turn="$ct" rows="$(jget "$cr" rows)"
                oracle requested "$O" seal who=child turn="$ct"
                step "$C" seal || { echo "HARNESS $tag: the child's seal got no reply: $WHY"; return; }; cr=$REPLY
                lsn=$(jget "$cr" sealed)
                oracle acknowledged "$O" seal who=child turn="$ct" ${lsn:+seal=$lsn}
                step "$C" exit >/dev/null || true ;;
            promote)
                oracle requested "$O" promote child="$child"
                step "$P" "promote $child" || { echo "HARNESS $tag: promote got no reply: $WHY"; return; }; rep=$REPLY
                [[ "$(jget "$rep" result.adopted)" == \[* ]] || { echo "REFUSED $tag: the promotion was refused: $(jget "$rep" refused)"; return; }
                oracle acknowledged "$O" promote child="$child"
                if ! wait_agent 120; then
                    # The Warden's own word on the parent is a result, not a harness fault
                    # (taso-test 2026-10-28: after adopting a fresh fork's files it refused to run the parent).
                    local said; said=$(grep -m1 "^$subject: .*refusing" "$R/warden-1.out" 2>/dev/null || true)
                    if [[ -n "$said" ]]; then echo "FAIL    $tag"; echo "        4: after the promotion the Warden refused to run the parent: ${said#*: }"
                    else echo "HARNESS $tag: the parent did not start again after its promotion"; fi
                    return
                fi; P=$AGENT
                turn=$(( $(ready_turn "$P") + 1 )) ;;
        esac
        [[ "$kind" == boundary && $i == "$k" ]] && break
    done
    # 3. the point
    local t0; t0=$(date +%s%N); "$DEVSH" "$mode" "$DEVNAME" >/dev/null; ms=$(( ($(date +%s%N) - t0) / 1000000 ))
    oracle cut "$O" --swap-ms "$ms" $missed
    if [[ "$mode" == error ]]; then   # provoke the error, bounded; count what was acknowledged after it
        if step "$P" seal 30 && [[ -n "$(jget "$REPLY" sealed)" ]]; then acks_err=$((acks_err + 1)); fi
        if step "$P" write 10 && [[ -n "$(jget "$REPLY" rows)" ]]; then acks_err=$((acks_err + 1)); fi
    fi
    # 4. the processes dead at the point; the image
    kill -9 "$WARDEN_PID" 2>/dev/null || true; kill -9 "$BLKD_PID" 2>/dev/null || true
    wait "$BLKD_PID" 2>/dev/null || true; WARDEN_PID=; BLKD_PID=
    if ! "$DEVSH" image "$DEVNAME" "$RUN" "$R/image.raw" >"$R/image.txt" 2>&1; then
        echo "HARNESS $tag: image ($(tail -1 "$R/image.txt"))"; return
    fi
    # 5. the rebirth, on a copy at the same path
    # No $(...) around a step that sets LOOP2: a subshell would keep it from
    # teardown, which then never detaches the loop, and the unlinked 2 GiB
    # copy stays held until reboot (taso-test 2026-10-28: 391 of them, the
    # disk full by round 380).  The errors go to a file instead.
    if ! { cp --sparse=always "$R/image.raw" "$WORK/rebirth.img" && LOOP2=$(losetup -f --show "$WORK/rebirth.img") && mount "$LOOP2" "$D"; } 2>"$R/rebirth.err"; then
        echo "HARNESS $tag: the rebirth copy could not be mounted: $(tr '\n' ' ' <"$R/rebirth.err") (df: $(df -h --output=avail "$WORK" | tail -1 | tr -d ' ') free on $WORK)"; return
    fi
    mkdir -p "$RUN/run"; KNOWN=" $(pgrep -x taso-sim | tr '\n' ' ') "
    start_stack 2 || { echo "HARNESS $tag: taso-blkd did not start on the image"; return; }
    local ds pdev resume="" deadline=$((SECONDS + 180)) a
    ds=$(grep -m1 -o "\] $subject: dataset .*" "$R/warden-1.err" | sed 's/.*: dataset //')
    [[ -n "$ds" ]] || { echo "HARNESS $tag: no dataset line for $subject in warden-1.err"; return; }
    while ((SECONDS < deadline)) && kill -0 "$WARDEN_PID" 2>/dev/null; do
        if wait_agent 1; then
            a=$AGENT
            pdev=$(blk_raw attach "$(blk find "$ds")" | sed -n 's/.*already attached as //p')
            if [[ -n "$pdev" && "$(findmnt -N "$a" -no MAJ:MIN /work 2>/dev/null)" == "$(stat -c '%Hr:%Lr' "$pdev")" ]]; then
                resume=$(ready_turn "$a")
            fi
            step "$a" exit 30 >/dev/null || true
        fi
    done
    if kill -0 "$WARDEN_PID" 2>/dev/null; then echo "HARNESS $tag: the reborn Warden did not finish in 180 s"; return; fi
    WARDEN_PID=
    if grep -q "^taso-wardend: starting:" "$R/warden-2.err"; then
        echo "HARNESS $tag: the reborn Warden did not start: $(grep -m1 "^taso-wardend: starting:" "$R/warden-2.err" | cut -c22-)"; return
    fi
    # 6. what the reborn Warden holds, and the grade
    gather "$subject" "$ds" "$resume" "$acks_err" "$mode" >"$R/a.json" || { echo "HARNESS $tag: gather"; return; }
    oracle check "$O" --after "$R/a.json" || true
}

gather() { # gather SUBJECT DATASET RESUME ACKS_ERR MODE -> a.json on stdout
    local subject=$1 ds=$2 branch layer tg lsn birth seals="" rd="$MNT/.read" tmp="$RUN/read" b dev ok lt
    birth=$(grep -m1 -o "\] $subject: birth Seal at lsn [0-9]*" "$R/warden-1.err" | grep -o '[0-9]*$' || true)
    branch=$(blk find "$ds") || return 1
    mkdir -p "$rd" "$tmp"
    for lt in $(blk seals "$branch"); do
        layer=${lt%%:*}; tg=${lt#*:}
        lsn=$(python3 -I -c 'import sys; t = bytes.fromhex(sys.argv[1]); print(int.from_bytes(t[:8], "little") if len(t) == 40 else "")' "$tg")
        [[ -n "$lsn" ]] || continue
        rm -f "$tmp/x.exp"; ok=false; blk export "$layer" - "$tmp/x.exp" >/dev/null 2>&1 && ok=true; rm -f "$tmp/x.exp"
        read -r b dev <<<"$(blk fork "$layer")" || return 1
        for _ in $(seq 50); do [[ -b "$dev" ]] && break; sleep 0.1; done
        rm -rf "$tmp/db"; mkdir -p "$tmp/db"
        if mount -o ro "$dev" "$rd" 2>/dev/null; then cp "$rd"/state.db* "$tmp/db/" 2>/dev/null || true; umount "$rd"; fi
        blk detach "$b" >/dev/null; blk drop "$b" >/dev/null
        seals="$seals$(python3 -I - "$tmp/db/state.db" "$lsn" "$ok" "${birth:-0}" <<'PY'
import json, os, sqlite3, sys
db, lsn, ok, birth = sys.argv[1], int(sys.argv[2]), sys.argv[3] == "true", int(sys.argv[4])
rows = {}
if os.path.exists(db):
    c = sqlite3.connect(db)
    try:
        for k, n in c.execute("SELECT CASE WHEN n >= 1000000 THEN 'c' || turn ELSE CAST(turn AS TEXT) END, count(*) FROM events GROUP BY 1"):
            rows[k] = n
    except sqlite3.OperationalError:
        pass
print(json.dumps({"lsn": lsn, "birth": lsn == birth, "export_ok": ok, "rows": rows}) + ",")
PY
)"
    done
    local forks report
    forks=$(cat "$R/warden-1.err" "$R/warden-2.err" 2>/dev/null | grep -o "\] $subject-fork-[0-9]*: dataset " | sed 's/^\] //; s/: dataset $//' | sort -u | tr '\n' ' ')
    report="$R/blkd-2.err $R/warden-2.err"; [[ "$5" == error ]] && report="$report $R/blkd-1.err $R/warden-1.err"
    # shellcheck disable=SC2086
    python3 -I - "[${seals%,}]" "$forks" "$3" "$4" $report <<'PY'
import json, sys
seals, forks, resume, acks = json.loads(sys.argv[1]), sys.argv[2].split(), sys.argv[3], int(sys.argv[4])
report = "".join(open(f, errors="replace").read() for f in sys.argv[5:])
print(json.dumps({"seals": seals, "forks": forks, "report": report,
                  "resume_turn": int(resume) if resume else None, "acks_after_error": acks}, indent=1))
PY
}

# ── commands ──────────────────────────────────────────────────────────
OUT=$WORK/results-$(date +%Y%m%d-%H%M%S)
mkdir -p "$OUT"
run_one() { # run_one N "SEQ" POINT MODE
    R="$OUT/$(printf '%04d' "$1")-$(echo "$2-$3-$4" | sed 's/ /_/g; s/[:+]/-/g')"; mkdir -p "$R"
    local t=$SECONDS line
    # In this shell, not a $(...): round's PIDs and loops must reach teardown.
    # Under ||, set -e is off inside it; its steps are guarded one by one.
    trap 'printf "ABORT: line %s: %s\n" "$LINENO" "$BASH_COMMAND" >&2' ERR
    round "$2" "$3" "$4" >"$R/round.out" 2>>"$R/harness.err" || true
    trap - ERR   # the bookkeeping below has nothing the trap should report
    line=$(grep -E '^(PASS|FAIL|MISSED|REFUSED|HARNESS) |^        ' "$R/round.out" || true)
    teardown >/dev/null 2>&1 || true
    [[ -n "$line" ]] || line="HARNESS [$2] $3 $4: no result (see $R/harness.err)"
    printf '%s  (%ds)\n' "$line" "$((SECONDS - t))" | tee -a "$OUT/results.txt"
    if [[ "$line" == HARNESS* ]]; then   # what the Warden and the agent said last, beside the line
        for f in warden-1.err warden-2.err; do
            [[ -s "$R/$f" ]] && tail -3 "$R/$f" | sed "s/^/        $f: /" | tee -a "$OUT/results.txt"
        done
    fi
    if [[ "$line" == PASS* || "$line" == MISSED* ]]; then
        rm -f "$R/image.raw"
    else   # keep the newest KEEP_FAILS failing rounds' images, across every results directory under $WORK
        local -a imgs=(); local f
        for f in "$WORK"/results-*/*/image.raw; do
            if [[ -f "$f" ]]; then imgs+=("$f"); fi
        done
        if [[ ${#imgs[@]} -gt $KEEP_FAILS ]]; then
            for f in "${imgs[@]:0:${#imgs[@]} - KEEP_FAILS}"; do rm -f "$f"; done
        fi
    fi
    true
}
case "${1:-}" in
    round)
        [[ $# == 4 ]] || die "round \"SEQ\" POINT MODE"
        say "one round; results in $OUT"
        run_one 1 "$2" "$3" "$4" ;;
    run)
        shift; sub=""; limit=0
        while (($#)); do case "$1" in --subset) sub=--subset ;; --limit) limit=$2; shift ;; *) die "run [--subset] [--limit N]" ;; esac; shift; done
        total=$(manifest "$sub" | wc -l); n=0
        say "$total rounds$( ((limit > 0)) && echo ", the first $limit"); results in $OUT/results.txt"
        while IFS='|' read -r s p m; do
            n=$((n + 1)); ((limit > 0 && n > limit)) && break
            printf '%4d/%d  ' "$n" "$total"; run_one "$n" "$s" "$p" "$m"
        done < <(manifest "$sub")
        python3 -I - "$OUT/results.txt" <<'PY'
import collections, re, sys
lines = [l for l in open(sys.argv[1]) if l[:1].isupper()]
c = collections.Counter(l.split()[0] for l in lines)
secs = [int(m.group(1)) for l in lines if (m := re.search(r"\((\d+)s\)\s*$", l))]
print("== " + ", ".join(f"{k} {v}" for k, v in sorted(c.items())) + (f"; {sum(secs) / len(secs):.0f} s per round" if secs else ""))
PY
        ;;
    *) sed -n '2,8p' "$0"; exit 64 ;;
esac
