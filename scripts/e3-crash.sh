#!/usr/bin/env bash
# e3-crash.sh: E3-3b of P5 B2, the crash round (one-pager
# Taso_onepager_p5_b2_e3 rev. 4; plan P5-17, P5-18; spec rev. 33, D92, D93).
#
#   sudo scripts/e3-crash.sh list  [--subset]                 the manifest and its count; runs nothing
#   sudo scripts/e3-crash.sh round "SEQ" POINT MODE           one round, e.g. round "write seal" boundary:2 drop
#   sudo scripts/e3-crash.sh run   [--subset] [--only KIND] [--limit N]
#                                                            every round of the manifest (or of one point
#                                                            kind: boundary, timing, hold, takeover), results tee'd
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
# only; MISSED, never covered, if the reply was already there);
# hold:NAME (E3-3c: the first stack starts with TASO_E3_HOLD=NAME; the
# harness arms the hold just before the last op, or before a `compact`
# sent to taso-blkd after the last op for compact.written, sends it without
# waiting, and cuts when the process says it is held there, so the point
# is exact and never MISSED; the reborn stack runs without the hold; under
# error the hold is released after the swap, so the held op meets the error);
# takeover:k or takeover:NAME (E3-4, one-pager rev. 6 § E3-4; spec D97):
# the coordinator (taso-coordd) and the pack store live under $WORK/h, never
# cut; Warden A runs on the device as always.  At the point (boundary k, or
# the shipping hold NAME) A's device drops and A is frozen (SIGSTOP to its
# Warden and taso-blkd, its containers paused); Warden B takes the Vessel
# over from the coordinator and the store (and a forked child after it) and
# is gathered as the reborn Warden is; then A is thawed and its agent asks
# one Seal and one effect, which must not be acknowledged (line F); the
# store's packs are listed before and after (lines H2, H3); and Warden C
# takes over from B and rebuilds from the store once more (line H1).  Drop
# only; run by hand (`run --only takeover`), not in the subset.
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
# these is in use, or if any taso-sim runs (takeover rounds also touch
# $WORK/h, $RUN/run-*, $RUN/{coord,blkb,blkc}.sock, $MNT/b and $MNT/c).
# Every wait is bounded; a
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
STAGGER_MS=${E3_STAGGER_MS:-10}   # E3-c2: the second Vessel's Seal after the first's, in a staggered burst
STEP_MS=${E3_STEP_MS:-10}   # a Seal takes ~40 ms on taso-test: 25 put three of four delays past it (111 MISSED of 220)
KEEP_FAILS=${KEEP_FAILS:-3}
DEVSH=$PWD/scripts/e3-device.sh
ORACLE=$PWD/scripts/e3-oracle.py
BIN=$PWD/target/release
SOCK=$RUN/blk.sock
# E3-4 (takeover rounds only): the coordinator, the store and the other nodes, never on the cut device.
HDIR=$WORK/h
COORD_SOCK=$RUN/coord.sock
COORD_PID=; declare -a TK_PIDS=()

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
# E3-4: the takeover point (one-pager rev. 6): every pair over write, seal,
# effect, fork at each boundary, and the two shipping holds; drop only; not
# in the subset (run once by hand, decided 2026-10-29).
if not subset:
    for seq in itertools.product(["write", "seal", "effect", "fork"], repeat=2):
        if valid(seq):
            for k in (1, 2):
                print(f"{' '.join(seq)}|takeover:{k}|drop")
    print("write seal|takeover:seal.shipped|drop")
    print("write effect|takeover:ledger.shipped|drop")
# E3-c2 (design rev. 2, decided 2026-10-30): two Vessels on one Warden, each
# `write seal` first, then a burst -- both `write`, then both `seal` without
# waiting (all: together; stagger: the second STAGGER_MS after the first) --
# cut at a timing point or a hold; in the subset from the start (c-e).
for shape in ("all", "stagger"):
    for d in (0, 5, 10, 20, 40):
        print(f"write seal|burst:{shape}:timing+{d}|drop")
    for name in ("seal.frozen", "seal.recorded", "seal.shipped"):
        for mode in ("drop", "error"):
            print(f"write seal|burst:{shape}:hold+{name}|{mode}")
# E3-c2 x E3-4 (c-g): B takes both Vessels over, after the burst or at the first shipping hold.
print("write seal|burst:all:takeover|drop")
print("write seal|burst:all:takeover+seal.shipped|drop")
# E3-3c: one round per hold site and mode, the shortest sequence reaching it
for name, s in (("seal.recorded", "write seal"), ("seal.frozen", "write seal"), ("seal.shipped", "write seal"),
                ("ledger.shipped", "write effect"), ("fork.branched", "write seal fork"),
                ("compact.written", "write seal")):
    for mode in ("drop", "error"):
        print(f"{s}|hold:{name}|{mode}")
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
for x in "$COORD_SOCK" "$RUN/blkb.sock" "$RUN/blkc.sock"; do [[ ! -S "$x" ]] || die "$x exists: a takeover round's process left? (pgrep -af 'taso-(coordd|blkd)')"; done
pgrep -x taso-sim >/dev/null && die "a taso-sim runs (a bench or an earlier round); E3 tells agents apart by pid and needs none but its own"
"$DEVSH" check >/dev/null 2>&1 || die "scripts/e3-device.sh check does not pass here; run it for the reason"
mkdir -p "$WORK" "$RUN" "$MNT"
[[ "$(findmnt -no FSTYPE -T "$WORK")" != tmpfs ]] || die "$WORK is on tmpfs; the images need a disk"

say "building (release)"
cargo build --release -q -p taso-warden -p taso-sim -p taso-landlock -p taso-blk
for b in taso-wardend taso-sim taso-landlock taso-blkd taso-coordd taso-logcheck; do [[ -x "$BIN/$b" ]] || die "$BIN/$b was not built"; done
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
held() { # held NAME SECONDS: the process reached the armed hold NAME (its marker is there)
    local deadline=$((SECONDS + $2))
    while ((SECONDS < deadline)); do [[ -f "$RUN/hold/$1.held" ]] && return 0; sleep 0.01; done
    return 1
}

thaw_vessels() { # every Vessel mount under $MNT thawed, bounded (a no-op on one not frozen)
    # A Vessel left frozen (the seal.frozen hold, or a Warden killed between
    # its freeze and thaw) blocks every writer in the kernel, unkillably, and
    # an umount of it; its image was taken at the freeze, so a thaw changes
    # nothing the round grades.
    local m; for m in $(findmnt -rn -o TARGET,SOURCE | awk -v r="$MNT" 'index($1, r "/") == 1 && $2 ~ /^\/dev\/ublkb/ { print $1 }'); do
        timeout 5 fsfreeze -u "$m" 2>/dev/null || true
    done
}

teardown() { # every piece of a round, guarded
    set +e
    [[ -n "$WARDEN_PID" ]] && kill -9 "$WARDEN_PID" 2>/dev/null; WARDEN_PID=
    [[ -n "$BLKD_PID" ]] && { kill -9 "$BLKD_PID" 2>/dev/null; wait "$BLKD_PID" 2>/dev/null; }; BLKD_PID=
    local p; for p in "${TK_PIDS[@]}"; do kill -9 "$p" 2>/dev/null; wait "$p" 2>/dev/null; done; TK_PIDS=()
    [[ -n "$COORD_PID" ]] && { kill -9 "$COORD_PID" 2>/dev/null; wait "$COORD_PID" 2>/dev/null; }; COORD_PID=
    local rr; for rr in "$RUN"/run/runc "$RUN"/run-*/runc; do
        [[ -d "$rr" ]] || continue
        # A takeover round pauses A's containers: resumed first, so the kill reaches them.
        for c in $(runc --root "$rr" list -q 2>/dev/null); do runc --root "$rr" resume "$c" 2>/dev/null; runc --root "$rr" delete --force "$c" 2>/dev/null; done
    done
    thaw_vessels
    for m in $(awk -v r="$MNT" '$5 == r || index($5, r "/") == 1 { print length($5), $5 }' /proc/self/mountinfo | sort -rn | cut -d' ' -f2-); do
        [[ "$m" == "$MNT" ]] || umount "$m" 2>/dev/null || umount -l "$m" 2>/dev/null
    done
    mountpoint -q "$D" && { umount "$D" 2>/dev/null || umount -l "$D"; }
    [[ -n "$LOOP2" ]] && losetup -d "$LOOP2" 2>/dev/null; LOOP2=
    # And every loop over a file of ours, remembered or not (the leak above).
    for l in $(losetup -j "$WORK/rebirth.img" 2>/dev/null | cut -d: -f1; losetup -a 2>/dev/null | grep -F "$WORK/" | cut -d: -f1); do losetup -d "$l" 2>/dev/null; done
    dmsetup info "$DEVNAME" >/dev/null 2>&1 && "$DEVSH" down "$DEVNAME" >/dev/null 2>&1
    rm -f "$WORK/dev.img" "$WORK/rebirth.img" "$SOCK" "$COORD_SOCK" "$RUN/blkb.sock" "$RUN/blkc.sock"
    rm -rf "$RUN/run" "$RUN"/run-* "$RUN/read" "$RUN/hold" "$HDIR"
    KNOWN=" "
    set -e
}
trap 'teardown' EXIT

config() { # config SUBJECT [OUT [OVERRIDES]] -> OUT ($RUN/w.json)
    # OVERRIDES (JSON, takeover rounds): top-level keys replaced; "takeover"
    # goes to the Vessel's entry, "child" adds the forked child's entry.
    python3 -I - "$1" "$D" "$RUN" "$MNT" "$ROOTFS" "$SOCK" "$ROWS" "${3:-null}" >"${2:-$RUN/w.json}" <<'PY'
import json, sys
subject, d, run, mnt, rootfs, sock, rows, over = sys.argv[1:]
cfg = {
    "warden": 1, "coordinator": {"local": d + "/coord.redb"}, "root": "e3/r",
    "storage": {"blk": {"socket": sock, "mounts": mnt, "spool": d + "/spool"}},
    "state_dir": d + "/state", "store": d + "/store", "prefix": "vessels", "run_dir": run + "/run",
    "batched_snapshots": True,
    "runtime": {"rootfs": rootfs, "host_uid_base": 200000, "landlock_shim": "/usr/lib/taso/landlock",
                "args": ["/usr/bin/taso-sim", "--step", "/tmp/e3", "--rows", rows, "--row-bytes", "512",
                         "--synchronous", "full", "--db", "/work/state.db", "--stats", "/work/sim-stats.json"],
                "memory_bytes": 268435456, "pids": 64},
    "vessels": [{"namespace": "e3" * 16, "subject": subject, "uid_slot": 1, "forks": {"slots": [2]}}],
}
o = json.loads(over) or {}
takeover, child = o.pop("takeover", None), o.pop("child", None)
also = o.pop("also", None)   # E3-c2: a second Vessel (slot 3; slot 2 is the first's fork slot)
if also:
    cfg["vessels"].append({"namespace": "e3" * 16, "subject": also["subject"], "uid_slot": 3,
                           **({"takeover": also["takeover"]} if also.get("takeover") else {})})
cfg.update(o)
if takeover:
    cfg["vessels"][0]["takeover"] = takeover
if child:   # after its parent: parent before child (P3 C6)
    # The node takes the existing child over and forks nothing new, so the parent's
    # entry reserves no fork slot (a slot both reserved and a Vessel's is refused at
    # start: "fork slot 2 is also <child>'s", taso-test 2026-10-29).
    cfg["vessels"][0].pop("forks", None)
    cfg["vessels"].append({"namespace": "e3" * 16, "subject": child["subject"], "uid_slot": 2,
                           "fork": {"parent": subject, "seal": child["seal"]}, "takeover": child["takeover"]})
print(json.dumps(cfg, indent=1))
PY
}
start_stack() { # start_stack TAG [VAR=VALUE ...]: taso-blkd and the Warden on $D, with the env given; logs $R/*-TAG.err
    # A killed taso-blkd leaves its socket file; the Warden must wait for the
    # new one to *answer*, not for the file (taso-test 2026-10-28: six rounds
    # lost that race, "taso-blkd socket: Connection refused").
    rm -f "$SOCK"
    env "${@:2}" "$BIN/taso-blkd" "$D/blk.log" "$SOCK" 2>>"$R/blkd-$1.err" & BLKD_PID=$!
    local i; for i in $(seq 600); do blk_raw stats >/dev/null 2>&1 && break; sleep 0.1; done
    blk_raw stats >/dev/null 2>&1 || return 1
    env "${@:2}" "$BIN/taso-wardend" "$RUN/w.json" >"$R/warden-$1.out" 2>"$R/warden-$1.err" & WARDEN_PID=$!
}

# ── E3-4: the takeover round's other nodes ────────────────────────────
# One-pager rev. 6 § E3-4; spec D97.  Every process here is in TK_PIDS or
# COORD_PID, so teardown reaches it; every wait is bounded.
coord_up() { # the coordinator, its redb and the pack store under $HDIR (never cut)
    mkdir -p "$HDIR/store"; rm -f "$COORD_SOCK"
    "$BIN/taso-coordd" "$HDIR/coord.redb" "$COORD_SOCK" 2>>"$R/coordd.err" & COORD_PID=$!
    local i; for i in $(seq 100); do [[ -S "$COORD_SOCK" ]] && return 0; sleep 0.05; done
    return 1
}
tk_over() { # tk_over WARDEN NODE TAKEOVER CHILD -> the config overrides of node NODE (b, c) under $HDIR
    python3 -I - "$@" "$COORD_SOCK" "$HDIR" "$RUN" "$MNT" <<'PY'
import json, sys
w, n, takeover, child, coord, h, run, mnt = sys.argv[1:]
print(json.dumps({"warden": int(w), "coordinator": {"remote": coord}, "root": "e3/" + n,
                  "storage": {"blk": {"socket": f"{run}/blk{n}.sock", "mounts": f"{mnt}/{n}", "spool": f"{h}/{n}/spool"}},
                  "state_dir": f"{h}/{n}/state", "store": f"{h}/store", "run_dir": f"{run}/run-{n}",
                  "takeover": json.loads(takeover), "child": json.loads(child)}))
PY
}
start_node() { # start_node TAG CONFIG BLKLOG SOCKET: another node's taso-blkd and Warden -> NODE_W; logs $R/*-TAG.*
    local SOCK=$4 i
    rm -f "$SOCK"; mkdir -p "$(dirname "$3")"
    "$BIN/taso-blkd" "$3" "$SOCK" 2>>"$R/blkd-$1.err" & TK_PIDS+=($!)
    for i in $(seq 600); do blk_raw stats >/dev/null 2>&1 && break; sleep 0.1; done
    blk_raw stats >/dev/null 2>&1 || return 1
    "$BIN/taso-wardend" "$2" >"$R/warden-$1.out" 2>"$R/warden-$1.err" & NODE_W=$!; TK_PIDS+=("$NODE_W")
}
node_down() { # node_down SOCKET MOUNT_ROOT RUNC_ROOT [WARDEN_PID]: the Warden killed, its containers deleted,
              # every mount under MOUNT_ROOT gone (innermost first), its taso-blkd told to quit (its devices detached)
    local SOCK=$1 m c i
    [[ -n "${4:-}" ]] && { kill -9 "$4" 2>/dev/null; wait "$4" 2>/dev/null; }
    for c in $(runc --root "$3" list -q 2>/dev/null); do runc --root "$3" resume "$c" 2>/dev/null; runc --root "$3" delete --force "$c" 2>/dev/null; done
    for m in $(awk -v r="$2" '$5 == r || index($5, r "/") == 1 { print length($5), $5 }' /proc/self/mountinfo | sort -rn | cut -d' ' -f2-); do
        umount "$m" 2>/dev/null || umount -l "$m" 2>/dev/null
    done
    blk_raw quit >/dev/null 2>&1 || true
    for i in $(seq 100); do [[ -S "$SOCK" ]] || return 0; sleep 0.1; done
    return 1
}
drain_node() { # drain_node TAG SOCKET SUBJECT WARDEN_PID: every agent of that Warden told `exit`; the Vessel's own
               # agent's turn taken -> DRAIN_DS, DRAIN_RESUME, DRAIN_WHY; fails if the Warden is still up after 180 s
    local SOCK=$2 subject=$3 deadline=$((SECONDS + 180)) a info pdev work
    DRAIN_DS=; DRAIN_RESUME=; DRAIN_WHY="no agent of Warden $1 came up"
    while ((SECONDS < deadline)) && kill -0 "$4" 2>/dev/null; do
        [[ -n "$DRAIN_DS" ]] || DRAIN_DS=$(grep -m1 -o "\] $subject: dataset .*" "$R/warden-$1.err" 2>/dev/null | sed 's/.*: dataset //' || true)
        if wait_agent 1; then
            a=$AGENT
            [[ -n "$DRAIN_DS" ]] || DRAIN_DS=$(grep -m1 -o "\] $subject: dataset .*" "$R/warden-$1.err" 2>/dev/null | sed 's/.*: dataset //' || true)
            [[ -n "$DRAIN_DS" ]] || DRAIN_WHY="agent $a came up before Warden $1 named the Vessel's dataset"
            if [[ -n "$DRAIN_DS" && -z "$DRAIN_RESUME" ]]; then
                info=$(blk info "$(blk find "$DRAIN_DS")" 2>&1) || true
                pdev=$(sed -n 's/.* dev=\(\/dev\/[^ ]*\).*/\1/p' <<<"$info")
                work=$(findmnt -N "$a" -no MAJ:MIN /work 2>/dev/null | tr -d '[:space:]' || true)
                if [[ -n "$pdev" && -n "$work" && "$work" == "$(stat -c '%Hr:%Lr' "$pdev")" ]]; then
                    DRAIN_RESUME=$(ready_turn "$a"); DRAIN_WHY=
                else
                    DRAIN_WHY="agent $a: /work on ${work:-nothing}, the branch's device ${pdev:-none}${pdev:+ is $(stat -c '%Hr:%Lr' "$pdev" 2>/dev/null)}; taso-blkd: ${info:-no answer}"
                fi
            fi
            step "$a" exit 30 >/dev/null || true
        fi
    done
    kill -0 "$4" 2>/dev/null && return 1
    [[ -n "$DRAIN_DS" ]] || DRAIN_DS=$(grep -m1 -o "\] $subject: dataset .*" "$R/warden-$1.err" 2>/dev/null | sed 's/.*: dataset //' || true)
    return 0
}
gather_none() { # gather_none TAG SUBJECT -> a.json for a Warden that named no dataset for the Vessel (it never ran it)
    python3 -I - "$2" "$R/warden-$1.out" "$R/warden-$1.err" "$R/blkd-$1.err" <<'PY'
import json, os, sys
subject, out, err = sys.argv[1:4]
lines = lambda f: open(f, errors="replace").read().splitlines() if os.path.exists(f) else []
said = next((l[len(subject) + 2:] for l in lines(out) if l.startswith(subject + ": ")), None) \
    or next((l for l in lines(err) if l.startswith("taso-wardend:")), None)   # e.g. "taso-wardend: <config>: config: ..."
report = "".join(open(f, errors="replace").read() for f in sys.argv[3:] if os.path.exists(f))
print(json.dumps({"seals": [], "forks": [], "report": report, "resume_turn": None,
                  "resume_why": "the Warden named no dataset for the Vessel", "acks_after_error": 0,
                  "opened": False, "not_run": said or "no dataset line, and no word why"}, indent=1))
PY
}
packs_list() { # packs_list OUT: every pack file in the store, "sha256  path", sorted
    (cd "$HDIR/store" && find . -path '*/pack/*' -type f -print0 | sort -z | xargs -0 -r sha256sum) >"$1"
}
is_ack() { # is_ack OP REPLY: the reply acknowledges the op
    case "$1" in
        seal) [[ -n "$(jget "$2" sealed)" ]] ;;
        effect) [[ "$(jget "$2" result)" == released ]] ;;
        fork) [[ -n "$(jget "$2" child)" ]] ;;
        *) [[ -n "$(jget "$2" rows)" ]] ;;
    esac
}
owner_of() { python3 -I -c 'import json,sys; o=json.load(open(sys.argv[1]))["ownership"]; print(json.dumps({"holder": o["holder"], "epoch": o["epoch"]}))' "$1"; }

takeover_tail() { # E3-4, the rest of a takeover round from the point on; round's locals in scope
    local ds id owner shipped childj=null cds cid cseal t0 ms c op acks=0 fenced wb wc a_ok=true
    local -a thaw=()
    # Read as an operator would, just before the point: who holds the Vessel
    # (B's takeover names exactly that) and the shipped anchor (line 1, D97).
    ds=$(grep -m1 -o "\] $subject: dataset .*" "$R/warden-1.err" | sed 's/.*: dataset //')
    [[ -n "$ds" ]] || { echo "HARNESS $tag: no dataset line for $subject in warden-1.err"; return; }
    id=${ds##*/v-}
    "$BIN/taso-logcheck" "$COORD_SOCK" "$D/state" "$id" >"$R/a-logcheck.json" 2>"$R/a-logcheck.err" \
        || { echo "HARNESS $tag: taso-logcheck of A's Vessel: $(head -c 200 "$R/a-logcheck.err")"; return; }
    owner=$(owner_of "$R/a-logcheck.json"); shipped=$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["shipped"]["lsn"])' "$R/a-logcheck.json")
    if [[ -n "$child" ]]; then
        cds=$(grep -m1 -o "\] $child: dataset .*" "$R/warden-1.err" | sed 's/.*: dataset //')
        cseal=$(grep -m1 -o "forked \"$child\" .* at Seal lsn [0-9]*" "$R/warden-1.err" | grep -o '[0-9]*$' || true)
        [[ -n "$cds" && -n "$cseal" ]] || { echo "HARNESS $tag: the child $child's dataset or fork Seal is not in warden-1.err"; return; }
        cid=${cds##*/v-}
        "$BIN/taso-logcheck" "$COORD_SOCK" "$D/state" "$cid" >"$R/a-child-logcheck.json" 2>>"$R/a-logcheck.err" \
            || { echo "HARNESS $tag: taso-logcheck of the child $child"; return; }
        childj="{\"subject\": \"$child\", \"seal\": $cseal, \"takeover\": $(owner_of "$R/a-child-logcheck.json")}"
    fi
    # 3. the point: A's disk drops, and A falls silent -- frozen, not killed.
    t0=$(date +%s%N); "$DEVSH" "$mode" "$DEVNAME" >/dev/null; ms=$(( ($(date +%s%N) - t0) / 1000000 ))
    kill -STOP "$WARDEN_PID" "$BLKD_PID" 2>/dev/null || true
    for c in $(runc --root "$RUN/run/runc" list -q 2>/dev/null); do runc --root "$RUN/run/runc" pause "$c" 2>>"$R/harness.err" || true; done
    # shellcheck disable=SC2086
    oracle cut "$O" --swap-ms "$ms" $missed $held_flag
    # 4. Warden B takes the Vessel over from the coordinator and the store (the child after it).
    mkdir -p "$HDIR/b/state" "$HDIR/b/spool" "$MNT/b"
    config "$subject" "$RUN/w-b.json" "$(tk_over 2 b "$owner" "$childj")" || { echo "HARNESS $tag: B's config"; return; }
    start_node 2 "$RUN/w-b.json" "$HDIR/b/blk.log" "$RUN/blkb.sock" || { echo "HARNESS $tag: B's taso-blkd did not start"; return; }
    wb=$NODE_W
    drain_node 2 "$RUN/blkb.sock" "$subject" "$wb" || { echo "HARNESS $tag: Warden B did not finish in 180 s"; return; }
    if [[ -n "$DRAIN_DS" ]]; then
        SOCK=$RUN/blkb.sock GATHER_TAG=2 gather "$subject" "$DRAIN_DS" "$DRAIN_RESUME" 0 "$mode" "$DRAIN_WHY" "" >"$R/a.json" \
            || { echo "HARNESS $tag: gather from B"; return; }
    else
        gather_none 2 "$subject" >"$R/a.json"
    fi
    node_down "$RUN/blkb.sock" "$MNT/b" "$RUN/run-b/runc" || echo "B's taso-blkd did not quit" >>"$R/harness.err"
    packs_list "$R/packs-before.txt"
    # 5. A wakes up believing it holds the Vessel: one Seal and one effect asked (line F).
    [[ -n "$hname" ]] && : >"$RUN/hold/$hname.release"
    for c in $(runc --root "$RUN/run/runc" list -q 2>/dev/null); do runc --root "$RUN/run/runc" resume "$c" 2>>"$R/harness.err" || true; done
    kill -CONT "$BLKD_PID" "$WARDEN_PID" 2>/dev/null || true
    if [[ -n "$inflight" ]]; then   # the held op's own reply, if it comes now
        if reply "$P" 30; then
            thaw+=("held ${ops[-1]}: $REPLY"); is_ack "${ops[-1]}" "$REPLY" && acks=$((acks + 1))
        else
            thaw+=("held ${ops[-1]}: no reply ($WHY)"); a_ok=false   # the agent is still inside it: nothing more to ask
        fi
    fi
    if [[ "$a_ok" == true ]]; then
        for op in seal effect; do
            if step "$P" "$op" 30; then
                thaw+=("$op: $REPLY"); is_ack "$op" "$REPLY" && acks=$((acks + 1))
            else
                thaw+=("$op: no reply ($WHY)"); break
            fi
        done
    fi
    # The Warden's own line when fenced (decided 2026-10-29, (a)): "<vessel>: fenced: <request> refused, ...".
    fenced=$(grep -m1 -hoE '.{0,80}(: fenced: |Fenced|StaleEpoch|stale epoch|EpochMismatch|NotHolder|not the holder).{0,80}' "$R/warden-1.err" "$R/warden-1.out" 2>/dev/null || true)
    printf '%s\n' "${thaw[@]}" >"$R/thaw.txt"
    node_down "$SOCK" "$MNT/e3" "$RUN/run/runc" "$WARDEN_PID" || echo "A's taso-blkd did not quit" >>"$R/harness.err"
    WARDEN_PID=; kill -9 "$BLKD_PID" 2>/dev/null; wait "$BLKD_PID" 2>/dev/null; BLKD_PID=
    packs_list "$R/packs-after.txt"
    # 6. Warden C takes over from B and rebuilds from the store once more (line H1).
    if [[ -n "$DRAIN_DS" ]] && "$BIN/taso-logcheck" "$COORD_SOCK" "$HDIR/b/state" "$id" >"$R/b-logcheck.json" 2>"$R/b-logcheck.err"; then
        mkdir -p "$HDIR/c/state" "$HDIR/c/spool" "$MNT/c"
        config "$subject" "$RUN/w-c.json" "$(tk_over 3 c "$(owner_of "$R/b-logcheck.json")" null)" || { echo "HARNESS $tag: C's config"; return; }
        start_node 3 "$RUN/w-c.json" "$HDIR/c/blk.log" "$RUN/blkc.sock" || { echo "HARNESS $tag: C's taso-blkd did not start"; return; }
        wc=$NODE_W
        drain_node 3 "$RUN/blkc.sock" "$subject" "$wc" || { echo "HARNESS $tag: Warden C did not finish in 180 s"; return; }
        if [[ -n "$DRAIN_DS" ]]; then
            SOCK=$RUN/blkc.sock GATHER_TAG=3 gather "$subject" "$DRAIN_DS" "$DRAIN_RESUME" 0 "$mode" "$DRAIN_WHY" "" >"$R/c.json" \
                || { echo "HARNESS $tag: gather from C"; return; }
        else
            gather_none 3 "$subject" >"$R/c.json"
        fi
        node_down "$RUN/blkc.sock" "$MNT/c" "$RUN/run-c/runc" || echo "C's taso-blkd did not quit" >>"$R/harness.err"
    else
        echo '{"skipped": "B never ran the Vessel, or its ownership could not be read"}' >"$R/c.json"
    fi
    # What the oracle needs beyond the reborn Warden's own (lines 1, F, H; 5a).
    python3 -I - "$R" "$owner" "$shipped" "$childj" "$acks" "$fenced" "${child:-}" <<'PY'
import json, os, re, sys
r, owner, shipped, childj, acks, fenced, child = sys.argv[1:]
packs = lambda f: dict(reversed(l.split(None, 1)) for l in open(os.path.join(r, f)).read().splitlines() if l.strip())
before, after = packs("packs-before.txt"), packs("packs-after.txt")
a = json.load(open(os.path.join(r, "a.json")))
ch = None
if child:
    err = open(os.path.join(r, "warden-2.err"), errors="replace").read()
    out = open(os.path.join(r, "warden-2.out"), errors="replace").read() if os.path.exists(os.path.join(r, "warden-2.out")) else ""
    said = next((l[len(child) + 2:] for l in out.splitlines() if l.startswith(child + ": ")), None)
    ch = dict(json.loads(childj), ran=bool(re.search(rf" {re.escape(child)}: (Opened\(|reborn at epoch)", err)), refused=said)
a["takeover"] = {
    "owner": json.loads(owner), "shipped_lsn": int(shipped), "child": ch,
    "thaw": {"acks": int(acks), "replies": open(os.path.join(r, "thaw.txt")).read().splitlines(), "fenced": fenced or None},
    "packs": {"added": sorted(set(after) - set(before)), "changed": sorted(n for n in before if n in after and after[n] != before[n]),
              "gone": sorted(set(before) - set(after))},
    "after_thaw": json.load(open(os.path.join(r, "c.json"))),
}
json.dump(a, open(os.path.join(r, "a.json"), "w"), indent=1)
PY
    oracle check "$O" --after "$R/a.json" || true
}

# ── E3-c2: two Vessels, their Seals overlapping at the point ──────────
# Design claude/Taso_design_e3_c2_2026-10-30.md rev. 2.  Each Vessel has
# its own oracle record (r-a.json, r-b.json) and its own gather (a-a.json,
# a-b.json), graded by the serial oracle's lines unchanged; the rows carry
# the Vessel's write tag (a: 0, b: 2), and a Seal holding the other's rows
# never equals a promise (C1).  An acknowledgement is a reply the harness
# read before the swap began (c-a); which Vessels a hold held is read from
# the replies (c-h): a Vessel with no reply at the cut is in flight.
vessel_of() { # vessel_of PID DS... -> the index of the dataset whose device is the agent's /work
    local p=$1 i=0 d info pdev work; shift
    work=$(findmnt -N "$p" -no MAJ:MIN /work 2>/dev/null | tr -d '[:space:]' || true)
    [[ -n "$work" ]] || return 1
    for d in "$@"; do
        info=$(blk info "$(blk find "$d")" 2>&1) || true
        pdev=$(sed -n 's/.* dev=\(\/dev\/[^ ]*\).*/\1/p' <<<"$info")
        if [[ -n "$pdev" && "$work" == "$(stat -c '%Hr:%Lr' "$pdev" 2>/dev/null)" ]]; then echo "$i"; return 0; fi
        i=$((i + 1))
    done
    return 1
}
burst_round() { # burst_round "SEQ" POINT MODE: round's tag and $R in scope; the merged line on stdout
    local seq=$1 point=$2 mode=$3 rest shape what hname="" delay=0 base ms v op rep lsn i deadline a out rc tk="" opoint
    rest=${point#burst:}; shape=${rest%%:*}; what=${rest#*:}
    case "$what" in
        timing+*) delay=${what#timing+} ;;
        hold+*) hname=${what#hold+} ;;
        takeover) tk=1 ;;
        takeover+*) tk=1; hname=${what#takeover+} ;;
        *) echo "HARNESS $tag: unknown burst point $what"; return ;;
    esac
    base="e3-$(date +%s%N | tail -c 9)"
    local -a bsubj=("$base-a" "$base-b") bwtag=(0 2) BO=("$R/r-a.json" "$R/r-b.json") BP=() bturn=() bds=() backs=(0 0) \
        brep=("" "") bres=("" "") bwhy=("no agent of the reborn Warden came up" "no agent of the reborn Warden came up") henv=() bout=() bmissed=() \
        brc=(0 0) bheld=()
    opoint=$point; [[ -n "$tk" ]] && opoint="takeover:$point"   # the oracle grades a takeover by what was shipped (D97)
    for v in 0 1; do
        oracle new "${BO[v]}" --sequence "$seq write seal" --point "$opoint" --mode "$mode" --rows "$ROWS"
    done
    if [[ -n "$hname" ]]; then
        rm -rf "$RUN/hold"; mkdir -p "$RUN/hold"
        henv=("TASO_E3_HOLD=$hname" "TASO_E3_HOLD_DIR=$RUN/hold")
    fi
    # 1. the device, the stack, the two agents (which is which: by the device under /work)
    "$DEVSH" make "$DEVNAME" "$WORK/dev.img" "$SIZE_MIB" >/dev/null || { echo "HARNESS $tag: make"; return; }
    mkfs.ext4 -q -F "/dev/mapper/$DEVNAME" && mkdir -p "$D" && mount -o errors=remount-ro "/dev/mapper/$DEVNAME" "$D" \
        || { echo "HARNESS $tag: mkfs or mount of the device"; return; }
    mkdir -p "$D/store" "$D/state" "$D/spool" "$RUN/run"
    if [[ -n "$tk" ]]; then
        # E3-4 x 2: the coordinator and the pack store shared by every node, never on the cut device.
        coord_up || { echo "HARNESS $tag: taso-coordd did not start (see $R/coordd.err)"; return; }
        config "${bsubj[0]}" "$RUN/w.json" "{\"coordinator\": {\"remote\": \"$COORD_SOCK\"}, \"store\": \"$HDIR/store\", \"also\": {\"subject\": \"${bsubj[1]}\"}}" \
            || { echo "HARNESS $tag: config"; return; }
    else
        config "${bsubj[0]}" "$RUN/w.json" "{\"also\": {\"subject\": \"${bsubj[1]}\"}}" || { echo "HARNESS $tag: config"; return; }
    fi
    start_stack 1 "${henv[@]}" || { echo "HARNESS $tag: taso-blkd did not start"; return; }
    deadline=$((SECONDS + 120))
    while ((SECONDS < deadline)) && [[ -z "${bds[0]:-}" || -z "${bds[1]:-}" ]]; do
        for v in 0 1; do bds[v]=$(grep -m1 -o "\] ${bsubj[v]}: dataset .*" "$R/warden-1.err" 2>/dev/null | sed 's/.*: dataset //' || true); done
        sleep 0.1
    done
    [[ -n "${bds[0]:-}" && -n "${bds[1]:-}" ]] || { echo "HARNESS $tag: the Warden named no dataset for both Vessels (see $R/warden-1.err)"; return; }
    for i in 1 2; do
        wait_agent 120 || { echo "HARNESS $tag: agent $i of 2 did not come up (see $R/warden-1.err)"; return; }
        v=$(vessel_of "$AGENT" "${bds[0]}" "${bds[1]}") || { echo "HARNESS $tag: agent $AGENT is on neither Vessel's device"; return; }
        BP[v]=$AGENT; bturn[v]=$(( $(ready_turn "$AGENT") + 1 ))
    done
    [[ -n "${BP[0]:-}" && -n "${BP[1]:-}" ]] || { echo "HARNESS $tag: both agents are on one Vessel"; return; }
    # 2. the prefix, one Vessel after the other, each op waited for
    wr() { [[ ${bwtag[$1]} == 0 ]] && echo write || echo "write ${bwtag[$1]}"; }
    for v in 0 1; do
        for op in $seq; do
            oracle requested "${BO[v]}" "$op" turn="${bturn[v]}"
            if [[ "$op" == write ]]; then
                step "${BP[v]}" "$(wr "$v")" || { echo "HARNESS $tag: ${bsubj[v]}'s write got no reply: $WHY"; return; }; rep=$REPLY
                oracle acknowledged "${BO[v]}" write turn="$(jget "$rep" turn)" rows="$(jget "$rep" rows)"
            else
                step "${BP[v]}" seal || { echo "HARNESS $tag: ${bsubj[v]}'s seal got no reply: $WHY"; return; }; rep=$REPLY
                lsn=$(jget "$rep" sealed)
                oracle acknowledged "${BO[v]}" seal turn="$(jget "$rep" turn)" ${lsn:+seal=$lsn}
                bturn[v]=$(( $(jget "$rep" turn) + 1 ))
            fi
        done
    done
    # 3. the burst: both writes, then both Seals without waiting
    for v in 0 1; do
        oracle requested "${BO[v]}" write turn="${bturn[v]}"
        step "${BP[v]}" "$(wr "$v")" || { echo "HARNESS $tag: ${bsubj[v]}'s burst write got no reply: $WHY"; return; }; rep=$REPLY
        oracle acknowledged "${BO[v]}" write turn="$(jget "$rep" turn)" rows="$(jget "$rep" rows)"
    done
    [[ -n "$hname" ]] && : >"$RUN/hold/$hname.arm"
    for v in 0 1; do oracle requested "${BO[v]}" seal turn="${bturn[v]}"; done
    send "${BP[0]}" seal || { echo "HARNESS $tag: the op file could not be written"; return; }
    [[ "$shape" == stagger ]] && sleep "$(python3 -I -c "print($STAGGER_MS / 1000)")"
    send "${BP[1]}" seal || { echo "HARNESS $tag: the op file could not be written"; return; }
    # 4. the point
    if [[ -n "$hname" ]]; then
        held "$hname" 10 || { echo "HARNESS $tag: the hold was never reached"; return; }
    elif [[ -n "$tk" ]]; then   # takeover at the boundary: both burst Seals answered first
        for v in 0 1; do
            reply "${BP[v]}" 60 || { echo "HARNESS $tag: ${bsubj[v]}'s burst seal got no reply: $WHY"; return; }; rep=$REPLY
            lsn=$(jget "$rep" sealed); brep[v]=1
            oracle acknowledged "${BO[v]}" seal turn="$(jget "$rep" turn)" ${lsn:+seal=$lsn}
        done
    else
        sleep "$(python3 -I -c "print($delay / 1000)")"
    fi
    # What was acknowledged is what was read before the swap began (c-a).
    for v in 0 1; do
        if [[ -f /proc/${BP[v]}/root/tmp/e3/reply.${NEXT[${BP[v]}]} ]]; then
            reply "${BP[v]}" 5 || { echo "HARNESS $tag: ${bsubj[v]}'s reply vanished: $WHY"; return; }; rep=$REPLY
            lsn=$(jget "$rep" sealed); brep[v]=1
            oracle acknowledged "${BO[v]}" seal turn="$(jget "$rep" turn)" ${lsn:+seal=$lsn}
        fi
    done
    if [[ -z "$hname" && -n "${brep[0]}" && -n "${brep[1]}" ]]; then bmissed=(--missed); fi
    [[ -n "$hname" ]] && bheld=(--held "$hname")
    if [[ -n "$tk" ]]; then burst_tk_tail; return; fi
    local t0; t0=$(date +%s%N); "$DEVSH" "$mode" "$DEVNAME" >/dev/null; ms=$(( ($(date +%s%N) - t0) / 1000000 ))
    for v in 0 1; do oracle cut "${BO[v]}" --swap-ms "$ms" "${bmissed[@]}" "${bheld[@]}"; done
    echo "held (no reply at the cut): $(for v in 0 1; do [[ -n "${brep[v]}" ]] || printf '%s ' "${bsubj[v]}"; done)" >"$R/held.txt"
    if [[ "$mode" == error ]]; then
        [[ -n "$hname" ]] && : >"$RUN/hold/$hname.release"
        for v in 0 1; do   # the in-flight Seal's own answer, after the error
            if [[ -z "${brep[v]}" ]] && reply "${BP[v]}" 10 && [[ -n "$(jget "$REPLY" sealed)" ]]; then backs[v]=$((backs[v] + 1)); fi
        done
    fi
    [[ "$hname" == seal.frozen ]] && thaw_vessels
    if [[ "$mode" == error ]]; then
        for v in 0 1; do
            if step "${BP[v]}" seal 30 && [[ -n "$(jget "$REPLY" sealed)" ]]; then backs[v]=$((backs[v] + 1)); fi
            if step "${BP[v]}" "$(wr "$v")" 10 && [[ -n "$(jget "$REPLY" rows)" ]]; then backs[v]=$((backs[v] + 1)); fi
        done
    fi
    # 5. dead at the point; the image; the rebirth on a copy
    kill -9 "$WARDEN_PID" 2>/dev/null || true; kill -9 "$BLKD_PID" 2>/dev/null || true
    wait "$BLKD_PID" 2>/dev/null || true; WARDEN_PID=; BLKD_PID=
    if ! "$DEVSH" image "$DEVNAME" "$RUN" "$R/image.raw" >"$R/image.txt" 2>&1; then
        echo "HARNESS $tag: image ($(tail -1 "$R/image.txt"))"; return
    fi
    if ! { cp --sparse=always "$R/image.raw" "$WORK/rebirth.img" && LOOP2=$(losetup -f --show "$WORK/rebirth.img") && mount "$LOOP2" "$D"; } 2>"$R/rebirth.err"; then
        echo "HARNESS $tag: the rebirth copy could not be mounted: $(tr '\n' ' ' <"$R/rebirth.err")"; return
    fi
    mkdir -p "$RUN/run"; KNOWN=" $(pgrep -x taso-sim | tr '\n' ' ') "
    start_stack 2 || { echo "HARNESS $tag: taso-blkd did not start on the image"; return; }
    deadline=$((SECONDS + 180))
    while ((SECONDS < deadline)) && kill -0 "$WARDEN_PID" 2>/dev/null; do
        if wait_agent 1; then
            a=$AGENT
            if v=$(vessel_of "$a" "${bds[0]}" "${bds[1]}"); then bres[v]=$(ready_turn "$a"); bwhy[v]=
            else bwhy=("agent $a on neither Vessel's device" "agent $a on neither Vessel's device"); fi
            step "$a" exit 30 >/dev/null || true
        fi
    done
    if kill -0 "$WARDEN_PID" 2>/dev/null; then echo "HARNESS $tag: the reborn Warden did not finish in 180 s"; return; fi
    WARDEN_PID=
    if grep -q "^taso-wardend: starting:" "$R/warden-2.err"; then
        echo "HARNESS $tag: the reborn Warden did not start: $(grep -m1 "^taso-wardend: starting:" "$R/warden-2.err" | cut -c22-)"; return
    fi
    # 6. each Vessel graded on its own; one line for the round
    for v in 0 1; do
        GATHER_OWN_TAG=${bwtag[v]} GATHER_ONLY=${bsubj[v]} gather "${bsubj[v]}" "${bds[v]}" "${bres[v]}" "${backs[v]}" "$mode" "${bwhy[v]}" "" \
            >"$R/a-$v.json" || { echo "HARNESS $tag: gather of ${bsubj[v]}"; return; }
        rc=0; out=$(oracle check "${BO[v]}" --after "$R/a-$v.json") || rc=$?
        bout[v]=$out; brc[v]=$rc
    done
    burst_line "$tag" "${brc[0]}" "${brc[1]}" "${bout[0]}" "${bout[1]}"
}
tk_drain() { # tk_drain TAG SOCKET WARDEN_PID: every agent of that Warden told `exit` -> TD_DS, TD_RES, TD_WHY per Vessel (burst_round's bsubj)
    local SOCK=$2 deadline=$((SECONDS + 180)) a v
    TD_DS=("" ""); TD_RES=("" ""); TD_WHY=("no agent of Warden $1 came up" "no agent of Warden $1 came up")
    while ((SECONDS < deadline)) && kill -0 "$3" 2>/dev/null; do
        for v in 0 1; do
            [[ -n "${TD_DS[v]}" ]] || TD_DS[v]=$(grep -m1 -o "\] ${bsubj[v]}: dataset .*" "$R/warden-$1.err" 2>/dev/null | sed 's/.*: dataset //' || true)
        done
        if wait_agent 1; then
            a=$AGENT
            # The agent may come up before its Warden names the dataset: read the names again
            # now, or the agent matches neither (taso-test 2026-10-30: b's resume never taken).
            for v in 0 1; do
                [[ -n "${TD_DS[v]}" ]] || TD_DS[v]=$(grep -m1 -o "\] ${bsubj[v]}: dataset .*" "$R/warden-$1.err" 2>/dev/null | sed 's/.*: dataset //' || true)
            done
            if v=$(vessel_of "$a" "${TD_DS[0]:-none}" "${TD_DS[1]:-none}"); then TD_RES[v]=$(ready_turn "$a"); TD_WHY[v]=
            else echo "Warden $1's agent $a: on neither Vessel's device" >>"$R/harness.err"; fi
            step "$a" exit 30 >/dev/null || true
        fi
    done
    kill -0 "$3" 2>/dev/null && return 1
    for v in 0 1; do
        [[ -n "${TD_DS[v]}" ]] || TD_DS[v]=$(grep -m1 -o "\] ${bsubj[v]}: dataset .*" "$R/warden-$1.err" 2>/dev/null | sed 's/.*: dataset //' || true)
    done
    return 0
}
tk_two() { # tk_two WARDEN NODE OWNER_A OWNER_B -> the overrides of node NODE taking both Vessels over
    python3 -I - "$(tk_over "$1" "$2" "$3" null)" "${bsubj[1]}" "$4" <<'PY'
import json, sys
o = json.loads(sys.argv[1]); o["also"] = {"subject": sys.argv[2], "takeover": json.loads(sys.argv[3])}
print(json.dumps(o))
PY
}
burst_tk_tail() { # E3-c2 x E3-4: the rest of a two-Vessel takeover round from the point on; burst_round's locals in scope
    local v t0 ms c wb wc op ok
    local -a ids=() owners=() shipped=() acks=(0 0) fenced=("" "") thaw=() bids=() bowners=()
    # Read as an operator would, just before the point: each Vessel's holder and shipped anchor.
    for v in 0 1; do
        ids[v]=${bds[v]##*/v-}
        "$BIN/taso-logcheck" "$COORD_SOCK" "$D/state" "${ids[v]}" >"$R/a-logcheck-$v.json" 2>>"$R/a-logcheck.err" \
            || { echo "HARNESS $tag: taso-logcheck of ${bsubj[v]} on A: $(head -c 200 "$R/a-logcheck.err")"; return; }
        owners[v]=$(owner_of "$R/a-logcheck-$v.json")
        shipped[v]=$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["shipped"]["lsn"])' "$R/a-logcheck-$v.json")
    done
    # The point: A's disk drops, and A falls silent -- frozen, not killed.
    t0=$(date +%s%N); "$DEVSH" "$mode" "$DEVNAME" >/dev/null; ms=$(( ($(date +%s%N) - t0) / 1000000 ))
    kill -STOP "$WARDEN_PID" "$BLKD_PID" 2>/dev/null || true
    for c in $(runc --root "$RUN/run/runc" list -q 2>/dev/null); do runc --root "$RUN/run/runc" pause "$c" 2>>"$R/harness.err" || true; done
    for v in 0 1; do oracle cut "${BO[v]}" --swap-ms "$ms" "${bheld[@]}"; done
    echo "held (no reply at the cut): $(for v in 0 1; do [[ -n "${brep[v]}" ]] || printf '%s ' "${bsubj[v]}"; done)" >"$R/held.txt"
    # Warden B takes both Vessels over from the coordinator and the store.
    mkdir -p "$HDIR/b/state" "$HDIR/b/spool" "$MNT/b"
    config "${bsubj[0]}" "$RUN/w-b.json" "$(tk_two 2 b "${owners[0]}" "${owners[1]}")" || { echo "HARNESS $tag: B's config"; return; }
    start_node 2 "$RUN/w-b.json" "$HDIR/b/blk.log" "$RUN/blkb.sock" || { echo "HARNESS $tag: B's taso-blkd did not start"; return; }
    wb=$NODE_W
    tk_drain 2 "$RUN/blkb.sock" "$wb" || { echo "HARNESS $tag: Warden B did not finish in 180 s"; return; }
    for v in 0 1; do
        if [[ -n "${TD_DS[v]}" ]]; then
            SOCK=$RUN/blkb.sock GATHER_TAG=2 GATHER_OWN_TAG=${bwtag[v]} GATHER_ONLY=${bsubj[v]} \
                gather "${bsubj[v]}" "${TD_DS[v]}" "${TD_RES[v]}" 0 "$mode" "${TD_WHY[v]}" "" >"$R/a-$v.json" \
                || { echo "HARNESS $tag: gather of ${bsubj[v]} from B"; return; }
            bids[v]=${TD_DS[v]##*/v-}
        else
            gather_none 2 "${bsubj[v]}" >"$R/a-$v.json"
        fi
    done
    node_down "$RUN/blkb.sock" "$MNT/b" "$RUN/run-b/runc" || echo "B's taso-blkd did not quit" >>"$R/harness.err"
    packs_list "$R/packs-before.txt"
    # A wakes up believing it holds both: each agent's in-flight Seal answered, then one Seal and one effect (line F).
    [[ -n "$hname" ]] && : >"$RUN/hold/$hname.release"
    for c in $(runc --root "$RUN/run/runc" list -q 2>/dev/null); do runc --root "$RUN/run/runc" resume "$c" 2>>"$R/harness.err" || true; done
    kill -CONT "$BLKD_PID" "$WARDEN_PID" 2>/dev/null || true
    for v in 0 1; do
        thaw=(); ok=true
        if [[ -z "${brep[v]}" ]]; then
            if reply "${BP[v]}" 30; then thaw+=("held seal: $REPLY"); is_ack seal "$REPLY" && acks[v]=$((acks[v] + 1))
            else thaw+=("held seal: no reply ($WHY)"); ok=false; fi
        fi
        if [[ "$ok" == true ]]; then
            for op in seal effect; do
                if step "${BP[v]}" "$op" 30; then thaw+=("$op: $REPLY"); is_ack "$op" "$REPLY" && acks[v]=$((acks[v] + 1))
                else thaw+=("$op: no reply ($WHY)"); break; fi
            done
        fi
        printf '%s\n' "${thaw[@]}" >"$R/thaw-$v.txt"
        fenced[v]=$(grep -h -F "${bsubj[v]}" "$R/warden-1.err" "$R/warden-1.out" 2>/dev/null \
            | grep -m1 -oE '.{0,80}(: fenced: |Fenced|StaleEpoch|stale epoch|EpochMismatch|NotHolder|not the holder).{0,80}' || true)
    done
    node_down "$SOCK" "$MNT/e3" "$RUN/run/runc" "$WARDEN_PID" || echo "A's taso-blkd did not quit" >>"$R/harness.err"
    WARDEN_PID=; kill -9 "$BLKD_PID" 2>/dev/null; wait "$BLKD_PID" 2>/dev/null; BLKD_PID=
    packs_list "$R/packs-after.txt"
    # Warden C takes both over from B and rebuilds from the store once more (line H1).
    ok=true
    for v in 0 1; do
        if [[ -n "${bids[v]:-}" ]] && "$BIN/taso-logcheck" "$COORD_SOCK" "$HDIR/b/state" "${bids[v]}" >"$R/b-logcheck-$v.json" 2>>"$R/b-logcheck.err"; then
            bowners[v]=$(owner_of "$R/b-logcheck-$v.json")
        else ok=false; fi
    done
    if [[ "$ok" == true ]]; then
        mkdir -p "$HDIR/c/state" "$HDIR/c/spool" "$MNT/c"
        config "${bsubj[0]}" "$RUN/w-c.json" "$(tk_two 3 c "${bowners[0]}" "${bowners[1]}")" || { echo "HARNESS $tag: C's config"; return; }
        start_node 3 "$RUN/w-c.json" "$HDIR/c/blk.log" "$RUN/blkc.sock" || { echo "HARNESS $tag: C's taso-blkd did not start"; return; }
        wc=$NODE_W
        tk_drain 3 "$RUN/blkc.sock" "$wc" || { echo "HARNESS $tag: Warden C did not finish in 180 s"; return; }
        for v in 0 1; do
            if [[ -n "${TD_DS[v]}" ]]; then
                SOCK=$RUN/blkc.sock GATHER_TAG=3 GATHER_OWN_TAG=${bwtag[v]} GATHER_ONLY=${bsubj[v]} \
                    gather "${bsubj[v]}" "${TD_DS[v]}" "${TD_RES[v]}" 0 "$mode" "${TD_WHY[v]}" "" >"$R/c-$v.json" \
                    || { echo "HARNESS $tag: gather of ${bsubj[v]} from C"; return; }
            else
                gather_none 3 "${bsubj[v]}" >"$R/c-$v.json"
            fi
        done
        node_down "$RUN/blkc.sock" "$MNT/c" "$RUN/run-c/runc" || echo "C's taso-blkd did not quit" >>"$R/harness.err"
    else
        for v in 0 1; do echo '{"skipped": "B never ran both Vessels, or an ownership could not be read"}' >"$R/c-$v.json"; done
    fi
    # Each Vessel's takeover facts (lines 1, F, H), graded on its own; one line for the round.
    for v in 0 1; do
        python3 -I - "$R" "$v" "${owners[v]}" "${shipped[v]}" "${acks[v]}" "${fenced[v]}" <<'PY'
import json, os, sys
r, v, owner, shipped, acks, fenced = sys.argv[1:]
packs = lambda f: dict(reversed(l.split(None, 1)) for l in open(os.path.join(r, f)).read().splitlines() if l.strip())
before, after = packs("packs-before.txt"), packs("packs-after.txt")
p = os.path.join(r, f"a-{v}.json"); a = json.load(open(p))
a["takeover"] = {
    "owner": json.loads(owner), "shipped_lsn": int(shipped), "child": None,
    "thaw": {"acks": int(acks), "replies": open(os.path.join(r, f"thaw-{v}.txt")).read().splitlines(), "fenced": fenced or None},
    "packs": {"added": sorted(set(after) - set(before)), "changed": sorted(n for n in before if n in after and after[n] != before[n]),
              "gone": sorted(set(before) - set(after))},
    "after_thaw": json.load(open(os.path.join(r, f"c-{v}.json"))),
}
json.dump(a, open(p, "w"), indent=1)
PY
        rc=0; out=$(oracle check "${BO[v]}" --after "$R/a-$v.json") || rc=$?
        bout[v]=$out; brc[v]=$rc
    done
    burst_line "$tag" "${brc[0]}" "${brc[1]}" "${bout[0]}" "${bout[1]}"
}
burst_line() { # burst_line TAG RC_A RC_B LINES_A LINES_B: FAIL if either failed; MISSED only if both were; else PASS
    local t=$1 v l notes=""
    local -a rc=("$2" "$3") out=("$4" "$5") name=(a b)
    if [[ ${rc[0]} == 1 || ${rc[1]} == 1 ]]; then
        echo "FAIL    $t"
        for v in 0 1; do
            [[ ${rc[v]} == 1 ]] || continue
            while IFS= read -r l; do [[ "$l" == "        "* ]] && echo "        ${name[v]}: ${l#        }"; done <<<"${out[v]}"
        done
    elif [[ ${rc[0]} == 2 && ${rc[1]} == 2 ]]; then
        echo "MISSED  $t: both Seals had replied before the swap; not covered"
    else
        for v in 0 1; do
            l=$(head -1 <<<"${out[v]}"); [[ "$l" == *"("*")" ]] && notes="$notes${name[v]}: ${l#*(}"; notes=${notes%)}; [[ "$l" == *"("*")" ]] && notes="$notes; "
        done
        echo "PASS    $t${notes:+ (${notes%; })}"
    fi
}

# ── one round ─────────────────────────────────────────────────────────
round() { # round "SEQ" POINT MODE -> the oracle's line on stdout; the round's files in $R
    local seq=$1 point=$2 mode=$3 subject O="$R/r.json"
    subject="e3-$(date +%s%N | tail -c 9)"
    local kind=${point%%:*} at=${point#*:} k delay=0 P C child="" turn rep lsn ms missed="" acks_err=0 ct cr hname="" held_flag="" log_ino="" tk="" inflight=""
    local -a ops henv=(); read -ra ops <<<"$seq"
    if [[ "$kind" == takeover ]]; then
        # E3-4: the point is a boundary or a shipping hold, driven as those are;
        # what follows the point is takeover_tail's.
        tk=1
        if [[ "$at" =~ ^[0-9]+$ ]]; then kind=boundary; else kind=hold; fi
    fi
    if [[ "$kind" == hold ]]; then
        # The held op is the last one; compact.written holds a `compact` sent after it.
        hname=$at; k=${#ops[@]}; [[ "$hname" == compact.written ]] && k=$((k + 1))
        held_flag="--held $hname"
        rm -rf "$RUN/hold"; mkdir -p "$RUN/hold"
        henv=("TASO_E3_HOLD=$hname" "TASO_E3_HOLD_DIR=$RUN/hold")
    else
        k=${at%%+*}; [[ "$at" == *+* ]] && delay=${at#*+}
    fi
    local tag="[$seq] $point $mode"
    if [[ "$kind" == burst ]]; then burst_round "$seq" "$point" "$mode"; return; fi
    oracle new "$O" --sequence "$seq" --point "$point" --mode "$mode" --rows "$ROWS"
    # 1. the device, the stack, the agent
    "$DEVSH" make "$DEVNAME" "$WORK/dev.img" "$SIZE_MIB" >/dev/null || { echo "HARNESS $tag: make"; return; }
    mkfs.ext4 -q -F "/dev/mapper/$DEVNAME" && mkdir -p "$D" && mount -o errors=remount-ro "/dev/mapper/$DEVNAME" "$D" \
        || { echo "HARNESS $tag: mkfs or mount of the device"; return; }
    mkdir -p "$D/store" "$D/state" "$D/spool" "$RUN/run"
    if [[ -n "$tk" ]]; then
        # E3-4: the coordinator and the pack store are shared by every node, never on the cut device.
        coord_up || { echo "HARNESS $tag: taso-coordd did not start (see $R/coordd.err)"; return; }
        config "$subject" "$RUN/w.json" "{\"coordinator\": {\"remote\": \"$COORD_SOCK\"}, \"store\": \"$HDIR/store\"}" \
            || { echo "HARNESS $tag: config"; return; }
    else
        config "$subject" || { echo "HARNESS $tag: config"; return; }
    fi
    start_stack 1 "${henv[@]}" || { echo "HARNESS $tag: taso-blkd did not start"; return; }
    wait_agent 120 || { echo "HARNESS $tag: no agent came up (see $R/warden-1.err)"; return; }; P=$AGENT
    turn=$(( $(ready_turn "$P") + 1 ))
    # 2. the operations, to the point
    local i=0 op
    for op in "${ops[@]}"; do
        i=$((i + 1))
        if [[ "$kind" == hold && $i == "$k" ]]; then
            # Arm, send without waiting, cut once held.  The oracle hears the
            # request as for any op; a reply already there (seal.shipped: the
            # publish runs after the reply) is heard as its acknowledgement.
            case "$op" in
                write|seal) oracle requested "$O" "$op" turn="$turn" ;;
                *) oracle requested "$O" "$op" ;;
            esac
            : >"$RUN/hold/$hname.arm"
            send "$P" "$op" || { echo "HARNESS $tag: the op file could not be written"; return; }
            held "$hname" 10 || { echo "HARNESS $tag: the hold was never reached"; return; }
            inflight=1
            if [[ -f /proc/$P/root/tmp/e3/reply.${NEXT[$P]} ]]; then
                reply "$P" 5 || { echo "HARNESS $tag: the reply vanished: $WHY"; return; }; rep=$REPLY; inflight=
                if [[ "$op" == seal && -n "$(jget "$rep" sealed)" ]]; then
                    oracle acknowledged "$O" seal turn="$(jget "$rep" turn)" seal="$(jget "$rep" sealed)"
                else
                    echo "HARNESS $tag: $op replied before its hold was reached: $rep"; return
                fi
            fi
            break
        fi
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
    if [[ "$hname" == compact.written ]]; then
        # taso-blkd's compaction, held before its rename; the client waits until the kill closes it.
        # The log's inode now: the rename would make the temp file the log (a new inode); the
        # rebirth copy keeps inode numbers, so after it the log must still be this one.
        log_ino=$(stat -c %i "$D/blk.log")
        : >"$RUN/hold/$hname.arm"
        blk_raw compact >"$R/compact.out" 2>&1 &
        held "$hname" 10 || { echo "HARNESS $tag: the hold was never reached (compact said: $(cat "$R/compact.out"))"; return; }
    fi
    if [[ -n "$tk" ]]; then takeover_tail; return; fi
    # 3. the point
    local t0; t0=$(date +%s%N); "$DEVSH" "$mode" "$DEVNAME" >/dev/null; ms=$(( ($(date +%s%N) - t0) / 1000000 ))
    # shellcheck disable=SC2086
    oracle cut "$O" --swap-ms "$ms" $missed $held_flag
    # At a hold under error: release it, so the held op runs on into the
    # failing device; its answer, if one comes, counts as any other
    # acknowledgement after the error (bounded, 10 s).
    if [[ "$mode" == error && "$kind" == hold ]]; then
        REPLY=; : >"$RUN/hold/$hname.release"
        if [[ "$hname" == compact.written ]]; then
            local w; for w in $(seq 100); do [[ -s "$R/compact.out" ]] && break; sleep 0.1; done
            [[ "$(cat "$R/compact.out" 2>/dev/null)" == ok* ]] && acks_err=$((acks_err + 1))
        elif [[ "$hname" != seal.shipped ]] && reply "$P" 10; then   # seal.shipped: its reply came before the hold
            case "${ops[-1]}" in
                seal) [[ -n "$(jget "$REPLY" sealed)" ]] && acks_err=$((acks_err + 1)) ;;
                effect) [[ "$(jget "$REPLY" result)" == released ]] && acks_err=$((acks_err + 1)) ;;
                fork) [[ -n "$(jget "$REPLY" child)" ]] && acks_err=$((acks_err + 1)) ;;
            esac
        fi
        printf '%s\n' "${REPLY:-}" >"$R/held-reply.json"
    fi
    # seal.frozen: the Warden's own thaw (under error, released) has answered
    # or is still held (under drop); whatever it did, the Vessel is thawed
    # now, or its agent's next write could never be killed.  Which thaw path
    # the Warden took is kept for reading (3570b49's: the Seal made, the
    # thaw failed).
    if [[ "$hname" == seal.frozen ]]; then
        grep -iE 'thaw|frozen' "$R/warden-1.err" "$R/warden-1.out" 2>/dev/null >"$R/thaw.txt" || echo "no thaw failure in the Warden's log" >"$R/thaw.txt"
        thaw_vessels
    fi
    # Provoke the error, bounded; count what was acknowledged after it.
    if [[ "$mode" == error ]]; then
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
    local ds pdev resume="" deadline=$((SECONDS + 180)) a work info resume_why="no agent of the reborn Warden came up"
    ds=$(grep -m1 -o "\] $subject: dataset .*" "$R/warden-1.err" | sed 's/.*: dataset //')
    [[ -n "$ds" ]] || { echo "HARNESS $tag: no dataset line for $subject in warden-1.err"; return; }
    while ((SECONDS < deadline)) && kill -0 "$WARDEN_PID" 2>/dev/null; do
        if wait_agent 1; then
            a=$AGENT
            # Is this agent the Vessel's?  Its /work must be on the branch's device.
            # Asked with `info`, which changes nothing (an `attach` started a device
            # when there was none); every reason not to take its turn is recorded.
            info=$(blk info "$(blk find "$ds")" 2>&1) || true
            pdev=$(sed -n 's/.* dev=\(\/dev\/[^ ]*\).*/\1/p' <<<"$info")
            work=$(findmnt -N "$a" -no MAJ:MIN /work 2>/dev/null | tr -d '[:space:]' || true)
            if [[ -n "$pdev" && -n "$work" && "$work" == "$(stat -c '%Hr:%Lr' "$pdev")" ]]; then
                resume=$(ready_turn "$a"); resume_why=
            elif [[ -z "$resume" ]]; then
                resume_why="agent $a: /work on ${work:-nothing}, the branch's device ${pdev:-none}${pdev:+ is $(stat -c '%Hr:%Lr' "$pdev" 2>/dev/null)}; taso-blkd: ${info:-no answer}"
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
    gather "$subject" "$ds" "$resume" "$acks_err" "$mode" "$resume_why" "$log_ino" >"$R/a.json" || { echo "HARNESS $tag: gather"; return; }
    oracle check "$O" --after "$R/a.json" || true
}

gather() { # gather SUBJECT DATASET RESUME ACKS_ERR MODE RESUME_WHY LOG_INO_BEFORE -> a.json on stdout
    # The reborn Warden's logs are $R/*-$GATHER_TAG.* (2; a takeover round's C is 3), its taso-blkd at $SOCK.
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
        seals="$seals$(python3 -I - "$tmp/db/state.db" "$lsn" "$ok" "${birth:-0}" "${GATHER_OWN_TAG:-0}" <<'PY'
import json, os, sqlite3, sys
db, lsn, ok, birth, own = sys.argv[1], int(sys.argv[2]), sys.argv[3] == "true", int(sys.argv[4]), int(sys.argv[5])
rows = {}
if os.path.exists(db):
    c = sqlite3.connect(db)
    try:
        # n = TAG * 1 000 000 + i: the Vessel's own tag as plain turns, a fork's child (1) as "cT",
        # any other tag as "x<TAG>:T" -- another Vessel's rows (E3-c2, C1), never equal to a promise.
        for tag, turn, n in c.execute("SELECT n / 1000000, turn, count(*) FROM events GROUP BY 1, 2"):
            k = str(turn) if tag == own else f"c{turn}" if tag == 1 else f"x{tag}:{turn}"
            rows[k] = rows.get(k, 0) + n
    except sqlite3.OperationalError:
        pass
print(json.dumps({"lsn": lsn, "birth": lsn == birth, "export_ok": ok, "rows": rows}) + ",")
PY
)"
    done
    local forks report
    forks=$(cat "$R/warden-1.err" "$R/warden-2.err" 2>/dev/null | grep -o "\] $subject-fork-[0-9]*: dataset " | sed 's/^\] //; s/: dataset $//' | sort -u | tr '\n' ' ')
    local gt=${GATHER_TAG:-2}
    report="$R/blkd-$gt.err $R/warden-$gt.err"; [[ "$5" == error ]] && report="$report $R/blkd-1.err $R/warden-1.err"
    # Did the reborn Warden open the Vessel?  Its Opened line on stderr says
    # so; if absent, its own word about the Vessel on stdout says why (a
    # refusal, a failed open).  Without this a Vessel never reborn was graded
    # on taso-blkd's layers alone (F2, 2026-10-28).
    local opened=false not_run=""
    # A Vessel rebuilt from the store says "reborn at epoch" instead (E3-4: B and C).
    grep -qE " $subject: (Opened\(|reborn at epoch)" "$R/warden-$gt.err" 2>/dev/null && opened=true
    [[ "$opened" == true ]] || not_run=$(grep -m1 "^$subject: " "$R/warden-$gt.out" 2>/dev/null | cut -c$((${#subject} + 3))- || true)
    # The log taso-blkd reopened (compact.written: it must be the one from before the held compaction).
    local ino_after=""; [[ -n "$7" ]] && ino_after=$(stat -c %i "$D/blk.log" 2>/dev/null || true)
    # shellcheck disable=SC2086
    python3 -I - "[${seals%,}]" "$forks" "$3" "$4" "$opened" "$not_run" "$6" "$7" "$ino_after" $report <<'PY'
import json, os, sys
seals, forks, resume, acks = json.loads(sys.argv[1]), sys.argv[2].split(), sys.argv[3], int(sys.argv[4])
opened, not_run, resume_why = sys.argv[5] == "true", sys.argv[6], sys.argv[7]
ino = lambda v: int(v) if v else None
only = os.environ.get("GATHER_ONLY")   # E3-c2: the Warden's lines about this Vessel only (taso-blkd's whole)
def lines(f):
    t = open(f, errors="replace").read()
    if only and "/warden-" in f:
        t = "".join(l for l in t.splitlines(True) if only in l)
    return t
report = "".join(lines(f) for f in sys.argv[10:])
print(json.dumps({"seals": seals, "forks": forks, "report": report,
                  "resume_turn": int(resume) if resume else None, "resume_why": resume_why or None,
                  "acks_after_error": acks, "opened": opened, "not_run": not_run or None,
                  "log_inode": {"before": ino(sys.argv[8]), "after": ino(sys.argv[9])} if sys.argv[8] else None}, indent=1))
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
        shift; sub=""; limit=0; only=""
        while (($#)); do case "$1" in --subset) sub=--subset ;; --only) only=$2; shift ;; --limit) limit=$2; shift ;; *) die "run [--subset] [--only KIND] [--limit N]" ;; esac; shift; done
        [[ -z "$only" || "$only" =~ ^(boundary|timing|hold|takeover|burst)$ ]] || die "--only boundary|timing|hold|takeover|burst"
        pick() { manifest "$sub" | { if [[ -n "$only" ]]; then grep -F "|$only:" || true; else cat; fi; }; }
        total=$(pick | wc -l); n=0
        say "$total rounds$( ((limit > 0)) && echo ", the first $limit"); results in $OUT/results.txt"
        while IFS='|' read -r s p m; do
            n=$((n + 1)); ((limit > 0 && n > limit)) && break
            printf '%4d/%d  ' "$n" "$total"; run_one "$n" "$s" "$p" "$m"
        done < <(pick)
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
