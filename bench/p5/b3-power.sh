#!/usr/bin/env bash
# bench/p5/b3-power.sh: B3 of P5, the power-loss test on the metal
# (design claude/Taso_design_b3_2026-10-31.md rev. 1; plan rev. 18 §3 B3;
# claim C2; spec D92, D93).
#
#   sudo bench/p5/b3-power.sh run [PORT]              taso-p5: the Warden and 8 Vessels at work, a witness port open
#        bench/p5/b3-power.sh listener HOST[:PORT]    the laptop: the witness (ends after 10 s of silence)
#   sudo bench/p5/b3-power.sh verify ACKED            taso-p5 after the cut: the rebirth, graded against the witness
#
# From the repository root, as root, on A1's host (taso-p5), apt timers
# stopped.  One round:
#   1 `run`: builds; a fresh work directory on the measured drive ($WORK,
#     the previous one kept beside it as $WORK-<time>); the rootfs and the
#     Warden's config written and SYNCED before any Vessel runs (S2.3's
#     rule: everything the harness writes on the node that will die is
#     synced first); taso-blkd on $WORK/blk.log with upkeep on (a checkpoint
#     every 64 MiB, compaction past 64 MiB of garbage at 30 %), the Warden
#     with $P Vessels whose agents are `taso-sim --step` (synchronous=full);
#     then it waits for the witness on PORT (default 7706).
#   2 `listener` on the laptop connects.  The driver (one thread per
#     Vessel) runs turns: $WRITES writes of $ROWS rows x $ROW_BYTES B, then a
#     Seal.  Before a Seal is sent the witness is told "requested" and must
#     confirm; after every reply the witness is told "acknowledged".  The
#     witness keeps it in ACKED (default ./b3-acked.json, rewritten every
#     second).
#   3 Scaleway console: Stop (a power cut, A2), then Power on.
#   4 a fresh `sudo -i` (tmux died with the machine), ACKED copied over,
#     `verify ACKED`: taso-blkd and the Warden start again on the same $WORK
#     (the same node, reborn), and per Vessel, with R the turn its reborn
#     agent resumes after:
#       line 1  R >= the last Seal acknowledged to the witness
#       line 2  R <= the last Seal requested (confirmed before it was sent)
#       line 3  each turn t <= R has exactly (writes acknowledged in t) x ROWS
#               rows; no turn > R has any (D92: an acknowledged write after
#               the last Seal is in the log, not in the reborn filesystem)
#       line 4  acknowledged writes after turn R => the Warden's line for the
#               Vessel says "reset to the Seal" with blocks discarded (D93 (i))
#       line 5  one more write and Seal acknowledged after the rebirth
#     Recorded, not graded: taso-blkd's recovered line, its checkpoints and
#     compactions, the in-flight Seal (R minus the last acknowledged).
#     PASS only if every line holds on every Vessel; a driver or setup
#     failure is HARNESS, never a pass.  Exit 0 PASS, 1 FAIL, 2 HARNESS.
#
# Touches, and nothing else: $WORK (/var/lib/taso-blk/b3, resolved) and
# $WORK-<time> (earlier rounds, kept), $RUN (/run/taso-b3), $MNT
# (/mnt/taso-b3), the ublk devices of this run's taso-blkd, runc containers
# under $RUN/run; the listener writes ACKED in the laptop's current
# directory.  Refuses to start if a taso-blkd, taso-wardend or taso-sim
# already runs.  Env: B3_VESSELS (8), B3_WRITES (3), B3_ROWS (64),
# B3_ROW_BYTES (1024), B3_PORT (7706), B3_COMPACT_PCT (30); B3_FIRST=DIR for a repeated verify
# of the same round: the cut's recovery and the settle lines (line 4) are
# read from that earlier verify's results, the rebirth that saw the cut.
# Needs python3 (stdlib only) on
# both sides; nsenter (util-linux) and runc on the host.

set -Eeuo pipefail
trap 'printf "ABORT: line %s: %s\n" "$LINENO" "$BASH_COMMAND" >&2' ERR

mode=${1:-}; shift || true
P=${B3_VESSELS:-8}
WRITES=${B3_WRITES:-3}
ROWS=${B3_ROWS:-64}
ROW_BYTES=${B3_ROW_BYTES:-1024}
PORT=${B3_PORT:-7706}
UID_BASE=200000
die() { printf 'REFUSED: %s\n' "$*" >&2; exit 2; }
say() { printf '== %s %s\n' "$(date +%H:%M:%S)" "$*"; }

# ── the laptop: the witness ──────────────────────────────────────────
if [[ "$mode" == listener ]]; then
    target=${1:-}; [[ -n "$target" ]] || die "usage: $0 listener HOST[:PORT] [ACKED]"
    host=${target%%:*}; port=$PORT; [[ "$target" == *:* ]] && port=${target##*:}
    exec python3 -I - "$host" "$port" "${2:-./b3-acked.json}" <<'PY'
import json, os, socket, sys, time
host, port, path = sys.argv[1], int(sys.argv[2]), sys.argv[3]
s = socket.create_connection((host, port), timeout=30)
s.settimeout(10)   # silence for 10 s ends the witness: a receiver never learns its peer lost power
f = s.makefile("r")
w = {"hello": None, "vessels": {}, "lines": 0, "started": time.time(), "last": None}
def v(i): return w["vessels"].setdefault(i, {"writes": {}, "seal_requested": 0, "seal_acked": 0, "errors": []})
def save():
    tmp = path + ".tmp"
    with open(tmp, "w") as o: json.dump(w, o, indent=1, sort_keys=True)
    os.replace(tmp, path)
last_save, why = 0.0, "?"
while True:
    try:
        line = f.readline()
    except (socket.timeout, TimeoutError):
        why = "10 s without a line (the host went quiet: a cut, or the end)"; break
    except OSError as e:
        why = f"the connection failed: {e}"; break
    if not line:
        why = "the host closed the connection"; break
    p = line.split()
    w["lines"] += 1; w["last"] = time.time()
    if p[0] == "hello":
        w["hello"] = {"vessels": int(p[1]), "writes": int(p[2]), "rows": int(p[3]), "host_commit": p[4]}
    elif p[0] == "req" and p[1] == "s":            # req s I T ID: a Seal about to be sent
        v(p[2])["seal_requested"] = max(v(p[2])["seal_requested"], int(p[3]))
        s.sendall(f"ok {p[4]}\n".encode())         # confirmed: only now does the host send it
    elif p[0] == "ack" and p[1] == "w":            # ack w I T K: write K of turn T acknowledged
        ws = v(p[2])["writes"]; ws[p[3]] = max(ws.get(p[3], 0), int(p[4]))
    elif p[0] == "ack" and p[1] == "s":            # ack s I T: the Seal of turn T acknowledged
        v(p[2])["seal_acked"] = max(v(p[2])["seal_acked"], int(p[3]))
    elif p[0] == "err":
        v(p[1])["errors"].append(" ".join(p[2:]))
    now = time.time()
    if now - last_save >= 1:
        save(); last_save = now
        acked = sum(x["seal_acked"] for x in w["vessels"].values())
        print(time.strftime("%H:%M:%S"), f"{len(w['vessels'])} Vessels, Seals acknowledged {acked}, lines {w['lines']}", flush=True)
save()
acked = {i: x["seal_acked"] for i, x in sorted(w["vessels"].items())}
print(f"witness ended: {why}")
print(f"Seals acknowledged per Vessel: {acked}")
print(f"saved to {os.path.abspath(path)}: copy it to the host for verify")
PY
fi

# ── the host ─────────────────────────────────────────────────────────
[[ $EUID -eq 0 ]] || die "run as root (sudo -i first)"
[[ "$mode" == run || "$mode" == verify ]] || die "usage: $0 run [PORT] | listener HOST[:PORT] [ACKED] | verify ACKED"
[[ -f bench/p5/b3-power.sh ]] || die "run from the repository root"
for t in runc nsenter python3 cargo fsfreeze; do command -v "$t" >/dev/null || die "$t is missing"; done
modprobe ublk_drv; [[ -c /dev/ublk-control ]] || die "/dev/ublk-control missing"
[[ -d /var/lib/taso-blk ]] || die "/var/lib/taso-blk is missing (A1's setup makes it)"
WORK=$(readlink -f /var/lib/taso-blk)/b3
RUN=/run/taso-b3
MNT=/mnt/taso-b3
SOCK=$RUN/blk.sock
BIN=$PWD/target/release
ROOTFS=$WORK/rootfs
CFG=$WORK/w.json
COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo '?')
# B3_COMPACT_PCT: rounds 1-3 (30) never compacted: the Warden keeps every
# Seal, so garbage stayed at 3.4 % of the log (taso-p5, 2026-10-31).
COMPACT_PCT=${B3_COMPACT_PCT:-30}
[[ "$COMPACT_PCT" =~ ^[0-9]+$ ]] && (( COMPACT_PCT <= 99 )) || die "B3_COMPACT_PCT=$COMPACT_PCT: 0 to 99"
BLKD_FLAGS=(--checkpoint-mib 64 --compact-pct "$COMPACT_PCT" --compact-min-mib 64)
for p in taso-blkd taso-wardend taso-sim; do
    ! pgrep -x "$p" >/dev/null || die "a $p is already running (pgrep -x $p): not ours to share"
done
BLKD_PID=; WARDEN_PID=

blk_raw() {
    python3 -I -c '
import socket, sys
s = socket.socket(socket.AF_UNIX); s.settimeout(30); s.connect(sys.argv[1])
s.sendall((" ".join(sys.argv[2:]) + "\n").encode()); print(s.makefile().readline().strip())' "$SOCK" "$@"
}
start_stack() { # start_stack TAG: taso-blkd and the Warden on $WORK; logs $WORK/{blkd,warden}-TAG.*
    mkdir -p "$RUN" "$MNT"; rm -f "$SOCK"
    "$BIN/taso-blkd" "$WORK/blk.log" "$SOCK" "${BLKD_FLAGS[@]}" 2>>"$WORK/blkd-$1.err" & BLKD_PID=$!
    local i; for i in $(seq 600); do blk_raw stats >/dev/null 2>&1 && break; sleep 0.1; done
    blk_raw stats >/dev/null 2>&1 || die "taso-blkd did not answer (see $WORK/blkd-$1.err)"
    "$BIN/taso-wardend" "$CFG" >"$WORK/warden-$1.out" 2>"$WORK/warden-$1.err" & WARDEN_PID=$!
}
stop_stack() { # the Warden, its containers, the mounts, taso-blkd; guarded
    # Failures here are expected (a process already gone, a mount already
    # off): no ERR trap inside, so no ABORT lines that are not aborts.
    trap - ERR; set +e
    [[ -n "$WARDEN_PID" ]] && { kill "$WARDEN_PID" 2>/dev/null; for _ in $(seq 100); do kill -0 "$WARDEN_PID" 2>/dev/null || break; sleep 0.1; done; kill -9 "$WARDEN_PID" 2>/dev/null; }
    WARDEN_PID=
    for c in $(runc --root "$RUN/run/runc" list -q 2>/dev/null); do runc --root "$RUN/run/runc" delete --force "$c" 2>/dev/null; done
    for m in $(findmnt -rn -o TARGET | awk -v r="$MNT" 'index($1, r "/") == 1' | sort -r); do
        timeout 5 fsfreeze -u "$m" 2>/dev/null; umount "$m" 2>/dev/null || umount -l "$m" 2>/dev/null
    done
    [[ -n "$BLKD_PID" ]] && { blk_raw quit >/dev/null 2>&1; for _ in $(seq 100); do kill -0 "$BLKD_PID" 2>/dev/null || break; sleep 0.1; done; kill -9 "$BLKD_PID" 2>/dev/null; }
    BLKD_PID=
    set -e; trap 'printf "ABORT: line %s: %s\n" "$LINENO" "$BASH_COMMAND" >&2' ERR
}

# The driver: finds the agents, maps each to its Vessel by its host uid
# (host_uid_base + uid_slot x 65536; slot i+1 is Vessel i), and talks to
# each through its --step channel (E3-3a): an op file written as the
# namespace's root (nsenter -U: root's own create fails EOVERFLOW in the
# agent's tmpfs, taso-test 2026-10-27), a reply file read and removed.
DRIVER=$(cat <<'PY'
import json, os, re, socket, sqlite3, subprocess, sys, threading, time
UID_BASE, RANGE, STEP = 200000, 65536, "/tmp/b3"

def agents(want, seconds, known=()):
    """{vessel index: pid} for `want` agents whose step channel is ready."""
    found, until = {}, time.time() + seconds
    while time.time() < until:
        for d in os.listdir("/proc"):
            if not d.isdigit() or int(d) in known:
                continue
            try:
                if open(f"/proc/{d}/comm").read().strip() != "taso-sim":
                    continue
                if not os.path.exists(f"/proc/{d}/root{STEP}/ready"):
                    continue
                uid = int(next(l for l in open(f"/proc/{d}/status") if l.startswith("Uid:")).split()[1])
            except (OSError, StopIteration, ValueError):
                continue
            found[(uid - UID_BASE) // RANGE - 1] = int(d)
        if len(found) >= want:
            return found
        time.sleep(0.1)
    return found

class Agent:
    def __init__(self, pid):
        self.pid, self.n = pid, 1
        self.ready = json.loads(open(f"/proc/{pid}/root{STEP}/ready").read())
    def step(self, op, seconds=120):
        d, n = f"/proc/{self.pid}/root{STEP}", self.n
        r = subprocess.run(["nsenter", "-t", str(self.pid), "-U", "-S", "0", "-G", "0", "--", "sh", "-c",
                            f"cat >'{d}/.op.{n}' && mv '{d}/.op.{n}' '{d}/op.{n}'"],
                           input=op + "\n", text=True, capture_output=True)
        if r.returncode:
            raise RuntimeError(f"op {op!r}: the op file could not be written: {r.stderr.strip()}")
        f, until = f"{d}/reply.{n}", time.time() + seconds
        while time.time() < until:
            try:
                text = open(f).read()
                os.unlink(f)
                self.n += 1
                return json.loads(text)
            except FileNotFoundError:
                if not os.path.isdir(f"/proc/{self.pid}"):
                    raise RuntimeError(f"op {op!r}: the agent (pid {self.pid}) is gone")
                time.sleep(0.005)
        raise RuntimeError(f"op {op!r}: no reply in {seconds} s")

def acked(op, reply):
    """E3's rule (e3-crash.sh is_ack): a write is acknowledged when its
    reply counts rows, a Seal when it names what was sealed."""
    if op.startswith("write"):
        return reply.get("rows") is not None
    return reply.get("sealed") is not None
PY
)

if [[ "$mode" == run ]]; then
    PORT=${1:-$PORT}
    say "B3 run at $COMMIT: $P Vessels, $WRITES writes of $ROWS x $ROW_BYTES B per turn, witness port $PORT"
    say "building (release)"
    cargo build --release -q -p taso-warden -p taso-sim -p taso-landlock -p taso-blk
    for b in taso-wardend taso-sim taso-landlock taso-blkd; do [[ -x "$BIN/$b" ]] || die "$BIN/$b was not built"; done
    if [[ -e "$WORK" ]]; then mv "$WORK" "$WORK-$(date +%Y%m%d-%H%M%S)"; say "the previous round's work kept beside it"; fi
    rm -rf "$RUN"; mkdir -p "$WORK/state" "$WORK/store" "$WORK/spool" "$RUN" "$MNT"
    copy_with_libs() {
        install -D -m 755 "$1" "$ROOTFS$2"
        ldd "$1" | grep -o '/[^ ]*' | while read -r lib; do install -D -m 755 "$lib" "$ROOTFS$lib"; done
    }
    copy_with_libs "$BIN/taso-sim" /usr/bin/taso-sim
    copy_with_libs "$BIN/taso-landlock" /usr/lib/taso/landlock
    mkdir -p "$ROOTFS"/{proc,dev,sys,tmp,work,run/taso}; : >"$ROOTFS/run/taso/field.sock"
    python3 -I - "$CFG" "$WORK" "$RUN" "$MNT" "$ROOTFS" "$SOCK" "$P" "$ROWS" "$ROW_BYTES" <<'PY'
import json, sys
cfg, work, run, mnt, rootfs, sock, p, rows, row_bytes = sys.argv[1:]
json.dump({
    "warden": 1, "coordinator": {"local": work + "/coord.redb"}, "root": "b3/w",
    "storage": {"blk": {"socket": sock, "mounts": mnt, "spool": work + "/spool"}},
    "state_dir": work + "/state", "store": work + "/store", "prefix": "vessels", "run_dir": run + "/run",
    "batched_snapshots": True,
    "runtime": {"rootfs": rootfs, "host_uid_base": 200000, "landlock_shim": "/usr/lib/taso/landlock",
                "args": ["/usr/bin/taso-sim", "--step", "/tmp/b3", "--rows", rows, "--row-bytes", row_bytes,
                         "--synchronous", "full", "--db", "/work/state.db", "--stats", "/work/sim-stats.json"],
                "memory_bytes": 268435456, "pids": 64},
    "vessels": [{"namespace": "b3" * 16, "subject": "b3-v%d" % i, "uid_slot": i + 1} for i in range(int(p))],
}, open(cfg, "w"), indent=1)
PY
    printf '%s\n' "$COMMIT" >"$WORK/commit"
    sync
    say "work directory, rootfs and config synced ($WORK)"
    trap 'stop_stack' EXIT
    start_stack run
    say "taso-blkd (${BLKD_FLAGS[*]}) and the Warden up; waiting for $P agents"
    python3 -I - "$P" "$WRITES" "$PORT" "$COMMIT" "$ROWS" <<PY
$DRIVER
p, writes, port, commit, rows = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3]), sys.argv[4], int(sys.argv[5])
found = agents(p, 300)
if len(found) < p:
    print(f"HARNESS: {len(found)} of {p} agents came up in 300 s: {sorted(found)}", flush=True); sys.exit(2)
ag = {i: Agent(pid) for i, pid in sorted(found.items())}
print(f"== {time.strftime('%H:%M:%S')} {p} agents ready; listening on port {port} for the witness", flush=True)
srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("0.0.0.0", port)); srv.listen(1)
conn, peer = srv.accept()
conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
print(f"== {time.strftime('%H:%M:%S')} witness connected from {peer[0]}; the driver starts", flush=True)
out, oklock, oks, wlock = conn.makefile("r"), threading.Condition(), set(), threading.Lock()
def tell(line):
    with wlock:
        conn.sendall((line + "\n").encode())
def confirmations():
    for l in out:
        q = l.split()
        if len(q) == 2 and q[0] == "ok":
            with oklock:
                oks.add(int(q[1])); oklock.notify_all()
threading.Thread(target=confirmations, daemon=True).start()
tell(f"hello {p} {writes} {rows} {commit}")
ids, idlock, stats = [0], threading.Lock(), {i: [0, 0] for i in ag}
def vessel(i, a):
    turn = (a.ready.get("resumed_after") or 0) + 1
    try:
        while True:
            for k in range(1, writes + 1):
                r = a.step("write")
                if not acked("write", r):
                    tell(f"err {i} write {turn}.{k}: {json.dumps(r)}"); return
                tell(f"ack w {i} {turn} {k}"); stats[i][0] += 1
            with idlock:
                ids[0] += 1; rid = ids[0]
            tell(f"req s {i} {turn} {rid}")
            with oklock:
                if not oklock.wait_for(lambda: rid in oks, timeout=60):
                    tell(f"err {i} the witness did not confirm the Seal of turn {turn}"); return
            r = a.step("seal")
            if not acked("seal", r):
                tell(f"err {i} seal {turn}: {json.dumps(r)}"); return
            tell(f"ack s {i} {turn}"); stats[i][1] += 1
            turn += 1
    except Exception as e:
        try: tell(f"err {i} {e}")
        except OSError: pass
for i, a in ag.items():
    threading.Thread(target=vessel, args=(i, a), daemon=True).start()
start = time.time()
while True:
    time.sleep(10)
    w, s = sum(x[0] for x in stats.values()), sum(x[1] for x in stats.values())
    print(f"   {time.strftime('%H:%M:%S')} +{time.time() - start:.0f} s: {w} writes and {s} Seals acknowledged -- Stop the machine when you like", flush=True)
PY
    exit 0
fi

# ── verify: the rebirth, graded ──────────────────────────────────────
ACKED=${1:-}; [[ -f "$ACKED" ]] || die "usage: $0 verify ACKED (the witness's file, copied from the laptop)"
[[ -f "$CFG" && -f "$WORK/blk.log" ]] || die "no B3 work directory at $WORK (run first)"
RAN=$(cat "$WORK/commit")
# The binaries are the round's ($BIN, built by `run`); the tree may differ
# from the round's commit only in this script.
if [[ "$RAN" != "$COMMIT" ]]; then
    git diff --quiet "$RAN" HEAD -- . ':(exclude)bench/p5/b3-power.sh' \
        || die "the tree is at $COMMIT, the round ran at $RAN, and they differ beyond this script: check out $RAN"
    say "the round ran at $RAN; this tree differs from it only in bench/p5/b3-power.sh"
fi
# B3_FIRST=DIR: an earlier verify of this round (its results directory).
# The first rebirth after the cut is the one that saw it: taso-blkd's
# recovery and the Warden's settle lines (line 4) are read from there.
FIRST=${B3_FIRST:-}
if [[ -n "$FIRST" ]]; then
    [[ -f "$FIRST/blkd-verify.err" && -f "$FIRST/warden-verify.err" ]] \
        || die "B3_FIRST=$FIRST holds no blkd-verify.err and warden-verify.err"
    say "taso-blkd's recovery and the Warden's settle lines from the first rebirth: $FIRST"
fi
OUT=$WORK/verify-$(date +%Y%m%d-%H%M%S); mkdir -p "$OUT"
say "B3 verify at $COMMIT, witness file $ACKED, results in $OUT"
cp "$ACKED" "$OUT/acked.json"
for f in blkd-run.err warden-run.err warden-run.out; do [[ -f "$WORK/$f" ]] && cp "$WORK/$f" "$OUT/" || true; done
trap 'stop_stack' EXIT
start_stack verify
say "taso-blkd and the Warden started on the cut log; waiting for $P agents"
rc=0
python3 -I - "$P" "$ROWS" "$OUT" "$WORK" "$FIRST" <<PY || rc=$?
$DRIVER
import shutil
p, rows, outdir, work, first = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5]
w = json.load(open(outdir + "/acked.json"))
if not w.get("hello"):
    print("HARNESS: the witness file has no hello: it never heard the host"); sys.exit(2)
found = agents(p, 300)
time.sleep(2)   # the Warden's settle lines are written before an agent starts; let stderr land
src = first or work
blkd = open(src + "/blkd-verify.err").read()
warden = open(src + "/warden-verify.err").read()
rec = re.findall(r"recovered .*", blkd)
run_blkd = open(work + "/blkd-run.err").read() if os.path.exists(work + "/blkd-run.err") else ""
lines, verdict = [], 0
if first:
    lines.append(f"recovery and settle lines from the first rebirth after the cut: {first}")
lines.append(f"taso-blkd after the cut: {rec[0] if first and rec else rec[-1] if rec else '(no recovered line: a fresh log?)'}")
lines.append(f"before the cut (as much of taso-blkd's log as survived): {len(re.findall(r'checkpoint at record', run_blkd))} checkpoint(s), {len(re.findall(r'compacted:', run_blkd))} compaction(s)")
for i in range(p):
    x = w["vessels"].get(str(i), {"writes": {}, "seal_requested": 0, "seal_acked": 0, "errors": []})
    a_s, q_s = x["seal_acked"], x["seal_requested"]
    wr = {int(t): k for t, k in x["writes"].items()}
    subj = f"b3-v{i}"
    fails, notes = [], []
    if x["errors"]:
        notes.append(f"driver errors before the cut: {x['errors'][:2]}")
    if i not in found:
        # Not a harness fault: a Vessel the Warden cannot reopen after the
        # cut is the failure B3 looks for (the F2 lesson: a Vessel nobody
        # looked at is no pass).  The Warden's own lines for it say why.
        said = [l.split(": ", 1)[1] for l in warden.splitlines() if l.startswith(f"taso-wardend[1] {subj}: ")]
        verdict = max(verdict, 1)
        lines.append(f"FAIL    v{i}: did not come back: its agent never started in 300 s")
        lines += [f"        1: the Warden said: {l}" for l in said[-4:]] or ["        1: the Warden said nothing about it"]
        continue
    a = Agent(found[i])
    R = a.ready.get("resumed_after") or 0
    # 1, 2: the Seals
    if R < a_s: fails.append(f"1: an acknowledged Seal is lost (resumed after turn {R}, the Seal of turn {a_s} was acknowledged)")
    if R > q_s: fails.append(f"2: a Seal never asked (resumed after turn {R}, the last requested was turn {q_s})")
    # 3: the rows, through the agent's own mount
    # Read from a copy (E3's way: cp state.db*): opened in place through
    # /proc/<pid>/root, SQLite refused (taso-p5, 2026-10-31: "unable to
    # open database file" on all eight).  The agent is idle between ops,
    # so the database and its WAL are copied whole; the -shm is rebuilt.
    src_db, cp_dir = f"/proc/{a.pid}/root/work/state.db", f"{outdir}/db-v{i}"
    try:
        os.makedirs(cp_dir, exist_ok=True)
        for sfx in ("", "-wal"):
            if os.path.exists(src_db + sfx):
                shutil.copyfile(src_db + sfx, f"{cp_dir}/state.db{sfx}")
        db = sqlite3.connect(f"{cp_dir}/state.db", timeout=30)
        have = dict(db.execute("SELECT turn, count(*) FROM events GROUP BY turn").fetchall())
        db.close()
    except (OSError, sqlite3.Error) as e:
        print(f"HARNESS v{i}: its database could not be read: {e}"); verdict = max(verdict, 2); continue
    for t in range(1, R + 1):
        want = wr.get(t, 0) * rows
        if have.get(t, 0) != want:
            fails.append(f"3: turn {t} has {have.get(t, 0)} rows, the witness acknowledged {wr.get(t, 0)} write(s) = {want}")
    beyond = {t: n for t, n in have.items() if t > R}
    if beyond: fails.append(f"3: rows after the last Seal in the reborn filesystem: {beyond}")
    # 4: the loss named
    after = sum(k for t, k in wr.items() if t > R)
    settle = [l for l in warden.splitlines() if l.startswith(f"taso-wardend[1] {subj}: state at") or l.startswith(f"taso-wardend[1] {subj}: no Seal layer")]
    sl = settle[-1].split(": ", 1)[1] if settle else "(no settle line)"
    m = re.search(r"reset to the Seal at lsn \d+: .*?(\d+) block\(s\) of the Vessel's filesystem discarded", sl)
    if after and not (m and int(m.group(1)) > 0):
        fails.append(f"4: {after} acknowledged write(s) after turn {R}, not named: {sl}")
    # 5: life
    try:
        r = a.step("write")
        ok_w = acked("write", r)
        r2 = a.step("seal") if ok_w else r
        if not (ok_w and acked("seal", r2) and r2.get("turn") == R + 1):
            fails.append(f"5: no new turn after the rebirth: {json.dumps(r2)}")
    except RuntimeError as e:
        fails.append(f"5: {e}")
    try: a.step("exit", 30)
    except RuntimeError: pass
    flight = R - a_s
    head = f"v{i}: resumed after turn {R}; Seals acknowledged {a_s}, requested {q_s} (in flight {flight}); acknowledged writes after it {after}; settle: {sl}"
    if fails:
        verdict = max(verdict, 1); lines.append("FAIL    " + head); lines += ["        " + f for f in fails]
    else:
        lines.append("PASS    " + head)
    lines += ["        note: " + n for n in notes]
total = {0: "PASS", 1: "FAIL", 2: "HARNESS"}[verdict]
lines.append(f"== B3 {total}: {p} Vessels; the witness held {sum(v['seal_acked'] for v in w['vessels'].values())} acknowledged Seals, {w['lines']} lines")
open(outdir + "/result.txt", "w").write("\n".join(lines) + "\n")
print("\n".join(lines))
sys.exit(verdict)
PY
stop_stack; trap - EXIT
cp "$WORK/blkd-verify.err" "$WORK/warden-verify.err" "$WORK/warden-verify.out" "$OUT/" 2>/dev/null || true
mkdir -p /home/ubuntu/p5 && cp -r "$OUT" "/home/ubuntu/p5/b3-$(basename "$OUT")" && chown -R ubuntu: /home/ubuntu/p5 2>/dev/null || true
say "results in $OUT (and /home/ubuntu/p5/b3-$(basename "$OUT") for scp)"
echo "B3 DONE"
exit "$rc"
