#!/usr/bin/env bash
# blk-bench.sh: K2-K7 of the block log spike, measured against ext4 on a
# loop device on the same disk.
#
#   sudo scripts/blk-bench.sh [--quick] [path/to/taso-blkd]   (default target/release/taso-blkd)
#
# --quick: small counts and short runs, to try the script (not for numbers).
#
# Needs: fio (apt-get install -y fio), ublk_drv, about 12 GiB free under
# /var/lib/taso-blk.  Takes about 10 minutes (K3 creates 1000 devices).
#
# Touches, and nothing else:
#   /var/lib/taso-blk/bench.log, bench.err, bench-base.img, bench-helper.py,
#                                bench-results.txt   (removed at start, kept after)
#   /run/taso-blk-bench.sock
#   /mnt/blk-bench, /mnt/blk-fork, /mnt/blk-base     (mounted, then unmounted)
#   one loop device for the baseline (detached at the end)
#   /sys/module/ublk_drv/parameters/ublks_max        (raised to 1200 if lower; left raised)
#   this shell's open-file limit (raised for the daemon; ends with the script)
#   the /dev/ublkb* devices the daemon creates for this run
#
# K3 stops early if MemAvailable drops below 1 GiB and reports how far it got.
# The pass/kill lines are the ones in the spike plan (section 2).

set -euo pipefail

QUICK=0
if [[ "${1:-}" == "--quick" ]]; then QUICK=1; shift; fi
BLKD=${1:-target/release/taso-blkd}
DIR=/var/lib/taso-blk
LOG=$DIR/bench.log
ERR=$DIR/bench.err
BASEIMG=$DIR/bench-base.img
HELPER=$DIR/bench-helper.py
RESULTS=$DIR/bench-results.txt
SOCK=/run/taso-blk-bench.sock
MB=/mnt/blk-bench
MF=/mnt/blk-fork
MBASE=/mnt/blk-base

if [[ $QUICK -eq 1 ]]; then
    N_FORK=10; N_BRANCH=20; N_SEAL=10; K4_SMALL=16; K4_BIG=64; K4_SAMPLES=3; FIO_TIME=3; FIO_SIZE=128
else
    N_FORK=100; N_BRANCH=1000; N_SEAL=100; K4_SMALL=64; K4_BIG=1024; K4_SAMPLES=10; FIO_TIME=20; FIO_SIZE=1024
fi

DAEMON_PID=
BASEDEV=

say() { printf '== %s\n' "$*"; }
die() { printf 'ABORT: %s\n' "$*" >&2; exit 2; }
H()   { python3 "$HELPER" "$SOCK" "$@"; }

wait_dev() {
    for _ in $(seq 100); do [[ -b "$1" ]] && return 0; sleep 0.05; done
    die "device $1 did not appear in 5 s"
}

mount_on() {   # mount_on DEV DIR
    mount "$1" "$2"
    [[ "$(findmnt -n -o SOURCE --mountpoint "$2")" == "$1" ]] || die "$2 is not mounted from $1"
}

cleanup() {
    local rc=$?
    set +e
    for m in "$MF" "$MB" "$MBASE"; do
        fsfreeze -u "$m" 2>/dev/null
        mountpoint -q "$m" && umount "$m"
    done
    [[ -n "$BASEDEV" ]] && losetup -d "$BASEDEV"
    if [[ -n "$DAEMON_PID" ]] && kill -0 "$DAEMON_PID" 2>/dev/null; then
        H cmd quit >/dev/null 2>&1 || kill "$DAEMON_PID"
        wait "$DAEMON_PID" 2>/dev/null
    fi
    exit "$rc"
}
trap cleanup EXIT

# ---- preflight -------------------------------------------------------------
[[ $EUID -eq 0 ]] || die "run as root"
[[ -x "$BLKD" ]] || die "no daemon at $BLKD (cargo build --release -p taso-blk)"
command -v fio >/dev/null || die "fio missing: apt-get install -y fio"
if [[ "${BLK_BENCH_NO_UBLK:-}" != 1 ]]; then
    modprobe ublk_drv
    [[ -c /dev/ublk-control ]] || die "/dev/ublk-control missing"
    P=/sys/module/ublk_drv/parameters/ublks_max
    if [[ $(cat "$P") -lt 1200 ]]; then echo 1200 >"$P"; fi
    [[ $(cat "$P") -ge 1200 ]] || die "could not raise ublks_max to 1200 (is $(cat "$P"))"
fi
for m in "$MB" "$MF" "$MBASE"; do
    mkdir -p "$m"
    ! mountpoint -q "$m" || die "$m is already a mount point"
done
mkdir -p "$DIR"
rm -f "$LOG" "$ERR" "$BASEIMG" "$HELPER" "$RESULTS"
FREE_GIB=$(( $(df --output=avail -k "$DIR" | tail -n 1) / 1048576 ))
NEED_GIB=$([[ $QUICK -eq 1 ]] && echo 2 || echo 12)
[[ $FREE_GIB -ge $NEED_GIB ]] || die "only ${FREE_GIB} GiB free under $DIR, need $NEED_GIB"

cat >"$HELPER" <<'PY'
"""bench helper: python3 HELPER SOCK MODE ARGS..."""
import fcntl, json, os, socket, statistics, sys, threading, time

FIFREEZE, FITHAW = 0xC0045877, 0xC0045878

class Daemon:
    def __init__(self, path):
        self.s = socket.socket(socket.AF_UNIX); self.s.settimeout(120); self.s.connect(path)
        self.f = self.s.makefile("rw")
    def cmd(self, *words):
        self.f.write(" ".join(words) + "\n"); self.f.flush()
        a = self.f.readline().strip()
        if a != "ok" and not a.startswith("ok "):
            raise SystemExit(f"daemon: {' '.join(words)} -> {a}")
        return a[3:]
    def stats(self):
        return dict(kv.split("=", 1) for kv in self.cmd("stats").split())

def wait_block(dev, limit=10.0):
    t = time.perf_counter()
    while True:
        try:
            if os.stat(dev).st_mode & 0o170000 == 0o060000: return
        except FileNotFoundError: pass
        if time.perf_counter() - t > limit: raise SystemExit(f"{dev} did not appear")
        time.sleep(0.0002)

def mem_available_kib():
    for line in open("/proc/meminfo"):
        if line.startswith("MemAvailable:"): return int(line.split()[1])

def pct(xs, p):
    xs = sorted(xs); return xs[min(len(xs) - 1, int(round(p / 100 * (len(xs) - 1))))]

def ms(x): return f"{x * 1000:.2f}"

def freeze(mnt):
    fd = os.open(mnt, os.O_RDONLY | os.O_DIRECTORY)
    fcntl.ioctl(fd, FIFREEZE, 0); return fd

def thaw(fd):
    try: fcntl.ioctl(fd, FITHAW, 0)
    finally: os.close(fd)

def forks(d, seal, n, milestones=(), mem_floor_kib=0):
    """n forks of seal; returns (branches, latencies, snapshots, stopped_early)."""
    branches, lat, snaps = [], [], {}
    if 0 in milestones: snaps[0] = d.stats()
    for i in range(1, n + 1):
        if mem_floor_kib and mem_available_kib() < mem_floor_kib:
            return branches, lat, snaps, True
        t = time.perf_counter()
        b, dev = d.cmd("fork", seal).split()
        wait_block(dev)
        lat.append(time.perf_counter() - t)
        branches.append(b)
        if i in milestones: snaps[i] = d.stats()
    return branches, lat, snaps, False

def main():
    sock, mode, args = sys.argv[1], sys.argv[2], sys.argv[3:]
    d = Daemon(sock)
    if mode == "cmd":                       # one command, answer printed
        print(d.cmd(*args))
    elif mode == "seal-frozen":             # seal-frozen BRANCH MNT: consistent Seal of a mounted ext4
        fd = freeze(args[1])
        try: print(d.cmd("seal", args[0]))
        finally: thaw(fd)
    elif mode == "k2":                      # k2 SEAL N
        branches, lat, _, _ = forks(d, args[0], int(args[1]))
        for b in branches: d.cmd("drop", b)
        print(json.dumps({"n": len(lat), "p50_ms": ms(pct(lat, 50)), "p95_ms": ms(pct(lat, 95)), "max_ms": ms(max(lat))}))
    elif mode == "k3k7":                    # k3k7 SEAL N
        n = int(args[1])
        marks = sorted({0, 1, min(100, n), n // 2, n})
        m0 = mem_available_kib()
        t = time.perf_counter()
        branches, lat, snaps, early = forks(d, args[0], n, marks, mem_floor_kib=1 << 20)
        total = time.perf_counter() - t
        m1 = mem_available_kib()
        last = snaps.get(len(branches)) or d.stats()
        snaps[len(branches)] = last
        g0 = int(d.stats()["garbage_bytes"])
        t = time.perf_counter()
        for b in branches: d.cmd("drop", b)
        drop_total = time.perf_counter() - t
        after = d.stats()
        print(json.dumps({
            "created": len(branches), "asked": n, "stopped_early_low_memory": early,
            "create_total_s": f"{total:.2f}", "fork_p50_ms": ms(pct(lat, 50)), "fork_p95_ms": ms(pct(lat, 95)),
            "snapshots": {k: {x: v[x] for x in ("devices", "threads", "rss_kib", "layers")} for k, v in sorted(snaps.items())},
            "mem_available_drop_mib": (m0 - m1) // 1024,
            "drop_total_s": f"{drop_total:.2f}",
            "log_bytes_after_drop": after["log_bytes"], "garbage_bytes_before_drop": g0,
            "garbage_bytes_after_drop": after["garbage_bytes"], "devices_after_drop": after["devices"],
            "threads_after_drop": after["threads"], "rss_kib_after_drop": after["rss_kib"]}))
    elif mode == "k6":                      # k6 BRANCH MNT N: Seals under light writes
        branch, mnt, n = args[0], args[1], int(args[2])
        stop = threading.Event()
        def writer():
            p = os.path.join(mnt, "k6-light")
            while not stop.is_set():
                try:
                    with open(p, "wb") as f: f.write(os.urandom(4096)); f.flush(); os.fsync(f.fileno())
                except OSError: pass        # while frozen, writes block until the thaw
                time.sleep(0.01)
        th = threading.Thread(target=writer, daemon=True); th.start()
        total, seal_only = [], []
        for _ in range(n):
            t0 = time.perf_counter()
            fd = freeze(mnt)
            try:
                t1 = time.perf_counter(); d.cmd("seal", branch); t2 = time.perf_counter()
            finally: thaw(fd)
            t3 = time.perf_counter()
            total.append(t3 - t0); seal_only.append(t2 - t1)
            time.sleep(0.02)
        stop.set(); th.join()
        print(json.dumps({"n": n, "total_p50_ms": ms(pct(total, 50)), "total_p95_ms": ms(pct(total, 95)),
                          "seal_only_p50_ms": ms(pct(seal_only, 50)), "seal_only_p95_ms": ms(pct(seal_only, 95)),
                          "layers_after": d.stats()["layers"]}))
    else:
        raise SystemExit(f"unknown mode {mode}")

if __name__ == "__main__":
    main()
PY

# 4 KiB pwrite + fsync into the middle of FILE; prints seconds.
small_write() {
    python3 -c '
import os, sys, time
fd = os.open(sys.argv[1], os.O_WRONLY)
off = (os.fstat(fd).st_size // 2) & ~4095
t = time.perf_counter(); os.pwrite(fd, os.urandom(4096), off); os.fsync(fd)
print(f"{time.perf_counter() - t:.6f}"); os.close(fd)' "$1"
}

# p50 and p95 in ms of numbers (seconds) on stdin.
p50p95() {
    python3 -c '
import sys
xs = sorted(float(x) for x in sys.stdin.read().split())
p = lambda q: xs[min(len(xs) - 1, int(round(q / 100 * (len(xs) - 1))))]
print(f"{p(50) * 1000:.2f} {p(95) * 1000:.2f}")'
}

# fio job on DIR; prints "value" for the metric asked.
fio_run() {   # fio_run DIR NAME METRIC fio-args...
    local dir=$1 name=$2 metric=$3 out; shift 3
    if ! out=$(fio --name="$name" --directory="$dir" --output-format=json "$@" 2>&1); then
        printf '%s\n' "$out" | tail -n 5 >&2
        die "fio $name on $dir failed"
    fi
    printf '%s\n' "$out" | python3 -c '
import json, sys
j = json.load(sys.stdin)["jobs"][0]; m = sys.argv[1]
if m == "write_iops":   print("%.0f" % j["write"]["iops"])
elif m == "write_mibs": print("%.1f" % (j["write"]["bw_bytes"] / 1048576))
elif m == "read_mibs":  print("%.1f" % (j["read"]["bw_bytes"] / 1048576))' "$metric"
}

ratio() { python3 -c 'import sys; a, b = float(sys.argv[1]), float(sys.argv[2]); print(f"{a / b:.2f}" if b else "inf")' "$1" "$2"; }

{
echo "blk-bench $(date -u +%Y-%m-%dT%H:%M:%SZ) on $(hostname), kernel $(uname -r), $(nproc) CPUs, $(free -g | awk '/Mem:/{print $2}') GiB RAM"
echo "daemon $BLKD, quick=$QUICK"
} | tee "$RESULTS"

# ---- setup -----------------------------------------------------------------
say "baseline: ext4 on a loop device, file $BASEIMG"
truncate -s 4G "$BASEIMG"
BASEDEV=$(losetup -f --show "$BASEIMG")
mkfs.ext4 -q -F -E nodiscard "$BASEDEV"
mount_on "$BASEDEV" "$MBASE"

say "taso-blkd: log $LOG"
rm -f "$SOCK"
# Each live device holds about two file descriptors (its character device
# and its io_uring); the default soft limit of 1024 stops K3 near 475.
ulimit -n 1048576 2>/dev/null || ulimit -n "$(ulimit -Hn)"
say "open-file limit for the daemon: $(ulimit -n)"
"$BLKD" "$LOG" "$SOCK" 2>>"$ERR" &
DAEMON_PID=$!
for _ in $(seq 100); do [[ -S "$SOCK" ]] && break; sleep 0.1; done
[[ -S "$SOCK" ]] || die "daemon socket did not appear; see $ERR"

ROOT=$(H cmd root)
read -r BR DEV <<<"$(H cmd fork "$ROOT")"
wait_dev "$DEV"
mkfs.ext4 -q -F -E nodiscard "$DEV"
mount_on "$DEV" "$MB"

say "K4 files: ${K4_SMALL} MiB and ${K4_BIG} MiB of random data, in the branch and in the baseline"
for m in "$MB" "$MBASE"; do
    dd if=/dev/urandom of="$m/small" bs=1M count="$K4_SMALL" status=none
    dd if=/dev/urandom of="$m/big" bs=1M count="$K4_BIG" status=none
done
sync
SEAL=$(H seal-frozen "$BR" "$MB")
say "Seal $SEAL holds the files; branch $BR moves on"

# ---- K2: fork ----------------------------------------------------------------
say "K2: $N_FORK forks of $SEAL, time until the device is ready"
K2=$(H k2 "$SEAL" "$N_FORK")
echo "K2 $K2" | tee -a "$RESULTS"

# ---- K4: first small write in a fresh fork ---------------------------------
say "K4: first 4 KiB write + fsync in a fresh fork ($K4_SAMPLES forks per size), and in the baseline"
for f in small big; do
    : >"$DIR/k4-$f"
    for _ in $(seq "$K4_SAMPLES"); do
        read -r FB FDEV <<<"$(H cmd fork "$SEAL")"
        wait_dev "$FDEV"
        mount_on "$FDEV" "$MF"
        sync; echo 3 >/proc/sys/vm/drop_caches
        small_write "$MF/$f" >>"$DIR/k4-$f"
        umount "$MF"
        H cmd drop "$FB" >/dev/null
    done
    : >"$DIR/k4-base-$f"
    for _ in $(seq "$K4_SAMPLES"); do
        sync; echo 3 >/proc/sys/vm/drop_caches   # cold, as a fresh fork is
        small_write "$MBASE/$f" >>"$DIR/k4-base-$f"
    done
done
read -r K4S50 K4S95 < <(p50p95 <"$DIR/k4-small")
read -r K4B50 K4B95 < <(p50p95 <"$DIR/k4-big")
read -r K4BS50 _ < <(p50p95 <"$DIR/k4-base-small")
read -r K4BB50 _ < <(p50p95 <"$DIR/k4-base-big")
rm -f "$DIR"/k4-*
{
echo "K4 fork ${K4_SMALL}MiB p50/p95 ms: $K4S50 / $K4S95; fork ${K4_BIG}MiB: $K4B50 / $K4B95"
echo "K4 baseline p50 ms: ${K4_SMALL}MiB $K4BS50, ${K4_BIG}MiB $K4BB50"
echo "K4 big/small (flat = ~1): $(ratio "$K4B50" "$K4S50"); fork/baseline at ${K4_BIG}MiB: $(ratio "$K4B50" "$K4BB50")"
} | tee -a "$RESULTS"

# ---- K5: steady state --------------------------------------------------------
say "K5: fio, ${FIO_TIME}s per job, branch vs baseline"
declare -A K5
for m in "$MB" "$MBASE"; do
    tag=$([[ $m == "$MB" ]] && echo blk || echo base)
    rw=$(fio_run "$m" k5rand write_iops --rw=randwrite --bs=4k --size=256M --fsync=1 --ioengine=psync --runtime="$FIO_TIME" --time_based)
    sw=$(fio_run "$m" k5seq write_mibs --rw=write --bs=1M --size="${FIO_SIZE}M" --direct=1 --ioengine=psync --end_fsync=1)
    sync; echo 3 >/proc/sys/vm/drop_caches
    sr=$(fio_run "$m" k5seq read_mibs --rw=read --bs=1M --size="${FIO_SIZE}M" --direct=1 --ioengine=psync)
    rm -f "$m"/k5rand* "$m"/k5seq*
    K5[${tag}_rw]=$rw; K5[${tag}_sw]=$sw; K5[${tag}_sr]=$sr
done
{
echo "K5 random 4k write+fsync IOPS: blk ${K5[blk_rw]}, base ${K5[base_rw]} (base/blk $(ratio "${K5[base_rw]}" "${K5[blk_rw]}"))"
echo "K5 seq write MiB/s:            blk ${K5[blk_sw]}, base ${K5[base_sw]} (base/blk $(ratio "${K5[base_sw]}" "${K5[blk_sw]}"))"
echo "K5 seq read MiB/s:             blk ${K5[blk_sr]}, base ${K5[base_sr]} (base/blk $(ratio "${K5[base_sr]}" "${K5[blk_sr]}"))"
} | tee -a "$RESULTS"

# ---- K6: Seal ------------------------------------------------------------------
say "K6: $N_SEAL Seals of $BR under light writes (freeze, seal, thaw)"
K6=$(H k6 "$BR" "$MB" "$N_SEAL")
echo "K6 $K6" | tee -a "$RESULTS"

# ---- K3 + K7: 1000 branches, then drop them ----------------------------------
say "K3: $N_BRANCH live branches of $SEAL; then K7: drop them all"
K3=$(H k3k7 "$SEAL" "$N_BRANCH")
echo "K3K7 $K3" | tee -a "$RESULTS"

umount "$MB"
say "stats: $(H cmd stats)"
H cmd quit >/dev/null
wait "$DAEMON_PID" || true
DAEMON_PID=
umount "$MBASE"
losetup -d "$BASEDEV"; BASEDEV=

# ---- verdicts ----------------------------------------------------------------
python3 - "$RESULTS" <<'PY' | tee -a "$RESULTS"
import json, sys
lines = open(sys.argv[1]).read().splitlines()
get = lambda tag: json.loads(next(l for l in lines if l.startswith(tag + " ")).split(" ", 1)[1])
def verdict(name, value, ok, kill, note=""):
    v = "PASS" if ok else ("KILL" if kill else "between")
    print(f"{name:3} {v:8} {value}{'  (' + note + ')' if note else ''}")
print("\nverdicts (spike plan section 2):")
k2 = get("K2"); p95 = float(k2["p95_ms"])
verdict("K2", f"fork p95 {p95} ms", p95 < 5, p95 > 50)
k3 = get("K3K7")
t = float(k3["create_total_s"]); n = k3["created"]; snaps = k3["snapshots"]
first, last = snaps["0"], snaps[str(n)]
per_rss = (int(last["rss_kib"]) - int(first["rss_kib"])) / max(n, 1) / 1024
per_thr = (int(last["threads"]) - int(first["threads"])) / max(n, 1)
verdict("K3", f"{n}/{k3['asked']} branches in {t} s; per branch {per_rss:.2f} MiB daemon RSS, {per_thr:.1f} threads; MemAvailable fell {k3['mem_available_drop_mib']} MiB",
        n == k3["asked"] and t < 5 and per_rss <= 32, k3["stopped_early_low_memory"] or per_rss > 32,
        "threads per branch: the plan's kill example; lazy devices are the fallback" if per_thr >= 1 else "")
l = next(x for x in lines if x.startswith("K4 big/small")); flat = float(l.split(":")[1].split(";")[0]); vs = float(l.rsplit(":", 1)[1])
verdict("K4", f"big/small {flat}, fork/baseline {vs}", flat <= 1.5 and vs <= 1.5, flat > 2)
r = [float(x.rsplit("base/blk ", 1)[1].rstrip(")")) for x in lines if x.startswith("K5 ")]
verdict("K5", f"baseline/blk ratios {r} (randwrite, seq write, seq read)", max(r) <= 1.5, max(r) > 2)
k6 = get("K6"); p95 = float(k6["total_p95_ms"])
verdict("K6", f"freeze+seal+thaw p95 {p95} ms, seal alone p95 {k6['seal_only_p95_ms']} ms", p95 < 2, p95 > 114)
d = float(k3["drop_total_s"])
verdict("K7", f"dropped {n} in {d} s; log {k3['log_bytes_after_drop']} B, garbage {k3['garbage_bytes_before_drop']} -> {k3['garbage_bytes_after_drop']} B", d < 5, False,
        "space reclaim is not built in the spike: the log never shrinks")
PY
say "results kept in $RESULTS"
