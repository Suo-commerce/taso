#!/usr/bin/env bash
# p5-fsfreeze-probe.sh: what starting the `fsfreeze` program costs a Seal,
# against making the same kernel calls directly (P5, the 50 ms line, bite 1).
#
#   sudo scripts/p5-fsfreeze-probe.sh [CONCURRENCY...]   (default: 1 8 64)
#
# Why: the Warden freezes and thaws a Vessel by starting `fsfreeze -f` and
# `fsfreeze -u` (crates/taso-warden/src/blk.rs, System::freeze/thaw, through
# Command::output).  On taso-p5 at P=64 (2026-10-31, 3af4321) seal.thaw is
# 18.5 ms p50 and seal.freeze 35.2; at P=8 the thaw is 6.9; at P=1 on
# taso-test 1-2 ms (blk-freeze-probe.sh run 1).  A thaw is one kernel call
# that releases a lock; its growth with load suggests the cost of starting
# a program under many concurrent Seals, not the thaw.
#
# What it does, per concurrency C: C threads in one process (as in the
# Warden), each with its own idle ext4 (no journal, nodiscard, as a
# Vessel's mkfs) on a loop device, each freezing and thawing its own
# filesystem ROUNDS times, timed separately, three ways:
#   program  starts `fsfreeze -f DIR` / `fsfreeze -u DIR`, output captured
#            (what the Warden does today)
#   ioctl    opens DIR and calls FIFREEZE / FITHAW on it (what the Warden
#            could do instead; the same calls fsfreeze makes)
#   true     starts `true`, output captured: the cost of starting a
#            program alone, for reference
# The modes alternate (program, ioctl, program, ioctl) so neither always
# runs first.  The filesystems are idle: a freeze here flushes nothing, so
# the difference between the modes is the mechanism, not the data.
#
# Predictions (before the run, 2026-11-02, taso-test; a VM's numbers check
# the mechanism and rank nothing):
#   F1  ioctl: freeze and thaw each under 1 ms p50 at C=1, and under 2 ms
#       p50 at C=64 (no lock shared between filesystems)
#   F2  program: freeze and thaw each 1-3 ms p50 at C=1 (the start of a
#       program), growing with C to 10+ ms p50 at C=64 on taso-test's
#       4 threads
#   F3  `true` alone costs most of the program mode's time at every C:
#       the cost is starting a program, not fsfreeze's work
# If F1 holds and F2/F3 show 5+ ms per call at C=64, bite 1 is worth a
# branch: System::freeze/thaw as the kernel calls (one file, blk.rs),
# measured with bench.sh at P=8 and P=64.  If program and ioctl are equal,
# bite 1 closes without touching Taso.
#
# Limits: the threads are Python's (the GIL is released in the ioctl and
# while waiting for a program), the Warden's are Rust's; the start of a
# program from Python and from Rust's Command take the same kernel path
# (vfork/clone + exec) but not the same user-space code.
#
# Touches, and nothing else: $WORK (/var/tmp/p5-fsfreeze-probe: sparse
# 64 MiB images, their mounts, removed at the end), one loop device per
# image (detached at the end).  Env: ROUNDS (40) per thread per pass.
# Output: the table on stdout; tee it to a new file name.

set -euo pipefail
die() { printf 'ABORT: %s\n' "$*" >&2; exit 2; }
[[ $EUID -eq 0 ]] || die "run as root"
for t in fsfreeze losetup mkfs.ext4 mount umount python3 true; do command -v "$t" >/dev/null || die "$t is missing"; done
CONC=("$@"); [[ ${#CONC[@]} -gt 0 ]] || CONC=(1 8 64)
for c in "${CONC[@]}"; do [[ "$c" =~ ^[1-9][0-9]*$ && "$c" -le 256 ]] || die "concurrency $c: 1 to 256"; done
ROUNDS=${ROUNDS:-40}; [[ "$ROUNDS" =~ ^[1-9][0-9]*$ ]] || die "ROUNDS=$ROUNDS"
MAX=$(printf '%s\n' "${CONC[@]}" | sort -n | tail -1)
WORK=/var/tmp/p5-fsfreeze-probe
[[ ! -e "$WORK" ]] || die "$WORK exists (an earlier run's?): check 'findmnt | grep $WORK' and remove it"

LOOPS=()
cleanup() {
    set +e
    for i in $(seq 0 $((MAX - 1))); do
        m="$WORK/m$i"
        mountpoint -q "$m" 2>/dev/null || continue
        fsfreeze -u "$m" 2>/dev/null
        umount "$m" 2>/dev/null || umount -l "$m"
    done
    for l in "${LOOPS[@]}"; do losetup -d "$l" 2>/dev/null; done
    rm -rf "$WORK"
}
trap cleanup EXIT

printf '== %s fsfreeze probe on %s, kernel %s, taso %s; concurrency %s, %s rounds per thread per pass\n' \
    "$(date +%H:%M:%S)" "$(hostname)" "$(uname -r)" "$(git rev-parse --short HEAD 2>/dev/null || echo ?)" "${CONC[*]}" "$ROUNDS"
mkdir -p "$WORK"
for i in $(seq 0 $((MAX - 1))); do
    truncate -s 64M "$WORK/img$i"
    l=$(losetup -f --show "$WORK/img$i"); LOOPS+=("$l")
    mkfs.ext4 -q -F -O ^has_journal -E nodiscard "$l"
    mkdir -p "$WORK/m$i"; mount -o discard "$l" "$WORK/m$i"
done
printf '== %s %s idle ext4 filesystems mounted under %s\n' "$(date +%H:%M:%S)" "$MAX" "$WORK"

python3 -I - "$WORK" "$ROUNDS" "${CONC[@]}" <<'PY'
import fcntl, os, subprocess, sys, threading, time
work, rounds, conc = sys.argv[1], int(sys.argv[2]), [int(c) for c in sys.argv[3:]]
FIFREEZE, FITHAW = 0xC0045877, 0xC0045878   # _IOWR('X', 119, int), _IOWR('X', 120, int)

def program(d, how):
    r = subprocess.run(["fsfreeze", how, d], capture_output=True)
    if r.returncode:
        raise RuntimeError(f"fsfreeze {how} {d}: {r.stderr.decode().strip()}")

def ioctl(d, req):
    fd = os.open(d, os.O_RDONLY)
    try:
        fcntl.ioctl(fd, req, 0)
    finally:
        os.close(fd)

def one(mode, i, out, errs):
    d = f"{work}/m{i}"
    try:
        for _ in range(rounds):
            if mode == "true":
                t0 = time.perf_counter()
                subprocess.run(["true"], capture_output=True, check=True)
                out["start"].append(time.perf_counter() - t0)
                continue
            t0 = time.perf_counter()
            program(d, "-f") if mode == "program" else ioctl(d, FIFREEZE)
            t1 = time.perf_counter()
            program(d, "-u") if mode == "program" else ioctl(d, FITHAW)
            t2 = time.perf_counter()
            out["freeze"].append(t1 - t0); out["thaw"].append(t2 - t1)
    except Exception as e:
        errs.append(f"{mode} m{i}: {e}")
        try: ioctl(d, FITHAW)
        except OSError: pass

def run(mode, c, acc):
    errs, threads = [], []
    for i in range(c):
        t = threading.Thread(target=one, args=(mode, i, acc, errs)); threads.append(t)
    for t in threads: t.start()
    for t in threads: t.join()
    if errs:
        print("FAILED:", *errs[:5], sep="\n  ", flush=True); sys.exit(1)

def q(v, p):
    v = sorted(v); return v[min(len(v) - 1, max(0, int(len(v) * p + 0.999999) - 1))] * 1000

print()
print("| C | mode | n | freeze p50 / p95 / max ms | thaw p50 / p95 / max ms | start of a program p50 / p95 ms |")
print("| ---: | --- | ---: | --- | --- | --- |")
for c in conc:
    res = {m: {"freeze": [], "thaw": [], "start": []} for m in ("program", "ioctl", "true")}
    for mode in ("program", "ioctl", "program", "ioctl", "true", "true"):
        run(mode, c, res[mode])
    for mode in ("program", "ioctl"):
        f, t = res[mode]["freeze"], res[mode]["thaw"]
        print(f"| {c} | {mode} | {len(f)} | {q(f,.5):.2f} / {q(f,.95):.2f} / {max(f)*1000:.2f} | {q(t,.5):.2f} / {q(t,.95):.2f} / {max(t)*1000:.2f} | |", flush=True)
    s = res["true"]["start"]
    print(f"| {c} | true | {len(s)} | | | {q(s,.5):.2f} / {q(s,.95):.2f} |", flush=True)
PY
printf '== %s fsfreeze probe DONE\n' "$(date +%H:%M:%S)"
