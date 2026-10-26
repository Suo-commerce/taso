#!/usr/bin/env bash
# p5-facts.sh: the facts about a measurement host that every P5 number is
# measured under (Taso_plan_p5 §2 A2): what the stack says about flushes,
# what a flush costs, and what the provider's "stop" actually cuts.
#
#   sudo scripts/p5-facts.sh report                 (a) what the stack reports
#   sudo scripts/p5-facts.sh flush                  (b) the cost of a flush
#   sudo scripts/p5-facts.sh writer [PORT]          (c) on the host, before the cut
#        scripts/p5-facts.sh listener HOST[:PORT]   (c) on the laptop, the witness
#   sudo scripts/p5-facts.sh verify ACKED           (c) on the host, after boot
#
# (a) report: for every disk, the kernel's queue flags (write_cache, fua),
#     the NVMe controller's write-cache feature as the drive reports it
#     (nvme get-feature 0x06: whether the volatile cache is enabled), id-ctrl
#     (model, firmware, vwc, FDP), zoned; ZFS's sync property on taso/vessel;
#     ext4's mount options on /var/lib/taso; the virtualisation.  Nothing
#     here proves a flush reaches the medium: it is what the stack claims.
#
# (b) flush: 1000 times, a 4 KiB write to one file followed by fdatasync,
#     on ext4 on taso-blk (/var/lib/taso/facts) and on taso/vessel
#     (/taso/vessel/facts), and the same with O_DSYNC (the FUA path on
#     ext4); p50/p90/p99/max in microseconds.  On a drive with a volatile
#     cache and no power-loss protection a flush costs milliseconds; a
#     flush answered in tens of microseconds is a flush that did not reach
#     the medium, or a drive with power-loss protection (A2 writes down
#     which, from (a) and (c)).
#
# (c) the cut, the real measurement.  writer (host) listens on PORT
#     (default 7705) and, once the listener (laptop) has connected, appends
#     16-byte records (seq, ~seq) in four streams, each its own thread and
#     file under its directory:
#        ext4-fdatasync   /var/lib/taso/facts   write, fdatasync, then ack
#        ext4-odsync      /var/lib/taso/facts   O_DSYNC write, then ack
#        zfs-fdatasync    /taso/vessel/facts    write, fdatasync, then ack
#        ext4-nosync      /var/lib/taso/facts   write to the page cache, ack
#     and sends "stream seq" to the listener after each ack.  The listener
#     records the last acknowledged seq per stream in ACKED (default
#     ./p5-facts-acked.txt, rewritten every second) and prints a status
#     line; it ends by itself after ten seconds without an acknowledgement
#     (a receiver never learns otherwise that its peer lost power).  Jarmo then cuts the host the provider's way (Scaleway: Stop;
#     also Reboot; UpCloud: stop), without stopping the writer.  After
#     boot, verify (host) reads each stream's file, finds the longest
#     valid prefix (consecutive seq from 1, check word right), and prints,
#     per stream, on-disk vs acknowledged (the ACKED file copied over
#     from the laptop).  Reading the result:
#        synced streams complete, nosync short  = a power loss (or, on a
#                                                 VM, a kill); every
#                                                 acknowledged flush survived
#                                                 it.  Bare metal: the medium
#                                                 was reached.  VM: the host's
#                                                 cache and power were never
#                                                 cut, so nothing is known
#                                                 about them from inside
#        all four complete                       = a graceful shutdown (the
#                                                 kernel flushed the page
#                                                 cache): NOT a power loss
#        a synced stream short                   = an acknowledged flush did
#                                                 not reach the medium
#     One run per cut method, each written in the finding with the method
#     named.  Each stream's file is removed by writer at start; verify
#     removes nothing.
#
# Touches, and nothing else: /var/lib/taso/facts/ and /taso/vessel/facts/
# (created; files flush-*.bin and stream-*.bin); the listener writes ACKED
# in the laptop's current directory.  Needs python3 (stdlib only) on both
# sides; nvme-cli on the host for (a).  Port PORT must be reachable from
# the laptop: Elastic Metal has no firewall in front of it unless one is
# added; close the port after (the writer exits with the cut).

set -euo pipefail

mode=${1:-}; shift || true
EXT4_DIR=${EXT4_DIR:-/var/lib/taso/facts}
ZFS_DIR=${ZFS_DIR:-/taso/vessel/facts}
PORT=7705
die() { printf 'REFUSED: %s\n' "$*" >&2; exit 1; }
q() { cat "/sys/block/$1/queue/$2" 2>/dev/null || echo -; }

case "$mode" in
# ---- (a) report ---------------------------------------------------------------
report)
    [[ $EUID -eq 0 ]] || die "run as root"
    echo "p5-facts report $(date -Is) $(hostname) kernel $(uname -r) virtualisation $(systemd-detect-virt 2>/dev/null || true)"
    for n in $(lsblk -dn -o NAME,TYPE | awk '$2 == "disk" {print $1}'); do
        echo "== $n $(lsblk -dn -o SIZE,MODEL "/dev/$n" | tr -s ' ')"
        echo "   queue: write_cache '$(q "$n" write_cache)' fua $(q "$n" fua) rotational $(q "$n" rotational) zoned $(q "$n" zoned) logical $(q "$n" logical_block_size) physical $(q "$n" physical_block_size)"
        if [[ "$n" == nvme* ]] && command -v nvme >/dev/null; then
            ctrl=/dev/${n%n[0-9]*}
            echo "   id-ctrl: $(nvme id-ctrl "/dev/$n" 2>/dev/null | awk -F' *: *' '$1 == "mn" || $1 == "fr" || $1 == "vwc" || $1 == "ctratt" {printf "%s=%s ", $1, $2}')"
            echo "   id-ctrl: $(nvme id-ctrl -H "/dev/$n" 2>/dev/null | grep -i 'flexible data placement' | sed 's/^ *//')"
            echo "   feature 0x06 (volatile write cache enable): $(nvme get-feature -f 0x06 -H "$ctrl" 2>&1 | sed 's/^ *//' | tr '\n' ' ')"
        fi
    done
    echo "== kernel lines about nvme and write cache"
    journalctl -k --no-pager -o cat 2>/dev/null | grep -iE 'nvme|write cache|fua' | head -20 | sed 's/^/   /' || true
    echo "== filesystems"
    if mountpoint -q /var/lib/taso; then echo "   /var/lib/taso: $(findmnt -no SOURCE,FSTYPE,OPTIONS /var/lib/taso)"; else echo "   /var/lib/taso: not a mount point"; fi
    if command -v zfs >/dev/null && zfs list taso/vessel >/dev/null 2>&1; then
        echo "   taso/vessel: $(zfs get -H -o property,value sync,compression,atime,recordsize taso/vessel | tr '\t' '=' | tr '\n' ' ')"
        echo "   pool taso: $(zpool status -P taso | awk '/\/dev\//{print $1; exit}') ashift=$(zpool get -H -o value ashift taso)"
    else
        echo "   taso/vessel: none"
    fi
    echo "   tmp: TMPDIR=${TMPDIR:-unset}, /tmp is $(findmnt -no FSTYPE /tmp 2>/dev/null || echo '(root fs)')"
    ;;

# ---- (b) flush ----------------------------------------------------------------
flush)
    [[ $EUID -eq 0 ]] || die "run as root"
    for d in "$EXT4_DIR" "$ZFS_DIR"; do
        if [[ -d "$(dirname "$d")" ]]; then mkdir -p "$d"; else echo "skip $d: $(dirname "$d") is not here"; fi
    done
    python3 - "$EXT4_DIR" "$ZFS_DIR" <<'PY'
import os, sys, time
N = 1000
def pct(xs, p): xs = sorted(xs); return xs[min(len(xs) - 1, int(p * len(xs)))]
def run(path, flags, label, sync):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | flags, 0o600)
    buf = os.urandom(4096)
    lat = []
    for i in range(N):
        t = time.perf_counter_ns()
        os.pwrite(fd, buf, 0)
        if sync: os.fdatasync(fd)
        lat.append((time.perf_counter_ns() - t) // 1000)
    os.close(fd); os.unlink(path)
    print("  %-28s p50 %7d  p90 %7d  p99 %7d  max %7d  us  (n=%d)" % (label, pct(lat, .5), pct(lat, .9), pct(lat, .99), max(lat), N))
for d, name in ((sys.argv[1], "ext4 on taso-blk"), (sys.argv[2], "zfs taso/vessel")):
    if not os.path.isdir(d):
        continue
    print("== %s (%s)" % (name, d))
    run(os.path.join(d, "flush-fdatasync.bin"), 0, "write + fdatasync", True)
    run(os.path.join(d, "flush-odsync.bin"), os.O_DSYNC, "O_DSYNC write", False)
    run(os.path.join(d, "flush-nosync.bin"), 0, "write only (page cache)", False)
PY
    ;;

# ---- (c) writer, on the host --------------------------------------------------
writer)
    [[ $EUID -eq 0 ]] || die "run as root"
    PORT=${1:-$PORT}
    [[ -d "$(dirname "$EXT4_DIR")" ]] || die "$(dirname "$EXT4_DIR") is not here (A1's setup makes it)"
    mkdir -p "$EXT4_DIR"
    [[ -d "$(dirname "$ZFS_DIR")" ]] && mkdir -p "$ZFS_DIR" || echo "no $(dirname "$ZFS_DIR"): the zfs stream is skipped"
    python3 - "$PORT" "$EXT4_DIR" "$ZFS_DIR" <<'PY'
import os, socket, struct, sys, threading, time
port, ext4, zfs = int(sys.argv[1]), sys.argv[2], sys.argv[3]
streams = [("ext4-fdatasync", ext4, 0, True), ("ext4-odsync", ext4, os.O_DSYNC, False), ("ext4-nosync", ext4, 0, False)]
if os.path.isdir(zfs):
    streams.insert(2, ("zfs-fdatasync", zfs, 0, True))
srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("0.0.0.0", port)); srv.listen(1)
print("writer: listening on %d; start the listener on the laptop: scripts/p5-facts.sh listener <this host>:%d" % (port, port), flush=True)
conn, peer = srv.accept()
conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
print("writer: listener connected from %s:%d; streams: %s" % (peer[0], peer[1], ", ".join(s[0] for s in streams)), flush=True)
print("writer: CUT THE HOST NOW the provider's way; do not stop this process", flush=True)
lock = threading.Lock()
gone = threading.Event()
counts = {}
def ack(name, seq):
    line = ("%s %d\n" % (name, seq)).encode()
    with lock:
        try:
            conn.sendall(line)
        except OSError:
            gone.set(); return
        counts[name] = seq
def stream(name, d, flags, fsync):
    path = os.path.join(d, "stream-%s.bin" % name)
    try: os.unlink(path)
    except FileNotFoundError: pass
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | flags, 0o600)
    seq = 0
    while not gone.is_set():
        seq += 1
        os.write(fd, struct.pack("<QQ", seq, seq ^ 0xFFFFFFFFFFFFFFFF))
        if fsync: os.fdatasync(fd)
        ack(name, seq)
for s in streams:
    threading.Thread(target=stream, args=s, daemon=True).start()
try:
    while not gone.wait(1):
        with lock:
            print("writer: " + "  ".join("%s=%d" % kv for kv in sorted(counts.items())), flush=True)
    print("writer: listener gone; stopping (the cut did not take this process down: not a power loss?)", flush=True)
except KeyboardInterrupt:
    print("writer: stopped by hand", flush=True)
PY
    ;;

# ---- (c) listener, on the laptop ----------------------------------------------
listener)
    target=${1:-}; [[ -n "$target" ]] || die "usage: $0 listener HOST[:PORT] [ACKED]"
    ACKED=${2:-p5-facts-acked.txt}
    host=${target%%:*}; port=${target#*:}; [[ "$port" != "$target" ]] || port=$PORT
    python3 - "$host" "$port" "$ACKED" <<'PY'
import socket, sys, time
host, port, out = sys.argv[1], int(sys.argv[2]), sys.argv[3]
s = socket.create_connection((host, port), timeout=10)
s.settimeout(10)   # the writer acknowledges every few ms; ten seconds of silence is the cut
print("listener: connected to %s:%d; recording to %s" % (host, port, out), flush=True)
last, started, buf, tick = {}, time.time(), b"", time.time()
def dump(reason):
    with open(out, "w") as f:
        f.write("# p5-facts acked, %s, host %s, %s\n" % (time.strftime("%Y-%m-%dT%H:%M:%S%z"), host, reason))
        for k in sorted(last): f.write("%s %d\n" % (k, last[k]))
try:
    while True:
        chunk = s.recv(65536)
        if not chunk:
            break
        buf += chunk
        *lines, buf = buf.split(b"\n")
        for ln in lines:
            name, seq = ln.decode().split()
            last[name] = int(seq)
        if time.time() - tick >= 1:
            tick = time.time(); dump("running")
            print("listener: %4ds  " % (tick - started) + "  ".join("%s=%d" % kv for kv in sorted(last.items())), flush=True)
except TimeoutError:
    print("listener: ten seconds without an acknowledgement: the host is gone", flush=True)
except (ConnectionResetError, OSError) as e:
    print("listener: connection lost (%s)" % e, flush=True)
except KeyboardInterrupt:
    print("listener: stopped by hand", flush=True)
dump("final: connection ended at %s" % time.strftime("%H:%M:%S"))
print("listener: final acknowledged counts written to %s:" % out, flush=True)
print(open(out).read(), flush=True)
PY
    ;;

# ---- (c) verify, on the host after boot ---------------------------------------
verify)
    [[ $EUID -eq 0 ]] || die "run as root"
    ACKED=${1:-}; [[ -f "$ACKED" ]] || die "usage: $0 verify ACKED  (the listener's file, copied from the laptop)"
    python3 - "$ACKED" "$EXT4_DIR" "$ZFS_DIR" <<'PY'
import os, struct, sys
acked_path, ext4, zfs = sys.argv[1:4]
acked = {}
for ln in open(acked_path):
    if ln.startswith("#") or not ln.strip(): continue
    k, v = ln.split(); acked[k] = int(v)
print("verify: %s" % open(acked_path).readline().strip())
bad = 0
for name, d in (("ext4-fdatasync", ext4), ("ext4-odsync", ext4), ("zfs-fdatasync", zfs), ("ext4-nosync", ext4)):
    path = os.path.join(d, "stream-%s.bin" % name)
    if name not in acked:
        continue
    if not os.path.exists(path):
        print("  %-16s acked %10d   on disk: FILE MISSING" % (name, acked[name])); bad += 1; continue
    data = open(path, "rb").read()
    good, torn = 0, False
    for i in range(len(data) // 16):
        seq, chk = struct.unpack_from("<QQ", data, i * 16)
        if seq != good + 1 or chk != seq ^ 0xFFFFFFFFFFFFFFFF:
            torn = True; break
        good = seq
    tail = len(data) - good * 16
    status = "complete" if good >= acked[name] else "SHORT by %d" % (acked[name] - good)
    extra = ""
    if good > acked[name]: extra += " (+%d written but not yet acknowledged)" % (good - acked[name])
    if tail: extra += " (%d bytes of tail after the valid prefix%s)" % (tail, ", torn" if torn else "")
    synced = name != "ext4-nosync"
    if synced and good < acked[name]: bad += 1
    print("  %-16s acked %10d   on disk %10d   %s%s" % (name, acked[name], good, status, extra))
ns = acked.get("ext4-nosync")
if ns is not None:
    path = os.path.join(ext4, "stream-ext4-nosync.bin")
    on = os.path.getsize(path) // 16 if os.path.exists(path) else 0
    print("reading: " + ("the unsynced stream is complete: the kernel flushed the page cache, so this was a GRACEFUL SHUTDOWN, not a power loss" if on >= ns
          else "the unsynced stream is short: the page cache was lost, so this was a power loss (or equivalent)"))
print("reading: " + ("every synced stream complete: every acknowledged flush survived this cut" if bad == 0 else "%d synced stream(s) short: an acknowledged flush did not survive this cut" % bad))
print("reading: on bare metal a power cut survived is the medium reached; on a VM a kill survived says nothing about the host's own cache or its power")
sys.exit(1 if bad else 0)
PY
    ;;
*)
    echo "usage: $0 report | flush | writer [PORT] | listener HOST[:PORT] [ACKED] | verify ACKED" >&2; exit 64 ;;
esac
