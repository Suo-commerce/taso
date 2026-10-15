#!/usr/bin/env bash
# Garage put latency on one node, for the ledger-shipping decision (P2).
#
# Question: what does one synchronous object put cost?  The design ships
# the unshipped Chronicle prefix before every effect dispatch (one put per
# effect) and after every Seal (async).  This measures the put.
#
# What it does:
#   - installs a single-node Garage (replication_factor = 1) under $ROOT
#   - measures sequential puts of 4 KiB and 64 KiB objects, and the same
#     with 16 in parallel, in two modes:
#       fsync   metadata_fsync = data_fsync = true   (what Taso needs)
#       nofsync both false                           (Garage's default)
#   - measures the same puts into a local directory the way LocalStore
#     does it (write, fsync, rename, fsync dir), as the baseline
#   - prints p50 / p95 / p99 / max in ms and writes them to $ROOT/results.txt
#
# Timing is curl's own %{time_total}: from the start of the request to the
# end of the response, without process start-up.  Each put opens a new
# TCP connection to localhost (~0.1 ms); a real client keeps the
# connection open, so this is slightly pessimistic.  Garage's data lives on
# the server's root disk (network block storage here), not local NVMe.
#
# Usage (as root on taso-test):
#   scripts/garage-put-bench.sh run      # install if needed, measure, stop
#   scripts/garage-put-bench.sh clean    # stop and remove everything
#
# Environment:
#   GARAGE_VERSION  release to download (default v2.1.0)
#   GARAGE_BIN      use this binary instead of downloading
#   N               puts per case (default 500), WARMUP (default 20)
#   PAR             parallel puts in the concurrent case (default 16)
#   ROOT            working directory (default /var/lib/taso-bench)

set -euo pipefail

GARAGE_VERSION=${GARAGE_VERSION:-v2.1.0}
ROOT=${ROOT:-/var/lib/taso-bench}
N=${N:-500}
WARMUP=${WARMUP:-20}
PAR=${PAR:-16}
CFG=$ROOT/garage.toml
BIN=${GARAGE_BIN:-$ROOT/garage}
PIDFILE=$ROOT/garage.pid
S3=http://127.0.0.1:3900
BUCKET=bench

die() { echo "error: $*" >&2; exit 1; }
g() { "$BIN" -c "$CFG" "$@"; }

need() {
    for c in curl python3 openssl xargs; do
        command -v "$c" >/dev/null || die "$c is required"
    done
    [ "$(id -u)" = 0 ] || die "run as root"
}

install_garage() {
    mkdir -p "$ROOT"
    if [ ! -x "$BIN" ]; then
        local url="https://garagehq.deuxfleurs.fr/_releases/$GARAGE_VERSION/x86_64-unknown-linux-musl/garage"
        echo "downloading $url"
        curl -fsSL -o "$BIN.tmp" "$url" || die "download failed; set GARAGE_VERSION or GARAGE_BIN"
        chmod +x "$BIN.tmp" && mv "$BIN.tmp" "$BIN"
    fi
    "$BIN" --version
}

# write_config <true|false>: fsync mode.  The rpc secret is kept across
# restarts so the node identity and layout survive a mode switch.
write_config() {
    local fsync=$1
    [ -f "$ROOT/rpc_secret" ] || openssl rand -hex 32 > "$ROOT/rpc_secret"
    cat > "$CFG" <<EOF
metadata_dir = "$ROOT/meta"
data_dir = "$ROOT/data"
db_engine = "lmdb"
replication_factor = 1
metadata_fsync = $fsync
data_fsync = $fsync
rpc_bind_addr = "127.0.0.1:3901"
rpc_public_addr = "127.0.0.1:3901"
rpc_secret = "$(cat "$ROOT/rpc_secret")"

[s3_api]
s3_region = "garage"
api_bind_addr = "127.0.0.1:3900"
root_domain = ".s3.garage.localhost"
EOF
}

start() {
    nohup "$BIN" -c "$CFG" server >> "$ROOT/garage.log" 2>&1 &
    echo $! > "$PIDFILE"
    for _ in $(seq 50); do
        g status >/dev/null 2>&1 && return 0
        sleep 0.2
    done
    tail -20 "$ROOT/garage.log" >&2
    die "garage did not come up"
}

stop() {
    if [ -f "$PIDFILE" ]; then
        kill "$(cat "$PIDFILE")" 2>/dev/null || true
        for _ in $(seq 50); do
            kill -0 "$(cat "$PIDFILE")" 2>/dev/null || break
            sleep 0.1
        done
        rm -f "$PIDFILE"
    fi
}

# One-time cluster setup: layout, bucket, key.
setup_cluster() {
    [ -f "$ROOT/key.env" ] && return 0
    local id
    id=$(g node id -q 2>/dev/null | cut -d@ -f1)
    [ -n "$id" ] || die "no node id"
    g layout assign -z dc1 -c 1G "$id" >/dev/null
    g layout apply --version 1 >/dev/null
    g bucket create "$BUCKET" >/dev/null
    local out kid sec
    out=$(g key create bench-key)
    kid=$(awk -F': *' '/Key ID/ {print $2; exit}' <<<"$out")
    sec=$(awk -F': *' '/Secret key/ {print $2; exit}' <<<"$out")
    if [ -z "$sec" ]; then
        sec=$(g key info --show-secret bench-key | awk -F': *' '/Secret key/ {print $2; exit}')
    fi
    [ -n "$kid" ] && [ -n "$sec" ] || die "could not read the key: $out"
    g bucket allow --read --write --owner "$BUCKET" --key bench-key >/dev/null
    printf 'KID=%s\nSEC=%s\n' "$kid" "$sec" > "$ROOT/key.env"
    chmod 600 "$ROOT/key.env"
}

# put <file> <object key>: prints the time in seconds; fails on non-200.
put() {
    local out
    out=$(curl -sS -o /dev/null -w '%{http_code} %{time_total}' \
        --aws-sigv4 "aws:amz:garage:s3" --user "$KID:$SEC" \
        -T "$1" "$S3/$BUCKET/$2")
    [ "${out%% *}" = 200 ] || { echo "put $2 -> $out" >&2; return 1; }
    echo "${out#* }"
}
export -f put
export S3 BUCKET

# stats <label>: reads seconds on stdin, prints one line in ms.
stats() {
    python3 -c '
import sys
label = sys.argv[1]
v = sorted(float(x) * 1000 for x in sys.stdin if x.strip())
if not v:
    sys.exit("no samples for " + label)
q = lambda p: v[min(len(v) - 1, int(p * len(v)))]
print(f"{label:<28} n={len(v):<5} p50={q(.50):7.2f}  p95={q(.95):7.2f}  p99={q(.99):7.2f}  max={v[-1]:7.2f}")
' "$1"
}

measure_garage() {
    local mode=$1 size f
    for size in 4k 64k; do
        f=$ROOT/payload-$size
        for i in $(seq "$WARMUP"); do put "$f" "warm/$mode/$size/$i" >/dev/null; done
        for i in $(seq "$N"); do put "$f" "seq/$mode/$size/$i"; done \
            | stats "garage $mode $size seq"
        seq "$N" | xargs -P "$PAR" -I{} bash -c 'put "$0" "par/'"$mode/$size"'/{}"' "$f" \
            | stats "garage $mode $size par$PAR"
    done
}

# The LocalStore path: write temp, fsync, rename, fsync the directory.
measure_local() {
    local size
    for size in 4k 64k; do
        python3 - "$ROOT/local" "$ROOT/payload-$size" "$N" "$WARMUP" <<'PY' | stats "local fsync $size seq"
import os, sys, time
d, payload, n, warm = sys.argv[1], open(sys.argv[2], "rb").read(), int(sys.argv[3]), int(sys.argv[4])
os.makedirs(d, exist_ok=True)
dfd = os.open(d, os.O_RDONLY)
for i in range(warm + n):
    t = time.perf_counter()
    tmp, dst = os.path.join(d, ".tmp"), os.path.join(d, f"obj-{i}")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.write(fd, payload)
    os.fsync(fd)
    os.close(fd)
    os.rename(tmp, dst)
    os.fsync(dfd)
    if i >= warm:
        print(time.perf_counter() - t)
PY
    done
}

run() {
    need
    install_garage
    head -c 4096 /dev/urandom > "$ROOT/payload-4k"
    head -c 65536 /dev/urandom > "$ROOT/payload-64k"
    {
        echo "# garage put bench $(date -u +%FT%TZ) $(hostname) $("$BIN" --version 2>&1 | head -1)"
        echo "# N=$N WARMUP=$WARMUP PAR=$PAR, times in ms, disk: $(df -h "$ROOT" | awk 'NR==2 {print $1}')"
        measure_local
        for mode in fsync nofsync; do
            stop
            if [ "$mode" = fsync ]; then write_config true; else write_config false; fi
            start
            setup_cluster
            # shellcheck disable=SC1091
            . "$ROOT/key.env"
            export KID SEC
            measure_garage "$mode"
        done
        stop
    } | tee "$ROOT/results.txt"
    echo "saved to $ROOT/results.txt; '$0 clean' removes Garage and its data"
}

clean() {
    stop
    rm -rf "$ROOT"
    echo "removed $ROOT"
}

case "${1:-}" in
    run) run ;;
    clean) clean ;;
    *) echo "usage: $0 run|clean" >&2; exit 2 ;;
esac
