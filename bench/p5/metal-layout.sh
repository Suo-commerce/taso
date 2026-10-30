#!/usr/bin/env bash
# bench/p5/metal-layout.sh: the metal hour for the record layout revision
# (Taso_design_layout_2026-10-30 rev. 4+, l-j and l-k) and design 2's
# question (Taso_design_round_2026-10-30, r-a): the same rows on one host,
# four ways, each against the one before it.
#
#   main      main before the layout (fe6e1bd)
#   buffered  the new format, the split write, the page cache (p5-layout-io)
#   direct    the same, O_DIRECT, the log written ahead 32 MiB
#   direct0   the same, O_DIRECT, nothing written ahead (l-j)
#
# Rows per way (bench.sh blk, RUNS=2 each): P=8; P=64; the noisy neighbour
# at P=8; the fork storm of 50.  First, L0's probe (p5-facts.sh appends)
# for the metal's number on the overlap of direct appends.
#
# Run from a root shell on taso-p5 after A1's setup, under tmux:
#   cp /root/taso/bench/p5/metal-layout.sh /root/ && tmux new -d -s metal \
#     '/root/metal-layout.sh 2>&1 | tee /root/metal.log; exec bash'
# It runs from /root because it checks out other commits of /root/taso.
# Results: /root/metal/<way>-<row>.log, copied to /home/ubuntu/p5/metal
# for scp at the end; a summary of the lines that decide, per way, in
# /root/metal/summary.txt.  About 25 minutes.

set -uo pipefail
MAIN=${MAIN:-fe6e1bd}
LAYOUT=${LAYOUT:-origin/p5-layout-io}
REPO=/root/taso
OUT=/root/metal
mkdir -p "$OUT"
. /etc/profile.d/taso-p5.sh 2>/dev/null || true
. /root/.cargo/env 2>/dev/null || true

say() { printf '== %s %s\n' "$(date +%H:%M:%S)" "$*"; }
checkout() {
    git -C "$REPO" fetch -q origin || { say "fetch failed"; exit 1; }
    git -C "$REPO" checkout -q --detach "$1" || { say "checkout $1 failed"; exit 1; }
    say "at $(git -C "$REPO" log --oneline -1)"
}
row() { # row WAY NAME ENV... -- ARGS...
    local way=$1 name=$2; shift 2
    local envs=()
    while [[ $# -gt 0 && "$1" != -- ]]; do envs+=("$1"); shift; done
    shift
    say "$way $name"
    (cd "$REPO" && env "${envs[@]}" bench/p5/bench.sh blk "$@") >"$OUT/$way-$name.log" 2>&1 \
        || say "$way $name: bench.sh exit $? (see $OUT/$way-$name.log)"
}
rows() { # rows WAY [BLKD_ARGS]
    local way=$1 args=${2:-}
    row "$way" p8 "BLKD_ARGS=$args" -- 8 10 2
    row "$way" p64 "BLKD_ARGS=$args" -- 64 10 2
    row "$way" noisy8 "BLKD_ARGS=$args" NOISY=1 -- 8 10 2
    row "$way" storm50 "BLKD_ARGS=$args" FORKS=50 -- 1 10 2
}

say "host $(hostname), kernel $(uname -r), rcu_expedited $(cat /sys/kernel/rcu_expedited 2>/dev/null)"
checkout "$LAYOUT"
say "L0 probe: appends on the metal"
(cd "$REPO" && scripts/p5-facts.sh appends) >"$OUT/l0-appends.log" 2>&1
grep -E 'speedup|^--' "$OUT/l0-appends.log"

checkout "$MAIN"
rows main
checkout "$LAYOUT"
rows buffered "--io buffered"
rows direct "--io direct"
rows direct0 "--io direct --ahead-mib 0"

# The lines that decide, per way and row.
{
    for f in "$OUT"/*-*.log; do
        [[ "$f" == */l0-appends.log ]] && continue
        echo "== $(basename "$f" .log)"
        grep -E 'taso [0-9a-f]{7}|taso-blkd|storage bytes|syncs:|turn pause|noisy neighbour: turn|^\| seal\.(total|freeze|log) |fork.total \(|^\| blk\.mount |durable turns|Warden CPU|Warden wall' "$f"
    done
} >"$OUT/summary.txt"
mkdir -p /home/ubuntu/p5 && rm -rf /home/ubuntu/p5/metal && cp -r "$OUT" /home/ubuntu/p5/metal && chown -R ubuntu: /home/ubuntu/p5
say "done: $OUT/summary.txt (and /home/ubuntu/p5/metal for scp)"
echo "METAL DONE"
