#!/usr/bin/env bash
# release-gate.sh: every gate on one commit, one table (V4b plan §9, the
# release runner).  A release needs a PASS of `full` on the commit tagged.
#
#   scripts/release-gate.sh quick    about 1.5 h: every gate once, the
#                                    default sizes
#   scripts/release-gate.sh full     overnight: quick's gates at release
#                                    sizes, plus xfstests -g quick,
#                                    blk-bench, and 100 crash rounds
#
# As root on taso-test, from the repository root, on a clean tree.  The
# commit is the one checked out; the runner refuses a dirty tree, and
# refuses the result if HEAD moved while it ran.
#
# Before the gates: builds the workspace (release), installs this build's
# taso-blkd as the node's daemon (/usr/local/bin, `systemctl restart
# taso-blkd`: gate-p2-blk, f6-fork-blk and p3-no-trace use the installed
# one) and checks that it answers.
#
# Each gate runs alone, in order, under a time limit; a gate that fails or
# times out does not stop the rest.  Output: $OUT/<gate>.txt per gate, and
# $OUT/summary.txt, the table (gate, exit, seconds, last line).  Exit 0
# only if every gate passed.
#
# One run at a time per node: a second one exits 3 (the lock).
#
# Env: OUT (default /root/release-<commit>-<tier>-<date>); the store for
# blk-warden-test and gate-p2-blk as those scripts take it
# (TASO_BLK_S3_*; unset: a local directory).  `full` needs xfstests set up
# once (scripts/blk-fstests.sh setup).

set -uo pipefail

TIER=${1:-}
case "$TIER" in quick|full) ;; *) echo "usage: $0 quick|full" >&2; exit 2 ;; esac
die() { echo "release-gate: $*" >&2; exit 2; }
[ "$(id -u)" = 0 ] || die "run as root"
[ -f Cargo.toml ] && [ -d scripts ] || die "run from the repository root"
[ -z "$(git status --porcelain --untracked-files=no)" ] || die "the tree has changes: a release gate runs on a commit"
# One gate run at a time on a node (they share taso-blkd, /run/taso and the
# ublk devices); exit 3 when another holds the lock (release-nightly.sh).
exec 9> /run/taso-release-gate.lock
flock -n 9 || { echo "release-gate: another release gate is running" >&2; exit 3; }
COMMIT=$(git rev-parse --short HEAD)
OUT=${OUT:-/root/release-$COMMIT-$TIER-$(date +%Y%m%d-%H%M%S)}
mkdir -p "$OUT"
S=$OUT/summary.txt
: > "$S"
FAILED=0

# run NAME LIMIT CMD...: one gate, its output to $OUT/NAME.txt, one line
# in the table.  LIMIT is timeout(1)'s duration.
run() {
    local n=$1 limit=$2 s rc; shift 2
    printf '%s  ' "$(date +%H:%M)"
    s=$(date +%s)
    timeout --foreground -k 60 "$limit" "$@" > "$OUT/$n.txt" 2>&1
    rc=$?
    [ "$rc" = 124 ] && echo "release-gate: timed out after $limit" >> "$OUT/$n.txt"
    [ "$rc" = 0 ] || FAILED=$((FAILED + 1))
    printf '%-10s exit %-3s %6ss  %s\n' "$n" "$rc" "$(( $(date +%s) - s ))" \
        "$(grep -v '^[[:space:]]*$' "$OUT/$n.txt" | tail -1 | cut -c1-90)" | tee -a "$S"
}

echo "== release gate ($TIER) on $COMMIT, output in $OUT"
# taso-blkd is built on its own, as every script and the README build it:
# built together with taso-warden, cargo unifies two dependency features
# (rustix default, serde alloc) into a different binary (taso-test
# 0e7a58e: gate-p2-blk found the installed daemon "not this build").
run build 60m bash -c 'cargo build --release -q --workspace --bins && cargo build --release -q -p taso-blk --bin taso-blkd'
run install 5m bash -c '
    install target/release/taso-blkd /usr/local/bin/taso-blkd &&
    systemctl restart taso-blkd &&
    python3 - <<PY && echo "taso-blkd: this build, answering"
import socket, time
# The old socket file outlives the restart: ask until the new daemon answers.
for i in range(100):
    try:
        s = socket.socket(socket.AF_UNIX); s.settimeout(10); s.connect("/run/taso/blk.sock")
        s.sendall(b"names\n"); a = s.makefile().readline()
        assert a.startswith("ok"), a
        break
    except (ConnectionRefusedError, FileNotFoundError):
        if i == 99: raise
        time.sleep(0.1)
PY
'

if [ "$TIER" = quick ]; then CRASH=10 P3N=20 P2N=20 LIMIT=45m
else                          CRASH=100 P3N=100 P2N=100 LIMIT=4h; fi

run unit     "$LIMIT" bash -c 'o=$(cargo test -q --workspace --no-fail-fast 2>&1); echo "$o" | grep -E "^test result|FAILED|panicked"; ! echo "$o" | grep -q FAILED && echo "$(echo "$o" | grep -E "^test result" | awk "{p+=\$4} END {print p}") passed"'
run clippy   "$LIMIT" bash -c 'cargo clippy -q --workspace --all-targets -- -D warnings && echo clean'
run fmt      5m       bash -c 'cargo fmt --all --check && echo clean'
run smoke    "$LIMIT" scripts/blk-smoke.sh
run contract "$LIMIT" scripts/blk-contract.sh
run crash    "$LIMIT" scripts/blk-crash.sh "$CRASH"
run blkpool  "$LIMIT" scripts/blk-warden-test.sh
run genesis  "$LIMIT" scripts/p4-genesis.sh blk
run births   "$LIMIT" scripts/p4-births.sh blk
run nominate "$LIMIT" scripts/p4-nominate.sh blk
run verify   "$LIMIT" scripts/p4-verify.sh blk
run decide   "$LIMIT" scripts/p4-decide.sh blk
run sanction "$LIMIT" scripts/p4-sanction.sh blk
run purge    "$LIMIT" scripts/p4-purge.sh blk
run f6fork   "$LIMIT" scripts/f6-fork-blk.sh
run p3       "$LIMIT" env N="$P3N" scripts/p3-no-trace.sh
run p2       "$LIMIT" env N="$P2N" scripts/gate-p2-blk.sh
if [ "$TIER" = full ]; then
    run fstests 6h scripts/blk-fstests.sh run
    run bench   1h scripts/blk-bench.sh
fi

NOW=$(git rev-parse --short HEAD)
if [ "$NOW" != "$COMMIT" ]; then
    echo "release-gate: HEAD moved from $COMMIT to $NOW during the run" | tee -a "$S"
    FAILED=$((FAILED + 1))
fi
TOTAL=$(wc -l < "$S")
echo
if [ "$FAILED" = 0 ]; then
    echo "RELEASE GATE ($TIER) on $COMMIT: PASS, $TOTAL of $TOTAL" | tee -a "$S"
else
    echo "RELEASE GATE ($TIER) on $COMMIT: FAIL, $FAILED failed; see $S" | tee -a "$S"
fi
[ "$FAILED" = 0 ]
