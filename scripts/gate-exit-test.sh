#!/usr/bin/env bash
# Tests of the gate scripts' own exit status: a gate that cannot fail checks
# nothing.  No root, no build; run from the repository root.
#
#   scripts/gate-exit-test.sh
#
# 1. gate-unit.sh fails when cargo test fails without printing "FAILED" (a
#    test binary killed by a signal), and when it prints FAILED; passes on a
#    clean run.
# 2. gate-p2-blk.sh's summary exits 1 when a check says FAIL, 0 when all pass.
# 3. p5-node.sh's report keeps its FAIL count when its output is saved.
# 4. soak.sh's growth rule fails a leak, and fails a run too short to judge.
# 5. release-gate.sh's lock is free again when the run ends, whatever a
#    gate left running.
# 6. soak.sh runs its cleanup when it is sent TERM (systemctl stop), and
#    stops at its free-space floor; release-gate.sh clean names the large
#    files the gates leave in /var/lib/taso-blk.
# 7. e3-crash.sh's grade exits 1 on a FAIL, on a HARNESS line and on a run
#    with no graded round; 0 when a round passed and none failed.
# 8. blk-crash.sh's grade of a round's writer fails one that stopped by
#    itself, one that ended by its own fault and one that made nothing durable.
# 9. blk-bench.sh's verdicts exit 1 on a KILL, 0 on "between", and 0 on a
#    KILL under --quick.
# 10. bench/p5/bench.sh's verdict exits 1 on a failed Warden run, on a Vessel
#    that did not end ok and on a stall.
# 11. bench/p5/b3-power.sh's verify refuses (2) a round whose machine did not
#    go down under a running `run`, and goes on for a cut or a dry round.
# (7-11: maturity review of e4a37b2, finding 12.)
set -uo pipefail
cd "$(dirname "$0")/.."
T=$(mktemp -d /tmp/gate-exit-test.XXXXXX); trap 'rm -rf "$T"' EXIT
bad=0
check() { # check NAME WANT GOT
    if [ "$2" = "$3" ]; then echo "ok    $1"; else echo "FAIL  $1: exit $3, expected $2"; bad=$((bad + 1)); fi
}

# 1. a cargo that prints $FAKE_OUT and exits $FAKE_RC
mkdir "$T/bin"
printf '#!/bin/sh\nprintf "%%s\\n" "$FAKE_OUT"\nexit "$FAKE_RC"\n' > "$T/bin/cargo"; chmod +x "$T/bin/cargo"
unit() { FAKE_OUT=$1 FAKE_RC=$2 PATH="$T/bin:$PATH" scripts/gate-unit.sh >/dev/null 2>&1; echo $?; }
check "unit: a clean run passes" 0 "$(unit 'test result: ok. 5 passed; 0 failed; 0 ignored' 0)"
check "unit: a FAILED line fails" 1 "$(unit 'test result: FAILED. 4 passed; 1 failed; 0 ignored' 101)"
check "unit: a test binary killed by a signal fails" 1 "$(unit 'test result: ok. 5 passed; 0 failed; 0 ignored
error: test failed, to rerun pass `-p taso-blk --lib`
  process didn'"'"'t exit successfully: (signal: 6, SIGABRT: process abort signal)' 101)"
check "unit: a build error fails" 1 "$(unit 'error: could not compile `taso-core`' 101)"

# 2. the summary of gate-p2-blk.sh, cut out of the script, over two tables
awk "/^python3 - .*rounds.tsv.*<<'PY'/ {on=1; next} on && /^PY\$/ {exit} on" scripts/gate-p2-blk.sh > "$T/p2.py"
row() { printf '%s\t' "$@" | sed 's/\t$/\n/'; }   # k secs refused same - resumed logok lost dbok blockeq fileeq
{ row 1 2.0 1 1 x 3 1 0 1 1 1; row 2 2.5 1 1 x 4 1 0 1 1 1; } > "$T/good.tsv"
{ row 1 2.0 1 1 x 3 1 0 1 1 1; row 2 2.5 1 0 x 4 1 0 1 0 0; } > "$T/bad.tsv"
p2() { python3 "$T/p2.py" "$1" 2 stop stop >/dev/null 2>&1; echo $?; }
check "p2: every check PASS exits 0" 0 "$(p2 "$T/good.tsv")"
check "p2: a FAIL line exits 1" 1 "$(p2 "$T/bad.tsv")"

# 3. p5-node.sh's way of saving its report: the count must reach the end
awk '/step "10 report"/ {on=1} on && /^ *report( |$)/ {print; exit}' scripts/p5-node.sh > "$T/save.line"
[ -s "$T/save.line" ] || { echo "FAIL  p5-node: the line that saves the report was not found"; bad=$((bad + 1)); }
p5() { bash -c 'fail=0; REPORT='"$T"'/report.txt; report() { echo "FAIL  x"; fail=$((fail + 1)); }
'"$(cat "$T/save.line")"' >/dev/null
[[ $fail -eq 0 ]]' >/dev/null 2>&1; echo $?; }
check "p5-node: setup's saved report keeps its FAIL count" 1 "$(p5)"

# 4. soak.sh's growth rule (its expect, its growth and the loop that
# judges both columns, cut out of the script) over made-up samples of
# "threads open-files"; the exit is the number of FAILs.
soak() {
    bash -c '
W=$1; shift; PASS=0 FAIL=0
eval "$(sed -n "/^expect() {/,/^atleast() /p" scripts/soak.sh)"
eval "$(sed -n "/^growth() {/,/^}/p" scripts/soak.sh)"
printf "time\tthreads\tfiles\n" > "$W/soak.tsv"
for v in "$@"; do printf "t\t%s\t%s\n" $v >> "$W/soak.tsv"; done
eval "$(sed -n "/^for c in \"1 threads\"/,/^done/p" scripts/soak.sh)"
exit "$FAIL"' soak "$T" "$@" >/dev/null 2>&1; echo $?
}
check "soak: steady threads and open files pass" 0 "$(soak "10 20" "12 22" "11 21" "12 20" "10 22" "11 21")"
check "soak: a leak fails, both columns" 2 "$(soak "10 20" "500 900" "1500 3000" "3000 6000" "5000 9000" "7000 12000")"
check "soak: too few samples to judge fail, both columns" 2 "$(soak "10 20" "500 900" "1500 3000" "3000 6000" "5000 9000")"

# 5. release-gate.sh's lock lines and its run(), cut out of the script, the
# lock file under $T (no root): a first run whose gate leaves a process
# behind, then a second run, which exits 3 if the lock is still held.
sed -n '/^exec 9> /,/^flock -n 9 /p' scripts/release-gate.sh | sed "s|/run/taso-release-gate.lock|$T/gate.lock|" > "$T/lock.lines"
sed -n '/^run() {/,/^}/p' scripts/release-gate.sh > "$T/run.fn"
grep -q "^exec 9> $T/gate.lock" "$T/lock.lines" && [ -s "$T/run.fn" ] ||
    { echo "FAIL  release-gate: its lock lines or its run() were not found"; bad=$((bad + 1)); }
gate() { # gate CMD: one run with CMD as its only gate; prints the run's exit
    bash -c 'OUT=$1 S=$1/summary.txt FAILED=0
free_gib() { echo 0; }
'"$(cat "$T/lock.lines" "$T/run.fn")"'
run gate 20 bash -c "$2"' gate "$T" "$1" >/dev/null 2>&1; echo $?
}
check "release-gate: a first run takes the lock" 0 "$(gate "sleep 60 & echo \$! > $T/left.pid")"
check "release-gate: what a gate left running does not keep the lock" 0 "$(gate true)"
[ -s "$T/left.pid" ] && kill "$(cat "$T/left.pid")" 2>/dev/null

# 6. soak.sh's trap, cut out of the script, around a stand-in cleanup and
# a long sleep: a TERM (systemctl stop, with KillMode=mixed) must end it
# through the cleanup.
grep -E "^trap cleanup EXIT\$" scripts/soak.sh > "$T/traps"
[ -s "$T/traps" ] || { echo "FAIL  soak: its EXIT trap was not found"; bad=$((bad + 1)); }
bash -c 'D=$1; cleanup() { echo cleaned > "$D/cleaned"; }
'"$(cat "$T/traps")"'
while :; do sleep 1; done' term "$T" & tp=$!
sleep 1; kill -TERM "$tp"; wait "$tp"; trc=$?
check "soak: a TERM ends it with 143" 143 "$trc"
check "soak: a TERM runs the cleanup" 0 "$([ "$(cat "$T/cleaned" 2>/dev/null)" = cleaned ]; echo $?)"
# The floor: the loop's check, cut out, with free space faked below it.
awk '/^while \[\[ \$SECONDS -lt \$END \]\]; do/ {on=1; next} on && /^    fi$/ {print; exit} on' scripts/soak.sh > "$T/floor"
grep -q FLOOR_GIB "$T/floor" || { echo "FAIL  soak: the floor check was not found"; bad=$((bad + 1)); }
floor() { # floor FREE: the loop body's floor check with FREE GiB free; exit 0 when it stopped
    bash -c 'W=$1 FREE=$2 FLOOR_GIB=10 FLOOR_AT= SECONDS=5; mkdir -p "$W/out"; free_gib() { echo "$FREE"; }
for _ in 1; do
'"$(cat "$T/floor")"'
done
[[ -n "$FLOOR_AT" ]]' floor "$T" "$1" >/dev/null 2>&1; echo $?
}
check "soak: below the floor it stops" 0 "$(floor 9)"
check "soak: above the floor it goes on" 1 "$(floor 11)"
# release-gate.sh clean: the gates' large leftovers in /var/lib/taso-blk.
for f in crash.log bench.log bench-base.img fst.log; do
    grep -q "/var/lib/taso-blk/$f" scripts/release-gate.sh && r=0 || r=1
    check "release-gate clean: removes /var/lib/taso-blk/$f" 0 "$r"
done

# 7. e3-crash.sh's grade(), its Python cut out of the script, over results files
awk '/<<.GRADE.$/ {on=1; next} on && /^GRADE$/ {exit} on' scripts/e3-crash.sh > "$T/grade.py"
[ -s "$T/grade.py" ] || { echo "FAIL  e3-crash: its grade was not found"; bad=$((bad + 1)); }
e3() { printf '== taso-blkd durable at fua\n%b' "$1" > "$T/e3.txt"; python3 -I "$T/grade.py" "$T/e3.txt" >/dev/null 2>&1; echo $?; }
check "e3: a PASS and a MISSED exit 0" 0 "$(e3 'PASS    [write seal] boundary:2 drop  (4s)\nMISSED  [write seal] timing:2+0 drop  (3s)\n')"
check "e3: a FAIL line exits 1" 1 "$(e3 'PASS    a  (4s)\nFAIL    b  (4s)\n        1: an acknowledged Seal is lost\n')"
check "e3: a HARNESS line exits 1" 1 "$(e3 'PASS    a  (4s)\nHARNESS b: no result  (2s)\n')"
check "e3: no graded round exits 1" 1 "$(e3 'MISSED  a  (3s)\nREFUSED b  (3s)\n')"
check "e3: no round at all exits 1" 1 "$(e3 "")"

# 8. blk-crash.sh's grade_writer (and its fail), cut out: the exit is the FAILs
sed -n '/^fail() /p; /^grade_writer() {$/,/^}$/p' scripts/blk-crash.sh > "$T/writer.fn"
grep -q '^grade_writer() {' "$T/writer.fn" && grep -q '^fail() ' "$T/writer.fn" ||
    { echo "FAIL  blk-crash: its grade_writer or its fail was not found"; bad=$((bad + 1)); }
writer() { # writer ALIVE STATUS BEFORE AFTER
    bash -c 'set -euo pipefail; FAILS=0
. "$0"
grade_writer 1 "$@"; exit "$FAILS"' "$T/writer.fn" "$@" >/dev/null 2>&1; echo $?
}
check "blk-crash: a writer cut at work passes" 0 "$(writer 1 0 5 9)"
check "blk-crash: a writer that stopped by itself fails" 1 "$(writer 0 0 5 9)"
check "blk-crash: a writer that ended by its own fault fails" 1 "$(writer 1 1 5 9)"
check "blk-crash: a writer that made nothing durable fails" 1 "$(writer 1 0 5 5)"

# 9. blk-bench.sh's verdicts, the Python cut out, over made-up result lines
awk 'index($0, "python3 - \"$RESULTS\" \"$QUICK\" <<") == 1 {on=1; next} on && /^PY$/ {exit} on' scripts/blk-bench.sh > "$T/verdict.py"
[ -s "$T/verdict.py" ] || { echo "FAIL  blk-bench: its verdicts were not found"; bad=$((bad + 1)); }
bench() { # bench FORK_P95_MS FREEZE_P95_MS QUICK
    cat > "$T/bench.txt" <<EOF
K2 {"branch_p95_ms": "$1", "attach_p95_ms": "4", "detach_p95_ms": "15"}
K3K7 {"branches": 1000, "asked": 1000, "branch_total_s": "0.1", "before": {"rss_kib": 1000, "threads": 4}, "after_branches": {"rss_kib": 1300, "threads": 4}, "after_attach": {"rss_kib": 18000, "threads": 304}, "attached": 100, "asked_attached": 100, "mem_drop_attach_mib": 77, "stopped_early_low_memory": false, "drop_total_s": "0.1", "detach_total_s": "1.4", "log_bytes_after_drop": 5}
K4 big/small: 1.17; fork/baseline: 1.25
K5 randwrite (base/blk 1.12)
K5 seqwrite (base/blk 1.08)
K6 {"seal_only_p95_ms": "1.0", "total_p95_ms": "$2"}
EOF
    python3 "$T/verdict.py" "$T/bench.txt" "$3" >/dev/null 2>&1; echo $?
}
check "blk-bench: every verdict PASS exits 0" 0 "$(bench 0.5 1.5 0)"
check "blk-bench: a between exits 0" 0 "$(bench 0.5 7.8 0)"
check "blk-bench: a KILL exits 1" 1 "$(bench 60 7.8 0)"
check "blk-bench: a KILL under --quick exits 0" 0 "$(bench 60 7.8 1)"

# 10. bench/p5/bench.sh's verdict, cut out, over the files a run leaves
sed -n '/^why=""$/,$p' bench/p5/bench.sh > "$T/p5verdict"
grep -q 'BENCH FAIL' "$T/p5verdict" || { echo "FAIL  bench.sh: its verdict was not found"; bad=$((bad + 1)); }
p5b() { # p5b WARDEN_STATUS STALLS VESSELS_OK (of 2)
    rm -rf "$T/p5"; mkdir "$T/p5"; echo "$1" > "$T/p5/warden-1.rc"; echo "$2" > "$T/p5/warden-1.stalls"; : > "$T/p5/warden-1.out"
    for _ in $(seq "$3"); do echo 'p5-bench-v0: 3 Seals, 0 publish failures, 2 segments pruned, 0 prune failures, agent ok' >> "$T/p5/warden-1.out"; done
    OUT="$T/p5" RUNS=1 P=2 FORKS=0 VESSEL_OK=' 0 publish failures, [0-9]+ segments pruned, 0 prune failures, agent ok$' \
        bash -c 'set -euo pipefail; . "$0"' "$T/p5verdict" >/dev/null 2>&1; echo $?
}
check "bench.sh: a good run exits 0" 0 "$(p5b 0 0 2)"
check "bench.sh: a Warden run that failed exits 1" 1 "$(p5b 1 0 2)"
check "bench.sh: a Vessel that did not end ok exits 1" 1 "$(p5b 0 0 1)"
check "bench.sh: a stall exits 1" 1 "$(p5b 0 3 2)"

# 11. b3-power.sh verify's check of the cut, cut out, over a work directory
sed -n '/^DRY=\${B3_DRY:-0}/,/^fi$/p' bench/p5/b3-power.sh > "$T/cut.lines"
grep -q 'boot-id' "$T/cut.lines" || { echo "FAIL  b3-power: its check of the cut was not found"; bad=$((bad + 1)); }
b3() { # b3 BOOT(same|other|none) STOPPED(0|1) DRY(0|1) -> 0 when verify would go on to grade
    rm -rf "$T/b3"; mkdir "$T/b3"
    case "$1" in same) cat /proc/sys/kernel/random/boot_id > "$T/b3/boot-id" ;; other) echo another-boot > "$T/b3/boot-id" ;; esac
    [ "$2" = 0 ] || date > "$T/b3/b3-stopped"
    WORK="$T/b3" B3_DRY="$3" bash -c 'set -Eeuo pipefail; die() { exit 2; }; say() { :; }; . "$0"' "$T/cut.lines" >/dev/null 2>&1; echo $?
}
check "b3: a machine that went down under a running round is graded" 0 "$(b3 other 0 0)"
check "b3: the same boot id is refused" 2 "$(b3 same 0 0)"
check "b3: a run that ended by itself is refused" 2 "$(b3 other 1 0)"
check "b3: a round with no boot id kept is refused" 2 "$(b3 none 0 0)"
check "b3: a dry round is graded" 0 "$(b3 same 1 1)"

[ "$bad" = 0 ] && echo "gate-exit-test: PASS" || { echo "gate-exit-test: $bad FAILED"; exit 1; }
