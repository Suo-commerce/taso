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

[ "$bad" = 0 ] && echo "gate-exit-test: PASS" || { echo "gate-exit-test: $bad FAILED"; exit 1; }
