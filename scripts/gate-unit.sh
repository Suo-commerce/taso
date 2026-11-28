#!/usr/bin/env bash
# The release gate's unit step: every test of the workspace, and the ones
# that need the test-hooks feature with it.
#
#   scripts/gate-unit.sh
#
# Prints each test binary's result line, every FAILED and panicked line and
# cargo's own errors, then "<n> passed".  Exit 0 only if cargo test itself
# exited 0 and printed no FAILED.
set -uo pipefail
o=$(cargo test -q --workspace --no-fail-fast 2>&1)
rc=$?
# The tests that need a test hook (step 8, 8-10 (a)): a plain build has
# none, so they run again with the feature.
if [ "$rc" = 0 ]; then
    o="$o
$(cargo test -q -p taso-blk --features test-hooks --test client_daemon --no-fail-fast 2>&1)"
    rc=$?
fi
echo "$o" | grep -E "^test result|FAILED|panicked|^error"
# cargo's status decides: a test binary killed by a signal, or a build
# error, prints no "FAILED" (audit 2026-11-09: the step passed on both).
if [ "$rc" != 0 ] || echo "$o" | grep -q FAILED; then
    echo "cargo test: exit $rc"
    exit 1
fi
echo "$(echo "$o" | grep -E "^test result" | awk '{p+=$4} END {print p}') passed"
