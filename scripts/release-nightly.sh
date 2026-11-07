#!/usr/bin/env bash
# release-nightly.sh: release-gate.sh full on origin/main, every night, on
# taso-test (D&D nightly-a, 2026-11-07).  No GitHub Actions: GitHub only
# serves the fetch.
#
#   scripts/release-nightly.sh install   once, as root, from a clone: puts
#                                        this script at $BIN and a systemd
#                                        timer (01:00, caught up after a
#                                        reboot) that runs it
#   taso-nightly                         (what the timer runs) one night
#
# A night: fetch origin/main into its own clone ($CLONE; your checkout is
# never touched), skip if that commit already passed full, else run
# `release-gate.sh full` with its output in $REL/<commit>-full-<date>.
# One line per night in $REL/nightly.log; the last $KEEP runs are kept.
# release-gate.sh holds a lock for its whole run, so a night and a gate
# started by hand never overlap: the second one finds it busy (a night is
# then skipped, and says so).  A single gate script run by hand takes no
# lock: start none near 01:00.
#
# Disk: release-gate.sh cleans at the start of every run, and the nightly
# runs `release-gate.sh clean` on the nights it skips, so leftovers go
# daily; its clone's target/ is cleaned past $TARGET_GIB GiB (15).
#
# Morning:  tail /root/release/nightly.log
# Rerun one night by hand:  systemctl start taso-nightly
# Reinstall after this script changes:  scripts/release-nightly.sh install

set -uo pipefail

CLONE=${CLONE:-/root/taso-nightly}
REL=${REL:-/root/release}
KEEP=${KEEP:-14}
TARGET_GIB=${TARGET_GIB:-15}
BIN=/usr/local/sbin/taso-nightly
LOG=$REL/nightly.log

die() { echo "release-nightly: $*" >&2; exit 2; }
[ "$(id -u)" = 0 ] || die "run as root"

if [ "${1:-}" = install ]; then
    url=$(git remote get-url origin 2>/dev/null) || die "run install from a clone of the repository"
    [ -d "$CLONE/.git" ] || git clone -q "$url" "$CLONE" || die "cannot clone $url to $CLONE"
    install -m 755 "$0" "$BIN"
    cat > /etc/systemd/system/taso-nightly.service <<EOF
[Unit]
Description=Taso release gate (full) on origin/main

[Service]
Type=oneshot
Environment=HOME=/root PATH=/root/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ExecStart=$BIN
TimeoutStartSec=12h
EOF
    cat > /etc/systemd/system/taso-nightly.timer <<EOF
[Unit]
Description=Taso release gate every night

[Timer]
OnCalendar=*-*-* 01:00
Persistent=true

[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload && systemctl enable --now taso-nightly.timer \
        && echo "installed: $BIN, clone $CLONE, results in $REL; next: $(systemctl show -p NextElapseUSecRealtime --value taso-nightly.timer)"
    exit
fi
[ -z "${1:-}" ] || die "usage: $0 [install]"

mkdir -p "$REL"
note() { echo "$(date '+%F %H:%M') $*" | tee -a "$LOG"; }
[ -d "$CLONE/.git" ] || { note "-- no clone at $CLONE (run install)"; exit 2; }
cd "$CLONE" || exit 2
git fetch -q origin || { note "-- fetch failed"; exit 1; }
git checkout -q --detach origin/main && git reset -q --hard origin/main || { note "-- checkout failed"; exit 1; }
c=$(git rev-parse --short HEAD)
if grep -q " $c full PASS" "$LOG" 2>/dev/null; then
    scripts/release-gate.sh clean >/dev/null 2>&1
    note "$c full skipped: passed already ($(df --output=avail -B1G /root | tail -1 | tr -d ' ') GiB free)"
    exit 0
fi
# The nightly's own build folder: cleaned when it passes $TARGET_GIB.
if [ -d target ] && [ "$(du -s -BG target | cut -dG -f1)" -gt "$TARGET_GIB" ]; then
    cargo clean -q && note "-- cargo clean: target/ was over $TARGET_GIB GiB"
fi
out=$REL/$c-full-$(date +%Y%m%d-%H%M)
OUT=$out scripts/release-gate.sh full > "$REL/last-night.txt" 2>&1
rc=$?
case $rc in
    0) note "$c full PASS ($out)" ;;
    3) note "$c full skipped: another gate was running" ;;
    *) note "$c full FAIL exit $rc: $(tail -1 "$out/summary.txt" 2>/dev/null || tail -1 "$REL/last-night.txt") ($out)" ;;
esac
# keep the last $KEEP runs
ls -1dt "$REL"/*-full-* 2>/dev/null | tail -n +$((KEEP + 1)) | xargs -r rm -rf
exit $rc
