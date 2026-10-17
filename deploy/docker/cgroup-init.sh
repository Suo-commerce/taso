#!/bin/sh
# Entrypoint of the taso-wardend image: make the container's cgroup able
# to hold the agents' cgroups, then exec the command (taso-wardend).
#
# Why.  On cgroup v2 a container gets its own cgroup namespace, and its
# processes sit in the root of it.  A cgroup with processes in it cannot
# hand domain controllers (memory, pids) to child cgroups ("no internal
# processes"), so runc cannot create an agent's cgroup with limits:
#
#   cannot enter cgroupv2 "/sys/fs/cgroup/taso-…" with domain controllers
#   -- it is in an invalid state
#
# (D2, measured on taso-test 2026-10-17: /proc/self/cgroup "0::/",
# cgroup.procs 2 entries, cgroup.subtree_control empty.)  The fix, as
# Docker-in-Docker does it: move this container's own processes into a
# child cgroup ("init"), then enable the controllers for the children.
#
# Only at the root of a cgroup namespace ("0::/"): with the host's cgroup
# namespace this would move processes it does not own, so it does nothing
# there.  memory and pids are required (the agents' limits); a failure to
# enable them stops the start here, with a clear reason, instead of every
# agent failing later.  Other controllers are enabled if available.
set -eu

if [ "$#" -eq 0 ]; then
    echo "cgroup-init: no command to run" >&2
    exit 2
fi

CG=/sys/fs/cgroup
if [ "$(cat /proc/self/cgroup 2>/dev/null)" = "0::/" ] && [ -f "$CG/cgroup.controllers" ]; then
    mkdir -p "$CG/init"
    # Processes can appear while they are moved: repeat until none is left.
    i=0
    while [ -s "$CG/cgroup.procs" ]; do
        while read -r pid; do
            echo "$pid" > "$CG/init/cgroup.procs" 2>/dev/null || :
        done < "$CG/cgroup.procs"
        i=$((i + 1))
        if [ "$i" -ge 20 ]; then
            echo "cgroup-init: processes keep appearing in $CG: $(tr '\n' ' ' < "$CG/cgroup.procs")" >&2
            exit 1
        fi
    done
    available=" $(cat "$CG/cgroup.controllers") "
    for c in memory pids; do
        case "$available" in
            *" $c "*) ;;
            *) echo "cgroup-init: the $c controller is not available here ($available): agents need it" >&2; exit 1 ;;
        esac
        if ! echo "+$c" > "$CG/cgroup.subtree_control"; then
            echo "cgroup-init: could not enable $c for child cgroups" >&2
            exit 1
        fi
    done
    for c in cpu io; do
        case "$available" in *" $c "*) echo "+$c" > "$CG/cgroup.subtree_control" 2>/dev/null || : ;; esac
    done
fi

exec "$@"
