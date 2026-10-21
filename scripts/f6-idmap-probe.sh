#!/usr/bin/env bash
# f6-idmap-probe.sh: can a forked Vessel in another uid slot use its
# parent's files through an idmapped mount, without a chown pass?
# (Fencing review F6, decided before P3 forks.)
#
# A fork is a branch of the parent's block log: the same ext4, its files
# owned by the parent's host uid range (slot A).  The child runs in
# slot B.  An idmapped bind mount shows slot A's ids as slot B's, and
# writes slot B's ids back as slot A's, with nothing on disk changed.
# Whether a filesystem allows it is a property of the filesystem
# (FS_ALLOW_IDMAP) and the kernel, not of the block device under it, so a
# loop device stands in for a ublk device here.
#
# Predictions (written before the first run, 2026-10-21):
#   P1  mount accepts X-mount.idmap on this ext4 (kernel >= 5.12, util-linux >= 2.39)
#   P2  through the idmapped mount, A's root (A+0) shows as B+0, A's 1000 as B+1000
#   P3  B+0 creates a file through the mount; on disk it is owned by A+0
#   P4  B+1000 writes into a directory owned (on disk) by A+1000
#   P5  A+1000 cannot create through the mount (its id is outside the
#       mapping: EOVERFLOW or EACCES), so a child cannot act as its parent
#   P6  runc on this host is >= 1.2 (idmapped mounts in the OCI config)
#
#   scripts/f6-idmap-probe.sh            (as root, from anywhere)
#
# Touches, and nothing else:
#   /var/lib/taso-f6/probe.img           (sparse 256 MiB, removed at the end)
#   /mnt/taso-f6/{disk,child}            (mounted, then unmounted and removed)
#   one loop device                      (detached at the end)
# Prints the report; also saved to /root/taso-f6-probe.txt.

set -euo pipefail

BASE=${F6_HOST_UID_BASE:-200000}   # deploy/docker uses 200000
A=$((BASE + 1 * 65536))            # slot 1: the parent
B=$((BASE + 2 * 65536))            # slot 2: the child
DIR=/var/lib/taso-f6
IMG=$DIR/probe.img
MNT=/mnt/taso-f6
REPORT=/root/taso-f6-probe.txt
LOOP=

die() { printf 'ABORT: %s\n' "$*" >&2; exit 2; }
out() { printf '%s\n' "$*" | tee -a "$REPORT"; }
verdict() { # $1 name, $2 0 = held
    if [ "$2" = 0 ]; then out "$1 held"; else out "$1 MISSED"; fi
}

cleanup() {
    set +e
    mountpoint -q "$MNT/child" && umount "$MNT/child"
    mountpoint -q "$MNT/disk" && umount "$MNT/disk"
    [ -n "$LOOP" ] && losetup -d "$LOOP"
    rm -f "$IMG"
    rmdir "$MNT/child" "$MNT/disk" "$MNT" "$DIR" 2>/dev/null
}
trap cleanup EXIT

[ "$(id -u)" = 0 ] || die "run as root"
for c in mkfs.ext4 losetup mount setpriv stat; do command -v "$c" >/dev/null || die "$c missing"; done
mountpoint -q "$MNT/disk" 2>/dev/null && die "$MNT/disk is mounted: a previous run did not clean up"

: > "$REPORT"
out "== host: $(hostname), kernel $(uname -r), $(mount --version | head -1)"
out "== runc: $(runc --version 2>/dev/null | head -1 || echo 'not installed')"
out "== slots: base $BASE, parent A = $A, child B = $B"

mkdir -p "$DIR" "$MNT/disk" "$MNT/child"
truncate -s 256M "$IMG"
mkfs.ext4 -q -F "$IMG"
LOOP=$(losetup --find --show "$IMG")
mount "$LOOP" "$MNT/disk"

# The parent's files, as a Vessel in slot A leaves them.
install -d -o "$A" -g "$A" -m 755 "$MNT/disk/root"
install -d -o $((A + 1000)) -g $((A + 1000)) -m 755 "$MNT/disk/root/home"
echo parent > "$MNT/disk/root/home/notes"
chown $((A + 1000)):$((A + 1000)) "$MNT/disk/root/home/notes"

# P1: the child's view.  util-linux's form is type:from:to:count, where
# `from` is the id stored on disk and `to` the id the mount shows: A..A+65535
# on disk appear as B..B+65535.  (The first draft had them the other way
# round; the dry run showed every file as 65534, the unmapped id.)
p1=0
mount --bind -o "X-mount.idmap=b:$A:$B:65536" "$MNT/disk" "$MNT/child" 2>>"$REPORT" || p1=1
verdict "P1 (idmapped bind mount accepted)" $p1
[ $p1 = 0 ] || { out "== the rest needs P1; F6 falls back to a chown pass"; exit 1; }

# P2: ownership as the child sees it.
own() { stat -c '%u:%g' "$1"; }
out "   disk:  root $(own "$MNT/disk/root"), home $(own "$MNT/disk/root/home"), notes $(own "$MNT/disk/root/home/notes")"
out "   child: root $(own "$MNT/child/root"), home $(own "$MNT/child/root/home"), notes $(own "$MNT/child/root/home/notes")"
p2=1
[ "$(own "$MNT/child/root")" = "$B:$B" ] && [ "$(own "$MNT/child/root/home/notes")" = "$((B + 1000)):$((B + 1000))" ] && p2=0
verdict "P2 (A's ids show as B's)" $p2

as() { local u=$1; shift; setpriv --reuid="$u" --regid="$u" --clear-groups "$@"; }

# P3: the child's root creates; on disk it is the parent's root.
p3=1
if as "$B" touch "$MNT/child/root/by-child-root" 2>>"$REPORT"; then
    out "   by-child-root on disk: $(own "$MNT/disk/root/by-child-root")"
    [ "$(own "$MNT/disk/root/by-child-root")" = "$A:$A" ] && p3=0
fi
verdict "P3 (B+0 writes, disk says A+0)" $p3

# P4: the child's user 1000 writes into the parent's user 1000's directory.
p4=1
if as $((B + 1000)) sh -c "echo child >> '$MNT/child/root/home/notes'" 2>>"$REPORT"; then
    [ "$(tail -1 "$MNT/disk/root/home/notes")" = child ] && [ "$(own "$MNT/disk/root/home/notes")" = "$((A + 1000)):$((A + 1000))" ] && p4=0
fi
verdict "P4 (B+1000 writes A+1000's file)" $p4

# P5: the parent's id is not in the child's mapping.
p5=1
if as $((A + 1000)) touch "$MNT/child/root/home/by-parent" 2>/dev/null; then
    out "   by-parent was created: the parent's id can act through the child's mount"
else
    p5=0
fi
verdict "P5 (A+1000 refused through the child's mount)" $p5

# P6: runc's version, for idmapped mounts in the OCI config.
p6=1
v=$(runc --version 2>/dev/null | awk 'NR==1 {print $3}')
if [ -n "$v" ]; then
    maj=${v%%.*}; rest=${v#*.}; min=${rest%%.*}
    { [ "$maj" -gt 1 ] || { [ "$maj" = 1 ] && [ "$min" -ge 2 ]; }; } && p6=0
fi
verdict "P6 (runc ${v:-none} >= 1.2)" $p6

total=$((p1 + p2 + p3 + p4 + p5 + p6))
out "== $((6 - total))/6 predictions held"
if [ $total = 0 ]; then
    out "== F6: an idmapped mount works here; no chown pass needed"
else
    out "== F6: see the misses above before deciding"
    exit 1
fi
