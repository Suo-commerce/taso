#!/usr/bin/env bash
# e3-device.sh: E3-1 of P5 B2 (one-pager Taso_onepager_p5_b2_e3, rev. 4).
# The device under a Warden's directory that stops keeping writes at a
# chosen point: dm-flakey over a loop file (or a partition), three tables
# (up / drop / error), swapped without syncing the filesystem first.
#
#   sudo scripts/e3-device.sh check                    # the host, the three self-checks, the swap's time
#   sudo scripts/e3-device.sh make  NAME BACKING [MiB] # BACKING: a file (made, MiB, default 1024) or a block device
#   sudo scripts/e3-device.sh up    NAME               # pass everything through
#   sudo scripts/e3-device.sh drop  NAME               # acknowledge every write admitted from now, keep none
#   sudo scripts/e3-device.sh error NAME               # fail every write admitted from now
#   sudo scripts/e3-device.sh image NAME WORK OUT      # the crash image: tear the writers down, copy the backing, remount
#   sudo scripts/e3-device.sh down  NAME               # remove the device (and the loop if we made it)
#
# The swap is `dmsetup suspend --nolockfs --noflush`, then `reload`, then
# `resume`.  Without the two flags suspend freezes the filesystem above
# and flushes what is outstanding before the table changes, so the page
# cache becomes durable right before "drop" and every crash test passes
# for the wrong reason.  The flags do not recall writes already dispatched
# below the target: the cut is in what the target admits after the swap,
# not a rollback to the last sync (one-pager rev. 4, "The device").
#
# `image` is the teardown of protocol step 4, enumerated and proven: the
# Warden and taso-blkd killed by the caller first; here every runc
# container under WORK deleted, every ublk device of ours removed and
# waited for, every mount under the mountpoint gone innermost first, the
# mountpoint unmounted, the loop shown with no opener; then the backing
# copied raw to OUT *before* anything mounts it (ext4 replays its journal
# even on a read-only mount), the table set to up, and OUT's copy is what
# the Warden is restarted on.  A step that fails is a harness failure
# (exit 3), never a pass.
#
# State per NAME, under /run/taso-e3/NAME: backing, loop (if we made it),
# sectors.  Nothing else is touched.  Root.

set -euo pipefail

STATE_ROOT=/run/taso-e3
die()  { printf 'REFUSED: %s\n' "$*" >&2; exit 1; }
harness_fail() { printf 'HARNESS FAIL: %s\n' "$*" >&2; exit 3; }
say()  { printf '== %s\n' "$*"; }
pass() { printf 'OK    %s\n' "$*"; }
bad()  { printf 'BAD   %s\n' "$*"; BAD=$((BAD + 1)); }
BAD=0

[[ $(id -u) == 0 ]] || die "run as root"
cmd=${1:-}; shift || true

# ── host facts ──────────────────────────────────────────────────────────
have_flakey() { modprobe dm-flakey 2>/dev/null; dmsetup targets 2>/dev/null | grep -q '^flakey '; }
have_ublk()   { modprobe ublk_drv 2>/dev/null; [[ -c /dev/ublk-control ]]; }
have_loop()   { modprobe loop 2>/dev/null; [[ -c /dev/loop-control ]]; }

# ── device state ────────────────────────────────────────────────────────
state_dir() { echo "$STATE_ROOT/$1"; }
backing_of() { cat "$(state_dir "$1")/backing"; }
loop_of()    { cat "$(state_dir "$1")/loop" 2>/dev/null || true; }
sectors_of() { cat "$(state_dir "$1")/sectors"; }
dev_of()     { echo "/dev/mapper/$1"; }
# The flakey table: "0 SECTORS flakey DEV 0 UP DOWN NFEATURES [FEATURE]".
# The features apply only during the DOWN seconds of the up/down cycle
# (dm-flakey.rst; taso-test 2026-10-27: with "1 0" drop_writes never
# applied, and self-check 1 said so).  So up is "1 0" (always up) and drop
# and error are "0 1" (always down): the harness decides when the device
# fails by swapping tables, never a timer.
table() { # table NAME MODE
    local dev cycle feats
    dev=$(loop_of "$1"); [[ -n "$dev" ]] || dev=$(backing_of "$1")
    case "$2" in
        up)    cycle="1 0"; feats="0" ;;
        drop)  cycle="0 1"; feats="1 drop_writes" ;;
        error) cycle="0 1"; feats="1 error_writes" ;;
        *) die "mode $2" ;;
    esac
    echo "0 $(sectors_of "$1") flakey $dev 0 $cycle $feats"
}
# Swap NAME to MODE without syncing the filesystem above.  Prints the
# swap's wall time in ms on stdout (the resolution of a point).
swap() { # swap NAME MODE
    local t0 t1
    t0=$(date +%s%N)
    dmsetup suspend --nolockfs --noflush "$1"
    dmsetup reload "$1" --table "$(table "$1" "$2")"
    dmsetup resume "$1"
    t1=$(date +%s%N)
    echo "$(( (t1 - t0) / 1000000 ))"
}
# The table: "0 SECTORS flakey DEV OFFSET UP DOWN NFEATURES [FEATURE]": no feature is up.
mode_of() { dmsetup table "$1" | awk '{ print ($8 == 0) ? "up" : $9 }' | sed 's/_writes//'; }

# ── commands ────────────────────────────────────────────────────────────
do_make() { # make NAME BACKING [MiB]
    local name=$1 backing=$2 mib=${3:-1024} sd loop
    [[ -n "$name" && -n "$backing" ]] || die "make NAME BACKING [MiB]"
    dmsetup info "$name" >/dev/null 2>&1 && die "$name exists (down it first)"
    [[ -e "$(dev_of "$name")" ]] && { rm -f "$(dev_of "$name")"; say "removed a stale node $(dev_of "$name")"; }
    have_flakey || die "no dm-flakey for kernel $(uname -r)"
    sd=$(state_dir "$name"); mkdir -p "$sd"
    if [[ -b "$backing" ]]; then
        echo "$backing" > "$sd/backing"
        rm -f "$sd/loop"
    else
        have_loop || die "no loop devices"
        [[ -e "$backing" ]] && die "$backing exists; name a fresh file or a block device"
        truncate -s "${mib}M" "$backing"
        loop=$(losetup --find --show --direct-io=on "$backing") || loop=$(losetup --find --show "$backing")
        echo "$backing" > "$sd/backing"; echo "$loop" > "$sd/loop"
    fi
    blockdev --getsz "$(loop_of "$name")" > "$sd/sectors" 2>/dev/null || blockdev --getsz "$backing" > "$sd/sectors"
    dmsetup create "$name" --table "$(table "$name" up)"
    udevadm settle 2>/dev/null || true
    say "$name: $(dev_of "$name") over ${loop:-$backing} ($(sectors_of "$name") sectors), up"
}

do_mode() { # up|drop|error NAME
    local mode=$1 name=$2 ms
    [[ -n "$name" ]] || die "$mode NAME"
    [[ -e "$(dev_of "$name")" ]] || die "$name: no such device"
    ms=$(swap "$name" "$mode")
    say "$name: $mode (swap ${ms} ms)"
}

# Mounts under $1, innermost first.
mounts_under() { awk -v r="$1" '$5 == r || index($5, r "/") == 1 { print length($5), $5 }' /proc/self/mountinfo | sort -rn | cut -d' ' -f2-; }
# ublk block devices present (ids), whatever made them.
ublk_ids() { ls /dev/ublkb* 2>/dev/null | sed 's|/dev/ublkb||' || true; }

do_image() { # image NAME WORK OUT
    local name=$1 work=$2 out=$3 mnt dev loop m n
    [[ -n "$name" && -n "$work" && -n "$out" ]] || die "image NAME WORK OUT"
    dev=$(dev_of "$name"); [[ -e "$dev" ]] || die "$name: no such device"
    [[ $(mode_of "$name") != up ]] || die "$name is up; the image is taken under drop or error"
    mnt=$(awk -v d="$dev" -v r="$(readlink -f "$dev")" '$10 == d || $10 == r { print $5; exit }' /proc/self/mountinfo)
    say "image of $name ($(mode_of "$name")): mount ${mnt:-none}, work $work"
    # 1. runc containers under WORK: deleted, none left
    for d in "$work"/run/runc "$work"/*/run/runc; do
        [[ -d "$d" ]] || continue
        for c in $(runc --root "$d" list -q 2>/dev/null); do
            runc --root "$d" delete --force "$c" || harness_fail "runc delete $c under $d"
        done
    done
    pass "runc: none left under $work"
    # 2. ublk devices: a killed taso-blkd leaves its devices in the kernel with
    #    no server; they hold nothing under the mountpoint open, and the next
    #    taso-blkd reaps them at its start.  Here: every mount on one is
    #    taken down, no live taso-blkd may own one, and what is left is said.
    if [[ -n "$mnt" ]] && fuser -m "$mnt" >/dev/null 2>&1; then
        harness_fail "something still holds $mnt open: $(fuser -vm "$mnt" 2>&1 | tail -n +2 | awk '{print $1"/"$2}' | tr '\n' ' ') (kill the Warden and its taso-blkd before image; the host's own taso-blkd is not one of them)"
    fi
    for m in $(awk '$10 ~ "^/dev/ublkb" { print length($5), $5 }' /proc/self/mountinfo | sort -rn | cut -d' ' -f2-); do
        umount "$m" 2>/dev/null || umount -l "$m" 2>/dev/null || harness_fail "umount $m (on a ublk device)"
    done
    n=$(ublk_ids | wc -l)
    pass "ublk: nothing holds the mountpoint, no mount on a ublk device; $n device(s) present (E3's dead ones are reaped by the next taso-blkd; the host's own may be among them)"
    # 3. mounts under the mountpoint, innermost first, then the mountpoint
    if [[ -n "$mnt" ]]; then
        for m in $(mounts_under "$mnt"); do
            [[ "$m" == "$mnt" ]] && continue
            umount "$m" || umount -l "$m" || harness_fail "umount $m"
        done
        umount "$mnt" || harness_fail "umount $mnt (busy: an opener survives the teardown)"
        pass "mounts: $mnt and everything under it unmounted"
    fi
    # 4. the device has no opener
    [[ -z "$(ls "/sys/block/$(basename "$(readlink -f "$dev")")/holders" 2>/dev/null)" ]] || harness_fail "$dev still has holders"
    pass "device: no holders"
    # 5. the raw image, before any mount (the device's buffer cache dropped first)
    blockdev --flushbufs "$dev"
    loop=$(loop_of "$name")
    dd if="${loop:-$(backing_of "$name")}" of="$out" bs=4M conv=fsync status=none || harness_fail "dd to $out"
    pass "image: $out ($(stat -c %s "$out") bytes, sha256 $(sha256sum "$out" | cut -c1-16)…)"
    # 6. the table back to up; the caller mounts OUT's copy (or a loop over it), not this device
    swap "$name" up >/dev/null
    say "$name: up; restart the Warden on a copy of $out, never on $dev"
    (( BAD == 0 )) || harness_fail "$BAD step(s) BAD above"
}

do_down() { # down NAME
    local name=$1 loop
    [[ -n "$name" ]] || die "down NAME"
    if dmsetup info "$name" >/dev/null 2>&1; then
        for m in $(mounts_under / | grep -F "$(dev_of "$name")" || true); do umount "$m" 2>/dev/null || true; done
        dmsetup remove "$name" 2>/dev/null || dmsetup remove --retry "$name"
    fi
    rm -f "$(dev_of "$name")"
    loop=$(loop_of "$name" 2>/dev/null || true)
    [[ -n "$loop" ]] && losetup -d "$loop" 2>/dev/null || true
    rm -rf "$(state_dir "$name")"
    say "$name: down"
}

# ── check: the host, and the three self-checks on a scratch device ─────
do_check() {
    local t ms h0 h1 h2
    # Not locals: the EXIT trap reads them after this function has returned.
    CHECK_NAME=e3check; CHECK_IMG=; CHECK_MNT=
    local name=$CHECK_NAME img mnt
    say "host $(hostname), kernel $(uname -r)"
    have_flakey && pass "dm-flakey target" || bad "no dm-flakey target for $(uname -r)"
    have_ublk  && pass "ublk_drv (/dev/ublk-control)" || bad "no ublk_drv for $(uname -r)"
    have_loop  && pass "loop devices" || bad "no loop devices"
    command -v dmsetup >/dev/null && pass "dmsetup $(dmsetup --version 2>/dev/null | head -1 | awk '{print $NF}')" || bad "no dmsetup"
    command -v mkfs.ext4 >/dev/null && pass "mkfs.ext4" || bad "no mkfs.ext4"
    (( BAD == 0 )) || die "$BAD host fact(s) BAD; E3 needs all of them"
    # A leftover scratch device from an aborted check is ours to remove.
    if dmsetup info "$name" >/dev/null 2>&1 || [[ -e "$(dev_of "$name")" || -d "$(state_dir "$name")" ]]; then
        do_down "$name" >/dev/null 2>&1 || true; say "removed a leftover $name from an earlier check"
    fi

    img=$(mktemp -p "${TMPDIR:-/var/tmp}" e3check.XXXXXX.img); rm -f "$img"
    mnt=$(mktemp -d -p "${TMPDIR:-/var/tmp}" e3check.XXXXXX.mnt)
    CHECK_IMG=$img; CHECK_MNT=$mnt
    trap 'set +e; umount "$CHECK_MNT" 2>/dev/null; do_down "$CHECK_NAME" >/dev/null 2>&1; rm -rf "$CHECK_MNT" "$CHECK_MNT.work" "$CHECK_IMG" "$CHECK_IMG".copy' EXIT
    do_make "$name" "$img" 256 >/dev/null
    mkfs.ext4 -q -F "$(dev_of "$name")"
    mount -o errors=remount-ro "$(dev_of "$name")" "$mnt"
    say "scratch: $(dev_of "$name") on $mnt, ext4 errors=remount-ro"

    # Self-check 1: a synced marker survives a drop swap, an unsynced one does not reach the backing
    # (it may: writeback dispatched before the swap is kept; what must hold is the synced one).
    echo "synced-marker" > "$mnt/synced"; sync -f "$mnt/synced"
    echo "unsynced-marker" > "$mnt/unsynced"      # in the page cache only
    ms=$(swap "$name" drop)
    echo "unsynced-after" > "$mnt/after"          # admitted under drop: must not reach the backing
    sync -f "$mnt/after" 2>/dev/null || true      # the sync is acknowledged (drop_writes acks), nothing kept
    umount "$mnt" || umount -l "$mnt"
    blockdev --flushbufs "$(dev_of "$name")"
    h1=$(sha256sum "$(loop_of "$name")" | cut -d' ' -f1)
    swap "$name" up >/dev/null
    mount -o ro,noload "$(dev_of "$name")" "$mnt"   # noload: no journal replay, the image as it is
    if [[ "$(cat "$mnt/synced" 2>/dev/null)" == "synced-marker" ]]; then pass "self-check 1: the synced marker survived the drop swap (swap ${ms} ms)"; else bad "self-check 1: the synced marker is GONE after the drop swap — the swap flushed nothing it should not have, yet the marker is missing; the device is not usable"; fi
    [[ -e "$mnt/after" ]] && bad "self-check 1: a file written under drop reached the backing (drop_writes did not drop)" || pass "self-check 1: nothing admitted under drop reached the backing (unsynced-before-swap: $([[ -e "$mnt/unsynced" ]] && echo kept || echo gone), either is allowed)"
    umount "$mnt"

    # Self-check 2: writes admitted under drop leave the backing's hash unchanged
    swap "$name" drop >/dev/null
    if dd if=/dev/urandom of="$(dev_of "$name")" bs=1M count=8 seek=16 conv=fsync status=none; then
        h2=$(sha256sum "$(loop_of "$name")" | cut -d' ' -f1)
        [[ "$h1" == "$h2" ]] && pass "self-check 2: 8 MiB written and fsynced under drop, acknowledged, backing hash unchanged" || bad "self-check 2: backing changed under drop"
    else
        bad "self-check 2: dd under drop failed (drop must acknowledge, not refuse; that is error's job)"
    fi
    # and the same under error must fail
    swap "$name" error >/dev/null
    if dd if=/dev/urandom of="$(dev_of "$name")" bs=1M count=1 seek=16 conv=fsync status=none 2>/dev/null; then
        bad "self-check 2: a write under error was accepted"
    else
        pass "self-check 2: a write under error was refused"
    fi
    swap "$name" drop >/dev/null

    # Self-check 3: the teardown (image) leaves the backing unchanged, and the copy equals it
    mkdir -p "$mnt.work"
    do_image "$name" "$mnt.work" "$img.copy" >/dev/null || bad "self-check 3: image failed"
    h0=$(sha256sum "$(loop_of "$name")" | cut -d' ' -f1)
    [[ "$h0" == "$h1" ]] && pass "self-check 3: teardown left the backing unchanged" || bad "self-check 3: the teardown changed the backing"
    [[ "$(sha256sum "$img.copy" | cut -d' ' -f1)" == "$h1" ]] && pass "self-check 3: the raw copy equals the backing" || bad "self-check 3: the copy differs from the backing"
    rm -rf "$mnt.work"

    # The swap's time, five more swaps
    t=""; for _ in 1 2 3 4 5; do t="$t $(swap "$name" drop) $(swap "$name" up)"; done
    say "swap time (ms, drop/up alternating): $ms$t — the resolution of a timing point"
    (( BAD == 0 )) && say "E3-1 check: all OK" || die "E3-1 check: $BAD BAD"
}

case "$cmd" in
    check) do_check ;;
    make)  do_make "$@" ;;
    up|drop|error) do_mode "$cmd" "$@" ;;
    image) do_image "$@" ;;
    down)  do_down "$@" ;;
    *) sed -n '2,32p' "$0"; exit 1 ;;
esac
