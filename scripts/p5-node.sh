#!/usr/bin/env bash
# p5-node.sh: set up one P5 measurement host from a fresh Ubuntu 26.04, the
# same way every time, and print what it found (Taso_plan_p5, §2 A1).
#
#   sudo scripts/p5-node.sh check                              read-only
#   sudo scripts/p5-node.sh setup --disk /dev/nvmeXn1 --commit <sha>
#
# Run setup under tmux with a log, from a root shell:
#   tmux new -s p5
#   scripts/p5-node.sh setup ... 2>&1 | tee /root/p5-setup.log
# An ssh session that drops takes a plain run with it (SIGHUP; apt died
# mid-unpack on taso-p5, 2026-10-26); under tmux the run goes on and
# `tmux attach -t p5` or the log shows where it is.
#
# check reads the host and prints the report; it changes nothing and works
# on any machine (taso-test included).  setup refuses the host unless it is
# Ubuntu 26.04, the disk is a whole NVMe drive with no partitions, no
# filesystem or pool signature and no mount, and the commit exists; then
# it does, in this order, each step skipped when already done:
#
#   1 hostname     taso-p5 (kept over reboots), so a prompt says which
#                  machine a command runs on
#   2 packages     apt: git, the C toolchain, pkg-config, libclang-dev
#                  (libublk's bindings), python3, jq, curl, chrony, runc,
#                  e2fsprogs, util-linux, fio, zfsutils-linux, nvme-cli
#   3 coreutils    GNU coreutils in place of uutils (Ubuntu 25.10 and later
#                  ship uutils; xfstests and our scripts assume GNU: 271 quick
#                  tests failed on an option before testing anything,
#                  taso-test 2026-10-18).  Same swap as blk-fstests.sh setup:
#                  the compilers marked manually installed, coreutils-from-gnu
#                  in, coreutils-from-uutils and the build-essential bundle
#                  out, a pin so upgrades keep it; refused if apt would
#                  remove anything else.  Checked after: ls is GNU, gcc
#                  compiles.
#   4 Rust         rustup stable, minimal profile plus rustfmt (bindgen needs
#                  it), under /root/.cargo
#   5 ublk_drv     loaded now and at boot (/etc/modules-load.d/taso-ublk.conf)
#   6 the disk     GPT with two partitions of equal size on the named NVMe:
#                    taso-zfs  -> zpool "taso" (ashift 12, lz4, atime off,
#                                 mountpoint /taso), dataset taso/vessel
#                    taso-blk  -> ext4, mounted at /var/lib/taso by label
#                                 (noatime; the block log, the packs, the
#                                 benchmark scratch, TMPDIR)
#                  Both storages on one drive: the comparison in §3 is then
#                  of the storage, not of two drives.  /var/lib/taso-blk is a
#                  symlink into it, so the blk-*.sh scripts land there too.
#   6b RCU         /sys/kernel/rcu_expedited=1, now and at boot
#                  (/etc/tmpfiles.d/taso-rcu.conf; it is a sysfs attribute,
#                  not a sysctl): a filesystem freeze
#                  takes the superblock's three write barriers, each a
#                  full RCU grace period of ~10 ms on a 24-thread host
#                  (scripts/blk-freeze-ftrace.sh, taso-p5 2026-10-26);
#                  expedited, they are under a millisecond.  P=64 Seal
#                  p50 120 -> 80 ms, freeze 70 -> 32, CPU per turn the
#                  same.  The cost: an expedited grace period sends an IPI
#                  to every CPU; on a host whose work is Vessels, nothing
#                  measurable.  A1 sets it; taso init will set it and say so.
#   7 TMPDIR       /var/lib/taso/tmp, exported for root logins with
#                  TASO_ZFS_DATASET=taso/vessel and cargo's PATH
#                  (/etc/profile.d/taso-p5.sh): temporary files of tests and
#                  benchmarks are on the measured NVMe, never on the root
#                  disk or in RAM
#   8 the repo     /root/taso at the named commit (detached), cloned from
#                  GitHub if missing; refused if the tree there is dirty
#   9 build        cargo build --release of taso-blkd, taso-wardend,
#                  taso-coordd and taso-logcheck, installed to /usr/local/bin
#                  (log /root/taso-build.log, shown only on failure)
#  10 the report   printed and saved to /var/lib/taso/p5-node-report.txt
#
# Not done here, on purpose: no coordinator or Warden is started (B1's
# harness starts what it measures and stops it after), no CPU governor,
# hugepage or scheduler setting is changed (the report prints them; a
# change is a measured step, not a setup step), and nothing is measured
# about durability: the report prints what the kernel and the drive
# *report* (write cache, FUA, FDP, zones); whether a flush reaches the
# medium is A2's measurement.
#
# Rerunning setup on a prepared host is safe: every step checks before it
# acts, and a disk that already carries exactly our two partitions is
# accepted, not reformatted.
#
# At the provider's install: give the OS one drive and leave the other
# untouched (no software RAID across both), or there is no empty NVMe to
# name.  check shows which drive is free.

set -euo pipefail

REPO=/root/taso
REPO_URL=${REPO_URL:-https://github.com/Suo-commerce/taso}
DATA=/var/lib/taso
REPORT=$DATA/p5-node-report.txt
HOST=taso-p5
POOL=taso

mode=${1:-}; shift || true
DISK=; COMMIT=
while [[ $# -gt 0 ]]; do
    case "$1" in
        --disk)   DISK=${2:-}; shift 2 ;;
        --commit) COMMIT=${2:-}; shift 2 ;;
        *) echo "unknown argument: $1" >&2; exit 64 ;;
    esac
done
case "$mode" in
    check) ;;
    setup) [[ -n "$DISK" && -n "$COMMIT" ]] || { echo "usage: $0 setup --disk /dev/nvmeXn1 --commit <sha>" >&2; exit 64; } ;;
    *) echo "usage: $0 check | $0 setup --disk /dev/nvmeXn1 --commit <sha>" >&2; exit 64 ;;
esac
[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 2; }

die()  { printf 'REFUSED: %s\n' "$*" >&2; exit 1; }
step() { printf '\n== %s\n' "$*"; }
export DEBIAN_FRONTEND=noninteractive

# The apt locks of a fresh node's first-boot updates, waited for with apt's
# own non-blocking lock (gate-cloud/node-setup.sh; measured there 2026-10-21:
# DPkg::Lock::Timeout does not cover the lists lock).
apt_wait() {
    python3 - <<'PY' || die "apt is still locked after 10 minutes"
import fcntl, sys, time
locks = ["/var/lib/apt/lists/lock", "/var/lib/dpkg/lock-frontend", "/var/lib/dpkg/lock"]
said = False
for _ in range(600):
    held = None
    for path in locks:
        try:
            f = open(path, "w"); fcntl.lockf(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.lockf(f, fcntl.LOCK_UN); f.close()
        except OSError:
            held = path; break
    if held is None:
        sys.exit(0)
    if not said:
        print("waiting for the apt lock (%s is held: a first-boot apt-daily or unattended-upgrades run)" % held, flush=True)
        said = True
    time.sleep(1)
sys.exit("apt lock %s still held" % held)
PY
}
apt_get() { apt_wait; apt-get -o DPkg::Lock::Timeout=600 -q "$@"; }
coreutils_version() { ls --version 2>/dev/null | head -n 1; }
gnu_coreutils() { coreutils_version | grep -q 'GNU coreutils'; }
has() { command -v "$1" >/dev/null 2>&1; }
q() { cat "/sys/block/$1/queue/$2" 2>/dev/null || echo -; }

# ---- what the host is ---------------------------------------------------------
kernel=$(uname -r)
os_id=$(. /etc/os-release && echo "${ID:-?}")
os_ver=$(. /etc/os-release && echo "${VERSION_ID:-?}")
root_src=$(findmnt -no SOURCE /)
root_disk=$(lsblk -no PKNAME "$root_src" 2>/dev/null | head -1)
[[ -n "$root_disk" ]] || root_disk=$(basename "$root_src")

# A disk is empty when it has no partitions, no signature blkid can name,
# no mount on it or under it, and is not the root disk.
disk_empty() { # disk_empty /dev/nvmeXn1 -> prints reasons, returns 1 if not empty
    local d=$1 n reasons=
    n=$(basename "$d")
    [[ -z "$(lsblk -no NAME "$d" | tail -n +2)" ]] || reasons+="has partitions; "
    [[ -z "$(blkid -p -o value -s TYPE "$d" 2>/dev/null)" ]] || reasons+="carries a $(blkid -p -o value -s TYPE "$d") signature; "
    [[ -z "$(lsblk -no MOUNTPOINTS "$d" | tr -d '[:space:]')" ]] || reasons+="is mounted; "
    ! zpool status 2>/dev/null | grep -q "^[[:space:]]*$n" || reasons+="is in a ZFS pool; "
    [[ -z "$reasons" ]] && return 0
    printf '%s' "${reasons%; }"; return 1
}
# Our layout, exactly: GPT, two partitions labelled taso-zfs and taso-blk,
# nothing else.
disk_is_ours() {
    local d=$1
    [[ "$(lsblk -no PARTLABEL "$d" | grep -v '^$' | sort | tr '\n' ' ')" == "taso-blk taso-zfs " ]] \
        && [[ "$(lsblk -no NAME "$d" | tail -n +2 | wc -l)" == 2 ]]
}

# ---- setup --------------------------------------------------------------------
if [[ "$mode" == setup ]]; then
    [[ "$os_id" == ubuntu && "$os_ver" == 26.04 ]] || die "this is $os_id $os_ver, not Ubuntu 26.04: P5 hosts are set up from one image (the plan, §2)"
    [[ "$DISK" == /dev/nvme*n[0-9]* && "$DISK" != *p[0-9]* ]] || die "$DISK is not a whole NVMe namespace (/dev/nvmeXnY)"
    [[ -b "$DISK" ]] || die "$DISK is not a block device"
    [[ "$COMMIT" =~ ^[0-9a-f]{7,40}$ ]] || die "--commit wants a commit hash, got '$COMMIT'"
    if disk_is_ours "$DISK"; then
        echo "disk $DISK already carries taso-zfs and taso-blk: kept"
    elif ! why=$(disk_empty "$DISK"); then
        lsblk -o NAME,SIZE,TYPE,FSTYPE,PARTLABEL,MOUNTPOINTS "$DISK"
        die "$DISK is not empty: $why.  Nothing changed.  Name the drive the OS was not installed on (check shows it), or clear this one by hand."
    fi
    [[ ! -d "$REPO/.git" ]] || [[ -z "$(git -C "$REPO" status --porcelain)" ]] || die "$REPO has uncommitted changes; nothing changed"

    step "1 hostname $HOST"
    if [[ "$(hostname)" != "$HOST" ]]; then
        hostnamectl set-hostname "$HOST"
        [[ -d /etc/cloud/cloud.cfg.d ]] && echo "preserve_hostname: true" >/etc/cloud/cloud.cfg.d/99-taso-hostname.cfg
    fi
    sed -i '/^127\.0\.1\.1[[:space:]]/d' /etc/hosts; echo "127.0.1.1 $HOST" >>/etc/hosts

    step "2 packages"
    apt_get update
    # build-essential only while there is no toolchain: on 26.04 it depends
    # on uutils, which step 3 removes, and it is only a bundle.
    toolchain=; has gcc && has make || toolchain=build-essential
    # shellcheck disable=SC2086
    apt_get install -y git $toolchain pkg-config libclang-dev python3 jq curl chrony runc \
        e2fsprogs util-linux fio zfsutils-linux nvme-cli

    step "3 GNU coreutils"
    if gnu_coreutils; then
        echo "already $(coreutils_version)"
    else
        swap=(coreutils-from-gnu coreutils-from-uutils-)
        removes=$(apt-get install -s "${swap[@]}" | sed -n 's/^Remv \([^ ]*\).*/\1/p' \
            | grep -vx -e coreutils-from-uutils -e build-essential || true)
        [[ -z "$removes" ]] || die "the coreutils swap would also remove: $removes (nothing changed; decide by hand)"
        keep=()
        for p in gcc g++ make libc6-dev dpkg-dev; do
            dpkg-query -W -f='${Status}' "$p" 2>/dev/null | grep -q 'install ok installed' && keep+=("$p")
        done
        [[ ${#keep[@]} -eq 0 ]] || apt-mark manual "${keep[@]}"
        apt_get install -y --allow-remove-essential "${swap[@]}"
        printf 'Package: coreutils-from-uutils\nPin: release a=*\nPin-Priority: -10\n' >/etc/apt/preferences.d/taso-gnu-coreutils
        hash -r
        gnu_coreutils || die "coreutils-from-gnu installed, but ls still reports: $(coreutils_version)"
        echo 'int main(void) { return 0; }' | gcc -x c - -o /dev/null || die "gcc no longer compiles after the coreutils swap"
        echo "now $(coreutils_version); gcc compiles; kept: ${keep[*]}"
    fi

    step "4 Rust"
    if [[ ! -x /root/.cargo/bin/cargo ]]; then
        curl -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable
    fi
    # shellcheck disable=SC1091
    . /root/.cargo/env
    rustup component add rustfmt >/dev/null
    cargo --version

    step "5 ublk_drv"
    modprobe ublk_drv || die "no ublk_drv for kernel $(uname -r); the block log needs it (try: apt-get install linux-modules-extra-$(uname -r))"
    echo ublk_drv >/etc/modules-load.d/taso-ublk.conf
    [[ -c /dev/ublk-control ]] || die "/dev/ublk-control missing after modprobe"
    echo "loaded; ublks_max $(cat /sys/module/ublk_drv/parameters/ublks_max 2>/dev/null || echo ?)"

    step "6 the disk $DISK"
    if ! disk_is_ours "$DISK"; then
        bytes=$(blockdev --getsize64 "$DISK")
        half=$(( bytes / 2 / 1048576 ))
        echo "$DISK: $(( bytes / 1073741824 )) GiB; two partitions of ${half} MiB"
        sfdisk --no-reread --wipe always "$DISK" <<EOF
label: gpt
name=taso-zfs, size=${half}MiB
name=taso-blk
EOF
        partx -u "$DISK" 2>/dev/null || partx -a "$DISK"
        udevadm settle
        disk_is_ours "$DISK" || die "the partitions did not appear as expected: $(lsblk -o NAME,SIZE,PARTLABEL "$DISK" | tr '\n' ';')"
    fi
    ZFS_PART=/dev/disk/by-partlabel/taso-zfs
    BLK_PART=/dev/disk/by-partlabel/taso-blk
    [[ -b "$ZFS_PART" && -b "$BLK_PART" ]] || die "by-partlabel links missing (udevadm settle did not help)"
    if zpool list "$POOL" >/dev/null 2>&1; then
        member=$(zpool status -P "$POOL" | awk '/\/dev\//{print $1; exit}')
        [[ "$(readlink -f "$member")" == "$(readlink -f "$ZFS_PART")" ]] || die "pool $POOL exists on $member, not on $ZFS_PART"
        echo "pool $POOL already on $ZFS_PART"
    else
        modprobe zfs || die "no zfs module for kernel $(uname -r)"
        [[ -z "$(blkid -p -o value -s TYPE "$ZFS_PART" 2>/dev/null)" ]] || die "$ZFS_PART already carries $(blkid -p -o value -s TYPE "$ZFS_PART"); nothing changed"
        zpool create -o ashift=12 -O compression=lz4 -O atime=off -O mountpoint=/taso "$POOL" "$ZFS_PART"
    fi
    zfs list "$POOL/vessel" >/dev/null 2>&1 || zfs create "$POOL/vessel"
    if ! blkid -p -o value -s TYPE "$BLK_PART" 2>/dev/null | grep -qx ext4; then
        [[ -z "$(blkid -p -o value -s TYPE "$BLK_PART" 2>/dev/null)" ]] || die "$BLK_PART already carries $(blkid -p -o value -s TYPE "$BLK_PART"); nothing changed"
        mkfs.ext4 -q -L taso-blk "$BLK_PART"
    fi
    mkdir -p "$DATA"
    grep -q "^LABEL=taso-blk[[:space:]]" /etc/fstab || echo "LABEL=taso-blk $DATA ext4 defaults,noatime 0 2" >>/etc/fstab
    mountpoint -q "$DATA" || { systemctl daemon-reload 2>/dev/null || true; mount "$DATA"; }
    [[ "$(findmnt -no SOURCE "$DATA")" == "$(readlink -f "$BLK_PART")" ]] || die "$DATA is mounted from $(findmnt -no SOURCE "$DATA"), not $BLK_PART"
    mkdir -p "$DATA/tmp" "$DATA/taso-blk"; chmod 1777 "$DATA/tmp"
    if [[ -e /var/lib/taso-blk && ! -L /var/lib/taso-blk ]]; then
        die "/var/lib/taso-blk exists and is not a symlink; move it aside (the blk-*.sh scripts must land on $DATA)"
    fi
    ln -sfn "$DATA/taso-blk" /var/lib/taso-blk

    step "6b expedited RCU (the freeze's superblock barriers)"
    echo 1 >/sys/kernel/rcu_expedited
    echo "w /sys/kernel/rcu_expedited - - - - 1" >/etc/tmpfiles.d/taso-rcu.conf
    echo "rcu_expedited=$(cat /sys/kernel/rcu_expedited), kept at boot by /etc/tmpfiles.d/taso-rcu.conf"

    step "7 TMPDIR and the login environment"
    cat >/etc/profile.d/taso-p5.sh <<EOF
# P5 measurement host (scripts/p5-node.sh): temporary files on the measured NVMe.
export TMPDIR=$DATA/tmp
export TASO_ZFS_DATASET=$POOL/vessel
[ -r /root/.cargo/env ] && . /root/.cargo/env
EOF
    export TMPDIR=$DATA/tmp
    echo "TMPDIR=$TMPDIR, TASO_ZFS_DATASET=$POOL/vessel (for root logins)"

    step "8 the repository at $COMMIT"
    if [[ ! -d "$REPO/.git" ]]; then
        git clone -q "$REPO_URL" "$REPO"
    fi
    git -C "$REPO" fetch -q origin
    git -C "$REPO" cat-file -e "$COMMIT^{commit}" 2>/dev/null || die "commit $COMMIT is not in $REPO_URL"
    git -C "$REPO" -c advice.detachedHead=false checkout -q --detach "$COMMIT"
    echo "$(git -C "$REPO" rev-parse --short HEAD): $(git -C "$REPO" log -1 --format=%s)"

    step "9 build"
    log=/root/taso-build.log
    echo "cargo build --release (minutes; log $log)"
    if ! (cd "$REPO" && cargo build --release -p taso-blk --bin taso-blkd \
            -p taso-warden --bin taso-wardend --bin taso-coordd --bin taso-logcheck >"$log" 2>&1); then
        tail -n 40 "$log"; die "cargo build failed; the full log is $log"
    fi
    install -m 755 "$REPO"/target/release/{taso-blkd,taso-wardend,taso-coordd,taso-logcheck} /usr/local/bin/
    echo "installed to /usr/local/bin: taso-blkd taso-wardend taso-coordd taso-logcheck"
fi

# ---- the report (check: this is all; setup: step 10) ---------------------------
ok=0; fail=0
pass() { printf 'OK    %s\n' "$*"; ok=$((ok + 1)); }
bad()  { printf 'FAIL  %s\n' "$*"; fail=$((fail + 1)); }
info() { printf '      %s\n' "$*"; }

report() {
    step "host"
    info "$(date -Is)  $(hostname)  $os_id $os_ver  kernel $(uname -r)  $(uname -m)"
    info "CPU: $(lscpu | awk -F': *' '/^Model name/{print $2; exit}') ($(nproc) threads); memory $(free -g | awk '/Mem:/{print $2}') GiB"
    info "virtualisation: $(systemd-detect-virt 2>/dev/null || true)"
    info "cpufreq governor: $(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo none)"
    [[ "$(cat /sys/kernel/rcu_expedited 2>/dev/null)" == 1 ]] && pass "rcu_expedited=1 (the freeze's barriers)" || bad "rcu_expedited is $(cat /sys/kernel/rcu_expedited 2>/dev/null || echo none), not 1 (setup sets it; a freeze pays ~30 ms of RCU grace periods without it)"
    info "unattended-upgrades timer: $(systemctl is-active apt-daily-upgrade.timer 2>/dev/null || true)"
    [[ "$os_id" == ubuntu && "$os_ver" == 26.04 ]] && pass "Ubuntu 26.04" || bad "not Ubuntu 26.04 ($os_id $os_ver)"
    [[ "${kernel%%.*}" -ge 6 ]] && pass "kernel $kernel" || bad "kernel $kernel is older than 6.0 (ublk)"

    step "tools"
    for t in gcc make git fio python3 jq runc mkfs.ext4 fsfreeze zpool nvme chronyd; do
        has "$t" && pass "$t" || bad "$t missing"
    done
    if ls /usr/lib/llvm-*/lib/libclang.so* >/dev/null 2>&1 || ls /usr/lib/*-linux-gnu/libclang*.so* >/dev/null 2>&1; then
        pass "libclang (libublk's bindings are generated with it)"
    else
        bad "libclang missing (libclang-dev)"
    fi
    gnu_coreutils && pass "$(coreutils_version)" || bad "coreutils are $(coreutils_version), not GNU (xfstests and our scripts assume GNU)"
    if [[ -x /root/.cargo/bin/cargo ]]; then pass "$(/root/.cargo/bin/cargo --version)"; else bad "cargo missing"; fi
    modprobe -n ublk_drv 2>/dev/null && pass "ublk_drv available" || bad "ublk_drv not available for $(uname -r)"
    [[ -c /dev/ublk-control ]] && pass "/dev/ublk-control (ublks_max $(cat /sys/module/ublk_drv/parameters/ublks_max 2>/dev/null || echo ?))" || bad "/dev/ublk-control not present (modprobe ublk_drv)"
    modprobe -n zfs 2>/dev/null && pass "zfs module available" || bad "zfs module not available for $(uname -r)"
    for b in taso-blkd taso-wardend taso-coordd taso-logcheck; do
        [[ -x /usr/local/bin/$b ]] && pass "/usr/local/bin/$b" || bad "/usr/local/bin/$b missing"
    done
    if [[ -d "$REPO/.git" ]]; then
        pass "$REPO at $(git -C "$REPO" rev-parse --short HEAD)$( [[ -n "$(git -C "$REPO" status --porcelain)" ]] && echo ' (DIRTY)')"
    else
        bad "$REPO missing"
    fi

    step "storage"
    info "root on $root_src (disk $root_disk); /tmp is $(findmnt -no FSTYPE /tmp 2>/dev/null || findmnt -no FSTYPE / )"
    info "block devices:"
    lsblk -d -o NAME,SIZE,ROTA,MODEL,TRAN | sed 's/^/        /'
    for n in $(lsblk -dn -o NAME,TYPE | awk '$2 == "disk" {print $1}'); do
        d=/dev/$n
        if [[ "$d" != /dev/nvme* ]]; then state="not NVMe (setup refuses it)"
        elif disk_is_ours "$d"; then state="ours (taso-zfs + taso-blk)"
        elif why=$(disk_empty "$d"); then state="EMPTY, free to name"
        else state="in use: $why"; fi
        [[ "$n" != "$root_disk" ]] || state+="; holds the root filesystem"
        # (root is refused by the mount and partition checks of disk_empty; named here for the reader)
        info "$n: $state"
        [[ "$d" == /dev/nvme* ]] || continue
        info "  queue: logical $(q "$n" logical_block_size) physical $(q "$n" physical_block_size) write_cache '$(q "$n" write_cache)' fua $(q "$n" fua) rotational $(q "$n" rotational) zoned $(q "$n" zoned) discard_granularity $(q "$n" discard_granularity) nr_requests $(q "$n" nr_requests)"
        if has nvme; then
            info "  nvme: $(nvme id-ctrl "$d" 2>/dev/null | awk -F' *: *' '$1 == "mn" || $1 == "fr" || $1 == "ctratt" || $1 == "vwc" {printf "%s=%s ", $1, $2}')"
            info "  nvme: $(nvme id-ctrl -H "$d" 2>/dev/null | grep -iE 'flexible data placement|zoned' | sed 's/^ *//' | tr '\n' ';' | sed 's/;$//')"
            info "  nvme: (vwc=0x1 means a volatile write cache per the drive; what a flush does to it is A2)"
        fi
    done
    if zpool list "$POOL" >/dev/null 2>&1; then
        pass "pool $POOL: $(zpool list -H -o size,alloc,free,health "$POOL" | tr '\t' ' ') on $(zpool status -P "$POOL" | awk '/\/dev\//{print $1; exit}')"
        info "  ashift=$(zpool get -H -o value ashift "$POOL") $(zfs get -H -o property,value compression,atime "$POOL" | tr '\t' '=' | tr '\n' ' ')"
        zfs list "$POOL/vessel" >/dev/null 2>&1 && pass "dataset $POOL/vessel" || bad "dataset $POOL/vessel missing"
    else
        bad "pool $POOL missing"
    fi
    if mountpoint -q "$DATA"; then
        pass "$DATA on $(findmnt -no SOURCE,FSTYPE,OPTIONS "$DATA"), $(df -h --output=avail "$DATA" | tail -1 | tr -d ' ') free"
    else
        bad "$DATA is not a mount point (the block log would be on the root disk)"
    fi
    [[ "$(readlink -f /var/lib/taso-blk 2>/dev/null)" == "$DATA/taso-blk" ]] && pass "/var/lib/taso-blk -> $DATA/taso-blk" || bad "/var/lib/taso-blk is not a link into $DATA"
    if [[ -f /etc/profile.d/taso-p5.sh ]] && [[ -d "$DATA/tmp" ]] && [[ "$(findmnt -no TARGET -T "$DATA/tmp" 2>/dev/null)" == "$DATA" ]]; then
        pass "TMPDIR=$DATA/tmp, on the measured drive"
    else
        bad "TMPDIR not set to a directory on $DATA (/etc/profile.d/taso-p5.sh)"
    fi
    info "disk free: root $(df -h --output=avail / | tail -1 | tr -d ' ')"

    echo
    echo "$ok OK, $fail FAIL"
}
if [[ "$mode" == setup ]]; then
    step "10 report"
    mkdir -p "$DATA"
    report | tee "$REPORT"
    echo "saved to $REPORT"
else
    report
fi
[[ $fail -eq 0 ]]
