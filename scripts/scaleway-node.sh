#!/usr/bin/env bash
# scaleway-node.sh: prepare a fresh Ubuntu 24.04 server (a Scaleway Instance
# or Elastic Metal) to build and test Taso's block log.
#
#   sudo scripts/scaleway-node.sh check     read-only: kernel, ublk, tools, disk
#   sudo scripts/scaleway-node.sh setup     install what is missing, then check
#
# setup touches, and nothing else:
#   apt packages: build-essential pkg-config clang libclang-dev git fio
#                 e2fsprogs util-linux python3
#   Rust (rustup, stable) under /root/.cargo and /root/.rustup, if cargo is missing
#   /etc/modules-load.d/taso-ublk.conf (loads ublk_drv at boot), and loads it now
# check touches nothing.
#
# The repository is not cloned here: clone it the way you do on taso-test.

set -euo pipefail

mode=${1:-}
[[ "$mode" == check || "$mode" == setup ]] || { echo "usage: $0 check|setup" >&2; exit 64; }
[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 2; }

ok=0
fail=0
pass() { printf 'OK    %s\n' "$*"; ok=$((ok + 1)); }
bad()  { printf 'FAIL  %s\n' "$*"; fail=$((fail + 1)); }
info() { printf '      %s\n' "$*"; }

if [[ "$mode" == setup ]]; then
    echo "== installing packages"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -q
    apt-get install -y -q build-essential pkg-config clang libclang-dev git fio e2fsprogs util-linux python3
    if ! command -v cargo >/dev/null && [[ ! -x /root/.cargo/bin/cargo ]]; then
        echo "== installing Rust (rustup, stable)"
        curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable
    fi
    echo "== ublk_drv: load now and at boot"
    echo ublk_drv >/etc/modules-load.d/taso-ublk.conf
    modprobe ublk_drv
fi

echo "== checks"
kernel=$(uname -r)
major=${kernel%%.*}
if [[ "$major" -ge 6 ]]; then pass "kernel $kernel (ublk needs 6.0 or newer)"; else bad "kernel $kernel is older than 6.0"; fi

if modprobe -n ublk_drv 2>/dev/null; then
    pass "ublk_drv module available"
else
    bad "ublk_drv module not available for this kernel (try: apt-get install linux-modules-extra-$kernel)"
fi
if [[ -c /dev/ublk-control ]]; then
    pass "/dev/ublk-control present (ublks_max $(cat /sys/module/ublk_drv/parameters/ublks_max 2>/dev/null || echo ?))"
else
    info "/dev/ublk-control not present yet (modprobe ublk_drv loads it; setup does)"
fi

for t in cc clang git fio mkfs.ext4 fsfreeze python3; do
    if command -v "$t" >/dev/null; then pass "$t"; else bad "$t missing (setup installs it)"; fi
done
if command -v cargo >/dev/null || [[ -x /root/.cargo/bin/cargo ]]; then
    pass "cargo $( (command -v cargo >/dev/null && cargo --version) || /root/.cargo/bin/cargo --version)"
else
    bad "cargo missing (setup installs Rust)"
fi
if ls /usr/lib/llvm-*/lib/libclang.so* >/dev/null 2>&1 || ls /usr/lib/x86_64-linux-gnu/libclang*.so* >/dev/null 2>&1; then
    pass "libclang (libublk's bindings are generated with it)"
else
    bad "libclang missing (setup installs libclang-dev)"
fi

root_free=$(df --output=avail -BG / | tail -n 1 | tr -dc 0-9)
if [[ "$root_free" -ge 30 ]]; then pass "${root_free} GiB free on /"; else bad "only ${root_free} GiB free on / (the benchmark wants about 12, a build about 10)"; fi
info "block devices (local NVMe shows as nvme*; network volumes as sd*/vd*):"
lsblk -d -o NAME,SIZE,ROTA,MODEL | sed 's/^/        /'
info "CPUs $(nproc), memory $(free -g | awk '/Mem:/{print $2}') GiB"

echo
echo "$ok OK, $fail FAIL"
[[ $fail -eq 0 ]]
