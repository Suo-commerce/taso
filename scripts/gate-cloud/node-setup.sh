#!/usr/bin/env bash
# Set up a gate machine (Hetzner Cloud, Ubuntu).  Run as root, once per
# node, from a clone of the repo at /root/taso:
#
#   scripts/gate-cloud/node-setup.sh hub    <hub private ip>
#   scripts/gate-cloud/node-setup.sh vessel <hub private ip>
#
# hub     taso-c: Garage (S3 on <ip>:3900, fsync on) and taso-coordd, whose
#         Unix socket is offered on <ip>:7700 (socat, private network only).
#         Writes /root/taso-s3.env (bucket, key id, secret) to copy to the
#         vessel nodes.
# vessel  taso-a, taso-b: a ZFS pool "taso" on a partition of the local
#         NVMe, runc, Rust, and /run/taso/coord.sock forwarded to the hub's
#         coordinator.
#
# The vessel nodes are created with growpart off (cloud-init-vessel.yaml),
# so the root partition does not take the whole disk.  This script grows
# root to $ROOT_GB and gives the rest of the disk to ZFS.  It prints the
# layout before changing it and stops if the layout is not what it
# expects; nothing is changed twice (rerunning is safe).
#
# The coordinator crosses the private network unauthenticated and in
# clear text (socat).  That is for the gate only; production needs a TCP
# coordinator with TLS.  Keep the Hetzner firewall closed except ssh.

set -euo pipefail

ROLE=${1:-}
HUB=${2:-}
ROOT_GB=${ROOT_GB:-100}
GARAGE_VERSION=${GARAGE_VERSION:-v2.1.0}
REPO=${REPO:-/root/taso}

die() { echo "error: $*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || die "run as root"
case "$ROLE" in hub|vessel) ;; *) die "usage: $0 hub|vessel <hub private ip>" ;; esac
[[ "$HUB" =~ ^10\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "give the hub's private IP (10.x.x.x)"
[ -d "$REPO/.git" ] || die "clone the repo to $REPO first"

export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -y -q git build-essential pkg-config python3 socat jq curl openssl chrony

rust() {
    if ! command -v cargo >/dev/null && [ ! -x /root/.cargo/bin/cargo ]; then
        curl -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal
    fi
    # shellcheck disable=SC1091
    . /root/.cargo/env
}

unit() {   # $1 name, $2 ExecStart, [$3 extra [Unit] lines]
    cat > "/etc/systemd/system/$1.service" <<EOF
[Unit]
Description=$1
After=network-online.target
Wants=network-online.target
${3:-}

[Service]
ExecStart=$2
Restart=always
RestartSec=1
RuntimeDirectory=taso
RuntimeDirectoryPreserve=yes

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable --now "$1"
}

# ── hub ─────────────────────────────────────────────────────────────────
if [ "$ROLE" = hub ]; then
    ip -4 addr | grep -q "inet $HUB/" || die "$HUB is not an address of this machine"
    rust
    (cd "$REPO" && cargo build --release -q -p taso-warden --bin taso-coordd)
    install -m 755 "$REPO/target/release/taso-coordd" /usr/local/bin/taso-coordd
    mkdir -p /var/lib/taso
    unit taso-coordd "/usr/local/bin/taso-coordd /var/lib/taso/coord.redb /run/taso/coord.sock"
    unit taso-coord-tcp "/usr/bin/socat TCP-LISTEN:7700,bind=$HUB,reuseaddr,fork UNIX-CONNECT:/run/taso/coord.sock" \
        "After=taso-coordd.service"

    if [ ! -x /usr/local/bin/garage ]; then
        curl -fsSL -o /usr/local/bin/garage \
            "https://garagehq.deuxfleurs.fr/_releases/$GARAGE_VERSION/x86_64-unknown-linux-musl/garage"
        chmod 755 /usr/local/bin/garage
    fi
    mkdir -p /var/lib/garage
    [ -f /var/lib/garage/rpc_secret ] || openssl rand -hex 32 > /var/lib/garage/rpc_secret
    cat > /etc/garage.toml <<EOF
metadata_dir = "/var/lib/garage/meta"
data_dir = "/var/lib/garage/data"
db_engine = "lmdb"
replication_factor = 1
metadata_fsync = true
data_fsync = true
rpc_bind_addr = "$HUB:3901"
rpc_public_addr = "$HUB:3901"
rpc_secret = "$(cat /var/lib/garage/rpc_secret)"

[s3_api]
s3_region = "garage"
api_bind_addr = "$HUB:3900"
root_domain = ".s3.garage.localhost"
EOF
    unit garage "/usr/local/bin/garage -c /etc/garage.toml server"
    g() { /usr/local/bin/garage -c /etc/garage.toml "$@"; }
    for _ in $(seq 50); do g status >/dev/null 2>&1 && break; sleep 0.2; done
    if [ ! -f /root/taso-s3.env ]; then
        id=$(g node id -q | cut -d@ -f1)
        g layout assign -z hel1 -c 100G "$id" >/dev/null
        g layout apply --version 1 >/dev/null
        g bucket create taso >/dev/null
        out=$(g key create taso-key)
        kid=$(awk -F': *' '/Key ID/ {print $2; exit}' <<<"$out")
        sec=$(awk -F': *' '/Secret key/ {print $2; exit}' <<<"$out")
        [ -n "$sec" ] || sec=$(g key info --show-secret taso-key | awk -F': *' '/Secret key/ {print $2; exit}')
        [ -n "$kid" ] && [ -n "$sec" ] || die "could not read the Garage key: $out"
        g bucket allow --read --write --owner taso --key taso-key >/dev/null
        printf 'TASO_S3_ENDPOINT=http://%s:3900\nTASO_S3_BUCKET=taso\nTASO_S3_KEY_ID=%s\nTASO_S3_SECRET=%s\n' \
            "$HUB" "$kid" "$sec" > /root/taso-s3.env
        chmod 600 /root/taso-s3.env
    fi
    echo
    echo "hub ready: Garage on $HUB:3900, coordinator on $HUB:7700"
    echo "copy /root/taso-s3.env to /root/taso-s3.env on taso-a and taso-b (scp)."
    exit 0
fi

# ── vessel ──────────────────────────────────────────────────────────────
apt-get install -y -q zfsutils-linux runc
rust

if ! zpool list taso >/dev/null 2>&1; then
    root_part=$(findmnt -no SOURCE /)
    disk=/dev/$(lsblk -no PKNAME "$root_part")
    partn=$(cat "/sys/class/block/$(basename "$root_part")/partition")
    echo "== disk layout before"
    lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINTS "$disk"
    sfdisk --list-free "$disk" | tail -n +2
    root_bytes=$(lsblk -bno SIZE "$root_part")
    want=$((ROOT_GB * 1024 * 1024 * 1024))
    if [ "$root_bytes" -lt "$want" ]; then
        echo "== growing $root_part to ${ROOT_GB}G"
        echo ",${ROOT_GB}G" | sfdisk --no-reread -N "$partn" "$disk"
        partx -u "$disk"
        resize2fs "$root_part"
    elif [ "$root_bytes" -gt $((want * 2)) ]; then
        die "root already takes $((root_bytes / 1024 / 1024 / 1024))G: was the server created with cloud-init-vessel.yaml (growpart off)?"
    fi
    before=$(lsblk -lno NAME "$disk" | sort)
    # The largest free region (sectors of 512 bytes): start and size.
    read -r start sectors < <(sfdisk --list-free "$disk" | awk '$1 ~ /^[0-9]+$/ && $3 ~ /^[0-9]+$/ && $3 + 0 > max + 0 { max = $3; s = $1 } END { print s + 0, max + 0 }')
    [ "$sectors" -gt $((50 * 1024 * 1024 * 2)) ] || die "no free region of 50G or more after root; see the layout above"
    echo "== new partition for ZFS at sector $start, $((sectors / 2 / 1024 / 1024))G"
    echo "$start," | sfdisk --append --no-reread "$disk"
    partx -a "$disk" 2>/dev/null || partx -u "$disk"
    sleep 1
    new=$(comm -13 <(echo "$before") <(lsblk -lno NAME "$disk" | sort) | head -1)
    [ -n "$new" ] || die "the new partition did not appear"
    partuuid=$(blkid -s PARTUUID -o value "/dev/$new")
    zpool create -f -o ashift=12 -O compression=lz4 -O atime=off -O mountpoint=/taso taso "/dev/disk/by-partuuid/$partuuid"
    zfs create taso/vessel
    echo "== disk layout after"
    lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINTS "$disk"
fi
zpool list taso
zfs list -r taso

# The coordinator, reached through the hub.
unit taso-coord-fwd "/usr/bin/socat UNIX-LISTEN:/run/taso/coord.sock,fork,unlink-early,mode=600 TCP:$HUB:7700"

echo
echo "vessel node ready: pool taso, dataset taso/vessel, coordinator at /run/taso/coord.sock"
echo "copy /root/taso-s3.env from the hub to this node, then: cd $REPO && cargo build --release"
