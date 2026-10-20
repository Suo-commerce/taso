#!/usr/bin/env bash
# Set up a gate machine (Ubuntu).  Run as root, once per node, from a clone
# of the repo at /root/taso.  Rerunning any role is safe.
#
# Hetzner, ZFS (the P2 gate of 2026-10-17; unchanged):
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
# UpCloud, block log (S2, 2026-10-20):
#
#   scripts/gate-cloud/node-setup.sh coord      <name>=<warden id>...
#   scripts/gate-cloud/node-setup.sh vessel-blk <coordinator host>|local <name>
#
# A Warden on the coordinator's own host (one machine; node B in the
# two-server layout) connects to the socket directly as root: give the
# coord role "local=<id>" for it and the vessel-blk role "local" as the
# coordinator host.  Every Warden config uses /run/taso/coord.sock: on a
# node it is the ssh forward's socket, on the coordinator's host a symlink
# to /run/taso-coord/coord.sock.
#
# coord       taso-coordd with a peer map: one Unix user "warden-<name>"
#             per Warden (no shell, key only, forwarding only), group
#             taso-wardens, socket /run/taso-coord/coord.sock 0660.  Reads each
#             node's public key from /root/taso-keys/<name>.pub if it is
#             there: run the role again after copying keys in.  No Garage,
#             no socat: packs go to Scaleway (the secret stays in
#             /root/s3-secret on each node).  The coordinator may run on a
#             vessel node too (two-server layout) or on its own (three).
# vessel-blk  runc, Rust, the ublk module, taso-blkd as a systemd unit on
#             /var/lib/taso/blk.log and /run/taso/blk.sock, and
#             /run/taso/coord.sock forwarded to the coordinator over ssh as
#             user warden-<name>.  Prints the node's public key to copy to
#             the coordinator's /root/taso-keys/<name>.pub.  No disk changes.
#             Ends with a check through the forward that says whether the
#             coordinator knows this node.
#
# How the coordinator is authenticated across machines (F3 step 1): the
# node forwards its socket over ssh; on the coordinator host sshd opens
# the connection to the coordinator's socket as the login user, so the
# coordinator reads that uid (SO_PEERCRED) and lets the connection act only
# as the Warden mapped to it (taso-coordd --peer).  The node's ssh key is
# the Warden's identity; the wire is ssh.  Measured 2026-10-20 (the
# forward, a nologin account with restrict,port-forwarding, the uid seen).
# Nothing but ssh needs to be open on the coordinator host.  The hub's host
# key is trusted on first use (StrictHostKeyChecking=accept-new).
#
# The Hetzner vessel nodes are created with growpart off
# (cloud-init-vessel.yaml), so the root partition does not take the whole
# disk.  The vessel role grows root to $ROOT_GB and gives the rest of the
# disk to ZFS.  It prints the layout before changing it and stops if the
# layout is not what it expects; nothing is changed twice.
#
# The Hetzner hub's coordinator crosses the private network
# unauthenticated and in clear text (socat).  That was for that gate only;
# the UpCloud roles replace it.  Keep every firewall closed except ssh.

set -euo pipefail

ROLE=${1:-}
ROOT_GB=${ROOT_GB:-100}
GARAGE_VERSION=${GARAGE_VERSION:-v2.1.0}
REPO=${REPO:-/root/taso}
BLKD_ARGS=${BLKD_ARGS:-}      # extra taso-blkd flags for the vessel-blk unit

die() { echo "error: $*" >&2; exit 1; }
usage() { die "usage: $0 hub|vessel <hub private ip>  |  $0 coord <name>=<warden id>...  |  $0 vessel-blk <coordinator host>|local <name>"; }
[ "$(id -u)" = 0 ] || die "run as root"
[ -d "$REPO/.git" ] || die "clone the repo to $REPO first"

export DEBIAN_FRONTEND=noninteractive

# build-essential only when there is no C toolchain: on Ubuntu 26.04 it
# depends on coreutils-from-uutils, which a machine moved to GNU coreutils
# (taso-test, 2026-10-18) cannot install, and a machine that has built the
# repo already has the toolchain.
toolchain() { if command -v gcc >/dev/null && command -v make >/dev/null; then echo; else echo build-essential; fi; }

rust() {
    if ! command -v cargo >/dev/null && [ ! -x /root/.cargo/bin/cargo ]; then
        curl -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal
    fi
    # shellcheck disable=SC1091
    . /root/.cargo/env
}

unit() {   # $1 name, $2 ExecStart, [$3 extra [Unit] lines], [$4 extra [Service] lines]
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
${4:-}

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable --now "$1"
}

# ── coord (UpCloud, block log) ──────────────────────────────────────────
if [ "$ROLE" = coord ]; then
    shift
    [ $# -ge 1 ] || usage
    PEERS=()   # name=id, checked
    for arg in "$@"; do
        [[ "$arg" =~ ^([a-z][a-z0-9-]{0,15})=([1-9][0-9]{0,9})$ ]] || die "coord: expected <name>=<warden id> (name [a-z][a-z0-9-]*, id a positive number), got '$arg'"
        PEERS+=("$arg")
    done
    for p in "${PEERS[@]}"; do for q in "${PEERS[@]}"; do
        [ "$p" = "$q" ] || { [ "${p%%=*}" != "${q%%=*}" ] && [ "${p#*=}" != "${q#*=}" ]; } || die "coord: '$p' and '$q' repeat a name or an id"
    done; done
    apt-get update -q
    # shellcheck disable=SC2046
    apt-get install -y -q git $(toolchain) pkg-config python3 curl chrony openssh-server
    rust
    (cd "$REPO" && cargo build --release -q -p taso-warden --bin taso-coordd)
    install -m 755 "$REPO/target/release/taso-coordd" /usr/local/bin/taso-coordd
    mkdir -p /var/lib/taso /root/taso-keys
    chmod 700 /root/taso-keys

    # sshd must allow Unix-socket forwarding (the default), or the nodes
    # cannot reach the socket at all.
    allow=$(sshd -T 2>/dev/null | awk '$1 == "allowstreamlocalforwarding" {print $2}')
    case "$allow" in yes|all|local) ;; *) die "sshd AllowStreamLocalForwarding is '$allow'; it must be yes, all or local" ;; esac

    getent group taso-wardens >/dev/null || groupadd --system taso-wardens
    GID=$(getent group taso-wardens | cut -d: -f3)
    peer_flags=()
    for p in "${PEERS[@]}"; do
        name=${p%%=*}; wid=${p#*=}; user="warden-$name"; home="/var/lib/taso/peers/$user"
        if [ "$name" = local ]; then
            # The Warden on this host: it connects to the socket directly,
            # as root, so uid 0 is its identity.  No user, no key.
            peer_flags+=(--peer "0=$wid")
            echo "warden $wid: root on this host (local), no forward"
            continue
        fi
        if ! id "$user" >/dev/null 2>&1; then
            useradd --system -M -s /usr/sbin/nologin -g taso-wardens -d "$home" "$user"
        fi
        usermod -p '*' "$user"     # not locked (sshd refuses locked accounts), no password
        install -d -m 700 -o "$user" -g taso-wardens "$home" "$home/.ssh"
        if [ -f "/root/taso-keys/$name.pub" ]; then
            key=$(head -1 "/root/taso-keys/$name.pub")
            [[ "$key" =~ ^ssh-(ed25519|rsa)\ [A-Za-z0-9+/=]+ ]] || die "/root/taso-keys/$name.pub is not a public key line"
            printf 'restrict,port-forwarding %s\n' "$key" > "$home/.ssh/authorized_keys"
            chown "$user:taso-wardens" "$home/.ssh/authorized_keys"
            chmod 600 "$home/.ssh/authorized_keys"
            keystate="key installed"
        else
            rm -f "$home/.ssh/authorized_keys"
            keystate="NO KEY YET: copy the node's key to /root/taso-keys/$name.pub and run this role again"
        fi
        peer_flags+=(--peer "$(id -u "$user")=$wid")
        echo "warden $wid: user $user (uid $(id -u "$user")), $keystate"
    done

    # The coordinator's own runtime directory, /run/taso-coord, 0750
    # root:taso-wardens: the peers reach the socket, nothing else does.
    # Its own, because systemd re-owns a unit's runtime directory to the
    # unit's user and group, recursively, when the unit starts; a
    # directory shared with root:root units (taso-blkd, the forward) lost
    # the socket's group that way (taso-test, 2026-10-20).  The socket
    # itself is 0660 by taso-coordd.
    unit taso-coordd "/usr/local/bin/taso-coordd /var/lib/taso/coord.redb /run/taso-coord/coord.sock ${peer_flags[*]} --socket-group $GID" \
        "" "RuntimeDirectory=
RuntimeDirectory=taso-coord
RuntimeDirectoryMode=0750
Group=taso-wardens"
    systemctl restart taso-coordd      # the flags may have changed
    systemctl disable --now taso-coord-tcp 2>/dev/null || true   # never both
    for _ in $(seq 50); do [ -S /run/taso-coord/coord.sock ] && break; sleep 0.2; done
    systemctl is-active -q taso-coordd || { journalctl -u taso-coordd -n 20 --no-pager; die "taso-coordd is not running"; }
    [ "$(stat -c '%a %U:%G' /run/taso-coord)" = "750 root:taso-wardens" ] || die "/run/taso-coord is $(stat -c '%a %U:%G' /run/taso-coord), expected 750 root:taso-wardens"
    [ "$(stat -c '%a %G' /run/taso-coord/coord.sock)" = "660 taso-wardens" ] || die "socket is $(stat -c '%a %G' /run/taso-coord/coord.sock), expected 660 taso-wardens"
    echo
    echo "coordinator ready: $(journalctl -u taso-coordd -n 1 --no-pager -o cat)"
    echo "socket /run/taso-coord/coord.sock, group taso-wardens; sshd is the only way in."
    exit 0
fi

# ── vessel-blk (UpCloud, block log) ─────────────────────────────────────
if [ "$ROLE" = vessel-blk ]; then
    COORD=${2:-}; NAME=${3:-}
    [ -n "$COORD" ] && [[ "$NAME" =~ ^[a-z][a-z0-9-]{0,15}$ ]] || usage
    apt-get update -q
    # shellcheck disable=SC2046
    apt-get install -y -q git $(toolchain) pkg-config python3 jq curl chrony runc e2fsprogs openssh-client
    rust
    [ -x "$(command -v runc)" ] || die "runc missing"
    modprobe ublk_drv || die "no ublk module on this kernel ($(uname -r)); the block log needs it"
    echo ublk_drv > /etc/modules-load.d/taso-ublk.conf
    (cd "$REPO" && cargo build --release -q -p taso-blk --bin taso-blkd -p taso-warden --bin taso-wardend --bin taso-logcheck)
    install -m 755 "$REPO/target/release/taso-blkd" "$REPO/target/release/taso-wardend" "$REPO/target/release/taso-logcheck" /usr/local/bin/
    mkdir -p /var/lib/taso

    # The node's identity toward the coordinator: one ed25519 key, made here,
    # never leaving this machine except as its public half.
    if [ ! -f /root/.ssh/taso-coord ]; then
        install -d -m 700 /root/.ssh
        ssh-keygen -q -t ed25519 -N '' -C "warden-$NAME@$(hostname)" -f /root/.ssh/taso-coord
    fi

    # The block log daemon.  The gate script (gate-p2-blk.sh) uses this one
    # in the two-node layout and starts its own in the one-machine layout.
    unit taso-blkd "/usr/local/bin/taso-blkd /var/lib/taso/blk.log /run/taso/blk.sock $BLKD_ARGS"

    if [ "$COORD" = local ]; then
        # The coordinator runs on this host: the Warden connects to its
        # socket directly, as root (coord ... local=<id>).  A forward here
        # would unlink the coordinator's own socket (same path), so none.
        systemctl disable --now taso-coord-fwd 2>/dev/null || true
        rm -f /etc/systemd/system/taso-coord-fwd.service; systemctl daemon-reload
        systemctl is-active -q taso-coordd || die "coordinator 'local' but taso-coordd is not running here: run the coord role first"
        # One path for every Warden config in every layout.
        ln -sfn /run/taso-coord/coord.sock /run/taso/coord.sock
        echo
        echo "coordinator on this host: /run/taso/coord.sock -> /run/taso-coord/coord.sock, no forward, root is the Warden (coord role: local=<id>)"
    else
        # The coordinator, through ssh.  ExitOnForwardFailure makes a refused
        # forward a failed unit (visible, restarted), not a silent dead socket.
        if systemctl is-active -q taso-coordd 2>/dev/null; then
            die "taso-coordd runs on this host; use: $0 vessel-blk local $NAME"
        fi
        [ -L /run/taso/coord.sock ] && rm -f /run/taso/coord.sock   # a 'local' symlink from before
        unit taso-coord-fwd "/usr/bin/ssh -N -o BatchMode=yes -o ExitOnForwardFailure=yes -o ServerAliveInterval=10 -o ServerAliveCountMax=3 -o StrictHostKeyChecking=accept-new -o StreamLocalBindMask=0177 -o StreamLocalBindUnlink=yes -i /root/.ssh/taso-coord -L /run/taso/coord.sock:/run/taso-coord/coord.sock warden-$NAME@$COORD" \
            "After=taso-blkd.service" "RestartSec=5"
        echo
        echo "== this node's public key: copy it to the coordinator host as /root/taso-keys/$NAME.pub, then run 'coord' there again"
        cat /root/.ssh/taso-coord.pub
        echo
        for _ in $(seq 50); do systemctl is-active -q taso-coord-fwd && [ -S /run/taso/coord.sock ] && break; sleep 0.2; done
        if ! systemctl is-active -q taso-coord-fwd || [ ! -S /run/taso/coord.sock ]; then
            echo "forward not up yet (the coordinator does not know this key, or is not reachable): $(systemctl is-active taso-coord-fwd)"
            journalctl -u taso-coord-fwd -n 5 --no-pager -o cat
            echo "vessel-blk node ready except the coordinator; install the key on the coordinator and: systemctl restart taso-coord-fwd"
            exit 0
        fi
    fi
    # One `head` request for a Chronicle that does not exist, through the
    # forward.  A mapped peer gets "unknown chronicle" (refusal 1); an
    # unmapped one "unknown peer" (refusal 12).  Either proves the forward.
    python3 - <<'PY'
import socket, struct, sys
s = socket.socket(socket.AF_UNIX); s.settimeout(5); s.connect("/run/taso/coord.sock")
body = bytes([1, 5]) + bytes(16)
s.sendall(struct.pack(">I", len(body)) + body)
def exactly(k):
    b = b""
    while len(b) < k:
        c = s.recv(k - len(b))
        if not c: sys.exit("coordinator check: connection closed without a reply")
        b += c
    return b
n = struct.unpack(">I", exactly(4))[0]; r = exactly(n)
if r[:2] == bytes([1, 1]):   print("coordinator check: this node is a known Warden (refusal: unknown chronicle, as expected)")
elif r[:2] == bytes([1, 12]): print("coordinator check: reached the coordinator, but it has no --peer for uid %d as seen on its host (0 = root: give the coord role local=<id>)" % struct.unpack(">I", r[2:6])[0], file=sys.stderr); sys.exit(1)
else:                          print("coordinator check: unexpected reply %r" % r, file=sys.stderr); sys.exit(1)
PY
    echo "vessel-blk node ready: taso-blkd on /run/taso/blk.sock (log /var/lib/taso/blk.log), coordinator at /run/taso/coord.sock"
    exit 0
fi

# ── Hetzner roles ───────────────────────────────────────────────────────
HUB=${2:-}
case "$ROLE" in hub|vessel) ;; *) usage ;; esac
[[ "$HUB" =~ ^10\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "give the hub's private IP (10.x.x.x)"

apt-get update -q
apt-get install -y -q git build-essential pkg-config python3 socat jq curl openssl chrony

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
