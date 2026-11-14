# Taso

A storage substrate for agents: every Vessel's work is a hash-chained
Chronicle, and a Vessel's sealed state can become the next Template.
The specifications the code cites are in [`docs/spec`](docs/spec/README.md).

## Install on one machine

Walked on a fresh Scaleway Ubuntu 26.04 instance (4 vCPU, 8 GB, 30 GB
disk) on 2026-11-04; every line below is what that machine needed.

**What the machine needs:** Linux 6.0 or later with the `ublk_drv`
module (the stock Ubuntu 26.04 cloud image ships it; if `modinfo
ublk_drv` finds nothing, `apt install linux-modules-extra-$(uname -r)`),
cgroup v2, no SELinux (below), and about 20 GB of free disk: the build's
`target/` alone is 3–4 GB.

**Build** (as root; the compiler, `pkg-config`, `libclang-dev` for the
ublk bindings, and `runc`, which the Warden starts agents with):

```
apt install -y build-essential pkg-config libclang-dev runc git curl
curl -fsSL https://sh.rustup.rs | sh -s -- -y && . ~/.cargo/env
git clone https://github.com/Suo-commerce/taso.git && cd taso
cargo build --release -p taso-warden --bin taso-ctl --bin taso-wardend
cargo build --release -p taso-blk --bin taso-blkd
```

About two minutes on four cores. The binaries are
`target/release/taso-ctl`, `taso-blkd` and `taso-wardend`.

**The demo agent.** A Vessel runs its agent from a root filesystem: an
unpacked image. The demo's agent is `taso-sim` (SQLite turns, and a
fork it asks for), built as the image `taso-agent-demo` and unpacked
into a directory. Docker is needed for these two steps only (`apt
install -y docker.io docker-buildx`); the Warden never uses it.

```
docker build -f deploy/docker/Dockerfile --target agent-demo -t taso-agent-demo .
mkdir -p /var/lib/taso/agent
docker create --name taso-agent-demo taso-agent-demo
docker export taso-agent-demo | tar -x -C /var/lib/taso/agent
```

The build compiles the agent inside the image's own Ubuntu 26.04, so it
takes a few minutes; the unpacked directory is about 115 MB.

**Set the host up:**

```
target/release/taso-ctl init --rootfs /var/lib/taso/agent
```

It checks the host first and writes nothing before every check has
passed — root, no SELinux, cgroup v2, `runc` on `PATH`, the `ublk_drv`
module, `/sys/kernel/rcu_expedited`, a data directory on a local
filesystem (not tmpfs, NFS, overlay or FUSE), not set up already — and
each refusal is one line that says what to do. Then it loads `ublk_drv`
and keeps it at boot (`/etc/modules-load.d/taso.conf`), sets
`rcu_expedited=1` and keeps it at boot (`/etc/tmpfiles.d/taso-rcu.conf`;
without it every Seal's freeze pays three slow RCU grace periods), makes
`/var/lib/taso` and `/run/taso`, and writes `/etc/taso/warden.json`: one
node, a local coordinator, the block log, effects **held** by default
(a Vessel acts outward only once its entry says `"effects":
"dispatch"`), and no Vessels yet. `--data DIR` moves the data
directory, `--size-gib N` sizes the block log, `--rootfs DIR` names the
agents' root filesystem, `--force` rewrites the config. Run again it
says "already set up" and changes nothing. It starts no process and
installs no service: the two commands below are yours, and `systemd`
units, if you want them, are yours too.

**Run:**

1. Add a Vessel to `"vessels"` in `/etc/taso/warden.json`. For the demo,
   `target/release/taso-ctl demo` adds one and starts nothing: the
   Vessel `demo`, its agent `taso-sim` for 20 turns and then one fork,
   whose child `demo-fork-2` runs 20 turns of its own. Your own Vessel's
   entry needs a root filesystem for its agent (an unpacked OCI image),
   either as the node's `"runtime": {"rootfs": …}` or on the entry.
2. Start the block log: `taso-blkd /var/lib/taso/blk.log
   /run/taso/blk.sock --size-gib 64`.
3. When `taso-ctl status` says the block log answers, start the Warden:
   `taso-wardend /etc/taso/warden.json`. On a static config the Warden
   runs the Vessels listed and ends when they are done; with none
   listed it ends at once.

The demo takes under a minute. The Warden's standard output ends with a
line per Vessel, both `agent ok`: `demo` with 21 Seals published (its
birth Seal and one per turn) and `demo-fork-2` with 21 of its own (its
birth at the parent's turn 20, then its turns); its standard error says
what happened in order — the birth, the fork "on its agent's request",
the child's `/work` idmapped over its parent's files. Then it ends.

`taso-ctl status` says what runs; `taso-ctl /etc/taso/warden.json
explain <id>` rebuilds every decision about a Vessel, a Template or a
Candidate from the records.

**How much of each Vessel's history stays on the node.** Every Seal is
shipped to the bucket, and the bucket keeps the Vessel's whole history.
The node keeps only the newest **16 Seals' layers per Vessel** by
default; an older Seal's layer is folded into the next one once both are
shipped, so the block log stays bounded and reads stay fast. Set it in
`/etc/taso/warden.json`:

```
"storage": { "blk": { …, "local_seals": 16 } }
```

At least 4. Higher keeps more forkable history on the node at the cost
of block-log space; lower saves space. What it means for you:

- **A fork starts from the newest Seal.** A fork asked for from a Seal
  whose layer was folded away is refused with a message naming the
  oldest Seal the node still has; ask again from the newest.
- A Seal that an open Candidate names, or that a fork stands on, is
  never folded while it is needed.
- A folded Seal is not lost: it is in the bucket, and the Vessel's
  state does not change. A Warden restart does not count it as a Seal
  without its layer.
- `taso-blkd`'s `stats` reports `depth_max=`, the longest chain of layers
  a read may walk, which folding keeps near `local_seals`.

**Read before running an agent:**

- Taso records; it does not police. Its guarantee holds only when every
  persistent writable device the agent can reach is the Warden's, and
  every external writable service is controlled by the hosting
  environment (spec D91).
- On a virtual machine the disk's durability under power loss is the
  provider's promise, asserted by you, not checked by the Warden.
- An agent's SQLite at `synchronous=full` costs four syncs a turn and
  buys the Seal nothing under load; `synchronous=normal` is enough — a
  Seal is the durable acknowledgement.

A small thing on Ubuntu 26.04: its coreutils are the Rust uutils, which
take `tail -n 3`, not `tail -3`.

## Supported hosts

Taso runs on **Linux without SELinux**, for example Ubuntu and Debian.

The Warden (`taso-wardend`) refuses to start on a host where SELinux is
enabled, in enforcing or permissive mode. The test is whether
`/sys/fs/selinux/enforce` exists. An empty `/sys/fs/selinux` directory
alone does not count: kernels that can run SELinux create it even when
SELinux is off.

The reason: SELinux puts a label on every file, stored as an extended
attribute (xattr). A manifest cannot describe xattrs, so it refuses every
entry that has one (P4 spec D32). On an SELinux host nothing could ever
become a Template.

Not yet supported: Amazon Linux 2023 (SELinux permissive by default),
Bottlerocket and Azure Container Linux (SELinux enforcing). Supporting
them is a later decision. It changes no stored format, because labels
are never part of a manifest.

To check a host:

```
test -e /sys/fs/selinux/enforce && echo "SELinux enabled: unsupported" || echo "no SELinux: supported"
```

## Dates in manifests

A manifest records each entry's modification time exactly as the
kernel stores it: whole seconds since 1970-01-01 (signed 64-bit) plus
nanoseconds (P4 spec D30). That covers any date, before 1970 or far
beyond 2262, so no file is ever refused for its date.

The date is a field that any program can set to anything (`touch -d`,
`tar`, `git`). It is not when Taso wrote the file. What a manifest
carries is what the filesystem stored, and filesystems have their own
limits. ext4, for example, stores dates up to the year 2446 and clamps
later ones when they are set.
