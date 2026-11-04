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
cargo build --release -p taso-warden --bin taso-ctl --bin taso-wardend -p taso-blk --bin taso-blkd
```

About two minutes on four cores. The binaries are
`target/release/taso-ctl`, `taso-blkd` and `taso-wardend`.

**Set the host up:**

```
target/release/taso-ctl init
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

1. Add a Vessel to `"vessels"` in `/etc/taso/warden.json`. Its entry
   needs a root filesystem for the agent (an unpacked OCI image), either
   as the node's `"runtime": {"rootfs": …}` or on the entry.
2. Start the block log: `taso-blkd /var/lib/taso/blk.log
   /run/taso/blk.sock --size-gib 64`.
3. When `taso-ctl status` says the block log answers, start the Warden:
   `taso-wardend /etc/taso/warden.json`. On a static config the Warden
   runs the Vessels listed and ends when they are done; with none
   listed it ends at once.

`taso-ctl status` says what runs; `taso-ctl /etc/taso/warden.json
explain <id>` rebuilds every decision about a Vessel, a Template or a
Candidate from the records.

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
