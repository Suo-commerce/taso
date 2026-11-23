# Taso

**Checkpoints and branches for the storage AI agents work on.**

Most databases remember what happened. Taso remembers what could have
happened, and lets you choose afterwards.

## What it does

An agent works on files and databases, and it makes mistakes. Taso gives
each agent its own workspace on an ordinary Linux filesystem and keeps a
complete, tamper-evident history of everything written to it. The agent
needs no changes: its files and its SQLite database work as they do on
any disk.

On top of that history you get four things:

- **Checkpoints.** Taso takes a checkpoint of the workspace at the end of
  every agent turn. After a crash, the workspace comes back exactly as it
  was at its last checkpoint, never half-written.
- **Branches.** Start a copy of a workspace from a checkpoint and let
  another agent (or a sub-agent) try something there. Nothing is copied
  up front, so a branch starts in an instant, however much data the
  workspace holds.
- **Merge by choice.** A branch changes nothing in its parent until
  someone outside the agent decides to merge it. A branch nobody merges
  simply goes away, with no trace in the parent.
- **Restore anywhere.** Every checkpoint is shipped to object storage (a
  local directory or an S3-compatible bucket). If a machine is lost,
  another machine rebuilds the workspace from the bucket, and the old
  machine is refused if it ever comes back.

Taso also keeps an **outbox** for anything the agent wants to do outside
its workspace: send an e-mail, call an API, push to a repository. The
agent declares the action, Taso records it and answers *released* or
*held*, and a separate sender of yours carries it out and reports the
result. Taso itself never sends anything. This is what lets a branch be
thrown away safely: its outside actions were waiting in the outbox, not
already done.

## Why you would use it

- You run agents and want to **undo** what one did, back to a known good
  point, without restoring a whole server.
- You want to run **many attempts in parallel** on the same starting
  data and keep only the one that worked.
- You want a **record you can trust** of what an agent wrote and what it
  asked to do in the outside world, with the reason for every decision
  rebuilt from the records (`taso-ctl explain`).
- You keep agent state in **object storage** and want it to survive the
  loss of a machine without duplicated or lost outside actions.

## What it is not

- **Not a replacement for your database.** Taso sits between the agent
  and its storage. Your SQLite file or your documents live inside the
  workspace as before.
- **Not a sandbox.** Taso runs each agent in a container, but its promise
  is about storage, not about containing a hostile agent.
- **Not a policy engine.** Taso records and holds; it does not decide.
  What to merge and which outside actions to allow is decided by you, or
  by a program of yours that Taso asks.

## How it works, in one paragraph

Each workspace is a virtual disk with ext4 on it. Every block the agent
writes becomes a record in an append-only log, and each record carries
the hash of the one before it, so history cannot be changed without
breaking the chain. A checkpoint is a position in that log. A branch is
a new log that points at its parent's checkpoint. Restoring is replaying
the log from the bucket. One service per machine (`taso-blkd`) serves the
disks; a second (`taso-wardend`) starts the agents, takes the
checkpoints and ships them.

## The words used in this repository

The rest of this README, the code and the specs use Taso's own names.

| Taso's name | What it is |
|---|---|
| Vessel | One agent's workspace: its disk and the container the agent runs in |
| Seal | A checkpoint of a Vessel |
| Chronicle | A Vessel's append-only, hash-chained log |
| Fork | A branch started from a Seal |
| Promotion | Merging a fork's files and outbox into its parent |
| Template | A reviewed checkpoint that new Vessels can start from |
| Effect | An action outside the workspace, declared to the outbox |
| Warden | The service that runs Vessels on a machine (`taso-wardend`) |
| Coordinator | The service that decides which Warden owns a Vessel |
| Rebirth | Rebuilding a Vessel on another machine from the bucket |

## Status

Taso is **pre-release**: version 0.1 is being prepared and stored formats
may still change before it. It runs on Linux 6.0 or later with the
`ublk_drv` module, without SELinux (Ubuntu and Debian, for example), on
one machine or in containers with Docker Compose. Kubernetes support is
in progress.

## Where to go next

- **Try it:** [Install on one machine](#install-on-one-machine) or
  [Run in containers](#run-in-containers). The demo takes under a minute.
- **Connect your own sender:** [`docs/relay.md`](docs/relay.md), the
  contract between Taso's outbox and whoever carries its actions out.
- **Read the design:** [`docs/spec`](docs/spec/README.md).

| In this repository | |
|---|---|
| `crates/taso-core` | The record types and rules, with no I/O |
| `crates/taso-blk` | The block log and `taso-blkd` |
| `crates/taso-warden` | The Warden, the coordinator and `taso-ctl` |
| `crates/taso-field` | The protocol between an agent and the Warden |
| `crates/taso-landlock` | The file-access limits put on an agent |
| `crates/taso-sim` | The demo agent |
| `deploy/` | Dockerfile, Compose file, Kubernetes resource definition |
| `scripts/`, `bench/` | Test gates, crash tests and benchmarks |

Licensed under [Apache-2.0](LICENSE).

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
(see "What an agent may send" below), and no Vessels yet. `--data DIR` moves the data
directory, `--size-gib N` sizes the block log, `--rootfs DIR` names the
agents' root filesystem, `--force` rewrites the config. Run again it
says "already set up" and changes nothing but the directory modes
below. It starts no process and installs no service: the two commands
below are yours, and `systemd` units, if you want them, are yours too.

**Who can read the data.** Every Vessel's files live in the block log,
the packs and the Warden's state, whatever their modes inside the Vessel
say, so these are root's alone. `init` makes `state`, `store` and
`spool` under the data directory `0700`, and the data directory and its
`mnt` `0711`: others may pass through them to reach the Vessels' mounts
(an agent's mapped uids must), but not list them. The block log, its
checkpoint, the coordinator's database and every pack are made `0600`;
if one made before is open to others, `taso-blkd`, the Warden and `init`
take that access away (keeping the group's; for old packs, from the
store's top directory) and say so. If your config
puts `state_dir`, `spool` or the store somewhere else, give those
directories the same modes yourself.

**Run:**

1. Add a Vessel to `"vessels"` in `/etc/taso/warden.json`. For the demo,
   `target/release/taso-ctl demo` adds one and starts nothing: the
   Vessel `demo`, its agent `taso-sim` for 20 turns and then one fork,
   whose child `demo-fork-2` runs 20 turns of its own. Your own Vessel's
   entry needs a root filesystem for its agent (an unpacked OCI image),
   either as the node's `"runtime": {"rootfs": …}` or on the entry.
2. Start the block log: `taso-blkd /var/lib/taso/blk.log
   /run/taso/blk.sock --size-gib 64`. It keeps `blk.sock.lock` beside
   its socket: while it runs, another `taso-blkd` on the same socket is
   refused.
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

**What an agent may send.** Taso never sends: an agent asks for an
action, the Warden records the exact request, and a sender of yours
sends what the Warden has released ([docs/relay.md](docs/relay.md)).
Each Vessel's entry says which:

- `"effects": "hold"` (what `init` writes, and what every fork has):
  the action is recorded and held. **Nothing goes out by itself.** You
  release it or refuse it, one action at a time: `taso-ctl proposals
  <vessel>` lists what is held, `taso-ctl approve <vessel> <op>`
  releases one to the sender, `taso-ctl deny <vessel> <op> reason…`
  closes one. A program of yours can do the same on the Warden's
  decider socket. An action can be approved once the turn that asked
  for it has ended; the agent reads the result in a later turn.
- `"effects": "dispatch"`: every action is released at once and the
  sender sends it; nobody is asked.

A held action that nobody decides stays held and fills the Vessel's
outbox (8 MiB), so decide each one.

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

## Run in containers

The same node in two containers with Docker Compose: `taso-blkd`, which
serves the block log as ublk devices, and the Warden, which runs the
Vessels on them (with the coordinator inside it, as on one machine).
Tested on Ubuntu 26.04 with Docker 29 and Compose v2 on 2026-11-17 by
`scripts/c3-compose-test.sh`, which also kills each container and checks
what is left (below).

**What the host needs:** what one machine needs above (Linux with
`ublk_drv`, cgroup v2, no SELinux), Docker with Compose 2.23 or later,
and two settings the containers do not make for you. A container that
could load kernel modules or change kernel settings could do anything to
the host, so these stay the host's, once:

```
modprobe ublk_drv
echo 1 > /sys/kernel/rcu_expedited
```

To keep them across reboots, do what `taso-ctl init` does on one
machine: `ublk_drv` in a file in `/etc/modules-load.d/`, and the
setting in `/etc/tmpfiles.d/` (`w /sys/kernel/rcu_expedited - - - - 1`).

**Run the demo:**

```
git clone https://github.com/Suo-commerce/taso.git && cd taso
docker build -f deploy/docker/Dockerfile --target agent-demo -t taso-agent-demo .
mkdir -p /var/lib/taso/agent
docker create --name taso-agent-demo taso-agent-demo
docker export taso-agent-demo | tar -x -C /var/lib/taso/agent
docker rm taso-agent-demo
docker compose -f deploy/docker/compose.yaml up --build
```

Compose builds the two images (`taso-blkd:dev`, `taso-wardend:dev`) and
starts both. The Warden waits until the block log answers (up to 60 s;
then it stops with the reason), runs the demo, and ends with the same
two lines as on one machine: `demo` and `demo-fork-2`, each 21 Seals
published and `agent ok`. `docker compose -f deploy/docker/compose.yaml
stop` then stops the block log too.

**What you can set:**

- `TASO_DATA` (default `/var/lib/taso`): the host directory everything
  lives in. `blk/` is the block log, every Vessel's data (put it on the
  data disk); `warden/` is the Warden's coordinator, state and store;
  `agent/` is the agent's root filesystem, read-only to the Warden.
  `taso-ctl init` does not make these, so give them the modes it gives
  its own (see "Who can read the data" above) once, before the first
  start:

  ```
  D=${TASO_DATA:-/var/lib/taso}
  mkdir -p $D/blk $D/warden/{mnt,state,store,spool}
  chmod 0711 $D $D/warden $D/warden/mnt
  chmod 0700 $D/blk $D/warden/state $D/warden/store $D/warden/spool
  ```
- `TASO_WARDEN_CONFIG` (default `deploy/docker/warden.json`, the demo):
  your own Warden config. Its paths are the containers' paths, as
  `warden.json` shows them; your Vessels go in its `"vessels"` as on one
  machine.

**What the containers get, and why:**

- Both run **privileged with the host's `/dev`**. `taso-blkd` makes a
  device for each Vessel after it starts, and a container's own `/dev`
  is copied once when it starts, so the new devices would appear in
  neither.
- Both see the Warden's spool at the same path. The Warden asks
  `taso-blkd` to write each Seal into a file there, by the Warden's own
  path, before shipping it.
- `taso-blkd` keeps its record of each device in the host's
  `/run/ublksrvd`, so a `taso-blkd` started again can remove the devices
  a killed one left behind.
- **One `taso-blkd` per host.** Stop any other first (a host install's,
  for example).

**Stopping and failures:**

- `docker compose stop` stops the Warden first (every agent stopped),
  then `taso-blkd`, which stops cleanly on SIGTERM: every device removed,
  the log checkpointed. If a device is still in use for a moment (the
  Warden just went), it tries again every 250 ms until it can.
- A Warden container killed or crashed: its agents end with it. Started
  again, the Warden reopens each Vessel from its last Seal, and releases
  a Vessel's filesystem the dead one left frozen in the middle of a Seal
  (the log says `thawed …, left frozen by a dead incarnation`).
- A `taso-blkd` container killed: its devices stay in the kernel until
  the next `taso-blkd` starts and removes them (`removed N leftover
  devices`); nothing is lost that a Seal or a flush acknowledged.

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
