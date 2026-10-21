# Gate machines

Two setups, one per storage:

- **Hetzner Cloud, ZFS** (P1 and P2, 2026-10-17): this section.
- **UpCloud, block log** (S2, 2026-10-20): [the section at the end](#upcloud-block-log-s2-2026-10-20).

# Hetzner Cloud (ZFS)

Three servers in one **separate** Hetzner project (never the hodd-cp
project), location **Helsinki (hel1)**, one private network.

| Name | Type | Role | cloud-init |
|---|---|---|---|
| taso-a | CPX62 (16 vCPU, 32 GB, 640 GB local NVMe) | Vessels, Warden (node A) | `cloud-init-vessel.yaml` |
| taso-b | CPX62 | Vessels, Warden (node B) | `cloud-init-vessel.yaml` |
| taso-c | CPX21 (or similar small) | Garage + taso-coordd | none |

All three are billed hourly: delete them when the gate runs are done (copy
`/root/taso-gate-p*` off taso-a first).  The project, network, firewall and
SSH key can stay for next time.

## In the console

1. New project, e.g. `taso-gate`.  **Security → SSH keys → Add SSH key**
   first, and mark it default: without a key, servers get emailed root
   passwords that must be changed at the first login, and the rescue system
   has no way in either.
2. **Networks → Create network** `taso`, IP range `10.0.0.0/16` (the console
   adds a subnet in the eu-central zone, which includes Helsinki).
3. **Firewalls → Create firewall** `taso`: inbound TCP 22 only (the private
   network is not filtered by Hetzner firewalls).  Apply it to all three.
4. **Servers → Add server**, three times:
   - Location Helsinki; image **Ubuntu 26.04** (24.04 if 26.04 is not listed:
     ZFS 2.2 also has the channel programs Taso needs);
   - type as in the table; your SSH key; network `taso`; firewall `taso`;
   - for taso-a and taso-b, paste `cloud-init-vessel.yaml` into
     **Cloud config**; nothing for taso-c.  **This is the step that is easy
     to miss, and it only works at creation**: without it cloud-init grows
     root over the whole disk on first boot (and again on every boot: its
     growpart module runs with frequency "always"), leaving nothing for ZFS.
5. Note each server's public IP and private IP (10.0.0.x).
6. Check before any setup, from your machine:
   ```
   ssh root@<public ip> 'hostname; ip -br -4 addr | grep 10\.0\.; lsblk -o NAME,SIZE,TYPE,MOUNTPOINT; cloud-init status'
   ```
   On taso-a and taso-b the root partition must be small (a few GB) with the
   rest unallocated.  If root fills the disk, see "Root grew over the disk".

## On each server (as root)

Rust is installed by the setup into `/root/.cargo`; a shell opened before
that needs `. /root/.cargo/env` (new logins have it).

```
git config --global credential.helper 'cache --timeout=900'
git clone https://github.com/Suo-commerce/taso.git /root/taso && cd /root/taso
```

Then, **first on taso-c**, then on taso-a and taso-b:

```
scripts/gate-cloud/node-setup.sh hub    <taso-c private ip>    # on taso-c
scripts/gate-cloud/node-setup.sh vessel <taso-c private ip>    # on taso-a, taso-b
```

The hub writes `/root/taso-s3.env`; copy it to `/root/taso-s3.env` on taso-a
and taso-b.  The vessel setup prints the disk layout before it changes it,
and stops if it does not look as expected.

Checks, on taso-a and taso-b:

```
zpool list taso; zfs list -r taso
ls -l /run/taso/coord.sock
set -a; . /root/taso-s3.env; set +a
cd /root/taso && cargo test -p taso-warden round_trip_on_garage -- --ignored
```

## Running the gates

Node A drives both gates.  For P2 it reaches node B over ssh on the
private network; give taso-a a key that taso-b accepts:

```
# on taso-a
ssh-keygen -t ed25519 -N '' -f /root/.ssh/id_ed25519 && cat /root/.ssh/id_ed25519.pub
# on taso-b: append that line to /root/.ssh/authorized_keys
# on taso-a, once, to accept B's host key:
ssh root@<taso-b private ip> true
```

Then, on taso-a, each run starting with the branch it tests:

```
cd /root/taso && git checkout <branch> && git pull
# P2: SIGSTOP the Warden on A, rebirth on B, 20 rounds
TASO_ZFS_DATASET=taso/vessel B_HOST=root@<taso-b private ip> N=20 scripts/gate-p2.sh
# P1: p64 on A's NVMe, 10 runs, publishing to Garage through the hub
TASO_ZFS_DATASET=taso/vessel HUB=1 RUNS=10 scripts/gate-p1.sh
```

Results land in `/root/taso-gate-p{1,2}-<time>/summary.txt`.

## Root grew over the disk (cloud config missing)

Seen on the first setup: no user data reached the servers, cloud-init's log
said `No 'growpart' entry in cfg`, and root took the whole disk.  Recreating
the server with the cloud config pasted is simplest.  Otherwise shrink root
from the rescue system (the server is empty, so nothing is at stake, but
every step is checked):

1. Console: server → **Rescue** → **Enable rescue & power cycle**, with the
   SSH key selected.  If the console's action list shows no reboot, use
   **Power → Power cycle**.  Then `ssh-keygen -R <ip>` and log in.
2. **Check where you are** before touching the disk:
   ```
   hostname; findmnt -no SOURCE /; sfdisk -l /dev/sda
   ```
   It must print `rescue`, a root that is not `/dev/sda1` (`overlay`), and
   sda14/sda15 at the start of the disk with sda1 after them.
3. Shrink (the `mkdir` matters: without it the no-grow file is not written
   and root grows back at the next boot):
   ```
   mkdir -p /mnt/r
   e2fsck -f -y /dev/sda1
   resize2fs /dev/sda1 90G
   echo ',100G' | sfdisk --no-reread -N 1 /dev/sda
   partx -u /dev/sda
   e2fsck -f -y /dev/sda1 && resize2fs /dev/sda1
   mount /dev/sda1 /mnt/r
   printf 'growpart:\n  mode: "off"\nresize_rootfs: false\n' > /mnt/r/etc/cloud/cloud.cfg.d/99-taso-nogrow.cfg
   cat /mnt/r/etc/cloud/cloud.cfg.d/99-taso-nogrow.cfg
   umount /mnt/r
   sfdisk -l /dev/sda; sfdisk --list-free /dev/sda
   ```
4. **Read the output before rebooting**: the second `e2fsck` clean, sda1
   100G at the same start sector, the config file printed back with no
   `mount` error, ~510 GiB free.  (The first `e2fsck` fixing free-block
   counts after the hard power cycle is normal.)  Then `reboot`.
5. After the reboot: `ssh-keygen -R <ip>`, then check
   `lsblk /dev/sda; df -h /` shows 100G, and run the vessel setup.

## What the gates found on the first Hetzner run (2026-10-17)

- P2: 20/20 on all six lines; rebirth p95 4.86 s.
- P1 at p64: SIGBUS 0, write ratio 1.18: pass.  Seal p95 114 ms: fail.  The
  coordinator round trip was first serialized in `RemoteCoord` (fixed: a
  connection pool); what remains is the snapshot: a Seal waits for the ZFS
  program in flight and then runs its own, ~23-34 ms each on this virtual
  disk under load (idle: 10-20 ms).  With a local store on the same disk it
  is worse (publishing competes for the disk).


# UpCloud (block log, S2, 2026-10-20)

The P2 gate on the block log (`scripts/gate-p2-blk.sh`): Vessels on
`taso-blkd` (ext4 on ublk), packs in Scaleway Object Storage (Paris), the
coordinator reached over ssh.  S2 passed in this layout, 85 rounds
(`Taso_finding_s2_5_2026-10-20` in the Project).  No disk changes are
needed: the block log is a file on the root disk.

| Name | Zone | Role |
|---|---|---|
| taso-test (keep) | FI-HEL2 | the hub: `taso-coordd` (`coord` role) and the gate driver; also a one-machine node (S2.1) |
| taso-a, taso-b (create, delete after) | FI-HEL1 | nodes: `taso-blkd`, `taso-wardend` started by the gate, runc (`vessel-blk` role) |

The driver and the coordinator must outlive the node that is killed, so
they are on a third machine (two servers also work: hub and driver on
node B, `coord … local=<id>` and `vessel-blk local <name>` there; that
was S2.2).  Servers of one account reach each other on UpCloud's
**utility network** (10.x, across zones, ~1 ms between FI-HEL1 and
FI-HEL2); every address below is a utility address.

## Creating a node

From the laptop, with `scripts/gate-cloud/upctl-nodes.sh` (UpCloud's CLI
`upctl` and `jq` installed; the API token from UpCloud Hub → API tokens in
`~/.config/upcloud-token`, mode 600):
```
export UPCLOUD_TOKEN=$(cat ~/.config/upcloud-token)
scripts/gate-cloud/upctl-nodes.sh check        # read-only: plan, template, key
scripts/gate-cloud/upctl-nodes.sh create a b   # taso-a, taso-b
```
It creates each node with the hub's plan, Ubuntu 26.04 and your key, and
a first-boot script that installs the security updates (a fresh image
predates them: the emSign root removed from `ca-certificates`,
2026-10-21).  It refuses a name that exists and checks that exactly one
server was made (the console's deploy button fired twice on 2026-10-20).
It prints each node's public and utility address.  `list` shows the gate
nodes; `delete a b` shows what it would delete, `delete --yes a b`
deletes them (gate nodes only, by UUID; the hub never).

Then, on each node, the repo:
```
git clone https://github.com/Suo-commerce/taso.git /root/taso
```

By hand instead (the console): Deploy server, Ubuntu 26.04, the hub's
plan, FI-HEL1, your SSH key; click deploy **once** and check the server
list for duplicates; on the node `apt-get update -q && apt-get upgrade -y
-q` before anything else.

## Setting up (as root, from `/root/taso`)

The roles wait for the apt lock of a fresh image's first-boot updates,
log their builds to `/root/taso-build.log`, and are rerunnable.  Every
block below names the machine it runs on; check the prompt before
pasting.

On each **node** (`a` on taso-a, `b` on taso-b; the role renames the host
`taso-a` / `taso-b`):
```
scripts/gate-cloud/node-setup.sh vessel-blk <hub utility ip> a
```
It prints the node's public key (`/root/.ssh/taso-coord.pub`, made on the
node, never copied anywhere but the hub).  Put it on the **hub** as
`/root/taso-keys/a.pub` (and `b.pub` for taso-b), then on the **hub**:
```
scripts/gate-cloud/node-setup.sh coord a=1 b=2
```
`a=1` means: the node whose key is in `a.pub` acts as Warden 1, and only
as Warden 1 (fencing F3 step 1: the coordinator reads the ssh login user's
uid).  Then on each **node**, `systemctl restart taso-coord-fwd`, or rerun
its role, which ends with the check that the coordinator knows it.

On the **hub**, the driver's key and the S3 settings:
- `/root/.ssh/id_ed25519.pub` appended to each node's
  `/root/.ssh/authorized_keys`, and one `ssh root@<node utility ip> true`
  from the hub to accept the host key;
- the Scaleway secret key in `/root/s3-secret` and the key id in
  `/root/s3-key-id`, both mode 600, typed on the hub (never in a chat, never
  in the repo).  The gate copies the secret into its work directory on the
  nodes (`/var/tmp/taso-p2blk.*/s3.secret`, mode 600) and removes the
  directory after a normal run.  **A run with `KEEP=1` or `KILL=power`
  keeps the directory as evidence, secret included**: remove the secret
  by hand after reading the evidence
  (`rm -f /var/tmp/taso-p2blk.*/s3.secret` on each node).

## Running the gate

On the **hub**, from `/root/taso` on the branch under test:
```
TASO_BLK_S3_ENDPOINT=https://s3.fr-par.scw.cloud TASO_BLK_S3_REGION=fr-par \
TASO_BLK_S3_BUCKET=taso-packs-suo TASO_BLK_S3_ACCESS_KEY_ID=$(cat /root/s3-key-id) \
A_HOST=root@<taso-a utility ip> B_HOST=root@<taso-b utility ip> \
scripts/gate-p2-blk.sh
```
The other direction: swap the hosts and the ids (`A_WARDEN=2 B_WARDEN=1`):
identity follows the key, not the gate's letters.  `KILL=power N=5` stops
node A's machine instantly; the script then waits until A answers ssh
again: start it from the console.  Results land in
`/root/taso-gate-p2blk-<time>/summary.txt` on the hub; the packs stay in
the bucket under `gate-p2blk-<run>/`.

Rebirth time grows with the turn Seals shipped before the kill (~0.8 s
per Seal fetched from Paris), so compare runs per Seal, not by a fixed
p95.

## Afterwards

- Copy anything wanted off the nodes, then delete taso-a and taso-b in the
  console (check for duplicates).  The hub keeps their users and keys
  (`warden-a`, `warden-b`, `/root/taso-keys/`): a recreated node gets a new
  key, so copy its `.pub` again and rerun `coord`.
- The hub's `coord.redb` accumulates every run's registrations; harmless.

## What S2 found (2026-10-20)

| Stage | Layout | Result |
|---|---|---|
| S2.1 | one machine (taso-test) | 20/20, p95 0.29 s (packs local) |
| S2.2 | two servers, packs in Paris | 20/20, p95 6.60 s |
| S2.3 | node A's power cut, 5 times | 5/5, p95 5.89 s |
| S2.4 | A's log after each cut | 0 bytes cut in 9 boots |
| S2.5 | hub + two nodes, both directions | 20/20 each, p95 9.2 s / 11.4 s |

The last common Seal was identical block for block in all 85 rounds, and
every lost record was named by a Gap.
