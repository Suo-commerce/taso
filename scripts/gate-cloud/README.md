# Gate machines on Hetzner Cloud

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

