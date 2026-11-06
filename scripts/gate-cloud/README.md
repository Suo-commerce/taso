# Gate machines

The block log on UpCloud (S2, 2026-10-20), below.  The Hetzner setup (P1
and P2, 2026-10-17) went with V4b; its findings are in the Project's
handoffs of that week.

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
