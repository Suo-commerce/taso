# Gate machines on Hetzner Cloud

Three servers in one **separate** Hetzner project (never the hodd-cp
project), location **Helsinki (hel1)**, one private network.

| Name | Type | Role | cloud-init |
|---|---|---|---|
| taso-a | CPX62 (16 vCPU, 32 GB, 640 GB local NVMe) | Vessels, Warden (node A) | `cloud-init-vessel.yaml` |
| taso-b | CPX62 | Vessels, Warden (node B) | `cloud-init-vessel.yaml` |
| taso-c | CPX21 (or similar small) | Garage + taso-coordd | none |

All three are billed hourly: delete them when the gate runs are done.

## In the console

1. New project, e.g. `taso-gate`.
2. **Networks → Create network** `taso`, IP range `10.0.0.0/16` (the console
   adds a subnet in the eu-central zone, which includes Helsinki).
3. **Firewalls → Create firewall** `taso`: inbound TCP 22 only (the private
   network is not filtered by Hetzner firewalls).  Apply it to all three.
4. **Servers → Add server**, three times:
   - Location Helsinki; image **Ubuntu 26.04** (24.04 if 26.04 is not listed:
     ZFS 2.2 also has the channel programs Taso needs);
   - type as in the table; your SSH key; network `taso`; firewall `taso`;
   - for taso-a and taso-b, paste `cloud-init-vessel.yaml` into
     **Cloud config**; nothing for taso-c.
5. Note each server's public IP and private IP (10.0.0.x).

## On each server (as root)

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
