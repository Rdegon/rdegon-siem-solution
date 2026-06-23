# Proxmox/SIEM relocation runbook: 192.168.1.0/24 + 192.168.3.0/24

Date: 2026-06-23

Superseded target: for the real segmented relocation, use
`docs/full_segmentation_plan_2026-06-23.md` and
`deploy/network_relocation/stage_full_segmentation.py`.
The `site3` mode below is only a temporary compatibility fallback with NAT and
port forwards; it is not the target design for the `sec`, `mgmt`, `users`,
`lab`, `servers/games` segmentation.

## Goal

Move the physical Proxmox host without breaking SIEM, service access, or VPN access.

The safest relocation model when the new place can provide `192.168.1.0/24` is:

- keep the SIEM/Proxmox infrastructure subnet on `192.168.1.0/24`;
- treat `192.168.3.0/24` as an operator/client LAN segment;
- keep internal lab zones unchanged:
  - `10.20.10.0/24`
  - `10.20.20.0/24`
  - `10.20.30.0/24`
- keep remote VPN access through the existing Proxmox WireGuard client `10.10.10.2/24`.

This avoids changing Kafka, ClickHouse, rsyslog collector targets, CMDB inventory, certificates, and most service URLs.

If the physical Proxmox uplink can only be connected to `192.168.3.0/24`, use the prepared `site3` cutover mode:

- Proxmox external management becomes `192.168.3.101/24`, gateway `192.168.3.1`;
- Proxmox keeps `192.168.1.1/24` as the old guest default gateway;
- Proxmox keeps `192.168.1.101/24` as the legacy Proxmox address for internal SIEM integrations;
- existing VM/LXC service IPs stay unchanged on `192.168.1.x` and `10.20.x`;
- Proxmox performs NAT/port-forwarding between `192.168.3.0/24`, the old `192.168.1.0/24`, internal `10.20.x`, and VPN.

This is the preferred fallback if the new site does not expose `192.168.1.0/24` at all.

## Current fixed addresses

| Role | Address |
| --- | --- |
| Proxmox `pve` | `192.168.1.101` |
| `lab-edge-01` | `192.168.1.102`, `10.20.10.1`, `10.20.20.1`, `10.20.30.1` |
| SIEM Ingest | `192.168.1.35` |
| SIEM Processing | `192.168.1.37` |
| SIEM Storage | `192.168.1.38` |
| SIEM Web | `192.168.1.39` |
| SIEM Transport | `192.168.1.40` |
| Minecraft | `192.168.1.32` |
| Gamepanel | `192.168.1.30` |
| Nextcloud/Navidrome | `10.20.20.120`, `10.20.20.121` |
| Pilot/vuln/OpenClaw | `10.20.30.122`-`10.20.30.126` |

## Router requirements at the new site

Preferred, if the router can expose `192.168.1.0/24`:

1. Connect Proxmox to the `192.168.1.0/24` infrastructure segment.
2. Reserve these static leases or exclusions on the router:
   `192.168.1.30`, `.32`, `.35`, `.37`, `.38`, `.39`, `.40`, `.101`, `.102`.
3. Allow routing from `192.168.3.0/24` to `192.168.1.0/24`.
4. Add routes on the site router if clients on `192.168.3.0/24` must access internal lab services directly:
   - `10.20.20.0/24 via 192.168.1.102`
   - `10.20.30.0/24 via 192.168.1.102`
5. Allow outbound UDP from Proxmox to `176.108.251.109:51820` for WireGuard.

If the router cannot hold static routes to `10.20.*`, use the SIEM Web/UI and public-facing service entry points on `192.168.1.*`; internal `10.20.*` direct access will be limited.

Fallback, if Proxmox must live in `192.168.3.0/24`:

1. Reserve `192.168.3.101` for Proxmox.
2. Confirm the gateway is `192.168.3.1`.
3. Allow outbound UDP from Proxmox to `176.108.251.109:51820` for WireGuard.
4. Optional but recommended on the site router:
   - `192.168.1.0/24 via 192.168.3.101`
   - `10.20.20.0/24 via 192.168.3.101`
   - `10.20.30.0/24 via 192.168.3.101`
5. If the router cannot add these routes, use the port-forward entrypoints on `192.168.3.101` listed below.

## Already prepared changes

Two scripts were added:

- `deploy/network_relocation/proxmox_post_move_network.sh`
  - installs persistent Proxmox routes to `10.20.*` via `192.168.1.102`;
  - installs NAT for VPN clients from `10.10.10.0/24`;
  - can stage and apply the `192.168.3.0/24` fallback cutover only when explicitly confirmed from console.
- `deploy/network_relocation/lab_edge_new_site_acl.sh`
  - allows `192.168.3.0/24` and `10.10.10.0/24` through `lab-edge-01` where `192.168.1.0/24` was already allowed;
  - updates Unbound DNS ACLs for the new operator/VPN networks.

## Before powering off

Run on Proxmox:

```bash
/usr/local/sbin/siem-post-move-network status || true
systemctl status siem-vpn-access.service --no-pager
wg show
qm list
pct list
```

Record the current access URLs:

- Proxmox: `https://192.168.1.101:8006`
- SIEM Web: `https://192.168.1.39`
- Ingest health: `http://192.168.1.35:8443/health`

## After plugging in at the new site

Preferred case, Proxmox remains in `192.168.1.0/24`:

1. Reserve/confirm the router gateway is `192.168.1.1`.
2. Boot Proxmox.
3. From `192.168.1.0/24`, open `https://192.168.1.101:8006`.
4. From `192.168.3.0/24`, test:

```powershell
Test-NetConnection 192.168.1.101 -Port 8006
Test-NetConnection 192.168.1.39 -Port 443
Test-NetConnection 192.168.1.35 -Port 8443
```

5. In the SIEM Web UI, verify events and incidents load.

Fallback case, the server must move to `192.168.3.0/24`:

Use local Proxmox console, not SSH:

```bash
/usr/local/sbin/siem-post-move-network apply-site3 --confirm-site3-cutover

ifreload -a
systemctl restart siem-site3-edge.service
/usr/local/sbin/siem-post-move-network status
```

Then access Proxmox at `https://192.168.3.101:8006`.

In this mode SIEM VM static addresses remain `192.168.1.*`, but they continue to work because Proxmox becomes their old gateway `192.168.1.1`.

### Port-forward entrypoints in `192.168.3.0/24` mode

Use these if the new router cannot route `192.168.1.0/24` to `192.168.3.101`:

| Entry point | Target |
| --- | --- |
| `https://192.168.3.101:8006` | Proxmox UI |
| `https://192.168.3.101/` | SIEM Web `192.168.1.39:443` |
| `http://192.168.3.101:8443/health` | SIEM Ingest `192.168.1.35:8443` |
| `192.168.3.101:1514-1518/tcp,udp` | SIEM syslog ingest ports |
| `192.168.3.101:25565` | Minecraft |
| `http://192.168.3.101:8100` | Minecraft admin console |
| `https://192.168.3.101:9443` | Nextcloud |
| `https://192.168.3.101:9444` | Navidrome |
| `https://192.168.3.101:9445` | Gamepanel |

If you want direct old IP access from a Windows workstation in `192.168.3.0/24`, add temporary persistent routes:

```powershell
route -p add 192.168.1.0 mask 255.255.255.0 192.168.3.101
route -p add 10.20.20.0 mask 255.255.255.0 192.168.3.101
route -p add 10.20.30.0 mask 255.255.255.0 192.168.3.101
```

## VPN access

The Proxmox WireGuard interface is an outbound client. It should reconnect after the move as long as outbound UDP/51820 is allowed.

Current pre-move observation: local `wg-quick@wg0` is active on Proxmox, but the remote peer was not handshaking at check time (`latest_handshake_epoch=0`, RX `0`). The local routing/NAT side is prepared; the remote VPN endpoint still has to be online and route the lab networks back through this peer.

On the remote WireGuard side, route these networks through the Proxmox peer if full access is required:

```text
192.168.1.0/24
192.168.3.0/24, only if Proxmox management is moved there
10.20.20.0/24
10.20.30.0/24
```

The prepared Proxmox NAT makes VM/LXC return traffic work without changing every guest gateway.

## Final smoke test

From Proxmox:

```bash
systemctl --failed --no-pager
systemctl status siem-vpn-access.service --no-pager
wg show
ip route get 10.20.30.126
curl -k --max-time 10 https://192.168.1.39/health || true
```

From SIEM Storage:

```bash
clickhouse-client --query "
SELECT count(), uniqExact(host_name), max(ts)
FROM siem.events
WHERE ts >= now() - INTERVAL 5 MINUTE
FORMAT PrettyCompact"

clickhouse-client --query "
SELECT rule_id, rule_name, count()
FROM siem.alerts_raw
WHERE lower(status) = 'open'
GROUP BY rule_id, rule_name
ORDER BY count() DESC
FORMAT PrettyCompact"
```

From a workstation in `192.168.3.0/24`:

```powershell
Test-NetConnection 192.168.1.101 -Port 8006
Test-NetConnection 192.168.1.39 -Port 443
Test-NetConnection 192.168.1.35 -Port 8443
```

## Rollback

Proxmox address rewrite backs up `/etc/network/interfaces` as:

```text
/etc/network/interfaces.bak.<UTC timestamp>
```

Restore from local console:

```bash
cp -a /etc/network/interfaces.bak.<timestamp> /etc/network/interfaces
ifreload -a
```

The VPN/NAT preparation can be disabled without changing guest IPs:

```bash
systemctl disable --now siem-vpn-access.service
nft delete table ip siem_vpn_access || true
```
