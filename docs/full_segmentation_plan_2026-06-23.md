# Full network segmentation plan

Date: 2026-06-23

## Current deployed state

Validated after the site move on 2026-07-25:

- operator workstation: `192.168.3.81`;
- Proxmox: `192.168.3.101`;
- `lab-edge-01`: `192.168.3.102`;
- all `sec`, `servers/games`, `lab`, and `users` bridges are present;
- SIEM and service guests use their `10.20.x` segment address as primary and retain required `192.168.1.x/32` aliases;
- traffic from `192.168.3.0/24` to internal segments is routed without source NAT so logs retain the real management-client IP;
- only remote VPN source ranges are masqueraded toward internal segments.

Local management entry points:

| Service | URL/address |
| --- | --- |
| Proxmox | `https://192.168.3.101:8006/` |
| SIEM Web | `https://192.168.3.102/` |
| SIEM Ingest health | `https://192.168.3.102:8443/health` |
| Nextcloud | `https://192.168.3.102:9443/` |
| Navidrome | `http://192.168.3.102:9444/` |
| Gamepanel | `http://192.168.3.102:9445/` |
| Minecraft | `192.168.3.102:25565` |
| BlueMap | `http://192.168.3.102:8100/` |
| Minecraft admin | `http://192.168.3.102:8111/` |

## Correction

The previous `site3` mode was a compatibility bridge with NAT/port forwards. The target state is now a real segmentation model:

- services move into internal segments;
- old service IPs are preserved as `/32` legacy service aliases where needed;
- Proxmox physical uplink moves to `192.168.3.0/24`;
- `lab-edge-01` remains the router/firewall/DNS boundary between segments.

## Segment map

| Segment | CIDR | Proxmox bridge | Gateway | Purpose |
| --- | --- | --- | --- | --- |
| `mgmt` | `192.168.3.0/24` | `vmbr0` | external router `192.168.3.1` | Proxmox and admin access |
| `sec` | `10.20.10.0/24` | `vmbr2` | `10.20.10.1` | SIEM core |
| `servers/games` | `10.20.20.0/24` | `vmbr3` | `10.20.20.1` | Nextcloud, Navidrome, Minecraft, Gamepanel |
| `lab` | `10.20.30.0/24` | `vmbr1` | `10.20.30.1` | Pilot, vuln, OpenClaw |
| `users` | `10.20.40.0/24` | `vmbr4` | `10.20.40.1` | reserved internal users/client segment |

`192.168.1.0/24` is no longer used as a physical segment in this plan. It becomes a legacy service-address space with host routes.

## Service IP preservation

Exact old service IPs can be preserved as `/32` aliases:

| Service | Segment IP | Legacy service IPs |
| --- | --- | --- |
| SIEM Ingest | `10.20.10.104` | `192.168.1.35` |
| SIEM Processing | `10.20.10.105` | `192.168.1.37` |
| SIEM Storage | `10.20.10.106` | `192.168.1.38` |
| SIEM Web | `10.20.10.107` | `192.168.1.39` |
| SIEM Transport | `10.20.10.108` | `192.168.1.40` |
| Minecraft | `10.20.20.100` | `192.168.1.32` |
| Nextcloud | `10.20.20.120` | unchanged |
| Navidrome | `10.20.20.121` | unchanged |
| Gamepanel | `10.20.20.130` | `192.168.1.30`, `192.168.1.43`, `192.168.1.44`, `192.168.1.45` |

Important: if the new physical site uses `192.168.1.0/24` as a real user LAN, these preserved `192.168.1.x` service IPs will conflict with local ARP behavior. In that case the choices are:

1. keep exact service IPs and do not use `192.168.1.0/24` as a client LAN near this Proxmox host;
2. use DNS names and move services fully to `10.20.x`;
3. use NAT/proxy as a temporary compatibility layer.

## Generated artifacts

- `deploy/network_relocation/full_segmentation_manifest.json`
- `deploy/network_relocation/stage_full_segmentation.py`

Run on Proxmox to stage reviewable scripts:

```bash
python3 stage_full_segmentation.py --output-dir /root/siem-full-segmentation
```

It writes:

- `/root/siem-full-segmentation/01_pve_cutover.sh`
- `/root/siem-full-segmentation/02_lab_edge_cutover.sh`
- `/root/siem-full-segmentation/03_guest_cutover_notes.md`
- `/root/siem-full-segmentation/04_disable_legacy_siem_vmbr0_nics.sh`

Do not execute generated cutover scripts over SSH. Use local Proxmox console.

## Cutover order

1. Snapshot/backup all affected VMs/LXCs.
2. Stage artifacts on Proxmox.
3. Apply Proxmox bridge/uplink changes from local console.
4. Apply lab-edge network/firewall/DNS changes.
5. Apply guest netplan/systemd-network changes one host at a time.
6. Verify SIEM ingest, Kafka, ClickHouse, Web, rsyslog and alerts through the new segments.
7. Disable old SIEM `vmbr0` NICs only after guest validation.
8. Only after all env files are moved to DNS/10.20.x, consider removing legacy `/32` service aliases.

The WireGuard service on Proxmox is enabled and starts automatically. End-to-end VPN readiness still depends on the remote peer producing a current handshake; a running local service alone is not sufficient evidence of remote reachability.
