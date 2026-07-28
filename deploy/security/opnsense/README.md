# OPNsense production NGFW

This directory contains the reproducible configuration automation for VM103
`opnsense-edge-01`. Credentials and exported firewall configuration are kept
outside Git in the operator bundle.

## Current production state

| Item | Value |
| --- | --- |
| OPNsense | 26.7.1_1 |
| Suricata | 8.0.6 |
| VMID | 103 |
| Resources | 4 vCPU, 8 GB RAM, 40 GB disk |
| Autostart | enabled, order 20 |
| Isolated management | `vtnet0`, `172.31.255.2/30`, `vmbr5` |
| WAN and WebGUI | `vtnet1`, `192.168.3.103/24`, `vmbr0` |
| sec | `vtnet2`, `10.20.10.254/24`, `vmbr2` |
| servers/games | `vtnet3`, `10.20.20.254/24`, `vmbr3` |
| lab | `vtnet4`, `10.20.30.254/24`, `vmbr1` |
| users | `vtnet5`, `10.20.40.254/24`, `vmbr4` |
| SIEM syslog | RFC5424 TCP to `10.20.10.104:1514` |

VM103 is the production router and NGFW for all internal segments. VM102
`lab-edge-01` remains the public SIEM entry and recovery edge; it is not the
primary inter-zone router.

## Management access

The local management endpoint is:

```text
https://192.168.3.103
```

WAN-side WebGUI and ICMP access is limited to:

- operator workstation `192.168.3.81/32`;
- Proxmox VPN transit `192.168.3.101/32`;
- management VPN `10.10.10.0/24`.

OPNsense has a return route for `10.10.10.0/24` through `192.168.3.101`.
The isolated `172.31.255.2/30` interface is a console-side recovery path and
is not exposed to the site LAN.

## IPS policy

Suricata uses Netmap IPS on `vtnet1-vtnet5`. Hardware checksum offload, TSO,
LRO and VLAN hardware filtering are disabled. The isolated management
interface is not captured.

The active inline set covers C2, malware, exploits, phishing, scans, Web,
mail, DNS and common service protocols. General rules alert only. The
`High-confidence IOC prevention` policy changes these rulesets to `drop`:

- `abuse.ch.feodotracker.rules`
- `abuse.ch.sslipblacklist.rules`
- `drop.rules`
- `threatview_CS_c2.rules`

Do not bulk-convert ET Open rules to `drop`. Promote a signature only after
historical replay, a canary test and review of the affected assets.

Large SSL-fingerprint, ThreatFox and URLhaus feeds are ingested as expiring
threat-intelligence indicators instead of inline rules. Compiling them inline
raised Suricata memory consumption above 6 GB. The production inline set uses
about 1.5 GB RSS.

## Reconciliation

Use these idempotent utilities after a restore or configuration drift:

```text
python deploy/security/opnsense/set_system_hostname.py
python deploy/security/opnsense/promote_internal_ngfw.py
```

The promotion tool verifies aliases, inter-zone rules, hybrid outbound NAT,
Unbound and IDS state. Run the SIEM source and Web smoke tests after every
firewall reconciliation.

## Recovery

- Keep VM102 configured as a published and recovery edge.
- Keep Proxmox console access independent from a routed production zone.
- Store OPNsense XML exports outside the Proxmox host.
- Test `siem-vpn-access.service`, `wg show wg0` and routes after every reboot.
- Add a second physical host, Proxmox Backup Server and UPS/NUT before
  claiming physical-host or power-loss continuity.
