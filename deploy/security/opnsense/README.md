# OPNsense staging and production cutover

This directory documents the reproducible state of VM103
`opnsense-staging`. It contains no credentials or exported firewall
configuration.

## Current staging state

| Item | Value |
| --- | --- |
| OPNsense | 26.7.1_1 |
| Suricata | 8.0.6 |
| VMID | 103 |
| Resources | 4 vCPU, 8 GB RAM, 40 GB disk |
| Autostart | enabled, order 20 |
| Isolated management | `vtnet0`, `172.31.255.2/30`, `vmbr5` |
| WAN staging | `vtnet1`, `192.168.3.103/24`, `vmbr0` |
| sec | `vtnet2`, `10.20.10.254/24`, `vmbr2` |
| servers/games | `vtnet3`, `10.20.20.254/24`, `vmbr3` |
| lab | `vtnet4`, `10.20.30.254/24`, `vmbr1` |
| users | `vtnet5`, `10.20.40.254/24`, `vmbr4` |
| SIEM syslog | RFC5424 TCP to `10.20.10.104:1514` |

VM102 remains the production gateway. Do not assign a production client to
VM103 until the canary checklist below passes.

## Management access

The normal local management endpoint is:

```text
https://192.168.3.103
```

The WAN-side WebGUI and ICMP rules accept only the following sources:

- operator workstation `192.168.3.81/32`;
- Proxmox VPN transit `192.168.3.101/32`;
- management VPN `10.10.10.0/24`.

OPNsense also has a return route for `10.10.10.0/24` through
`192.168.3.101`. Proxmox currently masquerades the WireGuard transit, so the
firewall normally sees `192.168.3.101`; the explicit route preserves a
non-NAT recovery option. The temporary Proxmox TCP proxies on ports `10443`
and `10022` are stopped. The isolated `172.31.255.2/30` interface remains a
console-side recovery path and is not exposed to the site LAN.

The active WireGuard interface on Proxmox has no current peer handshake.
Local access and the Proxmox transit path have been tested, but remote
end-to-end access must be repeated while the remote peer is online.

## IPS policy

Suricata uses Netmap IPS on `vtnet1-vtnet5`. Hardware checksum offload, TSO,
LRO and VLAN hardware filtering are disabled. The management interface is not
captured.

The selected content covers C2, malware, exploits, phishing, scans, web,
mail, DNS and common service protocols. General rules alert only. The
`High-confidence IOC prevention` policy changes these rulesets to `drop`:

- `abuse.ch.feodotracker.rules`
- `abuse.ch.sslipblacklist.rules`
- `drop.rules`
- `threatview_CS_c2.rules`

Do not bulk-convert ET Open rules to `drop`. Promote a signature only after
historical replay, a canary test and review of the matching assets.

The large SSL fingerprint, ThreatFox and URLhaus feeds are not compiled into
inline rules. They raised Suricata memory use above 6 GB on an 8 GB VM. Ingest
them as expiring threat-intelligence indicators instead; the current inline
set uses about 1.5 GB RSS and contains 46,047 active signatures.

## Canary checklist

1. Export and verify the latest OPNsense configuration backup.
2. Recreate VM102 aliases, NAT, published ports, DNS and VPN on VM103.
3. Apply explicit default-deny rules between zones.
4. Point one disposable host in each zone at its `.254` gateway.
5. Verify DNS, Internet, SIEM Web/SSO, HTTP ingest, syslog ingest and VPN.
6. Verify Kafka and ClickHouse lag, correlation latency and Web latency.
7. Run the production transport EPS ladder with IPS in path.
8. Observe alert and drop telemetry for at least seven days.
9. Test immediate rollback to the VM102 `.1` gateway.

## Production promotion

Freeze configuration, stop new state on VM102 and move the unchanged gateway
addresses to VM103:

```text
192.168.3.102
10.20.10.1
10.20.20.1
10.20.30.1
10.20.40.1
```

Keeping the internal gateway addresses unchanged avoids reconfiguring guests.
Existing TCP sessions can still reset during the first Linux nftables to
OPNsense pf cutover because their state tables cannot be synchronized.

Stateful zero-loss failover requires two OPNsense nodes on separate physical
hosts, CARP VIPs, a dedicated pfsync network and XMLRPC configuration sync.
Two VMs on the same Proxmox host do not survive host power loss or relocation.

## Recovery

- Keep VM102 configured and available until production validation is complete.
- Keep Proxmox console access; management access must not depend on a routed
  production zone.
- Store OPNsense exports outside the Proxmox host.
- Add a second physical host, Proxmox Backup Server and UPS/NUT before claiming
  site or power-loss continuity.
