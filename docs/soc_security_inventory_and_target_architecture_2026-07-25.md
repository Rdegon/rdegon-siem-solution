# SOC security inventory and target architecture

Date: 2026-07-25

## Executive finding

OPNsense 26.7.1_1 is now installed as VM103 `opnsense-staging`. It is connected
in parallel to every routed segment and has a separate isolated management
network. Its Suricata 8.0.6 engine runs in Netmap IPS mode on the WAN, sec,
servers/games, lab and users interfaces.

VM102 `lab-edge-01` remains the production gateway. It still provides the
active `.1` gateway addresses, NAT, nftables, Unbound and the public SIEM entry
point. VM103 uses `.254` staging addresses and therefore does not take over or
interrupt existing connections. Production promotion remains a controlled
cutover after canary routing, firewall policy validation and rollback tests.

## Current network

```text
                         Site gateway / Internet
                               192.168.3.1
                                     |
                         mgmt 192.168.3.0/24
                                     |
                 +-------------------+-------------------+
                 |                                       |
        Proxmox 192.168.3.101                 VM102 lab-edge-01
                                               192.168.3.102
                                          Ubuntu + nftables
                                          Unbound + Suricata
                 +-------------------+----------+----------+----------+
                 |                   |          |          |
          sec 10.20.10.1      lab 10.20.30.1   |    users 10.20.40.1
                 |                   |          |
           SIEM 104-108       vuln/pilot/       |
                              openclaw       servers/games 10.20.20.1
                                                |
                              Minecraft, Nextcloud, Navidrome, Gamepanel

        VM103 opnsense-staging is attached in parallel:
        WAN 192.168.3.103, sec 10.20.10.254,
        servers/games 10.20.20.254, lab 10.20.30.254,
        users 10.20.40.254, isolated mgmt 172.31.255.2/30.
        No production host currently uses VM103 as its default gateway.
```

Proxmox provides L2 bridges:

| Bridge | Segment | Gateway |
| --- | --- | --- |
| `vmbr0` | `mgmt` / physical uplink | upstream `192.168.3.1` |
| `vmbr2` | `sec` | VM102 `10.20.10.1` |
| `vmbr3` | `servers/games` | VM102 `10.20.20.1` |
| `vmbr1` | `lab` | VM102 `10.20.30.1` |
| `vmbr4` | `users` | VM102 `10.20.40.1` |
| `vmbr5` | isolated OPNsense management | PVE `172.31.255.1`, VM103 `172.31.255.2` |

## Asset inventory

| ID | Asset | Segment/address | Main role | State |
| --- | --- | --- | --- | --- |
| PVE | Proxmox 9.0.3 | `192.168.3.101` | Hypervisor, bridges, WireGuard | running |
| 100 | `minecraft-01` | `10.20.20.100` | Minecraft | running |
| 101 | `win-test` | stopped | Windows test source | stopped |
| 102 | `lab-edge-01` | `.3.102`, `10.20.{10,20,30,40}.1` | Router, DNS, IDS | running |
| 103 | `opnsense-staging` | `.3.103`, `10.20.{10,20,30,40}.254`, `172.31.255.2` | Staged NGFW, DNS/VPN target, inline IPS | running |
| 104 | `siem-ingest` | `10.20.10.104` | HTTP/syslog ingest, Kafka, Mongo/Postgres replica | running |
| 105 | `siem-processing` | `10.20.10.105` | Kafka, normalizer, filter | running |
| 106 | `siem-storage` | `10.20.10.106` | ClickHouse, writer, correlation | running |
| 107 | `siem-web` | `10.20.10.107` | Web, Keycloak, Vault, Mongo/Postgres | running |
| 108 | `siem-transport` | `10.20.10.108` | Kafka, processing standby, ClickHouse standby | running |
| 111 | `WIN-RTX-test` | `192.168.3.81` | Operator workstation and Windows source | running |
| 120 | `nextcloud-siem` | `10.20.20.120` | Nextcloud, Redis, Fail2ban | running |
| 121 | `navidrome-01` | `10.20.20.121` | Navidrome, OAuth2 proxy, Nginx | running |
| 122 | `vuln-mgr-01` | `10.20.30.122` | OpenVAS container | running |
| 123 | `pilot-web-01` | `10.20.30.123` | Gitea pilot | running |
| 124 | `pilot-db-01` | `10.20.30.124` | PostgreSQL pilot | running |
| 125 | `pilot-cache-01` | `10.20.30.125` | Valkey pilot | running |
| 126 | `openclaw-gateway` | `10.20.30.126` | Integration gateway | running |
| 130 | `gamepanel-01` | `10.20.20.130`, legacy `192.168.1.44/32` alias | Pterodactyl Wings, VPN, game workloads | running |

VM130 is attached to `servers/games` but still depends on a legacy `/32`
address. Add `10.20.20.130` while retaining the old address as an alias during
the transition, then update bindings and retire the alias after verification.

## Existing security controls

| Layer | Existing control | Finding |
| --- | --- | --- |
| Routing/firewall | VM102 Ubuntu + nftables | Active production gateway; single point of failure |
| Staged NGFW | OPNsense 26.7.1_1 on VM103 | All zones attached; not yet a production gateway |
| Network IDS | Suricata 7.0.3 on VM102 | Captures `eth0-eth4`; steady-state drop delta is zero, with 1,009 cumulative startup/reload drops on `eth0` |
| IDS rules | ET Open | 67,984 total, 52,051 enabled |
| Inline IPS | Suricata 8.0.6 on VM103 | Netmap on `vtnet1-vtnet5`; 44 curated rulesets and a high-confidence drop policy |
| DNS security | Unbound on VM102 | Active; no documented DNS policy lifecycle |
| SIEM ingest | VM104 | HTTP and syslog transport active |
| Message transport | Three Kafka brokers | VM104, VM105 and VM108 |
| Processing | Normalizer/filter workers | Active on VM105 and VM108 |
| Storage | ClickHouse primary/standby | VM106 and VM108 |
| Correlation | Stream, batch and aggregation | Active on VM106 |
| Detection content | 448 stream, 137 batch, 580 catalog rules | All enabled |
| Identity | Keycloak | Active, OIDC tested end to end |
| Secrets | Vault | Active on VM107 |
| Vulnerability management | OpenVAS | Healthy container on VM122 |
| Endpoint telemetry | Windows Defender/Sysmon and Windows event channels | Reaching SIEM |
| Linux telemetry | auditd and rsyslog | Present on SIEM and most lab VMs |
| Public-service protection | Fail2ban | Present only on Nextcloud |
| Cases/response | SIEM cases and orchestration | Present in the custom Web control plane |
| VPN/remote access | OpenVPN, reverse SSH, WireGuard | OpenVPN/reverse tunnel active; WireGuard has no current handshake |
| Source control | Private GitHub repository and runners | Runners active on SIEM nodes |

The SIEM currently receives fresh events from the edge, Proxmox, Windows,
SIEM core, OpenClaw, Gamepanel, Pilot, Nextcloud, Navidrome, OpenVAS and
Minecraft sources.

## Gaps and risks

1. VM102 is both router and IDS. Failure or maintenance affects every segment.
2. OPNsense is staged, but production NAT, published services, VPN and the
   complete default-deny inter-zone policy have not yet been promoted.
3. Proxmox firewall reports `disabled/running`; no cluster firewall policy file
   exists.
4. There is one physical Proxmox node. Proxmox HA services cannot provide
   host-level failover without another node.
5. No scheduled Proxmox backup jobs exist. Most critical VMs have no snapshot.
6. No UPS monitoring service is active.
7. WireGuard does not show a current peer handshake.
8. VM130 retains a legacy service address as a migration alias.
9. There is no dedicated EDR/FIM manager for all Linux and Windows endpoints.
10. There is no Zeek/Arkime network metadata or packet-retention layer.
11. There is no dedicated threat-intelligence platform such as MISP/OpenCTI.
12. There is no container image/SBOM scanning or runtime container security.
13. There is no independent infrastructure monitoring stack outside the SIEM.
14. `generic-http-refresh` remains as synthetic raw telemetry and should be
    classified as a health signal rather than an asset/source.
15. Kafka currently uses `PLAINTEXT` transport. Broker/client authentication
    and encryption are still required before treating the `sec` segment as a
    hardened trust boundary.
16. The SIEM health API is green, but the overview and dashboard paths remain
    slow enough to require query/materialization work outside the firewall
    cutover.

## Suricata remediation completed

- AF_PACKET now captures `eth0`, `eth1`, `eth2`, `eth3` and `eth4`.
- `HOME_NET` includes mgmt, legacy aliases, sec, servers/games, lab, users and
  the current VPN ranges.
- Each interface uses one capture thread and a unique AF_PACKET cluster ID.
- ET Open is installed and validated.
- Virtual-NIC checksum and repeated-stream artifacts are suppressed by exact
  SID.
- The informational APT user-agent SID is suppressed because routine package
  updates produced duplicate pre-NAT and post-NAT alerts.
- Expected Telegram traffic from OpenClaw and the edge DNS forwarder is
  suppressed only for their known source addresses.
- Post-change packet counters are non-zero on all five interfaces. A
  steady-state 20-second sample added 2,189 packets with zero new drops.
  `eth0` retains 1,009 cumulative drops from a prior startup/reload burst;
  `eth1-eth4` retain zero.
- EVE events continue to arrive in `siem.events`.

The current deployment remains IDS-only. It does not drop traffic.
It observes traffic that enters or leaves VM102 on each segment. Unicast
east-west traffic between two guests on the same Proxmox bridge does not cross
the router and therefore requires a bridge mirror/TAP feeding a separate
sensor.

## OPNsense staging deployment completed

- VM103 runs OPNsense 26.7.1_1 with 4 vCPU, 8 GB RAM and a 40 GB system disk.
- VM autostart is enabled with startup order 20. VM102 keeps startup order 10
  and remains the production recovery path.
- VirtIO hardware checksum, TSO, LRO and VLAN hardware filtering are disabled
  as required for Netmap IPS.
- Suricata 8.0.6 listens on `vtnet1`, `vtnet2`, `vtnet3`, `vtnet4` and
  `vtnet5`. The isolated management interface `vtnet0` is excluded.
- `HOME_NET` contains all five local segments plus the current VPN ranges.
- Forty-four curated rulesets are active. The configuration validates with
  `suricata -T`.
- The compiled set contains 46,047 active signatures: 45,953 `alert` and 94
  `drop`. Only Feodo Tracker, SSL IP blacklist, ET Drop and ThreatView C2 are
  promoted to `drop`.
- The large SSL fingerprint, ThreatFox and URLhaus rulesets are handled as
  threat-intelligence inputs instead of inline signatures. Loading them inline
  increased Suricata RSS from about 1.5 GB to more than 6 GB without adding a
  proportionate prevention benefit.
- OPNsense security telemetry is forwarded as RFC5424 over TCP to
  `10.20.10.104:1514`.
- Local WebGUI access is direct at `https://192.168.3.103`. It is restricted
  to the operator workstation, the Proxmox VPN transit address and
  `10.10.10.0/24`. The temporary Proxmox Web/SSH proxies are stopped.
- A `10.10.10.0/24` return route points to `192.168.3.101`. Local and
  Proxmox-transit access have been validated; the remote peer has no current
  WireGuard handshake, so a remote end-to-end check is still pending.
- The staging WAN can reach the site gateway and Internet. All `.254`
  interfaces are up and their Netmap counters are non-zero; unsolicited ICMP
  from VM102 is denied by the staged default policy until explicit canary
  rules are installed.
- A configuration backup exists under `/conf/backup` before the IDS/IPS
  changes.

The OPNsense engine is inline-capable and running, but it currently sees only
traffic addressed to VM103, broadcasts and canary traffic because production
hosts still use VM102. Full routed inspection starts only when a canary host
uses a `.254` gateway and later when the `.1` gateway addresses move to
OPNsense.

Same-segment unicast still does not traverse a router. "Suricata on every
segment" covers all routed traffic, not arbitrary L2 east-west traffic. A
Proxmox bridge mirror/TAP and a separate Zeek/Suricata NDR sensor are required
for that remaining visibility gap.

Current SIEM validation after the OPNsense changes:

| Check | Result |
| --- | --- |
| Web login and SSO | HTTP 200, redirect to `/app/dashboards` |
| SIEM overview | healthy, no reported issues |
| Sources | 18 healthy of 18 |
| Collectors | 22 healthy of 22 |
| OPNsense telemetry source | `10.20.10.254`, healthy, 4,853 events observed |
| Host runtime | 15 targets, 0 stale |
| Kafka transport | healthy, three configured brokers |
| Stream correlation | active |
| Incident list API | HTTP 200, about 0.3 seconds in the latest check |
| Overview API | HTTP 200, about 6.7 seconds; optimization still required |
| Transport API | HTTP 200, about 5.1 seconds; optimization still required |

## Relocation continuity boundary

The internal service addresses and gateway addresses are independent of the
site LAN and must remain unchanged:

- gateways: `10.20.10.1`, `10.20.20.1`, `10.20.30.1`, `10.20.40.1`;
- SIEM: `10.20.10.104-108`;
- servers/games: `10.20.20.100`, `10.20.20.120-121` and planned
  `10.20.20.130`;
- lab: `10.20.30.122-126`.

Only the upstream/WAN attachment is site-specific. Service configuration
should use internal FQDNs and OIDC issuer names, not `192.168.1.x` or
`192.168.3.x` literals. Remote recovery should use two outbound paths: the
primary VPN and an independent WireGuard tunnel to a public relay. Add a
cellular or second-ISP gateway group if connectivity during an upstream outage
is required.

A single physical Proxmox host cannot maintain sessions while it is powered
off and transported. The achievable result on the existing hardware is
deterministic recovery with unchanged internal addresses. Continuous stateful
service requires a second powered host at the destination, replicated service
data and two OPNsense nodes with CARP/pfsync.

## Target architecture

```text
                                Internet / site LAN
                                       |
                          +------------+------------+
                          | CARP WAN VIP 192.168.3.102
                          |
             +------------+-------------+-------------+
             |                                          |
     OPNsense-A primary                         OPNsense-B standby
     separate physical host                    separate physical host
     pf + Unbound + VPN                         pf + Unbound + VPN
     Suricata IPS                               Suricata IPS
             |-------- dedicated pfsync/XMLRPC ---------|
             |
       CARP gateway VIPs
       10.20.10.1 / 10.20.20.1 / 10.20.30.1 / 10.20.40.1
             |
     +-------+-------------------+-------------------+----------------+
     |                           |                   |                |
  sec/SIEM                 servers/games           lab             users
     |                           |                   |                |
 Kafka/CH/Web            public services       security tools   workstations
     |                           |                   |
     +---------------------------+-------------------+
                                 |
            OPNsense EVE + mirrored east-west Zeek/Suricata
                         + endpoint data
                                 |
                     Ingest -> Kafka -> processing
                                 |
                    ClickHouse -> correlation -> SOC Web
                                 |
             Cases / SOAR / notifications / threat enrichment
```

Two OPNsense VMs on the same Proxmox host improve upgrade rollback but do not
survive host power loss or physical relocation. Stateful failover requires a
second physical host, identical interface mapping, CARP virtual addresses and a
dedicated pfsync path.

The target separates coverage as follows:

| Traffic | Inspection point |
| --- | --- |
| Internet to internal zones | OPNsense Suricata inline IPS |
| Inter-segment routed traffic | OPNsense Suricata inline IPS |
| Same-segment east-west traffic | Proxmox bridge mirror/TAP to dedicated NDR sensor |
| Host-local activity | Windows/Linux EDR, Sysmon, auditd and FIM |

## OPNsense cutover plan

### Phase 0: recovery prerequisites

1. Configure Proxmox Backup Server or scheduled `vzdump` to separate storage.
2. Test restore of VM102 and one SIEM VM.
3. Export the current nftables, routing, Unbound, VPN and port-forward state.
4. Add UPS/NUT shutdown coordination.
5. Confirm local Proxmox console access and an out-of-band recovery path.

### Phase 1: parallel OPNsense deployment

Completed:

1. VMID `103` is deployed with one isolated management interface and five
   VirtIO data interfaces mapped to `vmbr0-4`.
2. Temporary addresses are active:
   - isolated management: `172.31.255.2/30`
   - WAN/mgmt: `192.168.3.103`
   - sec: `10.20.10.254`
   - servers/games: `10.20.20.254`
   - lab: `10.20.30.254`
   - users: `10.20.40.254`
3. Netmap IPS, curated ET Open content and SIEM RFC5424 forwarding are active.
4. No production gateway has changed.

Still required before promotion:

1. Recreate aliases, stateful firewall policy, NAT, published ports, Unbound
   and VPN without changing any production gateway.
2. Apply a default-deny inter-zone policy:
   - `mgmt` reaches only hypervisor, firewall and approved administration
     endpoints;
   - `users` reaches published services and the Internet, not `sec`;
   - `servers/games` receives only explicit published flows and limited
     egress;
   - `lab` is denied to `mgmt` and `sec` except explicit SIEM ingestion;
   - `sec` accepts telemetry and permits named administration flows;
   - VPN access is assigned by identity group, not a flat trusted subnet.

### Phase 2: canary routing

1. Route one test host from each segment through the `.254` gateway.
2. Validate Web, SSO, ingest, Kafka, ClickHouse, source logging and VPN.
3. Run a 500-1500 EPS transport test while OPNsense is in the path.
4. Keep general signatures in alert mode for at least seven days. Retain drops
   only for validated high-confidence IOC feeds and tune by asset group.

### Phase 3: controlled production cutover

1. Freeze configuration and export both firewall configurations.
2. Stop new state on VM102 but keep its console available.
3. Move `192.168.3.102` and all `10.20.x.1` gateway addresses to OPNsense.
4. Run automated health checks from every segment.
5. Keep VM102 powered off but ready for immediate address rollback.

Linux nftables state cannot be synchronized into OPNsense pf state. The first
cutover can preserve all addresses and reconnect automatically, but existing
TCP sessions may reset once. Zero-loss stateful failover is available only
after a two-node OPNsense CARP/pfsync deployment.

### Phase 4: IPS promotion

1. Netmap IPS is already enabled on staging interfaces.
2. Keep general policy actions in alert mode until historical replay and
   canary traffic show acceptable results.
3. Convert additional signatures to `drop` only after verification.
4. Monitor drops, bypasses, latency, CPU and interface errors in SIEM.
5. Maintain emergency disable and console rollback procedures.
6. Mirror Proxmox bridge traffic to the NDR sensor for same-segment coverage;
   do not duplicate mirrored flow telemetry into the hot correlation path.

OPNsense documents that IPS is Suricata-based and requires compatible
interfaces and disabled hardware offloading. See:

- https://docs.opnsense.org/manual/ips.html
- https://docs.opnsense.org/manual/how-tos/carp.html
- https://docs.opnsense.org/manual/hacarp.html
- https://docs.opnsense.org/manual/backups.html

## Additional SOC systems

Priority order:

1. **Backup and recovery:** Proxmox Backup Server on separate storage/host,
   encrypted off-site copy and quarterly restore tests.
2. **Firewall HA:** second physical node, OPNsense CARP/pfsync and separate
   synchronization link.
3. **Endpoint security:** Wazuh agents or an equivalent EDR/FIM layer for all
   Windows and Linux assets, forwarding only enriched findings to this SIEM.
4. **NDR metadata:** Zeek on a dedicated sensor; optionally Arkime for bounded
   packet capture on high-value segments.
5. **Threat intelligence:** MISP or OpenCTI with indicator expiry, confidence
   and source tracking.
6. **Container security:** Trivy/Grype in CI, SBOM generation and Falco for
   selected Docker hosts.
7. **Infrastructure monitoring:** Prometheus, Alertmanager and Grafana outside
   the SIEM data path.
8. **Public-service protection:** HAProxy/Caddy plus Coraza/ModSecurity WAF for
   Nextcloud, Gitea and exposed panels.
9. **Deception:** OpenCanary in an isolated lab VLAN, never sharing credentials
   or management paths with production.
10. **PKI:** internal CA and automated certificate rotation for service-to-
    service TLS.
11. **Secure transport:** Kafka TLS/SASL, service identities and certificate
    rotation for ingest, processing and storage links.

Do not deploy every product simultaneously. Each added platform creates a new
log source, attack surface, storage load and alert family. Introduce one control
per phase, establish ownership and retention, then integrate it into the SIEM.
