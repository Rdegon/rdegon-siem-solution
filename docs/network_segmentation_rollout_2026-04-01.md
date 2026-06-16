# Network Segmentation Rollout: 2026-04-01

## Purpose

This document captures the one-pass live network segmentation rollout completed on `2026-04-01` for the current Proxmox stand.

The goals of this wave were:

- split the estate into dedicated subnets for `SIEM`, `user services`, and `vulnerability / security services`
- keep the existing `192.168.1.0/24` management and household LAN path alive
- move internal service-to-service reachability onto routed internal networks behind `VM102`
- keep remote operator access and recovery access behind the jump-host `OpenVPN` path
- publish the resulting addressing model into the local DNS authority

`VM111 WIN-RTX-test` was intentionally left untouched.

## Resulting Network Model

| Zone | CIDR | Gateway | Primary role |
| --- | --- | --- | --- |
| `mgmt` | `192.168.1.0/24` | household router `192.168.1.1` | existing LAN, Proxmox management, legacy host access |
| `siem` | `10.20.10.0/24` | `10.20.10.1` on `VM102` | dual-homed SIEM nodes and internal control-plane DNS |
| `users` | `10.20.20.0/24` | `10.20.20.1` on `VM102` | single-homed user-facing service VMs / CTs |
| `vuln` | `10.20.30.0/24` | `10.20.30.1` on `VM102` | scanner, pilot, gateway, and security-side service segment |
| `vpn` | `10.66.66.0/24` | jump-host OpenVPN server | remote operator ingress and recovery path |

## Edge / DNS / Access Plane

`VM102 lab-edge-01` is the routed internal edge for the segmented zones:

- `192.168.1.102`
- `10.20.10.1`
- `10.20.20.1`
- `10.20.30.1`

Live services on `VM102` after the rollout:

- `Unbound` local DNS
- `nftables` routing and NAT policy
- `rsyslog` forwarding into SIEM ingest
- `Suricata` IDS still active in the current edge baseline

DNS naming published into `Unbound`:

- internal service names:
  - `siem-ingest.lab.home.arpa`
  - `siem-processing.lab.home.arpa`
  - `siem-storage.lab.home.arpa`
  - `siem-web.lab.home.arpa`
  - `siem-transport.lab.home.arpa`
  - `nextcloud-siem.lab.home.arpa`
  - `navidrome-01.lab.home.arpa`
  - `vuln-mgr-01.lab.home.arpa`
  - `pilot-web-01.lab.home.arpa`
  - `pilot-db-01.lab.home.arpa`
  - `pilot-cache-01.lab.home.arpa`
  - `openclaw-gateway.lab.home.arpa`
- gateway aliases:
  - `siem-gw.lab.home.arpa`
  - `users-gw.lab.home.arpa`
  - `vuln-gw.lab.home.arpa`
- management aliases:
  - `lab-edge-mgmt.lab.home.arpa`
  - `siem-ingest-mgmt.lab.home.arpa`
  - `siem-processing-mgmt.lab.home.arpa`
  - `siem-storage-mgmt.lab.home.arpa`
  - `siem-web-mgmt.lab.home.arpa`
  - `siem-transport-mgmt.lab.home.arpa`
  - `nextcloud-siem-mgmt.lab.home.arpa`
  - `navidrome-01-mgmt.lab.home.arpa`

Remote access model after the rollout:

- jump-host `OpenVPN` remains the primary remote operator ingress
- public SSH on the jump-host is now closed; `22/tcp` is allowed only on `tun-nextcloud` from `10.66.66.0/24`
- `VM107` remains the access-plane client and recovery tunnel origin
- `10.20.10.0/24`, `10.20.20.0/24`, and `10.20.30.0/24` are now advertised on the OpenVPN server with server-side `route` and `iroute`
- the operator split-tunnel route bundle was expanded to include all three segmented subnets

## VM Addressing Map

| VMID | Service | Management IP | Segmented IP | Zone |
| --- | --- | --- | --- | --- |
| `102` | `lab-edge-01` | `192.168.1.102` | `10.20.10.1`, `10.20.20.1`, `10.20.30.1` | edge |
| `104` | `siem-ingest` | `192.168.1.35` | `10.20.10.104` | `siem` |
| `105` | `siem-processing` | `192.168.1.37` | `10.20.10.105` | `siem` |
| `106` | `siem-storage` | `192.168.1.38` | `10.20.10.106` | `siem` |
| `107` | `siem-web` | `192.168.1.39` | `10.20.10.107` | `siem` |
| `108` | `siem-transport` | `192.168.1.40` | `10.20.10.108` | `siem` |
| `120` | `nextcloud-siem` | none | `10.20.20.120` | `users` |
| `121` | `navidrome-01` | none | `10.20.20.121` | `users` |
| `122` | `vuln-mgr-01` | none | `10.20.30.122` | `vuln` |
| `123` | `pilot-web-01` | none | `10.20.30.123` | `vuln` |
| `124` | `pilot-db-01` | none | `10.20.30.124` | `vuln` |
| `125` | `pilot-cache-01` | none | `10.20.30.125` | `vuln` |
| `126` | `openclaw-gateway` | none | `10.20.30.126` | `vuln` |
| `111` | `WIN-RTX-test` | unchanged | unchanged | out of scope |

## Live Changes Applied

### Proxmox

- created internal bridges:
  - `vmbr2` for `10.20.10.0/24`
  - `vmbr3` for `10.20.20.0/24`
- attached secondary NICs on:
  - `VM102`
  - `VM104-108`
  - `CT120-121`

### Guest networking

- `VM102` now routes all three internal segments
- `VM104-108` are dual-homed:
  - existing `192.168.1.x`
  - new `10.20.10.x`
- `CT120-121` were initially dual-homed for the cutover and then finalized as single-homed `10.20.20.x` services
- `VM122-126` stayed on `10.20.30.x`

### Routing

- `VM104-108` route `10.20.20.0/24` and `10.20.30.0/24` through `10.20.10.1`
- `CT120-121` now default-route and resolve DNS only through `10.20.20.1`
- `VM107` now NATs and forwards VPN traffic to:
  - `192.168.1.0/24`
  - `10.20.10.0/24`
  - `10.20.20.0/24`
  - `10.20.30.0/24`

### OpenVPN

- jump-host server now knows:
  - `10.20.10.0/24`
  - `10.20.20.0/24`
  - `10.20.30.0/24`
- `ccd/home-gateway-vm4` now carries `iroute` entries for all segmented subnets
- route push for the lab subnets was intentionally not expanded globally, because that would create conflicting routes on non-gateway clients; the operator route bundle is the supported client-side access path

## Validation Snapshot

Validated during the rollout:

- `VM102` listens on DNS `53/udp` and `53/tcp` on:
  - `192.168.1.102`
  - `10.20.10.1`
  - `10.20.20.1`
  - `10.20.30.1`
- `VM102` resolves:
  - `siem-web.lab.home.arpa -> 10.20.10.107`
  - `nextcloud-siem.lab.home.arpa -> 10.20.20.120`
  - `openclaw-gateway.lab.home.arpa -> 10.20.30.126`
- `VM104-108` all brought up `10.20.10.x` addresses
- `CT120-121` now expose only `10.20.20.120` and `10.20.20.121`, and both resolve `lab.home.arpa`
- `VM107` OpenVPN client and `siem-jump-tunnels` are active after the route-script rewrite
- recovery reverse tunnels `22120` and `22121` now target `10.20.20.120` and `10.20.20.121`
- `VM105` was restarted on the VPN client after the server-side route cleanup and no longer carries the stale `10.20.30.0/24 via tun-home` route
- jump-host OpenVPN server stayed healthy after reloading the segmentation-aware config

## SIEM Log Recovery

During the same wave, SIEM event flow dropped to `0 logs/hour` because `VM106` storage crashed and stayed wedged:

- `clickhouse-server` on `VM106` crashed with `SIGSEGV`
- Ubuntu `apport` consumed almost all guest RAM while processing the crash dump
- `siem-writer`, `siem-stream-corr`, `siem-batch-corr`, and `siem-alert-agg` stopped making forward progress
- `VM105` normalizer and filter workers kept flapping because `192.168.1.38:9000` refused connections

Recovery applied on `2026-04-01`:

- disabled `apport` on `VM106`
- disabled Proxmox memory ballooning on `VM106` by setting `balloon=0`
- rebooted `VM106`
- restarted `clickhouse-server`, `siem-writer`, `siem-writer-shadow`, `siem-stream-corr`, `siem-batch-corr`, and `siem-alert-agg`

Validation after recovery:

- `VM106` returned to healthy service state
- `VM105` normalizer and filter workers resumed stable processing
- `siem.events` advanced again with fresh inserts
- the last validated live bucket after recovery showed `38,716` events in the current minute on `VM106`

## Important Limits And External Dependencies

What is guaranteed after this rollout:

- every segmented service is reachable from the platform and from remote operators through the jump-host `OpenVPN` path
- SIEM nodes still remain reachable on their old `192.168.1.x` management addresses
- non-SIEM user services `CT120-121` are now intentionally `10.20.20.x` only
- vulnerability-side services are reachable through:
  - segmented routing inside the stand
  - `OpenVPN`
  - recovery reverse SSH tunnels

What was not automated in this pass:

- the household router at `192.168.1.1` was not reconfigured from this repo
- because of that, arbitrary LAN clients on `192.168.1.0/24` do not automatically receive:
  - static routes for `10.20.10.0/24`, `10.20.20.0/24`, `10.20.30.0/24`
  - DNS forwarding for `lab.home.arpa`

Operational consequence:

- the supported access path to every machine is `OpenVPN` through the jump-host
- for direct non-VPN LAN access to the segmented IPs from arbitrary household clients, add on the upstream router:
  - static route `10.20.10.0/24 -> 192.168.1.102`
  - static route `10.20.20.0/24 -> 192.168.1.102`
  - static route `10.20.30.0/24 -> 192.168.1.102`
  - conditional DNS forward `lab.home.arpa -> 192.168.1.102`

## Follow-Up Hardening

Recommended next hardening steps, after stable burn-in:

1. add upstream-router static routes and conditional DNS forward for direct `192.168.1.x -> 10.20.x.x` reachability without VPN
2. extend `Suricata` inspection policy from the current edge baseline to explicit multi-interface capture and tuned detection on all three internal segments
3. gradually move SIEM internal service endpoints from `192.168.1.x` references to `10.20.10.x` service names where safe
