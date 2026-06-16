# VM Access Guide

## Purpose

This document explains how to connect to each lab VM directly from the LAN or through the jump host.

Sensitive values are not duplicated here. Use:

- `C:\Users\Rdegon\Projects\siem_xfer_2026-03-25\access\operator_docs\SYSTEM_ACCESS_MATRIX.md`
- `C:\Users\Rdegon\Projects\siem_xfer_2026-03-25\access\operator_docs\OPERATOR_ACCESS_BUNDLE.md`

## Role Separation

- `176.108.250.215` is the public jump host for access into the home lab
- `45.89.111.208` is the outbound VLESS host and is not the management entry point

## VM Inventory

| VM | IP | Role |
| --- | --- | --- |
| `VM1` | `192.168.1.35` | ingest, syslog and HTTP collectors |
| `VM2` | `192.168.1.37` | Kafka processing, normalizer, filter |
| `VM3` | `192.168.1.38` | ClickHouse primary, writer, correlation |
| `VM4` | `192.168.1.39` | web UI, API, Postgres, Mongo, access plane |
| `VM5` | `192.168.1.40` | Kafka transport, standby processing, standby storage |

## Direct LAN Access

Use direct SSH on the home LAN:

```bash
ssh rdegon@192.168.1.35
ssh rdegon@192.168.1.37
ssh rdegon@192.168.1.38
ssh rdegon@192.168.1.39
ssh rdegon@192.168.1.40
```

Primary web URLs:

- `https://192.168.1.35/health`
- `https://192.168.1.39`
- `https://192.168.1.39/app`

## Jump-Host Reverse Tunnels

`VM4` maintains reverse tunnels through `siem-jump-tunnels` over the `home-gateway` OpenVPN path.

Documented operational forwards:

- `127.0.0.1:20035` -> `192.168.1.35:22`
- `127.0.0.1:20037` -> `192.168.1.37:22`
- `127.0.0.1:20038` -> `192.168.1.38:22`
- `127.0.0.1:20039` -> `192.168.1.39:22`
- `127.0.0.1:20435` -> `192.168.1.35:443`
- `127.0.0.1:20439` -> `192.168.1.39:443`
- `127.0.0.1:20121` -> `192.168.1.121:22`

The `20121` mapping is the vulnerability-scanner reverse tunnel and is part of the supported operator entry points.

## Remote Access Examples

Web UI through the jump host:

```bash
ssh -L 8443:127.0.0.1:20439 vpnadmin_rdegon@176.108.250.215
```

Ingest health through the jump host:

```bash
ssh -L 8435:127.0.0.1:20435 vpnadmin_rdegon@176.108.250.215
```

Scanner SSH through the jump host:

```bash
ssh -L 20121:127.0.0.1:20121 vpnadmin_rdegon@176.108.250.215
ssh -p 20121 scanneradmin@127.0.0.1
```

## Access-Plane Note

`openvpn-client@home-gateway` and `siem-jump-tunnels` are both mandatory green-state services on `VM4`. If either is unhealthy, treat it as an access-plane incident.
