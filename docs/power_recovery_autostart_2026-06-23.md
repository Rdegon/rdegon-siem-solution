# Power recovery autostart runbook

Date: 2026-06-23

## Proxmox autostart

`pve-guests.service` is enabled and active. All production VM/LXC guests are set to `onboot=1`.

Startup order:

| Order | Guest | Purpose |
| --- | --- | --- |
| 10 | `102 lab-edge-01` | router, DNS, firewall |
| 20 | `106 SIEM-Storage` | ClickHouse, writers, correlation |
| 30 | `105 SIEM-Processing` | Kafka, normalizer, filter |
| 35 | `108 SIEM-Transport` | transport/standby workers |
| 40 | `104 SIEM-Ingest` | ingest API and collectors entry |
| 50 | `107 SIEM-WEB` | Web UI, API, Vault, Keycloak |
| 60-64 | `124`, `125`, `123`, `122`, `126` | pilot DB/cache/web, vuln, OpenClaw |
| 70-71 | `120`, `121` | Nextcloud, Navidrome |
| 80-81 | `130`, `100` | Gamepanel/Wings, Minecraft |
| 90-91 | `101`, `111` | Windows sources, including `WIN-RTX-test` |

## Service autostart fixes

- `gamepanel-01`: `ssh.service` was running but disabled; it is now enabled.
- `siem-ingest`, `siem-web`, `pilot-db-01`: `postgresql@14-main.service` was made persistent `enabled` in addition to the parent `postgresql.service`.
- `gamepanel-01`: `wings.service` PIDFile path was updated from `/var/run/wings/daemon.pid` to `/run/wings/daemon.pid` to remove systemd boot/reload warnings.

## Current validation

- Proxmox storage: all storages active.
- Proxmox failed units: `0`.
- VM/LXC state: all listed guests running.
- HTTP checks:
  - `https://192.168.1.35/health` -> `200`
  - `https://192.168.1.39/` -> `307`
  - `https://10.20.20.120/` -> `302`
  - `http://10.20.20.121/` -> `302`
  - `http://192.168.1.30/` -> `200`
  - `http://192.168.1.32:8111/` -> `401`
- SIEM events: `siem.events` had more than 5k events in the last 10 minutes during validation.
- Windows source `WIN-RTX-test`: `RdegonSIEMCollector` scheduled task is active and sending events to Ingest; Sysmon is running and automatic.

## Post-power-on checks

Run on Proxmox after power returns:

```bash
systemctl --failed --no-pager --plain
systemctl is-active pve-guests
systemctl is-enabled pve-guests
qm list
pct list
pvesm status
curl -k -m 5 -s -o /dev/null -w '%{http_code}\n' https://192.168.1.35/health
curl -k -m 5 -s -o /dev/null -w '%{http_code}\n' https://192.168.1.39/
```

Run on `SIEM-Storage`:

```bash
clickhouse-client --query "SELECT count(), max(ts) FROM siem.events WHERE ts >= now() - INTERVAL 10 MINUTE"
```
