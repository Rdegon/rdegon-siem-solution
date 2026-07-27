# SIEM segmented-network cutover

Date: 2026-07-25

## Deployed topology

| Role | Address | Use |
| --- | --- | --- |
| Operator workstation | `192.168.3.81` | Browser and local administration |
| Proxmox | `192.168.3.101` | Hypervisor management |
| `lab-edge-01` management | `192.168.3.102` | Published Web, SSO and ingest entry point |
| `lab-edge-01` sec gateway | `10.20.10.1` | SIEM-core routing |
| `siem-ingest` | `10.20.10.104` | Ingest and Kafka broker |
| `siem-processing` | `10.20.10.105` | Normalize/filter and Kafka broker |
| `siem-storage` | `10.20.10.106` | Primary ClickHouse |
| `siem-web` | `10.20.10.107` | Web/API, Keycloak, PostgreSQL and MongoDB |
| `siem-transport` | `10.20.10.108` | Kafka broker and standby ClickHouse |

The active router is Ubuntu 24.04 on VM102 with nftables and Unbound. It is
`lab-edge-01`, not OPNsense. The inspected detached VM102 disk is empty, and no
OPNsense image, configuration backup or snapshot exists on the Proxmox host.
Deploying OPNsense therefore requires a separate planned installation and
cutover; it must not be assumed to be the current firewall.

## Communication contract

- Browser and demonstration URL: `https://192.168.3.102`
- OIDC issuer and Keycloak public hostname:
  `https://192.168.3.102/realms/siem`
- Public collector entry point: `https://192.168.3.102:8443`
- Velociraptor endpoint entry point: `https://192.168.3.102:8000`
- Web-to-ingest: `https://10.20.10.104`
- Kafka bootstrap:
  `10.20.10.104:9092,10.20.10.105:9092,10.20.10.108:9092`
- Kafka quorum:
  `1@10.20.10.104:9093,2@10.20.10.105:9093,3@10.20.10.108:9093`
- ClickHouse primary/standby: `10.20.10.106`, `10.20.10.108`
- MongoDB replica members: `10.20.10.104`, `10.20.10.107`,
  `10.20.10.108`
- Keycloak backchannel from Web: `http://127.0.0.1:8081`

Addresses `192.168.1.35`, `.37`, `.38`, `.39` and `.40` remain temporary `/32`
rollback aliases. Runtime service discovery, agents, Web APIs and database
members must not use them.

## Operator workstation routes

The DurevVPN adapter installs a lower-metric default route. Without explicit
routes, direct access to `10.20.x` is sent to that adapter instead of
`lab-edge-01`.

Open PowerShell as Administrator and run:

```powershell
Set-Location C:\Users\Rdegon\Projects\siem-solution-clean
.\deploy\network_relocation\install_windows_segment_routes.ps1
```

The script installs persistent `/24` routes for `sec`, `servers/games`, `lab`
and `users` through `192.168.3.102`. Remove only those routes with:

```powershell
.\deploy\network_relocation\install_windows_segment_routes.ps1 -Remove
```

The current Codex process was not elevated, so this is the only cutover step
that could not be applied automatically.

## Applied migration

- Kafka listeners, advertised listeners and quorum voters moved to `sec`.
- ClickHouse listeners and Web failover endpoints moved to `sec`.
- MongoDB bind addresses, replica-set members and Vault URI moved to `sec`.
- Web, OIDC and Keycloak public URLs moved to `192.168.3.102`.
- Keycloak client `siem-web` redirect URI, web origin, root URL and base URL
  moved to `https://192.168.3.102`; the migration is reproducible with
  `deploy/network_relocation/migrate_keycloak_public_endpoint.sh`.
- Web uses Keycloak loopback for backchannel discovery and token exchange,
  avoiding NAT hairpin dependency.
- Linux rsyslog sources moved to `10.20.10.104`; no active source connection
  remains on `192.168.1.35`.
- Reverse-SSH operator and remote-collector ports keep their external port
  numbers, while their internal targets now use `10.20.10.104-108` and
  `192.168.3.102`; the live tunnel command contains no `192.168.1.x` target.
- Windows collector defaults and remote VPN profiles publish through
  `192.168.3.102:8443`.
- Ingest TLS contains SANs for `10.20.10.104`, `192.168.3.102` and the
  temporary legacy address.

Runtime configuration backups were created under
`/root/siem-ip-cutover-20260725T185242` on SIEM nodes. Source rsyslog backups
use `/root/siem-rsyslog-cutover-*`.

## Validation result

- all SIEM units on VM104-108 active; failed units: `0`
- Kafka brokers/controllers: `3/3`; consumer lag: `0`
- ClickHouse event lag: `0` during validation
- active rules: `448` stream and `137` batch
- source E2E markers received from all Linux service guests
- Windows Security, Sysmon, PowerShell, Task Scheduler, WMI and WinRM events
  received after the cutover
- `/api/ingest/overview`, `/api/platform/status`, `/api/sources`,
  `/api/assets/inventory`, incident list and incident detail return `200`
- API payloads and browser requests contain no legacy SIEM-core URL
- Keycloak status healthy; OIDC authorization redirects to `192.168.3.102`
- full OIDC login and callback tested with the `admin` principal; its explicit
  SIEM admin grant is enabled for all current sections and group sync is
  `mirrored`
- Dashboard summary returns `200`; shared-cache responses measured 31-36 ms
- incident detail cold request reduced from about 15 seconds to 2.0 seconds;
  subsequent uncached cards measured 0.52-0.56 seconds

The incident improvement bounds evidence scans around first/last activity,
uses one priority query for command evidence, and removes schema DDL from the
read path. Incident schema remains managed by
`sql/11_event_schema_enrichment.sql`.

## Quick verification

```powershell
curl.exe -k https://192.168.3.102/
curl.exe -k https://192.168.3.102:8443/health
Test-NetConnection 192.168.3.101 -Port 8006
Test-NetConnection 192.168.3.102 -Port 443
```

After installing the workstation routes:

```powershell
Test-NetConnection 10.20.10.104 -Port 443
Test-NetConnection 10.20.10.106 -Port 8123
Test-NetConnection 10.20.10.107 -Port 443
```
