# Collectors And Source Families

## What Counts As A Collector

A collector is the ingest and transport profile that:

- listens on a concrete port or HTTP endpoint
- accepts a concrete payload family
- routes data into the correct transport path
- is associated with one or more source families

A collector is not the same thing as a source:

- `source` is the telemetry emitter
- `collector` is the transport and parsing path

## Current Collector Profiles

### Syslog/TCP

| Port | Collector profile | Source family |
| --- | --- | --- |
| `1514` | `linux-auth` | Linux auth and syslog |
| `1515` | `linux-audit` | Linux auditd |
| `1516` | `network` | Network and Cisco |
| `1517` | `vpn` | VPN syslog |
| `1518` | `app` | Application and service syslog |

### HTTPS / JSON

| Port | Collector profile | Source family |
| --- | --- | --- |
| `9440` | `windows-base-http` | Windows base |
| `9441` | `windows-security-http` | Windows Security |
| `9442` | `windows-sysmon-http` | Windows Sysmon |
| `9443` | `windows-powershell-http` | Windows PowerShell |
| `9444` | `app-json-http` | Generic application JSON |
| `9445` | `vulnscanner-http` | Vulnerability import |
| `9446` | `vpn-json-http` | VPN JSON and API |

## Adding A Collector

1. choose protocol, source family, and collector profile
2. add the port or route in the ingest layer
3. update ingest config and routing metadata
4. document the expected schema
5. expose the collector through health and inventory surfaces
6. add smoke coverage

## Removal Order

1. stop onboarding new sources to the collector
2. migrate existing sources
3. remove listener and env/config references
4. remove UI metadata
5. verify inventory and health surfaces no longer reference the retired collector

## End-To-End Verification

Check:

- `systemctl is-active siem-ingest`
- `ss -ltnp`
- `/api/sources`
- `/api/collectors`
- `/api/events/query`
- `/api/ingest/overview`

## Design Rules

- one collector profile should represent one clear transport role
- do not mix unrelated source families without an explicit reason
- each collector change must include docs, config, health, and smoke coverage
