# Production-Green Remediation 2026-03-26

## Summary

This pass converted the stand from a mixed `yellow/red` operating state into a production-green baseline and synchronized code, deploy logic, runtime health, and operator documentation.

No breaking API removals or path renames were introduced.

## Before

Observed pre-remediation issues:

- Kafka shadow pipeline missing
- ingest DLQ backlog and parser backlog were non-zero
- host-runtime health stale for all five monitored nodes
- backup readiness reported a false-red for stream-state SQLite
- Postgres standby lag surfaced false-red on idle standby state
- runner ownership drift existed between `VM2` and `VM5`
- `openvpn-client@home-gateway` was failed on `VM4`
- structured vulnerability maturity was only partially operational
- `/api/reports` raw report fallback missed `artifact_link`
- live API inventory and engineering docs had drift
- exportable env snapshots contained raw secrets

## Implemented Changes

### Transport And Ingest

- restored Kafka shadow readiness and made shadow health part of green-state evaluation
- drained and resolved DLQ and parser backlog handling
- fixed health logic so cleared backlog no longer leaves the stand red due to cumulative historical counters

### Host Runtime

- completed host-runtime delivery and freshness validation for all five Linux nodes
- aligned stale-target logic with actual target inventory and timestamps

### Storage HA And Backups

- corrected SQLite backup readiness evaluation to use the real source node and path
- fixed Postgres standby lag evaluation for idle but synchronized standbys
- aligned backup and HA gates with actual topology state

### Runner And Access Plane

- restored canonical runner ownership for `siem-vm2` and `siem-vm5`
- enforced access-plane health on `VM4`
- brought `openvpn-client@home-gateway` and `siem-jump-tunnels` into the mandatory green path

### Vulnerability Maturity

- completed the structured vulnerability runtime path
- added scheduled policy execution through node-local timer/service
- made `/api/vuln/maturity` reflect operational readiness instead of current critical-finding presence
- added `artifact_link` to the raw-report fallback path

### Windows Slice

- imported the native Windows Event Agent source tree into `windows-event-agent/`
- imported packaging and install scripts into `deploy/windows-agent/`
- imported the example operator profile into `ops/windows-agent-profile.local.example.json`
- updated packaging defaults so the imported source path is buildable from the repo

### Documentation And Exports

- repaired key docs with stale root paths
- repaired encoding-damaged collector and vulnerability contract docs
- synchronized endpoint documentation with the live OpenAPI surface
- documented previously live-but-undocumented reverse tunnel access for the vulnerability scanner

## Live Green Evidence

Validated healthy after remediation:

- `/api/health/overview`
- `/api/health/transport`
- `/api/health/backups`
- `/api/health/storage-ha`
- `/api/health/hosts/runtime`
- `/api/vuln/runtime`
- `/api/vuln/maturity`
- `/api/reports`

Validated smoke paths:

- `deploy/vm4_enterprise_foundation_smoke.py`
- `deploy/vm5_transport_wave_smoke.py`
- `deploy/storage_ha_wave_smoke.py`
- `deploy/host_runtime_wave_smoke.py`
- `deploy/kafka_shadow_wave_smoke.py`
- `deploy/homelab_watchdog.py`

## Secret Hygiene

- local git remote configuration was cleaned so `.git/config` no longer carries an embedded PAT
- raw secret-bearing env snapshot material was removed from the general export path and restricted to approved operator/runtime locations

## Operator Outputs

The current machine-local exports are produced by:

- `deploy/export_siem_docs.py`
- `deploy/export_clean_project_bundle.py`
- `deploy/publish_runtime_docs.py`

These outputs now align with the current repo baseline instead of the retired `remote-edit2` workspace references.
