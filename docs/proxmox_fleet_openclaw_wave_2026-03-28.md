# Proxmox Fleet, OpenClaw, and Vulnerability Coverage Wave: 2026-03-28

## Purpose

This document records the `March 28, 2026` post-closure expansion wave that extended the already-green stand with:

- Proxmox-backed fleet inventory inside SIEM
- OpenClaw full-metadata monitoring
- OpenVAS-first vulnerability coverage for the reachable fleet
- pilot-service deployment and monitoring
- `/app/*` fleet-oriented operator surfaces

This wave did not reopen any closure slab. It is a post-closure expansion executed on the live stand.

## Scope Landed

- `Proxmox` remains `monitored-only`, not an SSO target
- all live guests returned by the hypervisor inventory are now tracked in SIEM fleet state
- `OpenClaw` is now a first-class monitored source and asset
- `OpenVAS` remains the primary operator-facing vulnerability source
- `Nmap` remains queryable and retained, but is visually and operationally secondary
- `pilot-web-01` runs `Gitea`
- `pilot-db-01` runs `PostgreSQL`
- `pilot-cache-01` runs `Valkey`
- former `vuln-siem` now runs `Navidrome` and is represented as `navidrome-01`
- `/app/sources?view=fleet` and `/app/vuln` now show fleet-oriented coverage and status

## Live Fleet Metrics

Authenticated runtime checks on `https://192.168.1.39` after the wave completed returned:

- fleet total: `15`
- running guests: `14`
- connected guests: `13`
- reachable guests: `12`
- OpenVAS-scannable guests: `12`
- inventory-only guests: `1`
- offline guests: `1`
- operating system mix:
  - `linux=12`
  - `windows=2`
  - `bsd=1`

Latest live fleet coverage returned by `/api/vuln/runtime?days=14`:

- total guests: `15`
- reachable guests: `12`
- scannable guests: `12`
- recently scanned guests: `12`
- offline guests: `1`
- unresolved guests: `3`
- last successful import: `2026-03-28 03:42:55`

## Proxmox-Backed Inventory

The new fleet runtime and API layer are implemented through:

- `proxmox_fleet_runtime.py`
- `console_assets_routes.py`

Supported API surfaces:

- `GET /api/sources/proxmox-fleet`
- `POST /api/sources/proxmox-fleet/sync`

Fleet state is explicit and never silently hides unresolved nodes:

- `connected`
- `onboardable`
- `scan-only`
- `inventory-only`
- `offline`
- `unsupported`

The live hypervisor-backed scope for this wave included:

- core SIEM nodes
- `nextcloud-siem`
- `navidrome-01`
- `vuln-mgr-01`
- `pilot-web-01`
- `pilot-db-01`
- `pilot-cache-01`
- `openclaw-gateway`
- `WIN-RTX-test`
- `BSDRP-internal`

## OpenClaw Monitoring Model

`openclaw-gateway` is now monitored as a dedicated fleet asset and source family.

### System-Action Telemetry

The live node now emits:

- `auditd` syscall and file-watch events for:
  - process execution
  - service and unit changes
  - OpenClaw binary and config paths
  - connect/send syscalls for the OpenClaw service user
- journald and rsyslog-shipped service logs for:
  - `openclaw-gateway.service`
  - `openclaw-vless.service`
  - `systemd-resolved`

### Network Metadata Telemetry

The wave captures full network metadata without TLS interception:

- DNS request / cache activity from `systemd-resolved`
- outbound flow-related syscall metadata from `auditd`
- kernel-level firewall observations
- source asset / source IP / process context enrichment in SIEM

What is explicitly not introduced:

- no HTTPS/TLS man-in-the-middle
- no full packet capture
- no content interception of encrypted sessions

### Live Proof

Fresh OpenClaw DNS activity was forced after the live parser deploy and then confirmed through `/api/events/query`.

Fresh normalized events were present with:

- `category=network`
- `subcategory=linux_dns_query`
- `event_action=dns_query`
- `log_source=openclaw-gateway`
- sample domain: `api.telegram.org`

The parser fix that made this live proof possible was applied to the actual normalizer service runtime:

- `services/normalizer/normalizer_core.py`
- `tests/test_service_normalizer_core.py`

The file was then synchronized directly to the live normalizer workers on:

- `VM2`
- `VM5`

## Correlation Packs Landed

This wave added and published four operational rule packs:

- `correlation_rule_packs/fleet_observability_v1.json`
- `correlation_rule_packs/openclaw_behavior_v1.json`
- `correlation_rule_packs/vuln_coverage_v1.json`
- `correlation_rule_packs/pilot_services_v1.json`

Publishing is now handled by:

- `deploy/publish_operational_rule_packs.py`

These packs focus on:

- missing or stale fleet telemetry
- repeated service restarts and onboarding degradation
- OpenClaw outbound-behavior anomalies and config/service changes
- vulnerability coverage gaps and report-import failures
- pilot-service degradation and restart/auth failure patterns

Noise-control policy for this wave:

- suppression keys use `host + service + rule family`
- repeated audit/log bursts are rolled up
- single transient self-healing events are de-escalated
- maintenance and scan windows suppress false positives
- memory noise remains tied to real pressure, not raw cache-heavy `used RAM`

## Vulnerability Coverage

`OpenVAS` now builds targets from the Proxmox-backed fleet inventory rather than from a manually curated subset.

Operator-facing vulnerability surfaces now emphasize:

- scannable fleet
- recently scanned fleet
- unresolved or offline fleet
- critical exposure queue
- unmapped target queue

The live structured-import loop is green after the final fixes in:

- `vuln_store.py`
- `deploy/vm4_enterprise_foundation_deploy.py`

The critical runtime fixes were:

- avoiding the ClickHouse aggregation alias collision in `_load_previous_latest_findings()`
- preparing writable runtime artifact directories for `siem-greenbone-sync.service` on `VM4`

`Greenbone/OpenVAS` native UI SSO remains unsupported on the current build. Scanner integration is live; UI-native SSO is not.

## Pilot Services

The pilot-service bundle deployed in this wave is:

- `pilot-web-01` -> `Gitea`
- `pilot-db-01` -> `PostgreSQL`
- `pilot-cache-01` -> `Valkey`
- `vuln-siem` -> `Navidrome` as `navidrome-01`

Each of these services is now covered through:

- host runtime
- service health
- service logs
- inventory and asset presence
- OpenVAS target coverage where reachable

## Live Rollout And Verification

Successful live commands and waves in this pass:

- `deploy/proxmox_fleet_wave_deploy.py`
- `deploy/proxmox_fleet_wave_smoke.py`
- `deploy/host_runtime_wave_smoke.py`
- `deploy/vm4_enterprise_foundation_smoke.py`

## Vulnerability Operator Flow Closure

The same live wave also closed the broken operator path on `/app/vuln`.

### Root Cause Of The `403`

The `Vulnerability sync failed / Request failed: 403` error was caused by the SIEM authorization layer itself.

Before the fix:

- `POST /api/vuln/sync`
- `POST /api/vuln/import`
- `POST /api/vuln/policies/apply`

were guarded by `resources:write`.

That did not match the actual section model for `Vulnerability`, where operator roles already had visibility but not the unrelated `resources:write` permission. The result was a live UI that rendered the section, but rejected scanner actions with `403`.

### Runtime Fix

The operator permission model now uses a dedicated capability:

- `vuln:operate`

The permission is granted to:

- `admin`
- `analyst`

and intentionally not granted to:

- `viewer`

The live code paths updated for this were:

- `security.py`
- `control_plane_access_ops.py`
- `console_docs_routes.py`
- `frontend-react/src/shell/App.tsx`
- `frontend-react/src/shell/context.tsx`
- `frontend-react/src/shell/pages/VulnPage.tsx`
- `frontend-react/src/shell/types.ts`

The `/api/ui/bootstrap` payload now exposes the effective permission set, and `/app/vuln` uses that state to render operator actions honestly instead of showing buttons that are guaranteed to fail.

### Live Greenbone/OpenVAS Path

After the permission fix, the remaining live scanner path was verified and corrected until the whole chain became green:

- probe from `VM4` to `vuln-mgr-01`
- target sync
- structured report import
- policy application
- display in `/api/reports`
- display in `/api/vuln/runtime`
- display in `/api/vuln/maturity`
- display in `/app/vuln`

The final structured-data fix was landed in:

- `vuln_store.py`
- `vuln_runtime.py`

This restored the intended behavior:

- `OpenVAS / Greenbone` is the authoritative operator-facing scanner
- `Nmap` remains supplemental
- `/api/reports` prefers structured Greenbone data instead of falling back to raw secondary evidence

Live runtime after the fix:

- `probe.status=ok`
- `probe.authenticated=true`
- `scanner_family_breakdown.greenbone=37`
- `fleet_coverage.total_guests=15`
- `fleet_coverage.reachable_guests=12`
- `fleet_coverage.scannable_guests=12`
- `fleet_coverage.recently_scanned_guests=12`
- `fleet_coverage.offline_guests=1`
- `fleet_coverage.unresolved_guests=3`

## Nmap Cadence And Role

`Nmap` was reduced to a clearly secondary role in this wave.

Operational changes:

- timer cadence reduced to `3h`
- target set limited to exposure-relevant hosts rather than the whole fleet
- UI/report ordering keeps `OpenVAS / Greenbone` above `Nmap`

Relevant rollout files:

- `deploy/vuln/rdegon-vuln-scan.timer`
- `deploy/vuln/rdegon-vuln-scan.service`
- `deploy/proxmox_fleet_wave_deploy.py`
- `deploy/proxmox_fleet_wave_smoke.py`

## Fresh Screenshot Set

Fresh live screenshots for this wave were captured only after:

- `VM1` ingest smoke was green
- `VM4` enterprise-foundation smoke was green
- `/api/health/overview` returned `issues=[]`
- `/api/vuln/runtime` returned healthy scanner state

Artifacts:

- `../.artifacts/browser/live-vuln-fleet-ui-2026-03-28/overview.png`
- `../.artifacts/browser/live-vuln-fleet-ui-2026-03-28/sources-fleet.png`
- `../.artifacts/browser/live-vuln-fleet-ui-2026-03-28/vuln.png`
- `../.artifacts/browser/live-vuln-fleet-ui-2026-03-28/events.png`
- `../.artifacts/browser/live-vuln-fleet-ui-2026-03-28/assets.png`
- `../.artifacts/browser/live-vuln-fleet-ui-2026-03-28/access.png`
- `../.artifacts/browser/live-vuln-fleet-ui-2026-03-28/entities.png`
- `../.artifacts/browser/live-vuln-fleet-ui-2026-03-28/console.txt`

These captures show the live shell after the vulnerability, fleet, and OpenClaw wave, not an older reused evidence set.
- `frontend-react/tools/verify_app_ui.py --live`

Final green proofs from this wave:

- `vm4_enterprise_foundation_smoke.py` -> `smoke=success`
- `proxmox_fleet_wave_smoke.py` -> `smoke=success`
- `host_runtime_wave_smoke.py` -> `smoke=success`
- `console_errors=[]`
- `page_errors=[]`

## Browser Artifacts

The live browser bundle for this wave is:

- `../.artifacts/browser/live-proxmox-openclaw-wave/results.json`
- `../.artifacts/browser/live-proxmox-openclaw-wave/overview.png`
- `../.artifacts/browser/live-proxmox-openclaw-wave/sources-fleet.png`
- `../.artifacts/browser/live-proxmox-openclaw-wave/vuln.png`
- `../.artifacts/browser/live-proxmox-openclaw-wave/events.png`
- `../.artifacts/browser/live-proxmox-openclaw-wave/assets.png`
- `../.artifacts/browser/live-proxmox-openclaw-wave/entities.png`
- `../.artifacts/browser/live-proxmox-openclaw-wave/threat-intel.png`

## Result

The stand now has a live Proxmox-backed fleet model, OpenClaw full-metadata monitoring, OpenVAS-first fleet vulnerability coverage, pilot-service observability, and refreshed `/app/*` evidence for the expanded operator surface.

This is post-closure expansion work on top of an already-closed core system, not a reopened slab.
