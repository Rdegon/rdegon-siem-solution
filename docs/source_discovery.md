# Source Discovery Plane

The source discovery plane is a new `VM4` runtime slice that helps the operator find unmanaged nodes on the home LAN and turn them into onboarding candidates.

## Purpose

The feature is meant to close a recurring operational gap:

- the platform can already show active sources that are sending telemetry;
- it previously had no first-class way to find hosts that exist on the LAN but are not yet connected to SIEM monitoring.

The discovery plane now fills that gap with candidate-host inventory and onboarding-job preparation.

## Runtime Model

Persistent collections:

- `source_discovery_candidates`
- `source_discovery_jobs`

Storage location:

- `SIEM_CONTROL_PLANE_DIR`, if configured
- otherwise `services/web/app/runtime-control-plane/` on the web node

## What A Candidate Contains

Each candidate row stores:

- IP
- reverse-DNS hostname, when available
- open ports
- service hints and banners
- inferred `os_family`
- inferred `probable_role`
- inferred `source_family`
- onboarding recommendation
- `connected` state
- `monitoring_status`
- prepared onboarding job linkage

## Classification Rules

Current heuristics:

- `pveproxy`, `Proxmox`, or port `8006` -> `proxmox`
- `445`, `3389`, `5985`, `5986`, or Microsoft-like signatures -> `windows`
- `161` or syslog-only device behavior -> `network-device`
- `22` -> `linux-host`
- `80`, `443`, `8080`, `8443`, or other web responses -> `web-application`

These are heuristics, not authoritative fingerprinting. The feature is designed to help triage candidate onboarding, not replace a full asset-scanning product.

## Connected Vs Unmanaged

Discovery compares each candidate against the current source inventory from ClickHouse:

- if a host matches an already connected telemetry source, it is marked `connected`
- otherwise it remains an unmanaged candidate

Synthetic smoke emitters are excluded from ingest-health operational totals, so discovery and health no longer get polluted by `vm1-smoke`.

Rescans now also clean up stale onboarding intent:

- if a candidate becomes `connected`, any still-open prepared job for that candidate is marked `superseded`
- connected candidates always render with `monitoring_status=connected`, even if they had an older prepared job

## API Surface

- `GET /api/sources/discovery`
  - current candidate inventory, metrics, and recent onboarding jobs
- `POST /api/sources/discovery/scan`
  - scan a CIDR and refresh the candidate inventory
- `POST /api/sources/discovery/{candidate_id}/prepare`
  - create a prepared onboarding job for the selected candidate
- `POST /api/sources/discovery/jobs/{job_id}/execute`
  - execute or dry-run a prepared onboarding job

## Auto-Onboarding

Current support:

- Linux and Proxmox-like nodes
  - prepared through `linux_rsyslog_ssh`
  - dry-run supported
  - execution can push an `rsyslog` forwarding config to the target host over SSH

Current Windows support:

- Windows candidates
  - prepared through `windows_onboarding_package`
  - execution generates a host-specific native-service staging package
  - package includes host profile, native install wrapper, packaging scripts, status script, VPN profile helper, manifest, and operator README
  - the rollout is now enterprise-oriented around the native Windows service, not the legacy scheduled-task collector
- Network devices
  - `network_cli_ssh` is now live for supported device families
  - vendor inference covers `cisco_ios`, `mikrotik_routeros`, and `ubiquiti_edgeos`
  - the operator can preview generated commands, enter ephemeral SSH credentials, and execute config push from the UI
  - manual snippet generation remains available as fallback when no safe SSH path is inferred

## Operator Flow

1. Open `Sources -> Discovery`.
2. Run a subnet scan, typically `192.168.1.0/24`.
3. Inspect unmanaged candidates.
4. Prepare a monitoring job for the selected host.
5. Dry-run the job to confirm the rollout path.
6. Provide ephemeral credentials in the discovery drawer when the method requires SSH.
7. Execute the supported rollout when credentials and change approval are available.

## Limits

- The current scanner is TCP-based and optimized for the home lab, not for internet-scale discovery.
- Timeouts are intentionally short to keep scans usable on `/24` ranges.
- OS and role inference are signature-based and should be treated as guidance.
- Windows endpoint install still requires operator execution on the endpoint itself after package generation.
- Network rollout is only automated for supported SSH-manageable vendors and still expects change-approved credentials.

## Current Live Snapshot

Latest validated full-lab scan on `2026-03-13`:

- CIDR: `192.168.1.0/24`
- discovered hosts: `14`
- already connected sources: `6`
- unmanaged candidates: `8`
- auto-ready unmanaged Linux candidates: `4`
- prepared jobs still pending after rescan: `0`

The previously prepared job for `192.168.1.38` was automatically marked `superseded` after discovery recognized that node as the already-connected `siem-storage` host.
