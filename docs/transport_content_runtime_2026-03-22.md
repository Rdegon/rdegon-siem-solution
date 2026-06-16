# Transport And Content Runtime Status: 2026-03-22

This document captures the current live truth for the transport/runtime layer after the SQLite state-store rollout on `VM3` and the Mongo content-store cutover on `VM4`.

## Live State

### Analytics and persistence

- `ClickHouse` remains the analytics and detection store on `VM3`.
- `Postgres` remains the authoritative control-plane database on `VM4`.
- `MongoDB` is now the live content/document backend on `VM4`.
- `SQLite WAL` is now the live runtime state backend for event-time stream correlation on `VM3`.

### Transport

- `Kafka` is the live transport bus.
- broker/controller runtime spans `VM1`, `VM2`, and `VM5`.
- `VM2` and `VM5` run active processing consumers.
- writer and stream-correlation consumers run against Kafka on `VM3`.
- Redis is retired from the live path and remains only in archival documents.

## Health Visibility

### VM1

- `GET /health/transport`

Current surface:

- `backend`
- `consumer_backend`
- `cutover_stage`
- Kafka target metadata
- Kafka health and cutover state

### VM4

- `GET /api/health/transport`
- `GET /api/content/storage`
- `GET /api/health/overview`

Current surface:

- `transport_backend`
- `transport_cutover_stage`
- `stream_state_backend`
- `content_store_backend`
- `content_store_healthy`
- `shadow_compare_status`

## Stream Correlation Runtime

### Live backend

- `SIEM_STREAM_STATE_BACKEND=sqlite`
- `SIEM_STREAM_STATE_SQLITE_PATH=/var/lib/siem-stream-corr/runtime-state.db`

### Current live validation

- `VM3` smoke confirms:
  - `transport_backend=kafka`
  - `mode=event`
  - `shadow_compare=1`
  - `state_backend=sqlite`

## Content Store Runtime

### Live backend

- `SIEM_CONTENT_STORE_BACKEND=mongo`
- `mongod` now runs on `VM4`
- current content-backed collections migrated into Mongo:
  - `content_bundle`
  - `saved_search`
  - `docs_pages`
  - `dashboard_instances`
  - `builder_drafts`

### Filesystem role after cutover

Filesystem content data is no longer the authoritative live backend. It remains only as:

- bootstrap seed
- export snapshot
- rollback source

## Important Infra Note

MongoDB 7 would not start on the original `VM4` guest CPU profile `x86-64-v2-AES` because the guest did not expose `AVX`.

The live fix was:

- Proxmox VM `107` CPU profile moved to `x86-64-v3`
- `VM4` rebooted
- `mongod` installed and enabled
- content-store migration completed

`deploy/vm4_content_store_mongo_cutover.py` now includes this CPU-profile remediation path when Proxmox credentials are available.

## Latest Validation

- local targeted tests:
  - `tests.test_transport_runtime`
  - `tests.test_content_store_runtime`
  - `tests.test_stream_worker`
  - `tests.test_enterprise_control_plane`
- authoritative `VM4` tests:
  - `tests.test_content_store_runtime`
  - `tests.test_enterprise_control_plane`
- live smoke:
  - `vm3_stream_corr_event_time_smoke.py`
  - `vm4_enterprise_foundation_smoke.py`

Latest successful backup anchors:

- `VM4` Mongo cutover backup: `/tmp/siem-web-content-store-backup-20260322T173858Z`
- Proxmox VM4 CPU-profile backup: `/tmp/siem-vm4-cpu-profile-backup-20260322T173859Z`
- latest VM4 app backup after the transport/content sync: `/tmp/siem-web-backup-20260322T172922Z`
- latest VM3 stream-correlation backup: `/tmp/siem-stream-corr-backup-20260322T172535Z`

## What Is Still Not Done

- Kafka is live.
- Redis is retired from the live transport path.
- There is still no fully certified distributed EPS harness for Kafka ingest.
- `MongoDB`, `Postgres`, and `ClickHouse` now have HA preparation/live standby topology, but still need deeper failover certification.
- `VM5` is live as transport and standby processing/storage node.
