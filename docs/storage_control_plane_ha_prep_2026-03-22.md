# Storage And Control-Plane HA Preparation

This note captures the second of the next two large release waves and the concrete groundwork now present in the repo.

## What Is Now In Place

- richer content-store status through `/api/content/storage`
- persistent Mongo migration metadata and collection counts
- SQLite runtime-state status with committed offsets and runtime-meta visibility
- richer transport health through `/api/health/transport`
- backup-readiness status through `/api/health/backups` for the active `Postgres`, `Mongo`, `SQLite`, and `ClickHouse` layers

## Why This Matters

The product already has:

- `Postgres` for control plane
- `MongoDB` for content/documents
- `SQLite WAL` for stream-correlation runtime state
- `ClickHouse` for analytics and detections

To make those layers release-ready, the platform needs honest status surfaces and migration bookkeeping before the HA cutover work begins.

## Next Execution Items

- ClickHouse standby or replica preparation
- Postgres backup/restore and standby hardening
- Mongo backup/restore and failover hardening
- first domain split of `deps.py`, `enterprise_control_plane.py`, and `console.py`
