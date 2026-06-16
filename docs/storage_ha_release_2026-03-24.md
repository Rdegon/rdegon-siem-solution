# Storage HA Release State

This note captures the first fully green live state for the storage/control-plane HA wave on `2026-03-24`.

## Live Topology

- `ClickHouse`
  - primary: `VM3` `192.168.1.38`
  - standby: `VM5` `192.168.1.40`
- `Postgres`
  - primary: `VM4` `192.168.1.39`
  - standby: `VM1` `192.168.1.35`
- `MongoDB`
  - replica set: `siem-rs`
  - primary: `VM4`
  - secondaries: `VM1`, `VM5`

## Verified Runtime State

- `/api/health/storage-ha`
  - `clickhouse=true`
  - `postgres=true`
  - `mongo=true`
- `/api/control-plane/storage`
  - `backend=postgres`
  - `migration_status=completed`
- `/api/content/storage`
  - `backend=mongo`
  - `migration_status=completed`
- `/api/health/transport`
  - `transport_backend=kafka`
  - `stream_state_backend=sqlite`
  - `content_store_backend=mongo`
  - `shadow_pipeline_status=healthy`

## Backend Decomposition Applied

The live `VM4` web/API runtime now uses the decomposed backend helper set in `services/web/app`, not only the root-level copies:

- `clickhouse_runtime.py`
- `content_runtime.py`
- `control_plane_health.py`
- `health_surfaces.py`
- `storage_ha_runtime.py`
- `stream_state_runtime.py`
- `transport_health_runtime.py`
- `deps.py`
- `enterprise_control_plane.py`
- `console.py`

This closed the remaining observability drift where some health surfaces still showed legacy defaults instead of the live `kafka/sqlite/mongo/postgres` runtime.

## Redis Retirement

Redis is no longer part of the live data path.

- `VM1`, `VM2`, `VM3`, `VM5`
  - `redis-server=inactive`
  - `siem-redis-sentinel=inactive`
  - no active listeners on `6379` or `26379`
- `VM2` and `VM5`
  - stale UFW allow-rules for Redis were removed
- `VM3`
  - runtime Redis is retired, but stale UFW entries still appear in `ufw status`
  - direct file cleanup of `/etc/ufw/user.rules` is currently blocked by a read-only filesystem condition on that path
  - this is an inert firewall residue, not an active runtime dependency

`VM2` remains in service as a Kafka/processing node. Only the Redis role was retired.
