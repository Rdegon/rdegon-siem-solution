# Storage HA Operations

## Operational Goals

- failover readiness must be measurable
- controlled switchover must be repeatable
- restore readiness must be validated before an incident forces a restore
- health payloads must reflect real topology state instead of path-local false negatives

## Current Live Shape

- ClickHouse primary `VM3`, standby `VM5`
- Postgres primary `VM4`, standby `VM1`
- Mongo primary `VM4`, secondaries `VM1` and `VM5`
- stream-state SQLite source on `VM3`

## Health Gates

- `GET /api/health/backups`
- `GET /api/health/storage-ha`
- `GET /api/health/overview`

Green state requires:

- `healthy = true`
- `failover_ready = true`
- `controlled_switchover_ready = true`
- no storage HA alarms
- backup targets marked prepared for all required backends

## Postgres Replay Semantics

Standby replay lag is now evaluated with idle-replica awareness.

Meaning:

- if `pg_last_wal_receive_lsn()` equals `pg_last_wal_replay_lsn()`, the standby is treated as caught up even when wall-clock replay lag would otherwise look stale on an idle system;
- health payloads expose `wal_receive_replay_synced` to make that state explicit.

This prevents false-red lag alarms during low-write windows.

## Backup Readiness Semantics

- control-plane Postgres and Mongo readiness are evaluated on `VM4`
- stream-state SQLite readiness is evaluated against the real source node and source path on `VM3`
- ClickHouse backup readiness is tied to the live storage topology, not to a guessed local filesystem path on `VM4`

## Operator Commands

```powershell
python .\tools\siem_operator_cli.py storage-ha drill
python .\tools\siem_operator_cli.py storage-ha restore-verify --backup-root /tmp
python .\deploy\storage_ha_wave_smoke.py
```

## Incident Order

1. check `GET /api/health/storage-ha`
2. check `GET /api/health/backups`
3. verify primary and standby role assignments
4. verify replication lag and `wal_receive_replay_synced`
5. run restore verification before closing the incident
