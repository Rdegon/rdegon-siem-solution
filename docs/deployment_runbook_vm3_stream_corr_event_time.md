# VM3 Deployment Runbook: Event-Time Stream Correlation

## Purpose

This runbook rolls out the `2026-03-21` stream-correlation upgrade on `VM3`:

- event-time primary correlation mode
- lateness and watermark controls
- optional processing-time shadow comparison
- runtime status snapshots written to ClickHouse for VM4 health visibility

## Baseline

- Local source of truth: `C:\Users\lolol\Documents\Playground\remote-edit2`
- Remote target root: `/opt/siem/siem-solution`
- Remote worker path: `/opt/siem/siem-solution/services/stream_corr/worker.py`
- Remote env file: `/etc/siem/storage.env`
- Service to restart: `siem-stream-corr`

## Credentials

Use the authoritative lab secret sources:

- [SYSTEM_ACCESS_MATRIX.md](C:/Users/lolol/Documents/Playground/product-docs/SYSTEM_ACCESS_MATRIX.md)
- [OPERATOR_ACCESS_BUNDLE.md](C:/Users/lolol/Documents/Playground/product-docs/OPERATOR_ACCESS_BUNDLE.md)

Set these environment variables before the rollout:

- `SIEM_VM3_HOST`
- `SIEM_VM3_USER`
- `SIEM_VM3_PASSWORD`
- `SIEM_VM3_BASE_DIR`

Optional runtime knobs:

- `SIEM_STREAM_CORR_TIME_MODE=event|processing`
- `SIEM_STREAM_CORR_SHADOW_COMPARE=true|false`
- `SIEM_STREAM_CORR_ALLOWED_LATENESS_SEC`
- `SIEM_STREAM_CORR_WATERMARK_LAG_SEC`

Recommended live values for this slice:

- `SIEM_STREAM_CORR_TIME_MODE=event`
- `SIEM_STREAM_CORR_SHADOW_COMPARE=true`
- `SIEM_STREAM_CORR_ALLOWED_LATENESS_SEC=600`
- `SIEM_STREAM_CORR_WATERMARK_LAG_SEC=300`

## Deployment Tooling

- deploy: `deploy/vm3_stream_corr_event_time_deploy.py`
- smoke: `deploy/vm3_stream_corr_event_time_smoke.py`

## Standard Procedure

1. Export the VM3 access variables and the stream-correlation env knobs.
2. Run:

```powershell
python C:\Users\lolol\Documents\Playground\remote-edit2\deploy\vm3_stream_corr_event_time_deploy.py
```

3. The deploy script will:
   - back up the worker file and `/etc/siem/storage.env` under `/tmp/siem-stream-corr-backup-<timestamp>`
   - upload the event-time worker
   - update the env knobs in `/etc/siem/storage.env`
   - compile the worker with `/opt/siem/venv-storage/bin/python -m py_compile`
   - restart `siem-stream-corr`
   - verify `clickhouse-server` and `siem-stream-corr` are `active`

4. Run smoke validation:

```powershell
python C:\Users\lolol\Documents\Playground\remote-edit2\deploy\vm3_stream_corr_event_time_smoke.py
```

The smoke script verifies:

- `clickhouse-server=active`
- `siem-stream-corr=active`
- the runtime table `siem.stream_corr_runtime_status` is receiving snapshots
- the latest runtime row reports the expected `mode` and `shadow_compare` flags

## Rollback

1. Use the backup directory printed by the deploy script.
2. Restore:
   - `services/stream_corr/worker.py`
   - `/etc/siem/storage.env`
3. Restart `siem-stream-corr`.
4. Re-run the smoke script.

## Notes

- This slice keeps `processing` mode available as an emergency rollback toggle.
- `shadow_compare=true` is intentionally left enabled during the first live phase so mismatches remain visible through `/api/health/overview`.
- The runtime snapshot table is written even during idle periods, so health visibility does not depend on a fresh event batch arriving immediately after restart.
