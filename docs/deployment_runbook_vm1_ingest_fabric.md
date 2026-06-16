# VM1 Deployment Runbook: Ingest Fabric Slice

## Purpose

This runbook deploys the `2026-03-13` ingest-fabric slice from the local `remote-edit2` baseline to the live `VM1` ingest node.

## Baseline

- Local source of truth: `C:\Users\lolol\Documents\Playground\remote-edit2`
- Remote target root: `/opt/siem/siem-solution`
- Remote ingest slice: `/opt/siem/siem-solution/services/ingest`
- Service to restart: `siem-ingest`

## Credentials

Use the authoritative access matrix for live values:

- [SYSTEM_ACCESS_MATRIX.md](C:/Users/lolol/Documents/Playground/product-docs/SYSTEM_ACCESS_MATRIX.md)

Set these environment variables before running the scripts:

- `SIEM_VM1_HOST`
- `SIEM_VM1_USER`
- `SIEM_VM1_PASSWORD`
- `SIEM_VM1_BASE_DIR`

Optional runtime variable for protected ingest admin endpoints:

- `SIEM_INGEST_API_SHARED_SECRET`

Optional runtime variables for raw-stream pressure control:

- `SIEM_INGEST_RAW_STREAM_MAX_LEN`
- `SIEM_INGEST_RAW_STREAM_SOFT_LIMIT`
- `SIEM_INGEST_RAW_STREAM_HARD_LIMIT`

## Deployment Tooling

Deploy script:

- `deploy/vm1_ingest_fabric_deploy.py`

Smoke script:

- `deploy/vm1_ingest_fabric_smoke.py`

## File Mapping

| Local file | Remote file |
| --- | --- |
| `services/__init__.py` | `services/__init__.py` |
| `services/ingest/__init__.py` | `services/ingest/__init__.py` |
| `services/ingest/app.py` | `services/ingest/app.py` |
| `services/ingest/config.py` | `services/ingest/config.py` |
| `services/ingest/logging_conf.py` | `services/ingest/logging_conf.py` |
| `services/ingest/print_config.py` | `services/ingest/print_config.py` |
| `services/ingest/redis_client.py` | `services/ingest/redis_client.py` |
| `services/ingest/requirements.txt` | `services/ingest/requirements.txt` |
| `services/ingest/syslog_server.py` | `services/ingest/syslog_server.py` |

## Standard Procedure

1. Export the VM1 credentials into the expected environment variables.
2. Run:

```powershell
python C:\Users\lolol\Documents\Playground\remote-edit2\deploy\vm1_ingest_fabric_deploy.py
```

3. The script will:
   - back up the replaced files on VM1 under `/tmp/siem-ingest-backup-<timestamp>`
   - upload the ingest runtime files
   - compile the backend with `python3 -m py_compile`
   - restart `siem-ingest`
   - verify `systemctl is-active siem-ingest`

4. Run smoke validation:

```powershell
python C:\Users\lolol\Documents\Playground\remote-edit2\deploy\vm1_ingest_fabric_smoke.py
```

The smoke script validates:

- `/health`
- `/health/overview`
- `/health/sources`
- `/health/collectors`
- `/dlq/events`
- `/dlq/replay`

It also sends a mixed-validity ingest payload so the DLQ and replay paths are exercised on the live node.

The smoke payload is now explicitly marked `synthetic`, which keeps the heartbeat visible for debugging without turning `vm1-smoke` into a false delayed or stale operational source.

`/health/overview` now also exposes raw-stream pressure state:

- current raw stream length
- max length
- soft limit
- hard limit
- backpressure counter

## Rollback

- Use the backup directory reported by the deploy script.
- Copy the backed-up files back into place on VM1.
- Restart `siem-ingest`.

## Notes

- The deploy script assumes password-based SSH and `sudo -S` are available for the VM1 account documented in the access matrix.
- The live `2026-03-13` rollout succeeded with backup directory `/tmp/siem-ingest-backup-20260313T001101Z`.
- If `SIEM_INGEST_API_SHARED_SECRET` is configured on VM1, the smoke script should be run with the same variable so it can access the protected admin endpoints.
