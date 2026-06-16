# Deployment Runbook: VM3 Storage Memory Tuning

Use this runbook to apply the conservative ClickHouse memory baseline on `VM3`.

## Purpose

This slice lowers oversized ClickHouse memory limits and cache ceilings on the storage node without changing the current analytics contract.

## Defaults

If no overrides are provided, the deploy script applies:

- `SIEM_VM3_CH_MAX_SERVER_MEMORY_USAGE_BYTES = 17179869184`
- `SIEM_VM3_CH_MAX_SERVER_MEMORY_USAGE_TO_RAM_RATIO = 0.6`
- `SIEM_VM3_CH_MARK_CACHE_SIZE_BYTES = 1073741824`
- `SIEM_VM3_CH_UNCOMPRESSED_CACHE_SIZE_BYTES = 1073741824`

## Required Environment

- `SIEM_VM3_HOST`
- `SIEM_VM3_USER`
- `SIEM_VM3_PASSWORD`

Optional overrides:

- `SIEM_VM3_CH_MAX_SERVER_MEMORY_USAGE_BYTES`
- `SIEM_VM3_CH_MAX_SERVER_MEMORY_USAGE_TO_RAM_RATIO`
- `SIEM_VM3_CH_MARK_CACHE_SIZE_BYTES`
- `SIEM_VM3_CH_UNCOMPRESSED_CACHE_SIZE_BYTES`
- `SIEM_VM3_CH_APP_USER`
- `SIEM_VM3_STORAGE_MIN_AVAILABLE_MEMORY_BYTES`

## Commands

```powershell
python C:\Users\lolol\Documents\Playground\remote-edit2\deploy\vm3_storage_memory_tuning.py
python C:\Users\lolol\Documents\Playground\remote-edit2\deploy\vm3_storage_memory_smoke.py
```

## What The Deploy Script Changes

1. backs up the previous VM3 tuning file and `/etc/siem/storage.env`
2. writes `/etc/clickhouse-server/config.d/siem-memory-tuning.xml`
3. grants the ClickHouse app user access to `system.asynchronous_metrics`, `system.metrics`, and `system.server_settings`
4. persists the chosen values into `/etc/siem/storage.env`
5. restarts:
   - `clickhouse-server`
   - `siem-writer`
   - `siem-writer@2`
   - `siem-stream-corr`
   - `siem-batch-corr`
   - `siem-alert-agg`

## Validation

The smoke script checks:

- all storage services are `active`
- ClickHouse server settings match the expected values
- the ClickHouse app user keeps the required system-table grants for storage observability
- available system memory on `VM3` stays above the configured floor
- runtime metrics are readable from `system.asynchronous_metrics`

## Operator Notes

- a high `buff/cache` value in `free -h` is expected and is not by itself a failure
- the real danger signs are:
  - low `available` memory
  - swap growth
  - large `MemoryResident` relative to `max_server_memory_usage`
  - repeated OOM restarts of `clickhouse-server`
