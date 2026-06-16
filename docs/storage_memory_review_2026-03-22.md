# Storage Memory Review: 2026-03-22

This note captures the live memory snapshot across the stand and the follow-up tuning for `VM3`.

## Live Memory Snapshot

Observed directly over SSH on `2026-03-22`:

| Node | Total RAM | Used | Buff/Cache | Available | Notes |
| --- | --- | --- | --- | --- | --- |
| `VM1` ingest | `11 GiB` | `402 MiB` | `964 MiB` | `10 GiB` | healthy |
| `VM2` processing | `15 GiB` | `971 MiB` | `3.5 GiB` | `14 GiB` | healthy |
| `VM3` storage | `27 GiB` | `2.3 GiB` | `23 GiB` | `24 GiB` | high Linux page cache, not a process leak |
| `VM4` web | `7.8 GiB` | `509 MiB` | `1.4 GiB` | `6.9 GiB` | healthy |

## VM3 Diagnosis

The `27 GiB` alarm on `VM3` was mostly a Linux page-cache effect rather than runaway process RSS.

Direct runtime observations:

- `clickhouse-server` RSS: about `1.38 GiB`
- `jemalloc.allocated`: about `707 MiB`
- `MarkCacheBytes`: about `40 MiB` in active use
- `system.server_settings` still allowed a much larger budget:
  - `max_server_memory_usage ~= 24.68 GiB`
  - `max_server_memory_usage_to_ram_ratio = 0.9`
  - `mark_cache_size = 5 GiB`
  - `uncompressed_cache_size = 8 GiB`

That configuration is much looser than the current stand needs and makes the storage node look “full” much earlier than necessary.

## Tuning Defaults Added

The new deploy slice writes `/etc/clickhouse-server/config.d/siem-memory-tuning.xml` with these defaults:

- `max_server_memory_usage = 16 GiB`
- `max_server_memory_usage_to_ram_ratio = 0.6`
- `mark_cache_size = 1 GiB`
- `uncompressed_cache_size = 1 GiB`

These values are intentionally conservative for the current homelab:

- enough headroom for ClickHouse plus writer/correlation services
- enough free RAM for page cache and background merges
- much lower risk of the storage node appearing saturated under normal analyst activity

## Post-Deploy Reality Check

After the `2026-03-22` VM3 deploy completed, the live storage node reported:

- `max_server_memory_usage = 16 GiB`
- `max_server_memory_usage_to_ram_ratio = 0.6`
- `mark_cache_size = 1 GiB`
- `uncompressed_cache_size = 1 GiB`
- `MemoryResident ~= 1.01 GiB`
- `jemalloc.allocated ~= 780 MiB`
- `available memory ~= 24 GiB`

The first live pass of `/api/health/storage` still showed `storage_memory=unavailable` even though ClickHouse was healthy. Root cause: the `siem-web` ClickHouse user did not yet have `SELECT` grants on the required system tables. The VM3 storage tuning path now also applies these grants for:

- `system.asynchronous_metrics`
- `system.metrics`
- `system.server_settings`

## Proxmox Alignment Follow-Up

The next issue was not ClickHouse itself, but how `VM106` looked from Proxmox.

Even with healthy guest memory, Proxmox still showed the VM pinned near the full `28 GiB` ceiling because:

- Linux page cache was counted as used memory from the host point of view
- `qemu-guest-agent` was missing inside `VM3`
- no explicit Proxmox balloon floor had been configured

The VM now uses this alignment policy:

- `memory = 28672 MiB`
- `balloon = 24576 MiB`
- `qemu-guest-agent` installed and enabled
- live balloon target applied through QMP so the graph moves immediately instead of waiting for a future pressure event

Live result after alignment:

- guest `MemTotal ~= 24 GiB`
- guest `MemAvailable ~= 21 GiB`
- Proxmox-reported VM memory dropped out of the earlier `26-27 GiB` zone
- storage services stayed healthy throughout the change

No extra RAM was added in this pass because the guest still had large real headroom after alignment.

## New Runtime Paths

- deploy: `deploy/vm3_storage_memory_tuning.py`
- smoke: `deploy/vm3_storage_memory_smoke.py`
- API visibility: `/api/health/storage`

## Next Follow-Up

The next storage wave should be larger than memory tuning:

1. Kafka transport cutover so storage is no longer coupled to Redis on `VM2`
2. ClickHouse storage HA plan
3. split `deps.py` before adding more storage and search features
