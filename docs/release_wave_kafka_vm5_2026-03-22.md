# Release Wave: Kafka + VM5 + Storage Hardening

This is the next large slice after the current Mongo/SQLite follow-up.

## Scope

This wave should be treated as a `2-3 week` team block, not a one-off hotfix.

### Phase 1: VM5 and transport base

- provision `VM5`
- install self-hosted runner `siem-vm5`
- deploy Kafka KRaft brokers on `VM1`, `VM2`, `VM5`
- prepare TLS/SCRAM auth and topic bootstrap
- use the repo-owned topology scaffold in [kafka_cluster_layout.py](C:/Users/lolol/Documents/Playground/remote-edit2/deploy/kafka_cluster_layout.py)
- use the repo-owned unit templates in [siem-kafka.service](C:/Users/lolol/Documents/Playground/remote-edit2/deploy/vm1/siem-kafka.service), [siem-kafka.service](C:/Users/lolol/Documents/Playground/remote-edit2/deploy/vm2/siem-kafka.service), and [siem-kafka.service](C:/Users/lolol/Documents/Playground/remote-edit2/deploy/vm5/siem-kafka.service)
- use the repo-owned node prepare/smoke scripts in [kafka_wave_prepare.py](C:/Users/lolol/Documents/Playground/remote-edit2/deploy/kafka_wave_prepare.py) and [kafka_wave_smoke.py](C:/Users/lolol/Documents/Playground/remote-edit2/deploy/kafka_wave_smoke.py)
- use the repo-owned VM5 processing prepare/smoke scripts in [vm5_processing_prepare.py](C:/Users/lolol/Documents/Playground/remote-edit2/deploy/vm5_processing_prepare.py) and [vm5_processing_smoke.py](C:/Users/lolol/Documents/Playground/remote-edit2/deploy/vm5_processing_smoke.py)
- run the preparation pass from [prepare-kafka-wave.yml](C:/Users/lolol/Documents/Playground/remote-edit2/.github/workflows/prepare-kafka-wave.yml)

### Phase 2: Kafka shadow path

- dual-write ingest from `VM1`
- shadow `normalizer` and `filter` consumers on `VM2` and `VM5`
- shadow writer path into compare-friendly validation tables
- lag and broker health through `/api/health/transport`
- shadow freshness and parity through `/api/health/transport.transport_shadow`

#### Current Live Progress Inside Phase 2

- broker firewalls on `VM1`, `VM2`, and `VM5` now explicitly allow Kafka client traffic on `9092/tcp` from `VM3` and `VM4`; controller traffic on `9093/tcp` remains restricted to the broker nodes
- `VM1` syslog ingest now dual-writes to Kafka as well as the HTTP ingest path; the earlier live bug was that only the HTTP path passed a transport producer into `push_raw_event(...)`
- `VM5` shadow processing now runs `kafka` for both producer and consumer backends; the earlier live bug was a `dual + kafka-consumer` split that still forced the producer path to block on Redis/Sentinel
- the core dual-transport runtime now publishes Redis-side events to Redis stream keys again; the earlier live bug in [transport_runtime.py](C:/Users/lolol/Documents/Playground/remote-edit2/services/transport_runtime.py) sent the Redis half of dual-write into Kafka topic names like `siem.raw`, which left `events_shadow` fresh while the main Redis pipeline went flat
- `VM3` `siem-writer-shadow` now receives real Kafka-filtered traffic and writes into `siem.events_shadow`
- `/api/health/transport` now reports shadow freshness/parity through the `transport_shadow` section, including:
  - `status`
  - `healthy`
  - `shadow_events_5m`
  - `shadow_events_15m`
  - `shadow_last_event_ts`
  - `shadow_to_main_ratio_5m`
  - `shadow_to_main_ratio_15m`
- `Activate Kafka Shadow Wave` is now green on `main`: [run 23418190986](https://github.com/Rdegon/siem-solution/actions/runs/23418190986)
- the current live shadow parity after that run is:
  - `transport_backend=dual`
  - `transport_cutover_stage=dual_write`
  - `shadow_pipeline_status=healthy`
  - `shadow_pipeline_healthy=true`
  - `main_events_5m=3084`
  - `shadow_events_5m=3084`
  - `shadow_to_main_ratio_5m=1.0`
  - `shadow_last_event_ts=2026-03-23T02:01:58Z`
- the last live blocker inside this wave was not Kafka itself but runner-local file ownership on `VM1`; [vm1_kafka_shadow_prepare.py](C:/Users/lolol/Documents/Playground/remote-edit2/deploy/vm1_kafka_shadow_prepare.py) now syncs ingest files through explicit `sudo install` commands so the Actions runner can roll dual-write safely into the root-owned live checkout

### Phase 3: Live cutover

- `ingest -> Kafka`
- `normalizer/filter -> Kafka`
- `writer -> Kafka`
- keep `stream_corr` single-active on `VM3`, backed by SQLite
- observe a `48h` green window

### Phase 4: Redis exit

- remove Redis from the live transport path
- keep only archival rollback guidance in docs
- simplify watchdog and deploy jobs around Kafka quorum instead of Redis edge health

## Related Items Bundled Into The Same Wave

- warm-standby processing beyond one active `VM2`
- storage HA preparation after transport cutover
- first real backend decomposition wave, starting with `deps.py`

## What Is Deliberately Not In This Wave

- ClickHouse replication live rollout
- Postgres standby
- full backend monolith split

Those should start only after Kafka transport is green.
