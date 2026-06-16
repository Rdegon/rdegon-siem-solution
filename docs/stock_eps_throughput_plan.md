# Stock EPS Throughput Plan

Goal: increase the throughput of the stock SIEM system without reducing
functionality, disabling detection rules, or inserting test events directly into
ClickHouse. Load tests must use the production path:

`HTTP ingest -> Kafka -> normalizer/filter -> writer -> ClickHouse -> correlation -> Web`.

## 1. Baseline First

Before tuning, prove where the current system bottlenecks.

1. Verify Kafka-only transport:
   - `SIEM_TRANSPORT_BACKEND=kafka`
   - `SIEM_TRANSPORT_CONSUMER_BACKEND=kafka`
   - Kafka brokers are reachable on VM1, VM2, and VM5.
2. Run the EPS ladder through production transport:

```powershell
python deploy/eps_ladder_live.py --stages 500,750,1000,1250,1500 --duration-sec 60 --batch-size 200 --output runtime-control-plane/eps-ladder-live/eps_ladder_baseline.json
```

3. Capture these metrics for each stage:
   - achieved EPS;
   - ingest ACK latency p50/p95/max;
   - Kafka lag for `siem.raw`, `siem.normalized`, and `siem.filtered`;
   - ClickHouse stored EPS and insert health;
   - stream correlation lag;
   - Web p95 for incidents, events, and sources.
4. Remove only benchmark/test rows after the run:

```powershell
python deploy/cleanup_eps_benchmark_events.py --report runtime-control-plane/eps-ladder-live/eps_ladder_baseline.json --execute
```

## 2. Low-Risk Stock Tuning

This wave keeps the data model and rule coverage intact.

### VM1 Ingest

1. Keep fast ACK only after durable Kafka enqueue.
2. Increase HTTP batch publish gradually:
   - start: `SIEM_INGEST_HTTP_PUBLISH_BATCH_SIZE=250`;
   - if p95 is stable: `500`;
   - upper test bound: `1000`.
3. Expose or collect:
   - accepted events/sec;
   - publish batch size;
   - Kafka publish latency p50/p95;
   - failed publish count;
   - rejected/backpressure count.
4. If ACK p95 becomes the first bottleneck, add env-configurable Kafka producer
   knobs:
   - `linger_ms`;
   - `compression_type`;
   - `max_batch_size`;
   - `max_request_size`.
5. Test `compression_type=lz4` or `zstd` only after checking CPU headroom.

### Kafka

1. Inspect partitions for hot topics:
   - `siem.raw`;
   - `siem.normalized`;
   - `siem.filtered`;
   - `siem.dlq`.
2. Starting target for 500-1500 EPS: 6 partitions on hot topics, RF=3,
   `min.insync.replicas=2`.
3. If consumer lag remains after worker scale-out, raise hot topics to 9 or
   12 partitions.
4. Add a stable partition key for future ordering:
   - `host.name`, if present;
   - otherwise `log_source`;
   - otherwise source IP.

### VM2/VM5 Processing

1. Scale consumer instances up to partition count without CPU oversubscription:
   - normalizer: `siem-normalizer`, `siem-normalizer@1`, `@2`, `@3`;
   - filter: `siem-filter`, `siem-filter@1`, `@2`, `@3`.
2. Increase batch sizes:
   - `SIEM_NORMALIZER_BATCH_SIZE=500`;
   - `SIEM_FILTER_BATCH_SIZE=500`;
   - if CPU and memory remain stable: `1000`.
3. Treat the change as successful only if raw and normalized lag drains after
   load stops.
4. If normalizer CPU becomes the bottleneck:
   - move expensive parse/enrichment operations out of the hot path;
   - cache compiled expressions;
   - add a fast path for already-normalized JSON.

### VM3 Writer And ClickHouse Insert Path

1. Standardize ClickHouse port usage:
   - native `clickhouse_driver` workers must use `SIEM_CH_PORT=9000`;
   - HTTP `8123` must be used only with `clickhouse_connect`.
2. Increase writer batch size:
   - `SIEM_WRITER_BATCH_SIZE=500`;
   - then `1000`;
   - then `2000` if insert latency and memory remain stable.
3. Keep at least two writer consumer instances when partitions allow it:
   - `siem-writer`;
   - `siem-writer@2`;
   - add `@3`/`@4` only after dedupe and partition ownership checks.
4. Track ClickHouse:
   - insert throughput;
   - parts count;
   - background merges;
   - disk IO wait;
   - memory pressure.
5. If ClickHouse is the bottleneck:
   - test async insert only for the writer path after E2E verification;
   - increase insert batch and flush interval;
   - review schema and order key for `siem.events`;
   - add materialized summaries for Web counters instead of repeated raw scans.

## 3. Correlation Scaling

Correlation must not block ingest or ClickHouse writes.

### Stream Correlation

The current code already has a candidate rule index. For 1500 EPS with the full
rule set, add stronger profiling and sharding.

1. Measure:
   - events processed/sec;
   - candidate rules per event;
   - alerts created/sec;
   - state read/write latency;
   - lag on `siem.filtered`.
2. Reduce hot-path cost:
   - index rules by source, event type, asset group, and rule family;
   - cache compiled match expressions;
   - move JMESPath/YAML-heavy checks out of the per-event path.
3. Scale-out rule:
   - if state backend is SQLite, stream correlation stays single-active;
   - parallel stream correlation requires shared state or deterministic shard
     ownership;
   - shard key should be `rule_id + entity_key` or `asset_group + entity_key`;
   - each shard must own its state and alert dedupe.

### Batch Correlation

1. Do not run heavy batch queries during EPS test windows.
2. For noisy or heavy batch rules, add:
   - bounded time windows;
   - pre-aggregated inputs;
   - query timeout;
   - ClickHouse resource profile.
3. Parallel batch correlation is allowed only after idempotency design:
   - no overlapping windows without deterministic dedupe key;
   - one active owner per rule/window.

## 4. Web/API Throughput

The UI must stay usable during sustained 500+ EPS.

1. Remove raw scans from initial page load paths.
2. For incidents/events:
   - default bounded time range;
   - pagination;
   - lazy detail loading;
   - capped evidence samples;
   - server-side query timeout.
3. For counters:
   - materialized summaries or precomputed tables;
   - short TTL cache, usually 5-15 seconds.
4. Web acceptance:
   - incidents list p95 <= 2 seconds at 500 EPS;
   - incident detail p95 <= 3 seconds;
   - events page p95 <= 2 seconds for default window;
   - no 500 on ClickHouse timeout; return bounded error plus retry instead.

## 5. Rollout Order

1. Baseline EPS ladder.
2. VM1 ingest batch and Kafka producer tuning.
3. Kafka partition and backpressure checks.
4. VM2/VM5 normalizer/filter scale-out.
5. VM3 writer batch, port, and insert tuning.
6. Stream correlation hot-path profiling and rule index expansion.
7. Web/API bounded summaries.
8. Full EPS ladder again.
9. Cleanup benchmark events.
10. Commit and push reports/config changes.

## 6. Acceptance Matrix

| EPS | Expected result |
| --- | --- |
| 500 | Stable, no sustained Kafka lag, UI usable |
| 750 | Stable or clearly bounded bottleneck |
| 1000 | Lag drains after test; no data loss |
| 1250 | Report identifies first bottleneck if degraded |
| 1500 | Stretch target, accepted only with full metrics and cleanup |

Every run must produce:

- run id;
- target EPS and achieved EPS;
- ingest latency p50/p95/max;
- Kafka lag before/after;
- stored event count and delivery ratio;
- ClickHouse insert health;
- correlation lag;
- Web smoke timings;
- cleanup report.

## 7. Rollback

Rollback is configuration-first:

1. Reduce worker counts to the previous systemd unit set.
2. Reduce batch sizes to `100`.
3. Keep Kafka partitions unless there is no offset or retention risk in reducing
   them.
4. Disable only new performance flags, not detection rules.
5. Re-run 500 EPS and Web smoke before declaring recovery.

## 8. Immediate Implementation Items

1. Add env-configurable Kafka producer tuning:
   - `SIEM_KAFKA_PRODUCER_LINGER_MS`;
   - `SIEM_KAFKA_PRODUCER_COMPRESSION_TYPE`;
   - `SIEM_KAFKA_PRODUCER_MAX_BATCH_SIZE`;
   - `SIEM_KAFKA_PRODUCER_MAX_REQUEST_SIZE`.
2. Add worker lag/latency metrics to runtime status surfaces.
3. Add a deploy script for the stock performance profile:
   - writes env overrides;
   - restarts only affected services;
   - captures pre/post health.
4. Add Web smoke timing into `eps_ladder_live.py`.
5. Run production ladder and cleanup once lab network is reachable.
