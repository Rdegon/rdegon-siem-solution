# EPS Ladder Test - 2026-05-23

## Scope

Live source-event E2E load test through the production HTTP ingest endpoint:

- endpoint: `https://192.168.1.35/ingest/json`
- transport: production Kafka topics
- storage verification: ClickHouse `siem.events`
- primary ladder: `500, 750, 1000, 1250, 1500 EPS`
- primary profile: `4` injectors, `1` worker per injector, `batch_size=200`, `duration=20s`, `request_timeout=60s`

Raw result files:

- `runtime-control-plane/eps-ladder-live/eps_ladder_20260523T173636.json`
- `runtime-control-plane/eps-ladder-live/eps_ladder_diag_8w_20260523T174845.json`
- `runtime-control-plane/eps-ladder-live/eps_ladder_diag_8w_batch1000_20260523T175223.json`

## Primary Ladder Results

| Target EPS | Sent | Stored | Delivery | Achieved EPS | Load duration | HTTP p95 ACK | Max primary Kafka lag | Verdict |
|---:|---:|---:|---:|---:|---:|---:|---:|---|
| 500 | 10000 | 10000 | 1.0000 | 217.33 | 46.014s | 6876.8 ms | 79 | not sustained |
| 750 | 15000 | 15000 | 1.0000 | 278.26 | 53.907s | 7306.8 ms | 338 | not sustained |
| 1000 | 20000 | 20000 | 1.0000 | 219.21 | 91.237s | 9113.9 ms | 415 | not sustained |
| 1250 | 25000 | 25000 | 1.0000 | 264.80 | 94.411s | 7633.6 ms | 841 | not sustained |
| 1500 | 30000 | 30000 | 1.0000 | 236.66 | 126.762s | 8604.8 ms | 1505 | not sustained |

## Diagnostic Runs

| Target EPS | Profile | Sent | Stored | Delivery | Achieved EPS | HTTP p50 ACK | HTTP p95 ACK | Max primary Kafka lag | Interpretation |
|---:|---|---:|---:|---:|---:|---:|---:|---:|---|
| 1500 | 8 workers, batch 200 | 30000 | 30000 | 1.0000 | 432.20 | 2760.8 ms | 8271.2 ms | 1482 | more client concurrency helps, but still far below 1500 |
| 1500 | 8 workers, batch 1000 | 30000 | 30000 | 1.0000 | 299.60 | 32960.1 ms | 41918.4 ms | 478 | large payloads make synchronous ACK latency much worse |

## Findings

The system did not drop benchmark events in these tests. Every stage reached `delivery_ratio=1.0`, and writer lag stayed near zero after the run drained. This means the durable delivery and ClickHouse write path survived the event volume.

The system did not sustain the requested EPS levels. The intended 20-second load windows stretched to 46-127 seconds in the primary ladder, so the actual achieved rate stayed around 217-278 EPS. The best diagnostic rate was 432.20 EPS with 8 concurrent workers, still below the lowest requested sustained target of 500 EPS.

The main bottleneck is the collector-facing HTTP ingest acknowledgement path. Request p95 latency stayed around 6.9-9.1 seconds with batch 200, and a larger batch of 1000 pushed p50 ACK latency to about 33 seconds and p95 to about 42 seconds. This shows the issue is not only request count; large synchronous request processing also blocks.

The secondary bottleneck is real-time stream correlation. During high stages the largest primary lag was on `siem_stream_corr` over `siem.filtered`, peaking at 1505 in the primary ladder and 1482 in the 8-worker diagnostic. The writer and standby writer stayed effectively caught up. Stream correlation drained after the tests, so this is burst backlog rather than permanent failure.

## Per-Target Verdict

| Target EPS | Verdict | Immediate reason |
|---:|---|---|
| 500 | does not sustain | actual 217.33 EPS; HTTP ACK p95 6.9s |
| 750 | does not sustain | actual 278.26 EPS; stream correlation lag 338 |
| 1000 | does not sustain | actual 219.21 EPS; load window stretched to 91.2s |
| 1250 | does not sustain | actual 264.80 EPS; stream correlation lag 841 |
| 1500 | does not sustain | actual 236.66 EPS in primary ladder; best diagnostic 432.20 EPS |

## Post-Test State

After drain:

- Kafka primary lag returned to `1`
- standby lag returned to `1`
- VM1 `siem-ingest`, `siem-kafka`, `nginx` active
- VM3 `clickhouse-server`, `siem-writer`, `siem-writer@2`, `siem-stream-corr`, `siem-batch-corr`, `siem-alert-agg` active
- test-created HB-012 benchmark-host alerts were marked `false_positive`
- HB-012 runtime SQL was tuned to ignore `eps-bench`/benchmark synthetic sources

## Required Remediation Before Re-Testing 500+ EPS

1. Decouple HTTP ingest ACK from slow downstream work: validate request, publish to Kafka, and return quickly.
2. Avoid large synchronous batch processing on the request path; batch 1000 currently increases ACK latency sharply.
3. Scale or shard `siem_stream_corr` so correlation can keep up with bursty `siem.filtered` traffic.
4. Re-run the ladder with enough generator concurrency after the ACK path is fixed.
5. Treat benchmark hosts/tags as operational synthetic sources in all heartbeat/EPS rules.

## Benchmark Data Cleanup

A targeted cleanup helper was added at `deploy/cleanup_eps_benchmark_events.py`.

Dry-run command used:

```powershell
python repo\deploy\cleanup_eps_benchmark_events.py `
  --report repo\runtime-control-plane\eps-ladder-live\eps_ladder_20260523T173636.json `
  --report repo\runtime-control-plane\eps-ladder-live\eps_ladder_diag_8w_20260523T174845.json `
  --report repo\runtime-control-plane\eps-ladder-live\eps_ladder_diag_8w_batch1000_20260523T175223.json `
  --output repo\runtime-control-plane\eps-ladder-live\cleanup_eps_benchmark_dry_run_20260523.json
```

Dry-run matched:

| Table | Rows |
| --- | ---: |
| `siem.events` | 160000 |
| `siem.events_cold` | 0 |
| `siem.events_shadow` | 160000 |
| `siem.alerts_raw` | 4 |
| `siem.alerts_agg` | 4 |
| `siem.alert_history` | 0 |

To remove the benchmark rows after the results are no longer needed, run the same command with `--execute`.
