# Performance / EPS Assessment: 2026-03-26

## Scope

This pass measured the real collector-facing HTTP ingest path instead of only a single local injector loop.

Used tooling:

- `deploy/distributed_eps_benchmark.py`
- `deploy/eps_worker.py`

## Key Findings

### 1. Small single-request latency is healthy

Measured from `VM1`:

- `https://127.0.0.1/ingest/json` single-event POST: about `0.306s`
- `http://127.0.0.1:8443/ingest/json` single-event POST: about `0.145s`

Measured from `VM2`:

- `https://192.168.1.35/ingest/json` single-event POST: about `0.164s`

This means the path is not broken for low concurrency.

### 2. The bottleneck is the concurrent HTTP ingest ACK path

Distributed fan-out from `VM1`, `VM2`, `VM4`, and `VM5` caused request timeouts even on the lowest tested stage of `250` target EPS with:

- `8s` stage duration
- `25` event batch size
- `20s` request timeout

Observed behavior:

- all four injectors timed out waiting for HTTP response
- ClickHouse still showed partial event acceptance for the run
- the benchmark therefore measured an ACK-path failure before it measured a storage-plane ceiling

### 3. The internal app listener is local-only

`siem-ingest` listens on:

- `127.0.0.1:8443`

That listener is not exposed directly to LAN peers, so remote collectors currently depend on the external HTTPS front path on `443`.

## Interpreted Weak Spots

- synchronous per-request event handling in the HTTP ingest batch path
- concurrent response latency under multi-host fan-out
- inability to use the local fast `8443` listener from other hosts because it is loopback-bound

## Code Landed In This Pass

To reduce ACK latency on batch ingest, the HTTP ingest service now processes request payloads in bounded parallel chunks through:

- `SIEM_INGEST_HTTP_BATCH_PARALLELISM`

The benchmark tooling was also hardened so it:

- supports configurable request timeout
- records stage failure instead of aborting the whole run on the first worker timeout

## Operational Conclusion

The current production bottleneck is not ClickHouse write verification and not the benchmark query step.

It is the collector-facing HTTP ingest acknowledgment path under concurrent fan-out.

## Next Tuning Options

1. Deploy the new bounded-parallel HTTP ingest path and rerun the distributed benchmark.
2. Decide whether LAN collectors should keep using `443` only, or whether a controlled internal collector listener should be exposed separately.
3. If ACK latency remains high, move more per-event health/metrics updates off the synchronous request path.
