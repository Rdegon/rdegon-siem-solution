# Redis HA Resilience: 2026-03-22

Archive note: this document is historical. Redis is retired from the live runtime path and remains here only as migration and outage history.

## Summary

The Redis resilience slice is now live across the stand:

- `VM2` is the current Redis primary again
- `VM3` is the live Redis replica
- `VM2`, `VM3`, and `VM4` run `siem-redis-sentinel`
- `VM1`, `VM2`, and `VM3` runtime clients now resolve the active master through Sentinel and then open a normal Redis connection directly to that master

This closes the Redis stabilization block enough to move the transport roadmap forward toward Kafka instead of spending more cycles on basic Redis recoverability.

## What Changed

### 1. Sentinel quorum is live

- `redis-server` on `VM2` is configured as the intended primary
- `redis-server` on `VM3` is configured as the replica
- `siem-redis-sentinel` runs on `VM2`, `VM3`, and `VM4`
- UFW now explicitly allows:
  - Redis `6379/tcp` from the ingest, processing, storage, and web nodes
  - Sentinel `26379/tcp` not only between peer Sentinel nodes, but also from `VM1`, because the ingest edge is a Sentinel client too

### 2. Writer deploy mapping is corrected

The live `siem-writer` service executes:

- `/opt/siem/siem-solution/services/writer/worker.py`

The deploy script previously updated:

- `/opt/siem/siem-solution/writer_worker.py`

That mismatch meant the live writer never received the Sentinel-aware runtime changes. The deploy path now maps local [writer_worker.py](C:/Users/lolol/Documents/Playground/remote-edit2/writer_worker.py) to the real service entrypoint under `services/writer/worker.py`.

### 3. Redis runtime no longer depends on `redis-py` Sentinel master pools

The async `redis-py` Sentinel manager was too strict for the noisy homelab failover state and repeatedly rejected the active master even when `redis-cli SENTINEL get-master-addr-by-name` was already returning a valid result.

The shared runtime in [redis_runtime.py](C:/Users/lolol/Documents/Playground/remote-edit2/services/redis_runtime.py) now does this instead:

1. query Sentinel nodes for `SENTINEL get-master-addr-by-name <master>`
2. pick the first valid master address
3. create a normal async Redis client directly to that master

This preserves Sentinel-driven master discovery while removing the brittle dependency on `redis.asyncio.sentinel.Sentinel.master_for(...)`.

### 4. Smoke behavior is now HA-aware

[redis_ha_resilience_smoke.py](C:/Users/lolol/Documents/Playground/remote-edit2/deploy/redis_ha_resilience_smoke.py) now:

- tolerates short `activating` windows after HA restarts
- accepts either `VM2` or `VM3` as the active master as long as Sentinel and Redis replication agree
- validates fresh event flow in ClickHouse instead of only checking service liveness

### 5. Resilient Redis wrapper no longer crashes on keyword-based Redis API calls

The final outage after the Redis HA rollout was not another Sentinel failure. It was a runtime regression in the shared Redis wrapper:

- `ResilientAsyncRedis._call()` accepted the first argument as `name`
- Redis methods such as `xgroup_create(name=..., groupname=..., ...)` also pass `name` as a keyword
- that produced `TypeError: ResilientAsyncRedis._call() got multiple values for argument 'name'`

This crash-looped:

- `siem-normalizer`
- `siem-normalizer@2`
- `siem-filter`
- `siem-filter@2`

and stalled the whole `raw -> normalized -> filtered -> ClickHouse` path even though Redis itself was healthy again.

The wrapper now uses a non-conflicting internal parameter name and is covered by a regression test for keyword-based Redis calls.

## Root Causes Fixed

The outage after the first Redis HA cutover came from three separate issues at once:

1. `VM1` could not reach Sentinel on `26379`, so ingest health and HTTP/syslog pushes hung during master discovery.
2. `siem-writer` was never actually updated because deploy targeted the wrong remote file path.
3. `redis-py` Sentinel master discovery kept rejecting the live master in the noisy failover state even while raw Sentinel lookup already worked.

All three are now fixed in code and in the live stand.

The final live outage after that first recovery came from one more issue:

4. The new resilient Redis wrapper collided with Redis method signatures that also use `name=...`, which crash-looped the processing services on `VM2`.

That issue is now also fixed in code and on the stand.

## Live Validation

Latest successful Redis HA deploy backups:

- `/tmp/siem-redis-ha-backup-20260322T135420Z`
- `/tmp/siem-redis-ha-backup-20260322T140148Z`
- `/tmp/siem-redis-ha-backup-20260322T143723Z`

Latest successful VM3 event-time deploy backup after the final Redis-wrapper fix:

- `/tmp/siem-stream-corr-backup-20260322T143801Z`

Latest successful smoke result after the final recovery:

- `vm1_services=ok`
- `vm2_services=ok`
- `vm3_services=ok`
- `vm4_services=ok`
- `live_envs=ok`
- `sentinel_quorum=ok active_master=192.168.1.37`
- `replication=ok`
- `flow_events_5m=10399`
- `flow_alerts_5m=1835`
- `smoke=success`

Latest successful watchdog run after the final Redis-wrapper fix:

- `watchdog vm2_runner status=online busy=False`
- `watchdog counts_before events_5m=10594 alerts_5m=1835`
- `watchdog result=healthy`

Observed after the fix:

- `siem-writer` writes fresh batches into ClickHouse again
- `siem-stream-corr` can create or reuse its Redis consumer group again
- `siem-normalizer` and `siem-filter` no longer crash-loop on `xgroup_create(name=...)`
- `VM1 /health` no longer stalls on Redis discovery

## Operator Commands

### Deploy

```powershell
python C:\Users\lolol\Documents\Playground\remote-edit2\deploy\redis_ha_resilience_deploy.py
```

### Smoke

```powershell
python C:\Users\lolol\Documents\Playground\remote-edit2\deploy\redis_ha_resilience_smoke.py
```

### Current Redis master

```bash
sudo redis-cli -p 26379 --raw SENTINEL get-master-addr-by-name siem-master
```

Run it on `VM2`, `VM3`, or `VM4`.

### Replication role check

```bash
source /etc/siem/processing.env
redis-cli -h 127.0.0.1 -p 6379 -a "$SIEM_REDIS_PASSWORD" INFO replication
```

Run it on `VM2` and `VM3`.

### Event freshness

```bash
clickhouse-client --query "SELECT count(), max(ts) FROM siem.events WHERE ts >= now() - INTERVAL 5 MINUTE"
```

Run it on `VM3`.

## Remaining Redis-Adjacent Gaps

- warm-standby processing beyond one active processing node is still not complete
- Redis transport is now resilient enough to stop blocking release preparation, but Kafka remains the next architectural transport milestone
- a future transport migration should not remove the new event-flow smoke checks, because they caught the real outage faster than service-state checks alone
