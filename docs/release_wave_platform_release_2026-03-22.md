# Release Wave: Platform Release Path (3-4 Week View)

This note groups the next two large delivery slices into a single release-oriented view. The goal is to minimize passes and move the product toward a more serious release posture instead of continuing with isolated tactical fixes.

## Slice 1: Kafka Backbone + VM5 + Redis Exit

This is the next largest infrastructure wave.

### Scope

- provision `VM5` as the additional transport and warm-standby processing node
- build Kafka KRaft on `VM1 + VM2 + VM5`
- move ingest from Redis-only into dual-write and then Kafka-only
- move `normalizer` and `filter` to Kafka consumer groups on `VM2 + VM5`
- move `writer` to Kafka consumer groups
- keep `stream_corr` single-active on `VM3`, but fed from Kafka instead of Redis
- remove Redis from the live data plane after the green window

### Why This Comes First

Right now the stand is much more stable than before, but the live data plane still depends on Redis-era assumptions. To get closer to release posture, the platform needs:

- a more durable transport backbone
- cleaner replay semantics
- safer scale-out for processing
- less coupling between `VM1`, `VM2`, and `VM3`

### Exit Criteria

- `VM2` loss does not stop ingest-to-ClickHouse flow while `VM5` is healthy
- green `watchdog`, `validate-main`, and `deploy-homelab`
- event and alert parity validated across the shadow window
- Redis removed from the live transport path
- repo-owned KRaft topology, VM5 processing prepare artifacts, and transport-health surfaces are already in place before the live install cutover starts

## Slice 2: Storage / Control-Plane HA + Backend Decomposition

This is the follow-up wave immediately after Kafka cutover.

### Scope

- prepare ClickHouse replica or warm-standby storage topology
- add Postgres standby / backup hardening for the control plane
- break the largest backend monoliths by domain
- improve platform observability around storage, lag, memory, and failover

### First Decomposition Targets

- `deps.py`
- `enterprise_control_plane.py`
- `console.py`

The goal is not a cosmetic refactor. The goal is to make the backend maintainable enough for the storage and HA layer to keep growing without every change touching the same giant modules.

### Exit Criteria

- storage HA plan is implemented or at least fully deployable from the repo
- control-plane backup and failover posture is clearer and less manual
- the main backend data-access monoliths are split along domain boundaries
- new observability endpoints and runbooks match the live topology
- Mongo content migration state and SQLite runtime-state offsets are already visible through the health and storage APIs before the HA cutover work starts

## Why These Two Slices Belong Together

These are the two highest-leverage release blocks left:

1. transport and processing resilience
2. storage, control-plane, and maintainability resilience

Doing them as one coordinated wave reduces repeated migrations, repeated docs drift, and repeated operator retraining.

## What Comes Immediately After

Once those two waves are green, the next four large slices are:

3. `host telemetry + runtime observability correlation`
4. `identity, secrets, and enterprise access maturity`
5. `response / SOAR hardening`
6. `release hardening and certification`

The detailed six-wave backlog now lives in:

- [release_wave_backlog_2026-03-22.md](C:/Users/lolol/Documents/Playground/remote-edit2/docs/release_wave_backlog_2026-03-22.md)
