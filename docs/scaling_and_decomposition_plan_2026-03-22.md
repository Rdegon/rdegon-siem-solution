# Scaling And Decomposition Plan: 2026-03-22

This document captures the current platform shape, the most important remaining work, the biggest monoliths still in the tree, and an honest scaling assessment for the current five-VM SIEM stand.

## Update: 2026-03-26

Since the original draft:

- live transport moved to `kafka`
- storage/control/content HA baselines are live across `VM1-VM5`
- `console.py` route registration moved into `console_router_registry.py`
- default connector and response payload factories moved out of `enterprise_control_plane.py`
- inventory constants moved out of `deps.py`
- source onboarding runtime is now split into dedicated helpers
- vulnerability asset binding is now a dedicated module with source-inventory alias support

Remaining decomposition priorities after this pass:

- continue splitting query-heavy sections out of `deps.py`
- split response, auth, and content surfaces further away from `enterprise_control_plane.py`
- move ingest health / replay / metrics helpers into narrower modules
- keep `batch_corr` single-instance until overlap-safe parallel ownership is implemented

For execution ordering, this decomposition work is now tracked inside:

- `project_closure_execution_plan_2026-03-26.md`
- `production_certification_and_governance_closure_2026-03-26.md`

Within that plan, decomposition belongs to the `Platform Finalization` slab. `Production Certification` and `Identity, Secrets, Access, Governance` were closed for the current stand on `March 26, 2026`, so decomposition is now the active next slab unless a coverage-completion item is taken first for product reasons.

Safe parallel batch correlation planning now has a dedicated follow-up design document:

- `parallel_batch_correlation_design_2026-03-26.md`

## What Already Exists

### Live platform capabilities

- `VM1` ingest edge with HTTP, syslog, source heartbeat, collector heartbeat, DLQ, replay, and raw-stream pressure handling.
- `VM2` processing plane with Redis, Sentinel, `normalizer`, `normalizer@2`, `filter`, and `filter@2`, plus durable Redis AOF persistence.
- `VM3` storage and detection plane with ClickHouse, `writer`, `writer@2`, event-time stream correlation, batch correlation, alert aggregation, and SQLite-backed correlation runtime state.
- `VM3` now also has a dedicated ClickHouse memory-tuning deploy/smoke path and a fresh memory baseline review across `VM1-VM4`.
- `VM4` web/control-plane plane with FastAPI, React shell, Postgres-backed control-plane storage, Mongo-backed content/document storage, service accounts, API tokens, audit chain, docs, and deploy tooling.
- distributed GitHub Actions runner plane across `VM1`, `VM2`, `VM3`, and `VM4`.
- watchdog-based auto-heal for the most obvious `VM2` outage pattern through Proxmox guest control.

### What is now structurally scale-ready

- `normalizer` and `filter` workers already use Redis consumer groups.
- `writer` already uses Redis consumer groups.
- `stream_corr` already uses Redis consumer groups.
- the stream-correlation state backend is already decoupled from Redis and now runs on SQLite WAL.
- the web tier already separates UI/API from ingest, processing, and storage, so one web plane can front a larger backend fabric.

### What is still single-node in live production

- Redis processing bus: Sentinel-backed but still the active transport bus.
- ClickHouse analytics store: single primary on `VM3`.
- Postgres control-plane store: single primary on `VM4`.
- Mongo content/document store: single primary on `VM4`.
- Web/API plane: single primary `siem-web` on `VM4`.

## Biggest Remaining Engineering Work

### P0 reliability and architecture

1. Reduce `VM2` blast radius beyond restart repair:
   - warm standby or failover for processing workers;
   - replace Redis transport instead of deepening Redis dependency further.
2. Reduce transport fragility:
   - finish Kafka backbone for durable bus-level replay and consumer scaling;
   - complete dual-write/shadow validation and the final Redis removal.
3. Reduce single-node storage risk:
   - ClickHouse replication or warm standby;
   - Postgres backup and failover path;
   - Mongo backup and failover path.
4. Continue backend decomposition so one web does not depend on a few giant Python files.

### P1 maintainability and scale-out follow-up

5. Split the largest backend files into domain modules.
6. Split the largest UI files that are still acceptable but oversized.
7. Introduce standby or scale-out templates for more worker classes beyond `normalizer` and `filter`.
8. Move more deployment assumptions into repeatable code and runbooks.

## Biggest Monoliths Still In Tree

Measured on `2026-03-22`.

### Files

- `deps.py` — `5676` lines
- `enterprise_control_plane.py` — `2544`
- `frontend-react/src/styles.css` — `2390`
- `console.py` — `1786`
- `frontend-react/src/shell/pages/BuildersPage.tsx` — `1262`
- `normalizer_core.py` — `1224`
- `services/normalizer/normalizer_core.py` — `1224`
- `frontend-react/src/shell/types.ts` — `1062`
- `services/ingest/redis_client.py` — `721`
- `writer_worker.py` — `565`
- `source_discovery.py` — `562`
- `stream_worker.py` — `475`

### Biggest backend functions that should be split first

- `deps.py:2933` `fetch_geo_ip_detail()` — `175` lines
- `deps.py:1287` `fetch_alerts_agg()` — `145`
- `deps.py:2457` `fetch_source_inventory()` — `121`
- `deps.py:2004` `fetch_vulnerability_inventory()` — `102`
- `deps.py:4455` `update_alert_assignment()` — `101`
- `services/ingest/redis_client.py:393` `push_raw_event()` — `99`
- `services/ingest/redis_client.py:639` `replay_dlq_events()` — `91`
- `stream_worker.py:165` `run()` — `146`
- `enterprise_control_plane.py:698` `_default_connector_definitions()` — `167`

## Recommended Decomposition Order

### Backend first

1. Split `deps.py` into domain modules:
   - `events_queries.py`
   - `alerts_queries.py`
   - `assets_queries.py`
   - `geo_queries.py`
   - `threat_intel_queries.py`
   - `vuln_queries.py`
   - `cmdb_queries.py`
   - `dashboard_queries.py`
2. Split `enterprise_control_plane.py` into:
   - storage backend;
   - cases/entities/risk;
   - connectors runtime;
   - response runtime;
   - service accounts and tokens;
   - audit and health.
3. Split `console.py` route registration by domain.
4. Split `services/ingest/redis_client.py` into:
   - stream pressure;
   - source and collector health;
   - DLQ and replay;
   - overview and metrics.

### Frontend second

5. Split `frontend-react/src/styles.css` into shell, charts, tables, drawers, and responsive layers.
6. Split `BuildersPage.tsx` into editor, validation, catalog, and draft-management components.

## Honest Scaling Assessment

### Can one web front a larger backend?

Yes, to a point.

The current architecture already allows one `VM4` web/API plane to front:

- multiple ingest sources and source families;
- multiple processing consumers in Redis consumer groups;
- one ClickHouse storage plane;
- one Postgres control plane.

That means one web plane can realistically front a larger backend than the current lab, but it is still not an enterprise multi-region control plane.

### Can we raise multiple collectors?

Partly yes, today.

- We can already split collectors by protocol and source family at the ingest edge.
- We can also deploy more source-specific collectors and point them into the same Redis bus.
- The current limitation is not the React shell; it is that the ingest edge is still concentrated on `VM1`.

Recommended next step:

- split more ingest listeners and source families into separate services on `VM1` first;
- then prepare a second ingest edge when Kafka or replicated Redis arrives.

### Can we raise multiple parallel normalizers and filters?

Yes.

This is the safest part of the pipeline to scale horizontally because both stages already use Redis consumer groups.

As of this `2026-03-22` slice, the platform is moving from one consumer per stage toward scale-out processing workers instead of one singleton worker per transform step.

### Can we raise multiple parallel correlators?

Partly.

- `stream_corr` already uses Redis consumer groups, so multiple consumers are technically possible.
- `batch_corr` is not yet safely parallel because overlapping interval evaluation is still a design risk.
- `stream_corr` also still shares Redis-backed threshold state, so horizontal scale is possible but should be treated carefully until the correlation-state design is hardened further.

Recommended next step:

- scale `writer`, then `stream_corr`, with explicit ownership and duplicate-alert testing;
- keep `batch_corr` single-instance until overlap and idempotency are designed properly.

### Can we raise multiple databases and cores?

Not as true HA today.

- Redis is still single-primary live.
- ClickHouse is still single-primary live.
- Postgres control plane is still single-primary live.

We can scale compute workers more easily than we can scale the persistence layer today.

## Current scaling verdict

### What scales today with acceptable risk

- source count;
- source-family collectors on one ingest edge;
- `normalizer` consumers;
- `filter` consumers;
- likely `writer` consumers with controlled rollout;
- the React shell and FastAPI plane as a single control plane over a somewhat larger backend.

### What is only partly scale-ready

- `stream_corr` horizontal fan-out;
- ingest-edge fan-out across multiple nodes;
- one web plane over multiple storage backends.

### What is not yet real HA or enterprise scale

- Redis;
- ClickHouse;
- Postgres;
- batch correlation;
- full multi-node ingest failover.

## Next Architecture Milestones

1. Kafka + `VM5` release wave.
2. Warm-standby processing beyond one active `VM2`.
3. Writer and stream-correlation scale-out on the Kafka path.
4. `deps.py` and `enterprise_control_plane.py` domain split.
5. ClickHouse, Postgres, and Mongo standby or replica paths.
6. Host runtime telemetry plus correlation rules for CPU, RAM, disk, load, swap, inode pressure, and stale telemetry.
