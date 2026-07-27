# Web performance closure

Date: 2026-07-27.

## Root cause

The public edge and nginx were healthy. The latency came from synchronous
ClickHouse and platform inventory calls inside async route handlers:

- source and asset inventory each scanned about 23 million recent events;
- the combined asset catalog executed both scans sequentially;
- dashboard, geo, topology, threat-intel and health surfaces rebuilt large
  read models during user requests;
- four Uvicorn workers could therefore all wait on independent scans at the
  same time.

Before the correction, four parallel clients produced 32 timeouts among 76
GET APIs. Source and asset inventory took about 29 seconds each, and the
combined catalog took about 60 seconds.

## Changes

- blocking incident, event, inventory, health, dashboard and vulnerability
  calls run in Starlette's worker thread pool rather than the asyncio event
  loop;
- source and asset inventory use persistent stale-while-revalidate snapshots
  independent of the requested row limit;
- collectors are derived from the current source snapshot instead of running
  a second full ClickHouse inventory pass;
- dashboard, geo, topology, threat-intel, fleet, health and DLQ read models
  use atomic cross-worker caches with single-flight background refresh;
- the query package now lives in `services/web/app/query`, matching its
  ownership and import path instead of remaining as a root-level package;
- caches are prewarmed before a Web restart.

The runtime cache files are stored under `/opt/siem/runtime-docs`. They contain
derived operational data only. A stale value is returned while one worker
refreshes it; expired data is not served beyond the configured maximum stale
window.

## Acceptance

With four concurrent clients across all 75 parameter-free GET APIs:

| Metric | Result |
| --- | ---: |
| Successful APIs | 75/75 |
| Errors/timeouts | 0 |
| p50 | 0.253 s |
| p95 | 0.528 s |
| Maximum | 0.905 s |

Representative warm responses:

| Surface | Latency |
| --- | ---: |
| assets inventory | 0.08 s |
| combined assets catalog | 0.08 s |
| sources inventory | 0.05 s |
| incident list | 0.28 s |
| host runtime | 0.06 s |
| DLQ | 0.06 s |

The first uncached DLQ read remains about 5.2 seconds because it returns about
319 KiB of live data, but it no longer blocks unrelated requests and
subsequent responses use the 15-second cache.

## Validation

- `654` tests and `51` subtests passed;
- VM107 `siem-web`, nginx, Keycloak and related services remained active;
- public health, login, dashboards and authenticated API checks returned
  successfully after deployment.
