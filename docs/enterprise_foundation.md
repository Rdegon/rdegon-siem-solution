# Enterprise Foundation Slice

This document describes the `2026-03-12` enterprise foundation slice and the `2026-03-13` ingest-fabric runtime slice added on top of the existing Rdegon SIEM runtime.

## Scope

The original foundation slice focused on the web and control-plane layer. The follow-up ingest slice extends the edge on `VM1` and the React shell on `VM4` without re-platforming processing or ClickHouse storage.

## Backend Additions

New control-plane module:

- `enterprise_control_plane.py`

New runtime domains:

- `connector_definition`
- `connector_run`
- `service_account`
- `api_token`
- `case`
- `entity`
- `risk_signal`
- `response_action`
- `response_execution`
- `content_bundle`
- `saved_search`
- `audit_event`
- secret-readiness inventory
- aggregated health overview
- tamper-evident audit-chain verification
- backend-aware control-plane storage status

## Runtime Executors Added

Connector runtime now supports:

- `rest_pull` over HTTP or HTTPS with JSON parsing
- `sql_source` for sqlite polling
- `webhook_source` validation and event acceptance preview

Response runtime now supports:

- outbound `webhook`
- outbound `telegram`
- outbound `email`
- `approval_gate`

Approval-gated response executions can now be queued first and executed on approval instead of stopping at status tracking only.

Audit runtime now supports:

- append-only control-plane audit events
- hash chaining with previous-event linkage
- verification through `verify_audit_chain()`
- API exposure through `/api/audit/events`
- audit summary inside `/api/health/overview`

Access runtime now supports:

- service-account persistence in the control plane
- one-time API token issuance with hashed-at-rest token records
- token revocation
- token last-used tracking
- API authentication with machine tokens
- `/api/auth/me` for validating the current principal
- access-plane metrics inside `/api/health/overview`
- local-user password hashing with `pbkdf2_sha256`
- per-IP login rate limiting for `/auth/login`
- local-auth and rate-limit metrics inside `/api/health/overview.auth`

Control-plane storage now supports:

- `filesystem` mode as a snapshot/export backend
- `postgres` mode selected by `SIEM_CONTROL_PLANE_BACKEND`
- explicit migration from filesystem snapshots into Postgres
- safe fallback from `auto` to `filesystem` when Postgres is not configured
- API visibility through `/api/control-plane/storage`
- storage status inside `/api/health/overview`
- collection counts, migration state, and last migration timestamp

Stream-correlation runtime now supports:

- event-time or processing-time primary mode on `VM3`
- lateness and watermark control
- processing-time shadow comparison for event-time rollout validation
- timestamp fallback accounting when event timestamps are absent or invalid
- runtime status snapshots in ClickHouse for the VM4 health overview

Ingest runtime now supports:

- source heartbeat persisted in the Kafka-era ingest runtime state
- collector heartbeat persisted in the Kafka-era ingest runtime state
- dead-letter queue on the ingest runtime admin surface
- replay state on the ingest/runtime admin path
- partial acceptance for mixed-validity HTTP payload batches
- protected admin endpoints on `VM1` when `SIEM_INGEST_API_SHARED_SECRET` is configured
- `VM4` proxy APIs and native React visibility
- synthetic-emitter suppression for ingest health so smoke data no longer pollutes operational status

Source discovery runtime now supports:

- subnet scan for unmanaged LAN hosts
- candidate-source persistence on `VM4`
- port and banner capture
- OS and role inference
- onboarding recommendation generation
- prepared monitoring jobs
- dry-run execution for Linux-style SSH onboarding

Dashboard and investigation UX now supports:

- time-range controls for dashboard timelines
- adjustable bucket size and preview row count
- click-through from event and alert timeline spikes into `/app/events` and `/app/incidents`
- timezone-aware chart labels and incident timestamps
- wider incident queue limits

## API Additions

- `GET/POST /api/connectors`
- `GET /api/connectors/overview`
- `GET /api/connectors/{connector_id}`
- `POST /api/connectors/{connector_id}/run`
- `POST /api/connectors/{connector_id}/webhook`
- `GET /api/auth/me`
- `GET/POST /api/auth/service-accounts`
- `GET /api/auth/service-accounts/{service_account_id}`
- `GET /api/auth/service-accounts/{service_account_id}/tokens`
- `POST /api/auth/service-accounts/{service_account_id}/tokens`
- `POST /api/auth/service-accounts/{service_account_id}/tokens/{token_id}/revoke`
- `GET/POST /api/cases`
- `GET /api/cases/{case_id}`
- `POST /api/cases/{case_id}/comments`
- `POST /api/cases/{case_id}/tasks`
- `POST /api/cases/{case_id}/evidence`
- `GET /api/entities`
- `GET /api/entities/{entity_id}`
- `POST /api/entities/signals`
- `POST /api/entities/{entity_id}/promote`
- `GET/POST /api/response/actions`
- `GET /api/response/executions`
- `POST /api/response/actions/{action_id}/execute`
- `POST /api/response/executions/{execution_id}/approve`
- `GET /api/health/overview`
- `GET /api/ingest/overview`
- `GET /api/ingest/sources`
- `GET /api/ingest/collectors`
- `GET /api/ingest/dlq`
- `POST /api/ingest/dlq/replay`
- `GET /api/content/bundles`
- `GET/POST /api/search/saved`
- `GET/POST /api/lists/active`
- `GET /api/secrets/required`
- `GET /api/control-plane/storage`
- `GET /api/audit/events`
- `GET /api/openapi.json`
- `GET /api/sources/discovery`
- `POST /api/sources/discovery/scan`
- `POST /api/sources/discovery/{candidate_id}/prepare`
- `POST /api/sources/discovery/jobs/{job_id}/execute`

## Frontend Additions

React shell additions:

- `/app/connectors`
- `/app/entities`
- `/app/cases`
- `/app/ingest`
- `/app/access`
- richer `/app/dashboard`
- richer `/app/incidents`
- richer `/app/sources`

New page modules:

- `frontend-react/src/shell/pages/ConnectorsPage.tsx`
- `frontend-react/src/shell/pages/CasesPage.tsx`
- `frontend-react/src/shell/pages/EntitiesPage.tsx`
- `frontend-react/src/shell/pages/IngestPage.tsx`
- `frontend-react/src/shell/pages/AccessPage.tsx`
- `frontend-react/src/shell/pages/DashboardPage.tsx`
- `frontend-react/src/shell/pages/IncidentsPage.tsx`
- `frontend-react/src/shell/pages/SourcesPage.tsx`

Supporting shell changes:

- `frontend-react/src/shell/App.tsx`
- `frontend-react/src/shell/api.ts`
- `frontend-react/src/shell/context.tsx`
- `frontend-react/src/shell/DashboardCanvas.tsx`
- `frontend-react/src/shell/ui.tsx`
- `frontend-react/src/styles.css`

## Security And Secrets

- Secret-readiness endpoints only expose whether a required secret is configured, referenced, or missing.
- Secret values are never returned by the new API surface.
- Service-account tokens are returned only once at issuance time and are stored only as hashes afterward.
- The live `VM4` stand now stores only `pbkdf2_sha256` hashes for local web users in `/etc/siem/web.env`.
- The live `VM4` stand now verifies the `VM4 -> VM1` ingest certificate with a trusted CA file at `/etc/siem/tls/ingest-ca.crt`.
- Audit endpoints expose event metadata, chain state, and tamper-detection status only. Secret values are never copied into audit payloads.
- The current lab still stores live credentials in the internal access matrix. That is acceptable for this lab only and must be rotated before any production rollout.
- Production direction is to use `*_REF` environment variables or `vault://...` style references.

## Storage Model

The current slice stores control-plane objects as JSON files under:

- `services/web/app/runtime-control-plane/`

Override support:

- `SIEM_CONTROL_PLANE_DIR=/path/to/control-plane`
- `SIEM_CONTROL_PLANE_BACKEND=filesystem|auto|postgres`
- `SIEM_CONTROL_PLANE_PG_DSN=postgresql://...`
- `SIEM_CONTROL_PLANE_PG_TABLE=siem_control_plane_collections`

The live VM4 stand now uses `postgres` for the control plane after the `2026-03-20` cutover. Filesystem snapshots remain only as backup/export material and as the migration source for recovery.

The `2026-03-21` follow-up adds:

- filesystem snapshot migration reporting
- corrupt snapshot detection without silent reset
- live Postgres cutover tooling through `deploy/vm4_control_plane_postgres_cutover.py`

## Ingest Runtime Storage Model

The ingest slice now exposes runtime state through the Kafka-era ingest admin/runtime layer rather than Redis:

- ingest metrics runtime snapshot
- source heartbeat/runtime snapshot
- collector heartbeat/runtime snapshot
- DLQ backlog and replay state
- transport health with Kafka cutover state

## Validation

Local validation completed:

- `python -m py_compile enterprise_control_plane.py source_discovery.py security.py deps.py alerts.py console.py main.py deploy/vm4_enterprise_foundation_deploy.py deploy/vm4_enterprise_foundation_smoke.py`
- `python -m unittest discover -s tests -v`

Backend-specific validation completed locally:

- filesystem mode remains the default fallback
- a fake `psycopg` driver test covers Postgres-backed control-plane reads and writes
- filesystem snapshot migration into Postgres is covered by unit tests
- corrupt filesystem collections are reported instead of being silently replaced
- event-time stream correlation is covered for in-order, fallback, and runtime-status behavior

Deployment validation completed on `VM4`:

- deployed successfully on `2026-03-12`
- runtime-executor plus audit follow-up deployed again on `2026-03-13`
- optional Postgres-backed control-plane code path deployed on `2026-03-13` with filesystem still active on the stand
- backend compilation passed on the target host
- React build passed on the target host
- `siem-web` restarted successfully and reported `active`
- smoke checks passed for OpenAPI, enterprise APIs, control-plane storage API, audit API, connector dry-run runtime, response dry-run runtime, and `/app`
- smoke now also validates service-account issuance and a protected API call authenticated only by a freshly issued API token
- smoke now also validates control-plane migration fields and stream-correlation health telemetry

Deployment validation completed on `VM3` for the stream-correlation follow-up:

- deploy script updates `services/stream_corr/worker.py` and `/etc/siem/storage.env`
- runtime snapshots are written to `siem.stream_corr_runtime_status`
- smoke validates the reported `mode` and `shadow_compare` state after restart

Deployment validation completed on `VM1` and `VM4` for the ingest slice:

- deployed successfully on `2026-03-13`
- `siem-ingest` restarted successfully and reported `active`
- `siem-web` restarted successfully and reported `active`
- smoke checks passed on `VM1` for `/health`, `/health/overview`, `/health/sources`, `/health/collectors`, `/dlq/events`, and `/dlq/replay`
- smoke checks passed on `VM4` for `/api/ingest/overview`, `/api/ingest/sources`, `/api/ingest/collectors`, `/api/ingest/dlq`, `/api/health/overview`, and `/app`

The current rollout also targets:

- `/api/dashboard/summary` with time-window parameters
- `/api/incidents` with wider limits and time filters
- `/api/sources/discovery*`
- `/app/sources` discovery workflow

Operational validation is documented in:

- [deployment_runbook_vm4_enterprise_foundation.md](C:/Users/lolol/Documents/Playground/remote-edit2/docs/deployment_runbook_vm4_enterprise_foundation.md)
- [agent_handover_2026-03-12.md](C:/Users/lolol/Documents/Playground/remote-edit2/docs/agent_handover_2026-03-12.md)
