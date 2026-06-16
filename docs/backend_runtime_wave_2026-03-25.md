# Backend Runtime Wave: 2026-03-25

## Scope

This wave closes four backend-only items:

- decomposition of `enterprise_control_plane.py`, `deps.py`, and `console.py`
- live host-runtime telemetry and correlation path
- response/SOAR runtime hardening
- docs export, runtime doc publishing, and smoke/test-data cleanup

## Decomposition State

### `enterprise_control_plane.py`

- access lifecycle moved into `control_plane_access_ops.py`
- connectors moved into `control_plane_connector_ops.py`
- cases/entities/risk moved into `control_plane_case_ops.py`
- response runtime moved into `control_plane_response_ops.py`
- content and saved searches moved into `control_plane_content_ops.py`
- health aggregation moved into `control_plane_health.py`

### `deps.py`

- platform/runtime wrappers moved behind `deps_platform_ops.py`
- docs/dashboards/builders wrappers moved behind `deps_runtime_docs_ops.py`
- public entrypoints remain stable while backend modules stop growing as one file

### `console.py`

- auth routes moved into `console_auth_routes.py`
- health routes moved into `console_health_routes.py`
- operations routes moved into `console_operations_routes.py`
- response routes moved into `console_response_routes.py`

## Host Runtime Telemetry

The host runtime pipeline is now meant to be live, not planned-only.

### Sources

- `deploy/host_runtime_agent.py`
- `deploy/host_runtime_monitor.py`
- `host_runtime_pipeline.py`
- `host_runtime_runtime.py`
- `correlation_rule_packs/host_runtime_observability_v1.json`

### Covered event families

- CPU pressure
- RAM pressure
- disk pressure
- load pressure
- swap thrash
- inode pressure
- stale telemetry
- service flapping
- storage pressure
- control-plane runtime pressure

### Operator truth

- `/api/health/overview`
- `/api/health/transport`
- host-runtime saved searches:
  - `host-runtime-pressure`
  - `host-telemetry-gaps`

## Response / SOAR Hardening

The response plane now supports more reliable recovery semantics:

- idempotency ledger remains active
- retry policy now treats partial failures as resumable
- response DLQ retains `resume_from_step` and `resume_payload`
- chained actions can resume from the failed step instead of replaying the whole sequence
- audit trail records per-step execution

## Docs And Cleanup

- machine-local docs export path: `C:\Users\Rdegon\Projects\siem_xfer_2026-03-25\siem_docs`
- export script: `deploy/export_siem_docs.py`
- runtime docs publishing script: `deploy/publish_runtime_docs.py`
- smoke/test-data cleanup script: `deploy/system_cleanup.py`

## Current Runtime Truth

- transport backend: `kafka`
- stream state backend: `sqlite`
- control-plane backend: `postgres`
- content backend: `mongo`
- Redis is retired from the live runtime path
