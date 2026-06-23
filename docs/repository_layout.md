# Repository Layout

This repository is organized around runtime ownership rather than by file type.

## Current Layout

| Area | Ownership |
| --- | --- |
| root | Repository metadata, policy files and `sitecustomize.py` import bootstrap only. |
| `services/web/` | FastAPI web/control-plane service: `main.py`, `app/` runtime modules, routes, templates and maintenance jobs. |
| `services/writer/` | ClickHouse writer worker service. |
| `services/stream_corr/` | Stream correlation worker, settings, rules loader and logging setup. |
| `services/` | Long-running ingest, normalizer, filter, writer, stream-correlation, alert aggregation and transport services. |
| `frontend-react/` | Current React shell for the operator UI. |
| `correlation_rule_packs/` | Human-reviewed rule-pack source of truth. |
| `sql/` | ClickHouse schema/rule/catalog seeds consumed by deploy publishers. |
| `deploy/` | Repeatable operational actions, rollout scripts, smoke checks, and publishing utilities. |
| `docs/` | Current runbooks plus dated historical wave records. |

## Compatibility

The old development tree kept FastAPI/control-plane modules in the repository
root. The clean repository now keeps those modules under `services/web/app` and
workers under their service directories. `sitecustomize.py`, `tests/conftest.py`
and deploy path bootstraps keep old flat imports such as `import deps` working
while the runtime is rolled forward.

New code should use the service paths directly:

1. Web entrypoint: `services/web/main.py`.
2. Web runtime modules: `services/web/app/*.py`.
3. Web routes: `services/web/app/routes/*.py`.
4. Writer worker: `services/writer/worker.py`.
5. Stream correlation worker: `services/stream_corr/worker.py`.
