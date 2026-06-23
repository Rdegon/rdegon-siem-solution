# Repository Layout

This repository is organized around runtime ownership rather than by file type.

## Current Layout

| Area | Ownership |
| --- | --- |
| root Python modules | Legacy FastAPI/control-plane runtime imported directly by existing deploy units. |
| root HTML templates | Legacy server-rendered compatibility views. |
| `services/` | Long-running ingest, normalizer, filter, writer-adjacent, alert aggregation and transport services. |
| `frontend-react/` | Current React shell for the operator UI. |
| `correlation_rule_packs/` | Human-reviewed rule-pack source of truth. |
| `sql/` | ClickHouse schema/rule/catalog seeds consumed by deploy publishers. |
| `deploy/` | Repeatable operational actions, rollout scripts, smoke checks, and publishing utilities. |
| `docs/` | Current runbooks plus dated historical wave records. |

## Why Some Runtime Files Still Live In Root

The web/control-plane runtime was originally deployed as a flat module set. Many
tests, service units and deploy scripts still import modules such as `deps`,
`enterprise_control_plane`, `writer_worker`, and `normalizer_core` by root module
name. Moving these files without a compatibility layer would create deployment
risk.

The correct future refactor is:

1. introduce an explicit package such as `app/` or `src/rdegon_siem/`;
2. add import shims for old module names;
3. update service units and deploy file mappings;
4. run contract tests and live smoke tests;
5. remove shims only after production rollout has proven stable.

Until that refactor is done, root runtime modules are considered intentional,
not disposable clutter.
