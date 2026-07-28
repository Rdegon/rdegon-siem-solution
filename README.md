# Rdegon Sentinel SIEM

Production source repository for the Rdegon Sentinel homelab SIEM/SOC platform.

The repository contains the web control plane, ingest and processing workers,
correlation rule packs, ClickHouse SQL seeds, deployment automation, frontend
shell, tests, and operator runbooks. It intentionally does not contain local
runtime state, exported artifacts, credentials, VM dumps, screenshots, or
benchmark output.

## Repository Map

| Path | Purpose |
| --- | --- |
| `services/web/` | FastAPI web control plane, app runtime modules, route handlers and server-rendered fallback templates. |
| `services/` | Runtime workers: ingest, normalizer, filter, writer, stream correlation, alert aggregation and transport helpers. |
| `frontend-react/` | React operator shell used by `/app/*`. |
| `correlation_rule_packs/` | Source-controlled detection and correlation rule packs. |
| `sql/` | ClickHouse schema/rule/catalog seed SQL. |
| `deploy/` | Deployment, smoke-test, publishing, benchmark, and operational scripts. |
| `ops/` | Production profiles and operator-side examples. |
| `query/` | Saved operational queries. |
| `tools/` | Developer and validation tools. |
| `tests/` | Unit and contract tests for runtime, deploy scripts, rules, and UI helpers. |
| `docs/` | Architecture, runbooks, operation records, and historical wave notes. |
| root | Repository metadata only: README, git policy files and import bootstrap. Runtime code lives under service folders. |

## Read First

1. [Documentation index](docs/README.md)
2. [Architecture](docs/architecture.md)
3. [Repository layout](docs/repository_layout.md)
4. [Deployment runbook](docs/deployment_runbook.md)
5. [Rule audit runbook](docs/rules_audit_runbook.md)
6. [Power recovery autostart](docs/power_recovery_autostart_2026-06-23.md)
7. [Full network segmentation plan](docs/full_segmentation_plan_2026-06-23.md)
8. [Deployed network cutover](docs/network_cutover_2026-07-25.md)
9. [SOC security inventory and target architecture](docs/soc_security_inventory_and_target_architecture_2026-07-25.md)
10. [Vulnerability and exposure management](docs/vulnerability_exposure_management_2026-07-26.md)
11. [Current home SOC production acceptance](docs/home_soc_acceptance_2026-07-28.md)

## Local Checks

Python focused tests:

```powershell
python -m pytest tests/test_transport_runtime.py tests/test_ingest_fabric.py tests/test_stream_worker.py tests/test_full_rule_audit.py tests/test_event_incident_query_stability.py tests/test_deploy_rollout_regressions.py tests/test_rule_noise_tuning.py
```

Frontend tests:

```powershell
cd frontend-react
npm ci
npm test
```

Repository hygiene gate:

```powershell
python tools/repo_hygiene_check.py
```

## Operational Boundaries

- Secrets are loaded from local operator environments, Vault, or host-local
  files. Do not commit credentials, generated VPN kits, `.env`, dumps, logs, or
  benchmark artifacts.
- Historical docs may mention old local paths as context. Current entry points
  are the files linked from this README and `docs/README.md`.
- The web/control-plane runtime source of truth is `services/web`. Compatibility
  for old flat imports is handled by `sitecustomize.py` and test/bootstrap path setup.
