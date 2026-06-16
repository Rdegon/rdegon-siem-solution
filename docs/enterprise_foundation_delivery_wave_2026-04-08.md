# Enterprise Foundation Delivery Wave: 2026-04-08

This document records the single-pass enterprise uplift executed on `2026-04-08`.

It complements:

- `enterprise_market_gap_delivery_plan_2026-04-08.md`
- `project_closure_execution_plan_2026-03-26.md`

## Goal

Execute one pragmatic delivery wave on the current homelab stand that moves the platform toward enterprise maturity without replatforming:

- add memory headroom to the core VMs
- protect the current web deployment with rollback-ready backup
- land `content operations` and `rule-pack lifecycle`
- expand connector and telemetry governance
- land `UEBA v1`
- land `evidence graph v1`
- land `SOAR / playbooks` governance metadata
- land `compliance / reporting / governance` surfaces
- improve `UX / admin maturity`

## Web Backup And Rollback Readiness

Before changes were applied, a backup set was taken on `VM107 / siem-web`:

- `/var/backups/siem-web-backup-20260408T003743Z`
- `/var/backups/siem-web-backup-20260408T003743Z.tgz`

That snapshot includes:

- `/etc/siem`
- `/opt/siem/siem-solution`
- `/opt/siem/venv-web`
- relevant web service configuration

Proxmox VM configuration for `VM107` was also backed up into:

- `/var/backups/siem-vm107/107-<timestamp>.conf`

Rollback procedure for the web plane is therefore:

1. stop `siem-web` on `VM107`
2. restore the archived tree from `/var/backups/siem-web-backup-20260408T003743Z*`
3. restore VM configuration if required
4. start `siem-web` and verify `/auth/login` and `/app/dashboards`

## Infrastructure Changes

### Proxmox Memory Uplift

The following VM memory changes were applied in Proxmox and then activated inside the guests with controlled restart/start operations:

| VM | Role | Old RAM | New RAM |
| --- | --- | ---: | ---: |
| `104` | `siem-ingest` | `12 GiB` | `14 GiB` |
| `105` | `siem-processing` | `16 GiB` | `19 GiB` |
| `106` | `siem-storage` | `28 GiB` | `31 GiB` |
| `107` | `siem-web` | `12 GiB` | `14 GiB` |
| `108` | `siem-transport` | `12 GiB` | `14 GiB` |

Observed guest memory after activation:

- `VM104 / siem-ingest`: about `13.97 GiB`
- `VM105 / siem-processing`: about `18.99 GiB`
- `VM106 / siem-storage`: about `31.08 GiB`
- `VM107 / siem-web`: about `13.97 GiB`
- `VM108 / siem-transport`: about `13.97 GiB`

### Operational Note

`qm reboot` on this stand did not behave as a clean in-place reboot for every VM. On `VM104` and `VM107` it effectively resulted in a stopped guest that had to be started again. This is now an observed operational characteristic of the current Proxmox setup and should be treated as part of future maintenance procedure.

## Delivered Product Capabilities

## 1. Content Operations And Rule-Pack Lifecycle

Delivered in:

- `control_plane_content_ops.py`
- `console_operations_routes.py`
- `enterprise_control_plane.py`

What landed:

- normalized `content_bundles`
- normalized `saved_searches`
- explicit bundle lifecycle stages:
  - `draft`
  - `validated`
  - `staged`
  - `active`
  - `retired`
- quality-gate tracking:
  - `ci_status`
  - `validation_status`
  - `approval_status`
  - `signed`
  - `test_coverage_pct`
- save / promote bundle API:
  - `POST /api/content/bundles`
  - `POST /api/content/bundles/{bundle_id}/promote`

Current live result:

- `/api/content/bundles` returns `6` bundles on `VM4`

## 2. Connector Expansion And Telemetry Governance

Delivered in:

- `enterprise_control_plane_defaults.py`
- `control_plane_connector_ops.py`

What landed:

- additional enterprise connector templates:
  - `identity-provider-audit`
  - `endpoint-edr-stream`
  - `cloud-control-plane`
  - `mail-security-events`
  - `kubernetes-audit`
- telemetry contract on connector definitions:
  - `collection_depth`
  - `coverage_score`
  - `realtime`
  - `actor_ip_ready`
  - `entity_mapping_ready`
  - `host_telemetry_ready`
  - `event_families`
  - `evidence_fields`
  - `enrichment`
- operational governance on connector definitions:
  - `release_stage`
  - `bundle_id`
  - `owner`
  - `playbooks`
  - `compliance_controls`
- live backfill for legacy control-plane rows so old records do not zero-out new posture metrics

Current live result on `VM4`:

- connectors total: `11`
- enabled: `10`
- telemetry coverage average: `36.9`
- enterprise-ready connectors: `4`
- managed by bundle: `5`
- actor IP ready: `5`
- host telemetry ready: `2`
- evidence ready: `5`

## 3. UEBA v1

Delivered in:

- `control_plane_case_ops.py`

What landed:

- entity-level signal rollups
- baseline construction:
  - anomaly score
  - novelty score
  - privileged indicator
  - actor/source IP extraction
  - source-system extraction
- entity relationships:
  - linked sources
  - linked actor IPs
  - linked cases

Current live result:

- `/api/entities` now exposes:
  - `anomalous_entities`
  - `privileged_entities`
  - `graph_edges`

## 4. Evidence Graph v1

Delivered in:

- `control_plane_case_ops.py`

What landed:

- first evidence graph structure for entities
- node families:
  - entity
  - source
  - IP
- edge semantics:
  - `observed`
  - `acts_on`

This is intentionally `v1`: useful for investigations and UI framing, but not yet a full graph backend or path-analysis engine.

## 5. SOAR / Playbooks

Delivered in:

- `control_plane_response_ops.py`
- `enterprise_control_plane_defaults.py`

What landed:

- response actions now carry playbook metadata:
  - `playbook_class`
  - `governance_tier`
  - `evidence_contract`
  - `rollback_contract`
  - `compliance_controls`
- legacy response actions are backfilled from seed defaults instead of staying empty
- OpenVAS vulnerability actions were normalized into the same governance model

Current live result on `VM4`:

- actions total: `5`
- governed actions: `5`
- owner coverage: `100.0%`
- evidence contract coverage: `100.0%`
- rollback-ready coverage: `80.0%`
- compliance coverage: `100.0%`

## 6. Compliance / Reporting / Governance

Delivered in:

- `control_plane_response_ops.py`
- `control_plane_connector_ops.py`
- `enterprise_control_plane_defaults.py`

What landed:

- control-family mapping on connectors and playbooks
- compliance coverage metrics in response analytics
- governance coverage metrics in response analytics
- connector posture metrics and top-gap reporting

This is enough for an operator-grade governance surface on the current stand, but not yet a full auditor-facing compliance framework with evidence export packs.

## 7. UX / Admin Maturity

Delivered in:

- `frontend-react/src/shell/pages/ConnectorsPage.tsx`
- `frontend-react/src/shell/pages/EntitiesPage.tsx`
- `frontend-react/src/shell/pages/ResponsePage.tsx`
- `frontend-react/src/shell/pages/ControlPanelPage.tsx`
- `frontend-react/src/shell/api.ts`
- `frontend-react/src/shell/types.ts`

What landed:

- connectors surface now shows telemetry posture and lifecycle
- entities surface now shows baseline, evidence graph and hypotheses
- response surface now captures governance fields in editor flows
- control panel now exposes maturity-strip KPIs for content, connectors and response governance

## Live Validation

Local validation:

- `python -m pytest tests/test_enterprise_control_plane.py tests/test_response_maturity.py -q` -> `34 passed`
- `npm run typecheck` -> `pass`
- `npm run build` -> `pass`

Live validation on `VM4` after rollout:

- `POST /auth/login` with break-glass flow -> lands on `/app/dashboards`
- `/api/connectors/overview` -> `200`
- `/api/response/analytics?limit=20` -> `200`
- `/api/content/bundles` -> `200`
- `/api/entities` -> `200`

Live validation after memory activation:

- `siem-web` -> `active`
- `nginx` -> `active`
- `clickhouse-server` on `VM106` -> `active`
- `siem-kafka` on `VM105` and `VM108` -> `active`
- `siem-ingest` on `VM104` -> `active`

## What Is Realistically Achieved On The Current Stand

This wave proves that the current `5-VM` stand can support:

- enterprise-style content lifecycle metadata
- telemetry governance and connector maturity scoring
- first-pass UEBA
- first-pass evidence graph
- governed SOAR / playbook catalog
- admin-facing compliance and governance reporting
- moderate UI maturity improvements

## What Is Still Not Solved By This Wave

The following are intentionally not claimed as complete:

- true multi-tenant separation
- full-scale enterprise connector ecosystem
- production-grade graph database and attack-path analytics
- enterprise DR / multi-site failover
- large-volume DLQ remediation as a permanently self-healed closed loop

Operationally, one live issue remained after the infrastructure restart sequence:

- ingest `DLQ` backlog stayed elevated after restart and required manual replay to begin draining

That is an operations/runtime follow-up, not a blocker for the delivered enterprise control-plane capabilities.

## Recommended Next Step

The next focused follow-up should be:

1. automate bulk `DLQ` replay / suppression after restart
2. convert the new maturity metrics into hard release gates
3. deepen connector population so the new enterprise surfaces reflect more real telemetry families

