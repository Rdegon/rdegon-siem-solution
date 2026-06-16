# Contour Audit And False-Positive Remediation

Date: `2026-03-29`  
Scope: `public/VPN contour + internal SIEM contour`

## Goal

One-pass audit and remediation of the monitored stand to:

- improve source coverage and enrichment quality
- suppress confirmed false positives
- prevent false positives from reaching Telegram
- add host context to Telegram incident notifications
- verify that there is no confirmed external compromise across the two active contours
- restore honest green-gate health for transport shadow and connector hygiene

## What Changed

### Event quality and enrichment

- `runtime_humanization.py` was rewritten in clean UTF-8 and now repairs mojibake before label selection.
- Host and asset labels are humanized for common live objects, including:
  - `vpn-host-khanov`
  - `vm15611031`
  - `siem-web`
  - `siem-processing`
  - `openclaw-gateway`
- Incident aggregation now carries richer host context through `deps.py`:
  - `hosts`
  - `host_labels`
  - `host_summary`
  - `raw_hits_total`
- Telegram messages now include explicit host context and avoid sending confirmed false positives.

### False-positive suppression

Filter and batch-correlation logic were tightened to suppress expected operational noise from:

- OpenClaw research and proxy/runtime chatter
- OpenClaw internal syslog reconnect noise
- expected Greenbone scanner SSH probes from `192.168.1.29`
- expected SIEM operational `sudo` and deploy activity
- selected host pressure and service-noise families already confirmed as false positives

Files updated for this layer:

- `normalizer_core.py`
- `services/normalizer/normalizer_core.py`
- `sql_12_filter_rule_seed.sql`
- `sql_13_batch_corr_seed.sql`
- `sql_15_batch_corr_soc_seed.sql`

### Telegram delivery hardening

`services/incident_telegram_bot.py` now:

- renders clean Russian text
- includes `Статус`, `Ответственный`, `События`, `Хосты`, `Обновлено`
- skips incidents marked `false_positive`

Live bot smoke after remediation confirmed delivery state `sent` for valid alerts and `skipped` for false positives during the remediation loop.

### Shadow transport health fix

Transport shadow health was green in the data plane but red in the health surface because the web layer picked the wrong comparison basis.

Fixes:

- `clickhouse_runtime.py` now exports shadow-specific metrics per node:
  - `shadow_table_exists`
  - `shadow_events_5m`
  - `shadow_events_15m`
  - `shadow_latest_event_epoch`
  - `shadow_query_error`
- `deps.py` now prefers the freshest shadow-capable ClickHouse node and compares shadow counts against that node's main counters instead of a cluster-wide max that may belong to a different node.

Result:

- `/api/health/transport` -> `healthy=true`
- `/api/health/overview` -> `issues=[]`

### Connector hygiene fix

Residual connector error for `greenbone-openvas-import` was caused by a stale legacy connector definition:

- historical `block_type=rest_pull`
- no `runtime.request.url`
- last recorded error persisted in connector overview even though live vulnerability integration was already working

Fixes:

- `enterprise_control_plane_defaults.py`
  - `greenbone-openvas-import` now defaults to `block_type=vuln_runtime`
  - default runtime operation is `sync_import`
- `control_plane_connector_ops.py`
  - legacy `greenbone-openvas-import` definitions are auto-normalized from invalid `rest_pull` to `vuln_runtime`
  - old URL-related error state is cleared during normalization
  - new `vuln_runtime` connector executor validates and runs the actual vulnerability runtime path

Result:

- `/api/connectors/overview` has no `error` connectors

## Contour Audit Summary

### Public / VPN contour

Sampled indicators reviewed during the pass included:

- public exposure around `45.89.111.208`
- VPN-related host and TI-linked assets
- externally visible app and scanner-adjacent events

Findings:

- blocked and noisy external activity was observed
- no confirmed successful external compromise was identified in the sampled evidence reviewed during this remediation pass
- TI hits tied to VPN-facing assets remain open for analyst review where they still correlate to meaningful host evidence

### Internal SIEM contour

Sampled indicators reviewed during the pass included:

- SIEM-host operational `sudo` and deploy activity
- internal SSH/admin traffic
- Greenbone scanning traffic
- OpenClaw research and runtime telemetry

Findings:

- a large portion of prior alert volume in this contour was operational noise, not attacker behavior
- expected internal admin activity was preserved but de-noised
- no confirmed internal compromise was identified in the sampled evidence reviewed during this remediation pass

## Confirmed False-Positive Families Suppressed

During this pass, confirmed false-positive families were either reclassified or filtered so they no longer pollute incident triage and Telegram:

- OpenClaw reconnaissance/syslog/linux DNS query noise
- OpenClaw proxy/runtime reconnect chatter
- expected Greenbone scanner SSH probes
- `nextcloud-siem` host load pressure noise
- `navidrome-01` host load pressure noise
- operational `sudo` clusters on `siem-processing` and `siem-web`

## Remaining Open Clusters Requiring Human Review

The following live families still deserve analyst attention and were not auto-closed in this pass:

- `Threat Intel Hit On Critical Asset` on VPN-facing assets
- `Host Service Flapping` on `siem-processing`
- `Linux System Recon Burst` on `vm15611031`
- `Linux Systemd Unit Modified` on `vm15611031`
- `Linux Sudo To Root Burst` on `pilot-db-01`
- `Repeated External App Authentication Failures` on `navidrome-01`

These were left open intentionally because the available evidence was not strong enough to auto-classify them as false positives.

## Verification

Local verification:

- `python -m py_compile ...` for the touched runtime/test files
- `python -m pytest`
  - `tests/test_clickhouse_runtime.py`
  - `tests/test_deps_transport_shadow_status.py`
  - `tests/test_transport_health_runtime.py`
  - `tests/test_incident_telegram_bot.py`
  - `tests/test_service_normalizer_core.py`
  - `tests/test_runtime_humanization.py`
  - `tests/test_enterprise_control_plane.py`

Live verification:

- `deploy/vm4_enterprise_foundation_deploy.py` -> `deployment=success`
- `deploy/vm4_enterprise_foundation_smoke.py` -> `smoke=success`
- `deploy/vm1_ingest_fabric_smoke.py` -> `smoke=success`
- `deploy/pilot_db_incident_bot_smoke.py` -> `healthy=true`

Live API state after deploy:

- `/api/connectors/overview`
  - `error connectors = 0`
- `/api/health/overview`
  - `issues = []`
- `/api/health/transport`
  - `healthy = true`
  - `shadow_pipeline_status = healthy`
- `/api/vuln/runtime`
  - `healthy = true`

## Operational Outcome

After this pass the stand has:

- richer host context for investigations and Telegram notifications
- materially less operational noise in incidenting
- false positives blocked from Telegram delivery
- cleaner separation between genuine review candidates and expected platform behavior
- more honest transport-shadow and connector health signals

This pass improves alert quality and incident readability, but it does not replace human review for the remaining VPN-facing TI and auth-abuse clusters.
