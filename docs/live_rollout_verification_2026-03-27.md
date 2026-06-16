# Live Rollout Verification: 2026-03-27

## Purpose

This document records the actual `March 27, 2026` live rollout verification after the platform-finalization and `/app` redesign pass.

It exists because local green tests were not sufficient proof. The current authoritative close-out state requires:

- deploy validation on the live `VM1` to `VM5` stand
- post-deploy smoke on the live stand
- authenticated `/app/*` browser verification on the live `VM4` surface
- only then documentation and final git publication

## Deployment defect that blocked the live pass

Direct fact:

- the first real `VM4` deploy failed because `deploy/vm4_enterprise_foundation_deploy.py` did not ship all newly-landed runtime files and directories needed by the redesigned `/app` shell and the new decomposition layer
- the failure reproduced as missing `asset_binding_overrides` and later as missing `query` imports during runtime startup
- the same pass also exposed a remote `__pycache__` permissions issue during `py_compile` on `VM4`

Evidence:

- `deploy/vm4_enterprise_foundation_deploy.py`
- `docs/platform_finalization_and_app_redesign_2026-03-27.md`

## Fix applied for the live carrier

Direct fact:

- the VM4 deploy carrier now ships the new runtime modules and mirrored application paths required by the live web process
- the carrier now includes full directory mappings for:
  - `query/`
  - `services/web/app/query/`
  - `frontend-react/src/assets/`
  - `frontend-react/src/styles/`
  - `frontend-react/src/shell/pages/access/`
  - `frontend-react/src/shell/__tests__/`
- the remote compile step now uses `PYTHONPYCACHEPREFIX=/tmp/siem-pycache` so root-owned deploy trees do not fail during bytecode generation
- the remote validation subset now explicitly covers the Keycloak admin runtime and query-backed imports before service restart

Evidence:

- `deploy/vm4_enterprise_foundation_deploy.py`

## Live rollout sequence completed

Direct fact:

- `VM1`: ingest deploy and ingest smoke completed successfully
- `VM2`: processing deploy and processing smoke completed successfully
- `VM3`: storage / stream-correlation / memory-alignment deploys and smokes completed successfully
- `VM4`: enterprise foundation deploy and smoke completed successfully
- `VM5`: transport provision, transport wave deploy, and smokes completed successfully
- green-state waves were re-run after the per-node deploys:
  - storage HA
  - Kafka shadow
  - host runtime
  - VM4 security hardening
  - production certification
  - runtime docs publication

Evidence:

- `deploy/vm1_ingest_fabric_deploy.py`
- `deploy/vm1_ingest_fabric_smoke.py`
- `deploy/vm2_processing_resilience_deploy.py`
- `deploy/vm2_processing_resilience_smoke.py`
- `deploy/vm3_stream_corr_event_time_deploy.py`
- `deploy/vm3_stream_corr_event_time_smoke.py`
- `deploy/vm3_storage_memory_tuning.py`
- `deploy/vm3_storage_memory_smoke.py`
- `deploy/vm3_proxmox_memory_alignment.py`
- `deploy/vm3_proxmox_memory_smoke.py`
- `deploy/vm4_enterprise_foundation_deploy.py`
- `deploy/vm4_enterprise_foundation_smoke.py`
- `deploy/vm5_transport_provision.py`
- `deploy/vm5_transport_wave_deploy.py`
- `deploy/vm5_transport_wave_smoke.py`
- `deploy/storage_ha_wave_deploy.py`
- `deploy/storage_ha_wave_smoke.py`
- `deploy/kafka_shadow_wave_deploy.py`
- `deploy/kafka_shadow_wave_smoke.py`
- `deploy/host_runtime_wave_deploy.py`
- `deploy/host_runtime_wave_smoke.py`
- `deploy/vm4_security_hardening.py`
- `deploy/production_certification.py`
- `deploy/publish_runtime_docs.py`

## Live service-state verification

Direct fact:

- runner ownership is correct after the live rollout:
  - `VM2` runs only `actions.runner.Rdegon-siem-solution.siem-vm2.service`
  - `VM5` runs only `actions.runner.Rdegon-siem-solution.siem-vm5.service`
- `VM4` access-plane services are active:
  - `siem-web`
  - `siem-keycloak`
  - `siem-vault`
  - `openvpn-client@home-gateway`
  - `siem-jump-tunnels`

Evidence:

- live SSH checks against `192.168.1.37`, `192.168.1.39`, `192.168.1.40`
- `docs/architecture.md`

## Live runtime summary

Direct fact from authenticated runtime checks on `https://192.168.1.39`:

- `/api/health/overview` returned `issues=[]`
- `/api/health/certification` returned `healthy=true`
- latest certified ceiling remains `70 EPS`
- `/api/health/transport` returned healthy transport and healthy shadow status
- `/api/health/backups` returned `healthy=true`
- `/api/health/storage-ha` returned healthy ClickHouse, Postgres, and Mongo HA state
- `/api/health/hosts/runtime` returned `healthy=true` with `stale_targets=0`
- `/api/vuln/maturity` returned `ready_for_incident_policies=true` and `unmapped_targets_total=0`

Compact runtime snapshot captured after the rollout:

- overview generated: `2026-03-27T00:16:58Z`
- overview events in `5m`: `1012`
- overview alerts in `24h`: `391`
- certified ceiling: `70 EPS`
- certified p95 ingest latency budget target: `22000 ms`
- observed certification p95: `14714 ms`
- host runtime snapshots: `1490`

Evidence:

- `/api/health/overview`
- `/api/health/certification`
- `/api/health/transport`
- `/api/health/backups`
- `/api/health/storage-ha`
- `/api/health/hosts/runtime`
- `/api/vuln/maturity`

## Browser verification on live `/app/*`

Direct fact:

- authenticated Playwright verification succeeded on the live `VM4` shell
- no browser console errors were captured during the run
- the following live pages rendered and were captured:
  - `/app`
  - `/app/events`
  - `/app/incidents`
  - `/app/sources`
  - `/app/vuln`
  - `/app/builders`
  - `/app/access?tab=keycloak-users`
  - `/app/access?tab=keycloak-clients`
  - `/app/entities`
  - `/app/assets`
  - `/app/threat-intel`
- no horizontal overflow was detected on key pages at `1280x800` or `1024x768`

Artifacts:

- `../.artifacts/browser/live-audit/results.json`
- `../.artifacts/browser/live-audit/login-page.png`
- `../.artifacts/browser/live-audit/overview.png`
- `../.artifacts/browser/live-audit/events.png`
- `../.artifacts/browser/live-audit/incidents.png`
- `../.artifacts/browser/live-audit/sources.png`
- `../.artifacts/browser/live-audit/vuln.png`
- `../.artifacts/browser/live-audit/builders.png`
- `../.artifacts/browser/live-audit/access-users.png`
- `../.artifacts/browser/live-audit/access-clients.png`
- `../.artifacts/browser/live-audit/entities.png`
- `../.artifacts/browser/live-audit/assets.png`
- `../.artifacts/browser/live-audit/threat-intel.png`

## Final correction after the live recheck

Direct fact:

- the final verification pass caught two real live regressions and they were fixed before the close-out was accepted

Details:

- `VM1 ingest`: the service was running with `uvicorn --workers 4`, while each worker tried to bind the same syslog listener ports during startup; this made `siem-ingest` flap and caused `Ingest runtime unavailable: The read operation timed out` in `/api/health/overview`
- the runtime was corrected in `services/ingest/syslog_server.py` by enabling shared multi-worker binding for the syslog listeners, the regression was covered in `tests/test_ingest_syslog_transport.py`, `VM1` was redeployed, and `deploy/vm1_ingest_fabric_smoke.py` returned `smoke=success`
- `VM4 web shell`: the final recheck also caught a missing live frontend bundle at `/opt/siem/siem-solution/services/web/frontend-react/dist/index.html`, which caused `/auth/login` to redirect into `/app` and fail with `500`
- `VM4` was then redeployed with the full frontend build path enabled, `deploy/publish_runtime_docs.py` was rerun, and `deploy/vm4_enterprise_foundation_smoke.py` returned `smoke=success`
- authenticated Playwright verification was rerun after those corrections and refreshed the live `/app/*` evidence set in `../.artifacts/browser/live-audit/`
- the final live browser pass then exposed one more real frontend asset regression: the shell brand mark was still being resolved through a relative hashed SVG path, which the browser expanded to the site root and returned `404`
- the shell was corrected to use the canonical deployed path `/app/mark.svg`, the favicon path was aligned to `/app/favicon.svg`, the redesigned icon set was republished, and `deploy/vm4_enterprise_foundation_deploy.py` plus `deploy/vm4_enterprise_foundation_smoke.py` were rerun successfully
- authenticated Playwright verification was extended to cover the shared investigation pattern on `Events`, `Entities`, `Assets`, and `Threat Intel`, and the final live run completed without browser console errors or resource `404` values

## Final operator-facing hygiene correction

Direct fact:

- one more live correction pass was executed on `VM4` after the product-close rollout had already turned green
- this pass targeted remaining operator complaints rather than platform availability

Details:

- `Host Runtime` used two stacked control layers for time / refresh / rows; the duplicated secondary filter strip was removed so the page now uses one canonical control bar
- operator-facing `Sources` and `Assets` were still surfacing smoke / synthetic runtime residue such as `vm1-smoke` and `vm1-kafka-cutover`; the query layer now suppresses non-operational inventory records from those `/app/*` workspaces
- the live `Access` workspace was rechecked against the real Keycloak backend and the full create / list / delete cycle succeeded from `/app/access?tab=keycloak-users`
- VM memory pressure was rechecked directly on `VM1` to `VM5`; the earlier `90%+ used RAM` complaint was confirmed to be page-cache skew rather than real exhaustion, because `MemAvailable` remained healthy and swap usage stayed near zero on every node

Evidence:

- `query/shared.py`
- `query/sources.py`
- `query/assets.py`
- `frontend-react/src/shell/pages/HostRuntimePage.tsx`
- `tests/test_query_operational_filters.py`
- `../.artifacts/browser/live-final-pass-5/access-before.png`
- `../.artifacts/browser/live-final-pass-5/access-created.png`
- `../.artifacts/browser/live-final-pass-5/access-deleted.png`

## Final CI and ingest remediation loop

Direct fact:

- after the operator-hygiene corrections were committed, the exact `Validate Main` backend suite was rerun locally and exposed one last regression in the ingest DLQ visibility contract
- the regression was fixed before the final `main` push was allowed to proceed
- the live stand was then remediated and rechecked until both `VM1` ingest smoke and `VM4` foundation smoke were green again

Details:

- the failing backend test was `tests/test_ingest_runtime_state.py::test_dlq_listing_and_replay_metadata_work_with_sqlite_runtime_state`
- the root cause was an over-aggressive non-operational filter in `services/ingest/redis_client.py` that hid synthetic DLQ rows at the API layer instead of cleaning the live backlog itself
- the contract was restored so DLQ listing remains truthful unless an item is explicitly tagged with `operator_visibility=hidden`
- the same CI loop also exposed three GitHub-runner-specific backend problems that were invisible on the workstation:
  - `tests/test_frontend_brand_assets.py` assumed `frontend-react/dist/` already existed before the shell build stage
  - `services/filter/filter_core.py` hard-imported `clickhouse_driver`, which is not installed by the minimal backend dependency step
  - `deploy/vm2_processing_resilience_deploy.py` required a real local `bash` binary even in the synthetic fallback test case
- one follow-up `Validate Main` run exposed a fourth runner-only import issue:
  - `services/normalizer/normalizer_core.py` hard-imported `jmespath` and `clickhouse_driver`, even when the tested path only used builtin normalization with no loaded rules
- the next `Validate Main` run exposed one more import-time dependency leak:
  - `writer_worker.py` hard-imported `clickhouse_driver`, while the failing test only needed JSON normalization helpers and never initialized the live ClickHouse client
- those were corrected by making the brand-asset tests source/build-pipeline aware, making `filter_core` import-safe until ClickHouse-backed rule loading is actually invoked, and widening the portable `bash` fallback logic for the synthetic Windows-workstation test path
- `normalizer_core` now matches that import-safe model: the module is importable for unit tests and host-runtime roundtrip coverage, while `load_rules()` still fails loudly if live rule loading is attempted without `jmespath` or `clickhouse_driver`
- `writer_worker` now does the same: import stays cheap for unit tests, and `WriterWorker.init()` raises loudly only if a live runtime tries to initialize without the ClickHouse driver installed
- after the code fix, the full backend suite (`263` tests) passed locally again
- `VM1` was redeployed so the ingest runtime served the corrected DLQ listing behavior
- `VM4` was redeployed so the web/API layer picked up the same ingest-runtime contract
- the first post-deploy `VM4` smoke then failed on real ingest backlog, not on deployment: `DLQ outstanding=690` and parser-error-related overview issues
- the built-in ingest remediation path was executed through `deploy/vm4_enterprise_foundation_smoke.py` with `SIEM_SMOKE_REMEDIATE_INGEST_OVERVIEW_ISSUES=1`
- after remediation, `/health/overview` on `VM1` returned `issues=[]` and `dlq.outstanding=0`, while `VM4` smoke returned `smoke=success`
- the final correction was then pushed as `9882f1896dbbd0243547cca3aa5e540dd9e3f18a`
- GitHub Actions completed green on that exact `main` head:
  - `Validate Main` run `23654987740` -> `success`
  - `Deploy Homelab` run `23655094107` -> `success`
- `Watchdog Homelab` run `23655611425` -> `success`
- after those runs completed, the live stand was rechecked manually:
  - `deploy/vm4_enterprise_foundation_smoke.py` -> `smoke=success`
  - `deploy/vm1_ingest_fabric_smoke.py` -> `smoke=success`
  - a real OIDC analyst user completed a browser pass across `/app`, `/app/events`, `/app/incidents`, `/app/sources`, `/app/assets`, and `/app/vuln`
  - the browser pass produced `0` console/page errors after filtering transport noise and wrote artifacts to `../.artifacts/browser/live-user-final/`

## March 28 Vulnerability And Fleet Verification Addendum

Direct fact:

- the next post-closure operational wave exposed a real live `Vulnerability sync failed / Request failed: 403` defect on `/app/vuln`
- the failure was caused by the SIEM permission model, not by Greenbone connectivity itself

Details:

- `/api/vuln/sync`
- `/api/vuln/import`
- `/api/vuln/policies/apply`

were guarded by `resources:write`, while the `Vulnerability` section granted visibility without a dedicated operator permission for scanner actions

The fix:

- introduced `vuln:operate`
- granted it to `admin` and `analyst`
- updated the backend gates and the `/api/ui/bootstrap` effective permission payload
- updated `/app/vuln` so operator buttons match real backend authorization

The same wave then restored the full live structured scanner path:

- Greenbone probe `ok`
- target sync `ok`
- report import `ok`
- policy apply `ok`
- `/api/reports` switched back to structured Greenbone-first results
- `/api/vuln/runtime` and `/app/vuln` showed healthy fleet-aware coverage

The live stand was rechecked after the final fixes:

- `deploy/vm1_ingest_fabric_smoke.py` -> `smoke=success`
- `deploy/proxmox_fleet_wave_smoke.py` -> `smoke=success`
- `deploy/vm4_enterprise_foundation_smoke.py` -> `smoke=success`
- `/api/health/overview` -> `issues=[]`
- `/api/vuln/runtime?days=14` -> `healthy=true`

Fresh browser verification for that exact wave was captured in:

- `../.artifacts/browser/live-vuln-fleet-ui-2026-03-28/`

including:

- `overview.png`
- `sources-fleet.png`
- `vuln.png`
- `events.png`
- `assets.png`
- `access.png`
- `entities.png`

This addendum is still part of the same production-green rule:

- code change
- live deploy
- live smoke
- authenticated browser verification
- documentation
- only then git publication

## Post-Closure Expansion Reference

The next live expansion wave was executed on `March 28, 2026` without reopening any closure slab.

That wave is documented separately in:

- `proxmox_fleet_openclaw_wave_2026-03-28.md`

It records the live Proxmox-backed fleet inventory, OpenClaw full-metadata monitoring, OpenVAS-first fleet coverage, pilot-service rollout, and refreshed `/app/*` screenshot set in:

- `../.artifacts/browser/live-proxmox-openclaw-wave/`

## Final deploy-gate correction on March 28

Direct fact:

- one more GitHub `Deploy Homelab` gate failed after the Proxmox/OpenClaw wave, even though the node deploy jobs themselves were already green
- the remaining blocker was not rollout drift, but a false-red ingest freshness signal for a passive `network` syslog collector path

Details:

- the failing deploy job was `deploy-green-state` inside `Deploy Homelab`
- the only blocking issue was `Stale collectors detected: 1`
- live inspection showed the stale row was the passive collector entry:
  - `id=network`
  - `collector=syslog_tcp`
  - `collector_profile=network`
- the runtime was still evaluating that passive network listener against the default ingest freshness thresholds
- `services/ingest/redis_client.py` was corrected so `network` / `syslog_tcp` inventory is classified as `Network` and uses relaxed freshness thresholds
- the fix keeps the collector visible in `/api/ingest/collectors` and `/app/*`, but it now becomes `delayed` instead of falsely blocking green-state as `stale`
- the regression was covered in `tests/test_ingest_fabric.py`
- after the fix was synced to the live VM1 runtime path under `/opt/siem/siem-solution/services/ingest/redis_client.py`, the direct ingest runtime and the aggregated `/api/health/overview` stopped reporting stale collectors
- `deploy/vm4_enterprise_foundation_smoke.py` then completed successfully again with ingest remediation enabled

Evidence:

- `services/ingest/redis_client.py`
- `tests/test_ingest_fabric.py`
- `deploy/vm4_enterprise_foundation_smoke.py`
- `deploy/vm1_ingest_fabric_smoke.py`

Direct fact:

- after that fix, the next deploy gate exposed one more real false-red condition in production certification rather than in the node rollout itself

Details:

- `Deploy Homelab` then failed because `/api/health/certification` still carried `vm2_probe_failed:[Errno None] Unable to connect to port 22 on 192.168.1.37`
- live verification immediately afterward proved `VM2` SSH and the `siem-vm2` runner were both healthy
- the failure source was a one-shot runner-plane probe inside `deploy/production_certification.py`; a single transient SSH connection error was enough to poison the saved certification status
- `deploy/production_certification.py` was hardened with retry logic for the `VM2` and `VM5` runner-plane SSH probes
- the retry behavior was covered in `tests/test_certification_runtime.py`
- the certification run was then re-executed against the live stand, the updated certification status was republished on `VM4`, and `/api/health/certification` returned `healthy=true` again
- `deploy/vm4_enterprise_foundation_smoke.py` was rerun after the republish and completed successfully

Evidence:

- `deploy/production_certification.py`
- `tests/test_certification_runtime.py`
- `/api/health/certification`
- `deploy/vm4_enterprise_foundation_smoke.py`

## Final UI, access, memory, and external SSO closure

Direct fact:

- the final one-pass closure then extended the live proof set beyond shell rendering and into live access management, memory truthfulness, and external OIDC

Details:

- `/app/access` was verified against the live Keycloak admin runtime, not mocked data
- a real operator browser flow created a Keycloak user from `/app/access?tab=keycloak-users`
- the same flow added system access through the popup selector for:
  - `siem`
  - `nextcloud`
- `proxmox` was confirmed absent from the grantable system selector and remains `monitored-only`
- the ordinary OIDC user then logged into the live `/app` shell and rendered:
  - `/app`
  - `/app/events`
  - `/app/assets`
  - `/app/entities`
  - `/app/threat-intel`
  - `/app/host-runtime`
- the same live user then logged into `Nextcloud` through the landed Keycloak OIDC client
- the temporary verification identities were removed afterward from both Keycloak and Nextcloud
- `Host Runtime` and health surfaces were revalidated after the memory-truth and tuning pass:
  - `pressure_targets=0`
  - `stale_targets=0`
  - swap remained near zero across the stand
- `VM3` storage-memory and Proxmox-memory smokes were rerun on the actual storage node `192.168.1.38` and both returned `smoke=success`
- the current Nextcloud build required a compatibility patch for the installed `user_oidc` app on `Nextcloud 29.0.4.1`; that fix is now encoded in `deploy/nextcloud_oidc_rollout.py` and no longer exists only as a one-off manual hotfix
- `Greenbone/OpenVAS` native SSO was explicitly left unsupported on the current build, so it remains a scanner backend and not a grantable system in `/app/access`

Evidence:

- `docs/ui_access_memory_closure_2026-03-27.md`
- `deploy/nextcloud_oidc_rollout.py`
- `../.artifacts/browser/live-one-pass-final/results.json`
- `../.artifacts/browser/live-one-pass-final/access-admin.png`
- `../.artifacts/browser/live-one-pass-final/nextcloud.png`
- `../.artifacts/browser/live-one-pass-final/access-delete-check.json`

Evidence:

- `services/ingest/redis_client.py`
- `services/filter/filter_core.py`
- `services/normalizer/normalizer_core.py`
- `writer_worker.py`
- `deploy/vm2_processing_resilience_deploy.py`
- `tests/test_frontend_brand_assets.py`
- `tests/test_ingest_runtime_state.py`
- `deploy/vm1_ingest_fabric_smoke.py`
- `deploy/vm4_enterprise_foundation_smoke.py`
- `https://192.168.1.35/health/overview`
- `../.artifacts/browser/live-user-final/overview.png`
- `../.artifacts/browser/live-user-final/events.png`
- `../.artifacts/browser/live-user-final/incidents.png`
- `../.artifacts/browser/live-user-final/sources.png`
- `../.artifacts/browser/live-user-final/assets.png`
- `../.artifacts/browser/live-user-final/vuln.png`

## Outcome

Direct fact:

- the platform-finalization pass is now backed by a real live rollout, not only local validation
- the standard live stand on `VM1` to `VM5` is green after deploy, smoke, certification, and runtime-doc publication
- this document is the operational proof layer that was missing from the earlier close-out claim

## What remains after this verification

No core slab remains open for the current stand.

Remaining work is post-closure expansion only:

- external SSO client rollout for systems beyond the already-landed `Nextcloud`
- supportability revalidation for a native `Greenbone/OpenVAS` SSO path if the installed build or support path changes
- broader vendor expansion beyond the current supported Windows and managed network scope
- deeper decomposition and scale-out beyond the pragmatic close layer
- a higher-maturity UI system follow-up driven by the separate `March 27` UX audit

## Windowed access, builders, and host-correlation follow-up

Direct fact:

- the next live follow-up pass extended the correlation catalog for `Windows` and `Linux`, moved `Access` and `Builders` deeper into a side-window operator model, and added an explicit shell logout control

Details:

- `correlation_rule_packs/windows_activity_v1.json` and `correlation_rule_packs/linux_activity_v1.json` were added to the live publish set
- `deploy/publish_operational_rule_packs.py` now publishes both packs during the standard operational rollout
- the `VM4` deploy published a live total of `48` active stream rules after the follow-up wave
- `/app/access` now opens user, group, role, client, recovery, and service-account editors in side windows rather than leaving large inline editors expanded
- `/app/builders?workspace=correlation` now keeps page-level summaries compact and routes detailed pack, rule, and lifecycle work into dedicated side windows
- the shell top bar now exposes a direct `Logout` button wired to `/auth/logout`
- live browser verification on `VM4` confirmed:
  - `Access` user window opens and renders correctly
  - `Builders` correlation workspace renders the new `Windows` and `Linux` packs
  - `Builders` pack window opens without console errors
  - browser console errors remained `0`
- `deploy/vm4_enterprise_foundation_smoke.py` completed successfully after the same rollout

Evidence:

- `docs/windowed_access_builders_wave_2026-03-28.md`
- `frontend-react/src/shell/App.tsx`
- `frontend-react/src/shell/pages/access/AccessWorkspace.tsx`
- `frontend-react/src/shell/pages/BuildersPage.tsx`
- `frontend-react/src/styles/shell.css`
- `correlation_rule_packs/windows_activity_v1.json`
- `correlation_rule_packs/linux_activity_v1.json`
- `deploy/publish_operational_rule_packs.py`
- `../.artifacts/browser/windowed-ui-2026-03-28/overview-windowed.png`
- `../.artifacts/browser/windowed-ui-2026-03-28/access-user-window.png`
- `../.artifacts/browser/windowed-ui-2026-03-28/builders-correlation.png`
- `../.artifacts/browser/windowed-ui-2026-03-28/builders-pack-window.png`
