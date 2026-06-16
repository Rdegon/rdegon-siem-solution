# Rdegon SIEM Engineering Docs

## Source Of Truth

- code baseline: `C:\Users\Rdegon\Projects\siem_xfer_2026-03-25\repo`
- operator bundle: `C:\Users\Rdegon\Projects\siem_xfer_2026-03-25\access\operator_docs\OPERATOR_ACCESS_BUNDLE.md`
- authoritative access matrix: `C:\Users\Rdegon\Projects\siem_xfer_2026-03-25\access\operator_docs\SYSTEM_ACCESS_MATRIX.md`
- machine-local docs export: `C:\Users\Rdegon\Projects\siem_xfer_2026-03-25\siem_docs`
- machine-local clean bundle: `C:\Users\Rdegon\Projects\siem_xfer_2026-03-25\siem_project_bundle`

## Read First

1. `architecture.md`
2. `production_green_remediation_2026-03-26.md`
3. `production_certification_and_governance_closure_2026-03-26.md`
4. `platform_finalization_and_app_redesign_2026-03-27.md`
5. `live_rollout_verification_2026-03-27.md`
6. `proxmox_fleet_openclaw_wave_2026-03-28.md`
7. `pilot_sso_correlation_wave_2026-03-28.md`
8. `windowed_access_builders_wave_2026-03-28.md`
9. `builders_access_incident_bot_wave_2026-03-29.md`
10. `openclaw_incident_ai_telegram_wave_2026-03-29.md`
11. `contour_audit_and_false_positive_remediation_2026-03-29.md`
12. `windows_linux_telemetry_expansion_2026-03-30.md`
13. `ui_ux_system_audit_2026-03-27.md`
14. `app_section_guide_and_usability_2026-03-28.md`
15. `project_closure_execution_plan_2026-03-26.md`
16. `endpoints.md`
17. `sso_operations_and_external_integrations_2026-03-26.md`
18. `soar_response_hardening_2026-03-26.md`
19. `performance_eps_assessment_2026-03-26.md`
20. `deployment_runbook_vm4_enterprise_foundation.md`
21. `deployment_runbook_homelab_runners.md`
22. `host_runtime_observability_2026-03-22.md`
23. `storage_ha_operations_2026-03-25.md`
24. `vulnerability_maturity_2026-03-25.md`
25. `windows_collection_strategy.md`
26. `parallel_batch_correlation_design_2026-03-26.md`
27. `operator_cli_bundle_2026-03-25.md`
28. `correlation_rules.md`
29. `enterprise_market_gap_delivery_plan_2026-04-08.md`
30. `enterprise_foundation_delivery_wave_2026-04-08.md`

## Planning Baseline

For future tasking, the default execution baseline is:

- `project_closure_execution_plan_2026-03-26.md`

Closed slabs already documented:

- `production_certification_and_governance_closure_2026-03-26.md`
- `platform_finalization_and_app_redesign_2026-03-27.md`
- `live_rollout_verification_2026-03-27.md`

Latest post-closure expansion wave:

- `proxmox_fleet_openclaw_wave_2026-03-28.md`

Latest pilot SSO and correlation authoring wave:

- `pilot_sso_correlation_wave_2026-03-28.md`

Latest window-first UI and host-correlation wave:

- `windowed_access_builders_wave_2026-03-28.md`

Latest builders, access humanization, and incident-bot wave:

- `builders_access_incident_bot_wave_2026-03-29.md`

Latest OpenClaw incident-AI, Telegram, and source-coverage wave:

- `openclaw_incident_ai_telegram_wave_2026-03-29.md`

Latest contour audit, enrichment, and false-positive remediation wave:

- `contour_audit_and_false_positive_remediation_2026-03-29.md`

Latest Windows/Linux telemetry and detection expansion wave:

- `windows_linux_telemetry_expansion_2026-03-30.md`

Latest post-power-cycle ingest recovery closure:

- `post_power_cycle_ingest_recovery_closure_2026-04-01.md`

Latest storage rebalance and retention hardening wave:

- `storage_rebalance_and_retention_hardening_2026-04-05.md`

Current correlation authoring and publish guide:

- `correlation_rules.md`

Identity operations and external-app integration guidance:

- `sso_operations_and_external_integrations_2026-03-26.md`

Latest UI / UX evidence and follow-up audit:

- `ui_ux_system_audit_2026-03-27.md`

Latest section ownership and usability guide:

- `app_section_guide_and_usability_2026-03-28.md`

Separate diploma documentation pack:

- `docs/diploma/rdegon_siem_diploma_documentation_2026-03-28.md`
- `docs/diploma/README.md`

The older wave roadmap remains useful for history and context, but the closure plan is the active reference for accelerated project completion.

## TI / SOC / VOC Expansion Planning

- `ti_soc_voc_platform_plan_2026-04-01.md`
  - gap analysis, scope split, phased roadmap, and duration estimate for turning the current SIEM baseline into a full TI / SOC / VOC platform without replatforming the core runtime
  - use this document when the task is about strategic platform expansion rather than closure of the already-finished SIEM baseline

## Enterprise Market Gap Delivery Planning

- `enterprise_market_gap_delivery_plan_2026-04-08.md`
  - post-comparison implementation plan for closing the gap between the current stand and enterprise SIEM/SOAR leaders
  - explicitly answers what can be implemented on the current `5-VM` stand, what is only partially feasible, and what requires architecture change

## Latest Enterprise Foundation Delivery Wave

- `enterprise_foundation_delivery_wave_2026-04-08.md`
  - single-pass delivery record for enterprise uplift on the current stand
  - includes web backup paths, Proxmox memory uplift, live maturity metrics, and the exact feature set landed in `content`, `connectors`, `UEBA`, `evidence graph`, `SOAR`, `compliance`, and `admin UX`

## Latest Network Segmentation And Access Rollout

- `network_segmentation_rollout_2026-04-01.md`
  - live subnet split for `SIEM`, `user services`, and `vulnerability / security` services
  - dual-homing details for `VM104-108` and `CT120-121`
  - local DNS naming on `VM102`
  - jump-host `OpenVPN` routing changes and current external dependencies

## Current Service Placement And Topology

- `live_service_placement_and_network_topology_2026-04-01.md`
  - current host-to-service placement for all active platform nodes
  - current DNS names and segmented IPs
  - network topology of `mgmt`, `siem`, `users`, `vuln`, `OpenVPN`, and `VLESS` paths

## Latest Storage And Retention Hardening

- `storage_rebalance_and_retention_hardening_2026-04-05.md`
  - live guest redistribution across `Kingston` and `Toshiba` pools
  - Kafka retention limits for `VM104`, `VM105`, `VM108`
  - recurring cleanup timers for core nodes, Proxmox host, and pilot / fleet guests
  - root-cause record for the `Processing` / `Transport` post-restart disk-pressure incident

## Current Runtime Truth

- transport backend: `kafka`
- stream-state backend: `sqlite`
- control-plane backend: `postgres`
- content backend: `mongo`
- storage HA topology:
  - ClickHouse primary `VM3`, standby `VM5`
  - Postgres primary `VM4`, standby `VM1`
  - Mongo primary `VM4`, secondaries `VM1` and `VM5`
- host-runtime telemetry is live for all five Linux nodes
- Greenbone structured vulnerability import is live on `VM4`
- vulnerability operator actions are gated by `vuln:operate` for `admin` and `analyst`
- Proxmox-backed fleet inventory is live through `/api/sources/proxmox-fleet`
- OpenClaw full-metadata monitoring is live as a first-class fleet source
- pilot services `Gitea`, `PostgreSQL`, `Valkey`, and `Navidrome` are now represented in fleet monitoring and vulnerability coverage
- Builders now includes a dedicated correlation workspace backed by `correlation_rule_packs/*.json`
- scheduled vulnerability policy application is live through node-local `systemd` timer/service
- live human auth is `OIDC first` through Keycloak on `VM4`
- runtime secret backend is `Vault` on `VM4`
- primary operator shell surface for current work is `/app/*`
- `/app/access` is the live Keycloak identity control center
- operator-managed asset binding remediation is available through `/api/assets/binding-overrides*`
- `deploy-homelab.yml` is the standard production rollout path for `main`

## Production-Green Gates

The stand is considered green only when these are all healthy at the same time:

- `/api/health/overview`
- `/api/health/transport`
- `/api/health/backups`
- `/api/health/storage-ha`
- `/api/health/hosts/runtime`
- `/api/vuln/runtime`
- `/api/vuln/maturity`

Operational details for those gates live in the dedicated runbooks listed above.

## Important Notes

- Redis remains historical only; it is retired from the live ingest and processing path.
- The VM4 enterprise foundation deploy also owns the access-plane guardrails:
  - `openvpn-client@home-gateway`
  - `siem-jump-tunnels`
- Runner ownership is enforced operationally:
  - `siem-vm2` belongs only to `VM2`
  - `siem-vm5` belongs only to `VM5`
- Native Windows agent source now lives in:
  - `windows-event-agent/`
  - `deploy/windows-agent/`
  - `ops/windows-agent-profile.local.example.json`
- Runtime docs can be published into the document plane with `deploy/publish_runtime_docs.py`.
- Clean exports are produced with:
  - `deploy/export_siem_docs.py`
  - `deploy/export_clean_project_bundle.py`
- Legacy routes such as `/dashboards` remain compatibility surfaces; current operator UX work targets `/app/*`.
