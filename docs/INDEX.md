# Documentation Index

Use this file as the map. Dated files are operation records; undated files are
current references unless noted otherwise.

## Core References

- `architecture.md` - platform architecture and data flow.
- `configuration.md` - runtime configuration model.
- `endpoints.md` - API and UI endpoint reference.
- `repository_layout.md` - repository structure and packaging constraints.
- `source_manifest.md` - source inclusion and exclusion policy.
- `deployment_runbook.md` - baseline deployment path.

## Detection And Rules

- `correlation_rules.md` - correlation authoring and publishing guide.
- `rules_audit_runbook.md` - rule audit procedure.
- `contour_audit_and_false_positive_remediation_2026-03-29.md` - FP cleanup wave.
- `incident_false_positive_remediation_2026-03-29.md` - incident noise remediation.
- `demo_attack_simulation_2026-05-24.md` - demonstration alert generation.

## Operations

- `power_recovery_autostart_2026-06-23.md` - current power recovery and guest autostart state.
- `full_segmentation_plan_2026-06-23.md` - target network segmentation plan.
- `network_cutover_2026-07-25.md` - deployed segmented-network cutover and validation.
- `soc_security_inventory_and_target_architecture_2026-07-25.md` - live security inventory,
  Suricata coverage and staged OPNsense/SOC target design.
- `vulnerability_exposure_management_2026-07-26.md` - non-duplicating vulnerability
  management, exposure prioritization, remediation and safe-validation runbook.
- `home_soc_platform_target_2026-07-26.md` - current home SOC inventory,
  non-duplicating target stack, service map and phased delivery order.
- `production_recovery_and_rule_calibration_2026-07-26.md` - current recovery,
  scanner placement, NDR backlog handling, rule calibration and validation record.
- `network_relocation_runbook_2026-06-23.md` - legacy relocation fallback notes.
- `live_service_placement_and_network_topology_2026-04-01.md` - service placement and topology.
- `network_segmentation_rollout_2026-04-01.md` - previous segmentation rollout record.
- `storage_rebalance_and_retention_hardening_2026-04-05.md` - storage and retention hardening.

## Performance

- `stock_eps_throughput_plan.md` - throughput implementation plan.
- `performance_eps_ladder_2026-05-23.md` - EPS ladder testing notes.
- `performance_eps_assessment_2026-03-26.md` - earlier EPS assessment.
- `eps_benchmark_2026-03-24.md` - benchmark procedure.

## UI And Product

- `ui_ux_system_audit_2026-03-27.md` - UI/UX audit.
- `ui_ux_followup_closure_2026-03-27.md` - follow-up closure.
- `app_section_guide_and_usability_2026-03-28.md` - operator section guide.
- `platform_finalization_and_app_redesign_2026-03-27.md` - app redesign wave.

## Source And Collector Work

- `collectors.md` - collector overview.
- `source_discovery.md` - source discovery flow.
- `windows_collection_strategy.md` - Windows collection strategy.
- `windows_linux_telemetry_expansion_2026-03-30.md` - telemetry expansion record.

## Historical Records

Most dated wave files are retained for traceability. They are not automatically
current operating procedure. Prefer the core references and current operations
runbooks above when there is a conflict.
