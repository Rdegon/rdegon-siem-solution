# Rdegon SIEM Documentation

This directory contains current engineering references, operational runbooks,
and dated delivery records for the SIEM platform.

## Start Here

1. `INDEX.md` - categorized documentation map.
2. `architecture.md` - architecture and data flow.
3. `repository_layout.md` - why the repository is shaped this way.
4. `deployment_runbook.md` - baseline deployment procedure.
5. `rules_audit_runbook.md` - rule audit and false-positive workflow.
6. `power_recovery_autostart_2026-06-23.md` - current autostart/power recovery state.
7. `full_segmentation_plan_2026-06-23.md` - target segmented network design.
8. `network_cutover_2026-07-25.md` - deployed addresses, OPNsense status and validation.
9. `soc_security_inventory_and_target_architecture_2026-07-25.md` - security inventory
   and target NGFW/IPS/SOC design.
10. `vulnerability_exposure_management_2026-07-26.md` - current Greenbone,
    KEV/EPSS, remediation and safe-validation architecture.
11. `home_soc_platform_target_2026-07-26.md` - current home SOC capabilities,
    missing analysis layers, target service map and rollout order.

## Current Runtime Truth

- transport backend: Kafka
- primary event store: ClickHouse
- control-plane backend: PostgreSQL
- content backend: MongoDB
- runtime secret backend: Vault
- live operator shell: `/app/*`
- current identity model: OIDC first through Keycloak
- primary rule sources: `correlation_rule_packs/` and `sql/`

## Documentation Rules

- Put current operating procedure in stable runbooks.
- Keep dated files as delivery records, not as the default entry point.
- Do not add operator credentials, local secret bundle paths, exported VPN kits,
  benchmark dumps, screenshots, logs, or generated archives.
- If an old runbook conflicts with a newer dated runbook, follow the newer
  runbook and update `INDEX.md`.
