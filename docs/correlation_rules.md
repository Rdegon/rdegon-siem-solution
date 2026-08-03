# Correlation Rules

## Current Model

The live platform uses a pack-oriented correlation model.

- Source of truth for authored packs: `correlation_rule_packs/*.json`
- Stream runtime catalog: `siem.correlation_rules_stream`
- Batch runtime catalog: `siem.correlation_rules_batch`
- Detection catalog used by UI and test flows: `siem.detection_rule_catalog`
- Published stream rules emit into `siem.alerts_raw`, then aggregation promotes them into `siem.alerts_agg`

The Builders module now exposes a dedicated `Correlation` workspace for pack authoring, validation, targeted testing, and publish.

The backend rule list is reconciled through the stable identity model described
in [`unified_rule_inventory.md`](unified_rule_inventory.md). UI/API consumers
must use that inventory instead of independently counting catalog, stream, and
batch rows.

Current operational families include:

- `fleet_observability_v1`
- `openclaw_behavior_v1`
- `vuln_coverage_v1`
- `pilot_services_v1`
- `identity_access_v1`
- `gitea_activity_v1`
- `navidrome_activity_v1`
- `scanner_runtime_v1`
- `windows_activity_v1`
- `linux_activity_v1`

## Pack Structure

Each pack is a UTF-8 JSON document with this shape:

- `pack_id`
- `title`
- `version`
- `status`
- `owner`
- `notes[]`
- `stream_rules[]`
- `batch_rules[]`

Each stream rule should contain:

- `id`
- `title`
- `severity`
- `window_s`
- `threshold`
- `entity_field`
- `suppression_key`
- `status`
- `operator_action`
- `sigma_yaml`

Each batch rule entry is kept as explicit metadata for follow-up review and should contain:

- `id`
- `title`
- `severity`
- `status`
- `description`

## Runtime Relationship

- `stream correlation`
  - near-real-time
  - consumes filtered event flow
  - active rules are published from pack JSON into `siem.correlation_rules_stream`
- `batch correlation`
  - periodic review over historical windows
  - active SQL rules live in `siem.correlation_rules_batch`
- `runtime pack layer`
  - groups related stream and batch rules into one operational unit
  - is validated, tested, published, and rolled back as a coherent family

## Authoring Lifecycle

1. `Draft`
   Write or update a pack in the Builders `Correlation` workspace.
2. `Validate`
   Check structure, required fields, rule ids, and Sigma presence.
3. `Test`
   Compile Sigma to stream-correlation runtime rules and run targeted runtime tests.
4. `Publish`
   Publish only rules whose status is `active` or `publish_ready_after_host_metrics`.
5. `Observe`
   Verify `siem.alerts_raw`, `siem.alerts_agg`, `/api/incidents`, and the live event stream.
6. `Rollback`
   Revert the pack file or downgrade the affected rule status, then republish.

## Suppression Policy

Noise control must be explicit inside every pack.

Standard suppression policy for the current stand:

- primary suppression key: `host + service + rule family`
- repeated low-signal bursts should be rolled up rather than emitted as independent alerts
- self-healed one-off events should be de-escalated
- maintenance windows should suppress expected deploy and scan turbulence
- offline-by-design and offline-unexpected must use different severity semantics
- memory-related alerts should follow real pressure signals, not raw `used RAM %`

Every pack should document:

- rule condition
- suppression key
- escalation threshold
- evaluation window
- expected operator action

## Builders Correlation Workspace

The dedicated Builders `Correlation` workspace supports:

- list packs
- open pack details
- open dedicated pack, rule, and lifecycle side windows
- edit pack metadata
- edit stream-rule metadata
- edit suppression keys, thresholds, windows, and operator actions
- edit Sigma payloads
- validate packs
- test packs
- publish packs

Related API surface:

- `GET /api/correlation/packs`
- `GET /api/correlation/packs/{pack_id}`
- `POST /api/correlation/packs`
- `POST /api/correlation/packs/{pack_id}/validate`
- `POST /api/correlation/packs/{pack_id}/test`
- `POST /api/correlation/packs/{pack_id}/publish`

Permission model:

- authoring and publish: `rules:write`
- targeted testing: `rules:test`

## Operator Workflow

Recommended operator flow for a new or changed pack:

1. Open `Builders -> Correlation`.
2. Create or select a pack, then open the `pack window`.
3. Update metadata and notes first.
4. Select or create rules, then open the `rule window`.
5. Run validation from the `lifecycle window`.
6. Run targeted test.
7. Publish only after validation and test are clean enough for the current window.
8. Confirm live output in:
   - `/app/events`
   - `/app/incidents`
   - `/api/incidents`
   - `siem.alerts_raw`
   - `siem.alerts_agg`

Windows and Linux operational packs should prefer the existing normalized event types rather than raw source-specific strings. Current examples:

- Windows:
  - `windows_logon_failure`
  - `windows_audit_log_cleared`
  - `windows_user_added_to_privileged_group`
  - `windows_powershell_encoded_command`
  - `windows_service_installed`
  - `windows_user_created`
- Linux:
  - `ssh_login_failure`
  - `linux_root_ssh_login`
  - `sudo_command`
  - `linux_cron_modified`
  - `linux_sudoers_modified`
  - `linux_systemd_unit_modified`
  - `linux_systemd_service_disabled`

## CLI / Scripted Publish

Operational publish helper:

```powershell
python deploy/publish_operational_rule_packs.py
```

This helper publishes the currently approved operational packs into the live stream-correlation catalog.

## Rollback Guidance

If a pack causes noise or bad runtime behavior:

1. Edit the affected rule status back to `draft` or restore the previous pack file.
2. Republish the pack.
3. Confirm old rule ids are no longer active in `siem.correlation_rules_stream`.
4. Verify `alerts_raw` and `alerts_agg` settle back to the expected baseline.
