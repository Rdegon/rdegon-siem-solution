# Windowed Access, Builders, And Host Correlation Wave 2026-03-28

## Scope

This wave finished three user-facing goals in one pass:

- expanded operational correlation coverage for `Windows` and `Linux`
- moved `Access` and `Builders` closer to a window-first operator model
- added an explicit shell logout action in the live `/app/*` surface

## Implemented Changes

### Correlation Coverage

Two new operational packs were added and published through the standard runtime path:

- `windows-activity-v1`
- `linux-activity-v1`

The `Windows` pack now covers:

- logon failure bursts
- audit-log clearing
- privileged-group membership changes
- encoded PowerShell execution
- service installation
- local user creation

The `Linux` pack now covers:

- SSH failure bursts
- direct root SSH logins
- repeated `sudo` escalation
- cron persistence changes
- `sudoers` modification
- systemd unit changes
- security-critical service disablement

The live publish path was extended in:

- `deploy/publish_operational_rule_packs.py`

## Window-First UI Changes

### Access

`/app/access` now uses launcher cards and side windows for the main admin actions instead of keeping long inline editors permanently expanded.

Windowed flows now cover:

- Keycloak user editor
- groups editor
- roles editor
- clients editor
- break-glass recovery editor
- service-account editor

Mutation actions now close their own side windows after successful save, rotate, or delete operations.

### Builders

`/app/builders?workspace=correlation` now uses the same operator pattern:

- pack summary on the page
- `Pack window`
- `Rule window`
- `Lifecycle window`

The main page keeps compact context, while pack metadata and authoring actions run inside slide-out windows.

### Shell

The shell top bar now exposes an explicit `Logout` button that sends the operator to `/auth/logout`.

## Verification

Local verification completed before rollout:

- frontend `typecheck`
- frontend `lint`
- targeted `vitest` for `Access` and `Builders`
- `pytest tests/test_correlation_pack_runtime.py`
- frontend production `build`

Live verification after rollout:

- `deploy/vm4_enterprise_foundation_deploy.py` -> `deployment=success`
- `deploy/vm4_enterprise_foundation_smoke.py` -> `smoke=success`
- browser verification on the live `VM4` shell
- browser console errors -> `0`

Published live rule totals after the rollout included:

- `published_rules: 48`
- `windows-activity-v1: 6 active stream rules`
- `linux-activity-v1: 7 active stream rules`

## Evidence

Screenshots captured from the live deployed UI:

- `../.artifacts/browser/windowed-ui-2026-03-28/overview-windowed.png`
- `../.artifacts/browser/windowed-ui-2026-03-28/access-user-window.png`
- `../.artifacts/browser/windowed-ui-2026-03-28/builders-correlation.png`
- `../.artifacts/browser/windowed-ui-2026-03-28/builders-pack-window.png`

Primary implementation files:

- `frontend-react/src/shell/App.tsx`
- `frontend-react/src/shell/pages/access/AccessWorkspace.tsx`
- `frontend-react/src/shell/pages/BuildersPage.tsx`
- `frontend-react/src/styles/shell.css`
- `correlation_rule_packs/windows_activity_v1.json`
- `correlation_rule_packs/linux_activity_v1.json`
- `deploy/publish_operational_rule_packs.py`
- `docs/correlation_rules.md`

## Operational Outcome

The shell now exposes a direct logout path, `Access` and `Builders` behave more like operator work windows than long static forms, and the live correlation catalog covers materially more `Windows` and `Linux` behavior than before this wave.
