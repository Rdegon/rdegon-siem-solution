# Platform Finalization And `/app` Product Redesign: 2026-03-27

## Purpose

This document records the `March 27, 2026` pass that closed:

- `Slab 3: Platform Finalization`
- `Slab 4: Coverage Completion`

It is the authoritative closure record for the current stand after the earlier certification, governance, and production-green passes.

## Outcome

The current stand is now closed at the accelerated project-plan level.

The system is no longer only operationally green. It now has:

- a pragmatic decomposition layer for future supportability
- operator-driven remediation for source and vulnerability binding gaps
- a live Keycloak identity control center in `/app/access`
- a branded, instrument-grade `/app/*` shell instead of a generic dark admin surface
- a corrected live rollout carrier that now reliably ships the new decomposition, runtime, and frontend slices onto `VM4`

## What Changed

### Architecture finalization

- landed the first domain split out of `deps.py` through the `query/` package:
  - `dashboard`
  - `events`
  - `alerts`
  - `sources`
  - `assets`
  - `geo`
  - `threat_intel`
  - `vuln`
  - `shared`
- kept `deps.py` as a compatibility facade so the split did not require a risky full consumer rewrite in one pass
- split governance and identity-adjacent runtime responsibilities into narrower modules:
  - `control_plane_governance_runtime.py`
  - `keycloak_admin_runtime.py`
  - `asset_binding_overrides.py`
- corrected the live VM4 carrier so it now also ships:
  - `query/`
  - mirrored `services/web/app/query/`
  - the split governance / Keycloak / binding-override runtimes
  - branded frontend asset, style, and access-workspace directories
- switched remote Python compilation in the carrier to `PYTHONPYCACHEPREFIX=/tmp/siem-pycache` so deploy-time compile checks do not fail on permission-restricted `__pycache__` paths
- moved source-discovery and vulnerability binding logic onto the new override-aware path rather than leaving it in scattered ad hoc cleanup logic

### Coverage completion

- added operator-managed asset binding overrides:
  - `GET,POST /api/assets/binding-overrides`
  - `POST /api/assets/binding-overrides/{override_id}`
  - `DELETE /api/assets/binding-overrides/{override_id}`
- made source discovery and vulnerability maturity consume those overrides directly
- upgraded vulnerability maturity from a bare counter to a structured unmapped-target queue with suggested-asset hints
- kept Windows onboarding and network onboarding inside the supported managed scope:
  - Windows native-agent package preview
  - network dry-run / execute preview for supported vendors
  - artifact manifests and operator transcript visibility
- aligned `Sources` and `Vulnerability` around operator-first remediation rather than passive status reporting

### Identity control center

- added a real Keycloak admin runtime instead of request-handler shelling
- added the Keycloak admin API family:
  - `GET /api/auth/keycloak/status`
  - `GET,POST /api/auth/keycloak/users`
  - `GET,POST /api/auth/keycloak/users/{user_id}`
  - `POST /api/auth/keycloak/users/{user_id}/password`
  - `POST /api/auth/keycloak/users/{user_id}/groups`
  - `POST /api/auth/keycloak/users/{user_id}/roles`
  - `GET,POST /api/auth/keycloak/groups`
  - `POST /api/auth/keycloak/groups/{group_id}`
  - `GET,POST /api/auth/keycloak/roles`
  - `POST /api/auth/keycloak/roles/{role_name}`
  - `GET,POST /api/auth/keycloak/clients`
  - `GET,POST /api/auth/keycloak/clients/{client_id}`
  - `POST /api/auth/keycloak/clients/{client_id}/secret/rotate`
- turned `/app/access` into a live identity control center with deep-linkable tabs:
  - `overview`
  - `keycloak-users`
  - `keycloak-groups`
  - `keycloak-roles`
  - `keycloak-clients`
  - `recovery`
  - `service-accounts`
  - `secrets`
- preserved the boundary between:
  - Keycloak identities
  - SIEM break-glass users
  - SIEM service accounts

### `/app` product redesign

- rebranded the shell as `Rdegon Sentinel`
- added:
  - brand mark
  - favicon
  - branded bootstrap/loading state
  - self-hosted IBM Plex Sans / IBM Plex Mono
- replaced the single monolithic `styles.css` layer with a layered CSS stack:
  - `tokens`
  - `base`
  - `shell`
  - `components`
  - `data-surfaces`
  - `charts`
  - `page-families`
- refactored the primary operator pages onto the new visual system:
  - `Overview`
  - `Events`
  - `Incidents`
  - `Sources`
  - `Vulnerability`
  - `Builders`
  - `Access`
- preserved the existing dense operator model:
  - multi-dashboard structure
  - split views
  - side drawers
  - dense tables
  - graph-first builders
- removed the remaining visible mojibake from touched `/app` surfaces

## UI / UX Direction

The shell is now intentionally styled as `instrument-grade cyber operations`:

- graphite / navy / ink surfaces
- reserved semantic accents for state and urgency
- denser hierarchy with fewer equal-weight cards
- stronger right-side context panels for investigation and remediation
- more explicit operator focus on actionability rather than passive dashboard chrome

## Validation

### Backend

- `pytest tests/test_source_discovery.py tests/test_vuln_maturity_runtime.py tests/test_keycloak_admin_runtime.py tests/test_deploy_rollout_regressions.py -q`
- result: `25 passed`

### Frontend

- `tsc -p tsconfig.quality.json --noEmit`
- `eslint src --ext .ts,.tsx src/test --max-warnings=0`
- `vitest run`
- `node build.cjs`
- all passed on the local workstation

### Browser verification

Local Playwright verification now covers:

- `/app/`
- `/app/events`
- `/app/incidents`
- `/app/sources?view=discovery`
- `/app/vuln`
- `/app/builders`
- `/app/access?tab=keycloak-users`
- `/app/access?tab=keycloak-clients`

Artifacts are stored in:

- `frontend-react/.artifacts/browser/overview.png`
- `frontend-react/.artifacts/browser/events.png`
- `frontend-react/.artifacts/browser/incidents.png`
- `frontend-react/.artifacts/browser/sources.png`
- `frontend-react/.artifacts/browser/vuln.png`
- `frontend-react/.artifacts/browser/builders.png`
- `frontend-react/.artifacts/browser/access-users.png`
- `frontend-react/.artifacts/browser/access-clients.png`

Follow-up authenticated live browser verification against the deployed VM4 shell is stored in:

- `.artifacts/browser/live-audit/results.json`
- `.artifacts/browser/live-audit/*.png`

## Plan Change

`Slab 3` and `Slab 4` are now closed for the current stand.

The closure plan should now be used only as historical proof of closure and as a reference for future expansion work.

Remaining work, if any, is post-closure expansion:

- external SSO client rollout
- support validation for Greenbone/OpenVAS SSO
- broader vendor expansion
- deeper decomposition beyond the pragmatic close layer

See also:

- `live_rollout_verification_2026-03-27.md`
- `ui_ux_system_audit_2026-03-27.md`
