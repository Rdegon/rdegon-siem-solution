# SSO Operations And External Integrations: 2026-03-26

> Historical implementation record. The current public issuer is
> `https://192.168.3.102/realms/siem`; current network and console access are
> documented in `docs/network_cutover_2026-07-25.md` and
> `docs/operator_security_console_access.md`. References below to
> `192.168.1.39` describe the former deployment and must not be used for new
> clients.

## Purpose

This document is the operational reference for the current `OIDC-first` identity model on the stand.

Use it for:

- operator login flow
- account creation and role assignment
- break-glass and service-account boundaries
- future integration of external systems such as `Nextcloud`, `Greenbone/OpenVAS`, and other operator-facing services
- the live `/app/*` Keycloak account-management workspace

This is a runtime and planning note. It does not replace the VM4 deploy runbook or the closure plan.

## Current SSO Topology

- identity provider: `Keycloak` on `VM4`
- realm: `siem`
- current issuer on the stand: `https://192.168.1.39/realms/siem`
- current SIEM OIDC client: `siem-web`
- primary human auth path: `/auth/login` -> `Enterprise SSO`
- retained fallback path: `Break-glass local login`
- runtime secret backend: `Vault` on `VM4`
- primary operator UX surface: `/app/*`
- live identity control center: `/app/access`
- legacy `/dashboards` is not the target for new auth or identity UX work

Relevant project references:

- `production_certification_and_governance_closure_2026-03-26.md`
- `deployment_runbook_vm4_enterprise_foundation.md`
- `endpoints.md`

## How Operators Use It

### Human login

The normal operator path is:

1. open the SIEM login page
2. choose `Enterprise SSO`
3. complete OIDC login against `Keycloak`
4. return to the SIEM shell with the normal SIEM session cookie/JWT

The SIEM runtime remains the relying party. It does not delegate the whole application session to Keycloak. This preserves the existing SIEM shell and API model while moving human authentication to OIDC.

### Break-glass

Local username/password remains available only as `break-glass`.

Use it only for:

- IdP outage
- emergency recovery
- operator lockout

Do not treat local SIEM users as the normal identity store for daily operator access.

### Machine identities

Do not use human OIDC users for service integrations.

Use:

- SIEM `service accounts` for SIEM API or automation access
- `Vault` references for runtime secrets
- technical users only when an external product cannot use OIDC or a proper service-account pattern

## How To Create Accounts

### Where accounts live

Human user accounts should be created in `Keycloak`, not in the SIEM local user list.

The current bootstrap and runtime material is on `VM4`:

- Keycloak runtime
- Keycloak realm `siem`
- bootstrap admin env in `/etc/siem/keycloak.env`

### Recommended admin path

For day-to-day operations, use `/app/access?tab=keycloak-users`, `/app/access?tab=keycloak-groups`, `/app/access?tab=keycloak-roles`, and `/app/access?tab=keycloak-clients`.

The SIEM shell now exposes the Keycloak admin surface directly through the supported `/api/auth/keycloak/*` runtime.

Use the Keycloak admin console on `VM4` only when a realm-level action is missing from the current `/app` workspace or when doing emergency realm administration.

### Minimal operator flow

1. create the user in realm `siem`
2. set username, email, enabled state
3. set an initial password or temporary password
4. assign the role or group expected by the SIEM runtime

### Current role mapping

The current landed mapping for SIEM is:

- `siem-admin` -> `admin`
- `siem-analyst` -> `analyst`
- `siem-viewer` -> `viewer`

The SIEM runtime can read role information from:

- `groups`
- `realm_access.roles`
- `resource_access[client].roles`

For the current stand, the cleanest operator model is to assign realm roles or groups using the names above.

## Per-System Access Grants

The current stand now uses an explicit `system grant` model for application access.

What this means:

- Keycloak still owns human identities
- SIEM owns per-system access intent and mirrors it into Keycloak groups/claims
- access is `deny by default` for normal OIDC users

The live operator surface for this is `/app/access?tab=keycloak-users`.

From that page, the operator can:

- create and delete Keycloak users
- assign normal realm groups and roles
- open the `System access` popup
- choose the target system
- choose the system role
- choose the allowed sections

Grantable systems on the current stand:

- `siem`
- `nextcloud`

Explicitly non-grantable in the current model:

- `proxmox`
- `VM1` to `VM5`
- Windows hosts
- network devices
- scanner hosts

`Proxmox` remains `monitored-only` by policy because it is a critical dependency and should not be coupled to the same user-login rollout.

## What Lives In SIEM And What Does Not

### Keycloak-owned

- normal human identities
- role and group assignment for OIDC users
- future federation to external identity stores

### SIEM-owned

- break-glass local users
- service accounts
- service-account token rotation
- governance inventory
- runtime authorization inside the SIEM app

This separation should be preserved in future work.

## External System Integration Model

The correct integration pattern is:

- external apps integrate with the same `Keycloak` realm
- they do not authenticate "through SIEM"
- each external app gets its own client in `Keycloak`
- app-specific groups and roles should be preferred over reusing SIEM roles everywhere

Examples:

- `nextcloud`
- `greenbone`
- `grafana`
- `wiki`
- any internal admin portal

Use client-specific naming such as:

- `nextcloud-users`
- `nextcloud-admins`
- `greenbone-operators`

Avoid using `siem-admin` as a universal cross-application admin role.

## TLS State

The current stand no longer uses the raw internal Keycloak HTTP issuer for user-facing clients.

The landed OIDC issuer is:

- `https://192.168.1.39/realms/siem`

This is now proxied by the VM4 web edge and is the supported issuer used by both:

- SIEM
- Nextcloud

For wider production rollout, the next maturity step is still a stable DNS name such as:

- `https://sso.<internal-domain>/realms/siem`

## Nextcloud Integration Status

`Nextcloud` is no longer a planned target on this stand. It is a landed external OIDC client.

Current live model:

- `Nextcloud` uses the same `Keycloak` realm as SIEM
- client ID: `nextcloud`
- provider identifier inside `user_oidc`: `siem-keycloak`
- login mode: `OIDC primary`
- local admin: `break-glass only`
- group mapping is driven by mirrored grants such as:
  - `nextcloud-users`
  - `nextcloud-admins`

Important implementation note:

- the installed `Nextcloud 29.0.4.1` plus `user_oidc` combination required a compatibility patch for the current build
- that compatibility patch is now encoded into `deploy/nextcloud_oidc_rollout.py`
- the deployed scope set for the current build is `openid email profile`
- group mapping continues through the `groups` claim, not through a separate `groups` scope

Operational result:

- a real user created and granted from `/app/access` can log into `Nextcloud` through Keycloak on the current stand

## Greenbone / OpenVAS Integration Guidance

The situation for `Greenbone/OpenVAS` is different.

For the current pass, no official, confirmed `native OIDC/Keycloak login` path for the `Greenbone Community Edition` web UI was validated from the checked official documentation set.

What is officially documented and confirmed:

- local `gvmd/gsad` users for the Greenbone UI
- automation and integration through `GMP`
- `GMP` tooling over `SSH`, `TLS`, or Unix socket via `gvm-tools`

### Current recommendation

For the current build, the decision is explicit:

- keep local Greenbone UI accounts
- do not expose Greenbone as a grantable SSO system in `/app/access`
- keep using technical users plus `GMP` and the existing Greenbone import/sync path for machine integration

This is an explicit `unsupported on current build` decision for native Greenbone UI SSO, not a temporary omission.

## Future Work Reserved For Another Agent

The following future tasks are now explicitly reserved and documented:

### External SSO client rollout

- validate whether any additional internal systems should join the current `Keycloak` backbone
- keep `Greenbone/OpenVAS` behind the documented `unsupported on current build` decision unless the installed product changes
- connect additional internal systems to the same SSO backbone where appropriate
- make a clear distinction between:
  - Keycloak human identities
  - SIEM break-glass users
  - SIEM service accounts

This should not be implemented as a generic mixed table that hides the boundary between IdP identities and SIEM-local principals.

## Source Links Used For The Integration Guidance

- Keycloak server administration:
  - `https://www.keycloak.org/docs/latest/server_admin/`
- Nextcloud OIDC developer documentation:
  - `https://docs.nextcloud.com/server/stable/developer_manual/digging_deeper/oidc.html`
- Nextcloud `user_oidc` reference:
  - `https://github.com/nextcloud/user_oidc`
- Greenbone Community Documentation:
  - `https://greenbone.github.io/docs/latest/index.html`
- Greenbone `gvm-tools` reference:
  - `https://greenbone.github.io/gvm-tools/tools.html`

## Operational Summary

For the current stand, the correct mental model is:

- `Keycloak` is the identity source for humans
- `SIEM` is an OIDC client of that IdP
- `Vault` is the secret backend
- `break-glass` remains local and exceptional
- service integrations should prefer service accounts or dedicated app clients
- `Nextcloud` is a good near-term SSO client
- `Greenbone/OpenVAS` should be treated conservatively until a supported native SSO path is confirmed
