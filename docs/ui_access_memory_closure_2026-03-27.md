# UI, Access, Memory, and External SSO Closure: 2026-03-27

## Purpose

This document records the final one-pass closure for:

- live `/app/access` operability
- per-system SSO grants
- memory truth-surface and RAM-pressure tuning
- external OIDC rollout for `Nextcloud`
- final live browser verification and screenshot capture

This pass was completed on the live stand before final git publication.

## Landed state

Direct facts:

- `/app/access` is now operational against the live Keycloak admin runtime
- Keycloak user lifecycle is live from the product shell:
  - list users
  - create user
  - delete user
  - reset password
  - assign groups and roles
- per-system grants are live from `/app/access` through the `System access` popup
- the currently grantable systems are:
  - `siem`
  - `nextcloud`
- `proxmox` is explicitly excluded from SSO targeting and stays `monitored-only`
- `greenbone` remains non-grantable on the current build because native supported SSO was not validated for this environment
- `Overview` now keeps the control bar and the `Security overview / Обзор безопасности` heading in the corrected order requested during the live pass
- the unified investigation pattern is now the shared `/app` reference across `Events`, `Assets`, `Entities`, and `Threat Intel`

## `/app/access` live verification

The live browser pass proved the following operator flow from the actual shell:

1. open `/app/access?tab=keycloak-users`
2. create a Keycloak user
3. add a `siem` grant through the popup selector
4. add a `nextcloud` grant through the popup selector
5. confirm grant visibility through the live runtime
6. delete a Keycloak user from the same workspace

Verified facts:

- `proxmox` does not appear in the grantable system selector
- `deny by default` stays in effect for grantable systems
- the popup grant model is backed by the live `/api/auth/access-systems` and `/api/auth/access-grants*` runtime, not by mock data
- the delete path is proven separately by `../.artifacts/browser/live-one-pass-final/access-delete-check.json`

Artifacts:

- `../.artifacts/browser/live-one-pass-final/access-admin.png`
- `../.artifacts/browser/live-one-pass-final/access-delete-check.json`

## Nextcloud OIDC rollout

Direct facts:

- `Nextcloud` is now a live OIDC client of the `siem` Keycloak realm
- the provider flow is:
  - Keycloak issuer: `https://192.168.1.39/realms/siem`
  - Nextcloud base URL: `https://192.168.1.120`
  - client: `nextcloud`
  - provider identifier: `siem-keycloak`
- local Nextcloud admin remains break-glass only
- group mapping is driven by mirrored Keycloak groups and the SIEM-side `nextcloud` system grants

Important implementation note:

- the current `Nextcloud 29.0.4.1` plus `user_oidc` combination required a compatibility patch for the installed app code
- that patch is now encoded into `deploy/nextcloud_oidc_rollout.py`, so the OIDC path is reproducible and no longer depends on a one-off manual fix inside the container
- the rollout also keeps self-signed lab trust working for the current stand and uses `openid email profile` as the supported scope set for this build

Artifacts:

- `../.artifacts/browser/live-one-pass-final/nextcloud.png`

## Greenbone / OpenVAS decision

Decision for the current installed build:

- `Greenbone/OpenVAS native SSO` -> `unsupported on current build`

What this means:

- Greenbone remains the authoritative vulnerability scanner backend
- the SIEM continues to ingest and structure Greenbone-derived findings
- Greenbone UI accounts stay local for now
- Greenbone does not appear as a grantable system in `/app/access` on this stand

This is an explicit no-go decision for the current environment, not an unfinished integration.

## Memory truth surface and RAM optimization

This pass treated the RAM complaint as a real `truthfulness + tuning` issue.

What changed:

- host-runtime and health surfaces now expose:
  - `MemAvailable`
  - `buff/cache`
  - `swap_used_pct`
  - role-aware memory pressure classification
- `memory_used_pct` is no longer treated as the sole operator signal
- page-cache-heavy nodes no longer present as false-critical when `MemAvailable` is healthy and swap is near zero

Live post-tuning memory snapshot:

- `VM1 ingest`: available about `9.84 GiB` of `12.56 GiB`
- `VM2 processing`: available about `14.27 GiB` of `16.79 GiB`
- `VM3 storage`: available about `20.79 GiB` of `23.40+ GiB` guest-visible memory, with ClickHouse resident memory around `1.24 GiB`
- `VM4 control-plane`: available about `6.76 GiB` of `8.33 GiB`
- `VM5 transport`: available about `8.89 GiB` of `12.54 GiB`
- swap remained near zero across the stand
- host runtime ended with `pressure_targets=0`

Live memory-smoke evidence:

- `deploy/vm3_storage_memory_smoke.py` -> `smoke=success`
- `deploy/vm3_proxmox_memory_smoke.py` -> `smoke=success`
- `deploy/host_runtime_wave_smoke.py` -> `smoke=success`

## Browser evidence set

The final live browser set for this pass was captured as:

- `../.artifacts/browser/live-one-pass-final/results.json`
- `../.artifacts/browser/live-one-pass-final/access-admin.png`
- `../.artifacts/browser/live-one-pass-final/overview.png`
- `../.artifacts/browser/live-one-pass-final/events.png`
- `../.artifacts/browser/live-one-pass-final/assets.png`
- `../.artifacts/browser/live-one-pass-final/entities.png`
- `../.artifacts/browser/live-one-pass-final/threat_intel.png`
- `../.artifacts/browser/live-one-pass-final/host_runtime.png`
- `../.artifacts/browser/live-one-pass-final/nextcloud.png`

The same pass also confirmed:

- `Host Runtime` shows non-zero, truthful memory state
- `Overview`, `Events`, `Assets`, `Entities`, and `Threat Intel` all render correctly for an ordinary OIDC user
- `Nextcloud` login works with a real OIDC user created and granted from `/app/access`

## Cleanup hygiene

The validation pass created temporary `ui.*` users to prove the UI and OIDC flows.

After verification:

- temporary Keycloak users were deleted
- temporary SIEM system grants for those users were deleted
- temporary Nextcloud users created by OIDC provisioning were deleted

The stand was left without the temporary `ui.final.*`, `ui.oidc.*`, or `ui.delete.*` identities.
