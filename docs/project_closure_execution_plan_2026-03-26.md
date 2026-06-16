# Project Closure Execution Plan: 2026-03-26

This document is the authoritative accelerated close-out plan for the project.

Use it as the default execution baseline when assigning the next implementation tasks.

It does not replace architecture or runbooks. It replaces the old slower roadmap ordering when the goal is to close the project in an accelerated `3-4 week` window.

## Current Position

Already operationally complete for the current stand:

- transport baseline on `kafka`
- storage / control-plane / content HA baseline
- host-runtime observability baseline
- SOAR / response hardening baseline
- source discovery live onboarding baseline
- vulnerability structured runtime baseline
- production-green mainline deploy path

Closed in the `March 26, 2026` certification and governance pass:

- `Slab 1: Production Certification`
- `Slab 2: Identity, Secrets, Access, Governance`
- live `OIDC first` identity through `Keycloak on VM4`
- live `Vault on VM4` runtime secret backend with `vault://...` resolution
- certified EPS and drill status exposed through `/api/health/certification`, with the first certification ladder stage treated as warmup and the latency budget evaluated only on the certified ceiling stage
- `/app/*` operator shell updated for identity/governance and approval/execution control
- self-hosted deployment carrier stabilized so the standard VM4 rollout reuses installed identity runtimes, the storage HA wave resolves Vault-backed runtime refs directly on VM4, standalone VM4 maintenance runtimes can resolve Vault-backed ClickHouse credentials, and the ingest health path no longer blocks on legacy `generic-http` source or collector identities

What remained before the `March 27, 2026` close-out pass was the final closure layer:

- finish decomposition and scale-safe architecture work
- finish remaining Windows / network / vulnerability / UX quality gaps

Closed in the `March 27, 2026` platform finalization and `/app` redesign pass:

- `Slab 3: Platform Finalization`
- `Slab 4: Coverage Completion`
- first decomposition layer landed through the `query/` package and the split governance / Keycloak / binding-override runtimes
- `/app/access` became the live Keycloak identity control center with separate Keycloak, break-glass, service-account, and secret-governance surfaces
- operator-driven binding remediation for vulnerability and source discovery landed through `/api/assets/binding-overrides*`
- source discovery, Windows onboarding preview, network config preview, and vulnerability unmapped-target remediation were aligned into one operator workflow
- the `/app/*` shell was redesigned into the branded `Rdegon Sentinel` instrument-grade control plane with layered design tokens, self-hosted IBM Plex typography, favicon / brand mark, and flagship page refactors
- browser verification artifacts now cover `Overview`, `Events`, `Incidents`, `Sources`, `Vulnerability`, `Builders`, and `Access`

Verified in the `March 27, 2026` live rollout correction pass:

- the VM4 deploy carrier was corrected to ship the split runtime modules, `query/`, mirrored `services/web/app/query/`, and the branded `/app` asset directories required by the live web service
- the full rollout was re-executed across `VM1`, `VM2`, `VM3`, `VM4`, and `VM5`
- the final live recheck then caught and closed two additional runtime regressions before sign-off: VM1 multi-worker syslog port binding inside `siem-ingest`, and a VM4 frontend-bundle gap that broke `/app` after login
- authenticated live browser verification was captured against the real `/app/*` shell on `VM4`
- a follow-up UI / UX audit was completed from repository evidence plus live rendered artifacts
- the remaining UI closure items were then closed in the same live cycle:
  - `Overview` strengthened as a clearer command surface
  - investigation detail unified across `Events`, `Entities`, `Assets`, and `Threat Intel`
  - Storybook and visual-baseline coverage landed
  - brand icon / favicon and desktop `Hide` control regressions were fixed and re-verified live
  - synthetic rollout residue was removed from operator-facing `Sources` and `Assets`
  - `Host Runtime` was reduced to one canonical time / refresh / rows control bar
  - live Keycloak user create / delete flows were re-verified from `/app/access`
  - per-system grant popups for `siem` and `nextcloud` were re-verified from `/app/access`
  - `Nextcloud` OIDC was landed as the first external Keycloak client on the stand
  - `Greenbone/OpenVAS` native UI SSO was explicitly left unsupported on the current build
  - memory truth surfaces were reworked so page-cache-heavy nodes no longer appear falsely critical when `MemAvailable` is healthy and swap pressure is near zero

The current stand is now considered closed at the slab level. Remaining work is follow-up expansion, not core project closure.

## Slab Status

- `Slab 1: Production Certification` -> `closed for the current stand`
- `Slab 2: Identity, Secrets, Access, Governance` -> `closed for the current stand`
- `Slab 3: Platform Finalization` -> `closed on March 27, 2026 for the current stand`
- `Slab 4: Coverage Completion` -> `closed on March 27, 2026 for the current stand`

## Execution Rule

Future work should be grouped into the four closure slabs below.

When assigning a task, reference:

- the slab name
- the target outcome
- the done criteria

Do not reopen already-closed baseline waves unless a regression is found.

## Slab 1: Production Certification

### Goal

Status: `closed on March 26, 2026 for the current stand`

Turn the current green system into a measured and release-certifiable system.

### Scope

- remove the remaining ingest HTTP ACK bottleneck
- rerun distributed EPS benchmarking after each material ingest/runtime change
- define the real max EPS and safe operating envelope
- define transport, ingest, storage, and lag budgets
- automate failover drills for Kafka, ClickHouse, Postgres, Mongo, and runner-plane recovery
- automate rollback drills and disaster-recovery validation
- promote these checks into the standard release gate

### Why first

This is the highest remaining production risk. The platform is functional, but the final proof layer for load and failure is not yet closed.

### Done criteria

- measured distributed EPS ceiling is documented and repeatable
- safe production envelope is documented
- failover, rollback, and DR drills are green
- release gate includes load, lag, failover, and smoke checks
- the system can be declared not only green, but certified for the current stand

## Slab 2: Identity, Secrets, Access, Governance

### Goal

Status: `closed on March 26, 2026 for the current stand`

Close the enterprise auth and secret-handling layer in one coherent pass.

### Scope

- add enterprise SSO bridge work: `OIDC`, `SAML`, `LDAP`, `AD`
- move secret handling toward vault-backed references
- implement secret and token rotation workflows
- harden service-account lifecycle governance
- define and document break-glass flows
- tighten SOAR approval governance and role boundaries
- remove remaining secret-handling drift in exportable or operator-facing artifacts

### Why second

After performance and certification, this is the highest remaining security and governance risk.

### Done criteria

- auth paths follow a single mature model
- secrets are not managed through ad hoc raw-value workflows
- token and service-account lifecycle is governed and documented
- SOAR approvals match operator roles and governance rules
- docs, runtime behavior, and operator flow all match

## Slab 3: Platform Finalization

### Goal

Status: `closed on March 27, 2026 for the current stand`

Finish the architecture so the system is supportable, extensible, and safe to evolve after project closure.

### Scope

- continue splitting `deps.py`
- continue splitting `enterprise_control_plane.py`
- continue shrinking oversized route/runtime entrypoints
- move ingest health, replay, and metrics helpers into narrower modules
- isolate more worker/runtime classes for scale-out
- formalize safe ownership boundaries for future correlation parallelism
- keep `batch_corr` single-instance until the safe parallel design is implemented

### Why third

This is the main maintainability and change-risk layer. It matters most after production behavior and governance are stabilized.

### Done criteria

- the largest monoliths are no longer operational risks
- domain boundaries are clear in code and deployment
- future scale-out work does not depend on giant shared modules
- the codebase is materially easier to extend without regression

## Slab 4: Coverage Completion

### Goal

Status: `closed on March 27, 2026 for the current stand`

Finish the remaining product surfaces so the project can be considered complete, not just operational.

### Scope

- raise Windows rollout from baseline-native support to fleet-grade operational support
- keep network-device onboarding as a fully managed path for supported vendors
- reduce `unmapped_targets` in the vulnerability plane
- improve source-inventory quality and asset binding quality
- expand SOAR playbooks for vulnerability-driven and high-severity workflows
- polish the operator UX for `SOAR`, `Sources`, and `Vulnerability` sections
- connect external operator systems to the landed `Keycloak` backbone where supportable, starting with `Nextcloud`
- validate whether `Greenbone/OpenVAS` has a supported native SSO path for this environment before attempting UI-level SSO rollout
- if operator-driven IdP account administration becomes necessary, implement it on `/app/*` as a dedicated identity-management workspace rather than on legacy `/dashboards`

### Why fourth

This slab benefits from the stability and governance work completed in the first three slabs.

### Done criteria

- Windows, network, source discovery, and vulnerability surfaces feel complete
- remaining manual-only operator gaps are reduced to explicit exceptions
- UI and backend maturity are aligned across these surfaces
- quality gaps are no longer treated as unfinished core project work
- external SSO client integrations are documented and landed only where the target product has a supported path
- any future account-management UI preserves the boundary between Keycloak identities, SIEM break-glass users, and SIEM service accounts

## Execution Order

The closure order is fixed:

1. `Production Certification`
2. `Identity, Secrets, Access, Governance`
3. `Platform Finalization`
4. `Coverage Completion`

For core project closure on the current stand, no further slabs remain open.

Any new implementation work after `March 27, 2026` should be treated as post-closure expansion work, not unfinished slab work.

Post-closure expansion wave already landed on `March 28, 2026`:

- Proxmox-backed fleet inventory and `/api/sources/proxmox-fleet`
- OpenClaw full-metadata monitoring with audit, DNS, and outbound-flow telemetry
- OpenVAS-first fleet coverage for reachable guests and containers
- pilot-service bundle:
  - `Gitea`
  - `PostgreSQL`
  - `Valkey`
  - `Navidrome`
- fleet-aware `/app/sources` and `/app/vuln` operator surfaces
- dedicated wave record in `docs/proxmox_fleet_openclaw_wave_2026-03-28.md`

Final note from the `March 27` live verification loop:

- no slab was reopened
- the last red `Validate Main` gate was caused by a backend DLQ-visibility regression, not by missing closure work
- the final correction restored the ingest API contract, replayed the outstanding live DLQ backlog through the supported remediation path, and returned the current stand to green without changing slab scope
- the final green proof set is anchored on `main` commit `9882f1896dbbd0243547cca3aa5e540dd9e3f18a`
- the corresponding green pipeline set is:
  - `Validate Main` run `23654987740`
  - `Deploy Homelab` run `23655094107`
  - `Watchdog Homelab` run `23655611425`
- the close-out now includes a real ordinary-user browser pass with captured `/app/*` evidence in `../.artifacts/browser/live-user-final/`

## Post-Closure Enterprise Expansion Baseline

The slab plan above is closed for the current stand.

When the task is no longer `close the baseline`, but instead `move the platform toward enterprise-class market parity`, the planning baseline changes.

Use:

- `enterprise_market_gap_delivery_plan_2026-04-08.md`
- `enterprise_foundation_delivery_wave_2026-04-08.md`

That document is the authoritative follow-up baseline for:

- market-gap-driven implementation planning
- deciding what can be delivered on the current `5-VM` stand
- deciding what is only partially feasible on the current stand
- deciding what should be deferred until after a real architecture change

The first concrete implementation slab against that baseline was executed on `2026-04-08` and recorded in:

- `enterprise_foundation_delivery_wave_2026-04-08.md`

That wave landed:

- web rollback backup for `VM107`
- Proxmox memory uplift for `VM104-108`
- `content operations` and bundle lifecycle controls
- connector telemetry governance and maturity scoring
- `UEBA v1`
- `evidence graph v1`
- governed `SOAR / playbook` metadata
- compliance / governance posture metrics
- first admin-maturity surface in the `/app/*` shell

## Parallelization Rules

- During `Production Certification`, only low-risk discovery and doc prep may run in parallel.
- During `Identity / Secrets / Governance`, low-risk parts of `Coverage Completion` may run in parallel if they do not change auth or secret boundaries.
- `Platform Finalization` and `Coverage Completion` can overlap after the governance model is stable.
- `batch_corr` parallelization is explicitly blocked until the safe ownership model is implemented.

## Project Closure Definition

The project is considered closed only when all of the following are true:

- the system passes certified load and failover gates
- identity and secret governance are operationally complete
- the remaining architecture debt is reduced below operational-risk level
- Windows / network / vulnerability / source surfaces are complete for the current stand
- docs match live runtime and live deploy behavior

All of the above are now satisfied for the current stand as of `March 27, 2026`.

## Post-Closure Follow-Up

The following items remain valid follow-up work, but they are no longer required for project closure on the current stand:

- external SSO client rollout for systems beyond the already-landed `Nextcloud` integration
- re-evaluation of the native `Greenbone/OpenVAS` SSO decision only if the installed product build or support posture changes
- broader vendor expansion beyond the current managed network scope
- post-power-cycle ingest recovery hardening: resolved on `2026-04-01`
  - closure record: `post_power_cycle_ingest_recovery_closure_2026-04-01.md`
- storage rebalance and retention hardening after the restart / migration pressure incident: resolved on `2026-04-05`
  - closure record: `storage_rebalance_and_retention_hardening_2026-04-05.md`
- deeper normalization and correlation packs for new monitored service families beyond the current Proxmox/OpenClaw/pilot wave
- broader fleet onboarding beyond the current hypervisor-backed environment
- deeper decomposition and scale-out beyond the pragmatic close layer
- federation layers beyond the landed `OIDC-first` Keycloak model
- further shell decomposition beyond `frontend-react/src/shell/App.tsx`
- retirement of `legacy.css` after the compatibility layer is no longer needed

## How To Use This Document

When issuing the next task, use this template:

1. name the slab
2. name the concrete outcome
3. name the expected done criteria

Examples:

- `Slab 1: certify max distributed EPS and fail the release gate below budget`
- `Slab 2: implement token rotation workflow and break-glass path`
- `Slab 3: split deps.py query domains and ingest metrics helpers`
- `Slab 4: reduce unmapped vuln targets and finish Windows fleet rollout docs`

This keeps future work aligned to the accelerated project close-out instead of the older slower wave framing.
