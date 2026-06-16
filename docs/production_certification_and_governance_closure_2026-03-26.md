# Production Certification And Governance Closure: 2026-03-26

This document closes the first two slabs of the accelerated project closure plan for the current five-VM stand:

- `Slab 1: Production Certification`
- `Slab 2: Identity, Secrets, Access, Governance`

The closure date for this pass is `March 26, 2026`.

## Scope Closed In This Pass

### Production Certification

- ingest HTTP ACK path moved to batched runtime bookkeeping instead of full per-event synchronous bookkeeping
- distributed EPS benchmark promoted into the release/certification toolchain
- certification profile is now machine-readable in `ops/production_certification_profile.json`
- the first certification stage is treated as warmup for latency budgeting, and the ingest p95 gate is evaluated on the certified ceiling stage instead of on exploratory overload stages above it
- certification status is now published through `GET /api/health/certification`
- destructive drill validation is part of the production certification path for the current stand
- `Validate Main` validates the certification profile
- `Deploy Homelab` runs production certification as part of the standard green-state path

### Identity, Secrets, Access, Governance

- enterprise SSO is now `OIDC first` through `Keycloak` on `VM4`
- runtime secret backend is now `Vault` on `VM4`
- local username/password login is retained only as `break-glass`
- Vault-backed `vault://...` secret resolution is live in runtime code
- service-account rotation and break-glass workflows are operationally visible
- response approvals now enforce policy-pack, quorum, expiry, trigger-kind, and linkage rules
- operator UX for this slab ships in the `/app/*` shell surfaces

## Implemented Runtime Model

### Identity

- primary human auth provider: `Enterprise SSO`
- provider type: `OIDC`
- live issuer: `http://192.168.1.39:8081/realms/siem`
- retained fallback: `Break-glass local login`
- `SAML/LDAP/AD` remain future provider layers behind the landed OIDC-first model; they are not separate live login paths for the current stand

### Secrets

- live secret backend: `Vault 1.21.3`
- runtime auth method: `AppRole`
- current healthy auth source: `approle_cache`
- runtime-critical secret refs now resolve through `vault://...`
- live vault-backed references confirmed in governance inventory:
  - JWT signing
  - ClickHouse password
  - Mongo URI
  - Greenbone password

### Governance

- `/api/auth/providers` exposes the live provider registry
- `/api/auth/governance` exposes service-account, break-glass, and secret governance inventory
- `/api/auth/break-glass` is the explicit break-glass lifecycle surface
- `/api/auth/service-accounts/{service_account_id}/rotate` is the service-account rotation surface
- response execution now requires stronger linkage between `detection -> case/finding/report -> action`, unless a valid break-glass path is used

## Certification Result

Live certification state on `March 26, 2026`:

- certification health: `healthy`
- latest certified ceiling: `runtime-published through GET /api/health/certification`
- minimum delivery ratio: `0.995`
- latency budget warmup skip: `1 initial stage`
- ingest p95 latency budget: `22000 ms`
- Kafka lag budget: `5000`
- post-benchmark health: `healthy`

This is exposed to operators through:

- `GET /api/health/certification`

## Live Acceptance Evidence

Live operator checks on `March 26, 2026` confirmed:

- `/api/health/overview` returned `issues=[]`
- transport backend is `kafka`
- content backend is `mongo`
- OIDC provider registry is healthy with:
  - `enterprise-oidc`
  - `break-glass-local`
- governance inventory reports:
  - `providers_healthy=2`
  - `vault_healthy=true`
  - `vault_backed=4`
  - `required_missing=0`
  - `local_users_plaintext=0`
- `deploy/vm4_enterprise_foundation_smoke.py` completed with `smoke=success`

Additional same-day stabilization required after the initial close-out push:

- VM4 self-hosted deploy was hardened to reuse the already-installed `Vault` and `Keycloak` runtimes before attempting vendor downloads, so the standard `Deploy Homelab` path no longer depends on `releases.hashicorp.com` reachability from the self-hosted runner network
- the storage HA wave now resolves Vault-backed references directly on `VM4` before rebuilding the Mongo replica-set URI, so `Deploy Homelab` no longer depends on a raw `SIEM_MONGO_URI` literal inside `/etc/siem/web.env`
- the storage HA wave now runs `mongosh` through a remote `.js` script instead of inline `--eval` quoting, which removes the previous UTF-8 / quoting failure mode during Mongo user and replica-set reconciliation
- VM1 ingest health gating now excludes the legacy `generic-http` source and collector identities from stale blocking while continuing to count real active collectors and sources
- standalone VM4 maintenance processes such as the host-runtime monitor now resolve Vault-backed ClickHouse credentials even if they fall back to env-based runtime config instead of the full web config object
- the live ingest DLQ backlog caused by transient `ProducerClosed` replayable syslog failures was drained back to `outstanding=0` through the live `/dlq/replay` path
- final end-to-end smoke was rerun after this stabilization and returned `smoke=success`

## UI / UX Surface For This Slab

The operator surface for this closure work is the React shell under `/app/*`.

Primary operator workspaces for this pass:

- `/app` shell bootstrap
- Access / Identity / Governance workspace
- Response / Approval / Execution Control workspace

Legacy routes such as `/dashboards` remain historical compatibility surfaces and are not the primary UI for this closure layer.

## Standard Delivery Path After This Pass

The standard path for these slabs is now:

1. `main` push
2. `Validate Main`
3. `Deploy Homelab`
4. VM4 foundation smoke
5. production certification health gate

`deploy/vm4_enterprise_foundation_deploy.py` now deploys:

- Keycloak
- Vault
- OIDC-aware auth runtime
- governance APIs
- frontend `/app/*` shell updates

Its remote backend test step is intentionally a `remote-compatible subset`, while the full backend suite remains enforced in `Validate Main`.

The VM4 deploy carrier now also treats already-installed `Vault` and `Keycloak` runtimes as the primary bootstrap path on the current stand, using external vendor downloads only as fallback installation material.

## Closure Impact On The Main Plan

The accelerated closure plan changes after this pass:

- `Slab 1` is now closed for the current stand
- `Slab 2` is now closed for the current stand
- remaining active slabs are now:
  - `Slab 3: Platform Finalization`
  - `Slab 4: Coverage Completion`
