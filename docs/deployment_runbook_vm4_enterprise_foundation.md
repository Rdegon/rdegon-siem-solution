# VM4 Deployment Runbook: Enterprise Foundation

## Purpose

This runbook deploys the VM4 control-plane foundation that now owns:

- web UI and API
- enterprise identity and governance runtime
- Keycloak-based OIDC provider
- Vault-based runtime secret resolution
- runtime health surfaces
- Postgres control plane
- Mongo content plane
- runtime docs publication
- structured vulnerability runtime and maturity surfaces
- access-plane services:
  - `openvpn-client@home-gateway`
  - `siem-jump-tunnels`

## Baseline

- local source of truth: `C:\Users\Rdegon\Projects\siem_xfer_2026-03-25\repo`
- remote root: `/opt/siem/siem-solution`
- remote web slice: `/opt/siem/siem-solution/services/web`
- service to restart: `siem-web`
- primary operator shell surface: `/app/*`
- legacy compatibility surface: `/dashboards`

## Required Environment

- `SIEM_VM4_HOST`
- `SIEM_VM4_USER`
- `SIEM_VM4_PASSWORD`
- `SIEM_VM4_BASE_DIR`
- `SIEM_WEB_BASE_URL`
- `SIEM_WEB_ADMIN_USER`
- `SIEM_WEB_ADMIN_PASSWORD`

Use the approved operator bundle for live values.

For operator usage of the landed OIDC model and future external-app SSO integrations, use:

- `docs/sso_operations_and_external_integrations_2026-03-26.md`

## Standard Deploy

```powershell
python .\deploy\vm4_enterprise_foundation_deploy.py
python .\deploy\vm4_enterprise_foundation_smoke.py
```

The deploy path also ships:

- VM4 OpenVPN helper scripts
- `siem-jump-tunnels` unit material
- `siem-vault` and `siem-keycloak` units plus config
- the Keycloak admin runtime and `/api/auth/keycloak/*` API surface
- vulnerability policy timer and service
- asset-binding override runtime and `/api/assets/binding-overrides*`
- runtime docs content
- mirrored backend support modules required by SOAR, source discovery, and vulnerability maturity slices
- the split `query/` package and its mirrored `services/web/app/query/` runtime copy
- Windows native-agent packaging assets under `deploy/windows-agent/` and `ops/windows-agent-profile.local.example.json`
- frontend shell sources, branded assets, self-hosted fonts, and production build artifacts when `SIEM_VM4_DEPLOY_FRONTEND` is enabled

The standard `deploy-homelab.yml` path now treats frontend rollout as part of the VM4 deploy slice, not a separate manual follow-up.

The VM4 deploy also runs a remote-compatible backend regression subset before frontend build and service restart. The complete backend suite remains enforced in `Validate Main`.

Remote Python compile checks are executed with `PYTHONPYCACHEPREFIX=/tmp/siem-pycache` so carrier validation remains compatible with the deployed ownership model on `VM4`.

On the current stand, the identity bootstrap path first reuses the already-installed `Vault` and `Keycloak` runtimes on VM4 and refreshes the `current` symlinks. External vendor downloads remain fallback-only for first install or explicit runtime replacement.

The downstream green-state storage HA path now resolves Vault-backed web secrets directly on VM4 before rebuilding Mongo replica configuration. A raw `SIEM_MONGO_URI` literal is no longer required in `/etc/siem/web.env`.

Standalone VM4 runtime helpers that import `clickhouse_runtime.py` outside the main web process now also resolve `SIEM_CH_PASSWORD_REF` through Vault-backed secret resolution, so maintenance timers do not depend on a raw ClickHouse password in `web.env`.

## Mandatory Green Checks

After deploy, all of these must be healthy:

- `systemctl is-active openvpn-client@home-gateway`
- `systemctl is-active siem-jump-tunnels`
- `systemctl is-active siem-web`
- `systemctl is-active siem-vault`
- `systemctl is-active siem-keycloak`
- `GET /api/health/overview`
- `GET /api/health/certification`
- `GET /api/health/transport`
- `GET /api/health/backups`
- `GET /api/health/storage-ha`
- `GET /api/health/hosts/runtime`
- `GET /api/auth/providers`
- `GET /api/auth/governance`
- `GET /api/auth/keycloak/status`
- `GET /api/auth/keycloak/users`
- `GET /api/vuln/runtime`
- `GET /api/vuln/maturity`
- `GET /api/reports`
- `GET /api/assets/binding-overrides`

## Smoke Coverage

`deploy/vm4_enterprise_foundation_smoke.py` verifies:

- authenticated login flow
- OIDC provider registry
- governance inventory
- Keycloak admin runtime and read-only realm inventory bootstrap
- certification health surface
- certification latency budget now evaluates only the certified ceiling stage, with the initial ladder stage used as warmup when later successful stages are available
- OpenAPI availability
- control-plane and content-plane storage surfaces
- production-green health surfaces
- ingest proxy APIs
- service-account and local-user APIs
- response, reports, and vulnerability runtime APIs
- source discovery runtime APIs, including live onboarding package generation
- asset binding override APIs
- structured report artifact links
- access-plane service health
- `/app` shell bootstrap and `/app/access` identity control center bootstrap

## Follow-Up Maintenance

Publish runtime docs after major doc changes:

```powershell
python .\deploy\publish_runtime_docs.py
```

Export clean docs or bundles when handing over the stand:

```powershell
python .\deploy\export_siem_docs.py
python .\deploy\export_clean_project_bundle.py --build-binary
```

## Rollback

1. restore the backup directory printed by the deploy script
2. restart `siem-web`
3. revalidate `siem-vault`
4. revalidate `siem-keycloak`
5. revalidate `openvpn-client@home-gateway`
6. revalidate `siem-jump-tunnels`
7. rerun the smoke
