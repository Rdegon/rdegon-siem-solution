# Pilot SSO And Correlation Wave 2026-03-28

## Summary

This wave closes three live operator gaps together:

1. pilot application SSO and bootstrap state
2. clean operator-facing access documentation
3. dedicated correlation-pack authoring and publish flow

The live outcome of this wave is:

- `Gitea` on `pilot-web-01` now uses native Keycloak OIDC as the primary human login path
- `Navidrome` on `navidrome-01` now uses browser SSO through `oauth2-proxy + nginx` against the same Keycloak realm
- both pilot apps have local break-glass admin accounts recorded in the operator bundle
- `/app/access` now exposes `gitea` and `navidrome` as grantable systems
- `Builders` now includes a dedicated `Correlation` workspace backed by `correlation_rule_packs/*.json`
- event enrichment now carries stronger fleet/app/source identity for investigation surfaces

## Live Fixes Found During Browser Pass

The final live browser verification exposed additional runtime drift that had to be fixed on the same pass before the wave could be considered complete.

### Gitea

- Keycloak initially rejected the Gitea login flow with `Invalid parameter: redirect_uri`
- the `pilot-gitea` Keycloak client was corrected to allow:
  - `http://192.168.1.34:3000/*`
- Gitea then failed on the stored OIDC scopes because the auth source carried a malformed combined value and an unsupported `groups` scope
- the deploy flow now normalizes the Gitea auth source to:
  - `profile`
  - `email`
- the deploy flow also now enforces the intended bootstrap state in `app.ini`:
  - public registration disabled for unauthenticated local users
  - external-only auto registration enabled for Keycloak logins
  - automatic account linking enabled for the OIDC path

### Navidrome

- `oauth2-proxy` initially failed with an invalid scope set because it also requested `groups`
- the proxy scope is now constrained to:
  - `openid`
  - `profile`
  - `email`
- after authentication succeeded, `nginx` returned `502 Bad Gateway` because the split auth cookies from `oauth2-proxy` exceeded the default upstream header buffers
- the live fix is now encoded in the shipped `nginx` config:
  - larger proxy header buffers
  - explicit bypasses for `favicon.ico`
  - explicit bypasses for `app/manifest.webmanifest`

### VM4 Runtime

- the final smoke pass exposed one more live drift item on the standby ClickHouse path:
  - `siem.events_shadow` was missing on the standby node
- the missing table was created on the standby runtime and the final `VM4` enterprise foundation deploy was rerun so the web/API node republished fresh runtime state
- only after that redeploy did both:
  - `deploy/pilot_sso_correlation_wave_smoke.py`
  - `deploy/vm4_enterprise_foundation_smoke.py`
  return `success`

## Access Model Changes

Grantable systems added in this wave:

- `gitea`
- `navidrome`

Enforcement modes:

- `gitea` -> `native_oidc`
- `navidrome` -> `proxy_extauth`

Curated roles and sections:

- `gitea`
  - roles: `user`, `admin`
  - sections: `repos`, `issues`, `wiki`, `packages`, `admin`
- `navidrome`
  - roles: `user`, `admin`
  - sections: `library`, `playlists`, `sharing`, `admin`

Mirrored groups:

- `gitea-users`
- `gitea-admins`
- `navidrome-users`
- `navidrome-admins`

The access-system catalog and grant mirror remain managed from the SIEM control plane, with Keycloak acting as the identity carrier.

## Pilot Bootstrap State

### Gitea

- internal URL: `http://192.168.1.34:3000`
- auth source present: `Keycloak SSO`
- public registration disabled
- local break-glass admin present
- primary human login path: native Keycloak OIDC

### Navidrome

- internal URL: `http://192.168.1.121`
- front door: `nginx` with `oauth2-proxy`
- local application listener remains `127.0.0.1:4533`
- seeded SSO admin exists in Keycloak and Navidrome state
- local break-glass admin is stored in the Navidrome SQLite state
- primary human login path: proxy-based browser SSO

## Correlation Authoring

The dedicated correlation workspace now lives under:

- `/app/builders?workspace=correlation`

New API surface:

- `GET /api/correlation/packs`
- `GET /api/correlation/packs/{pack_id}`
- `POST /api/correlation/packs`
- `POST /api/correlation/packs/{pack_id}/validate`
- `POST /api/correlation/packs/{pack_id}/test`
- `POST /api/correlation/packs/{pack_id}/publish`

New pack families added in this wave:

- `identity_access_v1`
- `gitea_activity_v1`
- `navidrome_activity_v1`
- `scanner_runtime_v1`

Existing operational publish flow remains:

```powershell
python deploy/publish_operational_rule_packs.py
```

## Event Enrichment

The event read path now enriches runtime rows with additional fleet and app identity fields:

- `asset_name`
- `asset_role`
- `business_service`
- `criticality`
- `fleet_state`
- `scanner_family`
- `source_family`
- `dns_query_name`
- `destination_host`
- `destination_ip`
- `destination_port`
- `app_family`
- `route_family`
- `keycloak_principal`

This enrichment is consumed by the current investigation surfaces so `Events`, `Assets`, `Entities`, and `Threat Intel` can pivot on the same canonical object identity.

## Validation

Local validation:

- `pytest tests/test_access_grants.py tests/test_correlation_pack_runtime.py`
- frontend targeted tests for `AccessWorkspace` and `Builders correlation workspace`
- frontend `typecheck`
- frontend `lint`
- frontend `build`

Live validation:

- `deploy/pilot_sso_correlation_wave_deploy.py`
- `deploy/pilot_sso_correlation_wave_smoke.py`
- `deploy/vm4_enterprise_foundation_smoke.py`
- live browser pass with fresh screenshots in:
  - `.artifacts/browser/pilot-sso-correlation-wave-2026-03-28/`

Operator docs updated in this wave:

- `access/operator_docs/SYSTEM_ACCESS_MATRIX.md`
- `access/operator_docs/OPERATOR_ACCESS_BUNDLE.md`
- `docs/correlation_rules.md`

## Notes

- `Proxmox` remains `monitored-only`; it was not added to the grant selector.
- `Navidrome` SSO is intentionally proxy-based rather than native OIDC.
- Local break-glass accounts remain documented for both pilot apps as recovery paths.
