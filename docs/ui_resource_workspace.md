# UI resource workspace

## Scope

The React shell under `/app` is the production operator interface. It keeps the
existing Sentinel API, RBAC, topology, incident, event, source, asset, response,
and security-service contracts. The UI does not contain fallback demo records.

The shell exposes two navigation levels:

- monitoring and platform workspaces in the primary sidebar;
- security controls in the persistent secondary drawer.

Tenant scope is loaded from `GET /api/ui/tenants`, stored in the URL and local
storage, and sent as `X-SIEM-Tenant-Scope`. The server rejects unknown scopes.
Only the production `main` scope is exposed until another data tenant exists.

## Managed resources

`/app/resources` combines read-only runtime inventory with versioned managed
resources:

- collectors;
- stream and batch correlators;
- correlation rules;
- normalizers;
- filters;
- connectors, destinations, enrichment, active lists, response rules, storage,
  agents, proxies, aggregation rules, dictionaries, context tables, searches,
  secrets, segmentation rules, email templates and event routers.

Runtime-discovered resources cannot be overwritten. An operator can duplicate
one into a managed draft, validate it, and publish the draft.

Publishing reports the actual runtime result rather than treating a catalog
write as activation:

- normalizer: writes an enabled row to `siem.normalizer_rules`;
- filter: writes an enabled row to `siem.filter_rules`;
- correlation rule: creates and publishes a correlation pack into the
  detection catalog and `siem.correlation_rules_stream`;
- collector: publishes the production ingest contract and collector profile;
- connector: creates or updates the connector control-plane definition;
- response rule: creates or updates the governed response action;
- kinds without an executable runtime adapter are marked `registered`, not
  `active`, and show the missing adapter in the activation result;
- correlator definitions remain `registered` until bound to a managed running
  correlation service instance.

Inline credentials are rejected. Managed resources reference secrets through
`secret_ref`; API tokens, passwords and private keys are never persisted in the
resource catalog.

All write, validation, and publish routes retain `rules:write` or `rules:test`
permission checks.

Backend versioning, duplicate/rollback/delete safety, and Sentinel-native
package import/export are documented in `managed_resource_lifecycle.md`.

## KUMA package workflow

KUMA access uses its REST API on port `7223` with a bearer token stored in
Vault at `kv/siem/kuma-api`. `/etc/siem/web.env` contains only
`SIEM_KUMA_API_TOKEN_REF`. TLS validation uses the deployed external KUMA CA.

Supported operations follow the KUMA package API:

1. Search resources with `GET /api/v2/resources`.
2. Export with `POST /api/v1/resources/export`, then download the returned file.
3. Upload a package with `POST /api/v1/resources/upload`.
4. Import it with `POST /api/v1/resources/import`.

The package password is supplied for the current action and is never persisted.
The integration does not claim a direct create/update API that KUMA does not
provide.

## Release checks

Run before deployment:

```powershell
cd frontend-react
npm run typecheck
npm run lint
npm test
npm run build

cd ..
python -m pytest tests/test_ui_resource_workspace.py tests/test_deploy_rollout_regressions.py -q
```

Deploy VM4 with an API token file only for initial provisioning or rotation:

```powershell
$env:SIEM_KUMA_API_TOKEN_FILE = "C:\secure\kuma-api-token"
python deploy/vm4_enterprise_foundation_deploy.py
```

Do not place the token, KUMA user password, package password, or runtime
credentials in the repository.
