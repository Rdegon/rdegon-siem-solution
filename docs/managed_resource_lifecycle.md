# Managed Resource Lifecycle

Sentinel-managed resources use an append-only definition history. Runtime
inventory objects remain read-only and must be duplicated before they can be
edited. Publishing still uses the adapter selected by
`resource_catalog_runtime.publish_resource`: an adapter reports `applied=true`
only after it has applied the definition, while resources without an executable
adapter remain `registered`. The lifecycle layer never emits `catalog_only` and
never marks a registry-only definition active.

## State And Concurrency

- Every save creates a new resource `version` and an immutable full definition
  snapshot.
- `revision` changes on save and publish. Clients can send `expected_revision`
  on an update; delete and rollback always require it.
- Publishing does not rewrite a version snapshot. It changes the current
  deployment state and revision while preserving the definition that was
  published.
- Rollback reads an old snapshot and saves it as the next version. Existing
  snapshots are never updated or deleted.
- Deleting a draft removes only its current catalog row. Its version snapshots
  and audit records remain queryable with `deleted=true`.
- Only a `sentinel-managed`, writable resource in `draft` state with an empty
  `published_ts` can be deleted. A resource that has ever been published cannot
  be deleted through this operation, even after a later edit returns it to
  draft state.

Mutation requests use `Idempotency-Key` values of 8-160 safe characters.
Sentinel stores only the SHA-256 key identifier and a request fingerprint.
Reusing a key for the same completed operation returns the stored result;
reusing it for different arguments returns `409 idempotency_conflict`.

## API

All endpoints are tenant-scoped with `X-Tenant-Scope`; the current production
scope is `main`.

| Method | Endpoint | Permission | Behavior |
| --- | --- | --- | --- |
| `POST` | `/api/resources/catalog/{id}/duplicate` | `resources:write` | Copy a runtime/read-only or managed definition into a sanitized managed draft. |
| `GET` | `/api/resources/catalog/{id}/versions` | `resources:view` | List immutable version snapshots and current revision. |
| `GET` | `/api/resources/catalog/{id}/versions/compare?from_version=1&to_version=2` | `resources:view` | Return bounded JSON-pointer changes between definitions. |
| `POST` | `/api/resources/catalog/{id}/rollback` | `resources:write` | Create a new version from `target_version`; requires `expected_revision`. |
| `DELETE` | `/api/resources/catalog/{id}` | `resources:write` | Delete only a never-published managed draft; requires `expected_revision`. |
| `POST` | `/api/resources/catalog/export` | `resources:view` | Export selected managed definitions as a Sentinel JSON package. |
| `POST` | `/api/resources/catalog/import` | `resources:write` | Validate a multipart package and create managed drafts. |

Duplicate, rollback, delete, and import require `Idempotency-Key`. Successful
save, publish/register, duplicate, rollback, delete, package export, and package
import operations append control-plane audit events without recording resource
configuration or credentials.

## Sentinel Package Gate

The package schema is `rdegon-sentinel.resource-package/v1` and contains only
resource definitions. Imports are drafts and never publish automatically.

Bounds and gates:

- maximum package size: 1 MiB;
- maximum resource count: 100;
- maximum serialized definition size: 128 KiB;
- maximum retained versions per resource: 200; the operation fails instead of
  truncating immutable history;
- exact envelope and definition fields, unique safe source IDs, positive source
  versions, supported resource kinds, and normal resource validation;
- no `secret` resources, inline passwords/tokens/keys/cookies, credentials in
  URLs or Authorization values, private-key blocks, artifact fields, archives,
  database dumps, or large embedded base64 payloads;
- `secret_ref` references are allowed because the package contains no secret
  value. The target environment must provision that reference independently.

Imported IDs are retained only when they do not collide. A collision produces
a deterministic managed suffix and never overwrites the existing resource.

## Storage

The current catalog remains in `platform_resources`. Immutable snapshots use
`platform_resource_versions`; idempotency records use
`platform_resource_idempotency`. Both follow the configured content-store
backend with the existing filesystem mirror. Snapshots created before this
feature are not reconstructable; a legacy managed resource exposes its current
definition as the initial snapshot until its next save.
