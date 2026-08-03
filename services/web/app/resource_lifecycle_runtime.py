from __future__ import annotations

import hashlib
import json
import os
import re
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from threading import RLock
from typing import Any, Callable

from .content_store import load_list, save_list
from .control_plane_governance_runtime import append_audit_event
from .tenant_scope_runtime import validate_tenant_scope_header

SNAPSHOT_FILE = Path(
    os.getenv("SIEM_RESOURCE_VERSION_FILE", "/opt/siem/runtime-docs/platform_resource_versions.json")
)
IDEMPOTENCY_FILE = Path(
    os.getenv("SIEM_RESOURCE_IDEMPOTENCY_FILE", "/opt/siem/runtime-docs/platform_resource_idempotency.json")
)
PACKAGE_SCHEMA = "rdegon-sentinel.resource-package/v1"
MAX_PACKAGE_BYTES = 1_048_576
MAX_PACKAGE_RESOURCES = 100
MAX_RESOURCE_BYTES = 131_072
MAX_VERSIONS_PER_RESOURCE = 200
MAX_IDEMPOTENCY_ROWS = 2_000

_LOCK = RLock()
_IDEMPOTENCY_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{7,159}")
_SAFE_ID_PATTERN = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,127}")
_ARTIFACT_KEYS = {
    "artifact",
    "artifacts",
    "attachment",
    "attachments",
    "binary",
    "blob",
    "file_content",
    "archive_content",
    "database_dump",
}
_ARTIFACT_SUFFIXES = (".zip", ".tar", ".tar.gz", ".tgz", ".7z", ".dump", ".sqlite", ".db", ".pfx", ".p12")
_SECRET_MARKERS = ("-----BEGIN PRIVATE KEY-----", "-----BEGIN OPENSSH PRIVATE KEY-----")
_URL_CREDENTIALS = re.compile(r"(?i)^[a-z][a-z0-9+.-]*://[^/\s:@]+:[^/@\s]+@")
_AUTHORIZATION_VALUE = re.compile(r"(?i)\b(?:basic|bearer)\s+[a-z0-9+/=._-]{8,}")
_BASE64_BLOB = re.compile(r"[A-Za-z0-9+/]{4096,}={0,2}")
_DEFINITION_FIELDS = ("name", "kind", "description", "tenant_id", "config", "bindings")


class ResourceLifecycleError(ValueError):
    def __init__(self, message: str, *, code: str = "invalid_request", status_code: int = 400) -> None:
        super().__init__(message)
        self.code = code
        self.status_code = status_code


def _catalog():
    from . import resource_catalog_runtime

    return resource_catalog_runtime


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _load_snapshots() -> list[dict[str, Any]]:
    SNAPSHOT_FILE.parent.mkdir(parents=True, exist_ok=True)
    return load_list("platform_resource_versions", SNAPSHOT_FILE, [])


def _save_snapshots(rows: list[dict[str, Any]]) -> None:
    save_list("platform_resource_versions", SNAPSHOT_FILE, rows)


def _load_idempotency() -> list[dict[str, Any]]:
    IDEMPOTENCY_FILE.parent.mkdir(parents=True, exist_ok=True)
    return load_list("platform_resource_idempotency", IDEMPOTENCY_FILE, [])


def _save_idempotency(rows: list[dict[str, Any]]) -> None:
    save_list("platform_resource_idempotency", IDEMPOTENCY_FILE, rows[-MAX_IDEMPOTENCY_ROWS:])


def _tenant(value: str) -> str:
    try:
        selected = validate_tenant_scope_header(str(value or "main"))
    except ValueError as exc:
        raise ResourceLifecycleError(str(exc), code="invalid_tenant_scope") from exc
    if len(selected) != 1:
        raise ResourceLifecycleError("Exactly one tenant is required", code="invalid_tenant_scope")
    return selected[0]


def _assert_tenant(resource: dict[str, Any], tenant_id: str) -> None:
    actual = str(resource.get("tenant_id") or "main")
    if actual != tenant_id:
        raise ResourceLifecycleError("Resource is outside the selected tenant", code="tenant_mismatch", status_code=404)


def _json_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _definition(resource: dict[str, Any]) -> dict[str, Any]:
    result = {field: deepcopy(resource.get(field)) for field in _DEFINITION_FIELDS}
    result["name"] = str(result.get("name") or "").strip()
    result["kind"] = str(result.get("kind") or "").strip()
    result["description"] = str(result.get("description") or "").strip()
    result["tenant_id"] = str(result.get("tenant_id") or "main")
    result["config"] = dict(result.get("config") or {})
    result["bindings"] = dict(result.get("bindings") or {})
    _package_gate(result, path="resource")
    if len(_json_bytes(result)) > MAX_RESOURCE_BYTES:
        raise ResourceLifecycleError("Resource definition exceeds the size limit", code="resource_too_large", status_code=413)
    return result


def _snapshot(resource: dict[str, Any], *, actor: str, action: str) -> dict[str, Any]:
    resource_id = str(resource.get("id") or "").strip()
    version = int(resource.get("version") or 0)
    if not _SAFE_ID_PATTERN.fullmatch(resource_id) or version <= 0:
        raise ResourceLifecycleError("Resource id and positive version are required", code="invalid_resource")
    definition = _definition(resource)
    tenant_id = _tenant(str(definition.get("tenant_id") or "main"))
    return {
        "id": f"{tenant_id}:{resource_id}:{version}",
        "resource_id": resource_id,
        "tenant_id": tenant_id,
        "version": version,
        "definition_hash": hashlib.sha256(_json_bytes(definition)).hexdigest(),
        "definition": definition,
        "created_ts": _now_iso(),
        "created_by": str(actor or "system")[:128],
        "action": str(action or "save")[:32],
        "immutable": True,
    }


def record_resource_version(resource: dict[str, Any], *, actor: str, action: str = "save") -> dict[str, Any]:
    """Persist one immutable definition snapshot; an existing version can never be replaced."""
    candidate = _snapshot(resource, actor=actor, action=action)
    with _LOCK:
        rows = [dict(item) for item in _load_snapshots() if isinstance(item, dict)]
        existing = next((item for item in rows if str(item.get("id") or "") == candidate["id"]), None)
        if existing:
            if str(existing.get("definition_hash") or "") != candidate["definition_hash"]:
                raise ResourceLifecycleError(
                    "Immutable resource version already exists with different content",
                    code="immutable_version_conflict",
                    status_code=409,
                )
            return existing
        count = sum(
            1
            for item in rows
            if str(item.get("resource_id") or "") == candidate["resource_id"]
            and str(item.get("tenant_id") or "main") == candidate["tenant_id"]
        )
        if count >= MAX_VERSIONS_PER_RESOURCE:
            raise ResourceLifecycleError("Resource version limit reached", code="version_limit", status_code=409)
        rows.append(candidate)
        _save_snapshots(rows)
    return candidate


def _current_resource(resource_id: str, tenant_id: str) -> dict[str, Any]:
    try:
        resource = dict(_catalog().get_resource(resource_id))
    except ValueError as exc:
        raise ResourceLifecycleError(str(exc), code="resource_not_found", status_code=404) from exc
    _assert_tenant(resource, tenant_id)
    return resource


def _stored_versions(resource_id: str, tenant_id: str) -> list[dict[str, Any]]:
    return [
        dict(item)
        for item in _load_snapshots()
        if str(item.get("resource_id") or "") == resource_id
        and str(item.get("tenant_id") or "main") == tenant_id
    ]


def _versions(resource_id: str, tenant_id: str) -> list[dict[str, Any]]:
    rows = _stored_versions(resource_id, tenant_id)
    try:
        current = _current_resource(resource_id, tenant_id)
    except ResourceLifecycleError as exc:
        if exc.code != "resource_not_found" or not rows:
            raise
    else:
        if str(current.get("origin") or "") != "sentinel-managed" or bool(current.get("read_only")):
            raise ResourceLifecycleError(
                "Version history is available only for Sentinel-managed resources; duplicate this resource first",
                code="not_managed",
                status_code=409,
            )
        current_version = int(current.get("version") or 0)
        if current_version > 0 and not any(int(item.get("version") or 0) == current_version for item in rows):
            rows.append(_snapshot(current, actor="legacy-import", action="legacy_current"))
    rows.sort(key=lambda item: int(item.get("version") or 0), reverse=True)
    return rows


def list_resource_versions(resource_id: str, *, tenant_id: str = "main") -> dict[str, Any]:
    safe_tenant = _tenant(tenant_id)
    items = _versions(resource_id, safe_tenant)
    try:
        current = _current_resource(resource_id, safe_tenant)
    except ResourceLifecycleError as exc:
        if exc.code != "resource_not_found" or not items:
            raise
        current = {}
    return {
        "resource_id": resource_id,
        "tenant_id": safe_tenant,
        "current_version": int(current.get("version") or 0) or None,
        "current_revision": int(current.get("revision") or current.get("version") or 0) or None,
        "deleted": not bool(current),
        "items": items,
        "total": len(items),
    }


def _version(resource_id: str, tenant_id: str, version: int) -> dict[str, Any]:
    item = next((row for row in _versions(resource_id, tenant_id) if int(row.get("version") or 0) == version), None)
    if not item:
        raise ResourceLifecycleError("Resource version was not found", code="version_not_found", status_code=404)
    return item


def _diff_values(before: Any, after: Any, *, path: str = "", changes: list[dict[str, Any]]) -> None:
    if len(changes) >= 500:
        return
    if isinstance(before, dict) and isinstance(after, dict):
        for key in sorted(set(before) | set(after)):
            child = f"{path}/{str(key).replace('~', '~0').replace('/', '~1')}"
            if key not in before:
                changes.append({"op": "add", "path": child, "after": deepcopy(after[key])})
            elif key not in after:
                changes.append({"op": "remove", "path": child, "before": deepcopy(before[key])})
            else:
                _diff_values(before[key], after[key], path=child, changes=changes)
        return
    if isinstance(before, list) and isinstance(after, list):
        if before != after:
            changes.append({"op": "replace", "path": path or "/", "before": deepcopy(before), "after": deepcopy(after)})
        return
    if before != after:
        changes.append({"op": "replace", "path": path or "/", "before": deepcopy(before), "after": deepcopy(after)})


def compare_resource_versions(
    resource_id: str,
    *,
    from_version: int,
    to_version: int,
    tenant_id: str = "main",
) -> dict[str, Any]:
    safe_tenant = _tenant(tenant_id)
    before = _version(resource_id, safe_tenant, int(from_version))
    after = _version(resource_id, safe_tenant, int(to_version))
    changes: list[dict[str, Any]] = []
    _diff_values(before["definition"], after["definition"], changes=changes)
    return {
        "resource_id": resource_id,
        "tenant_id": safe_tenant,
        "from_version": int(from_version),
        "to_version": int(to_version),
        "identical": not changes,
        "changes": changes,
        "truncated": len(changes) >= 500,
    }


def _fingerprint(action: str, payload: dict[str, Any]) -> str:
    return hashlib.sha256(_json_bytes({"action": action, "payload": payload})).hexdigest()


def _reserve_idempotency(key: str, action: str, payload: dict[str, Any]) -> dict[str, Any] | None:
    if not _IDEMPOTENCY_PATTERN.fullmatch(str(key or "")):
        raise ResourceLifecycleError("A valid Idempotency-Key is required", code="invalid_idempotency_key")
    fingerprint = _fingerprint(action, payload)
    key_hash = hashlib.sha256(str(key).encode("utf-8")).hexdigest()
    with _LOCK:
        rows = [dict(item) for item in _load_idempotency() if isinstance(item, dict)]
        existing = next((item for item in rows if str(item.get("id") or "") == key_hash), None)
        if existing:
            if str(existing.get("fingerprint") or "") != fingerprint:
                raise ResourceLifecycleError(
                    "Idempotency key was already used for another operation",
                    code="idempotency_conflict",
                    status_code=409,
                )
            if str(existing.get("status") or "") == "completed" and isinstance(existing.get("response"), dict):
                return {**deepcopy(existing["response"]), "idempotent_replay": True}
            raise ResourceLifecycleError("The operation is already in progress", code="operation_in_progress", status_code=409)
        rows.append(
            {
                "id": key_hash,
                "fingerprint": fingerprint,
                "action": action,
                "status": "pending",
                "created_ts": _now_iso(),
            }
        )
        _save_idempotency(rows)
    return None


def _complete_idempotency(key: str, response: dict[str, Any]) -> None:
    key_hash = hashlib.sha256(str(key).encode("utf-8")).hexdigest()
    with _LOCK:
        rows = [dict(item) for item in _load_idempotency() if isinstance(item, dict)]
        for item in rows:
            if str(item.get("id") or "") == key_hash:
                item["status"] = "completed"
                item["completed_ts"] = _now_iso()
                item["response"] = deepcopy(response)
                break
        _save_idempotency(rows)


def _release_idempotency(key: str) -> None:
    key_hash = hashlib.sha256(str(key).encode("utf-8")).hexdigest()
    with _LOCK:
        _save_idempotency([item for item in _load_idempotency() if str(item.get("id") or "") != key_hash])


def _idempotent_mutation(
    *,
    key: str,
    action: str,
    payload: dict[str, Any],
    operation: Callable[[], dict[str, Any]],
) -> dict[str, Any]:
    replay = _reserve_idempotency(key, action, payload)
    if replay is not None:
        return replay
    try:
        result = operation()
    except Exception:
        _release_idempotency(key)
        raise
    result = {**result, "idempotent_replay": False}
    _complete_idempotency(key, result)
    return result


def _unique_resource_id(kind: str, name: str, *, preferred: str = "") -> str:
    catalog = _catalog()
    existing = {str(item.get("id") or "") for item in catalog._stored_resources()}
    if preferred and _SAFE_ID_PATTERN.fullmatch(preferred) and preferred not in existing and not preferred.startswith("runtime-"):
        return preferred
    base = f"{kind.lower()}-{catalog._slug(name)}"[:120].rstrip("-_") or f"{kind.lower()}-imported"
    candidate = base
    index = 2
    while candidate in existing:
        suffix = f"-{index}"
        candidate = f"{base[:128 - len(suffix)]}{suffix}"
        index += 1
    return candidate


def duplicate_resource(
    resource_id: str,
    *,
    actor: str,
    idempotency_key: str,
    tenant_id: str = "main",
    name: str = "",
) -> dict[str, Any]:
    safe_tenant = _tenant(tenant_id)
    mutation = {"resource_id": resource_id, "tenant_id": safe_tenant, "name": str(name or "").strip()}

    def operation() -> dict[str, Any]:
        catalog = _catalog()
        with catalog.RESOURCE_MUTATION_LOCK:
            source = _current_resource(resource_id, safe_tenant)
            if str(source.get("kind") or "") == "secret":
                raise ResourceLifecycleError("Secret resources cannot be duplicated", code="secret_resource_forbidden")
            duplicate_name = str(name or "").strip() or f"{source.get('name') or resource_id} copy"
            config = catalog._sanitize_config(deepcopy(dict(source.get("config") or {})))
            duplicate_id = _unique_resource_id(str(source.get("kind") or "resource"), duplicate_name)
            created = catalog.save_resource(
                {
                    "id": duplicate_id,
                    "name": duplicate_name,
                    "kind": str(source.get("kind") or ""),
                    "description": str(source.get("description") or ""),
                    "tenant_id": safe_tenant,
                    "config": config,
                    "bindings": deepcopy(dict(source.get("bindings") or {})),
                },
                actor=actor,
            )
        append_audit_event(
            actor=actor,
            action="resource.duplicated",
            object_type="platform_resource",
            object_id=str(created["id"]),
            summary=f"Duplicated resource {resource_id} into managed draft {created['id']}",
            details={"source_id": resource_id, "tenant_id": safe_tenant, "version": created["version"]},
        )
        return {"status": "created", "resource": created, "source_id": resource_id}

    return _idempotent_mutation(key=idempotency_key, action="duplicate", payload=mutation, operation=operation)


def rollback_resource(
    resource_id: str,
    *,
    target_version: int,
    expected_revision: int,
    actor: str,
    idempotency_key: str,
    tenant_id: str = "main",
) -> dict[str, Any]:
    safe_tenant = _tenant(tenant_id)
    mutation = {
        "resource_id": resource_id,
        "target_version": int(target_version),
        "expected_revision": int(expected_revision),
        "tenant_id": safe_tenant,
    }

    def operation() -> dict[str, Any]:
        catalog = _catalog()
        with catalog.RESOURCE_MUTATION_LOCK:
            current = _current_resource(resource_id, safe_tenant)
            if str(current.get("origin") or "") != "sentinel-managed" or bool(current.get("read_only")):
                raise ResourceLifecycleError("Only Sentinel-managed resources can be rolled back", code="not_managed", status_code=409)
            revision = int(current.get("revision") or current.get("version") or 0)
            if revision != int(expected_revision):
                raise ResourceLifecycleError(
                    f"Resource changed concurrently: expected revision {expected_revision}, current revision {revision}",
                    code="revision_conflict",
                    status_code=409,
                )
            if int(current.get("version") or 0) == int(target_version):
                raise ResourceLifecycleError("Target version is already current", code="version_already_current", status_code=409)
            target = _version(resource_id, safe_tenant, int(target_version))
            definition = deepcopy(dict(target.get("definition") or {}))
            created = catalog.save_resource({"id": resource_id, **definition}, actor=actor)
        append_audit_event(
            actor=actor,
            action="resource.rolled_back",
            object_type="platform_resource",
            object_id=resource_id,
            summary=f"Rolled resource {resource_id} back to version {target_version} as version {created['version']}",
            details={
                "tenant_id": safe_tenant,
                "source_version": int(target_version),
                "created_version": int(created["version"]),
                "previous_revision": revision,
            },
        )
        return {"status": "created", "resource": created, "rolled_back_from_version": int(target_version)}

    return _idempotent_mutation(key=idempotency_key, action="rollback", payload=mutation, operation=operation)


def delete_unpublished_draft(
    resource_id: str,
    *,
    expected_revision: int,
    actor: str,
    idempotency_key: str,
    tenant_id: str = "main",
) -> dict[str, Any]:
    safe_tenant = _tenant(tenant_id)
    mutation = {
        "resource_id": resource_id,
        "expected_revision": int(expected_revision),
        "tenant_id": safe_tenant,
    }

    def operation() -> dict[str, Any]:
        catalog = _catalog()
        with catalog.RESOURCE_MUTATION_LOCK:
            resource = _current_resource(resource_id, safe_tenant)
            revision = int(resource.get("revision") or resource.get("version") or 0)
            if revision != int(expected_revision):
                raise ResourceLifecycleError("Resource revision does not match", code="revision_conflict", status_code=409)
            if str(resource.get("origin") or "") != "sentinel-managed" or bool(resource.get("read_only")):
                raise ResourceLifecycleError("Only Sentinel-managed drafts can be deleted", code="not_managed", status_code=409)
            if str(resource.get("status") or "") != "draft" or str(resource.get("published_ts") or "").strip():
                raise ResourceLifecycleError(
                    "Only drafts that have never been published can be deleted",
                    code="published_resource_forbidden",
                    status_code=409,
                )
            rows = [item for item in catalog._stored_resources() if str(item.get("id") or "") != resource_id]
            catalog._save_resources(rows)
        append_audit_event(
            actor=actor,
            action="resource.draft_deleted",
            object_type="platform_resource",
            object_id=resource_id,
            summary=f"Deleted unpublished managed draft {resource_id}",
            details={"tenant_id": safe_tenant, "revision": revision, "history_retained": True},
        )
        return {
            "status": "deleted",
            "resource_id": resource_id,
            "tenant_id": safe_tenant,
            "deleted_revision": revision,
            "version_history_retained": True,
        }

    return _idempotent_mutation(key=idempotency_key, action="delete_draft", payload=mutation, operation=operation)


def _package_gate(value: Any, *, path: str = "package") -> None:
    catalog = _catalog()
    secret_paths = catalog._inline_secret_paths(value, prefix=path)
    if secret_paths:
        raise ResourceLifecycleError(
            f"Package contains inline secrets: {', '.join(secret_paths[:5])}",
            code="secret_gate_failed",
        )

    def visit(item: Any, item_path: str) -> None:
        if isinstance(item, dict):
            for key, child in item.items():
                normalized = str(key).strip().lower()
                child_path = f"{item_path}.{key}"
                if normalized in _ARTIFACT_KEYS and child not in (None, "", [], {}):
                    raise ResourceLifecycleError(f"Package artifact field is forbidden: {child_path}", code="artifact_gate_failed")
                visit(child, child_path)
        elif isinstance(item, list):
            for index, child in enumerate(item):
                visit(child, f"{item_path}[{index}]")
        elif isinstance(item, str):
            upper = item.upper()
            if any(marker in upper for marker in _SECRET_MARKERS):
                raise ResourceLifecycleError(f"Private key material is forbidden: {item_path}", code="secret_gate_failed")
            if _URL_CREDENTIALS.search(item) or _AUTHORIZATION_VALUE.search(item):
                raise ResourceLifecycleError(f"Embedded credentials are forbidden: {item_path}", code="secret_gate_failed")
            if len(item) > 4_096 and _BASE64_BLOB.fullmatch(item.strip()):
                raise ResourceLifecycleError(f"Embedded binary payload is forbidden: {item_path}", code="artifact_gate_failed")
            lower = item.lower().split("?", 1)[0]
            if len(item) > 4_096 and lower.endswith(_ARTIFACT_SUFFIXES):
                raise ResourceLifecycleError(f"Embedded artifact is forbidden: {item_path}", code="artifact_gate_failed")

    visit(value, path)


def export_resource_package(
    resource_ids: list[str],
    *,
    actor: str,
    tenant_id: str = "main",
) -> dict[str, Any]:
    safe_tenant = _tenant(tenant_id)
    ids = list(dict.fromkeys(str(item or "").strip() for item in resource_ids if str(item or "").strip()))
    if not ids:
        raise ResourceLifecycleError("At least one resource id is required", code="empty_package")
    if len(ids) > MAX_PACKAGE_RESOURCES:
        raise ResourceLifecycleError("Package resource count exceeds the limit", code="package_count_limit", status_code=413)
    resources: list[dict[str, Any]] = []
    for resource_id in ids:
        if not _SAFE_ID_PATTERN.fullmatch(resource_id) or resource_id.startswith("runtime-"):
            raise ResourceLifecycleError("Package resource id is invalid", code="invalid_resource")
        resource = _current_resource(resource_id, safe_tenant)
        if str(resource.get("origin") or "") != "sentinel-managed" or bool(resource.get("read_only")):
            raise ResourceLifecycleError("Only Sentinel-managed resources can be exported", code="not_managed", status_code=409)
        if str(resource.get("kind") or "") == "secret":
            raise ResourceLifecycleError("Secret resources cannot be exported", code="secret_resource_forbidden")
        resources.append(
            {
                "source_id": resource_id,
                "source_version": int(resource.get("version") or 0),
                "definition": _definition(resource),
            }
        )
    package = {
        "schema": PACKAGE_SCHEMA,
        "tenant_id": safe_tenant,
        "exported_ts": _now_iso(),
        "resources": resources,
    }
    _package_gate(package)
    content = _json_bytes(package)
    if len(content) > MAX_PACKAGE_BYTES:
        raise ResourceLifecycleError("Package exceeds the size limit", code="package_too_large", status_code=413)
    package_id = hashlib.sha256(content).hexdigest()
    append_audit_event(
        actor=actor,
        action="resource.package_exported",
        object_type="platform_resource_package",
        object_id=package_id,
        summary=f"Exported {len(resources)} Sentinel resources",
        details={"tenant_id": safe_tenant, "resource_ids": ids, "bytes": len(content)},
    )
    return {"package_id": package_id, "content": content, "resource_count": len(resources), "tenant_id": safe_tenant}


def _parse_package(content: bytes | dict[str, Any]) -> tuple[dict[str, Any], bytes]:
    if isinstance(content, dict):
        raw = _json_bytes(content)
        package = deepcopy(content)
    else:
        raw = bytes(content)
        if len(raw) > MAX_PACKAGE_BYTES:
            raise ResourceLifecycleError("Package exceeds the size limit", code="package_too_large", status_code=413)
        try:
            package = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ResourceLifecycleError("Package must be UTF-8 JSON", code="invalid_package_schema") from exc
    if len(raw) > MAX_PACKAGE_BYTES:
        raise ResourceLifecycleError("Package exceeds the size limit", code="package_too_large", status_code=413)
    if not isinstance(package, dict) or str(package.get("schema") or "") != PACKAGE_SCHEMA:
        raise ResourceLifecycleError("Unsupported Sentinel resource package schema", code="invalid_package_schema")
    allowed = {"schema", "tenant_id", "exported_ts", "resources"}
    if set(package) - allowed:
        raise ResourceLifecycleError("Package contains unsupported top-level fields", code="invalid_package_schema")
    resources = package.get("resources")
    if not isinstance(resources, list) or not resources:
        raise ResourceLifecycleError("Package resources must be a non-empty array", code="invalid_package_schema")
    if len(resources) > MAX_PACKAGE_RESOURCES:
        raise ResourceLifecycleError("Package resource count exceeds the limit", code="package_count_limit", status_code=413)
    if not isinstance(package.get("exported_ts"), str) or not str(package.get("exported_ts") or "").strip():
        raise ResourceLifecycleError("Package exported_ts is required", code="invalid_package_schema")
    _package_gate(package)
    return package, raw


def import_resource_package(
    content: bytes | dict[str, Any],
    *,
    actor: str,
    idempotency_key: str,
    tenant_id: str = "main",
) -> dict[str, Any]:
    safe_tenant = _tenant(tenant_id)
    package, raw = _parse_package(content)
    source_tenant = _tenant(str(package.get("tenant_id") or "main"))
    definitions: list[tuple[str, dict[str, Any]]] = []
    source_ids: set[str] = set()
    for index, item in enumerate(package["resources"]):
        if not isinstance(item, dict) or set(item) - {"source_id", "source_version", "definition"}:
            raise ResourceLifecycleError(f"Invalid resource envelope at index {index}", code="invalid_package_schema")
        source_id = str(item.get("source_id") or "").strip()
        if not _SAFE_ID_PATTERN.fullmatch(source_id) or source_id.startswith("runtime-"):
            raise ResourceLifecycleError(f"Invalid source_id at index {index}", code="invalid_package_schema")
        if source_id in source_ids:
            raise ResourceLifecycleError(f"Duplicate source_id at index {index}", code="invalid_package_schema")
        source_ids.add(source_id)
        try:
            source_version = int(item.get("source_version") or 0)
        except (TypeError, ValueError) as exc:
            raise ResourceLifecycleError(f"Invalid source_version at index {index}", code="invalid_package_schema") from exc
        if source_version <= 0:
            raise ResourceLifecycleError(f"Invalid source_version at index {index}", code="invalid_package_schema")
        definition = item.get("definition")
        if not isinstance(definition, dict) or set(definition) != set(_DEFINITION_FIELDS):
            raise ResourceLifecycleError(f"Invalid resource definition at index {index}", code="invalid_package_schema")
        definition = deepcopy(definition)
        definition["tenant_id"] = safe_tenant
        if str(definition.get("kind") or "") == "secret":
            raise ResourceLifecycleError("Secret resources cannot be imported", code="secret_resource_forbidden")
        validation = _catalog().validate_resource_payload(definition)
        if not validation["valid"]:
            raise ResourceLifecycleError(
                f"Invalid resource at index {index}: {'; '.join(validation['errors'])}",
                code="resource_validation_failed",
            )
        _definition(definition)
        definitions.append((source_id, definition))
    package_hash = hashlib.sha256(raw).hexdigest()
    mutation = {
        "package_hash": package_hash,
        "tenant_id": safe_tenant,
        "source_tenant": source_tenant,
        "resource_count": len(definitions),
    }

    def operation() -> dict[str, Any]:
        imported: list[dict[str, Any]] = []
        catalog = _catalog()
        with catalog.RESOURCE_MUTATION_LOCK:
            for source_id, definition in definitions:
                resource_id = _unique_resource_id(
                    str(definition.get("kind") or "resource"),
                    str(definition.get("name") or "Imported resource"),
                    preferred=source_id,
                )
                created = catalog.save_resource({"id": resource_id, **definition}, actor=actor)
                imported.append(
                    {
                        "source_id": source_id,
                        "resource_id": str(created["id"]),
                        "version": int(created["version"]),
                        "revision": int(created.get("revision") or created["version"]),
                        "status": "draft",
                    }
                )
        append_audit_event(
            actor=actor,
            action="resource.package_imported",
            object_type="platform_resource_package",
            object_id=package_hash,
            summary=f"Imported {len(imported)} Sentinel resources as managed drafts",
            details={
                "tenant_id": safe_tenant,
                "source_tenant": source_tenant,
                "resource_ids": [item["resource_id"] for item in imported],
            },
        )
        return {
            "status": "imported",
            "package_id": package_hash,
            "tenant_id": safe_tenant,
            "items": imported,
            "total": len(imported),
        }

    return _idempotent_mutation(key=idempotency_key, action="import_package", payload=mutation, operation=operation)
