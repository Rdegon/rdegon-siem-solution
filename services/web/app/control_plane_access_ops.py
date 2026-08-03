from __future__ import annotations

import base64
import binascii
from datetime import datetime, timedelta, timezone
import hashlib
import os
import secrets as pysecrets
from typing import Any


class AccessMutationConflict(RuntimeError):
    """A local access mutation would remove the safe break-glass path."""


def _core():
    try:
        from . import enterprise_control_plane as module
    except ImportError:  # pragma: no cover - local test fallback
        import enterprise_control_plane as module  # type: ignore[no-redef]
    return module


def _control_plane_schema_version() -> str:
    return str(_core().CONTROL_PLANE_SCHEMA_VERSION)


def _collection(name: str, default_factory):
    return _core()._collection(name, default_factory)


def _find_by_id(rows, item_id: str):
    return _core()._find_by_id(rows, item_id)


def _json_clone(value):
    return _core()._json_clone(value)


def _new_id(prefix: str) -> str:
    return str(_core()._new_id(prefix))


def _now():
    return _core()._now()


def _now_iso() -> str:
    return str(_core()._now_iso())


def _parse_ts(value: str):
    return _core()._parse_ts(value)


def _safe_slug(value: str, *, default: str = "") -> str:
    return str(_core()._safe_slug(value, default=default))


def _save_collection(name: str, rows) -> None:
    _core()._save_collection(name, rows)


def append_audit_event(*args, **kwargs) -> None:
    _core().append_audit_event(*args, **kwargs)


def _default_service_accounts():
    return _core()._default_service_accounts()


def _default_service_account_tokens():
    return _core()._default_service_account_tokens()
PASSWORD_HASH_SCHEME = "pbkdf2_sha256"
PASSWORD_HASH_ITERATIONS = 390_000
_FALLBACK_ROLE_PERMISSIONS: dict[str, set[str]] = {
    "viewer": {
        "dashboard:view",
        "events:view",
        "events:query",
        "alerts:view",
        "alerts:history:view",
        "assets:view",
        "resources:view",
        "connectors:view",
        "cases:view",
        "entities:view",
        "response:view",
        "health:view",
        "ingest:view",
        "content:view",
    },
    "analyst": {
        "dashboard:view",
        "events:view",
        "events:query",
        "alerts:view",
        "alerts:history:view",
        "incidents:update",
        "assets:view",
        "rules:test",
        "resources:view",
        "connectors:view",
        "connectors:run",
        "cases:view",
        "cases:write",
        "entities:view",
        "entities:write",
        "response:view",
        "response:run",
        "health:view",
        "ingest:view",
        "ingest:replay",
        "vuln:operate",
        "sources:discover",
        "content:view",
    },
    "admin": {
        "dashboard:view",
        "dashboards:write",
        "events:view",
        "events:query",
        "alerts:view",
        "alerts:history:view",
        "incidents:update",
        "assets:view",
        "rules:test",
        "rules:write",
        "normalizers:write",
        "active_lists:write",
        "cmdb:write",
        "threat_intel:write",
        "resources:view",
        "resources:write",
        "docs:write",
        "storage:archive",
        "connectors:view",
        "connectors:write",
        "connectors:run",
        "cases:view",
        "cases:write",
        "entities:view",
        "entities:write",
        "response:view",
        "response:run",
        "health:view",
        "ingest:view",
        "ingest:replay",
        "vuln:operate",
        "sources:discover",
        "content:view",
        "search:write",
        "audit:view",
        "auth:view",
        "auth:write",
    },
    "service": set(),
}


def _security_module():
    try:
        from . import security as security_module
    except ImportError:  # pragma: no cover - local test fallback
        try:
            import security as security_module  # type: ignore[no-redef]
        except Exception:  # noqa: BLE001
            return None

    return security_module


def _default_local_users() -> list[dict[str, Any]]:
    module = _core()
    if hasattr(module, "_default_local_users"):
        return module._default_local_users()
    return []


def _default_break_glass_sessions() -> list[dict[str, Any]]:
    return []


def _default_service_account_rotations() -> list[dict[str, Any]]:
    return []


SIEM_SECTION_CATALOG: list[dict[str, Any]] = [
    {"id": "overview", "title": "Overview"},
    {"id": "events", "title": "Events"},
    {"id": "incidents", "title": "Incidents"},
    {"id": "assets", "title": "Assets"},
    {"id": "entities", "title": "Entities"},
    {"id": "threat-intel", "title": "Threat Intel"},
    {"id": "sources", "title": "Sources"},
    {"id": "collectors", "title": "Collectors"},
    {"id": "builders", "title": "Builders"},
    {"id": "vuln", "title": "Vulnerability"},
    {"id": "connectors", "title": "Connectors"},
    {"id": "ingest", "title": "Ingest"},
    {"id": "cases", "title": "Cases"},
    {"id": "response", "title": "SOAR"},
    {"id": "host-runtime", "title": "Host Runtime"},
    {"id": "access", "title": "Access"},
    {"id": "docs", "title": "Documentation"},
    {"id": "control", "title": "Control"},
]

NEXTCLOUD_SECTION_CATALOG: list[dict[str, Any]] = [
    {"id": "files", "title": "Files"},
    {"id": "shares", "title": "Shares"},
    {"id": "groupware", "title": "Groupware"},
    {"id": "apps", "title": "Apps"},
    {"id": "admin", "title": "Admin"},
]

GREENBONE_SECTION_CATALOG: list[dict[str, Any]] = [
    {"id": "dashboard", "title": "Dashboard"},
    {"id": "reports", "title": "Reports"},
    {"id": "scans", "title": "Scans"},
    {"id": "assets", "title": "Assets"},
    {"id": "config", "title": "Config"},
]

GITEA_SECTION_CATALOG: list[dict[str, Any]] = [
    {"id": "repos", "title": "Repositories"},
    {"id": "issues", "title": "Issues"},
    {"id": "wiki", "title": "Wiki"},
    {"id": "packages", "title": "Packages"},
    {"id": "admin", "title": "Admin"},
]

NAVIDROME_SECTION_CATALOG: list[dict[str, Any]] = [
    {"id": "library", "title": "Library"},
    {"id": "playlists", "title": "Playlists"},
    {"id": "sharing", "title": "Sharing"},
    {"id": "admin", "title": "Admin"},
]

SIEM_SECTION_PERMISSIONS: dict[str, set[str]] = {
    "overview": {"dashboard:view"},
    "events": {"events:view", "events:query"},
    "incidents": {"alerts:view", "alerts:history:view", "incidents:update", "cases:view", "cases:write"},
    "assets": {"assets:view"},
    "entities": {"entities:view", "entities:write"},
    "threat-intel": {"content:view", "entities:view"},
    "sources": {"sources:discover", "health:view", "content:view", "resources:write"},
    "collectors": {"health:view", "ingest:view"},
    "builders": {"content:view", "rules:test", "rules:write", "normalizers:write", "active_lists:write", "search:write"},
    "vuln": {"assets:view", "content:view", "health:view", "response:view", "resources:view", "vuln:operate"},
    "connectors": {"connectors:view", "connectors:write", "connectors:run"},
    "ingest": {"ingest:view", "ingest:replay", "health:view"},
    "cases": {"cases:view", "cases:write"},
    "response": {"response:view", "response:run"},
    "host-runtime": {"health:view"},
    "access": {"auth:view", "auth:write"},
    "docs": {"content:view", "docs:write", "resources:view", "resources:write"},
    "control": {"health:view", "audit:view"},
}


def _greenbone_sso_supported() -> bool:
    return str(os.getenv("SIEM_GREENBONE_SSO_SUPPORTED", "0") or "0").strip().lower() in {"1", "true", "yes", "on"}


def _access_system_catalog() -> list[dict[str, Any]]:
    greenbone_supported = _greenbone_sso_supported()
    return [
        {
            "id": "siem",
            "title": "SIEM",
            "kind": "internal_app",
            "grantable": True,
            "mode": "grantable",
            "sso_supported": True,
            "roles": [
                {"id": "viewer", "title": "Viewer"},
                {"id": "analyst", "title": "Analyst"},
                {"id": "admin", "title": "Admin"},
            ],
            "sections": list(SIEM_SECTION_CATALOG),
        },
        {
            "id": "nextcloud",
            "title": "Nextcloud",
            "kind": "external_app",
            "grantable": True,
            "mode": "grantable",
            "sso_supported": True,
            "enforcement_mode": "native_oidc",
            "client_id": "nextcloud",
            "internal_url": "https://nextcloud-siem.lab.home.arpa",
            "roles": [
                {"id": "user", "title": "User"},
                {"id": "admin", "title": "Admin"},
            ],
            "sections": list(NEXTCLOUD_SECTION_CATALOG),
        },
        {
            "id": "gitea",
            "title": "Gitea",
            "kind": "external_app",
            "grantable": True,
            "mode": "grantable",
            "sso_supported": True,
            "enforcement_mode": "native_oidc",
            "client_id": "pilot-gitea",
            "internal_url": "http://pilot-web-01.lab.home.arpa:3000",
            "roles": [
                {"id": "user", "title": "User"},
                {"id": "admin", "title": "Admin"},
            ],
            "sections": list(GITEA_SECTION_CATALOG),
        },
        {
            "id": "navidrome",
            "title": "Navidrome",
            "kind": "external_app",
            "grantable": True,
            "mode": "grantable",
            "sso_supported": True,
            "enforcement_mode": "proxy_extauth",
            "client_id": "navidrome-proxy",
            "internal_url": "http://navidrome-01.lab.home.arpa",
            "roles": [
                {"id": "user", "title": "User"},
                {"id": "admin", "title": "Admin"},
            ],
            "sections": list(NAVIDROME_SECTION_CATALOG),
        },
        {
            "id": "greenbone",
            "title": "Greenbone / OpenVAS",
            "kind": "external_app",
            "grantable": bool(greenbone_supported),
            "mode": "grantable" if greenbone_supported else "unsupported",
            "sso_supported": bool(greenbone_supported),
            "enforcement_mode": "native_oidc" if greenbone_supported else "unsupported",
            "roles": [
                {"id": "user", "title": "User"},
                {"id": "admin", "title": "Admin"},
            ],
            "sections": list(GREENBONE_SECTION_CATALOG),
        },
        {"id": "proxmox", "title": "Proxmox", "kind": "platform", "grantable": False, "mode": "monitored_only", "sso_supported": False, "roles": [], "sections": []},
        {"id": "vm1", "title": "VM1 ingest", "kind": "platform", "grantable": False, "mode": "monitored_only", "sso_supported": False, "roles": [], "sections": []},
        {"id": "vm2", "title": "VM2 processing", "kind": "platform", "grantable": False, "mode": "monitored_only", "sso_supported": False, "roles": [], "sections": []},
        {"id": "vm3", "title": "VM3 storage", "kind": "platform", "grantable": False, "mode": "monitored_only", "sso_supported": False, "roles": [], "sections": []},
        {"id": "vm4", "title": "VM4 control-plane", "kind": "platform", "grantable": False, "mode": "monitored_only", "sso_supported": False, "roles": [], "sections": []},
        {"id": "vm5", "title": "VM5 transport", "kind": "platform", "grantable": False, "mode": "monitored_only", "sso_supported": False, "roles": [], "sections": []},
    ]


def _system_definition(system_id: str) -> dict[str, Any] | None:
    safe_system_id = str(system_id or "").strip()
    return next((item for item in _access_system_catalog() if str(item.get("id") or "") == safe_system_id), None)


def _system_role_ids(system_id: str) -> list[str]:
    system = _system_definition(system_id) or {}
    return [str(item.get("id") or "").strip() for item in list(system.get("roles") or []) if str(item.get("id") or "").strip()]


def _system_section_ids(system_id: str) -> list[str]:
    system = _system_definition(system_id) or {}
    return [str(item.get("id") or "").strip() for item in list(system.get("sections") or []) if str(item.get("id") or "").strip()]


def _default_access_grants() -> list[dict[str, Any]]:
    return []


def _normalize_sections(system_id: str, items: list[Any] | None) -> list[str]:
    allowed = set(_system_section_ids(system_id))
    normalized = sorted({str(item).strip() for item in (items or []) if str(item).strip()})
    if not normalized:
        return sorted(allowed)
    invalid = [item for item in normalized if item not in allowed]
    if invalid:
        raise ValueError(f"Unsupported sections for {system_id}: {', '.join(invalid)}")
    return normalized


def _role_permissions(role: str) -> set[str]:
    security_module = _security_module()
    if security_module is None:
        source = _FALLBACK_ROLE_PERMISSIONS
    else:
        source = dict(getattr(security_module, "ROLE_PERMISSIONS", _FALLBACK_ROLE_PERMISSIONS))
    return {str(item).strip() for item in source.get(str(role or "").strip().lower(), set()) if str(item).strip()}


def _siem_permissions_for_sections(role: str, sections: list[str]) -> list[str]:
    allowed_permissions: set[str] = set()
    for section in sections:
        allowed_permissions.update(SIEM_SECTION_PERMISSIONS.get(str(section), set()))
    if not allowed_permissions:
        return []
    return sorted(_role_permissions(role) & allowed_permissions)


def _keycloak_runtime():
    try:
        from . import keycloak_admin_runtime as runtime
    except ImportError:  # pragma: no cover - local test fallback
        import keycloak_admin_runtime as runtime  # type: ignore[no-redef]
    return runtime


def list_access_systems(*, grantable_only: bool = False) -> list[dict[str, Any]]:
    items = [_json_clone(item) for item in _access_system_catalog()]
    if grantable_only:
        items = [item for item in items if bool(item.get("grantable"))]
    return items


def _grant_public_view(item: dict[str, Any]) -> dict[str, Any]:
    system = _system_definition(str(item.get("system_id") or "")) or {}
    return {
        "id": str(item.get("id") or ""),
        "principal_kind": str(item.get("principal_kind") or "keycloak_user"),
        "principal_id": str(item.get("principal_id") or ""),
        "system_id": str(item.get("system_id") or ""),
        "system_title": str(system.get("title") or item.get("system_id") or ""),
        "role": str(item.get("role") or ""),
        "sections": _normalize_sections(str(item.get("system_id") or ""), item.get("sections") or []),
        "enabled": bool(item.get("enabled", True)),
        "sync_status": str(item.get("sync_status") or ""),
        "last_synced_ts": str(item.get("last_synced_ts") or ""),
        "created_ts": str(item.get("created_ts") or ""),
        "updated_ts": str(item.get("updated_ts") or ""),
    }


def list_access_grants(
    *,
    principal_kind: str = "",
    principal_id: str = "",
    include_disabled: bool = True,
) -> list[dict[str, Any]]:
    safe_kind = str(principal_kind or "").strip()
    safe_principal_id = str(principal_id or "").strip()
    rows = []
    for item in _collection("access_grants", _default_access_grants):
        if safe_kind and str(item.get("principal_kind") or "") != safe_kind:
            continue
        if safe_principal_id and str(item.get("principal_id") or "") != safe_principal_id:
            continue
        if not include_disabled and not bool(item.get("enabled", True)):
            continue
        rows.append(_grant_public_view(item))
    rows.sort(key=lambda item: _parse_ts(str(item.get("updated_ts") or item.get("created_ts") or "")), reverse=True)
    return _json_clone(rows)


def _managed_group_names_for_grants(items: list[dict[str, Any]]) -> list[str]:
    groups: set[str] = set()
    for item in items:
        if not bool(item.get("enabled", True)):
            continue
        system_id = str(item.get("system_id") or "").strip()
        role = str(item.get("role") or "").strip()
        if not system_id or not role:
            continue
        groups.add(f"sys:{system_id}:role:{role}")
        for section in _normalize_sections(system_id, item.get("sections") or []):
            groups.add(f"sys:{system_id}:section:{section}")
        if system_id == "nextcloud":
            groups.add("nextcloud-users")
            if role == "admin":
                groups.add("nextcloud-admins")
        if system_id == "gitea":
            groups.add("gitea-users")
            if role == "admin":
                groups.add("gitea-admins")
        if system_id == "navidrome":
            groups.add("navidrome-users")
            if role == "admin":
                groups.add("navidrome-admins")
    return sorted(groups)


def _sync_keycloak_principal_groups(principal_kind: str, principal_id: str, *, actor: str) -> dict[str, Any]:
    safe_kind = str(principal_kind or "").strip()
    safe_principal_id = str(principal_id or "").strip()
    if safe_kind != "keycloak_user" or not safe_principal_id:
        return {"status": "not_applicable", "managed_groups": []}
    runtime = _keycloak_runtime()
    users = list(runtime.list_users(search=safe_principal_id, limit=50) or [])
    user_summary = next((item for item in users if str(item.get("username") or "").strip().lower() == safe_principal_id.lower()), None)
    if user_summary is None:
        return {"status": "user_missing", "managed_groups": []}
    user_id = str(user_summary.get("id") or "").strip()
    if not user_id:
        return {"status": "user_missing", "managed_groups": []}
    grants = [
        item
        for item in _collection("access_grants", _default_access_grants)
        if str(item.get("principal_kind") or "") == safe_kind and str(item.get("principal_id") or "") == safe_principal_id
    ]
    desired_groups = _managed_group_names_for_grants(grants)
    existing_groups = {str(item.get("name") or "").strip() for item in list(runtime.list_groups() or []) if str(item.get("name") or "").strip()}
    for group_name in desired_groups:
        if group_name not in existing_groups:
            runtime.save_group({"name": group_name}, actor=actor)
            existing_groups.add(group_name)
    detail = runtime.get_user(user_id)
    current_group_names = [str(item.get("name") or "").strip() for item in list(detail.get("groups") or []) if str(item.get("name") or "").strip()]
    preserved_group_names = [item for item in current_group_names if not item.startswith("sys:")]
    runtime.set_user_groups(user_id, {"group_names": sorted({*preserved_group_names, *desired_groups})}, actor=actor)
    return {"status": "mirrored", "managed_groups": desired_groups, "user_id": user_id}


def save_access_grant(payload: dict[str, Any], *, actor: str = "system", grant_id: str = "") -> dict[str, Any]:
    safe_principal_kind = str(payload.get("principal_kind") or "keycloak_user").strip() or "keycloak_user"
    safe_principal_id = str(payload.get("principal_id") or "").strip()
    safe_system_id = str(payload.get("system_id") or "").strip()
    safe_role = str(payload.get("role") or "").strip().lower()
    if not safe_principal_id:
        raise ValueError("principal_id is required")
    system = _system_definition(safe_system_id)
    if system is None:
        raise ValueError(f"Unsupported system: {safe_system_id}")
    if not bool(system.get("grantable")):
        raise ValueError(f"System is not grantable: {safe_system_id}")
    allowed_roles = set(_system_role_ids(safe_system_id))
    if safe_role not in allowed_roles:
        raise ValueError(f"Unsupported role for {safe_system_id}: {safe_role}")
    safe_sections = _normalize_sections(safe_system_id, payload.get("sections") or [])
    rows = _collection("access_grants", _default_access_grants)
    safe_grant_id = str(grant_id or payload.get("id") or "").strip()
    existing = None
    if safe_grant_id:
        existing = _find_by_id(rows, safe_grant_id)
    if existing is None:
        existing = next(
            (
                item
                for item in rows
                if str(item.get("principal_kind") or "") == safe_principal_kind
                and str(item.get("principal_id") or "") == safe_principal_id
                and str(item.get("system_id") or "") == safe_system_id
            ),
            None,
        )
    now_iso = _now_iso()
    item = {
        "id": str((existing or {}).get("id") or _new_id("grant")),
        "type": "access_grant",
        "schema_version": _control_plane_schema_version(),
        "principal_kind": safe_principal_kind,
        "principal_id": safe_principal_id,
        "system_id": safe_system_id,
        "role": safe_role,
        "sections": safe_sections,
        "enabled": bool(payload.get("enabled", existing.get("enabled", True) if existing else True)),
        "created_ts": str((existing or {}).get("created_ts") or now_iso),
        "updated_ts": now_iso,
        "sync_status": str((existing or {}).get("sync_status") or ""),
        "last_synced_ts": str((existing or {}).get("last_synced_ts") or ""),
    }
    rows = [row for row in rows if str(row.get("id") or "") != str(item.get("id") or "")]
    rows.append(item)
    _save_collection("access_grants", rows)
    sync_result = _sync_keycloak_principal_groups(safe_principal_kind, safe_principal_id, actor=actor)
    item["sync_status"] = str(sync_result.get("status") or "")
    item["last_synced_ts"] = now_iso if item["sync_status"] not in {"", "not_applicable"} else str(item.get("last_synced_ts") or "")
    rows = [item if str(row.get("id") or "") == str(item.get("id") or "") else row for row in rows]
    _save_collection("access_grants", rows)
    append_audit_event(
        actor=actor,
        action="access_grant.saved",
        object_type="access_grant",
        object_id=str(item.get("id") or ""),
        summary=f"{safe_principal_id}:{safe_system_id}",
        details={"role": safe_role, "sections": safe_sections, "enabled": item["enabled"], "sync_status": item["sync_status"]},
    )
    return _grant_public_view(item)


def delete_access_grant(grant_id: str, *, actor: str = "system") -> dict[str, Any]:
    safe_grant_id = str(grant_id or "").strip()
    rows = _collection("access_grants", _default_access_grants)
    item = _find_by_id(rows, safe_grant_id)
    if item is None:
        raise ValueError(f"Access grant not found: {safe_grant_id}")
    rows = [row for row in rows if str(row.get("id") or "") != safe_grant_id]
    _save_collection("access_grants", rows)
    _sync_keycloak_principal_groups(str(item.get("principal_kind") or ""), str(item.get("principal_id") or ""), actor=actor)
    append_audit_event(
        actor=actor,
        action="access_grant.deleted",
        object_type="access_grant",
        object_id=safe_grant_id,
        summary=f"{item.get('principal_id')}:{item.get('system_id')}",
        details={},
    )
    return _grant_public_view(item)


def resolve_keycloak_principal_access(
    username: str,
    *,
    claimed_groups: list[str] | None = None,
    fallback_role: str = "viewer",
) -> dict[str, Any]:
    safe_username = str(username or "").strip()
    if not safe_username:
        return {"allowed": False, "reason": "missing_username"}
    enabled_grants = [
        item
        for item in _collection("access_grants", _default_access_grants)
        if str(item.get("principal_kind") or "") == "keycloak_user"
        and str(item.get("principal_id") or "") == safe_username
        and bool(item.get("enabled", True))
    ]
    siem_grant = next((item for item in enabled_grants if str(item.get("system_id") or "") == "siem"), None)
    if siem_grant is None:
        return {
            "allowed": False,
            "reason": "siem_grant_missing",
            "message": f"No explicit SIEM access grant assigned for {safe_username}",
            "system_grants": [_grant_public_view(item) for item in enabled_grants],
        }
    sections = _normalize_sections("siem", siem_grant.get("sections") or [])
    role = str(siem_grant.get("role") or fallback_role or "viewer").strip().lower() or "viewer"
    permissions = _siem_permissions_for_sections(role, sections)
    return {
        "allowed": True,
        "role": role,
        "permissions": permissions,
        "section_access": sections,
        "groups": [str(item).strip() for item in (claimed_groups or []) if str(item).strip()],
        "system_grants": [_grant_public_view(item) for item in enabled_grants],
    }


def _normalize_permissions(items: list[Any] | None) -> list[str]:
    values = {str(item).strip() for item in (items or []) if str(item).strip()}
    return sorted(values)


def _permission_catalog() -> list[str]:
    security_module = _security_module()
    if security_module is None:
        values = [permission for permissions in _FALLBACK_ROLE_PERMISSIONS.values() for permission in permissions]
    else:
        values = [str(item).strip() for item in getattr(security_module, "ALL_PERMISSIONS", ()) if str(item).strip()]
    return sorted(set(values))


def _permission_bundles() -> list[dict[str, Any]]:
    security_module = _security_module()
    role_permissions_source = _FALLBACK_ROLE_PERMISSIONS if security_module is None else dict(getattr(security_module, "ROLE_PERMISSIONS", {}))
    role_permissions = {
        str(name): sorted({str(item).strip() for item in permissions if str(item).strip()})
        for name, permissions in role_permissions_source.items()
    }
    return [
        {"id": "viewer", "title": "Viewer baseline", "permissions": role_permissions.get("viewer", [])},
        {"id": "analyst", "title": "Analyst baseline", "permissions": role_permissions.get("analyst", [])},
        {"id": "admin", "title": "Admin baseline", "permissions": role_permissions.get("admin", [])},
        {"id": "dashboard-editor", "title": "Dashboard editor", "permissions": sorted({"dashboard:view", "dashboards:write"})},
        {"id": "rule-editor", "title": "Rule editor", "permissions": sorted({"assets:view", "rules:test", "rules:write"})},
        {"id": "normalizer-editor", "title": "Normalizer editor", "permissions": sorted({"assets:view", "normalizers:write"})},
        {"id": "content-maintainer", "title": "Content and docs maintainer", "permissions": sorted({"content:view", "docs:write", "search:write"})},
    ]


def _permission_categories() -> list[dict[str, Any]]:
    grouped: dict[str, list[str]] = {}
    for permission in _permission_catalog():
        namespace = permission.split(":", 1)[0]
        grouped.setdefault(namespace, []).append(permission)
    return [
        {
            "id": key,
            "title": key.replace("_", " ").replace("-", " ").title(),
            "permissions": sorted(values),
        }
        for key, values in sorted(grouped.items())
    ]


def _validate_permissions(items: list[Any] | None) -> list[str]:
    normalized = _normalize_permissions(items)
    allowed = set(_permission_catalog())
    invalid = [item for item in normalized if item not in allowed]
    if invalid:
        raise ValueError(f"Unsupported permissions: {', '.join(invalid)}")
    return normalized


def _permission_bundle_map() -> dict[str, list[str]]:
    return {
        str(item.get("id") or ""): _normalize_permissions(item.get("permissions") or [])
        for item in _permission_bundles()
        if str(item.get("id") or "").strip()
    }


def _normalize_permission_bundles(items: list[Any] | None) -> list[str]:
    return sorted({str(item).strip() for item in (items or []) if str(item).strip()})


def _validate_permission_bundles(items: list[Any] | None) -> list[str]:
    normalized = _normalize_permission_bundles(items)
    bundle_map = _permission_bundle_map()
    invalid = [item for item in normalized if item not in bundle_map]
    if invalid:
        raise ValueError(f"Unsupported permission bundles: {', '.join(invalid)}")
    return normalized


def _expand_permission_bundles(items: list[Any] | None) -> list[str]:
    bundle_map = _permission_bundle_map()
    permissions: list[str] = []
    for bundle_id in _validate_permission_bundles(items):
        permissions.extend(bundle_map.get(bundle_id, []))
    return _normalize_permissions(permissions)


def _compose_permissions(
    *,
    requested_permissions: list[Any] | None,
    requested_bundles: list[Any] | None,
    existing_permissions: list[Any] | None,
    existing_bundles: list[Any] | None,
) -> tuple[list[str], list[str]]:
    effective_bundles = _validate_permission_bundles(requested_bundles if requested_bundles is not None else existing_bundles)
    base_permissions = list(requested_permissions if requested_permissions is not None else (existing_permissions or []))
    expanded_permissions = _expand_permission_bundles(effective_bundles)
    effective_permissions = _validate_permissions([*base_permissions, *expanded_permissions])
    return effective_permissions, effective_bundles


def get_permission_inventory() -> dict[str, Any]:
    return {
        "available_permissions": _permission_catalog(),
        "available_roles": ["admin", "analyst", "viewer"],
        "permission_categories": _permission_categories(),
        "permission_bundles": _permission_bundles(),
    }


def _encode_hash_component(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _decode_hash_component(value: str) -> bytes:
    safe_value = str(value or "").strip()
    padding = "=" * (-len(safe_value) % 4)
    return base64.urlsafe_b64decode(f"{safe_value}{padding}".encode("ascii"))


def _hash_password(password: str) -> str:
    safe_password = str(password or "")
    if not safe_password:
        raise ValueError("password must not be empty")
    salt = pysecrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", safe_password.encode("utf-8"), salt, PASSWORD_HASH_ITERATIONS)
    return f"{PASSWORD_HASH_SCHEME}${PASSWORD_HASH_ITERATIONS}${_encode_hash_component(salt)}${_encode_hash_component(digest)}"


def _verify_pbkdf2_password(password: str, password_hash: str) -> bool:
    try:
        scheme, iterations_raw, salt_b64, digest_b64 = str(password_hash or "").split("$", 3)
        if scheme != PASSWORD_HASH_SCHEME:
            return False
        iterations = int(iterations_raw)
        salt = _decode_hash_component(salt_b64)
        expected_digest = _decode_hash_component(digest_b64)
    except (TypeError, ValueError, binascii.Error):
        return False
    actual_digest = hashlib.pbkdf2_hmac("sha256", str(password or "").encode("utf-8"), salt, iterations)
    return pysecrets.compare_digest(actual_digest, expected_digest)


def _token_status(item: dict[str, Any]) -> str:
    if bool(item.get("revoked")):
        return "revoked"
    expires_ts = str(item.get("expires_ts") or "").strip()
    if expires_ts and _parse_ts(expires_ts) < _now():
        return "expired"
    return "active"


def _service_token_public_view(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": str(item.get("id") or ""),
        "type": "api_token",
        "schema_version": str(item.get("schema_version") or _control_plane_schema_version()),
        "service_account_id": str(item.get("service_account_id") or ""),
        "title": str(item.get("title") or item.get("id") or ""),
        "prefix": str(item.get("prefix") or ""),
        "created_ts": str(item.get("created_ts") or ""),
        "created_by": str(item.get("created_by") or ""),
        "expires_ts": str(item.get("expires_ts") or ""),
        "last_used_ts": str(item.get("last_used_ts") or ""),
        "uses_total": int(item.get("uses_total") or 0),
        "status": _token_status(item),
        "revoked": bool(item.get("revoked", False)),
        "revoked_ts": str(item.get("revoked_ts") or ""),
        "revoked_by": str(item.get("revoked_by") or ""),
    }


def _service_account_public_view(item: dict[str, Any], tokens: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    account_tokens = [
        token
        for token in (tokens or _collection("service_account_tokens", _default_service_account_tokens))
        if str(token.get("service_account_id") or "") == str(item.get("id") or "")
    ]
    active_tokens = [token for token in account_tokens if _token_status(token) == "active"]
    next_expiry = min(
        (_parse_ts(str(token.get("expires_ts") or "")) for token in active_tokens if str(token.get("expires_ts") or "").strip()),
        default=datetime.max.replace(tzinfo=timezone.utc),
    )
    return {
        "id": str(item.get("id") or ""),
        "type": "service_account",
        "schema_version": str(item.get("schema_version") or _control_plane_schema_version()),
        "name": str(item.get("name") or item.get("id") or ""),
        "description": str(item.get("description") or ""),
        "enabled": bool(item.get("enabled", True)),
        "permissions": _normalize_permissions(item.get("permissions") or []),
        "permission_bundles": _normalize_permission_bundles(item.get("permission_bundles") or []),
        "tags": [str(token).strip() for token in (item.get("tags") or []) if str(token).strip()],
        "created_ts": str(item.get("created_ts") or ""),
        "updated_ts": str(item.get("updated_ts") or ""),
        "last_used_ts": str(item.get("last_used_ts") or ""),
        "last_rotation_ts": str(item.get("last_rotation_ts") or ""),
        "token_count": len(account_tokens),
        "active_tokens": len(active_tokens),
        "next_token_expiry_ts": "" if next_expiry == datetime.max.replace(tzinfo=timezone.utc) else next_expiry.isoformat().replace("+00:00", "Z"),
    }


def list_service_accounts() -> list[dict[str, Any]]:
    rows = _collection("service_accounts", _default_service_accounts)
    tokens = _collection("service_account_tokens", _default_service_account_tokens)
    items = [_service_account_public_view(item, tokens) for item in rows]
    items.sort(key=lambda item: str(item.get("name") or item.get("id") or ""))
    return _json_clone(items)


def get_service_account(service_account_id: str) -> dict[str, Any] | None:
    rows = _collection("service_accounts", _default_service_accounts)
    item = _find_by_id(rows, service_account_id)
    if item is None:
        return None
    tokens = _collection("service_account_tokens", _default_service_account_tokens)
    return _service_account_public_view(item, tokens)


def save_service_account(payload: dict[str, Any], *, actor: str = "system") -> dict[str, Any]:
    rows = _collection("service_accounts", _default_service_accounts)
    service_account_id = _safe_slug(str(payload.get("id") or payload.get("name") or ""), default=_new_id("svc"))
    existing = _find_by_id(rows, service_account_id)
    now = _now_iso()
    permissions, permission_bundles = _compose_permissions(
        requested_permissions=payload.get("permissions") if "permissions" in payload else None,
        requested_bundles=payload.get("permission_bundles") if "permission_bundles" in payload else None,
        existing_permissions=existing.get("permissions") if existing else [],
        existing_bundles=existing.get("permission_bundles") if existing else [],
    )
    item = {
        "id": service_account_id,
        "type": "service_account",
        "schema_version": _control_plane_schema_version(),
        "name": str(payload.get("name") or (existing.get("name") if existing else service_account_id) or service_account_id),
        "description": str(payload.get("description") or (existing.get("description") if existing else "") or ""),
        "enabled": bool(payload.get("enabled", existing.get("enabled", True) if existing else True)),
        "permissions": permissions,
        "permission_bundles": permission_bundles,
        "tags": [str(item).strip() for item in (payload.get("tags") or (existing.get("tags") if existing else [])) if str(item).strip()],
        "created_ts": str(existing.get("created_ts") if existing else now),
        "updated_ts": now,
        "last_used_ts": str(existing.get("last_used_ts") if existing else ""),
    }
    rows = [row for row in rows if str(row.get("id") or "") != service_account_id]
    rows.append(item)
    _save_collection("service_accounts", rows)
    append_audit_event(
        actor=actor,
        action="service_account.saved",
        object_type="service_account",
        object_id=item["id"],
        summary=item["name"],
        details={"enabled": item["enabled"], "permissions": item["permissions"], "permission_bundles": item["permission_bundles"]},
    )
    return get_service_account(item["id"]) or _service_account_public_view(item)


def delete_service_account(service_account_id: str, *, actor: str = "system") -> dict[str, Any]:
    safe_id = str(service_account_id or "").strip()
    rows = _collection("service_accounts", _default_service_accounts)
    item = _find_by_id(rows, safe_id)
    if item is None:
        raise ValueError(f"Service account not found: {safe_id}")
    tokens = _collection("service_account_tokens", _default_service_account_tokens)
    deleted_tokens = [token for token in tokens if str(token.get("service_account_id") or "") == safe_id]
    _save_collection("service_accounts", [row for row in rows if str(row.get("id") or "") != safe_id])
    _save_collection("service_account_tokens", [token for token in tokens if str(token.get("service_account_id") or "") != safe_id])
    append_audit_event(
        actor=actor,
        action="service_account.deleted",
        object_type="service_account",
        object_id=safe_id,
        summary=str(item.get("name") or safe_id),
        details={"deleted_tokens": len(deleted_tokens)},
    )
    payload = _service_account_public_view(item, [])
    payload["deleted_tokens"] = len(deleted_tokens)
    return payload


def list_service_account_tokens(*, service_account_id: str = "", include_revoked: bool = False) -> list[dict[str, Any]]:
    rows = _collection("service_account_tokens", _default_service_account_tokens)
    safe_id = str(service_account_id or "").strip()
    filtered = rows
    if safe_id:
        filtered = [item for item in filtered if str(item.get("service_account_id") or "") == safe_id]
    items = [_service_token_public_view(item) for item in filtered]
    if not include_revoked:
        items = [item for item in items if str(item.get("status") or "") != "revoked"]
    items.sort(key=lambda item: _parse_ts(str(item.get("created_ts") or "")), reverse=True)
    return _json_clone(items)


def issue_service_account_token(
    service_account_id: str,
    *,
    title: str = "",
    actor: str = "system",
    expires_days: int = 90,
) -> dict[str, Any]:
    accounts = _collection("service_accounts", _default_service_accounts)
    account = _find_by_id(accounts, service_account_id)
    if account is None:
        raise ValueError(f"Service account not found: {service_account_id}")
    safe_days = max(1, min(3650, int(expires_days or 90)))
    token_id = _new_id("token")
    secret = pysecrets.token_urlsafe(32)
    token_value = f"rsiem_{token_id}_{secret}"
    now = _now()
    token = {
        "id": token_id,
        "type": "api_token",
        "schema_version": _control_plane_schema_version(),
        "service_account_id": service_account_id,
        "title": str(title or f"{account.get('name') or service_account_id} token").strip(),
        "prefix": token_value[:24],
        "token_hash": hashlib.sha256(token_value.encode("utf-8")).hexdigest(),
        "created_ts": now.replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "created_by": actor,
        "expires_ts": (now + timedelta(days=safe_days)).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "last_used_ts": "",
        "uses_total": 0,
        "revoked": False,
        "revoked_ts": "",
        "revoked_by": "",
    }
    tokens = _collection("service_account_tokens", _default_service_account_tokens)
    tokens.append(token)
    tokens = sorted(tokens, key=lambda item: _parse_ts(str(item.get("created_ts") or "")), reverse=True)[:2000]
    _save_collection("service_account_tokens", tokens)
    append_audit_event(
        actor=actor,
        action="service_account.token_issued",
        object_type="api_token",
        object_id=token_id,
        summary=token["title"],
        details={"service_account_id": service_account_id, "expires_ts": token["expires_ts"]},
    )
    return {
        "service_account": get_service_account(service_account_id) or _service_account_public_view(account, tokens),
        "token": {
            **_service_token_public_view(token),
            "token": token_value,
        },
    }


def revoke_service_account_token(service_account_id: str, token_id: str, *, actor: str = "system") -> dict[str, Any]:
    rows = _collection("service_account_tokens", _default_service_account_tokens)
    token = next(
        (
            item
            for item in rows
            if str(item.get("id") or "") == str(token_id or "").strip()
            and str(item.get("service_account_id") or "") == str(service_account_id or "").strip()
        ),
        None,
    )
    if token is None:
        raise ValueError(f"Token not found: {token_id}")
    token["revoked"] = True
    token["revoked_ts"] = _now_iso()
    token["revoked_by"] = actor
    _save_collection(
        "service_account_tokens",
        [token if str(item.get("id") or "") == str(token_id or "").strip() else item for item in rows],
    )
    append_audit_event(
        actor=actor,
        action="service_account.token_revoked",
        object_type="api_token",
        object_id=str(token.get("id") or ""),
        summary=str(token.get("title") or token.get("id") or ""),
        details={"service_account_id": service_account_id},
    )
    return _service_token_public_view(token)


def rotate_service_account_token(
    service_account_id: str,
    *,
    title: str = "",
    actor: str = "system",
    expires_days: int = 90,
    revoke_predecessors: bool = False,
    overlap_minutes: int = 60,
) -> dict[str, Any]:
    safe_account_id = str(service_account_id or "").strip()
    if not safe_account_id:
        raise ValueError("service_account_id is required")
    active_before = list_service_account_tokens(service_account_id=safe_account_id, include_revoked=False)
    issued = issue_service_account_token(
        safe_account_id,
        title=title or f"{safe_account_id} rotation",
        actor=actor,
        expires_days=expires_days,
    )
    new_token = dict(issued.get("token") or {})
    predecessor_ids = [str(item.get("id") or "") for item in active_before if str(item.get("id") or "") != str(new_token.get("id") or "")]
    revoked: list[dict[str, Any]] = []
    if revoke_predecessors:
        for token_id in predecessor_ids:
            revoked.append(revoke_service_account_token(safe_account_id, token_id, actor=actor))
    account_rows = _collection("service_accounts", _default_service_accounts)
    account = _find_by_id(account_rows, safe_account_id)
    if account is not None:
        account["last_rotation_ts"] = _now_iso()
        account["updated_ts"] = account["last_rotation_ts"]
        _save_collection("service_accounts", account_rows)
    rotation = {
        "id": _new_id("rot"),
        "type": "service_account_rotation",
        "schema_version": _control_plane_schema_version(),
        "service_account_id": safe_account_id,
        "created_ts": _now_iso(),
        "created_by": actor,
        "new_token_id": str(new_token.get("id") or ""),
        "predecessor_token_ids": predecessor_ids,
        "revoke_predecessors": bool(revoke_predecessors),
        "revoked_token_ids": [str(item.get("id") or "") for item in revoked],
        "overlap_until_ts": (_now() + timedelta(minutes=max(1, min(1440, int(overlap_minutes or 60))))).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    }
    rotations = _collection("service_account_rotations", _default_service_account_rotations)
    rotations.append(rotation)
    rotations = sorted(rotations, key=lambda item: _parse_ts(str(item.get("created_ts") or "")), reverse=True)[:1000]
    _save_collection("service_account_rotations", rotations)
    append_audit_event(
        actor=actor,
        action="service_account.token_rotated",
        object_type="service_account_rotation",
        object_id=str(rotation.get("id") or ""),
        summary=safe_account_id,
        details={
            "service_account_id": safe_account_id,
            "new_token_id": str(new_token.get("id") or ""),
            "predecessor_token_ids": predecessor_ids,
            "revoked_token_ids": [str(item.get("id") or "") for item in revoked],
        },
    )
    return {
        "service_account": get_service_account(safe_account_id),
        "rotation": rotation,
        "token": new_token,
        "predecessors": active_before,
        "revoked": revoked,
    }


def authenticate_service_account_token(token_value: str) -> dict[str, Any] | None:
    safe_token = str(token_value or "").strip()
    if not safe_token:
        return None
    token_hash = hashlib.sha256(safe_token.encode("utf-8")).hexdigest()
    token_rows = _collection("service_account_tokens", _default_service_account_tokens)
    token = next(
        (
            item
            for item in token_rows
            if not bool(item.get("revoked"))
            and str(item.get("token_hash") or "") == token_hash
            and _token_status(item) == "active"
        ),
        None,
    )
    if token is None:
        return None
    account_rows = _collection("service_accounts", _default_service_accounts)
    account = _find_by_id(account_rows, str(token.get("service_account_id") or ""))
    if account is None or not bool(account.get("enabled", True)):
        return None
    now = _now_iso()
    token["last_used_ts"] = now
    token["uses_total"] = int(token.get("uses_total") or 0) + 1
    account["last_used_ts"] = now
    account["updated_ts"] = now
    _save_collection(
        "service_account_tokens",
        [token if str(item.get("id") or "") == str(token.get("id") or "") else item for item in token_rows],
    )
    _save_collection(
        "service_accounts",
        [account if str(item.get("id") or "") == str(account.get("id") or "") else item for item in account_rows],
    )
    return {
        "service_account": _service_account_public_view(account, token_rows),
        "token": _service_token_public_view(token),
    }


def _break_glass_public_view(item: dict[str, Any]) -> dict[str, Any]:
    expires_ts = str(item.get("expires_ts") or "")
    state = str(item.get("status") or "active")
    if state == "active" and expires_ts and _parse_ts(expires_ts) < _now():
        state = "expired"
    return {
        "id": str(item.get("id") or ""),
        "username": str(item.get("username") or ""),
        "role": str(item.get("role") or "viewer"),
        "reason": str(item.get("reason") or ""),
        "client_ip": str(item.get("client_ip") or ""),
        "created_ts": str(item.get("created_ts") or ""),
        "expires_ts": expires_ts,
        "status": state,
        "created_by": str(item.get("created_by") or ""),
        "closed_ts": str(item.get("closed_ts") or ""),
        "closed_by": str(item.get("closed_by") or ""),
        "close_reason": str(item.get("close_reason") or ""),
    }


def list_break_glass_sessions(*, active_only: bool = False, limit: int = 100) -> list[dict[str, Any]]:
    rows = [_break_glass_public_view(item) for item in _collection("break_glass_sessions", _default_break_glass_sessions)]
    if active_only:
        rows = [item for item in rows if str(item.get("status") or "") == "active"]
    rows.sort(key=lambda item: _parse_ts(str(item.get("created_ts") or "")), reverse=True)
    return _json_clone(rows[: max(1, min(500, int(limit or 100)))])


def record_break_glass_session(
    username: str,
    *,
    role: str,
    reason: str,
    actor: str = "self",
    client_ip: str = "",
    expires_minutes: int = 60,
) -> dict[str, Any]:
    safe_username = str(username or "").strip()
    safe_reason = str(reason or "").strip()
    if not safe_username:
        raise ValueError("username is required")
    if not safe_reason:
        raise ValueError("reason is required")
    now = _now()
    item = {
        "id": _new_id("bgs"),
        "type": "break_glass_session",
        "schema_version": _control_plane_schema_version(),
        "username": safe_username,
        "role": str(role or "viewer").strip().lower() or "viewer",
        "reason": safe_reason,
        "created_by": str(actor or "self"),
        "client_ip": str(client_ip or "").strip(),
        "created_ts": now.replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "expires_ts": (now + timedelta(minutes=max(5, min(240, int(expires_minutes or 60))))).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "status": "active",
        "closed_ts": "",
        "closed_by": "",
        "close_reason": "",
    }
    rows = _collection("break_glass_sessions", _default_break_glass_sessions)
    rows.append(item)
    rows = sorted(rows, key=lambda row: _parse_ts(str(row.get("created_ts") or "")), reverse=True)[:500]
    _save_collection("break_glass_sessions", rows)
    append_audit_event(
        actor=str(actor or safe_username),
        action="break_glass.session_opened",
        object_type="break_glass_session",
        object_id=str(item.get("id") or ""),
        summary=safe_username,
        details={"reason": safe_reason, "client_ip": str(client_ip or ""), "expires_ts": item["expires_ts"]},
    )
    return _break_glass_public_view(item)


def revoke_break_glass_session(session_id: str, *, actor: str = "system", reason: str = "") -> dict[str, Any]:
    safe_session_id = str(session_id or "").strip()
    rows = _collection("break_glass_sessions", _default_break_glass_sessions)
    item = _find_by_id(rows, safe_session_id)
    if item is None:
        raise ValueError(f"Break-glass session not found: {safe_session_id}")
    item["status"] = "revoked"
    item["closed_ts"] = _now_iso()
    item["closed_by"] = actor
    item["close_reason"] = str(reason or "revoked").strip() or "revoked"
    _save_collection("break_glass_sessions", rows)
    append_audit_event(
        actor=actor,
        action="break_glass.session_revoked",
        object_type="break_glass_session",
        object_id=safe_session_id,
        summary=str(item.get("username") or safe_session_id),
        details={"reason": item["close_reason"]},
    )
    return _break_glass_public_view(item)


def is_break_glass_session_active(session_id: str) -> bool:
    safe_session_id = str(session_id or "").strip()
    if not safe_session_id:
        return False
    item = _find_by_id(_collection("break_glass_sessions", _default_break_glass_sessions), safe_session_id)
    if item is None:
        return False
    return str(_break_glass_public_view(item).get("status") or "") == "active"


def get_auth_overview() -> dict[str, Any]:
    try:
        from .control_plane_health import get_auth_overview as get_auth_overview_impl
    except ImportError:  # pragma: no cover - local test fallback
        from control_plane_health import get_auth_overview as get_auth_overview_impl  # type: ignore[no-redef]

    return get_auth_overview_impl()


def _user_public_view(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "username": str(item.get("username") or ""),
        "role": str(item.get("role") or "viewer"),
        "enabled": bool(item.get("enabled", True)),
        "permissions": _normalize_permissions(item.get("permissions") or []),
        "permission_bundles": _normalize_permission_bundles(item.get("permission_bundles") or []),
        "created_ts": str(item.get("created_ts") or ""),
        "updated_ts": str(item.get("updated_ts") or ""),
        "password_updated_ts": str(item.get("password_updated_ts") or ""),
        "source": str(item.get("source") or "control_plane"),
    }


def load_local_user_auth_records() -> list[dict[str, Any]]:
    rows = _collection("local_users", _default_local_users)
    records: list[dict[str, Any]] = []
    for item in rows:
        username = str(item.get("username") or "").strip()
        if not username:
            continue
        records.append(
            {
                "username": username,
                "role": str(item.get("role") or "viewer").strip().lower() or "viewer",
                "password_hash": str(item.get("password_hash") or "").strip(),
                "permissions": _normalize_permissions(item.get("permissions") or []),
                "permission_bundles": _normalize_permission_bundles(item.get("permission_bundles") or []),
                "enabled": bool(item.get("enabled", True)),
            }
        )
    return records


def _invalidate_local_auth_cache() -> None:
    try:
        from . import security
    except Exception:  # pragma: no cover - local test fallback
        try:
            import security  # type: ignore[no-redef]
        except Exception:
            return

    invalidate = getattr(security, "invalidate_local_auth_cache", None)
    if callable(invalidate):
        invalidate()


def list_local_users(*, include_disabled: bool = True) -> list[dict[str, Any]]:
    rows = [_user_public_view(item) for item in _collection("local_users", _default_local_users)]
    if not include_disabled:
        rows = [item for item in rows if item.get("enabled", True)]
    rows.sort(key=lambda item: str(item.get("username") or ""))
    return _json_clone(rows)


def get_local_user(username: str) -> dict[str, Any] | None:
    safe_username = str(username or "").strip()
    item = next((row for row in _collection("local_users", _default_local_users) if str(row.get("username") or "") == safe_username), None)
    return _user_public_view(item) if item else None


def _ensure_safe_local_admin_mutation(
    rows: list[dict[str, Any]],
    current: dict[str, Any],
    *,
    actor: str,
    deleting: bool = False,
    desired_role: str = "",
    desired_enabled: bool | None = None,
) -> None:
    username = str(current.get("username") or "").strip()
    role_demotion = str(current.get("role") or "").lower() == "admin" and desired_role not in {"", "admin"}
    status_disable = bool(current.get("enabled", True)) and desired_enabled is False
    removes_access = deleting or role_demotion or status_disable
    if removes_access and username.casefold() == str(actor or "").strip().casefold():
        raise AccessMutationConflict("The current break-glass user cannot be deleted, disabled, or demoted")
    is_enabled_admin = str(current.get("role") or "").lower() == "admin" and bool(current.get("enabled", True))
    if not is_enabled_admin or not removes_access:
        return
    enabled_admins = [
        row
        for row in rows
        if str(row.get("role") or "").lower() == "admin" and bool(row.get("enabled", True))
    ]
    if len(enabled_admins) <= 1:
        raise AccessMutationConflict("The last enabled break-glass administrator cannot be deleted, disabled, or demoted")


def save_local_user(payload: dict[str, Any], *, actor: str = "system") -> dict[str, Any]:
    safe_username = str(payload.get("username") or "").strip()
    if not safe_username:
        raise ValueError("username is required")
    role = str(payload.get("role") or "viewer").strip().lower() or "viewer"
    if role not in {"admin", "analyst", "viewer"}:
        raise ValueError(f"Unsupported role: {role}")
    rows = _collection("local_users", _default_local_users)
    existing = next((row for row in rows if str(row.get("username") or "") == safe_username), None)
    if existing is not None:
        _ensure_safe_local_admin_mutation(
            rows,
            existing,
            actor=actor,
            desired_role=role,
            desired_enabled=bool(payload.get("enabled", existing.get("enabled", True))),
        )
    password_hash = str(payload.get("password_hash") or "").strip()
    raw_password = str(payload.get("password") or "")
    if raw_password and not password_hash:
        password_hash = _hash_password(raw_password)
    if existing is None and not password_hash:
        raise ValueError("password or password_hash is required for a new user")
    if password_hash and not raw_password and not str(password_hash).startswith(f"{PASSWORD_HASH_SCHEME}$"):
        raise ValueError("Unsupported password hash format")
    now_iso = _now_iso()
    permissions, permission_bundles = _compose_permissions(
        requested_permissions=payload.get("permissions") if "permissions" in payload else None,
        requested_bundles=payload.get("permission_bundles") if "permission_bundles" in payload else None,
        existing_permissions=existing.get("permissions") if existing else [],
        existing_bundles=existing.get("permission_bundles") if existing else [],
    )
    item = {
        "username": safe_username,
        "role": role,
        "enabled": bool(payload.get("enabled", existing.get("enabled", True) if existing else True)),
        "permissions": permissions,
        "permission_bundles": permission_bundles,
        "password_hash": password_hash or str(existing.get("password_hash") or ""),
        "created_ts": str(existing.get("created_ts") if existing else now_iso),
        "updated_ts": now_iso,
        "password_updated_ts": (
            now_iso
            if password_hash and password_hash != str(existing.get("password_hash") if existing else "")
            else str(existing.get("password_updated_ts") if existing else now_iso)
        ),
        "source": "control_plane",
    }
    rows = [row for row in rows if str(row.get("username") or "") != safe_username]
    rows.append(item)
    _save_collection("local_users", rows)
    _invalidate_local_auth_cache()
    append_audit_event(
        actor=actor,
        action="local_user.saved",
        object_type="local_user",
        object_id=safe_username,
        summary=safe_username,
        details={"role": role, "enabled": item["enabled"], "permissions": item["permissions"], "permission_bundles": item["permission_bundles"]},
    )
    return _user_public_view(item)


def set_local_user_password(username: str, *, new_password: str, actor: str = "system") -> dict[str, Any]:
    safe_username = str(username or "").strip()
    if not safe_username:
        raise ValueError("username is required")
    if not str(new_password or ""):
        raise ValueError("new_password is required")
    rows = _collection("local_users", _default_local_users)
    item = next((row for row in rows if str(row.get("username") or "") == safe_username), None)
    if item is None:
        raise ValueError(f"Local user not found: {safe_username}")
    item["password_hash"] = _hash_password(new_password)
    item["updated_ts"] = _now_iso()
    item["password_updated_ts"] = item["updated_ts"]
    _save_collection("local_users", rows)
    _invalidate_local_auth_cache()
    append_audit_event(
        actor=actor,
        action="local_user.password_rotated",
        object_type="local_user",
        object_id=safe_username,
        summary=safe_username,
        details={},
    )
    return _user_public_view(item)


def delete_local_user(username: str, *, actor: str = "system") -> dict[str, Any]:
    safe_username = str(username or "").strip()
    rows = _collection("local_users", _default_local_users)
    item = next((row for row in rows if str(row.get("username") or "") == safe_username), None)
    if item is None:
        raise ValueError(f"Local user not found: {safe_username}")
    _ensure_safe_local_admin_mutation(rows, item, actor=actor, deleting=True)
    rows = [row for row in rows if str(row.get("username") or "") != safe_username]
    _save_collection("local_users", rows)
    _invalidate_local_auth_cache()
    append_audit_event(
        actor=actor,
        action="local_user.deleted",
        object_type="local_user",
        object_id=safe_username,
        summary=safe_username,
        details={},
    )
    return _user_public_view(item)


