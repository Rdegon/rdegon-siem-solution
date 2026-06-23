from __future__ import annotations

import json
import os
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

try:
    from .control_plane_governance_runtime import append_audit_event
except ImportError:  # pragma: no cover - local test fallback
    from control_plane_governance_runtime import append_audit_event  # type: ignore[no-redef]

try:
    from .oidc_runtime import provider_status
except ImportError:  # pragma: no cover - local test fallback
    from oidc_runtime import provider_status  # type: ignore[no-redef]

try:
    from .secret_runtime import resolve_secret_value
except ImportError:  # pragma: no cover - local test fallback
    from secret_runtime import resolve_secret_value  # type: ignore[no-redef]


_TOKEN_LOCK = threading.RLock()
_TOKEN_CACHE: dict[str, Any] = {"value": "", "expires_epoch": 0.0}


def _string(value: Any) -> str:
    return str(value or "").strip()


def _issuer_url() -> str:
    return _string(os.getenv("SIEM_OIDC_ISSUER_URL"))


def _realm_name() -> str:
    explicit = _string(os.getenv("SIEM_KEYCLOAK_REALM"))
    if explicit:
        return explicit
    issuer = _issuer_url().rstrip("/")
    marker = "/realms/"
    if marker in issuer:
        return issuer.rsplit(marker, 1)[-1].strip("/") or "siem"
    return "siem"


def _base_url() -> str:
    explicit = _string(os.getenv("SIEM_KEYCLOAK_BASE_URL"))
    if explicit:
        return explicit.rstrip("/")
    issuer = _issuer_url().rstrip("/")
    marker = "/realms/"
    if marker in issuer:
        return issuer.split(marker, 1)[0].rstrip("/")
    return ""


def _admin_client_id() -> str:
    return _string(os.getenv("SIEM_KEYCLOAK_ADMIN_CLIENT_ID") or "siem-keycloak-admin")


def _admin_client_secret() -> str:
    value, _, _ = resolve_secret_value("SIEM_KEYCLOAK_ADMIN_CLIENT_SECRET")
    return _string(value)


def _tls_verify_enabled() -> bool:
    raw = _string(os.getenv("SIEM_KEYCLOAK_TLS_VERIFY") or os.getenv("SIEM_OIDC_TLS_VERIFY") or "enabled").lower()
    return raw not in {"0", "false", "no", "off", "disabled"}


def _ssl_context() -> ssl.SSLContext | None:
    if _tls_verify_enabled():
        return None
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def _token_endpoint() -> str:
    base = _base_url()
    realm = _realm_name()
    return f"{base}/realms/{realm}/protocol/openid-connect/token" if base and realm else ""


def _admin_base() -> str:
    base = _base_url()
    realm = _realm_name()
    return f"{base}/admin/realms/{realm}" if base and realm else ""


def _provider_issues() -> list[str]:
    issues: list[str] = []
    if not _base_url():
        issues.append("keycloak_base_url_missing")
    if not _realm_name():
        issues.append("keycloak_realm_missing")
    if not _admin_client_id():
        issues.append("keycloak_admin_client_id_missing")
    if not _admin_client_secret():
        issues.append("keycloak_admin_client_secret_missing")
    return issues


def _request(
    path_or_url: str,
    *,
    method: str = "GET",
    payload: dict[str, Any] | list[Any] | None = None,
    token: str = "",
    form: dict[str, str] | None = None,
) -> tuple[int, dict[str, Any] | list[Any] | str, dict[str, str]]:
    url = path_or_url if path_or_url.startswith("http") else f"{_admin_base()}{path_or_url}"
    headers = {"Accept": "application/json"}
    data = None
    if form is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        data = urllib.parse.urlencode(form).encode("utf-8")
    elif payload is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers, data=data, method=method.upper())
    try:
        with urllib.request.urlopen(request, timeout=15, context=_ssl_context()) as response:
            body = response.read().decode("utf-8", errors="replace")
            parsed: dict[str, Any] | list[Any] | str
            if not body:
                parsed = {}
            else:
                try:
                    parsed = json.loads(body)
                except json.JSONDecodeError:
                    parsed = body
            return response.status, parsed, {key.lower(): value for key, value in response.headers.items()}
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        if body:
            try:
                parsed = json.loads(body)
            except json.JSONDecodeError:
                parsed = body
        else:
            parsed = {}
        return exc.code, parsed, {key.lower(): value for key, value in exc.headers.items()}


def _ensure_ok(status: int, payload: Any, *, allowed: set[int] | None = None) -> Any:
    accepted = allowed or {200}
    if status in accepted:
        return payload
    if isinstance(payload, dict):
        message = "; ".join(str(item) for item in (payload.get("errors") or []) if str(item).strip())
        if not message:
            message = _string(payload.get("errorMessage") or payload.get("error_description") or payload.get("error"))
    else:
        message = _string(payload)
    raise RuntimeError(message or f"Keycloak admin request failed: {status}")


def _token_payload() -> tuple[str, str]:
    issues = _provider_issues()
    if issues:
        raise RuntimeError(", ".join(issues))
    with _TOKEN_LOCK:
        cached = _string(_TOKEN_CACHE.get("value"))
        expiry = float(_TOKEN_CACHE.get("expires_epoch") or 0.0)
        if cached and expiry > time.time() + 15:
            return cached, "cache"
        status, payload, _ = _request(
            _token_endpoint(),
            method="POST",
            form={
                "grant_type": "client_credentials",
                "client_id": _admin_client_id(),
                "client_secret": _admin_client_secret(),
            },
        )
        data = _ensure_ok(status, payload, allowed={200})
        if not isinstance(data, dict):
            raise RuntimeError("keycloak_admin_token_invalid")
        token = _string(data.get("access_token"))
        expires_in = int(data.get("expires_in") or 300)
        if not token:
            raise RuntimeError("keycloak_admin_token_missing")
        _TOKEN_CACHE["value"] = token
        _TOKEN_CACHE["expires_epoch"] = time.time() + max(30, expires_in - 15)
        return token, "client_credentials"


def _auth_token() -> str:
    token, _ = _token_payload()
    return token


def _user_summary(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": _string(item.get("id")),
        "username": _string(item.get("username")),
        "email": _string(item.get("email")),
        "first_name": _string(item.get("firstName")),
        "last_name": _string(item.get("lastName")),
        "enabled": bool(item.get("enabled", True)),
        "email_verified": bool(item.get("emailVerified", False)),
        "created_ts": int(item.get("createdTimestamp") or 0),
    }


def _group_summary(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": _string(item.get("id")),
        "name": _string(item.get("name")),
        "path": _string(item.get("path")),
        "sub_group_count": len(item.get("subGroups") or []),
    }


def _role_summary(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": _string(item.get("id")),
        "name": _string(item.get("name")),
        "description": _string(item.get("description")),
        "composite": bool(item.get("composite", False)),
        "client_role": bool(item.get("clientRole", False)),
    }


def _client_summary(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": _string(item.get("id")),
        "client_id": _string(item.get("clientId")),
        "name": _string(item.get("name")),
        "description": _string(item.get("description")),
        "enabled": bool(item.get("enabled", True)),
        "protocol": _string(item.get("protocol") or "openid-connect"),
        "public_client": bool(item.get("publicClient", False)),
        "service_accounts_enabled": bool(item.get("serviceAccountsEnabled", False)),
        "redirect_uris": list(item.get("redirectUris") or []),
        "web_origins": list(item.get("webOrigins") or []),
        "root_url": _string(item.get("rootUrl")),
        "base_url": _string(item.get("baseUrl")),
        "standard_flow_enabled": bool(item.get("standardFlowEnabled", True)),
        "direct_access_grants_enabled": bool(item.get("directAccessGrantsEnabled", False)),
        "frontchannel_logout": bool(item.get("frontchannelLogout", False)),
    }


def _find_client(identifier: str) -> dict[str, Any] | None:
    safe = _string(identifier)
    if not safe:
        return None
    status, payload, _ = _request(f"/clients?clientId={urllib.parse.quote(safe)}", token=_auth_token())
    if status == 200 and isinstance(payload, list) and payload:
        return dict(payload[0])
    status, payload, _ = _request(f"/clients/{urllib.parse.quote(safe)}", token=_auth_token())
    if status == 200 and isinstance(payload, dict):
        return dict(payload)
    return None


def _find_group(identifier: str) -> dict[str, Any] | None:
    safe = _string(identifier)
    if not safe:
        return None
    for item in list_groups():
        if _string(item.get("id")) == safe or _string(item.get("name")) == safe or _string(item.get("path")) == safe:
            return dict(item)
    return None


def status() -> dict[str, Any]:
    provider = dict(provider_status())
    issues = list(provider.get("issues") or [])
    issues.extend(_provider_issues())
    admin_ready = False
    auth_source = ""
    inventory = {"users": 0, "groups": 0, "roles": 0, "clients": 0}
    try:
        _, auth_source = _token_payload()
        inventory = {
            "users": len(list_users(limit=300)),
            "groups": len(list_groups()),
            "roles": len(list_roles()),
            "clients": len(list_clients()),
        }
        admin_ready = True
    except Exception as exc:  # noqa: BLE001
        issues.append(str(exc))
    return {
        "provider": provider,
        "realm": _realm_name(),
        "base_url": _base_url(),
        "admin_client_id": _admin_client_id(),
        "auth_source": auth_source,
        "healthy": bool(provider.get("healthy")) and admin_ready and not issues,
        "admin_ready": admin_ready,
        "issues": issues,
        "inventory": inventory,
    }


def list_users(*, search: str = "", limit: int = 200) -> list[dict[str, Any]]:
    params = {"max": str(max(1, min(limit, 500)))}
    if _string(search):
        params["search"] = _string(search)
    status, payload, _ = _request(f"/users?{urllib.parse.urlencode(params)}", token=_auth_token())
    data = _ensure_ok(status, payload, allowed={200})
    return [_user_summary(dict(item)) for item in (data if isinstance(data, list) else [])]


def get_user(user_id: str) -> dict[str, Any]:
    safe_user_id = _string(user_id)
    if not safe_user_id:
        raise ValueError("user_id is required")
    status, payload, _ = _request(f"/users/{urllib.parse.quote(safe_user_id)}", token=_auth_token())
    user_payload = _ensure_ok(status, payload, allowed={200})
    detail = _user_summary(dict(user_payload if isinstance(user_payload, dict) else {}))
    status, groups_payload, _ = _request(f"/users/{urllib.parse.quote(safe_user_id)}/groups", token=_auth_token())
    detail["groups"] = [_group_summary(dict(item)) for item in (_ensure_ok(status, groups_payload, allowed={200}) if isinstance(groups_payload, list) else [])]
    status, roles_payload, _ = _request(f"/users/{urllib.parse.quote(safe_user_id)}/role-mappings/realm", token=_auth_token())
    detail["roles"] = [_role_summary(dict(item)) for item in (_ensure_ok(status, roles_payload, allowed={200}) if isinstance(roles_payload, list) else [])]
    status, sessions_payload, _ = _request(f"/users/{urllib.parse.quote(safe_user_id)}/sessions", token=_auth_token())
    detail["sessions"] = list(sessions_payload) if status == 200 and isinstance(sessions_payload, list) else []
    detail["attributes"] = dict((user_payload if isinstance(user_payload, dict) else {}).get("attributes") or {})
    return detail


def create_user(payload: dict[str, Any], *, actor: str = "system") -> dict[str, Any]:
    body = {
        "username": _string(payload.get("username")),
        "email": _string(payload.get("email")),
        "firstName": _string(payload.get("first_name") or payload.get("firstName")),
        "lastName": _string(payload.get("last_name") or payload.get("lastName")),
        "enabled": bool(payload.get("enabled", True)),
        "emailVerified": bool(payload.get("email_verified", False)),
        "attributes": dict(payload.get("attributes") or {}),
    }
    if not body["username"]:
        raise ValueError("username is required")
    status, response_payload, headers = _request("/users", method="POST", payload=body, token=_auth_token())
    _ensure_ok(status, response_payload, allowed={201, 204})
    location = _string(headers.get("location"))
    user_id = location.rsplit("/", 1)[-1] if "/" in location else ""
    if not user_id:
        items = list_users(search=body["username"], limit=10)
        user_id = _string((items[0] if items else {}).get("id"))
    if not user_id:
        raise RuntimeError("keycloak_user_create_location_missing")
    if _string(payload.get("password")):
        set_user_password(user_id, {"password": _string(payload.get("password")), "temporary": bool(payload.get("temporary_password", False))}, actor=actor)
    if payload.get("group_ids") or payload.get("group_names"):
        set_user_groups(user_id, payload, actor=actor)
    if payload.get("roles"):
        set_user_roles(user_id, payload, actor=actor)
    detail = get_user(user_id)
    append_audit_event(
        actor=actor,
        action="keycloak.user.created",
        object_type="keycloak_user",
        object_id=user_id,
        summary=f"Created Keycloak user {detail.get('username')}",
        details={"username": detail.get("username"), "groups": [item.get("name") for item in detail.get("groups", [])], "roles": [item.get("name") for item in detail.get("roles", [])]},
    )
    return detail


def update_user(user_id: str, payload: dict[str, Any], *, actor: str = "system") -> dict[str, Any]:
    current = get_user(user_id)
    body = {
        "id": _string(user_id),
        "username": _string(payload.get("username") if "username" in payload else current.get("username")),
        "email": _string(payload.get("email") if "email" in payload else current.get("email")),
        "firstName": _string(payload.get("first_name") if "first_name" in payload else payload.get("firstName") if "firstName" in payload else current.get("first_name")),
        "lastName": _string(payload.get("last_name") if "last_name" in payload else payload.get("lastName") if "lastName" in payload else current.get("last_name")),
        "enabled": bool(payload.get("enabled")) if "enabled" in payload else bool(current.get("enabled", True)),
        "emailVerified": bool(payload.get("email_verified")) if "email_verified" in payload else bool(current.get("email_verified", False)),
        "attributes": dict(payload.get("attributes") if "attributes" in payload else current.get("attributes") or {}),
    }
    status, response_payload, _ = _request(f"/users/{urllib.parse.quote(_string(user_id))}", method="PUT", payload=body, token=_auth_token())
    _ensure_ok(status, response_payload, allowed={204})
    if payload.get("group_ids") or payload.get("group_names"):
        set_user_groups(user_id, payload, actor=actor)
    if payload.get("roles"):
        set_user_roles(user_id, payload, actor=actor)
    detail = get_user(user_id)
    append_audit_event(
        actor=actor,
        action="keycloak.user.updated",
        object_type="keycloak_user",
        object_id=_string(user_id),
        summary=f"Updated Keycloak user {detail.get('username')}",
        details={"username": detail.get("username"), "enabled": detail.get("enabled")},
    )
    return detail


def set_user_password(user_id: str, payload: dict[str, Any], *, actor: str = "system") -> dict[str, Any]:
    password = _string(payload.get("password") or payload.get("new_password"))
    if not password:
        raise ValueError("password is required")
    status, response_payload, _ = _request(
        f"/users/{urllib.parse.quote(_string(user_id))}/reset-password",
        method="PUT",
        payload={"type": "password", "temporary": bool(payload.get("temporary", False)), "value": password},
        token=_auth_token(),
    )
    _ensure_ok(status, response_payload, allowed={204})
    detail = get_user(user_id)
    append_audit_event(
        actor=actor,
        action="keycloak.user.password_rotated",
        object_type="keycloak_user",
        object_id=_string(user_id),
        summary=f"Rotated password for Keycloak user {detail.get('username')}",
        details={"username": detail.get("username")},
    )
    return detail


def delete_user(user_id: str, *, actor: str = "system") -> dict[str, Any]:
    detail = get_user(user_id)
    safe_user_id = _string(user_id)
    if not safe_user_id:
        raise ValueError("user_id is required")
    status, response_payload, _ = _request(f"/users/{urllib.parse.quote(safe_user_id)}", method="DELETE", token=_auth_token())
    _ensure_ok(status, response_payload, allowed={204})
    append_audit_event(
        actor=actor,
        action="keycloak.user.deleted",
        object_type="keycloak_user",
        object_id=safe_user_id,
        summary=f"Deleted Keycloak user {detail.get('username')}",
        details={"username": detail.get("username")},
    )
    return {"deleted": True, "id": safe_user_id, "username": detail.get("username")}


def set_user_groups(user_id: str, payload: dict[str, Any], *, actor: str = "system") -> dict[str, Any]:
    desired = set()
    for raw in list(payload.get("group_ids") or []):
        group = _find_group(_string(raw))
        if group:
            desired.add(_string(group.get("id")))
    for raw in list(payload.get("group_names") or []):
        group = _find_group(_string(raw))
        if group:
            desired.add(_string(group.get("id")))
    current = {_string(item.get("id")) for item in get_user(user_id).get("groups", [])}
    token = _auth_token()
    for group_id in sorted(current - desired):
        status, response_payload, _ = _request(
            f"/users/{urllib.parse.quote(_string(user_id))}/groups/{urllib.parse.quote(group_id)}",
            method="DELETE",
            token=token,
        )
        _ensure_ok(status, response_payload, allowed={204})
    for group_id in sorted(desired - current):
        status, response_payload, _ = _request(
            f"/users/{urllib.parse.quote(_string(user_id))}/groups/{urllib.parse.quote(group_id)}",
            method="PUT",
            token=token,
        )
        _ensure_ok(status, response_payload, allowed={204})
    detail = get_user(user_id)
    append_audit_event(
        actor=actor,
        action="keycloak.user.groups_updated",
        object_type="keycloak_user",
        object_id=_string(user_id),
        summary=f"Updated groups for Keycloak user {detail.get('username')}",
        details={"groups": [item.get("name") for item in detail.get("groups", [])]},
    )
    return detail


def list_roles() -> list[dict[str, Any]]:
    status, payload, _ = _request("/roles", token=_auth_token())
    data = _ensure_ok(status, payload, allowed={200})
    return [_role_summary(dict(item)) for item in (data if isinstance(data, list) else [])]


def set_user_roles(user_id: str, payload: dict[str, Any], *, actor: str = "system") -> dict[str, Any]:
    desired_names = {_string(item) for item in (payload.get("roles") or []) if _string(item)}
    role_index = {_string(item.get("name")): dict(item) for item in list_roles()}
    current_roles = {_string(item.get("name")): dict(item) for item in get_user(user_id).get("roles", [])}
    token = _auth_token()
    to_remove = [current_roles[name] for name in sorted(set(current_roles) - desired_names) if name in current_roles]
    if to_remove:
        status, response_payload, _ = _request(
            f"/users/{urllib.parse.quote(_string(user_id))}/role-mappings/realm",
            method="DELETE",
            payload=to_remove,
            token=token,
        )
        _ensure_ok(status, response_payload, allowed={204})
    to_add = [role_index[name] for name in sorted(desired_names - set(current_roles)) if name in role_index]
    if to_add:
        status, response_payload, _ = _request(
            f"/users/{urllib.parse.quote(_string(user_id))}/role-mappings/realm",
            method="POST",
            payload=to_add,
            token=token,
        )
        _ensure_ok(status, response_payload, allowed={204})
    detail = get_user(user_id)
    append_audit_event(
        actor=actor,
        action="keycloak.user.roles_updated",
        object_type="keycloak_user",
        object_id=_string(user_id),
        summary=f"Updated roles for Keycloak user {detail.get('username')}",
        details={"roles": [item.get("name") for item in detail.get("roles", [])]},
    )
    return detail


def list_groups() -> list[dict[str, Any]]:
    status, payload, _ = _request("/groups?briefRepresentation=false", token=_auth_token())
    data = _ensure_ok(status, payload, allowed={200})
    return [_group_summary(dict(item)) for item in (data if isinstance(data, list) else [])]


def save_group(payload: dict[str, Any], *, actor: str = "system", group_id: str = "") -> dict[str, Any]:
    safe_group_id = _string(group_id or payload.get("id"))
    body = {"name": _string(payload.get("name")), "attributes": dict(payload.get("attributes") or {})}
    if not body["name"]:
        raise ValueError("group name is required")
    if safe_group_id:
        status, response_payload, _ = _request(f"/groups/{urllib.parse.quote(safe_group_id)}", method="PUT", payload=body, token=_auth_token())
        _ensure_ok(status, response_payload, allowed={204})
        result = _find_group(safe_group_id) or {"id": safe_group_id, "name": body["name"]}
        append_audit_event(actor=actor, action="keycloak.group.updated", object_type="keycloak_group", object_id=_string(result.get("id")), summary=f"Updated Keycloak group {body['name']}", details={"name": body["name"]})
        return _group_summary(result)
    status, response_payload, headers = _request("/groups", method="POST", payload=body, token=_auth_token())
    _ensure_ok(status, response_payload, allowed={201, 204})
    location = _string(headers.get("location"))
    resolved_id = location.rsplit("/", 1)[-1] if "/" in location else ""
    result = _find_group(resolved_id or body["name"]) or {"id": resolved_id, "name": body["name"]}
    append_audit_event(actor=actor, action="keycloak.group.created", object_type="keycloak_group", object_id=_string(result.get("id")), summary=f"Created Keycloak group {body['name']}", details={"name": body["name"]})
    return _group_summary(result)


def save_role(payload: dict[str, Any], *, actor: str = "system", role_name: str = "") -> dict[str, Any]:
    name = _string(role_name or payload.get("name"))
    if not name:
        raise ValueError("role name is required")
    body = {"name": name, "description": _string(payload.get("description"))}
    existing = next((item for item in list_roles() if _string(item.get("name")) == name), None)
    if existing:
        status, response_payload, _ = _request(f"/roles/{urllib.parse.quote(name)}", method="PUT", payload=body, token=_auth_token())
        _ensure_ok(status, response_payload, allowed={204})
        action = "keycloak.role.updated"
        summary = f"Updated Keycloak role {name}"
    else:
        status, response_payload, _ = _request("/roles", method="POST", payload=body, token=_auth_token())
        _ensure_ok(status, response_payload, allowed={201, 204})
        action = "keycloak.role.created"
        summary = f"Created Keycloak role {name}"
    result = next((item for item in list_roles() if _string(item.get("name")) == name), {"name": name, "description": body["description"]})
    append_audit_event(actor=actor, action=action, object_type="keycloak_role", object_id=name, summary=summary, details={"description": body["description"]})
    return _role_summary(result)


def list_clients() -> list[dict[str, Any]]:
    status, payload, _ = _request("/clients?max=500", token=_auth_token())
    data = _ensure_ok(status, payload, allowed={200})
    return [_client_summary(dict(item)) for item in (data if isinstance(data, list) else [])]


def get_client(client_id: str) -> dict[str, Any]:
    client = _find_client(client_id)
    if not client:
        raise ValueError(f"Keycloak client not found: {client_id}")
    detail = _client_summary(client)
    status, secret_payload, _ = _request(f"/clients/{urllib.parse.quote(_string(client.get('id')))}/client-secret", token=_auth_token())
    if status == 200 and isinstance(secret_payload, dict):
        detail["secret_type"] = _string(secret_payload.get("type"))
        detail["has_secret"] = bool(_string(secret_payload.get("value")))
    return detail


def save_client(payload: dict[str, Any], *, actor: str = "system", client_id: str = "") -> dict[str, Any]:
    current = _find_client(client_id or _string(payload.get("client_id")) or _string(payload.get("id")))
    body = {
        "clientId": _string(payload.get("client_id") or payload.get("clientId") or (current or {}).get("clientId")),
        "name": _string(payload.get("name") or (current or {}).get("name")),
        "description": _string(payload.get("description") or (current or {}).get("description")),
        "enabled": bool(payload.get("enabled")) if "enabled" in payload else bool((current or {}).get("enabled", True)),
        "protocol": _string(payload.get("protocol") or (current or {}).get("protocol") or "openid-connect"),
        "publicClient": bool(payload.get("public_client")) if "public_client" in payload else bool((current or {}).get("publicClient", False)),
        "serviceAccountsEnabled": bool(payload.get("service_accounts_enabled")) if "service_accounts_enabled" in payload else bool((current or {}).get("serviceAccountsEnabled", False)),
        "redirectUris": list(payload.get("redirect_uris") or (current or {}).get("redirectUris") or []),
        "webOrigins": list(payload.get("web_origins") or (current or {}).get("webOrigins") or []),
        "rootUrl": _string(payload.get("root_url") or (current or {}).get("rootUrl")),
        "baseUrl": _string(payload.get("base_url") or (current or {}).get("baseUrl")),
        "standardFlowEnabled": bool(payload.get("standard_flow_enabled")) if "standard_flow_enabled" in payload else bool((current or {}).get("standardFlowEnabled", True)),
        "directAccessGrantsEnabled": bool(payload.get("direct_access_grants_enabled")) if "direct_access_grants_enabled" in payload else bool((current or {}).get("directAccessGrantsEnabled", False)),
        "frontchannelLogout": bool(payload.get("frontchannel_logout")) if "frontchannel_logout" in payload else bool((current or {}).get("frontchannelLogout", False)),
    }
    if not body["clientId"]:
        raise ValueError("client_id is required")
    if current:
        status, response_payload, _ = _request(f"/clients/{urllib.parse.quote(_string(current.get('id')))}", method="PUT", payload=body, token=_auth_token())
        _ensure_ok(status, response_payload, allowed={204})
        action = "keycloak.client.updated"
        summary = f"Updated Keycloak client {body['clientId']}"
    else:
        if not body["publicClient"] and _string(payload.get("secret")):
            body["secret"] = _string(payload.get("secret"))
        status, response_payload, _ = _request("/clients", method="POST", payload=body, token=_auth_token())
        _ensure_ok(status, response_payload, allowed={201, 204})
        action = "keycloak.client.created"
        summary = f"Created Keycloak client {body['clientId']}"
    result = get_client(body["clientId"])
    append_audit_event(
        actor=actor,
        action=action,
        object_type="keycloak_client",
        object_id=_string(result.get("id") or result.get("client_id")),
        summary=summary,
        details={"client_id": result.get("client_id"), "service_accounts_enabled": result.get("service_accounts_enabled")},
    )
    return result


def list_client_protocol_mappers(client_id: str) -> list[dict[str, Any]]:
    client = _find_client(client_id)
    if not client:
        raise ValueError(f"Keycloak client not found: {client_id}")
    status, payload, _ = _request(f"/clients/{urllib.parse.quote(_string(client.get('id')))}/protocol-mappers/models", token=_auth_token())
    data = _ensure_ok(status, payload, allowed={200})
    return [dict(item) for item in (data if isinstance(data, list) else [])]


def save_client_protocol_mapper(
    client_id: str,
    payload: dict[str, Any],
    *,
    actor: str = "system",
    mapper_name: str = "",
) -> dict[str, Any]:
    client = _find_client(client_id)
    if not client:
        raise ValueError(f"Keycloak client not found: {client_id}")
    safe_name = _string(mapper_name or payload.get("name"))
    if not safe_name:
        raise ValueError("mapper name is required")
    current = next((item for item in list_client_protocol_mappers(client_id) if _string(item.get("name")) == safe_name), None)
    body = {
        "name": safe_name,
        "protocol": _string(payload.get("protocol") or (current or {}).get("protocol") or "openid-connect"),
        "protocolMapper": _string(payload.get("protocol_mapper") or payload.get("protocolMapper") or (current or {}).get("protocolMapper")),
        "config": dict(payload.get("config") or (current or {}).get("config") or {}),
    }
    if not body["protocolMapper"]:
        raise ValueError("protocol_mapper is required")
    if current:
        mapper_id = _string(current.get("id"))
        status, response_payload, _ = _request(
            f"/clients/{urllib.parse.quote(_string(client.get('id')))}/protocol-mappers/models/{urllib.parse.quote(mapper_id)}",
            method="PUT",
            payload={**body, "id": mapper_id},
            token=_auth_token(),
        )
        _ensure_ok(status, response_payload, allowed={204})
        result = next((item for item in list_client_protocol_mappers(client_id) if _string(item.get("name")) == safe_name), {**body, "id": mapper_id})
        action = "keycloak.client.mapper.updated"
        summary = f"Updated mapper {safe_name} for client {client_id}"
    else:
        status, response_payload, _ = _request(
            f"/clients/{urllib.parse.quote(_string(client.get('id')))}/protocol-mappers/models",
            method="POST",
            payload=body,
            token=_auth_token(),
        )
        _ensure_ok(status, response_payload, allowed={201, 204})
        result = next((item for item in list_client_protocol_mappers(client_id) if _string(item.get("name")) == safe_name), body)
        action = "keycloak.client.mapper.created"
        summary = f"Created mapper {safe_name} for client {client_id}"
    append_audit_event(
        actor=actor,
        action=action,
        object_type="keycloak_client_mapper",
        object_id=_string(result.get("id") or safe_name),
        summary=summary,
        details={"client_id": client_id, "protocol_mapper": body["protocolMapper"]},
    )
    return dict(result)


def ensure_group_membership_mapper(
    client_id: str,
    *,
    actor: str = "system",
    claim_name: str = "groups",
    mapper_name: str = "groups",
    full_path: bool = False,
) -> dict[str, Any]:
    return save_client_protocol_mapper(
        client_id,
        {
            "name": mapper_name,
            "protocol_mapper": "oidc-group-membership-mapper",
            "config": {
                "full.path": "true" if full_path else "false",
                "id.token.claim": "true",
                "access.token.claim": "true",
                "userinfo.token.claim": "true",
                "introspection.token.claim": "true",
                "claim.name": claim_name,
                "jsonType.label": "String",
            },
        },
        actor=actor,
        mapper_name=mapper_name,
    )


def ensure_audience_mapper(
    client_id: str,
    *,
    actor: str = "system",
    audience: str = "",
    mapper_name: str = "audience",
) -> dict[str, Any]:
    safe_audience = _string(audience or client_id)
    return save_client_protocol_mapper(
        client_id,
        {
            "name": mapper_name,
            "protocol_mapper": "oidc-audience-mapper",
            "config": {
                "included.client.audience": safe_audience,
                "included.custom.audience": safe_audience,
                "id.token.claim": "false",
                "access.token.claim": "true",
                "userinfo.token.claim": "false",
                "introspection.token.claim": "true",
            },
        },
        actor=actor,
        mapper_name=mapper_name,
    )


def rotate_client_secret(client_id: str, *, actor: str = "system") -> dict[str, Any]:
    client = _find_client(client_id)
    if not client:
        raise ValueError(f"Keycloak client not found: {client_id}")
    status, payload, _ = _request(f"/clients/{urllib.parse.quote(_string(client.get('id')))}/client-secret", method="POST", token=_auth_token())
    data = _ensure_ok(status, payload, allowed={200})
    if not isinstance(data, dict):
        raise RuntimeError("Keycloak secret rotation response was invalid")
    response = {
        "client_id": _string(client.get("clientId")),
        "secret_type": _string(data.get("type")),
        "secret": _string(data.get("value")),
    }
    append_audit_event(
        actor=actor,
        action="keycloak.client.secret_rotated",
        object_type="keycloak_client",
        object_id=_string(client.get("id") or client.get("clientId")),
        summary=f"Rotated client secret for {_string(client.get('clientId'))}",
        details={"client_id": _string(client.get("clientId"))},
    )
    return response
