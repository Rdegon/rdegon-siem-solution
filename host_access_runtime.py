from __future__ import annotations

import ipaddress
import uuid
from datetime import datetime, timezone
from typing import Any

try:
    from .enterprise_control_plane import append_audit_event, load_control_plane_rows, save_control_plane_rows
except ImportError:  # pragma: no cover - local test fallback
    from enterprise_control_plane import append_audit_event, load_control_plane_rows, save_control_plane_rows  # type: ignore[no-redef]

try:
    from .secret_runtime import vault_kv_write
except ImportError:  # pragma: no cover - local test fallback
    from secret_runtime import vault_kv_write  # type: ignore[no-redef]


HOST_ACCESS_COLLECTION = "host_access_profiles"
SUPPORTED_PROTOCOLS = {"ssh", "rdp", "winrm", "http", "https", "snmp", "custom"}
SUPPORTED_AUTH_METHODS = {"none", "password", "private_key", "certificate", "vault_ref", "kerberos"}
SECRET_INPUT_FIELDS = {
    "password",
    "credential",
    "credential_material",
    "private_key",
    "private_key_pem",
    "certificate",
    "certificate_pem",
    "passphrase",
}


def _now_iso() -> str:
    return datetime.now(tz=timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _slug(value: Any, default: str = "host") -> str:
    raw = str(value or "").strip().lower()
    cleaned = "".join(ch if ch.isalnum() else "-" for ch in raw).strip("-")
    while "--" in cleaned:
        cleaned = cleaned.replace("--", "-")
    return cleaned or default


def _new_id() -> str:
    return f"host-access-{uuid.uuid4().hex[:10]}"


def _string(value: Any) -> str:
    return str(value or "").strip()


def _list(value: Any) -> list[str]:
    if isinstance(value, list):
        source = value
    else:
        source = str(value or "").split(",")
    return [str(item).strip() for item in source if str(item).strip()]


def _bool(value: Any, default: bool = True) -> bool:
    if isinstance(value, bool):
        return value
    text = str(value if value is not None else "").strip().lower()
    if not text:
        return default
    if text in {"1", "true", "yes", "on", "enabled"}:
        return True
    if text in {"0", "false", "no", "off", "disabled"}:
        return False
    return default


def _safe_port(value: Any, protocol: str) -> int:
    default = {"ssh": 22, "rdp": 3389, "winrm": 5986, "http": 80, "https": 443, "snmp": 161}.get(protocol, 22)
    try:
        port = int(value or default)
    except (TypeError, ValueError):
        port = default
    return max(1, min(port, 65535))


def _normalize_ip(value: Any) -> str:
    text = _string(value)
    if not text:
        return ""
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return text


def _default_vault_ref(profile_id: str, field: str) -> str:
    return f"vault://secret/siem/host-access/{_slug(profile_id, 'profile')}?field={field}"


def _secret_payload(payload: dict[str, Any]) -> dict[str, str]:
    values: dict[str, str] = {}
    password = _string(payload.get("password") or payload.get("credential") or payload.get("credential_material"))
    if password:
        values["password"] = password
    private_key = _string(payload.get("private_key") or payload.get("private_key_pem"))
    if private_key:
        values["private_key"] = private_key
    certificate = _string(payload.get("certificate") or payload.get("certificate_pem"))
    if certificate:
        values["certificate"] = certificate
    passphrase = _string(payload.get("passphrase"))
    if passphrase:
        values["passphrase"] = passphrase
    return values


def _strip_secret_inputs(payload: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in dict(payload or {}).items() if key not in SECRET_INPUT_FIELDS}


def _profile_public_view(item: dict[str, Any]) -> dict[str, Any]:
    credential_refs = [ref for ref in [item.get("credential_ref"), item.get("private_key_ref"), item.get("certificate_ref")] if _string(ref)]
    return {
        "profile_id": _string(item.get("profile_id")),
        "host_id": _string(item.get("host_id")),
        "host_label": _string(item.get("host_label")),
        "hostname": _string(item.get("hostname")),
        "ip": _string(item.get("ip")),
        "protocol": _string(item.get("protocol")),
        "port": int(item.get("port") or 0),
        "username": _string(item.get("username")),
        "auth_method": _string(item.get("auth_method")),
        "credential_ref": _string(item.get("credential_ref")),
        "private_key_ref": _string(item.get("private_key_ref")),
        "certificate_ref": _string(item.get("certificate_ref")),
        "credential_label": _string(item.get("credential_label")),
        "jump_host": _string(item.get("jump_host")),
        "scope": _string(item.get("scope")),
        "allowed_actions": _list(item.get("allowed_actions")),
        "tags": _list(item.get("tags")),
        "notes": _string(item.get("notes")),
        "enabled": _bool(item.get("enabled"), True),
        "last_validated_ts": _string(item.get("last_validated_ts")),
        "validation_status": _string(item.get("validation_status") or "not_validated"),
        "secret_status": _string(item.get("secret_status") or ("configured" if credential_refs else "missing")),
        "secret_fields": _list(item.get("secret_fields")),
        "created_ts": _string(item.get("created_ts")),
        "updated_ts": _string(item.get("updated_ts")),
    }


def _rows() -> list[dict[str, Any]]:
    return list(load_control_plane_rows(HOST_ACCESS_COLLECTION, list))


def _save_rows(rows: list[dict[str, Any]]) -> None:
    save_control_plane_rows(HOST_ACCESS_COLLECTION, rows)


def list_host_access_profiles(*, limit: int = 500, host_id: str = "", ip: str = "") -> dict[str, Any]:
    safe_host_id = _string(host_id)
    safe_ip = _normalize_ip(ip)
    items = [_profile_public_view(row) for row in _rows()]
    if safe_host_id:
        items = [item for item in items if item.get("host_id") == safe_host_id]
    if safe_ip:
        items = [item for item in items if item.get("ip") == safe_ip]
    items.sort(key=lambda item: (str(item.get("host_label") or ""), str(item.get("protocol") or ""), str(item.get("profile_id") or "")))
    safe_limit = max(1, min(int(limit or 500), 2000))
    return {
        "items": items[:safe_limit],
        "metrics": {
            "profiles": len(items),
            "enabled": sum(1 for item in items if _bool(item.get("enabled"), True)),
            "with_secret_ref": sum(1 for item in items if _string(item.get("credential_ref") or item.get("private_key_ref") or item.get("certificate_ref"))),
            "ssh": sum(1 for item in items if item.get("protocol") == "ssh"),
            "rdp": sum(1 for item in items if item.get("protocol") == "rdp"),
            "winrm": sum(1 for item in items if item.get("protocol") == "winrm"),
        },
    }


def save_host_access_profile(payload: dict[str, Any], *, actor: str = "system") -> dict[str, Any]:
    raw = dict(payload or {})
    profile_id = _string(raw.get("profile_id")) or _new_id()
    existing_rows = _rows()
    existing = next((row for row in existing_rows if _string(row.get("profile_id")) == profile_id), {})
    protocol = _string(raw.get("protocol") or existing.get("protocol") or "ssh").lower()
    if protocol not in SUPPORTED_PROTOCOLS:
        raise ValueError(f"Unsupported host access protocol: {protocol}")
    auth_method = _string(raw.get("auth_method") or existing.get("auth_method") or "password").lower()
    if auth_method not in SUPPORTED_AUTH_METHODS:
        raise ValueError(f"Unsupported host access auth method: {auth_method}")
    now = _now_iso()
    secret_values = _secret_payload(raw)
    credential_ref = _string(raw.get("credential_ref") or existing.get("credential_ref"))
    private_key_ref = _string(raw.get("private_key_ref") or existing.get("private_key_ref"))
    certificate_ref = _string(raw.get("certificate_ref") or existing.get("certificate_ref"))
    secret_status = _string(existing.get("secret_status") or "missing")
    secret_fields = _list(existing.get("secret_fields"))
    if secret_values:
        vault_ref = credential_ref or private_key_ref or certificate_ref or _default_vault_ref(profile_id, "value")
        write_result = vault_kv_write(vault_ref, secret_values)
        secret_fields = _list(write_result.get("fields"))
        secret_status = "configured"
        if "password" in secret_values and not credential_ref:
            credential_ref = _default_vault_ref(profile_id, "password")
        if "private_key" in secret_values and not private_key_ref:
            private_key_ref = _default_vault_ref(profile_id, "private_key")
        if "certificate" in secret_values and not certificate_ref:
            certificate_ref = _default_vault_ref(profile_id, "certificate")
    elif credential_ref or private_key_ref or certificate_ref:
        secret_status = "reference"

    sanitized = _strip_secret_inputs(raw)
    item = {
        "profile_id": profile_id,
        "host_id": _string(sanitized.get("host_id") or existing.get("host_id") or sanitized.get("node_id")),
        "host_label": _string(sanitized.get("host_label") or existing.get("host_label") or sanitized.get("hostname") or sanitized.get("ip")),
        "hostname": _string(sanitized.get("hostname") or existing.get("hostname")),
        "ip": _normalize_ip(sanitized.get("ip") or existing.get("ip")),
        "protocol": protocol,
        "port": _safe_port(sanitized.get("port") or existing.get("port"), protocol),
        "username": _string(sanitized.get("username") or existing.get("username")),
        "auth_method": auth_method,
        "credential_ref": credential_ref,
        "private_key_ref": private_key_ref,
        "certificate_ref": certificate_ref,
        "credential_label": _string(sanitized.get("credential_label") or existing.get("credential_label") or "default"),
        "jump_host": _string(sanitized.get("jump_host") or existing.get("jump_host")),
        "scope": _string(sanitized.get("scope") or existing.get("scope") or "soar-irp"),
        "allowed_actions": _list(sanitized.get("allowed_actions") if "allowed_actions" in sanitized else existing.get("allowed_actions") or ["ssh_command"]),
        "tags": _list(sanitized.get("tags") if "tags" in sanitized else existing.get("tags")),
        "notes": _string(sanitized.get("notes") if "notes" in sanitized else existing.get("notes")),
        "enabled": _bool(sanitized.get("enabled", existing.get("enabled", True)), True),
        "last_validated_ts": _string(existing.get("last_validated_ts")),
        "validation_status": _string(existing.get("validation_status") or "not_validated"),
        "secret_status": secret_status,
        "secret_fields": secret_fields,
        "created_ts": _string(existing.get("created_ts") or now),
        "updated_ts": now,
    }
    if not item["host_id"] and not item["ip"] and not item["hostname"]:
        raise ValueError("Host access profile requires host_id, hostname, or ip")
    next_rows = [row for row in existing_rows if _string(row.get("profile_id")) != profile_id]
    next_rows.append(item)
    _save_rows(next_rows)
    append_audit_event(
        actor=actor,
        action="host_access_profile.saved",
        object_type="host_access_profile",
        object_id=profile_id,
        summary=item["host_label"] or item["ip"] or profile_id,
        details={"protocol": protocol, "auth_method": auth_method, "secret_status": secret_status},
    )
    return _profile_public_view(item)


def delete_host_access_profile(profile_id: str, *, actor: str = "system") -> dict[str, Any]:
    safe_id = _string(profile_id)
    rows = _rows()
    item = next((row for row in rows if _string(row.get("profile_id")) == safe_id), None)
    if item is None:
        raise ValueError(f"Host access profile not found: {safe_id}")
    _save_rows([row for row in rows if _string(row.get("profile_id")) != safe_id])
    append_audit_event(
        actor=actor,
        action="host_access_profile.deleted",
        object_type="host_access_profile",
        object_id=safe_id,
        summary=_string(item.get("host_label") or item.get("ip") or safe_id),
        details={"protocol": _string(item.get("protocol"))},
    )
    return _profile_public_view(item)
