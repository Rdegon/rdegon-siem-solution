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


_TOKEN_LOCK = threading.RLock()
_TOKEN_CACHE: dict[str, Any] = {"token": "", "expires_epoch": 0.0}


def _string(value: Any) -> str:
    return str(value or "").strip()


def _extract_env_reference_name(value: str) -> str:
    text = _string(value)
    if not text:
        return ""
    if text.startswith("${") and text.endswith("}"):
        return text[2:-1].strip()
    if text.startswith("env://"):
        return text[6:].strip()
    if text.startswith("ref://"):
        return text[6:].strip()
    return ""


def _vault_addr() -> str:
    return _string(os.getenv("SIEM_VAULT_ADDR") or os.getenv("VAULT_ADDR") or "http://127.0.0.1:8200")


def _vault_timeout_seconds() -> float:
    try:
        timeout = float(os.getenv("SIEM_VAULT_TIMEOUT_SECONDS", "5") or "5")
    except ValueError:
        timeout = 5.0
    return max(1.0, min(30.0, timeout))


def _vault_verify_tls() -> bool:
    return _string(os.getenv("SIEM_VAULT_TLS_VERIFY", "1")).lower() not in {"0", "false", "no", "off"}


def _vault_ca_file() -> str:
    return _string(os.getenv("SIEM_VAULT_CA_FILE"))


def _vault_ssl_context():
    addr = _vault_addr()
    if not addr.startswith("https://"):
        return None
    if not _vault_verify_tls():
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context
    ca_file = _vault_ca_file()
    return ssl.create_default_context(cafile=ca_file or None)


def _resolve_inline_reference(value: str) -> str:
    ref_name = _extract_env_reference_name(value)
    if ref_name:
        return _string(os.getenv(ref_name))
    return value


def _vault_auth_method() -> str:
    explicit = _string(os.getenv("SIEM_VAULT_AUTH_METHOD") or os.getenv("VAULT_AUTH_METHOD")).lower()
    if explicit in {"token", "approle"}:
        return explicit
    if _string(os.getenv("SIEM_VAULT_ROLE_ID") or os.getenv("VAULT_ROLE_ID")) and _string(
        os.getenv("SIEM_VAULT_SECRET_ID") or os.getenv("VAULT_SECRET_ID")
    ):
        return "approle"
    return "token"


def _vault_request(
    api_path: str,
    *,
    method: str = "GET",
    payload: dict[str, Any] | None = None,
    token: str = "",
) -> dict[str, Any]:
    base_url = _vault_addr().rstrip("/")
    url = f"{base_url}{api_path}"
    headers = {"Accept": "application/json"}
    body = None
    if payload is not None:
        headers["Content-Type"] = "application/json"
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    if token:
        headers["X-Vault-Token"] = token
    request = urllib.request.Request(url, data=body, headers=headers, method=method.upper())
    try:
        with urllib.request.urlopen(request, timeout=_vault_timeout_seconds(), context=_vault_ssl_context()) as response:
            raw = response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        try:
            payload_data = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            payload_data = {"errors": [raw or f"HTTP {exc.code}"]}
        message = "; ".join(str(item) for item in (payload_data.get("errors") or []) if str(item).strip()) or f"HTTP {exc.code}"
        raise RuntimeError(f"Vault request failed for {api_path}: {message}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Vault request failed for {api_path}: {exc.reason}") from exc
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Vault returned invalid JSON for {api_path}") from exc
    return parsed if isinstance(parsed, dict) else {}


def _vault_direct_token() -> str:
    for name in ("SIEM_VAULT_TOKEN", "VAULT_TOKEN"):
        value = _resolve_inline_reference(_string(os.getenv(name)))
        if value:
            return value
    return ""


def _vault_approle_credentials() -> tuple[str, str]:
    role_id = _resolve_inline_reference(_string(os.getenv("SIEM_VAULT_ROLE_ID") or os.getenv("VAULT_ROLE_ID")))
    secret_id = _resolve_inline_reference(_string(os.getenv("SIEM_VAULT_SECRET_ID") or os.getenv("VAULT_SECRET_ID")))
    return role_id, secret_id


def _vault_client_token() -> tuple[str, str]:
    method = _vault_auth_method()
    if method == "token":
        token = _vault_direct_token()
        return token, "token"
    with _TOKEN_LOCK:
        cached_token = _string(_TOKEN_CACHE.get("token"))
        cached_expiry = float(_TOKEN_CACHE.get("expires_epoch") or 0.0)
        if cached_token and cached_expiry > time.time() + 15:
            return cached_token, "approle_cache"
        role_id, secret_id = _vault_approle_credentials()
        if not role_id or not secret_id:
            return "", "approle_missing"
        payload = _vault_request("/v1/auth/approle/login", method="POST", payload={"role_id": role_id, "secret_id": secret_id})
        auth = dict(payload.get("auth") or {})
        token = _string(auth.get("client_token"))
        lease_duration = int(auth.get("lease_duration") or 300)
        if token:
            _TOKEN_CACHE["token"] = token
            _TOKEN_CACHE["expires_epoch"] = time.time() + max(30, lease_duration - 15)
        return token, "approle"


def _parse_vault_ref(ref: str) -> dict[str, str]:
    text = _string(ref)
    if not text.startswith("vault://"):
        raise ValueError(f"Unsupported Vault reference: {ref}")
    parsed = urllib.parse.urlsplit(text)
    raw_path = parsed.path.lstrip("/")
    if parsed.netloc:
        raw_path = f"{parsed.netloc}/{raw_path}" if raw_path else parsed.netloc
    parts = [part for part in raw_path.split("/") if part]
    if len(parts) < 2:
        raise ValueError(f"Vault reference must contain mount and path: {ref}")
    mount = parts[0]
    secret_path = "/".join(parts[1:])
    field = urllib.parse.parse_qs(parsed.query).get("field", [""])[0].strip()
    if not field and parsed.fragment:
        field = parsed.fragment.strip()
    if not field:
        field = "value"
    return {
        "mount": mount,
        "secret_path": secret_path,
        "field": field,
        "ref": text,
    }


def vault_kv_read(ref: str) -> tuple[str, dict[str, Any]]:
    spec = _parse_vault_ref(ref)
    token, auth_source = _vault_client_token()
    if not token:
        return "", {"source": auth_source or "vault_auth_missing", "ref": ref, "status": "missing"}
    payload = _vault_request(f"/v1/{spec['mount']}/data/{spec['secret_path']}", token=token)
    data = dict(dict(payload.get("data") or {}).get("data") or {})
    metadata = dict(dict(payload.get("data") or {}).get("metadata") or {})
    value = _string(data.get(spec["field"]))
    return value, {
        "source": auth_source,
        "ref": spec["ref"],
        "mount": spec["mount"],
        "secret_path": spec["secret_path"],
        "field": spec["field"],
        "metadata": metadata,
        "status": "configured" if value else "missing",
    }


def vault_kv_write(ref: str, data: dict[str, Any]) -> dict[str, Any]:
    spec = _parse_vault_ref(ref)
    token, auth_source = _vault_client_token()
    if not token:
        raise RuntimeError(f"Vault write unavailable for {ref}: {auth_source or 'vault_auth_missing'}")
    payload = {
        "data": {
            str(key).strip(): _string(value)
            for key, value in dict(data or {}).items()
            if str(key).strip() and _string(value)
        }
    }
    if not payload["data"]:
        raise ValueError("Vault write requires at least one non-empty field")
    _vault_request(f"/v1/{spec['mount']}/data/{spec['secret_path']}", method="POST", payload=payload, token=token)
    return {
        "source": auth_source,
        "ref": spec["ref"],
        "mount": spec["mount"],
        "secret_path": spec["secret_path"],
        "fields": sorted(payload["data"].keys()),
        "status": "configured",
    }


def vault_runtime_status() -> dict[str, Any]:
    enabled = bool(_vault_addr())
    if not enabled:
        return {"enabled": False, "healthy": False, "configured": False, "issues": ["vault_addr_missing"]}
    try:
        health = _vault_request("/v1/sys/health?standbyok=true&perfstandbyok=true")
        token, auth_source = _vault_client_token()
        configured = bool(token)
        issues: list[str] = []
        if not configured:
            issues.append("vault_auth_unavailable")
        return {
            "enabled": True,
            "configured": configured,
            "healthy": True,
            "sealed": bool(health.get("sealed", False)),
            "initialized": bool(health.get("initialized", True)),
            "standby": bool(health.get("standby", False)),
            "version": _string(health.get("version")),
            "cluster_name": _string(health.get("cluster_name")),
            "cluster_id": _string(health.get("cluster_id")),
            "auth_method": _vault_auth_method(),
            "auth_source": auth_source,
            "addr": _vault_addr(),
            "issues": issues,
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "enabled": True,
            "configured": False,
            "healthy": False,
            "sealed": True,
            "initialized": False,
            "auth_method": _vault_auth_method(),
            "addr": _vault_addr(),
            "issues": [str(exc)],
        }


def resolve_secret_value(env_name: str, *, explicit_value: str = "") -> tuple[str, str, dict[str, Any]]:
    inline_value = _string(explicit_value)
    if inline_value:
        ref_name = _extract_env_reference_name(inline_value)
        if ref_name:
            value = _string(os.getenv(ref_name))
            return value, ref_name, {"status": "configured" if value else "missing", "reference_type": "env"}
        if inline_value.startswith("vault://"):
            value, details = vault_kv_read(inline_value)
            return value, inline_value, {**details, "reference_type": "vault"}
        return inline_value, "inline", {"status": "configured", "reference_type": "inline"}

    safe_env = _string(env_name)
    if not safe_env:
        return "", "", {"status": "missing"}
    ref_env = f"{safe_env}_REF"
    ref_value = _string(os.getenv(ref_env))
    if ref_value:
        ref_name = _extract_env_reference_name(ref_value)
        if ref_name:
            value = _string(os.getenv(ref_name))
            return value, ref_name, {"status": "configured" if value else "missing", "reference_type": "env", "reference_env": ref_env}
        if ref_value.startswith("vault://"):
            value, details = vault_kv_read(ref_value)
            return value, ref_value, {**details, "reference_type": "vault", "reference_env": ref_env}
        return _string(ref_value), ref_env, {"status": "configured", "reference_type": "literal_ref", "reference_env": ref_env}
    value = _string(os.getenv(safe_env))
    if value:
        ref_name = _extract_env_reference_name(value)
        if ref_name:
            resolved = _string(os.getenv(ref_name))
            return resolved, ref_name, {"status": "configured" if resolved else "missing", "reference_type": "env_inline", "env": safe_env}
        if value.startswith("vault://"):
            resolved, details = vault_kv_read(value)
            return resolved, value, {**details, "reference_type": "vault", "env": safe_env}
        return value, safe_env, {"status": "configured", "reference_type": "literal", "env": safe_env}
    return "", safe_env, {"status": "missing", "env": safe_env}


def describe_secret_env(env_name: str) -> dict[str, Any]:
    safe_env = _string(env_name)
    ref_env = f"{safe_env}_REF"
    ref_value = _string(os.getenv(ref_env))
    raw_value = _string(os.getenv(safe_env))
    if ref_value.startswith("vault://"):
        _, source, details = resolve_secret_value(safe_env)
        metadata = dict(details.get("metadata") or {})
        return {
            "status": "reference",
            "resolved_status": str(details.get("status") or "missing"),
            "source": ref_env,
            "reference_type": "vault",
            "vault_ref": source,
            "last_rotated_ts": _string(metadata.get("created_time")),
            "version": metadata.get("version"),
        }
    if raw_value.startswith("vault://"):
        _, source, details = resolve_secret_value(safe_env)
        metadata = dict(details.get("metadata") or {})
        return {
            "status": "reference",
            "resolved_status": str(details.get("status") or "missing"),
            "source": safe_env,
            "reference_type": "vault",
            "vault_ref": source,
            "last_rotated_ts": _string(metadata.get("created_time")),
            "version": metadata.get("version"),
        }
    if ref_value:
        return {"status": "reference", "source": ref_env, "reference_type": "env", "last_rotated_ts": ""}
    if raw_value.startswith("ref://") or raw_value.startswith("${") or raw_value.startswith("env://"):
        return {"status": "reference", "source": safe_env, "reference_type": "env", "last_rotated_ts": ""}
    if raw_value:
        return {"status": "configured", "source": safe_env, "reference_type": "literal", "last_rotated_ts": ""}
    return {"status": "missing", "source": safe_env, "reference_type": "", "last_rotated_ts": ""}


def resolve_runtime_object(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): resolve_runtime_object(item) for key, item in value.items()}
    if isinstance(value, list):
        return [resolve_runtime_object(item) for item in value]
    if not isinstance(value, str):
        return value
    text = _string(value)
    ref_name = _extract_env_reference_name(text)
    if ref_name:
        return _string(os.getenv(ref_name))
    if text.startswith("vault://"):
        resolved, _, _ = resolve_secret_value("", explicit_value=text)
        return resolved
    return value
