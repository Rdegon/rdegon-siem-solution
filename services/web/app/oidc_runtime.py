from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import ssl
import time
import urllib.parse
import urllib.request
from typing import Any

try:
    from .secret_runtime import resolve_secret_value
except ImportError:  # pragma: no cover - local test fallback
    from secret_runtime import resolve_secret_value  # type: ignore[no-redef]


def _string(value: Any) -> str:
    return str(value or "").strip()


def _json_env(name: str) -> dict[str, Any]:
    raw = _string(os.getenv(name))
    if not raw:
        return {}
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    return payload if isinstance(payload, dict) else {}


def oidc_enabled() -> bool:
    return _string(os.getenv("SIEM_OIDC_ENABLED", "0")).lower() in {"1", "true", "yes", "on"}


def _issuer_url() -> str:
    return _string(os.getenv("SIEM_OIDC_ISSUER_URL"))


def _client_id() -> str:
    return _string(os.getenv("SIEM_OIDC_CLIENT_ID") or "siem-web")


def _client_secret() -> str:
    value, _, _ = resolve_secret_value("SIEM_OIDC_CLIENT_SECRET")
    return _string(value)


def _scope() -> str:
    return _string(os.getenv("SIEM_OIDC_SCOPE") or "openid profile email").replace(",", " ")


def _base_endpoint(default_suffix: str, explicit_name: str) -> str:
    explicit = _string(os.getenv(explicit_name))
    if explicit:
        return explicit
    issuer = _issuer_url().rstrip("/")
    if not issuer:
        return ""
    return f"{issuer}{default_suffix}"


def _tls_verify_enabled() -> bool:
    raw = _string(os.getenv("SIEM_OIDC_TLS_VERIFY") or "enabled").lower()
    return raw not in {"0", "false", "no", "off", "disabled"}


def _ssl_context() -> ssl.SSLContext | None:
    if _tls_verify_enabled():
        return None
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def authorize_endpoint() -> str:
    return _base_endpoint("/protocol/openid-connect/auth", "SIEM_OIDC_AUTHORIZE_URL")


def token_endpoint() -> str:
    return _base_endpoint("/protocol/openid-connect/token", "SIEM_OIDC_TOKEN_URL")


def userinfo_endpoint() -> str:
    return _base_endpoint("/protocol/openid-connect/userinfo", "SIEM_OIDC_USERINFO_URL")


def _discovery_endpoint() -> str:
    issuer = _issuer_url().rstrip("/")
    if not issuer:
        return ""
    return f"{issuer}/.well-known/openid-configuration"


def _probe_provider() -> tuple[bool, list[str]]:
    if not oidc_enabled():
        return False, []
    discovery = _discovery_endpoint()
    if not discovery:
        return False, ["oidc_discovery_missing"]
    try:
        request = urllib.request.Request(discovery, headers={"Accept": "application/json"}, method="GET")
        with urllib.request.urlopen(request, timeout=5, context=_ssl_context()) as response:
            raw = response.read().decode("utf-8", errors="replace")
        payload = json.loads(raw) if raw else {}
        if not isinstance(payload, dict):
            return False, ["oidc_discovery_invalid"]
        issuer = _string(payload.get("issuer"))
        if issuer and issuer.rstrip("/") != _issuer_url().rstrip("/"):
            return False, ["oidc_discovery_issuer_mismatch"]
        return True, []
    except Exception as exc:  # noqa: BLE001
        return False, [f"oidc_provider_unreachable:{exc}"]


def end_session_endpoint() -> str:
    return _base_endpoint("/protocol/openid-connect/logout", "SIEM_OIDC_END_SESSION_URL")


_PROVIDER_STATUS_CACHE: dict[str, Any] | None = None
_PROVIDER_STATUS_CACHE_TS = 0.0


def _provider_status_cache_ttl_seconds() -> int:
    raw = _string(os.getenv("SIEM_OIDC_STATUS_CACHE_SECONDS") or "30")
    try:
        ttl = int(raw)
    except ValueError:
        ttl = 30
    return max(0, ttl)


def invalidate_provider_status_cache() -> None:
    global _PROVIDER_STATUS_CACHE, _PROVIDER_STATUS_CACHE_TS
    _PROVIDER_STATUS_CACHE = None
    _PROVIDER_STATUS_CACHE_TS = 0.0


def _build_provider_status() -> dict[str, Any]:
    enabled = oidc_enabled()
    issuer = _issuer_url()
    client_id = _client_id()
    config_ok = all((issuer, client_id, authorize_endpoint(), token_endpoint()))
    issues: list[str] = []
    if enabled and not config_ok:
        issues.append("oidc_config_incomplete")
    if enabled and not _client_secret():
        issues.append("oidc_client_secret_missing")
    provider_reachable = False
    if enabled and config_ok:
        provider_reachable, probe_issues = _probe_provider()
        issues.extend(probe_issues)
    return {
        "id": "enterprise-oidc",
        "title": "Enterprise SSO",
        "kind": "oidc",
        "enabled": enabled,
        "healthy": enabled and config_ok and provider_reachable and not issues,
        "issuer": issuer,
        "authorize_url": authorize_endpoint(),
        "token_url": token_endpoint(),
        "userinfo_url": userinfo_endpoint(),
        "client_id": client_id,
        "scope": _scope(),
        "discovery_url": _discovery_endpoint(),
        "provider_reachable": provider_reachable,
        "issues": issues,
    }


def provider_status(*, force_refresh: bool = False) -> dict[str, Any]:
    global _PROVIDER_STATUS_CACHE, _PROVIDER_STATUS_CACHE_TS
    ttl = _provider_status_cache_ttl_seconds()
    now = time.monotonic()
    if not force_refresh and ttl > 0 and _PROVIDER_STATUS_CACHE is not None:
        if now - _PROVIDER_STATUS_CACHE_TS < ttl:
            return dict(_PROVIDER_STATUS_CACHE)
    payload = _build_provider_status()
    if ttl > 0:
        _PROVIDER_STATUS_CACHE = dict(payload)
        _PROVIDER_STATUS_CACHE_TS = now
    else:
        invalidate_provider_status_cache()
    return payload


def providers_inventory(status: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    return [
        dict(status or provider_status()),
        {
            "id": "break-glass-local",
            "title": "Break-glass local login",
            "kind": "local",
            "enabled": True,
            "healthy": True,
            "issues": [],
        },
    ]


def _state_secret() -> str:
    fallback = _string(os.getenv("SIEM_JWT_SECRET"))
    value, _, _ = resolve_secret_value("SIEM_JWT_SECRET", explicit_value=fallback)
    return _string(value or fallback or "siem-oidc-state")


def _sign_state(payload: dict[str, Any]) -> str:
    body = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
    signature = hmac.new(_state_secret().encode("utf-8"), body, hashlib.sha256).hexdigest()
    token = base64.urlsafe_b64encode(body).decode("ascii").rstrip("=")
    return f"{token}.{signature}"


def _decode_state(token: str) -> dict[str, Any]:
    text = _string(token)
    if "." not in text:
        raise ValueError("oidc_state_invalid")
    encoded, signature = text.rsplit(".", 1)
    padded = encoded + "=" * (-len(encoded) % 4)
    body = base64.urlsafe_b64decode(padded.encode("ascii"))
    expected = hmac.new(_state_secret().encode("utf-8"), body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected):
        raise ValueError("oidc_state_signature_invalid")
    payload = json.loads(body.decode("utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("oidc_state_invalid_payload")
    expires_epoch = int(payload.get("expires_epoch") or 0)
    if expires_epoch and expires_epoch < int(time.time()):
        raise ValueError("oidc_state_expired")
    return payload


def build_authorize_redirect(*, redirect_uri: str, next_path: str) -> tuple[str, str]:
    if not oidc_enabled():
        raise RuntimeError("OIDC is disabled")
    state_payload = {
        "nonce": secrets.token_urlsafe(24),
        "next_path": _string(next_path) or "/app",
        "created_epoch": int(time.time()),
        "expires_epoch": int(time.time()) + 600,
    }
    signed_state = _sign_state(state_payload)
    params = {
        "client_id": _client_id(),
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": _scope(),
        "state": signed_state,
    }
    return f"{authorize_endpoint()}?{urllib.parse.urlencode(params)}", signed_state


def _post_form(url: str, payload: dict[str, str]) -> dict[str, Any]:
    body = urllib.parse.urlencode(payload).encode("utf-8")
    request = urllib.request.Request(url, data=body, headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"}, method="POST")
    with urllib.request.urlopen(request, timeout=10, context=_ssl_context()) as response:
        raw = response.read().decode("utf-8", errors="replace")
    parsed = json.loads(raw) if raw else {}
    return parsed if isinstance(parsed, dict) else {}


def _get_json(url: str, *, access_token: str = "") -> dict[str, Any]:
    headers = {"Accept": "application/json"}
    if access_token:
        headers["Authorization"] = f"Bearer {access_token}"
    request = urllib.request.Request(url, headers=headers, method="GET")
    with urllib.request.urlopen(request, timeout=10, context=_ssl_context()) as response:
        raw = response.read().decode("utf-8", errors="replace")
    parsed = json.loads(raw) if raw else {}
    return parsed if isinstance(parsed, dict) else {}


def _decode_jwt_payload(token: str) -> dict[str, Any]:
    parts = _string(token).split(".")
    if len(parts) < 2:
        return {}
    padded = parts[1] + "=" * (-len(parts[1]) % 4)
    try:
        payload = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8"))
    except Exception:  # noqa: BLE001
        return {}
    return payload if isinstance(payload, dict) else {}


def _claim_groups(claims: dict[str, Any]) -> list[str]:
    groups: list[str] = []
    for raw in (claims.get("groups") or []):
        value = _string(raw)
        if value:
            groups.append(value)
    realm_access = dict(claims.get("realm_access") or {})
    for raw in (realm_access.get("roles") or []):
        value = _string(raw)
        if value:
            groups.append(value)
    resource_access = dict(claims.get("resource_access") or {})
    client_access = dict(resource_access.get(_client_id()) or {})
    for raw in (client_access.get("roles") or []):
        value = _string(raw)
        if value:
            groups.append(value)
    deduped: list[str] = []
    seen: set[str] = set()
    for item in groups:
        key = item.lower()
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped


def _map_groups_to_role(groups: list[str]) -> str:
    mapping = {str(key).strip().lower(): _string(value).lower() for key, value in _json_env("SIEM_OIDC_GROUP_ROLE_MAP_JSON").items()}
    if not mapping:
        mapping = {
            "siem-admin": "admin",
            "siem-analyst": "analyst",
            "soc-admin": "admin",
            "soc-analyst": "analyst",
            "viewer": "viewer",
        }
    for group in groups:
        role = mapping.get(group.lower())
        if role in {"admin", "analyst", "viewer"}:
            return role
    return _string(os.getenv("SIEM_OIDC_DEFAULT_ROLE") or "viewer").lower() or "viewer"


def finalize_callback(*, code: str, state: str, cookie_state: str, redirect_uri: str) -> dict[str, Any]:
    if _string(state) != _string(cookie_state):
        raise ValueError("oidc_state_mismatch")
    state_payload = _decode_state(state)
    token_payload = _post_form(
        token_endpoint(),
        {
            "grant_type": "authorization_code",
            "code": _string(code),
            "redirect_uri": redirect_uri,
            "client_id": _client_id(),
            "client_secret": _client_secret(),
        },
    )
    access_token = _string(token_payload.get("access_token"))
    id_token = _string(token_payload.get("id_token"))
    claims = _get_json(userinfo_endpoint(), access_token=access_token) if userinfo_endpoint() and access_token else {}
    if not claims and id_token:
        claims = _decode_jwt_payload(id_token)
    username = (
        _string(claims.get("preferred_username"))
        or _string(claims.get("email"))
        or _string(claims.get("name"))
        or _string(claims.get("sub"))
        or "oidc-user"
    )
    groups = _claim_groups(claims)
    session_expires_ts = ""
    id_token_claims = _decode_jwt_payload(id_token) if id_token else {}
    if id_token_claims.get("exp"):
        session_expires_ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(int(id_token_claims["exp"])))
    return {
        "username": username,
        "role": _map_groups_to_role(groups),
        "groups": groups,
        "issuer": _issuer_url(),
        "session_expires_ts": session_expires_ts,
        "next_path": _string(state_payload.get("next_path")) or "/app",
        "subject": _string(claims.get("sub") or username),
        "email": _string(claims.get("email")),
    }
