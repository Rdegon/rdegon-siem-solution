from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
from typing import Any
from urllib import error as url_error
from urllib import parse as url_parse
from urllib import request as url_request
from uuid import uuid4

from .secret_runtime import resolve_secret_value


_DEFAULT_TIMEOUT = 12.0
_CAPABILITIES = (
    "inbounds.read",
    "inbounds.create",
    "inbounds.update",
    "inbounds.delete",
    "clients.create",
    "clients.update",
    "clients.delete",
    "clients.profile",
    "traffic.reset",
    "traffic.read",
    "online.read",
)
_MONITORING_CAPABILITIES = ("inbounds.read", "traffic.read", "online.read")
_MONITORING_INBOUND_FIELDS = (
    "id",
    "remark",
    "enable",
    "protocol",
    "port",
    "up",
    "down",
    "total",
    "expiry_time",
    "protected",
    "managed_by_sentinel",
)
_PUBLIC_CLIENT_FIELDS = (
    "email",
    "enable",
    "flow",
    "limitIp",
    "totalGB",
    "expiryTime",
    "traffic",
)
_MANAGEMENT_CLIENT_FIELDS = (*_PUBLIC_CLIENT_FIELDS, "tgId", "reset")


class XuiControllerError(RuntimeError):
    pass


def _validate_base_url(base_url: str) -> None:
    try:
        parsed = url_parse.urlparse(base_url)
    except ValueError as exc:
        raise XuiControllerError("VLESS controller URL is invalid") from exc
    if parsed.scheme != "http" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise XuiControllerError("VLESS controller URL must be an HTTP loopback URL without credentials or query parameters")
    if parsed.hostname.lower() != "localhost":
        try:
            if not ipaddress.ip_address(parsed.hostname).is_loopback:
                raise XuiControllerError("VLESS controller URL must remain loopback-only")
        except ValueError as exc:
            raise XuiControllerError("VLESS controller URL must remain loopback-only") from exc


def _settings() -> tuple[str, str, float]:
    base_url = str(os.getenv("SIEM_VLESS_CONTROLLER_URL") or "").strip().rstrip("/")
    token, _, _ = resolve_secret_value(
        "SIEM_VLESS_CONTROLLER_TOKEN",
        explicit_value=str(os.getenv("SIEM_VLESS_CONTROLLER_TOKEN") or ""),
    )
    try:
        timeout = max(2.0, min(float(os.getenv("SIEM_VLESS_CONTROLLER_TIMEOUT") or _DEFAULT_TIMEOUT), 60.0))
    except ValueError:
        timeout = _DEFAULT_TIMEOUT
    return base_url, str(token or "").strip(), timeout


def controller_configured() -> bool:
    base_url, token, _ = _settings()
    return bool(base_url and token)


def client_fingerprint(client_id: str) -> str:
    """Create an opaque, token-bound reference without exposing a VLESS UUID."""
    _, token, _ = _settings()
    if not token:
        raise XuiControllerError("VLESS controller token is not configured")
    return _client_fingerprint_with_token(client_id, token)


def _client_fingerprint_with_token(client_id: str, token: str) -> str:
    digest = hmac.new(token.encode("utf-8"), str(client_id).encode("utf-8"), hashlib.sha256).hexdigest()
    return f"client-{digest[:24]}"


def audit_fingerprint(value: str) -> str:
    _, token, _ = _settings()
    if not token:
        raise XuiControllerError("VLESS controller token is not configured")
    digest = hmac.new(token.encode("utf-8"), f"audit:{value}".encode("utf-8"), hashlib.sha256).hexdigest()
    return f"fp-{digest[:24]}"


def _request(path: str, *, method: str = "GET", payload: dict[str, Any] | None = None) -> dict[str, Any]:
    base_url, token, timeout = _settings()
    if not base_url or not token:
        raise XuiControllerError("VLESS controller is not configured")
    _validate_base_url(base_url)
    request_id = uuid4().hex
    data = None if payload is None else json.dumps(payload, ensure_ascii=False).encode("utf-8")
    request = url_request.Request(
        f"{base_url}{path}",
        method=method,
        data=data,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Request-ID": request_id,
        },
    )
    try:
        with url_request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - operator-controlled endpoint
            body = response.read().decode("utf-8")
    except url_error.HTTPError as exc:
        try:
            error_payload = json.loads(exc.read().decode("utf-8"))
            detail = error_payload.get("error")
            remote_request_id = error_payload.get("request_id")
        except (json.JSONDecodeError, UnicodeDecodeError):
            detail = ""
            remote_request_id = ""
        suffix = f" (request {remote_request_id})" if remote_request_id else ""
        raise XuiControllerError(f"{str(detail or f'VLESS controller returned HTTP {exc.code}')[:450]}{suffix}") from exc
    except (OSError, url_error.URLError) as exc:
        raise XuiControllerError(f"VLESS controller is unreachable: {str(exc)[:300]}") from exc
    try:
        result = json.loads(body or "{}")
    except json.JSONDecodeError as exc:
        raise XuiControllerError("VLESS controller returned invalid JSON") from exc
    if not isinstance(result, dict):
        raise XuiControllerError("VLESS controller returned an invalid response")
    if result.get("success") is False:
        raise XuiControllerError(str(result.get("error") or result.get("message") or "3x-ui operation failed")[:500])
    return result


def _unavailable_state(*, configured: bool, issue: str) -> dict[str, Any]:
    return {
        "configured": configured,
        "status": "degraded" if configured else "unavailable",
        "capabilities": [],
        "issue": issue,
        "inbounds": [],
        "clients": [],
        "client_count": 0,
        "online_count": 0,
    }


def _public_client(client: dict[str, Any], *, management: bool, token: str = "") -> dict[str, Any]:
    fields = _MANAGEMENT_CLIENT_FIELDS if management else _PUBLIC_CLIENT_FIELDS
    public = {key: client.get(key) for key in fields if key in client}
    if management:
        raw_id = str(client.get("id") or "")
        if raw_id:
            if not token:
                raise XuiControllerError("VLESS controller token is not configured")
            public["client_ref"] = _client_fingerprint_with_token(raw_id, token)
    return public


def _public_inbound(inbound: dict[str, Any], *, management: bool, token: str = "") -> dict[str, Any]:
    public = {key: inbound.get(key) for key in _MONITORING_INBOUND_FIELDS if key in inbound}
    raw_clients = inbound.get("clients") if isinstance(inbound.get("clients"), list) else []
    public["client_count"] = int(inbound.get("client_count") or len(raw_clients))
    if management:
        public["listen"] = str(inbound.get("listen") or "")
        public["stream_settings"] = dict(inbound.get("stream_settings") or {})
        public["sniffing"] = dict(inbound.get("sniffing") or {})
        public["clients"] = [
            _public_client(client, management=True, token=token)
            for client in raw_clients
            if isinstance(client, dict)
        ]
    return public


def _state(*, management: bool) -> dict[str, Any]:
    configured = controller_configured()
    if not configured:
        return _unavailable_state(
            configured=False,
            issue="Set SIEM_VLESS_CONTROLLER_URL and SIEM_VLESS_CONTROLLER_TOKEN on SIEM-WEB",
        )
    try:
        snapshot = _request("/state" if management else "/monitoring")
    except XuiControllerError as exc:
        state = _unavailable_state(configured=True, issue=str(exc))
        state["connectivity"] = {"controller": "unreachable", "panel": "unknown"}
        state["protection"] = {"state": "unknown"}
        return state
    _, token, _ = _settings()
    raw_inbounds = snapshot.get("inbounds") if isinstance(snapshot.get("inbounds"), list) else []
    inbounds = [
        _public_inbound(inbound, management=management, token=token)
        for inbound in raw_inbounds
        if isinstance(inbound, dict)
    ]
    clients: list[dict[str, Any]] = []
    if management:
        for inbound in inbounds:
            for client in inbound.get("clients", []) if isinstance(inbound.get("clients"), list) else []:
                if isinstance(client, dict):
                    clients.append({**client, "inbound_id": inbound.get("id"), "inbound_remark": inbound.get("remark")})
    client_count = sum(int(inbound.get("client_count") or 0) for inbound in inbounds)
    online = list(snapshot.get("online") or []) if management else []
    return {
        "configured": True,
        "status": str(snapshot.get("status") or "active"),
        "version": str(snapshot.get("version") or ""),
        "generated_at": snapshot.get("generated_at"),
        "capabilities": list(snapshot.get("capabilities") or _CAPABILITIES) if management else list(_MONITORING_CAPABILITIES),
        "issue": str(snapshot.get("issue") or ""),
        "inbounds": inbounds,
        "clients": clients,
        "client_count": client_count,
        "online": online,
        "online_count": int(snapshot.get("online_count") or len(online)),
        "traffic": dict(snapshot.get("traffic") or {}),
        "connectivity": dict(snapshot.get("connectivity") or {}),
        "protection": dict(snapshot.get("protection") or {}),
    }


def xui_state() -> dict[str, Any]:
    """Return the credential-free monitoring DTO."""
    return _state(management=False)


def xui_management_state() -> dict[str, Any]:
    return _state(management=True)


def _resolve_client_id(inbound_id: int, client_ref: str) -> str:
    expected_ref = str(client_ref or "").strip()
    if not expected_ref.startswith("client-") or len(expected_ref) != 31:
        raise ValueError("Invalid VLESS client reference")
    _, token, _ = _settings()
    if not token:
        raise XuiControllerError("VLESS controller token is not configured")
    snapshot = _request("/state")
    for inbound in snapshot.get("inbounds", []) if isinstance(snapshot.get("inbounds"), list) else []:
        if not isinstance(inbound, dict) or int(inbound.get("id") or 0) != int(inbound_id):
            continue
        for client in inbound.get("clients", []) if isinstance(inbound.get("clients"), list) else []:
            if isinstance(client, dict):
                raw_id = str(client.get("id") or "")
                if raw_id and hmac.compare_digest(_client_fingerprint_with_token(raw_id, token), expected_ref):
                    return raw_id
    raise ValueError("VLESS client reference was not found in the requested inbound")


def _public_client_mutation(result: dict[str, Any]) -> dict[str, Any]:
    public = dict(result)
    client = public.get("client")
    if isinstance(client, dict):
        _, token, _ = _settings()
        public["client"] = _public_client(client, management=True, token=token)
    return public


def create_inbound(payload: dict[str, Any]) -> dict[str, Any]:
    return _request("/inbounds", method="POST", payload=payload)


def update_inbound(inbound_id: int, payload: dict[str, Any]) -> dict[str, Any]:
    return _request(f"/inbounds/{int(inbound_id)}", method="PUT", payload=payload)


def delete_inbound(inbound_id: int) -> dict[str, Any]:
    return _request(f"/inbounds/{int(inbound_id)}", method="DELETE")


def create_client(inbound_id: int, payload: dict[str, Any]) -> dict[str, Any]:
    safe_payload = dict(payload or {})
    safe_payload.pop("id", None)
    return _public_client_mutation(
        _request(f"/inbounds/{int(inbound_id)}/clients", method="POST", payload=safe_payload)
    )


def update_client(inbound_id: int, client_ref: str, payload: dict[str, Any]) -> dict[str, Any]:
    safe_id = url_parse.quote(_resolve_client_id(inbound_id, client_ref), safe="")
    return _public_client_mutation(
        _request(f"/inbounds/{int(inbound_id)}/clients/{safe_id}", method="PUT", payload=payload)
    )


def delete_client(inbound_id: int, client_ref: str) -> dict[str, Any]:
    safe_id = url_parse.quote(_resolve_client_id(inbound_id, client_ref), safe="")
    return _request(f"/inbounds/{int(inbound_id)}/clients/{safe_id}", method="DELETE")


def client_profile(inbound_id: int, client_ref: str) -> dict[str, Any]:
    safe_id = url_parse.quote(_resolve_client_id(inbound_id, client_ref), safe="")
    return _request(f"/inbounds/{int(inbound_id)}/clients/{safe_id}/profile")


def reset_client_traffic(inbound_id: int, client_ref: str) -> dict[str, Any]:
    safe_id = url_parse.quote(_resolve_client_id(inbound_id, client_ref), safe="")
    return _request(f"/inbounds/{int(inbound_id)}/clients/{safe_id}/reset-traffic", method="POST", payload={})


def reset_inbound_traffic(inbound_id: int) -> dict[str, Any]:
    return _request(f"/inbounds/{int(inbound_id)}/reset-traffic", method="POST", payload={})
