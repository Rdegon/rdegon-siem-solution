from __future__ import annotations

import json
import os
from typing import Any
from urllib import error as url_error
from urllib import parse as url_parse
from urllib import request as url_request

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


class XuiControllerError(RuntimeError):
    pass


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


def _request(path: str, *, method: str = "GET", payload: dict[str, Any] | None = None) -> dict[str, Any]:
    base_url, token, timeout = _settings()
    if not base_url or not token:
        raise XuiControllerError("VLESS controller is not configured")
    data = None if payload is None else json.dumps(payload, ensure_ascii=False).encode("utf-8")
    request = url_request.Request(
        f"{base_url}{path}",
        method=method,
        data=data,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
    )
    try:
        with url_request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - operator-controlled endpoint
            body = response.read().decode("utf-8")
    except url_error.HTTPError as exc:
        try:
            detail = json.loads(exc.read().decode("utf-8")).get("error")
        except (json.JSONDecodeError, UnicodeDecodeError):
            detail = ""
        raise XuiControllerError(str(detail or f"VLESS controller returned HTTP {exc.code}")[:500]) from exc
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


def xui_state() -> dict[str, Any]:
    configured = controller_configured()
    if not configured:
        return {
            "configured": False,
            "status": "unavailable",
            "capabilities": [],
            "issue": "Set SIEM_VLESS_CONTROLLER_URL and SIEM_VLESS_CONTROLLER_TOKEN on SIEM-WEB",
            "inbounds": [],
            "clients": [],
        }
    try:
        health = _request("/health")
        inventory = _request("/inbounds")
    except XuiControllerError as exc:
        return {
            "configured": True,
            "status": "degraded",
            "capabilities": list(_CAPABILITIES),
            "issue": str(exc),
            "inbounds": [],
            "clients": [],
        }
    inbounds = inventory.get("inbounds") if isinstance(inventory.get("inbounds"), list) else []
    clients: list[dict[str, Any]] = []
    for inbound in inbounds:
        if not isinstance(inbound, dict):
            continue
        for client in inbound.get("clients", []) if isinstance(inbound.get("clients"), list) else []:
            if isinstance(client, dict):
                clients.append({**client, "inbound_id": inbound.get("id"), "inbound_remark": inbound.get("remark")})
    return {
        "configured": True,
        "status": str(health.get("status") or "active"),
        "version": str(health.get("version") or ""),
        "generated_at": health.get("generated_at"),
        "capabilities": list(health.get("capabilities") or _CAPABILITIES),
        "issue": str(health.get("issue") or ""),
        "inbounds": inbounds,
        "clients": clients,
        "online": list(inventory.get("online") or []),
        "traffic": dict(inventory.get("traffic") or {}),
    }


def create_inbound(payload: dict[str, Any]) -> dict[str, Any]:
    return _request("/inbounds", method="POST", payload=payload)


def update_inbound(inbound_id: int, payload: dict[str, Any]) -> dict[str, Any]:
    return _request(f"/inbounds/{int(inbound_id)}", method="PUT", payload=payload)


def delete_inbound(inbound_id: int) -> dict[str, Any]:
    return _request(f"/inbounds/{int(inbound_id)}", method="DELETE")


def create_client(inbound_id: int, payload: dict[str, Any]) -> dict[str, Any]:
    return _request(f"/inbounds/{int(inbound_id)}/clients", method="POST", payload=payload)


def update_client(inbound_id: int, client_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    safe_id = url_parse.quote(client_id, safe="")
    return _request(f"/inbounds/{int(inbound_id)}/clients/{safe_id}", method="PUT", payload=payload)


def delete_client(inbound_id: int, client_id: str) -> dict[str, Any]:
    safe_id = url_parse.quote(client_id, safe="")
    return _request(f"/inbounds/{int(inbound_id)}/clients/{safe_id}", method="DELETE")


def client_profile(inbound_id: int, client_id: str) -> dict[str, Any]:
    safe_id = url_parse.quote(client_id, safe="")
    return _request(f"/inbounds/{int(inbound_id)}/clients/{safe_id}/profile")


def reset_client_traffic(inbound_id: int, client_id: str) -> dict[str, Any]:
    safe_id = url_parse.quote(client_id, safe="")
    return _request(f"/inbounds/{int(inbound_id)}/clients/{safe_id}/reset-traffic", method="POST", payload={})


def reset_inbound_traffic(inbound_id: int) -> dict[str, Any]:
    return _request(f"/inbounds/{int(inbound_id)}/reset-traffic", method="POST", payload={})
