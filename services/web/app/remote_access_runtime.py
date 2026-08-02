from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
from threading import RLock
from typing import Any
from urllib import error as url_error
from urllib import request as url_request
from uuid import uuid4


_LOCK = RLock()
_PROFILE_FILE = Path(os.getenv("SIEM_REMOTE_ACCESS_PROFILE_FILE", "/opt/siem/runtime-docs/remote_access_profiles.json"))
_ROUTE_PRESETS: dict[str, list[str]] = {
    "siem-ingest-only": ["192.168.3.102/32"],
    "siem-ingest-and-web": ["192.168.3.102/32", "10.20.10.0/24"],
    "siem-core-admin": ["10.20.10.0/24", "192.168.3.102/32"],
    "siem-full-lab": ["10.20.10.0/24", "10.20.20.0/24", "10.20.30.0/24", "10.20.40.0/24", "192.168.3.0/24"],
}


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _load() -> list[dict[str, Any]]:
    if not _PROFILE_FILE.exists():
        return []
    try:
        payload = json.loads(_PROFILE_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    return [dict(item) for item in payload if isinstance(item, dict)] if isinstance(payload, list) else []


def _save(items: list[dict[str, Any]]) -> None:
    _PROFILE_FILE.parent.mkdir(parents=True, exist_ok=True)
    temporary = _PROFILE_FILE.with_suffix(".tmp")
    temporary.write_text(json.dumps(items, ensure_ascii=False, indent=2), encoding="utf-8")
    temporary.replace(_PROFILE_FILE)


def _controller(provider: str) -> dict[str, Any]:
    prefix = "SIEM_OPENVPN" if provider == "openvpn" else "SIEM_VLESS"
    url = str(os.getenv(f"{prefix}_CONTROLLER_URL") or "").rstrip("/")
    token = str(os.getenv(f"{prefix}_CONTROLLER_TOKEN") or "")
    return {
        "provider": provider,
        "configured": bool(url and token),
        "url_configured": bool(url),
        "credential_configured": bool(token),
        "mode": "managed" if url and token else "profile_preparation",
    }


def _activate(provider: str, payload: dict[str, Any]) -> dict[str, Any]:
    prefix = "SIEM_OPENVPN" if provider == "openvpn" else "SIEM_VLESS"
    base_url = str(os.getenv(f"{prefix}_CONTROLLER_URL") or "").rstrip("/")
    token = str(os.getenv(f"{prefix}_CONTROLLER_TOKEN") or "")
    if not base_url or not token:
        return {"status": "prepared", "issue": f"{provider} controller is not configured on the SIEM Web node"}
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = url_request.Request(
        f"{base_url}/profiles",
        data=body,
        method="POST",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    try:
        with url_request.urlopen(req, timeout=12) as response:  # noqa: S310 - endpoint is operator-configured
            result = json.loads(response.read().decode("utf-8") or "{}")
    except (OSError, url_error.URLError, json.JSONDecodeError) as exc:
        return {"status": "failed", "issue": f"Controller activation failed: {str(exc)[:300]}"}
    return {"status": str(result.get("status") or "active"), "controller_id": str(result.get("id") or ""), "download_ready": bool(result.get("download_ready", True))}


def remote_access_state() -> dict[str, Any]:
    with _LOCK:
        profiles = _load()
    controllers = [_controller("openvpn"), _controller("vless")]
    issues = [f"{item['provider']} controller credentials are not configured" for item in controllers if not item["configured"]]
    return {
        "generated_at": _now(),
        "profiles": profiles,
        "route_presets": [{"id": key, "routes": value} for key, value in _ROUTE_PRESETS.items()],
        "controllers": controllers,
        "issues": issues,
    }


def create_remote_access_profile(payload: dict[str, Any], *, actor: str) -> dict[str, Any]:
    provider = str(payload.get("provider") or "").strip().lower()
    name = str(payload.get("name") or "").strip()
    preset = str(payload.get("route_preset") or "siem-core-admin").strip()
    if provider not in {"openvpn", "vless"}:
        raise ValueError("Provider must be openvpn or vless")
    if not name:
        raise ValueError("Profile name is required")
    if preset not in _ROUTE_PRESETS:
        raise ValueError("Unknown route preset")
    public_options = {
        "endpoint": str(payload.get("endpoint") or "").strip(),
        "server_name": str(payload.get("server_name") or "").strip(),
        "transport": str(payload.get("transport") or ("tcp" if provider == "openvpn" else "ws")).strip(),
        "credential_ref": str(payload.get("credential_ref") or "").strip(),
    }
    activation = _activate(provider, {"name": name, "route_preset": preset, "routes": _ROUTE_PRESETS[preset], **public_options})
    record = {
        "id": f"remote-{uuid4().hex[:12]}",
        "name": name,
        "provider": provider,
        "route_preset": preset,
        "routes": list(_ROUTE_PRESETS[preset]),
        "status": activation["status"],
        "activation": activation,
        "configuration": public_options,
        "created_at": _now(),
        "created_by": actor,
    }
    with _LOCK:
        items = _load()
        items.append(record)
        _save(items)
    return record


def delete_remote_access_profile(profile_id: str) -> dict[str, Any]:
    with _LOCK:
        items = _load()
        found = next((item for item in items if str(item.get("id")) == profile_id), None)
        if not found:
            raise KeyError(profile_id)
        _save([item for item in items if str(item.get("id")) != profile_id])
    return {"deleted": True, "id": profile_id}
