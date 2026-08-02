from __future__ import annotations

import base64
import binascii
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import socket
import subprocess
from threading import RLock
from typing import Any
from urllib import error as url_error
from urllib import request as url_request
from uuid import uuid4


_LOCK = RLock()
_PROFILE_FILE = Path(os.getenv("SIEM_REMOTE_ACCESS_PROFILE_FILE", "/opt/siem/runtime-docs/remote_access_profiles.json"))
_PROFILE_ARTIFACT_DIR = Path(os.getenv("SIEM_REMOTE_ACCESS_ARTIFACT_DIR", "/opt/siem/runtime-docs/remote-access"))
_LOCAL_OPENVPN_CONTROLLER = Path(os.getenv("SIEM_OPENVPN_LOCAL_CONTROLLER", "/usr/local/sbin/siem-vpn-profile-controller"))
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
    local_controller = provider == "openvpn" and _LOCAL_OPENVPN_CONTROLLER.is_file()
    return {
        "provider": provider,
        "configured": bool((url and token) or local_controller),
        "url_configured": bool(url),
        "credential_configured": bool(token),
        "local_controller": local_controller,
        "mode": "managed" if (url and token) or local_controller else "profile_preparation",
    }


def _service_state(unit: str) -> str:
    try:
        result = subprocess.run(
            ["systemctl", "is-active", unit],
            check=False,
            capture_output=True,
            text=True,
            timeout=2,
        )
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    return (result.stdout or "").strip() or "inactive"


def _interface_address(interface: str) -> str:
    try:
        result = subprocess.run(
            ["ip", "-j", "address", "show", interface],
            check=False,
            capture_output=True,
            text=True,
            timeout=2,
        )
        payload = json.loads(result.stdout or "[]")
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
        return ""
    for item in payload if isinstance(payload, list) else []:
        for address in item.get("addr_info", []):
            if address.get("family") == "inet":
                return str(address.get("local") or "")
    return ""


def _tcp_reachable(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=1):
            return True
    except OSError:
        return False


def _access_planes() -> list[dict[str, Any]]:
    openvpn_service = _service_state("openvpn-client@home-gateway")
    tunnel_service = _service_state("siem-jump-tunnels")
    tunnel_address = _interface_address("tun-home")
    jump_reachable = _tcp_reachable("10.66.66.1", 22)
    openvpn_active = (
        openvpn_service == "active"
        and tunnel_service == "active"
        and bool(tunnel_address)
        and jump_reachable
    )
    return [
        {
            "provider": "openvpn",
            "role": "remote_ingress",
            "status": "active" if openvpn_active else "degraded",
            "endpoint": "176.108.250.215:443/TCP",
            "interface": "tun-home",
            "address": tunnel_address,
            "service_state": openvpn_service,
            "tunnel_state": tunnel_service,
            "jump_host_reachable": jump_reachable,
            "managed_profile_issuance": _controller("openvpn")["configured"],
        },
        {
            "provider": "vless",
            "role": "outbound_egress",
            "status": "retired",
            "endpoint": "45.89.111.208",
            "interface": "",
            "address": "",
            "service_state": "not_deployed_for_remote_access",
            "tunnel_state": "not_applicable",
            "jump_host_reachable": False,
            "managed_profile_issuance": _controller("vless")["configured"],
        },
    ]


def _activate(provider: str, payload: dict[str, Any]) -> dict[str, Any]:
    if provider == "openvpn" and _LOCAL_OPENVPN_CONTROLLER.is_file():
        try:
            result = subprocess.run(
                [
                    "sudo",
                    "-n",
                    str(_LOCAL_OPENVPN_CONTROLLER),
                    "create",
                    str(payload["name"]),
                    str(payload["route_preset"]),
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=100,
            )
            response = json.loads(result.stdout or "{}")
        except (OSError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
            return {"status": "failed", "issue": f"Local OpenVPN controller failed: {str(exc)[:300]}"}
        if result.returncode or response.get("status") == "failed":
            return {"status": "failed", "issue": str(response.get("issue") or result.stderr or "OpenVPN controller failed")[:300]}
        return dict(response)
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
    access_planes = _access_planes()
    issues: list[str] = []
    if not controllers[0]["configured"]:
        issues.append("OpenVPN transport is monitored, but CA profile issuance is not connected to the SIEM controller")
    if not controllers[1]["configured"]:
        issues.append("VLESS is not deployed as remote ingress; the known endpoint was outbound egress only")
    return {
        "generated_at": _now(),
        "profiles": profiles,
        "route_presets": [{"id": key, "routes": value} for key, value in _ROUTE_PRESETS.items()],
        "controllers": controllers,
        "access_planes": access_planes,
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
        "endpoint": str(payload.get("endpoint") or ("176.108.250.215:443/TCP" if provider == "openvpn" else "")).strip(),
        "server_name": str(payload.get("server_name") or "").strip(),
        "transport": str(payload.get("transport") or ("tcp" if provider == "openvpn" else "ws")).strip(),
        "credential_ref": str(payload.get("credential_ref") or "").strip(),
    }
    record_id = f"remote-{uuid4().hex[:12]}"
    activation = _activate(provider, {"name": name, "route_preset": preset, "routes": _ROUTE_PRESETS[preset], **public_options})
    profile_b64 = str(activation.pop("profile_b64", "") or "")
    download_url = ""
    if profile_b64:
        try:
            profile_content = base64.b64decode(profile_b64, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise RuntimeError("OpenVPN controller returned an invalid profile") from exc
        if not profile_content.startswith(b"client\n") or b"<key>" not in profile_content:
            raise RuntimeError("OpenVPN controller returned an invalid profile")
        _PROFILE_ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
        artifact = _PROFILE_ARTIFACT_DIR / f"{record_id}.ovpn"
        artifact.write_bytes(profile_content)
        artifact.chmod(0o600)
        download_url = f"/api/security-services/vpn/remote-access/{record_id}/download"
    record = {
        "id": record_id,
        "name": name,
        "provider": provider,
        "route_preset": preset,
        "routes": list(_ROUTE_PRESETS[preset]),
        "status": activation["status"],
        "activation": activation,
        "download_url": download_url,
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
        controller_id = str((found.get("activation") or {}).get("controller_id") or "")
        if found.get("provider") == "openvpn" and controller_id and _LOCAL_OPENVPN_CONTROLLER.is_file():
            result = subprocess.run(
                ["sudo", "-n", str(_LOCAL_OPENVPN_CONTROLLER), "revoke", controller_id],
                check=False,
                capture_output=True,
                text=True,
                timeout=100,
            )
            if result.returncode:
                raise RuntimeError((result.stderr or result.stdout or "OpenVPN revocation failed")[:500])
        _save([item for item in items if str(item.get("id")) != profile_id])
        artifact = _PROFILE_ARTIFACT_DIR / f"{profile_id}.ovpn"
        artifact.unlink(missing_ok=True)
    return {"deleted": True, "id": profile_id}


def remote_access_profile_artifact(profile_id: str) -> tuple[Path, str]:
    with _LOCK:
        found = next((item for item in _load() if str(item.get("id")) == profile_id), None)
    if not found:
        raise KeyError(profile_id)
    artifact = _PROFILE_ARTIFACT_DIR / f"{profile_id}.ovpn"
    if not artifact.is_file() or not str(found.get("download_url") or ""):
        raise FileNotFoundError(profile_id)
    filename = f"{str(found.get('name') or profile_id)}.ovpn"
    return artifact, filename
