#!/usr/bin/env python3
from __future__ import annotations

import hmac
import hashlib
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import secrets
import socket
import subprocess
import tempfile
import threading
from datetime import datetime, timezone
from typing import Any
from urllib import error as url_error
from urllib import parse as url_parse
from urllib import request as url_request
from uuid import UUID, uuid4


PANEL_URL = str(os.getenv("XUI_PANEL_URL") or "http://127.0.0.1:2053").rstrip("/")
PANEL_USER = str(os.getenv("XUI_PANEL_USERNAME") or "")
PANEL_PASSWORD = str(os.getenv("XUI_PANEL_PASSWORD") or "")
CONTROLLER_TOKEN = str(os.getenv("SIEM_XUI_CONTROLLER_TOKEN") or "")
PUBLIC_HOST = str(os.getenv("XUI_PUBLIC_HOST") or "").strip()
LISTEN_HOST = str(os.getenv("SIEM_XUI_LISTEN_HOST") or "127.0.0.1")
LISTEN_PORT = int(os.getenv("SIEM_XUI_LISTEN_PORT") or "8787")
MAX_BODY_BYTES = max(1024, min(int(os.getenv("SIEM_XUI_MAX_BODY_BYTES") or str(256 * 1024)), 1024 * 1024))
MAX_CONCURRENT_REQUESTS = max(1, min(int(os.getenv("SIEM_XUI_MAX_CONCURRENT_REQUESTS") or "32"), 256))
REQUEST_TIMEOUT_SECONDS = max(1.0, min(float(os.getenv("SIEM_XUI_REQUEST_TIMEOUT_SECONDS") or "10"), 60.0))
STATE_PATH = Path(os.getenv("XUI_PROTECTION_STATE") or "/var/lib/siem-xui-controller/protection.json")
ALLOW_INBOUND_CREATE = str(os.getenv("XUI_ALLOW_INBOUND_CREATE") or "false").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}
PROTECTED_INBOUND_IDS = {
    int(value)
    for value in str(os.getenv("XUI_PROTECTED_INBOUND_IDS") or "").split(",")
    if value.strip().isdigit()
}
_COOKIE = ""
_STATE_LOCK = threading.RLock()
_PROTECTION_STATE: dict[str, Any] | None = None


class RequestBodyTooLarge(ValueError):
    pass


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _fingerprint(value: str) -> str:
    digest = hmac.new(
        CONTROLLER_TOKEN.encode("utf-8"),
        str(value).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return f"client-{digest[:24]}"


def _safe_log_path(value: str) -> str:
    path = url_parse.urlparse(str(value or "/")).path
    parts = path.split("/")
    for index, part in enumerate(parts[:-1]):
        if part == "clients" and parts[index + 1]:
            parts[index + 1] = _fingerprint(url_parse.unquote(parts[index + 1]))
    return "/".join(parts) or "/"


def _validate_config() -> None:
    parsed = url_parse.urlparse(PANEL_URL)
    if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise RuntimeError("XUI_PANEL_URL must be an HTTP loopback URL")
    if not PANEL_USER or not PANEL_PASSWORD or not CONTROLLER_TOKEN:
        raise RuntimeError("XUI panel credentials and controller token are required")


def _login() -> None:
    global _COOKIE
    payload = url_parse.urlencode({"username": PANEL_USER, "password": PANEL_PASSWORD}).encode("ascii")
    request = url_request.Request(f"{PANEL_URL}/login", data=payload, method="POST")
    with url_request.urlopen(request, timeout=8) as response:  # noqa: S310 - loopback is validated
        cookies = SimpleCookie()
        for header in response.headers.get_all("Set-Cookie", []):
            cookies.load(header)
        _COOKIE = "; ".join(f"{key}={morsel.value}" for key, morsel in cookies.items())
    if not _COOKIE:
        raise RuntimeError("3x-ui login did not return a session cookie")


def _panel(path: str, *, method: str = "GET", payload: dict[str, Any] | None = None) -> dict[str, Any]:
    global _COOKIE
    for attempt in range(2):
        if not _COOKIE:
            _login()
        data = None if payload is None else url_parse.urlencode(payload).encode("utf-8")
        request = url_request.Request(
            f"{PANEL_URL}{path}",
            data=data,
            method=method,
            headers={"Cookie": _COOKIE, "Content-Type": "application/x-www-form-urlencoded"},
        )
        try:
            with url_request.urlopen(request, timeout=12) as response:  # noqa: S310 - loopback is validated
                result = json.loads(response.read().decode("utf-8") or "{}")
        except url_error.HTTPError as exc:
            if exc.code in {HTTPStatus.UNAUTHORIZED, HTTPStatus.FORBIDDEN} and attempt == 0:
                _COOKIE = ""
                continue
            raise RuntimeError(f"3x-ui returned HTTP {exc.code}") from exc
        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"3x-ui request failed: {str(exc)[:300]}") from exc
        if not isinstance(result, dict):
            raise RuntimeError("3x-ui returned invalid JSON")
        if result.get("success") is False:
            raise RuntimeError(str(result.get("msg") or "3x-ui operation failed")[:500])
        return result
    raise RuntimeError("3x-ui authentication failed")


def _mutation_result(result: dict[str, Any]) -> dict[str, Any]:
    """Return only operation metadata; 3x-ui objects may contain private keys."""
    raw_object = result.get("obj")
    if isinstance(raw_object, dict):
        raw_object = raw_object.get("id")
    safe_id = raw_object if isinstance(raw_object, (int, str)) else ""
    return {
        "success": bool(result.get("success", True)),
        "message": str(result.get("msg") or "")[:300],
        "id": safe_id,
    }


def _json_object(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return dict(value)
    if not isinstance(value, str) or not value:
        return {}
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return {}
    return dict(parsed) if isinstance(parsed, dict) else {}


def _clients(inbound: dict[str, Any]) -> list[dict[str, Any]]:
    settings = _json_object(inbound.get("settings"))
    stats = {str(item.get("email") or ""): item for item in inbound.get("clientStats", []) if isinstance(item, dict)}
    result: list[dict[str, Any]] = []
    for client in settings.get("clients", []) if isinstance(settings.get("clients"), list) else []:
        if not isinstance(client, dict):
            continue
        email = str(client.get("email") or "")
        result.append({**client, "traffic": stats.get(email, {})})
    return result


def _public_stream_settings(value: Any) -> dict[str, Any]:
    stream = _json_object(value)
    reality = stream.get("realitySettings")
    if isinstance(reality, dict):
        safe_reality = dict(reality)
        private_key_present = bool(safe_reality.pop("privateKey", ""))
        safe_reality.pop("password", None)
        safe_reality["privateKeyConfigured"] = private_key_present
        stream["realitySettings"] = safe_reality
    return stream


def _normalize_inbound(item: dict[str, Any]) -> dict[str, Any]:
    inbound_id = int(item.get("id") or 0)
    return {
        "id": inbound_id,
        "remark": str(item.get("remark") or ""),
        "enable": bool(item.get("enable", True)),
        "protocol": str(item.get("protocol") or ""),
        "port": int(item.get("port") or 0),
        "listen": str(item.get("listen") or ""),
        "up": int(item.get("up") or 0),
        "down": int(item.get("down") or 0),
        "total": int(item.get("total") or 0),
        "expiry_time": int(item.get("expiryTime") or 0),
        "protected": inbound_id in _protected_ids(),
        "managed_by_sentinel": inbound_id in _managed_ids(),
        "settings": _json_object(item.get("settings")),
        "stream_settings": _public_stream_settings(item.get("streamSettings")),
        "sniffing": _json_object(item.get("sniffing")),
        "clients": _clients(item),
    }


def _raw_inventory() -> list[dict[str, Any]]:
    result = _panel("/panel/api/inbounds/list")
    rows = result.get("obj") if isinstance(result.get("obj"), list) else []
    return [item for item in rows if isinstance(item, dict)]


def _valid_ids(value: Any) -> set[int]:
    if not isinstance(value, list):
        return set()
    return {int(item) for item in value if isinstance(item, int) and item > 0}


def _write_protection_state(state: dict[str, Any]) -> None:
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary_name = tempfile.mkstemp(prefix=f".{STATE_PATH.name}.", dir=STATE_PATH.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            json.dump(state, stream, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, STATE_PATH)
    finally:
        temporary.unlink(missing_ok=True)


def _read_protection_state() -> dict[str, Any] | None:
    if not STATE_PATH.exists():
        return None
    if STATE_PATH.is_symlink() or not STATE_PATH.is_file():
        raise RuntimeError("3x-ui protection state must be a regular file")
    try:
        value = json.loads(STATE_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError("3x-ui protection state is unreadable") from exc
    if not isinstance(value, dict) or int(value.get("schema") or 0) != 1:
        raise RuntimeError("3x-ui protection state has an unsupported schema")
    baseline_ids = _valid_ids(value.get("baseline_inbound_ids"))
    managed_ids = _valid_ids(value.get("managed_inbound_ids"))
    if baseline_ids.intersection(managed_ids):
        raise RuntimeError("3x-ui protection state contains conflicting inbound ownership")
    return {
        "schema": 1,
        "created_at": str(value.get("created_at") or ""),
        "updated_at": str(value.get("updated_at") or ""),
        "baseline_inbound_ids": sorted(baseline_ids),
        "managed_inbound_ids": sorted(managed_ids),
    }


def _initialize_protection_state(rows: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    global _PROTECTION_STATE
    with _STATE_LOCK:
        if _PROTECTION_STATE is not None:
            return dict(_PROTECTION_STATE)
        state = _read_protection_state()
        if state is None:
            inventory = rows if rows is not None else _raw_inventory()
            baseline_ids = sorted(
                {int(row.get("id") or 0) for row in inventory if int(row.get("id") or 0) > 0}.union(PROTECTED_INBOUND_IDS)
            )
            now = _utc_now()
            state = {
                "schema": 1,
                "created_at": now,
                "updated_at": now,
                "baseline_inbound_ids": baseline_ids,
                "managed_inbound_ids": [],
            }
            _write_protection_state(state)
        else:
            baseline = _valid_ids(state.get("baseline_inbound_ids")).union(PROTECTED_INBOUND_IDS)
            managed = _valid_ids(state.get("managed_inbound_ids")) - baseline
            state["baseline_inbound_ids"] = sorted(baseline)
            state["managed_inbound_ids"] = sorted(managed)
        _PROTECTION_STATE = state
        return dict(state)


def _protected_ids() -> set[int]:
    with _STATE_LOCK:
        state = _PROTECTION_STATE
        if state is None:
            return set(PROTECTED_INBOUND_IDS)
        return _valid_ids(state.get("baseline_inbound_ids")).union(PROTECTED_INBOUND_IDS)


def _managed_ids() -> set[int]:
    with _STATE_LOCK:
        return _valid_ids((_PROTECTION_STATE or {}).get("managed_inbound_ids"))


def _mark_managed_inbound(inbound_id: int) -> None:
    global _PROTECTION_STATE
    with _STATE_LOCK:
        state = _initialize_protection_state()
        if inbound_id in _valid_ids(state.get("baseline_inbound_ids")):
            raise RuntimeError("Existing production inbound cannot become Sentinel-managed")
        managed = _valid_ids(state.get("managed_inbound_ids"))
        managed.add(inbound_id)
        state["managed_inbound_ids"] = sorted(managed)
        state["updated_at"] = _utc_now()
        _write_protection_state(state)
        _PROTECTION_STATE = state


def _unmark_managed_inbound(inbound_id: int) -> None:
    global _PROTECTION_STATE
    with _STATE_LOCK:
        state = _initialize_protection_state()
        managed = _valid_ids(state.get("managed_inbound_ids"))
        managed.discard(inbound_id)
        state["managed_inbound_ids"] = sorted(managed)
        state["updated_at"] = _utc_now()
        _write_protection_state(state)
        _PROTECTION_STATE = state


def _guard_inbound_structure(inbound_id: int) -> None:
    _initialize_protection_state()
    if inbound_id in _protected_ids():
        raise ValueError("Protected production inbound cannot be updated or deleted")
    if inbound_id not in _managed_ids():
        raise ValueError("Only inbounds created by Sentinel can be updated or deleted")


def _protection_summary() -> dict[str, Any]:
    state = _initialize_protection_state()
    return {
        "mode": "immutable-baseline",
        "state": "active",
        "baseline_count": len(_valid_ids(state.get("baseline_inbound_ids"))),
        "managed_count": len(_valid_ids(state.get("managed_inbound_ids"))),
        "created_at": state.get("created_at"),
        "updated_at": state.get("updated_at"),
        "inbound_create_enabled": ALLOW_INBOUND_CREATE,
    }


def _inventory() -> list[dict[str, Any]]:
    rows = _raw_inventory()
    _initialize_protection_state(rows)
    return [_normalize_inbound(item) for item in rows if isinstance(item, dict)]


def _find_inbound(inbound_id: int) -> dict[str, Any]:
    for inbound in _inventory():
        if int(inbound.get("id") or 0) == inbound_id:
            return inbound
    raise KeyError("Inbound not found")


def _new_reality_private_key() -> str:
    try:
        generated = subprocess.run(
            ["xray", "x25519"],
            check=False,
            capture_output=True,
            text=True,
            timeout=3,
        ).stdout
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError("xray is required to generate Reality keys") from exc
    match = re.search(r"(?:Private key|PrivateKey):\s*(\S+)", generated, re.I)
    if not match:
        match = re.search(r"(?:Private key|Password):\s*(\S+)", generated, re.I)
    if not match:
        raise RuntimeError("Unable to parse generated Reality private key")
    return match.group(1)


def _xui_inbound_payload(payload: dict[str, Any], *, existing: dict[str, Any] | None = None) -> dict[str, Any]:
    if existing is None and not str(payload.get("remark") or "").strip():
        raise ValueError("Inbound remark is required")
    if "protocol" in payload and str(payload.get("protocol") or "").lower() != "vless":
        raise ValueError("This controller manages VLESS inbounds only")
    if "port" in payload:
        try:
            port = int(payload.get("port") or 0)
        except (TypeError, ValueError) as exc:
            raise ValueError("Inbound port must be an integer") from exc
        if not 1 <= port <= 65535:
            raise ValueError("Inbound port must be between 1 and 65535")
        payload = {**payload, "port": port}
    elif existing is None:
        raise ValueError("Inbound port is required")
    stream_input = payload.get("stream_settings")
    if isinstance(stream_input, dict):
        if str(stream_input.get("network") or "tcp") not in {"tcp", "ws", "grpc"}:
            raise ValueError("Unsupported VLESS transport")
        if str(stream_input.get("security") or "reality") not in {"reality", "tls", "none"}:
            raise ValueError("Unsupported VLESS security mode")
    allowed = {"up", "down", "total", "remark", "enable", "expiryTime", "listen", "port", "protocol"}
    result = {key: value for key, value in (existing or {}).items() if key in allowed}
    result.update({key: value for key, value in payload.items() if key in allowed})
    for source, target in (("settings", "settings"), ("stream_settings", "streamSettings"), ("sniffing", "sniffing")):
        if source in payload:
            value = payload[source]
            if source == "stream_settings" and existing is None and isinstance(value, dict):
                value = dict(value)
                reality = value.get("realitySettings")
                if value.get("security") == "reality" and isinstance(reality, dict):
                    reality = dict(reality)
                    reality.setdefault("privateKey", _new_reality_private_key())
                    if not reality.get("shortIds"):
                        reality["shortIds"] = [secrets.token_hex(8)]
                    value["realitySettings"] = reality
            result[target] = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
        elif existing is not None and target in existing:
            result[target] = existing[target]
    return result


def _client_payload(
    payload: dict[str, Any],
    *,
    client_id: str | None = None,
    existing: dict[str, Any] | None = None,
) -> dict[str, Any]:
    current = dict(existing or {})
    identifier = str(client_id or payload.get("id") or current.get("id") or uuid4())
    try:
        UUID(identifier)
    except (ValueError, AttributeError) as exc:
        raise ValueError("Client ID must be a UUID") from exc
    email = str(payload.get("email") if "email" in payload else current.get("email") or f"client-{identifier[:8]}").strip()[:128]
    if not email or any(character in email for character in "\r\n/\\"):
        raise ValueError("Client email/name is invalid")
    try:
        limit_ip = int(
            payload.get("limit_ip")
            if "limit_ip" in payload
            else payload.get("limitIp")
            if "limitIp" in payload
            else current.get("limitIp") or 0
        )
        if "total_gb" in payload:
            total_bytes = int(payload.get("total_gb") or 0) * 1024**3
        elif "totalGB" in payload:
            total_bytes = int(payload.get("totalGB") or 0)
        else:
            total_bytes = int(current.get("totalGB") or 0)
        expiry_time = int(
            payload.get("expiry_time")
            if "expiry_time" in payload
            else payload.get("expiryTime")
            if "expiryTime" in payload
            else current.get("expiryTime") or 0
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("Client limits and expiration must be integers") from exc
    if not 0 <= limit_ip <= 128:
        raise ValueError("Client IP limit must be between 0 and 128")
    if not 0 <= total_bytes <= 1_000_000 * 1024**3:
        raise ValueError("Client traffic limit is out of range")
    if expiry_time < 0:
        raise ValueError("Client expiration cannot be negative")
    return {
        "id": identifier,
        "email": email,
        "enable": bool(payload.get("enable")) if "enable" in payload else bool(current.get("enable", True)),
        "flow": str(payload.get("flow") if "flow" in payload else current.get("flow") or "xtls-rprx-vision"),
        "limitIp": limit_ip,
        "totalGB": total_bytes,
        "expiryTime": expiry_time,
        "tgId": str(
            payload.get("telegram_id")
            if "telegram_id" in payload
            else payload.get("tgId")
            if "tgId" in payload
            else current.get("tgId") or ""
        ),
        "subId": str(
            payload.get("subscription_id")
            if "subscription_id" in payload
            else payload.get("subId")
            if "subId" in payload
            else current.get("subId") or uuid4().hex[:16]
        ),
        "reset": int(payload.get("reset") if "reset" in payload else current.get("reset") or 0),
    }


def _find_client(inbound_id: int, client_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
    inbound = _find_inbound(inbound_id)
    client = next((row for row in inbound["clients"] if str(row.get("id")) == client_id), None)
    if client is None:
        raise KeyError("Client not found in the requested inbound")
    return inbound, dict(client)


def _profile(inbound_id: int, client_id: str) -> dict[str, Any]:
    inbound, client = _find_client(inbound_id, client_id)
    if inbound["protocol"] != "vless" or not PUBLIC_HOST:
        return {"success": True, "profile": "", "issue": "Profile URI is available only for VLESS with XUI_PUBLIC_HOST"}
    raw = next((row for row in _raw_inventory() if int(row.get("id") or 0) == inbound_id), {})
    stream = _json_object(raw.get("streamSettings"))
    security = str(stream.get("security") or "none")
    network = str(stream.get("network") or "tcp")
    reality = stream.get("realitySettings") if isinstance(stream.get("realitySettings"), dict) else {}
    server_names = reality.get("serverNames") if isinstance(reality.get("serverNames"), list) else []
    short_ids = reality.get("shortIds") if isinstance(reality.get("shortIds"), list) else []
    public_key = str(reality.get("publicKey") or "")
    if not public_key and reality.get("privateKey"):
        try:
            generated = subprocess.run(
                ["xray", "x25519", "-i", str(reality["privateKey"])],
                check=False,
                capture_output=True,
                text=True,
                timeout=3,
            ).stdout
            match = re.search(r"(?:Public key|Password):\s*(\S+)", generated, re.I)
            public_key = match.group(1) if match else ""
        except (OSError, subprocess.SubprocessError):
            public_key = ""
    params = {
        "encryption": "none",
        "security": security,
        "type": network,
        "flow": str(client.get("flow") or ""),
        "sni": str(server_names[0] if server_names else ""),
        "sid": str(short_ids[0] if short_ids else ""),
        "fp": "chrome",
        "pbk": public_key,
    }
    query = url_parse.urlencode({key: value for key, value in params.items() if value})
    profile = f"vless://{client_id}@{PUBLIC_HOST}:{inbound['port']}?{query}#{url_parse.quote(str(client.get('email') or client_id))}"
    return {"success": True, "profile": profile, "email": client.get("email")}


def _online_clients() -> list[str]:
    try:
        result = _panel("/panel/api/inbounds/onlines")
    except RuntimeError:
        return []
    rows = result.get("obj") if isinstance(result.get("obj"), list) else []
    return sorted({str(item).strip() for item in rows if str(item).strip()})


def _capabilities() -> list[str]:
    capabilities = [
        "inbounds.read",
        "clients.create",
        "clients.update",
        "clients.delete",
        "clients.profile",
        "traffic.reset",
        "traffic.read",
        "online.read",
        "protection.immutable_baseline",
    ]
    if ALLOW_INBOUND_CREATE:
        capabilities.extend(("inbounds.create", "inbounds.update", "inbounds.delete"))
    return capabilities


def _controller_state() -> dict[str, Any]:
    inbounds = _inventory()
    try:
        version = subprocess.run(
            ["x-ui", "-v"],
            check=False,
            capture_output=True,
            text=True,
            timeout=3,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        version = ""
    return {
        "success": True,
        "status": "active",
        "version": version,
        "generated_at": _utc_now(),
        "capabilities": _capabilities(),
        "connectivity": {
            "controller": "active",
            "panel": "active",
            "transport": str(os.getenv("SIEM_XUI_TRANSPORT") or "private-loopback"),
        },
        "protection": _protection_summary(),
        "inbounds": inbounds,
        "traffic": {
            "up": sum(int(row["up"]) for row in inbounds),
            "down": sum(int(row["down"]) for row in inbounds),
        },
        "online": _online_clients(),
    }


def _monitoring_state() -> dict[str, Any]:
    state = _controller_state()
    inbounds = []
    client_count = 0
    for inbound in state["inbounds"]:
        clients = inbound.get("clients") if isinstance(inbound.get("clients"), list) else []
        client_count += len(clients)
        inbounds.append(
            {
                key: inbound.get(key)
                for key in (
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
            }
            | {"client_count": len(clients)}
        )
    return {
        "success": True,
        "status": state["status"],
        "version": state["version"],
        "generated_at": state["generated_at"],
        "capabilities": ["inbounds.read", "traffic.read", "online.read"],
        "connectivity": state["connectivity"],
        "protection": state["protection"],
        "inbounds": inbounds,
        "client_count": client_count,
        "online_count": len(state["online"]),
        "traffic": state["traffic"],
    }


class BoundedThreadingHTTPServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(
        self,
        server_address: tuple[str, int],
        request_handler_class: type[BaseHTTPRequestHandler],
        *,
        max_concurrent_requests: int,
        request_timeout: float,
    ) -> None:
        self._request_slots = threading.BoundedSemaphore(max_concurrent_requests)
        self._request_timeout = request_timeout
        super().__init__(server_address, request_handler_class)

    def get_request(self):
        request, client_address = super().get_request()
        request.settimeout(self._request_timeout)
        return request, client_address

    def process_request(self, request, client_address) -> None:
        if not self._request_slots.acquire(blocking=False):
            try:
                request.sendall(
                    b"HTTP/1.1 503 Service Unavailable\r\n"
                    b"Connection: close\r\nContent-Length: 0\r\n\r\n"
                )
            finally:
                self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._request_slots.release()
            raise

    def process_request_thread(self, request, client_address) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._request_slots.release()


class Handler(BaseHTTPRequestHandler):
    server_version = "RdegonXuiController/1.0"

    def log_message(self, fmt: str, *args: object) -> None:
        status = str(args[1]) if len(args) > 1 else "-"
        command = str(getattr(self, "command", "-") or "-")
        path = str(getattr(self, "path", "/") or "/")
        print(f"xui-controller: {command} {_safe_log_path(path)} {status}", flush=True)

    def _authorized(self) -> bool:
        supplied = self.headers.get("Authorization", "").removeprefix("Bearer ")
        return bool(supplied) and hmac.compare_digest(supplied, CONTROLLER_TOKEN)

    def _body(self) -> dict[str, Any]:
        if self.headers.get("Transfer-Encoding"):
            raise ValueError("Transfer-Encoding is not supported")
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError as exc:
            raise ValueError("Content-Length must be an integer") from exc
        if length < 0:
            raise ValueError("Content-Length cannot be negative")
        if length > MAX_BODY_BYTES:
            raise RequestBodyTooLarge(f"Request body exceeds the {MAX_BODY_BYTES}-byte limit")
        if not length:
            return {}
        body = self.rfile.read(length)
        if len(body) != length:
            raise ValueError("Request body ended before Content-Length bytes were received")
        parsed = json.loads(body.decode("utf-8"))
        if not isinstance(parsed, dict):
            raise ValueError("JSON object required")
        return parsed

    def _send(self, status: int, payload: dict[str, Any]) -> None:
        data = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Request-ID", str(payload.get("request_id") or ""))
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _dispatch(self) -> dict[str, Any]:
        path = url_parse.urlparse(self.path).path.rstrip("/") or "/"
        if path == "/health" and self.command == "GET":
            state = _controller_state()
            return {
                key: value
                for key, value in state.items()
                if key not in {"inbounds", "traffic", "online"}
            } | {"inbounds": len(state["inbounds"])}
        if path == "/state" and self.command == "GET":
            return _controller_state()
        if path == "/monitoring" and self.command == "GET":
            return _monitoring_state()
        if path == "/inbounds" and self.command == "GET":
            state = _controller_state()
            return {
                "success": True,
                "inbounds": state["inbounds"],
                "traffic": state["traffic"],
                "online": state["online"],
                "protection": state["protection"],
            }
        if path == "/inbounds" and self.command == "POST":
            if not ALLOW_INBOUND_CREATE:
                raise ValueError("Inbound creation is disabled; Sentinel manages profiles on the existing production inbounds")
            before_ids = {int(row.get("id") or 0) for row in _raw_inventory()}
            mutation = _mutation_result(
                _panel("/panel/api/inbounds/add", method="POST", payload=_xui_inbound_payload(self._body()))
            )
            after_ids = {int(row.get("id") or 0) for row in _raw_inventory()}
            candidates = sorted(item for item in after_ids - before_ids if item > 0)
            try:
                created_id = int(mutation.get("id") or 0)
            except (TypeError, ValueError):
                created_id = 0
            if created_id <= 0 and len(candidates) == 1:
                created_id = candidates[0]
            if created_id <= 0 or created_id not in after_ids:
                raise RuntimeError("Inbound was created but its identity could not be verified; it remains immutable")
            _mark_managed_inbound(created_id)
            mutation["id"] = created_id
            return {"success": True, "result": mutation}
        match = re.fullmatch(r"/inbounds/(\d+)", path)
        if match:
            inbound_id = int(match.group(1))
            if self.command == "PUT":
                _guard_inbound_structure(inbound_id)
                existing = next((row for row in _raw_inventory() if int(row.get("id") or 0) == inbound_id), None)
                if existing is None: raise KeyError("Inbound not found")
                return {"success": True, "result": _mutation_result(_panel(f"/panel/api/inbounds/update/{inbound_id}", method="POST", payload=_xui_inbound_payload(self._body(), existing=existing)))}
            if self.command == "DELETE":
                _guard_inbound_structure(inbound_id)
                result = _mutation_result(_panel(f"/panel/api/inbounds/del/{inbound_id}", method="POST"))
                _unmark_managed_inbound(inbound_id)
                return {"success": True, "result": result}
        match = re.fullmatch(r"/inbounds/(\d+)/clients", path)
        if match and self.command == "POST":
            inbound_id = int(match.group(1)); inbound = _find_inbound(inbound_id); client = _client_payload(self._body())
            if any(str(item.get("id")) == client["id"] or str(item.get("email")) == client["email"] for item in inbound["clients"]):
                raise ValueError("A client with this ID or email already exists in the inbound")
            result = _panel("/panel/api/inbounds/addClient", method="POST", payload={"id": inbound_id, "settings": json.dumps({"clients": [client]}, separators=(",", ":"))})
            return {"success": True, "client": client, "result": _mutation_result(result)}
        match = re.fullmatch(r"/inbounds/(\d+)/clients/([^/]+)", path)
        if match:
            inbound_id, client_id = int(match.group(1)), url_parse.unquote(match.group(2))
            if self.command == "PUT":
                inbound, existing_client = _find_client(inbound_id, client_id)
                client = _client_payload(self._body(), client_id=client_id, existing=existing_client)
                if any(str(item.get("id")) != client_id and str(item.get("email")) == client["email"] for item in inbound["clients"]):
                    raise ValueError("A client with this email already exists in the inbound")
                result = _panel(f"/panel/api/inbounds/updateClient/{url_parse.quote(client_id)}", method="POST", payload={"id": inbound_id, "settings": json.dumps({"clients": [client]}, separators=(",", ":"))})
                return {"success": True, "client": client, "result": _mutation_result(result)}
            if self.command == "DELETE":
                _find_client(inbound_id, client_id)
                return {"success": True, "result": _mutation_result(_panel(f"/panel/api/inbounds/{inbound_id}/delClient/{url_parse.quote(client_id)}", method="POST"))}
        match = re.fullmatch(r"/inbounds/(\d+)/clients/([^/]+)/profile", path)
        if match and self.command == "GET":
            return _profile(int(match.group(1)), url_parse.unquote(match.group(2)))
        match = re.fullmatch(r"/inbounds/(\d+)/clients/([^/]+)/reset-traffic", path)
        if match and self.command == "POST":
            inbound_id, client_id = int(match.group(1)), url_parse.unquote(match.group(2)); _, client = _find_client(inbound_id, client_id)
            return {"success": True, "result": _mutation_result(_panel(f"/panel/api/inbounds/{inbound_id}/resetClientTraffic/{url_parse.quote(str(client.get('email') or ''))}", method="POST"))}
        match = re.fullmatch(r"/inbounds/(\d+)/reset-traffic", path)
        if match and self.command == "POST":
            inbound_id = int(match.group(1))
            _guard_inbound_structure(inbound_id)
            return {"success": True, "result": _mutation_result(_panel(f"/panel/api/inbounds/resetAllClientTraffics/{inbound_id}", method="POST"))}
        raise KeyError("Unknown controller operation")

    def _handle(self) -> None:
        supplied_request_id = str(self.headers.get("X-Request-ID") or "")[:64]
        request_id = supplied_request_id if re.fullmatch(r"[A-Za-z0-9._-]{1,64}", supplied_request_id) else uuid4().hex
        if not self._authorized():
            self._send(HTTPStatus.UNAUTHORIZED, {"success": False, "code": "unauthorized", "error": "Unauthorized", "request_id": request_id}); return
        try:
            self._send(HTTPStatus.OK, {**self._dispatch(), "request_id": request_id})
        except RequestBodyTooLarge as exc:
            self._send(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"success": False, "code": "body_too_large", "error": str(exc), "request_id": request_id})
        except (TimeoutError, socket.timeout):
            self._send(HTTPStatus.REQUEST_TIMEOUT, {"success": False, "code": "request_timeout", "error": "Request timed out", "request_id": request_id})
        except KeyError as exc:
            self._send(HTTPStatus.NOT_FOUND, {"success": False, "code": "not_found", "error": str(exc).strip("'"), "request_id": request_id})
        except (ValueError, json.JSONDecodeError) as exc:
            self._send(HTTPStatus.BAD_REQUEST, {"success": False, "code": "invalid_operation", "error": str(exc)[:300], "request_id": request_id})
        except Exception as exc:  # noqa: BLE001
            self._send(HTTPStatus.BAD_GATEWAY, {"success": False, "code": "panel_failure", "error": str(exc)[:500], "request_id": request_id})

    do_GET = _handle
    do_POST = _handle
    do_PUT = _handle
    do_DELETE = _handle


def main() -> None:
    _validate_config()
    _initialize_protection_state(_raw_inventory())
    server = BoundedThreadingHTTPServer(
        (LISTEN_HOST, LISTEN_PORT),
        Handler,
        max_concurrent_requests=MAX_CONCURRENT_REQUESTS,
        request_timeout=REQUEST_TIMEOUT_SECONDS,
    )
    server.serve_forever()


if __name__ == "__main__":
    main()
