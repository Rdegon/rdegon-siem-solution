#!/usr/bin/env python3
from __future__ import annotations

import hmac
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import re
import secrets
import subprocess
from typing import Any
from urllib import error as url_error
from urllib import parse as url_parse
from urllib import request as url_request
from uuid import uuid4


PANEL_URL = str(os.getenv("XUI_PANEL_URL") or "http://127.0.0.1:2053").rstrip("/")
PANEL_USER = str(os.getenv("XUI_PANEL_USERNAME") or "")
PANEL_PASSWORD = str(os.getenv("XUI_PANEL_PASSWORD") or "")
CONTROLLER_TOKEN = str(os.getenv("SIEM_XUI_CONTROLLER_TOKEN") or "")
PUBLIC_HOST = str(os.getenv("XUI_PUBLIC_HOST") or "").strip()
LISTEN_HOST = str(os.getenv("SIEM_XUI_LISTEN_HOST") or "127.0.0.1")
LISTEN_PORT = int(os.getenv("SIEM_XUI_LISTEN_PORT") or "8787")
PROTECTED_INBOUND_IDS = {
    int(value)
    for value in str(os.getenv("XUI_PROTECTED_INBOUND_IDS") or "").split(",")
    if value.strip().isdigit()
}
_COOKIE = ""


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
    return {
        "id": item.get("id"),
        "remark": str(item.get("remark") or ""),
        "enable": bool(item.get("enable", True)),
        "protocol": str(item.get("protocol") or ""),
        "port": int(item.get("port") or 0),
        "listen": str(item.get("listen") or ""),
        "up": int(item.get("up") or 0),
        "down": int(item.get("down") or 0),
        "total": int(item.get("total") or 0),
        "expiry_time": int(item.get("expiryTime") or 0),
        "protected": int(item.get("id") or 0) in PROTECTED_INBOUND_IDS,
        "settings": _json_object(item.get("settings")),
        "stream_settings": _public_stream_settings(item.get("streamSettings")),
        "sniffing": _json_object(item.get("sniffing")),
        "clients": _clients(item),
    }


def _raw_inventory() -> list[dict[str, Any]]:
    result = _panel("/panel/api/inbounds/list")
    rows = result.get("obj") if isinstance(result.get("obj"), list) else []
    return [item for item in rows if isinstance(item, dict)]


def _inventory() -> list[dict[str, Any]]:
    rows = _raw_inventory()
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


def _client_payload(payload: dict[str, Any], *, client_id: str | None = None) -> dict[str, Any]:
    identifier = str(client_id or payload.get("id") or uuid4())
    email = str(payload.get("email") or f"client-{identifier[:8]}").strip()[:128]
    if not email or any(character in email for character in "\r\n/\\"):
        raise ValueError("Client email/name is invalid")
    try:
        limit_ip = int(payload.get("limit_ip") or payload.get("limitIp") or 0)
        total_gb = int(payload.get("total_gb") or payload.get("totalGB") or 0)
        expiry_time = int(payload.get("expiry_time") or payload.get("expiryTime") or 0)
    except (TypeError, ValueError) as exc:
        raise ValueError("Client limits and expiration must be integers") from exc
    if not 0 <= limit_ip <= 128:
        raise ValueError("Client IP limit must be between 0 and 128")
    if not 0 <= total_gb <= 1_000_000:
        raise ValueError("Client traffic limit is out of range")
    if expiry_time < 0:
        raise ValueError("Client expiration cannot be negative")
    return {
        "id": identifier,
        "email": email,
        "enable": bool(payload.get("enable", True)),
        "flow": str(payload.get("flow") or "xtls-rprx-vision"),
        "limitIp": limit_ip,
        "totalGB": total_gb * 1024**3,
        "expiryTime": expiry_time,
        "tgId": str(payload.get("telegram_id") or payload.get("tgId") or ""),
        "subId": str(payload.get("subscription_id") or payload.get("subId") or uuid4().hex[:16]),
        "reset": int(payload.get("reset") or 0),
    }


def _profile(inbound_id: int, client_id: str) -> dict[str, Any]:
    inbound = _find_inbound(inbound_id)
    client = next((row for row in inbound["clients"] if str(row.get("id")) == client_id), None)
    if client is None:
        raise KeyError("Client not found")
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


class Handler(BaseHTTPRequestHandler):
    server_version = "RdegonXuiController/1.0"

    def log_message(self, fmt: str, *args: object) -> None:
        print(f"xui-controller: {fmt % args}", flush=True)

    def _authorized(self) -> bool:
        supplied = self.headers.get("Authorization", "").removeprefix("Bearer ")
        return bool(supplied) and hmac.compare_digest(supplied, CONTROLLER_TOKEN)

    def _body(self) -> dict[str, Any]:
        length = min(int(self.headers.get("Content-Length") or 0), 1024 * 1024)
        if not length:
            return {}
        parsed = json.loads(self.rfile.read(length).decode("utf-8"))
        if not isinstance(parsed, dict):
            raise ValueError("JSON object required")
        return parsed

    def _send(self, status: int, payload: dict[str, Any]) -> None:
        data = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _dispatch(self) -> dict[str, Any]:
        path = url_parse.urlparse(self.path).path.rstrip("/") or "/"
        if path == "/health" and self.command == "GET":
            inbounds = _inventory()
            try:
                version = subprocess.run(["x-ui", "-v"], check=False, capture_output=True, text=True, timeout=3).stdout.strip()
            except (OSError, subprocess.SubprocessError):
                version = ""
            return {"success": True, "status": "active", "version": version, "capabilities": ["inbounds.read", "inbounds.create", "inbounds.update", "inbounds.delete", "clients.create", "clients.update", "clients.delete", "clients.profile", "traffic.reset", "traffic.read", "online.read"], "inbounds": len(inbounds)}
        if path == "/inbounds" and self.command == "GET":
            inbounds = _inventory()
            return {"success": True, "inbounds": inbounds, "traffic": {"up": sum(int(row["up"]) for row in inbounds), "down": sum(int(row["down"]) for row in inbounds)}, "online": []}
        if path == "/inbounds" and self.command == "POST":
            return {"success": True, "result": _mutation_result(_panel("/panel/api/inbounds/add", method="POST", payload=_xui_inbound_payload(self._body())))}
        match = re.fullmatch(r"/inbounds/(\d+)", path)
        if match:
            inbound_id = int(match.group(1))
            if self.command == "PUT":
                existing = next((row for row in _raw_inventory() if int(row.get("id") or 0) == inbound_id), None)
                if existing is None: raise KeyError("Inbound not found")
                return {"success": True, "result": _mutation_result(_panel(f"/panel/api/inbounds/update/{inbound_id}", method="POST", payload=_xui_inbound_payload(self._body(), existing=existing)))}
            if self.command == "DELETE":
                if inbound_id in PROTECTED_INBOUND_IDS:
                    raise ValueError("Protected production inbound cannot be deleted")
                return {"success": True, "result": _mutation_result(_panel(f"/panel/api/inbounds/del/{inbound_id}", method="POST"))}
        match = re.fullmatch(r"/inbounds/(\d+)/clients", path)
        if match and self.command == "POST":
            inbound_id = int(match.group(1)); client = _client_payload(self._body())
            result = _panel("/panel/api/inbounds/addClient", method="POST", payload={"id": inbound_id, "settings": json.dumps({"clients": [client]}, separators=(",", ":"))})
            return {"success": True, "client": client, "result": _mutation_result(result)}
        match = re.fullmatch(r"/inbounds/(\d+)/clients/([^/]+)", path)
        if match:
            inbound_id, client_id = int(match.group(1)), url_parse.unquote(match.group(2))
            if self.command == "PUT":
                client = _client_payload(self._body(), client_id=client_id)
                result = _panel(f"/panel/api/inbounds/updateClient/{url_parse.quote(client_id)}", method="POST", payload={"id": inbound_id, "settings": json.dumps({"clients": [client]}, separators=(",", ":"))})
                return {"success": True, "client": client, "result": _mutation_result(result)}
            if self.command == "DELETE":
                return {"success": True, "result": _mutation_result(_panel(f"/panel/api/inbounds/{inbound_id}/delClient/{url_parse.quote(client_id)}", method="POST"))}
        match = re.fullmatch(r"/inbounds/(\d+)/clients/([^/]+)/profile", path)
        if match and self.command == "GET":
            return _profile(int(match.group(1)), url_parse.unquote(match.group(2)))
        match = re.fullmatch(r"/inbounds/(\d+)/clients/([^/]+)/reset-traffic", path)
        if match and self.command == "POST":
            inbound_id, client_id = int(match.group(1)), url_parse.unquote(match.group(2)); inbound = _find_inbound(inbound_id)
            client = next((row for row in inbound["clients"] if str(row.get("id")) == client_id), None)
            if client is None: raise KeyError("Client not found")
            return {"success": True, "result": _mutation_result(_panel(f"/panel/api/inbounds/{inbound_id}/resetClientTraffic/{url_parse.quote(str(client.get('email') or ''))}", method="POST"))}
        match = re.fullmatch(r"/inbounds/(\d+)/reset-traffic", path)
        if match and self.command == "POST":
            return {"success": True, "result": _mutation_result(_panel(f"/panel/api/inbounds/resetAllClientTraffics/{int(match.group(1))}", method="POST"))}
        raise KeyError("Unknown controller operation")

    def _handle(self) -> None:
        if not self._authorized():
            self._send(HTTPStatus.UNAUTHORIZED, {"success": False, "error": "Unauthorized"}); return
        try:
            self._send(HTTPStatus.OK, self._dispatch())
        except KeyError as exc:
            self._send(HTTPStatus.NOT_FOUND, {"success": False, "error": str(exc).strip("'")})
        except (ValueError, json.JSONDecodeError) as exc:
            self._send(HTTPStatus.BAD_REQUEST, {"success": False, "error": str(exc)[:300]})
        except Exception as exc:  # noqa: BLE001
            self._send(HTTPStatus.BAD_GATEWAY, {"success": False, "error": str(exc)[:500]})

    do_GET = _handle
    do_POST = _handle
    do_PUT = _handle
    do_DELETE = _handle


def main() -> None:
    _validate_config()
    server = ThreadingHTTPServer((LISTEN_HOST, LISTEN_PORT), Handler)
    server.serve_forever()


if __name__ == "__main__":
    main()
