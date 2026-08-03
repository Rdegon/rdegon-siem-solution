from __future__ import annotations

import importlib.util
import socket
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace

import pytest

from app import xui_runtime


ROOT = Path(__file__).resolve().parents[1]


def test_xui_state_is_explicit_when_controller_is_not_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SIEM_VLESS_CONTROLLER_URL", raising=False)
    monkeypatch.delenv("SIEM_VLESS_CONTROLLER_TOKEN", raising=False)
    monkeypatch.delenv("SIEM_VLESS_CONTROLLER_TOKEN_REF", raising=False)

    state = xui_runtime.xui_state()

    assert state["configured"] is False
    assert state["status"] == "unavailable"
    assert state["capabilities"] == []
    assert state["inbounds"] == []


def test_xui_controller_token_uses_secret_resolver(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SIEM_VLESS_CONTROLLER_URL", "http://127.0.0.1:18787")
    monkeypatch.setattr(
        xui_runtime,
        "resolve_secret_value",
        lambda *_args, **_kwargs: ("resolved-token", "vault", {"status": "configured"}),
    )

    assert xui_runtime._settings()[:2] == ("http://127.0.0.1:18787", "resolved-token")  # noqa: SLF001


def test_xui_runtime_rejects_non_loopback_controller(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SIEM_VLESS_CONTROLLER_URL", "http://45.89.111.208:8787")
    monkeypatch.setattr(
        xui_runtime,
        "resolve_secret_value",
        lambda *_args, **_kwargs: ("resolved-token", "vault", {"status": "configured"}),
    )

    state = xui_runtime.xui_state()

    assert state["configured"] is True
    assert state["status"] == "degraded"
    assert "loopback" in state["issue"]


def test_xui_monitoring_state_never_exposes_client_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(xui_runtime, "controller_configured", lambda: True)

    def fake_request(path: str, **_: object) -> dict:
        assert path == "/monitoring"
        return {
            "status": "active",
            "version": "2.6.4",
            "capabilities": ["clients.create", "clients.profile"],
            "inbounds": [
                {
                    "id": 4,
                    "remark": "reality-main",
                    "client_count": 1,
                    "settings": {"clients": [{"id": "raw-client-credential", "subId": "private-subscription"}]},
                    "clients": [{"id": "raw-client-credential", "subId": "private-subscription", "tgId": "42"}],
                }
            ],
            "traffic": {"up": 10, "down": 20},
            "online": ["operator"],
            "online_count": 1,
        }

    monkeypatch.setattr(xui_runtime, "_request", fake_request)
    state = xui_runtime.xui_state()

    assert state["status"] == "active"
    assert state["clients"] == []
    assert state["inbounds"] == [{"id": 4, "remark": "reality-main", "client_count": 1}]
    assert state["capabilities"] == ["inbounds.read", "traffic.read", "online.read"]
    assert state["online"] == []
    assert state["online_count"] == 1
    assert state["traffic"] == {"up": 10, "down": 20}
    serialized = str(state)
    assert "raw-client-credential" not in serialized
    assert "private-subscription" not in serialized
    assert "tgId" not in serialized
    assert "settings" not in serialized


def test_xui_management_state_uses_opaque_client_references(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(xui_runtime, "controller_configured", lambda: True)
    monkeypatch.setattr(xui_runtime, "_settings", lambda: ("http://127.0.0.1:18787", "test-controller-token", 3.0))
    raw_id = "86ddcb83-1b80-4f4f-8144-2be5809d054e"
    monkeypatch.setattr(
        xui_runtime,
        "_request",
        lambda path, **_: {
            "status": "active",
            "capabilities": ["clients.update", "clients.profile"],
            "inbounds": [{
                "id": 4,
                "remark": "reality-main",
                "settings": {"clients": [{"id": raw_id}]},
                "clients": [{"id": raw_id, "email": "operator", "enable": True, "subId": "private-sub", "tgId": "42"}],
            }],
        } if path == "/state" else {},
    )

    state = xui_runtime.xui_management_state()

    client = state["clients"][0]
    assert client["client_ref"].startswith("client-")
    assert "id" not in client
    assert "subId" not in client
    assert client["tgId"] == "42"
    assert "settings" not in state["inbounds"][0]
    assert raw_id not in str(state)


def test_xui_client_operations_resolve_opaque_reference(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, str]] = []
    raw_id = "86ddcb83-1b80-4f4f-8144-2be5809d054e"
    monkeypatch.setattr(xui_runtime, "_settings", lambda: ("http://127.0.0.1:18787", "test-controller-token", 3.0))
    client_ref = xui_runtime.client_fingerprint(raw_id)

    def fake_request(path: str, *, method: str = "GET", payload: dict | None = None) -> dict:
        calls.append((path, method))
        if path == "/state":
            return {"inbounds": [{"id": 7, "clients": [{"id": raw_id, "email": "operator"}]}]}
        return {"success": True, "payload": payload}

    monkeypatch.setattr(xui_runtime, "_request", fake_request)
    xui_runtime.update_client(7, client_ref, {"email": "operator"})
    xui_runtime.delete_client(7, client_ref)
    xui_runtime.client_profile(7, client_ref)
    xui_runtime.reset_client_traffic(7, client_ref)

    assert calls == [
        ("/state", "GET"),
        (f"/inbounds/7/clients/{raw_id}", "PUT"),
        ("/state", "GET"),
        (f"/inbounds/7/clients/{raw_id}", "DELETE"),
        ("/state", "GET"),
        (f"/inbounds/7/clients/{raw_id}/profile", "GET"),
        ("/state", "GET"),
        (f"/inbounds/7/clients/{raw_id}/reset-traffic", "POST"),
    ]


def test_deployed_controller_redacts_reality_private_key() -> None:
    path = ROOT / "deploy" / "vless" / "siem_xui_controller.py"
    spec = importlib.util.spec_from_file_location("siem_xui_controller", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    public = module._public_stream_settings(  # noqa: SLF001 - deployment contract test
        '{"security":"reality","realitySettings":{"privateKey":"server-secret","serverNames":["example.net"]}}'
    )

    assert "privateKey" not in public["realitySettings"]
    assert public["realitySettings"]["privateKeyConfigured"] is True
    assert public["realitySettings"]["serverNames"] == ["example.net"]


def test_deployed_controller_marks_protected_inbound(monkeypatch: pytest.MonkeyPatch) -> None:
    path = ROOT / "deploy" / "vless" / "siem_xui_controller.py"
    monkeypatch.setenv("XUI_PROTECTED_INBOUND_IDS", "7,9")
    spec = importlib.util.spec_from_file_location("siem_xui_controller_protected", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    inbound = module._normalize_inbound({"id": 7, "port": 443, "protocol": "vless"})  # noqa: SLF001

    assert inbound["protected"] is True


def test_deployed_controller_never_returns_panel_objects() -> None:
    path = ROOT / "deploy" / "vless" / "siem_xui_controller.py"
    spec = importlib.util.spec_from_file_location("siem_xui_controller_mutation", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    result = module._mutation_result(  # noqa: SLF001
        {"success": True, "msg": "ok", "obj": {"streamSettings": {"privateKey": "server-secret"}}}
    )

    assert result == {"success": True, "message": "ok", "id": ""}
    assert "server-secret" not in str(result)


def test_deployed_controller_validates_inbound_and_client_limits() -> None:
    path = ROOT / "deploy" / "vless" / "siem_xui_controller.py"
    spec = importlib.util.spec_from_file_location("siem_xui_controller_validation", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    with pytest.raises(ValueError, match="port"):
        module._xui_inbound_payload({"remark": "bad", "protocol": "vless", "port": 70000})  # noqa: SLF001
    with pytest.raises(ValueError, match="email"):
        module._client_payload({"email": "bad/name", "limit_ip": 1})  # noqa: SLF001
    with pytest.raises(ValueError, match="IP limit"):
        module._client_payload({"email": "operator", "limit_ip": 200})  # noqa: SLF001


def test_controller_snapshots_existing_inbounds_and_only_manages_its_own(tmp_path: Path) -> None:
    module = _controller_module("siem_xui_controller_baseline")
    module.STATE_PATH = tmp_path / "protection.json"
    module.PROTECTED_INBOUND_IDS = set()
    module._PROTECTION_STATE = None  # noqa: SLF001

    state = module._initialize_protection_state([{"id": 7}, {"id": 9}])  # noqa: SLF001

    assert state["baseline_inbound_ids"] == [7, 9]
    with pytest.raises(ValueError, match="Protected production inbound"):
        module._guard_inbound_structure(7)  # noqa: SLF001
    module._mark_managed_inbound(12)  # noqa: SLF001
    module._guard_inbound_structure(12)  # noqa: SLF001
    with pytest.raises(ValueError, match="created by Sentinel"):
        module._guard_inbound_structure(13)  # noqa: SLF001

    module._PROTECTION_STATE = None  # noqa: SLF001
    reloaded = module._initialize_protection_state([])  # noqa: SLF001
    assert reloaded["baseline_inbound_ids"] == [7, 9]
    assert reloaded["managed_inbound_ids"] == [12]


def test_controller_client_update_preserves_omitted_limits() -> None:
    module = _controller_module("siem_xui_controller_client_merge")
    client_id = "86ddcb83-1b80-4f4f-8144-2be5809d054e"
    current = {
        "id": client_id,
        "email": "operator",
        "enable": True,
        "flow": "xtls-rprx-vision",
        "limitIp": 3,
        "totalGB": 17 * 1024**3,
        "expiryTime": 123456789,
        "tgId": "42",
        "subId": "stable-subscription",
        "reset": 0,
    }

    updated = module._client_payload({"enable": False}, client_id=client_id, existing=current)  # noqa: SLF001

    assert updated["enable"] is False
    assert updated["email"] == "operator"
    assert updated["limitIp"] == 3
    assert updated["totalGB"] == 17 * 1024**3
    assert updated["expiryTime"] == 123456789
    assert updated["subId"] == "stable-subscription"


def test_controller_monitoring_dto_is_credential_free(monkeypatch: pytest.MonkeyPatch) -> None:
    module = _controller_module("siem_xui_controller_monitoring")
    raw_id = "86ddcb83-1b80-4f4f-8144-2be5809d054e"
    monkeypatch.setattr(
        module,
        "_controller_state",
        lambda: {
            "status": "active",
            "version": "test",
            "generated_at": "now",
            "connectivity": {"controller": "active", "panel": "active"},
            "protection": {"state": "active"},
            "traffic": {"up": 1, "down": 2},
            "online": ["operator"],
            "inbounds": [{
                "id": 7,
                "remark": "production",
                "enable": True,
                "protocol": "vless",
                "port": 443,
                "settings": {"clients": [{"id": raw_id}]},
                "stream_settings": {"security": "reality"},
                "clients": [{"id": raw_id, "subId": "private-sub", "tgId": "42"}],
            }],
        },
    )

    state = module._monitoring_state()  # noqa: SLF001

    assert state["client_count"] == 1
    assert state["online_count"] == 1
    assert state["inbounds"][0]["client_count"] == 1
    serialized = str(state)
    assert raw_id not in serialized
    assert "private-sub" not in serialized
    assert "settings" not in serialized
    assert "subId" not in serialized
    assert "tgId" not in serialized


def test_controller_log_replaces_client_uuid_with_fingerprint(capsys: pytest.CaptureFixture[str]) -> None:
    module = _controller_module("siem_xui_controller_log_redaction")
    module.CONTROLLER_TOKEN = "test-controller-token"
    raw_id = "86ddcb83-1b80-4f4f-8144-2be5809d054e"
    handler = SimpleNamespace(command="GET", path=f"/inbounds/7/clients/{raw_id}/profile")

    module.Handler.log_message(handler, '"%s" %s %s', "request", 200, "-")

    output = capsys.readouterr().out
    assert raw_id not in output
    assert "client-" in output


def test_controller_rejects_oversized_and_incomplete_bodies() -> None:
    module = _controller_module("siem_xui_controller_body_limits")
    oversized = SimpleNamespace(
        headers={"Content-Length": str(module.MAX_BODY_BYTES + 1)},
        rfile=BytesIO(),
    )
    incomplete = SimpleNamespace(headers={"Content-Length": "10"}, rfile=BytesIO(b"{}"))

    with pytest.raises(module.RequestBodyTooLarge):
        module.Handler._body(oversized)
    with pytest.raises(ValueError, match="ended before"):
        module.Handler._body(incomplete)


def test_controller_rejects_connections_above_concurrency_limit() -> None:
    module = _controller_module("siem_xui_controller_concurrency")

    class FakeSocket:
        def __init__(self) -> None:
            self.sent = b""
            self.closed = False

        def sendall(self, value: bytes) -> None:
            self.sent += value

        def shutdown(self, _how: int) -> None:
            return None

        def close(self) -> None:
            self.closed = True

    server = module.BoundedThreadingHTTPServer(
        ("127.0.0.1", 0),
        module.Handler,
        max_concurrent_requests=1,
        request_timeout=1,
    )
    request = FakeSocket()
    try:
        assert server._request_slots.acquire(blocking=False)  # noqa: SLF001
        server.process_request(request, ("127.0.0.1", 12345))
        assert b"503 Service Unavailable" in request.sent
        assert request.closed is True
    finally:
        server._request_slots.release()  # noqa: SLF001
        server.server_close()


def test_controller_applies_socket_timeout_before_parsing_headers() -> None:
    module = _controller_module("siem_xui_controller_socket_timeout")
    server = module.BoundedThreadingHTTPServer(
        ("127.0.0.1", 0),
        module.Handler,
        max_concurrent_requests=1,
        request_timeout=1.5,
    )
    client = socket.create_connection(server.server_address, timeout=2)
    accepted = None
    try:
        accepted, _ = server.get_request()
        assert accepted.gettimeout() == 1.5
    finally:
        if accepted is not None:
            accepted.close()
        client.close()
        server.server_close()


def test_create_client_discards_caller_supplied_uuid(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict = {}
    monkeypatch.setattr(xui_runtime, "_settings", lambda: ("http://127.0.0.1:18787", "test-controller-token", 3.0))

    def fake_request(path: str, *, method: str = "GET", payload: dict | None = None) -> dict:
        captured.update(payload or {})
        return {
            "success": True,
            "client": {"id": "86ddcb83-1b80-4f4f-8144-2be5809d054e", "email": "operator"},
        }

    monkeypatch.setattr(xui_runtime, "_request", fake_request)

    result = xui_runtime.create_client(7, {"id": "caller-selected-id", "email": "operator"})

    assert "id" not in captured
    assert "id" not in result["client"]
    assert result["client"]["client_ref"].startswith("client-")


def _controller_module(name: str):
    path = ROOT / "deploy" / "vless" / "siem_xui_controller.py"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
