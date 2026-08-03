from __future__ import annotations

import importlib.util
from pathlib import Path

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


def test_xui_state_flattens_real_clients_and_preserves_inbound_context(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(xui_runtime, "controller_configured", lambda: True)

    def fake_request(path: str, **_: object) -> dict:
        if path == "/health":
            return {"status": "active", "version": "2.6.4", "capabilities": ["clients.create"]}
        return {
            "inbounds": [
                {
                    "id": 4,
                    "remark": "reality-main",
                    "clients": [{"id": "client-id", "email": "operator", "enable": True}],
                }
            ],
            "traffic": {"up": 10, "down": 20},
            "online": ["operator"],
        }

    monkeypatch.setattr(xui_runtime, "_request", fake_request)
    state = xui_runtime.xui_state()

    assert state["status"] == "active"
    assert state["clients"] == [
        {
            "id": "client-id",
            "email": "operator",
            "enable": True,
            "inbound_id": 4,
            "inbound_remark": "reality-main",
        }
    ]
    assert state["traffic"] == {"up": 10, "down": 20}


def test_xui_client_operations_encode_identifier(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, str]] = []

    def fake_request(path: str, *, method: str = "GET", payload: dict | None = None) -> dict:
        calls.append((path, method))
        return {"success": True, "payload": payload}

    monkeypatch.setattr(xui_runtime, "_request", fake_request)
    xui_runtime.update_client(7, "client/id value", {"email": "operator"})
    xui_runtime.delete_client(7, "client/id value")
    xui_runtime.client_profile(7, "client/id value")
    xui_runtime.reset_client_traffic(7, "client/id value")

    assert calls == [
        ("/inbounds/7/clients/client%2Fid%20value", "PUT"),
        ("/inbounds/7/clients/client%2Fid%20value", "DELETE"),
        ("/inbounds/7/clients/client%2Fid%20value/profile", "GET"),
        ("/inbounds/7/clients/client%2Fid%20value/reset-traffic", "POST"),
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
