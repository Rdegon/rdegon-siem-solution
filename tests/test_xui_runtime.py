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


def _controller_module(name: str):
    path = ROOT / "deploy" / "vless" / "siem_xui_controller.py"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
