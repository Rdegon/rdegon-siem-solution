from __future__ import annotations

from pathlib import Path

import pytest

from app import remote_access_runtime


def test_remote_access_profile_is_prepared_without_fabricating_activation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(remote_access_runtime, "_PROFILE_FILE", tmp_path / "profiles.json")
    monkeypatch.delenv("SIEM_OPENVPN_CONTROLLER_URL", raising=False)
    monkeypatch.delenv("SIEM_OPENVPN_CONTROLLER_TOKEN", raising=False)

    result = remote_access_runtime.create_remote_access_profile(
        {
            "provider": "openvpn",
            "name": "operator-core",
            "route_preset": "siem-core-admin",
            "credential_ref": "vault://remote-access/operator-core",
        },
        actor="tester",
    )
    state = remote_access_runtime.remote_access_state()

    assert result["status"] == "prepared"
    assert "not configured" in result["activation"]["issue"]
    assert result["routes"] == ["10.20.10.0/24", "192.168.3.102/32"]
    assert state["profiles"][0]["name"] == "operator-core"
    assert state["controllers"][0]["configured"] is False

    assert remote_access_runtime.delete_remote_access_profile(result["id"])["deleted"] is True
    assert remote_access_runtime.remote_access_state()["profiles"] == []


def test_remote_access_rejects_unknown_provider(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(remote_access_runtime, "_PROFILE_FILE", tmp_path / "profiles.json")
    with pytest.raises(ValueError, match="Provider"):
        remote_access_runtime.create_remote_access_profile(
            {"provider": "pptp", "name": "legacy", "route_preset": "siem-core-admin"},
            actor="tester",
        )
