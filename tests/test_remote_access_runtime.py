from __future__ import annotations

import base64
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from app import remote_access_runtime


def test_remote_access_profile_is_prepared_without_fabricating_activation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(remote_access_runtime, "_PROFILE_FILE", tmp_path / "profiles.json")
    monkeypatch.delenv("SIEM_OPENVPN_CONTROLLER_URL", raising=False)
    monkeypatch.delenv("SIEM_OPENVPN_CONTROLLER_TOKEN", raising=False)
    monkeypatch.setattr(remote_access_runtime, "_access_planes", lambda: [])

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


def test_remote_access_state_reports_observed_openvpn_and_non_ingress_vless(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(remote_access_runtime, "_PROFILE_FILE", tmp_path / "profiles.json")
    monkeypatch.setattr(remote_access_runtime, "_service_state", lambda unit: "active")
    monkeypatch.setattr(remote_access_runtime, "_interface_address", lambda interface: "10.66.66.4")
    monkeypatch.setattr(remote_access_runtime, "_tcp_reachable", lambda host, port: True)

    state = remote_access_runtime.remote_access_state()

    openvpn, vless = state["access_planes"]
    assert openvpn["status"] == "active"
    assert openvpn["role"] == "remote_ingress"
    assert openvpn["jump_host_reachable"] is True
    assert vless["status"] == "retired"
    assert vless["role"] == "outbound_egress"


def test_remote_access_rejects_unknown_provider(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(remote_access_runtime, "_PROFILE_FILE", tmp_path / "profiles.json")
    with pytest.raises(ValueError, match="Provider"):
        remote_access_runtime.create_remote_access_profile(
            {"provider": "pptp", "name": "legacy", "route_preset": "siem-core-admin"},
            actor="tester",
        )


def test_local_openvpn_controller_persists_download_and_revokes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    controller = tmp_path / "controller"
    controller.write_text("controller", encoding="utf-8")
    monkeypatch.setattr(remote_access_runtime, "_LOCAL_OPENVPN_CONTROLLER", controller)
    monkeypatch.setattr(remote_access_runtime, "_PROFILE_FILE", tmp_path / "profiles.json")
    monkeypatch.setattr(remote_access_runtime, "_PROFILE_ARTIFACT_DIR", tmp_path / "artifacts")
    calls: list[list[str]] = []

    def fake_run(args: list[str], **_: object) -> SimpleNamespace:
        calls.append(args)
        if "create" in args:
            profile = b"client\n<key>\nprivate\n</key>\n"
            payload = {
                "status": "active",
                "controller_id": "operator-core",
                "download_ready": True,
                "profile_b64": base64.b64encode(profile).decode("ascii"),
            }
        else:
            payload = {"status": "revoked", "controller_id": "operator-core"}
        return SimpleNamespace(returncode=0, stdout=json.dumps(payload), stderr="")

    monkeypatch.setattr(remote_access_runtime.subprocess, "run", fake_run)
    result = remote_access_runtime.create_remote_access_profile(
        {
            "provider": "openvpn",
            "name": "operator-core",
            "route_preset": "siem-core-admin",
        },
        actor="tester",
    )

    artifact, filename = remote_access_runtime.remote_access_profile_artifact(result["id"])
    assert result["status"] == "active"
    assert result["download_url"].endswith("/download")
    assert artifact.read_bytes().startswith(b"client\n")
    assert filename == "operator-core.ovpn"

    remote_access_runtime.delete_remote_access_profile(result["id"])
    assert not artifact.exists()
    assert any("create" in call for call in calls)
    assert any("revoke" in call for call in calls)
