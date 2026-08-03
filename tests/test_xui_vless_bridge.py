from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import stat
import tempfile

import pytest


ROOT = Path(__file__).resolve().parents[1]


def _module(filename: str, name: str):
    path = ROOT / "deploy" / "vless" / filename
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _uri() -> str:
    return (
        "vless://86ddcb83-1b80-4f4f-8144-2be5809d054e@45.89.111.208:443"
        "?encryption=none&security=reality&type=tcp&flow=xtls-rprx-vision"
        "&sni=www.example.com&fp=chrome&pbk=public-key&sid=0123456789abcdef#controller"
    )


def test_bridge_renders_a_loopback_only_dokodemo_target() -> None:
    renderer = _module("render_xui_vless_bridge.py", "xui_bridge_renderer")
    profile = renderer.parse_vless_uri(_uri())
    config = renderer.render_config(profile)

    inbound = config["inbounds"][0]
    assert inbound["listen"] == "127.0.0.1"
    assert inbound["port"] == 18787
    assert inbound["settings"] == {"address": "127.0.0.1", "port": 8787, "network": "tcp"}
    outbound = config["outbounds"][0]
    assert outbound["settings"]["vnext"][0]["address"] == "45.89.111.208"
    assert outbound["streamSettings"]["realitySettings"]["publicKey"] == "public-key"


def test_bridge_rejects_public_management_targets() -> None:
    renderer = _module("render_xui_vless_bridge.py", "xui_bridge_public_reject")
    with pytest.raises(ValueError, match="loopback"):
        renderer.render_config(renderer.parse_vless_uri(_uri()), target_host="45.89.111.208")
    with pytest.raises(ValueError, match="loopback"):
        renderer.render_config(renderer.parse_vless_uri(_uri()), listen_host="0.0.0.0")


def test_bridge_installer_is_plan_only_by_default_and_keeps_secrets_private() -> None:
    installer = _module("install_xui_vless_bridge.py", "xui_bridge_installer")
    with tempfile.TemporaryDirectory() as temporary:
        base = Path(temporary)
        root = base / "stage"
        env = base / "bridge.env"
        env.write_text(
            "\n".join(
                (
                    "XUI_BRIDGE_URI_FILE=/etc/siem/credentials/xui-controller-vless-uri",
                    "XUI_BRIDGE_XRAY_BINARY=/usr/local/bin/xray",
                    "XUI_BRIDGE_LISTEN_PORT=18787",
                    "XUI_CONTROLLER_TARGET_PORT=8787",
                    "",
                )
            ),
            encoding="utf-8",
        )
        uri = base / "profile.uri"
        uri.write_text(_uri(), encoding="utf-8")
        if os.name != "nt":
            env.chmod(0o600)
            uri.chmod(0o600)
        args = installer.build_parser().parse_args(
            ["--root", str(root), "--env-source", str(env), "--uri-source", str(uri)]
        )

        actions = installer.install(args)

        assert actions
        assert not root.exists()
        assert all("86ddcb83" not in action and "public-key" not in action for action in actions)


def test_bridge_installer_stages_idempotently() -> None:
    installer = _module("install_xui_vless_bridge.py", "xui_bridge_stage_installer")
    with tempfile.TemporaryDirectory() as temporary:
        base = Path(temporary)
        root = base / "stage"
        env = base / "bridge.env"
        env.write_text(
            "XUI_BRIDGE_URI_FILE=/etc/siem/credentials/xui-controller-vless-uri\n"
            "XUI_BRIDGE_XRAY_BINARY=/usr/local/bin/xray\n"
            "XUI_BRIDGE_LISTEN_PORT=18787\n"
            "XUI_CONTROLLER_TARGET_PORT=8787\n",
            encoding="utf-8",
        )
        uri = base / "profile.uri"
        uri.write_text(_uri(), encoding="utf-8")
        if os.name != "nt":
            env.chmod(0o600)
            uri.chmod(0o600)
        args = installer.build_parser().parse_args(
            [
                "--root",
                str(root),
                "--env-source",
                str(env),
                "--uri-source",
                str(uri),
                "--apply",
                "--skip-systemd",
            ]
        )
        installer.install(args)
        installer.install(args)

        installed_uri = root / "etc" / "siem" / "credentials" / "xui-controller-vless-uri"
        installed_wrapper = root / "opt" / "rdegon-sentinel" / "run_xui_vless_bridge.py"
        assert installed_uri.read_text(encoding="utf-8") == _uri()
        assert installed_wrapper.is_file()
        assert "os.execv" in installed_wrapper.read_text(encoding="utf-8")
        if os.name != "nt":
            assert stat.S_IMODE(installed_uri.stat().st_mode) == 0o600


def test_bridge_unit_uses_a_fixed_exec_wrapper() -> None:
    unit = (ROOT / "deploy" / "vless" / "siem-xui-vless-bridge.service").read_text(encoding="utf-8")
    wrapper = (ROOT / "deploy" / "vless" / "run_xui_vless_bridge.py").read_text(encoding="utf-8")

    assert "ExecStart=/usr/bin/python3 /opt/rdegon-sentinel/run_xui_vless_bridge.py" in unit
    assert "ExecStart=${XUI_BRIDGE_XRAY_BINARY}" not in unit
    assert "os.execv" in wrapper
