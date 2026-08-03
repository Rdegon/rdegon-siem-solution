from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import importlib.util
import io
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
INSTALLER_PATH = ROOT / "deploy" / "vless" / "install_xui_controller.py"
SPEC = importlib.util.spec_from_file_location("install_xui_controller", INSTALLER_PATH)
assert SPEC and SPEC.loader
installer = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = installer
SPEC.loader.exec_module(installer)


class XuiDeployTests(unittest.TestCase):
    def _controller_env(self, directory: Path, *, listen: str = "127.0.0.1", password: str = "private-password") -> Path:
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / "controller.env"
        path.write_text(
            "\n".join(
                (
                    "XUI_PANEL_URL=http://127.0.0.1:2053",
                    "XUI_PANEL_USERNAME=local-operator",
                    f"XUI_PANEL_PASSWORD={password}",
                    "XUI_PUBLIC_HOST=vpn.example.net",
                    "XUI_PROTECTED_INBOUND_IDS=1,4,7",
                    "SIEM_XUI_CONTROLLER_TOKEN=0123456789abcdef0123456789abcdef",
                    f"SIEM_XUI_LISTEN_HOST={listen}",
                    "SIEM_XUI_LISTEN_PORT=8787",
                    "",
                )
            ),
            encoding="utf-8",
        )
        if os.name != "nt":
            path.chmod(0o600)
        return path

    def _tunnel_material(self, directory: Path) -> tuple[Path, Path, Path]:
        env = directory / "tunnel.env"
        env.write_text(
            "\n".join(
                (
                    "TUNNEL_KEY=/etc/siem/credentials/xui-controller-tunnel_ed25519",
                    "TUNNEL_KNOWN_HOSTS=/etc/siem/credentials/xui-controller-known_hosts",
                    "JUMP_USER=sentinel-tunnel",
                    "JUMP_HOST=jump.example.net",
                    "JUMP_PORT=22",
                    "JUMP_REMOTE_PORT=18787",
                    "CONTROLLER_LOCAL_PORT=8787",
                    "",
                )
            ),
            encoding="utf-8",
        )
        key = directory / "tunnel.key"
        key.write_text("test-private-key-material\n", encoding="utf-8")
        known_hosts = directory / "known_hosts"
        known_hosts.write_text("jump.example.net ssh-ed25519 AAAATESTPIN\n", encoding="utf-8")
        if os.name != "nt":
            env.chmod(0o600)
            key.chmod(0o600)
        return env, key, known_hosts

    def _args(self, stage: Path, controller: Path, tunnel: Path, key: Path, known_hosts: Path, *extra: str):
        return installer.build_parser().parse_args(
            [
                "--root",
                str(stage),
                "--controller-env-source",
                str(controller),
                "--tunnel-env-source",
                str(tunnel),
                "--tunnel-key-source",
                str(key),
                "--jump-known-hosts-source",
                str(known_hosts),
                *extra,
            ]
        )

    def test_default_is_a_read_only_plan_and_does_not_print_secrets(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            stage = base / "stage"
            controller = self._controller_env(base)
            tunnel, key, known_hosts = self._tunnel_material(base)
            stdout = io.StringIO()
            stderr = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                result = installer.main(
                    [
                        "--root",
                        str(stage),
                        "--controller-env-source",
                        str(controller),
                        "--tunnel-env-source",
                        str(tunnel),
                        "--tunnel-key-source",
                        str(key),
                        "--jump-known-hosts-source",
                        str(known_hosts),
                        "--enable-controller",
                        "--enable-tunnel",
                    ]
                )
            self.assertEqual(result, 0, stderr.getvalue())
            self.assertFalse(stage.exists())
            rendered = stdout.getvalue() + stderr.getvalue()
            self.assertNotIn("private-password", rendered)
            self.assertNotIn("0123456789abcdef0123456789abcdef", rendered)

    def test_apply_is_idempotent_and_installs_private_modes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            stage = base / "stage"
            controller = self._controller_env(base)
            tunnel, key, known_hosts = self._tunnel_material(base)
            args = self._args(stage, controller, tunnel, key, known_hosts, "--apply", "--skip-systemd")
            first = installer.install(args)
            destination = stage / "etc" / "siem" / "xui-controller.env"
            first_mtime = destination.stat().st_mtime_ns
            second = installer.install(args)
            self.assertEqual(first, second)
            self.assertEqual(destination.stat().st_mtime_ns, first_mtime)
            self.assertEqual(destination.read_bytes(), controller.read_bytes())
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o600)
                installed_key = stage / "etc" / "siem" / "credentials" / "xui-controller-tunnel_ed25519"
                self.assertEqual(stat.S_IMODE(installed_key.stat().st_mode), 0o600)

    def test_existing_secret_is_not_replaced_without_explicit_rotation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            stage = base / "stage"
            controller = self._controller_env(base)
            tunnel, key, known_hosts = self._tunnel_material(base)
            installer.install(self._args(stage, controller, tunnel, key, known_hosts, "--apply", "--skip-systemd"))
            replacement = self._controller_env(base / "replacement", password="different-private-password")
            with self.assertRaisesRegex(installer.InstallError, "Refusing to replace existing secret"):
                installer.install(self._args(stage, replacement, tunnel, key, known_hosts, "--apply", "--skip-systemd"))
            installed = stage / "etc" / "siem" / "xui-controller.env"
            self.assertNotIn("different-private-password", installed.read_text(encoding="utf-8"))

    def test_controller_rejects_public_panel_or_listen_addresses(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            public_listen = self._controller_env(base, listen="0.0.0.0")
            with self.assertRaisesRegex(installer.InstallError, "LISTEN_HOST must be loopback"):
                installer.validate_controller_env(public_listen)
            public_panel = base / "public-panel.env"
            public_panel.write_text(
                public_listen.read_text(encoding="utf-8")
                .replace("SIEM_XUI_LISTEN_HOST=0.0.0.0", "SIEM_XUI_LISTEN_HOST=127.0.0.1")
                .replace("http://127.0.0.1:2053", "http://45.89.111.208:2053"),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(installer.InstallError, "PANEL_URL must use HTTP on loopback"):
                installer.validate_controller_env(public_panel)

    def test_enable_tunnel_requires_pinned_configured_jump_host(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            stage = base / "stage"
            controller = self._controller_env(base)
            tunnel, key, known_hosts = self._tunnel_material(base)
            known_hosts.write_text("other.example.net ssh-ed25519 AAAATESTPIN\n", encoding="utf-8")
            with self.assertRaisesRegex(installer.InstallError, "does not contain the configured jump host"):
                installer.install(
                    self._args(
                        stage,
                        controller,
                        tunnel,
                        key,
                        known_hosts,
                        "--enable-controller",
                        "--enable-tunnel",
                    )
                )

    def test_units_keep_panel_and_reverse_forward_on_loopback(self) -> None:
        controller_unit = (ROOT / "deploy" / "vless" / "siem-xui-controller.service").read_text(encoding="utf-8")
        tunnel_unit = (ROOT / "deploy" / "vless" / "siem-xui-reverse-tunnel.service").read_text(encoding="utf-8")
        installer_source = INSTALLER_PATH.read_text(encoding="utf-8")
        self.assertIn("IPAddressDeny=any", controller_unit)
        self.assertIn("IPAddressAllow=localhost", controller_unit)
        self.assertIn("StrictHostKeyChecking=yes", tunnel_unit)
        self.assertIn("UserKnownHostsFile=${TUNNEL_KNOWN_HOSTS}", tunnel_unit)
        self.assertIn("-R 127.0.0.1:${JUMP_REMOTE_PORT}:127.0.0.1:${CONTROLLER_LOCAL_PORT}", tunnel_unit)
        self.assertNotIn("/panel/api/inbounds", installer_source)
        self.assertNotIn("ufw ", installer_source)
        self.assertNotIn("iptables ", installer_source)


if __name__ == "__main__":
    unittest.main()
