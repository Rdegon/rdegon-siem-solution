#!/usr/bin/env python3
"""Install the SIEM-side loopback bridge to a private 3x-ui controller."""

from __future__ import annotations

import argparse
import hmac
import importlib.util
import os
from pathlib import Path, PurePosixPath
import socket
import stat
import subprocess
import sys
import tempfile

try:
    import pwd
except ImportError:  # pragma: no cover - Windows staging/tests
    pwd = None  # type: ignore[assignment]


SOURCE_DIR = Path(__file__).resolve().parent
ENV_PATH = Path("/etc/siem/xui-vless-bridge.env")
URI_PATH = Path("/etc/siem/credentials/xui-controller-vless-uri")
URI_VALUE = "/etc/siem/credentials/xui-controller-vless-uri"
USER = "siem-xui-bridge"


class InstallError(RuntimeError):
    pass


def _rooted(root: Path, path: Path) -> Path:
    return root / str(path).lstrip("/\\")


def _parse_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise InstallError(f"Invalid bridge environment entry at line {number}")
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip("\"'")
    required = {
        "XUI_BRIDGE_URI_FILE",
        "XUI_BRIDGE_XRAY_BINARY",
        "XUI_BRIDGE_LISTEN_PORT",
        "XUI_CONTROLLER_TARGET_PORT",
    }
    missing = sorted(name for name in required if not values.get(name))
    if missing:
        raise InstallError(f"Missing bridge environment keys: {', '.join(missing)}")
    if values["XUI_BRIDGE_URI_FILE"] != URI_VALUE:
        raise InstallError(f"XUI_BRIDGE_URI_FILE must be {URI_VALUE}")
    binary_value = values["XUI_BRIDGE_XRAY_BINARY"]
    if not PurePosixPath(binary_value).is_absolute() or ".." in PurePosixPath(binary_value).parts:
        raise InstallError("XUI_BRIDGE_XRAY_BINARY must be an absolute path")
    for name in ("XUI_BRIDGE_LISTEN_PORT", "XUI_CONTROLLER_TARGET_PORT"):
        try:
            port = int(values[name])
        except ValueError as exc:
            raise InstallError(f"{name} must be an integer") from exc
        if not 1024 <= port <= 65535:
            raise InstallError(f"{name} must be an unprivileged TCP port")
    return values


def _validate_private(path: Path) -> None:
    if not path.is_file() or path.is_symlink():
        raise InstallError(f"Private source must be a regular file: {path}")
    if os.name != "nt" and stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise InstallError(f"Private source must not be group/world accessible: {path}")


def _validate_uri(path: Path) -> None:
    spec = importlib.util.spec_from_file_location("xui_vless_bridge_renderer", SOURCE_DIR / "render_xui_vless_bridge.py")
    if not spec or not spec.loader:
        raise InstallError("Unable to load VLESS bridge renderer")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    try:
        module.parse_vless_uri(path.read_text(encoding="utf-8").strip())
    except Exception as exc:  # noqa: BLE001
        raise InstallError(str(exc)) from exc


def _atomic_install(source: Path, destination: Path, mode: int) -> None:
    content = source.read_bytes()
    if destination.exists() and hmac.compare_digest(content, destination.read_bytes()):
        os.chmod(destination, mode)
        return
    destination.parent.mkdir(parents=True, exist_ok=True)
    handle, name = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent)
    temporary = Path(name)
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def _ensure_user() -> None:
    if pwd is None:
        raise InstallError("System-user provisioning is available only on Linux")
    try:
        pwd.getpwnam(USER)
    except KeyError:
        nologin = "/usr/sbin/nologin" if Path("/usr/sbin/nologin").exists() else "/bin/false"
        subprocess.run(
            ["useradd", "--system", "--no-create-home", "--home-dir", "/nonexistent", "--shell", nologin, USER],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )


def install(args: argparse.Namespace) -> list[str]:
    root = Path(args.root).resolve()
    env_source = Path(args.env_source).resolve()
    uri_source = Path(args.uri_source).resolve()
    values = _parse_env(env_source)
    _validate_private(env_source)
    _validate_private(uri_source)
    _validate_uri(uri_source)
    files = [
        (SOURCE_DIR / "render_xui_vless_bridge.py", _rooted(root, Path("/opt/rdegon-sentinel/render_xui_vless_bridge.py")), 0o755, False),
        (SOURCE_DIR / "run_xui_vless_bridge.py", _rooted(root, Path("/opt/rdegon-sentinel/run_xui_vless_bridge.py")), 0o755, False),
        (SOURCE_DIR / "siem-xui-vless-bridge.service", _rooted(root, Path("/etc/systemd/system/siem-xui-vless-bridge.service")), 0o644, False),
        (env_source, _rooted(root, ENV_PATH), 0o600, True),
        (uri_source, _rooted(root, URI_PATH), 0o600, True),
    ]
    for source, destination, _, secret in files:
        if secret and destination.exists() and not hmac.compare_digest(source.read_bytes(), destination.read_bytes()) and not args.rotate_secrets:
            raise InstallError(f"Refusing to replace existing secret file {destination}; use --rotate-secrets")
    actions = [f"install {destination} mode={mode:04o}" for _, destination, mode, _ in files]
    if args.enable:
        actions.append("enable loopback-only VLESS bridge")
    if not args.apply:
        return actions
    production = root == Path("/")
    if production and os.geteuid() != 0:
        raise InstallError("Production installation must run as root")
    if production:
        _ensure_user()
    for source, destination, mode, _ in files:
        _atomic_install(source, destination, mode)
    if production:
        assert pwd is not None
        account = pwd.getpwnam(USER)
        os.chown(URI_PATH, account.pw_uid, account.pw_gid)
        binary = Path(values["XUI_BRIDGE_XRAY_BINARY"])
        if not binary.is_file() or not os.access(binary, os.X_OK):
            raise InstallError(f"Configured Xray binary is not executable: {binary}")
    if not production or args.skip_systemd:
        return actions
    subprocess.run(["systemctl", "daemon-reload"], check=True, timeout=30)
    if args.enable:
        subprocess.run(["systemctl", "enable", "--now", "siem-xui-vless-bridge.service"], check=True, timeout=30)
        listen_port = int(values["XUI_BRIDGE_LISTEN_PORT"])
        try:
            with socket.create_connection(("127.0.0.1", listen_port), timeout=5):
                pass
        except OSError as exc:
            raise InstallError("VLESS bridge did not open its loopback listener") from exc
    return actions


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default="/")
    parser.add_argument("--env-source", required=True)
    parser.add_argument("--uri-source", required=True)
    parser.add_argument("--enable", action="store_true")
    parser.add_argument("--rotate-secrets", action="store_true")
    parser.add_argument("--skip-systemd", action="store_true")
    parser.add_argument("--apply", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        actions = install(build_parser().parse_args(argv))
    except InstallError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    print("APPLY" if "--apply" in (argv if argv is not None else sys.argv[1:]) else "PLAN")
    for action in actions:
        print(f"- {action}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
