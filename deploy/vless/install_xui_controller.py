#!/usr/bin/env python3
"""Install the loopback-only Sentinel controller beside an existing 3x-ui.

The installer never calls the 3x-ui API, changes firewall rules, or manages
Xray/3x-ui services. Secret files must be provisioned out of band and are
preserved unless an explicit rotation is requested.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hmac
import ipaddress
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import tempfile
import time
from typing import Iterable
from urllib import parse as url_parse
from urllib import request as url_request

try:
    import pwd
except ImportError:  # pragma: no cover - Windows staging/tests
    pwd = None  # type: ignore[assignment]


SOURCE_DIR = Path(__file__).resolve().parent
CONTROLLER_USER = "siem-xui-controller"
TUNNEL_USER = "siem-xui-tunnel"
CONTROLLER_ENV_PATH = Path("/etc/siem/xui-controller.env")
TUNNEL_ENV_PATH = Path("/etc/siem/xui-tunnel.env")
TUNNEL_KEY_VALUE = "/etc/siem/credentials/xui-controller-tunnel_ed25519"
KNOWN_HOSTS_VALUE = "/etc/siem/credentials/xui-controller-known_hosts"
TUNNEL_KEY_PATH = Path(TUNNEL_KEY_VALUE)
KNOWN_HOSTS_PATH = Path(KNOWN_HOSTS_VALUE)
PLACEHOLDER_VALUES = {"replace-in-runtime", "changeme", "example"}


class InstallError(RuntimeError):
    pass


@dataclass(frozen=True)
class ManagedFile:
    source: Path
    destination: Path
    mode: int
    secret: bool = False
    owner: str = "root"


def rooted(root: Path, absolute: Path) -> Path:
    return root / str(absolute).lstrip("/\\")


def parse_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].strip()
        if "=" not in line:
            raise InstallError(f"Invalid environment entry at line {line_number}")
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if value[:1] == value[-1:] and value[:1] in {'"', "'"}:
            value = value[1:-1]
        if not key or any(character.isspace() for character in key):
            raise InstallError(f"Invalid environment key at line {line_number}")
        if "\n" in value or "\r" in value:
            raise InstallError(f"Invalid environment value at line {line_number}")
        values[key] = value
    return values


def _required(values: dict[str, str], names: Iterable[str]) -> None:
    missing = [name for name in names if not values.get(name)]
    if missing:
        raise InstallError(f"Missing required environment keys: {', '.join(missing)}")


def _is_placeholder(value: str) -> bool:
    lowered = value.strip().lower()
    return lowered in PLACEHOLDER_VALUES or (lowered.startswith("<") and lowered.endswith(">"))


def _loopback_host(value: str) -> bool:
    if value.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(value).is_loopback
    except ValueError:
        return False


def validate_controller_env(path: Path) -> dict[str, str]:
    values = parse_env_file(path)
    _required(
        values,
        (
            "XUI_PANEL_URL",
            "XUI_PANEL_USERNAME",
            "XUI_PANEL_PASSWORD",
            "SIEM_XUI_CONTROLLER_TOKEN",
            "SIEM_XUI_LISTEN_HOST",
            "SIEM_XUI_LISTEN_PORT",
        ),
    )
    parsed = url_parse.urlparse(values["XUI_PANEL_URL"])
    if parsed.scheme != "http" or not parsed.hostname or not _loopback_host(parsed.hostname):
        raise InstallError("XUI_PANEL_URL must use HTTP on loopback")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise InstallError("XUI_PANEL_URL must not contain credentials, query, or fragment")
    if not _loopback_host(values["SIEM_XUI_LISTEN_HOST"]):
        raise InstallError("SIEM_XUI_LISTEN_HOST must be loopback")
    for name in ("XUI_PANEL_USERNAME", "XUI_PANEL_PASSWORD", "SIEM_XUI_CONTROLLER_TOKEN"):
        if _is_placeholder(values[name]):
            raise InstallError(f"{name} still contains a placeholder")
    if len(values["SIEM_XUI_CONTROLLER_TOKEN"]) < 32:
        raise InstallError("SIEM_XUI_CONTROLLER_TOKEN must contain at least 32 characters")
    inbound_ids_value = values.get("XUI_PROTECTED_INBOUND_IDS", "auto").strip().lower()
    inbound_ids = [item.strip() for item in inbound_ids_value.split(",") if item.strip() and item.strip() != "auto"]
    if any(not item.isdigit() or int(item) <= 0 for item in inbound_ids):
        raise InstallError("XUI_PROTECTED_INBOUND_IDS must be 'auto' or a comma-separated list of positive IDs")
    state_path = values.get("XUI_PROTECTION_STATE", "/var/lib/siem-xui-controller/protection.json")
    if state_path != "/var/lib/siem-xui-controller/protection.json":
        raise InstallError("XUI_PROTECTION_STATE must remain inside the controller StateDirectory")
    allow_create = values.get("XUI_ALLOW_INBOUND_CREATE", "false").strip().lower()
    if allow_create not in {"0", "1", "false", "true", "no", "yes", "off", "on"}:
        raise InstallError("XUI_ALLOW_INBOUND_CREATE must be a boolean")
    try:
        listen_port = int(values["SIEM_XUI_LISTEN_PORT"])
    except ValueError as exc:
        raise InstallError("SIEM_XUI_LISTEN_PORT must be an integer") from exc
    if not 1024 <= listen_port <= 65535:
        raise InstallError("SIEM_XUI_LISTEN_PORT must be an unprivileged TCP port")
    integer_limits = {
        "SIEM_XUI_MAX_BODY_BYTES": (1024, 1024 * 1024, 256 * 1024),
        "SIEM_XUI_MAX_CONCURRENT_REQUESTS": (1, 256, 32),
    }
    for name, (minimum, maximum, default) in integer_limits.items():
        try:
            value = int(values.get(name, str(default)))
        except ValueError as exc:
            raise InstallError(f"{name} must be an integer") from exc
        if not minimum <= value <= maximum:
            raise InstallError(f"{name} must be between {minimum} and {maximum}")
    try:
        request_timeout = float(values.get("SIEM_XUI_REQUEST_TIMEOUT_SECONDS", "10"))
    except ValueError as exc:
        raise InstallError("SIEM_XUI_REQUEST_TIMEOUT_SECONDS must be numeric") from exc
    if not 1 <= request_timeout <= 60:
        raise InstallError("SIEM_XUI_REQUEST_TIMEOUT_SECONDS must be between 1 and 60")
    return values


def validate_tunnel_env(path: Path) -> dict[str, str]:
    values = parse_env_file(path)
    _required(
        values,
        (
            "TUNNEL_KEY",
            "TUNNEL_KNOWN_HOSTS",
            "JUMP_USER",
            "JUMP_HOST",
            "JUMP_PORT",
            "JUMP_REMOTE_PORT",
            "CONTROLLER_LOCAL_PORT",
        ),
    )
    if values["TUNNEL_KEY"] != TUNNEL_KEY_VALUE:
        raise InstallError(f"TUNNEL_KEY must be {TUNNEL_KEY_VALUE}")
    if values["TUNNEL_KNOWN_HOSTS"] != KNOWN_HOSTS_VALUE:
        raise InstallError(f"TUNNEL_KNOWN_HOSTS must be {KNOWN_HOSTS_VALUE}")
    if _is_placeholder(values["JUMP_USER"]) or _is_placeholder(values["JUMP_HOST"]):
        raise InstallError("Jump-host identity still contains a placeholder")
    if any(character.isspace() for character in values["JUMP_USER"] + values["JUMP_HOST"]):
        raise InstallError("Jump-host identity contains whitespace")
    try:
        jump_port = int(values["JUMP_PORT"])
        remote_port = int(values["JUMP_REMOTE_PORT"])
        controller_port = int(values["CONTROLLER_LOCAL_PORT"])
    except ValueError as exc:
        raise InstallError("Tunnel ports must be integers") from exc
    if not 1 <= jump_port <= 65535:
        raise InstallError("JUMP_PORT is out of range")
    if not 1024 <= remote_port <= 65535:
        raise InstallError("JUMP_REMOTE_PORT must be an unprivileged TCP port")
    if not 1024 <= controller_port <= 65535:
        raise InstallError("CONTROLLER_LOCAL_PORT must be an unprivileged TCP port")
    return values


def validate_private_source(path: Path) -> None:
    if not path.is_file():
        raise InstallError(f"Required private source is missing: {path}")
    if os.name != "nt" and stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise InstallError(f"Private source must not be group/world accessible: {path}")


def validate_known_hosts(path: Path, jump_host: str, jump_port: int) -> None:
    if not path.is_file():
        raise InstallError(f"Pinned jump-host known_hosts file is missing: {path}")
    expected = {jump_host} if jump_port == 22 else {f"[{jump_host}]:{jump_port}"}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        if len(fields) >= 3 and expected.intersection(fields[0].split(",")):
            return
    raise InstallError("Pinned known_hosts does not contain the configured jump host")


def ensure_same_or_rotatable(source: Path, destination: Path, *, rotate: bool) -> None:
    if not destination.exists() or hmac.compare_digest(source.read_bytes(), destination.read_bytes()):
        return
    if not rotate:
        raise InstallError(
            f"Refusing to replace existing secret file {destination}; use --rotate-secrets after an approved rotation"
        )


def atomic_install(source: Path, destination: Path, mode: int) -> bool:
    content = source.read_bytes()
    if destination.exists() and hmac.compare_digest(content, destination.read_bytes()):
        os.chmod(destination, mode)
        return False
    destination.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary_name = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)
    return True


def _run(command: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=check, capture_output=True, text=True, timeout=30)


def ensure_system_user(name: str) -> None:
    if pwd is None:
        raise InstallError("System-user provisioning is available only on Linux")
    try:
        pwd.getpwnam(name)
        return
    except KeyError:
        pass
    nologin = next((path for path in ("/usr/sbin/nologin", "/sbin/nologin") if Path(path).exists()), "/bin/false")
    _run(["useradd", "--system", "--no-create-home", "--home-dir", "/nonexistent", "--shell", nologin, name])


def _chown(path: Path, owner: str) -> None:
    if pwd is None:
        raise InstallError("Ownership provisioning is available only on Linux")
    account = pwd.getpwnam(owner)
    os.chown(path, account.pw_uid, account.pw_gid)


def panel_socket_ready(values: dict[str, str], timeout: float = 2.0) -> bool:
    parsed = url_parse.urlparse(values["XUI_PANEL_URL"])
    port = parsed.port or 80
    try:
        with socket.create_connection((str(parsed.hostname), port), timeout=timeout):
            return True
    except OSError:
        return False


def controller_health(values: dict[str, str], attempts: int = 15) -> bool:
    host = values["SIEM_XUI_LISTEN_HOST"]
    if host == "::1":
        host = "[::1]"
    url = f"http://{host}:{values['SIEM_XUI_LISTEN_PORT']}/health"
    for _ in range(attempts):
        request = url_request.Request(
            url,
            headers={"Authorization": f"Bearer {values['SIEM_XUI_CONTROLLER_TOKEN']}"},
        )
        try:
            with url_request.urlopen(request, timeout=3) as response:  # noqa: S310 - validated loopback
                if response.status == 200:
                    return True
        except OSError:
            time.sleep(1)
    return False


def managed_files(
    root: Path,
    *,
    controller_env_source: Path | None,
    tunnel_env_source: Path | None,
    tunnel_key_source: Path | None,
    known_hosts_source: Path | None,
) -> list[ManagedFile]:
    files = [
        ManagedFile(SOURCE_DIR / "siem_xui_controller.py", rooted(root, Path("/opt/rdegon-sentinel/siem_xui_controller.py")), 0o755),
        ManagedFile(SOURCE_DIR / "siem-xui-controller.service", rooted(root, Path("/etc/systemd/system/siem-xui-controller.service")), 0o644),
        ManagedFile(SOURCE_DIR / "siem-xui-reverse-tunnel.service", rooted(root, Path("/etc/systemd/system/siem-xui-reverse-tunnel.service")), 0o644),
    ]
    optional = (
        (controller_env_source, rooted(root, CONTROLLER_ENV_PATH), 0o600, "root"),
        (tunnel_env_source, rooted(root, TUNNEL_ENV_PATH), 0o600, "root"),
        (tunnel_key_source, rooted(root, TUNNEL_KEY_PATH), 0o600, TUNNEL_USER),
        (known_hosts_source, rooted(root, KNOWN_HOSTS_PATH), 0o644, "root"),
    )
    for source, destination, mode, owner in optional:
        if source is not None:
            files.append(ManagedFile(source, destination, mode, secret=True, owner=owner))
    return files


def existing_or_source(root: Path, destination: Path, source: Path | None) -> Path | None:
    if source is not None:
        return source
    installed = rooted(root, destination)
    return installed if installed.exists() else None


def install(args: argparse.Namespace) -> list[str]:
    root = Path(args.root).resolve()
    controller_env_source = Path(args.controller_env_source).resolve() if args.controller_env_source else None
    tunnel_env_source = Path(args.tunnel_env_source).resolve() if args.tunnel_env_source else None
    tunnel_key_source = Path(args.tunnel_key_source).resolve() if args.tunnel_key_source else None
    known_hosts_source = Path(args.jump_known_hosts_source).resolve() if args.jump_known_hosts_source else None

    controller_env = existing_or_source(root, CONTROLLER_ENV_PATH, controller_env_source)
    tunnel_env = existing_or_source(root, TUNNEL_ENV_PATH, tunnel_env_source)
    tunnel_key = existing_or_source(root, TUNNEL_KEY_PATH, tunnel_key_source)
    known_hosts = existing_or_source(root, KNOWN_HOSTS_PATH, known_hosts_source)

    controller_values = validate_controller_env(controller_env) if controller_env else None
    tunnel_values = validate_tunnel_env(tunnel_env) if tunnel_env else None
    for private_source in (controller_env_source, tunnel_env_source, tunnel_key_source):
        if private_source is not None:
            validate_private_source(private_source)
    if known_hosts_source is not None and not known_hosts_source.is_file():
        raise InstallError(f"Pinned jump-host known_hosts file is missing: {known_hosts_source}")
    if args.enable_controller and controller_values is None:
        raise InstallError("Controller environment is required before enabling the controller")
    if args.enable_tunnel:
        if not args.enable_controller:
            raise InstallError("--enable-tunnel requires --enable-controller")
        if tunnel_values is None or tunnel_key is None or known_hosts is None:
            raise InstallError("Tunnel environment, private key, and pinned known_hosts are required")
        validate_known_hosts(known_hosts, tunnel_values["JUMP_HOST"], int(tunnel_values["JUMP_PORT"]))
        if controller_values and tunnel_values["CONTROLLER_LOCAL_PORT"] != controller_values["SIEM_XUI_LISTEN_PORT"]:
            raise InstallError("CONTROLLER_LOCAL_PORT must match SIEM_XUI_LISTEN_PORT")

    files = managed_files(
        root,
        controller_env_source=controller_env_source,
        tunnel_env_source=tunnel_env_source,
        tunnel_key_source=tunnel_key_source,
        known_hosts_source=known_hosts_source,
    )
    for item in files:
        if item.secret:
            ensure_same_or_rotatable(item.source, item.destination, rotate=args.rotate_secrets)

    actions = [f"install {item.destination} mode={item.mode:04o}" for item in files]
    if args.enable_controller:
        actions.append("snapshot existing inbounds as immutable and enable controller after local 3x-ui preflight")
    if args.enable_tunnel:
        actions.append("enable loopback-only reverse tunnel")
    if not args.apply:
        return actions

    production_root = root == Path("/")
    if production_root and (not hasattr(os, "geteuid") or os.geteuid() != 0):
        raise InstallError("Production installation must run as root")
    if production_root:
        ensure_system_user(CONTROLLER_USER)
        ensure_system_user(TUNNEL_USER)
    for directory, mode in (
        (rooted(root, Path("/opt/rdegon-sentinel")), 0o750),
        (rooted(root, Path("/etc/siem")), 0o750),
        (rooted(root, Path("/etc/siem/credentials")), 0o700),
    ):
        directory.mkdir(parents=True, exist_ok=True)
        os.chmod(directory, mode)
    for item in files:
        atomic_install(item.source, item.destination, item.mode)
        if production_root:
            _chown(item.destination, item.owner)

    if not production_root or args.skip_systemd:
        return actions
    _run(["systemctl", "daemon-reload"])
    if args.enable_controller:
        assert controller_values is not None
        if not panel_socket_ready(controller_values):
            raise InstallError("Existing 3x-ui loopback panel is not reachable; no service was enabled")
        if _run(["systemctl", "is-active", "--quiet", "x-ui.service"], check=False).returncode != 0:
            raise InstallError("Existing x-ui.service is not active; installer will not start or modify it")
        _run(["systemctl", "enable", "--now", "siem-xui-controller.service"])
        _run(["systemctl", "restart", "siem-xui-controller.service"])
        if not controller_health(controller_values):
            raise InstallError("Controller health check failed; inspect the local service journal")
    if args.enable_tunnel:
        _run(["systemctl", "enable", "--now", "siem-xui-reverse-tunnel.service"])
        _run(["systemctl", "restart", "siem-xui-reverse-tunnel.service"])
        if _run(["systemctl", "is-active", "--quiet", "siem-xui-reverse-tunnel.service"], check=False).returncode != 0:
            raise InstallError("Reverse tunnel did not become active")
    return actions


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default="/", help="Alternate root for staging/tests")
    parser.add_argument("--controller-env-source")
    parser.add_argument("--tunnel-env-source")
    parser.add_argument("--tunnel-key-source")
    parser.add_argument("--jump-known-hosts-source")
    parser.add_argument("--enable-controller", action="store_true")
    parser.add_argument("--enable-tunnel", action="store_true")
    parser.add_argument("--rotate-secrets", action="store_true")
    parser.add_argument("--skip-systemd", action="store_true")
    parser.add_argument("--apply", action="store_true", help="Apply the plan; default is read-only planning")
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
