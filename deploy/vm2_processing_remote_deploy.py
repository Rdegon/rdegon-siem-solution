from __future__ import annotations

import os
import posixpath
import shlex
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import paramiko
except ModuleNotFoundError:  # pragma: no cover
    paramiko = None  # type: ignore[assignment]


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REMOTE_ROOT = "/opt/siem/siem-solution"


@dataclass(frozen=True)
class FileMapping:
    local_rel: str
    remote_rel: str
    mode: str = "0644"


FILE_MAPPINGS: tuple[FileMapping, ...] = (
    FileMapping("services/__init__.py", "services/__init__.py"),
    FileMapping("services/redis_runtime.py", "services/redis_runtime.py"),
    FileMapping("services/transport_runtime.py", "services/transport_runtime.py"),
    FileMapping("deploy/kafka_cluster_layout.py", "deploy/kafka_cluster_layout.py"),
    FileMapping("deploy/kafka_wave_prepare.py", "deploy/kafka_wave_prepare.py"),
    FileMapping("services/normalizer/__init__.py", "services/normalizer/__init__.py"),
    FileMapping("services/normalizer/config.py", "services/normalizer/config.py"),
    FileMapping("services/normalizer/logging_conf.py", "services/normalizer/logging_conf.py"),
    FileMapping("services/normalizer/normalizer_core.py", "services/normalizer/normalizer_core.py"),
    FileMapping("services/normalizer/requirements.txt", "services/normalizer/requirements.txt"),
    FileMapping("services/normalizer/worker.py", "services/normalizer/worker.py"),
    FileMapping("services/filter/__init__.py", "services/filter/__init__.py"),
    FileMapping("services/filter/config.py", "services/filter/config.py"),
    FileMapping("services/filter/filter_core.py", "services/filter/filter_core.py"),
    FileMapping("services/filter/logging_conf.py", "services/filter/logging_conf.py"),
    FileMapping("services/filter/requirements.txt", "services/filter/requirements.txt"),
    FileMapping("services/filter/worker.py", "services/filter/worker.py"),
    FileMapping("deploy/vm2/siem-normalizer@.service", "deploy/vm2/siem-normalizer@.service"),
    FileMapping("deploy/vm2/siem-filter@.service", "deploy/vm2/siem-filter@.service"),
)

SYSTEMD_TEMPLATE_MAPPINGS: tuple[FileMapping, ...] = (
    FileMapping("deploy/vm2/siem-normalizer@.service", "/etc/systemd/system/siem-normalizer@.service"),
    FileMapping("deploy/vm2/siem-filter@.service", "/etc/systemd/system/siem-filter@.service"),
)

PROCESSING_UNITS = (
    "siem-normalizer.service",
    "siem-normalizer@1.service",
    "siem-normalizer@2.service",
    "siem-normalizer@3.service",
    "siem-filter.service",
    "siem-filter@1.service",
    "siem-filter@2.service",
    "siem-filter@3.service",
)


def _required_env(name: str, *, default: str | None = None) -> str:
    value = str(os.getenv(name, default or "") or "").strip()
    if value:
        return value
    raise SystemExit(f"Missing required environment variable: {name}")


def _remote_path(remote_root: str, rel_path: str) -> str:
    if rel_path.startswith("/"):
        return rel_path
    return posixpath.join(remote_root.rstrip("/"), rel_path.replace("\\", "/"))


def _resolve_local_path(mapping: FileMapping) -> Path:
    path = ROOT / mapping.local_rel
    if not path.exists():
        raise FileNotFoundError(f"Missing local file: {path}")
    return path


def _connect(host: str, user: str, password: str) -> Any:
    if paramiko is None:
        raise RuntimeError("paramiko is required for VM2 remote deploy")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        host,
        username=user,
        password=password,
        timeout=20,
        banner_timeout=20,
        auth_timeout=20,
        look_for_keys=False,
        allow_agent=False,
    )
    return client


def _run(client: Any, command: str, *, sudo_password: str = "", use_sudo: bool = False, timeout_sec: float = 120.0) -> tuple[int, str, str]:
    wrapped = f"sudo -S -p '' bash -lc {shlex.quote(command)}" if use_sudo else command
    stdin, stdout, stderr = client.exec_command(wrapped, timeout=timeout_sec, get_pty=use_sudo)
    if use_sudo:
        stdin.write(f"{sudo_password}\n")
        stdin.flush()
    stdin.close()
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    return stdout.channel.recv_exit_status(), out, err


def _mkdir_remote(sftp: Any, path: str) -> None:
    parts = [part for part in path.split("/") if part]
    current = ""
    for part in parts:
        current = f"{current}/{part}"
        try:
            sftp.stat(current)
        except OSError:
            sftp.mkdir(current)


def _install_file(client: Any, sftp: Any, mapping: FileMapping, *, remote_root: str, sudo_password: str, backup_root: str) -> None:
    local_path = _resolve_local_path(mapping)
    remote_path = _remote_path(remote_root, mapping.remote_rel)
    temp_path = posixpath.join("/tmp", f"siem-vm2-{Path(mapping.remote_rel).name}")
    _mkdir_remote(sftp, posixpath.dirname(temp_path))
    sftp.put(str(local_path), temp_path)
    backup_cmd = (
        f"if [ -f {shlex.quote(remote_path)} ]; then "
        f"install -d -m 0755 {shlex.quote(backup_root)} && "
        f"cp {shlex.quote(remote_path)} {shlex.quote(posixpath.join(backup_root, mapping.remote_rel.replace('/', '__').replace('@', '_')))}; "
        "fi"
    )
    code, _, err = _run(client, backup_cmd, sudo_password=sudo_password, use_sudo=True)
    if code != 0:
        raise RuntimeError(f"Unable to back up {remote_path}: {err.strip()}")
    install_cmd = (
        f"install -d -m 0755 {shlex.quote(posixpath.dirname(remote_path))} && "
        f"install -m {shlex.quote(mapping.mode)} {shlex.quote(temp_path)} {shlex.quote(remote_path)} && "
        f"rm -f {shlex.quote(temp_path)}"
    )
    code, _, err = _run(client, install_cmd, sudo_password=sudo_password, use_sudo=True)
    if code != 0:
        raise RuntimeError(f"Unable to install {remote_path}: {err.strip()}")


def main() -> int:
    host = _required_env("SIEM_VM2_HOST", default="192.168.1.37")
    user = _required_env("SIEM_VM2_USER", default="rdegon")
    password = _required_env("SIEM_VM2_PASSWORD")
    remote_root = _required_env("SIEM_VM2_BASE_DIR", default=DEFAULT_REMOTE_ROOT)
    backup_root = f"/tmp/siem-vm2-processing-backup-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
    mappings = (*FILE_MAPPINGS, *SYSTEMD_TEMPLATE_MAPPINGS)

    client = _connect(host, user, password)
    sftp = client.open_sftp()
    try:
        for mapping in mappings:
            _install_file(client, sftp, mapping, remote_root=remote_root, sudo_password=password, backup_root=backup_root)
            print(f"uploaded {mapping.local_rel} -> {_remote_path(remote_root, mapping.remote_rel)}")

        compile_targets = " ".join(
            shlex.quote(_remote_path(remote_root, mapping.remote_rel))
            for mapping in FILE_MAPPINGS
            if mapping.remote_rel.endswith(".py")
        )
        code, out, err = _run(
            client,
            f"cd {shlex.quote(remote_root)} && python3 -m py_compile {compile_targets}",
            sudo_password=password,
            use_sudo=True,
            timeout_sec=180,
        )
        if out.strip():
            print(out, end="")
        if code != 0:
            raise RuntimeError(f"VM2 py_compile failed: {err.strip()}")

        units = " ".join(shlex.quote(unit) for unit in PROCESSING_UNITS)
        restart_cmd = (
            "systemctl daemon-reload && "
            f"for unit in {units}; do systemctl cat \"$unit\" >/dev/null 2>&1 && systemctl try-restart \"$unit\" || true; done && "
            f"systemctl is-active {units} || true"
        )
        code, out, err = _run(client, restart_cmd, sudo_password=password, use_sudo=True, timeout_sec=180)
        if out.strip():
            print(out, end="")
        if code != 0:
            raise RuntimeError(f"VM2 processing restart failed: {err.strip()}")
        print("vm2_processing_remote_deploy=success")
        print(f"backup_root={backup_root}")
        return 0
    finally:
        sftp.close()
        client.close()


if __name__ == "__main__":
    sys.exit(main())
