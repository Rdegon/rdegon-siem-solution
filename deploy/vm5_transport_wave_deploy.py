from __future__ import annotations

import os
import posixpath
import shlex
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

try:
    import paramiko
except ModuleNotFoundError:  # pragma: no cover - exercised in CI/unit imports
    paramiko = None  # type: ignore[assignment]

if TYPE_CHECKING:  # pragma: no cover
    import paramiko as _paramiko


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REMOTE_ROOT = "/opt/siem/siem-solution"

for stream_name in ("stdout", "stderr"):
    stream = getattr(sys, stream_name, None)
    if stream is not None and hasattr(stream, "reconfigure"):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            pass


@dataclass(frozen=True)
class FileMapping:
    local_rel: str
    remote_rel: str


FILE_MAPPINGS: tuple[FileMapping, ...] = (
    FileMapping("services/__init__.py", "services/__init__.py"),
    FileMapping("services/redis_runtime.py", "services/redis_runtime.py"),
    FileMapping("services/transport_runtime.py", "services/transport_runtime.py"),
    FileMapping("services/normalizer/__init__.py", "services/normalizer/__init__.py"),
    FileMapping("services/normalizer/config.py", "services/normalizer/config.py"),
    FileMapping("services/normalizer/logging_conf.py", "services/normalizer/logging_conf.py"),
    FileMapping("services/normalizer/normalizer_core.py", "services/normalizer/normalizer_core.py"),
    FileMapping("services/normalizer/security_tool_normalizers.py", "services/normalizer/security_tool_normalizers.py"),
    FileMapping("services/normalizer/requirements.txt", "services/normalizer/requirements.txt"),
    FileMapping("services/normalizer/worker.py", "services/normalizer/worker.py"),
    FileMapping("services/filter/__init__.py", "services/filter/__init__.py"),
    FileMapping("services/filter/config.py", "services/filter/config.py"),
    FileMapping("services/filter/filter_core.py", "services/filter/filter_core.py"),
    FileMapping("services/filter/logging_conf.py", "services/filter/logging_conf.py"),
    FileMapping("services/filter/requirements.txt", "services/filter/requirements.txt"),
    FileMapping("services/filter/worker.py", "services/filter/worker.py"),
    FileMapping("deploy/kafka_cluster_layout.py", "deploy/kafka_cluster_layout.py"),
    FileMapping("deploy/kafka_wave_prepare.py", "deploy/kafka_wave_prepare.py"),
    FileMapping("deploy/kafka_wave_smoke.py", "deploy/kafka_wave_smoke.py"),
    FileMapping("deploy/vm5_processing_prepare.py", "deploy/vm5_processing_prepare.py"),
    FileMapping("deploy/vm5_processing_smoke.py", "deploy/vm5_processing_smoke.py"),
    FileMapping("deploy/vm5/siem-normalizer@.service", "deploy/vm5/siem-normalizer@.service"),
    FileMapping("deploy/vm5/siem-filter@.service", "deploy/vm5/siem-filter@.service"),
    FileMapping("deploy/vm5/siem-kafka.service", "deploy/vm5/siem-kafka.service"),
    FileMapping("deploy/vm5/systemd-networkd-wait-online.override.conf", "deploy/vm5/systemd-networkd-wait-online.override.conf"),
    FileMapping("docs/deployment_runbook_vm5_processing_wave_2026-03-22.md", "docs/deployment_runbook_vm5_processing_wave_2026-03-22.md"),
    FileMapping("docs/release_wave_kafka_vm5_2026-03-22.md", "docs/release_wave_kafka_vm5_2026-03-22.md"),
)


def _required_env(name: str, *, default: str | None = None) -> str:
    value = str(os.getenv(name, default or "") or "").strip()
    if value:
        return value
    raise SystemExit(f"Missing required environment variable: {name}")


def _remote_path(remote_root: str, rel_path: str) -> str:
    return posixpath.join(remote_root.rstrip("/"), rel_path.replace("\\", "/"))


def _resolve_local_path(mapping: FileMapping) -> Path:
    direct = ROOT / mapping.local_rel
    if direct.exists():
        return direct
    mirrored = ROOT / mapping.remote_rel
    if mirrored.exists():
        return mirrored
    raise FileNotFoundError(f"Missing local file: {direct}")


def _connect_client(host: str, user: str, password: str, *, attempts: int = 5, delay_seconds: float = 3.0) -> "paramiko.SSHClient":
    if paramiko is None:
        raise RuntimeError("paramiko is required to deploy VM5 transport wave")
    last_error: Exception | None = None
    for attempt in range(1, attempts + 1):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
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
        except Exception as exc:  # noqa: BLE001
            last_error = exc
            client.close()
            if attempt == attempts:
                break
            print(f"vm5_wave ssh retry host={host} attempt={attempt}/{attempts} error={exc}")
            time.sleep(delay_seconds)
    raise RuntimeError(f"Unable to connect to {host}: {last_error}")


def _run_command(client: "paramiko.SSHClient", command: str, *, sudo_password: str = "", use_sudo: bool = False) -> tuple[int, str, str]:
    wrapped = f"sudo -S -p '' bash -lc {shlex.quote(command)}" if use_sudo else command
    stdin, stdout, stderr = client.exec_command(wrapped, get_pty=use_sudo)
    if use_sudo:
        stdin.write(f"{sudo_password}\n")
        stdin.flush()
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    code = stdout.channel.recv_exit_status()
    return code, out, err


def _strip_sudo_echo(text: str, sudo_password: str) -> str:
    if not sudo_password:
        return text
    cleaned_lines: list[str] = []
    for raw_line in str(text or "").replace("\r", "\n").split("\n"):
        line = raw_line.strip("\x00")
        if line.strip() == sudo_password:
            continue
        cleaned_lines.append(line)
    return "\n".join(cleaned_lines)


def _mkdir_remote(sftp: "paramiko.SFTPClient", path: str) -> None:
    parts = [part for part in path.split("/") if part]
    current = ""
    for part in parts:
        current = f"{current}/{part}"
        try:
            sftp.stat(current)
        except OSError:
            sftp.mkdir(current)


def _upload_with_sudo_install(
    client: "paramiko.SSHClient",
    sftp: "paramiko.SFTPClient",
    *,
    local_path: Path,
    remote_path: str,
    temp_root: str,
    sudo_password: str,
    mode: str = "0644",
) -> None:
    temp_path = posixpath.join(temp_root.rstrip("/"), remote_path.lstrip("/"))
    _mkdir_remote(sftp, posixpath.dirname(temp_path))
    sftp.put(str(local_path), temp_path)
    command = (
        f"install -D -m {mode} {shlex.quote(temp_path)} {shlex.quote(remote_path)} "
        f"&& rm -f {shlex.quote(temp_path)}"
    )
    code, out, err = _run_command(client, command, sudo_password=sudo_password, use_sudo=True)
    cleaned = _strip_sudo_echo(out, sudo_password)
    if cleaned.strip():
        print(cleaned, end="")
    if code != 0:
        raise RuntimeError(f"Unable to install VM5 file {remote_path}: {err.strip()}")


def main() -> int:
    host = _required_env("SIEM_VM5_HOST", default="192.168.1.40")
    user = _required_env("SIEM_VM5_USER", default="rdegon")
    password = _required_env("SIEM_VM5_PASSWORD")
    remote_root = _required_env("SIEM_VM5_BASE_DIR", default=DEFAULT_REMOTE_ROOT)
    expected_host = _required_env("SIEM_VM5_EXPECT_HOST", default="siem-transport")

    client = _connect_client(host, user, password)
    try:
        backup_root = f"/tmp/siem-vm5-wave-backup-{datetime.now(tz=timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
        upload_root = f"/tmp/siem-vm5-wave-upload-{datetime.now(tz=timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
        code, out, err = _run_command(client, f"mkdir -p {shlex.quote(backup_root)}")
        if code != 0:
            raise RuntimeError(f"Unable to create VM5 backup root: {err.strip()}")
        code, out, err = _run_command(client, f"mkdir -p {shlex.quote(upload_root)}")
        if code != 0:
            raise RuntimeError(f"Unable to create VM5 upload root: {err.strip()}")

        sftp = client.open_sftp()
        try:
            for mapping in FILE_MAPPINGS:
                local_path = _resolve_local_path(mapping)
                remote_path = _remote_path(remote_root, mapping.remote_rel)
                code, out, err = _run_command(
                    client,
                    f"if [ -f {shlex.quote(remote_path)} ]; then cp {shlex.quote(remote_path)} {shlex.quote(posixpath.join(backup_root, mapping.remote_rel.replace('/', '__')))}; fi",
                    sudo_password=password,
                    use_sudo=True,
                )
                if code != 0:
                    raise RuntimeError(f"Unable to back up VM5 file {remote_path}: {err.strip()}")
                _upload_with_sudo_install(
                    client,
                    sftp,
                    local_path=local_path,
                    remote_path=remote_path,
                    temp_root=upload_root,
                    sudo_password=password,
                )
                print(f"uploaded {mapping.local_rel} -> {remote_path}")
        finally:
            sftp.close()

        compile_cmd = (
            f"cd {shlex.quote(remote_root)} && "
            "python3 -m py_compile "
            "services/__init__.py "
            "services/redis_runtime.py "
            "services/transport_runtime.py "
            "services/normalizer/__init__.py "
            "services/normalizer/config.py "
            "services/normalizer/logging_conf.py "
            "services/normalizer/normalizer_core.py "
            "services/normalizer/worker.py "
            "services/filter/__init__.py "
            "services/filter/config.py "
            "services/filter/filter_core.py "
            "services/filter/logging_conf.py "
            "services/filter/worker.py "
            "deploy/kafka_cluster_layout.py "
            "deploy/kafka_wave_prepare.py "
            "deploy/kafka_wave_smoke.py "
            "deploy/vm5_processing_prepare.py "
            "deploy/vm5_processing_smoke.py"
        )
        code, out, err = _run_command(client, compile_cmd, sudo_password=password, use_sudo=True)
        cleaned = _strip_sudo_echo(out, password)
        if cleaned.strip():
            print(cleaned, end="")
        if code != 0:
            raise RuntimeError(f"VM5 py_compile failed: {err.strip()}")

        processing_cmd = (
            f"cd {shlex.quote(remote_root)} && "
            f"SIEM_VM5_PASSWORD={shlex.quote(password)} "
            f"SIEM_VM5_EXPECT_HOST={shlex.quote(expected_host)} "
            "SIEM_VM5_ENABLE_PROCESSING=1 "
            "python3 deploy/vm5_processing_prepare.py"
        )
        code, out, err = _run_command(client, processing_cmd)
        if out.strip():
            print(out, end="")
        if code != 0:
            raise RuntimeError(f"VM5 processing prepare failed: {err.strip()}")

        kafka_cmd = (
            f"cd {shlex.quote(remote_root)} && "
            f"SIEM_NODE_PASSWORD={shlex.quote(password)} "
            "SIEM_KAFKA_NODE_ID=3 "
            f"SIEM_KAFKA_EXPECT_HOST={shlex.quote(expected_host)} "
            "python3 deploy/kafka_wave_prepare.py"
        )
        code, out, err = _run_command(client, kafka_cmd)
        cleaned = _strip_sudo_echo(out, password)
        if cleaned.strip():
            print(cleaned, end="")
        if code != 0:
            raise RuntimeError(f"VM5 Kafka prepare failed: {err.strip()}")

        print("deployment=success")
        print(f"backup_root={backup_root}")
        return 0
    finally:
        client.close()


if __name__ == "__main__":
    sys.exit(main())
