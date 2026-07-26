from __future__ import annotations

import os
import posixpath
import shlex
import sys
import time
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
class HostWave:
    name: str
    host_env: str
    user_env: str
    password_env: str
    default_host: str
    files: tuple[str, ...]
    units: tuple[str, ...]
    python: str


WAVES = (
    HostWave(
        name="storage",
        host_env="SIEM_VM3_HOST",
        user_env="SIEM_VM3_USER",
        password_env="SIEM_VM3_PASSWORD",
        default_host="10.20.10.106",
        files=(
            "services/transport_runtime.py",
            "services/writer/worker.py",
            "sql/18_security_analytics_schema.sql",
        ),
        units=("siem-writer.service", "siem-writer@2.service"),
        python="/opt/siem/venv-storage/bin/python",
    ),
    HostWave(
        name="processing",
        host_env="SIEM_VM2_HOST",
        user_env="SIEM_VM2_USER",
        password_env="SIEM_VM2_PASSWORD",
        default_host="10.20.10.105",
        files=(
            "services/transport_runtime.py",
            "services/normalizer/normalizer_core.py",
            "services/normalizer/security_tool_normalizers.py",
        ),
        units=(
            "siem-normalizer.service",
            "siem-normalizer@1.service",
            "siem-normalizer@2.service",
            "siem-normalizer@3.service",
        ),
        python="/opt/siem/venv-processing/bin/python",
    ),
    HostWave(
        name="transport",
        host_env="SIEM_VM5_HOST",
        user_env="SIEM_VM5_USER",
        password_env="SIEM_VM5_PASSWORD",
        default_host="10.20.10.108",
        files=(
            "services/transport_runtime.py",
            "services/normalizer/normalizer_core.py",
            "services/normalizer/security_tool_normalizers.py",
        ),
        units=(
            "siem-normalizer.service",
            "siem-normalizer@1.service",
            "siem-normalizer@2.service",
            "siem-normalizer@3.service",
        ),
        python="/opt/siem/venv-transport/bin/python",
    ),
)


def _required_env(name: str, default: str = "") -> str:
    value = str(os.getenv(name, default) or "").strip()
    if not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value


def _connect(host: str, user: str, password: str) -> Any:
    if paramiko is None:
        raise RuntimeError("paramiko is required for the security analytics deployment wave")
    last_error: Exception | None = None
    for attempt in range(1, 6):
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
            if attempt < 5:
                time.sleep(2)
    raise RuntimeError(f"Unable to connect to {host}: {last_error}")


def _run(
    client: Any,
    command: str,
    *,
    password: str = "",
    sudo: bool = False,
    timeout: int = 180,
) -> tuple[int, str, str]:
    wrapped = f"sudo -S -p '' bash -lc {shlex.quote(command)}" if sudo else command
    stdin, stdout, stderr = client.exec_command(wrapped, timeout=timeout, get_pty=sudo)
    if sudo:
        stdin.write(f"{password}\n")
        stdin.flush()
    stdin.close()
    output = stdout.read().decode("utf-8", errors="replace")
    error = stderr.read().decode("utf-8", errors="replace")
    code = stdout.channel.recv_exit_status()
    return code, _strip_secret_echo(output, password), _strip_secret_echo(error, password)


def _strip_secret_echo(text: str, secret: str) -> str:
    if not secret:
        return str(text or "")
    return "\n".join(line for line in str(text or "").replace("\r", "\n").split("\n") if line.strip() != secret)


def _mkdir_sftp(sftp: Any, path: str) -> None:
    current = ""
    for part in [item for item in path.split("/") if item]:
        current = f"{current}/{part}"
        try:
            sftp.stat(current)
        except OSError:
            sftp.mkdir(current)


def _upload_file(
    client: Any,
    sftp: Any,
    *,
    local_path: Path,
    remote_path: str,
    backup_root: str,
    password: str,
) -> None:
    temp_path = f"/tmp/siem-security-analytics-{local_path.name}"
    sftp.put(str(local_path), temp_path)
    backup_path = posixpath.join(backup_root, remote_path.lstrip("/").replace("/", "__"))
    command = (
        f"install -d -m 0750 {shlex.quote(posixpath.dirname(remote_path))} {shlex.quote(backup_root)} && "
        f"if [ -f {shlex.quote(remote_path)} ]; then cp -a {shlex.quote(remote_path)} {shlex.quote(backup_path)}; fi && "
        f"install -m 0644 {shlex.quote(temp_path)} {shlex.quote(remote_path)} && "
        f"rm -f {shlex.quote(temp_path)}"
    )
    code, _, error = _run(client, command, password=password, sudo=True)
    if code != 0:
        raise RuntimeError(f"Unable to install {remote_path}: {error.strip()}")


def _compile(client: Any, wave: HostWave, remote_root: str, password: str) -> None:
    python_files = [posixpath.join(remote_root, path) for path in wave.files if path.endswith(".py")]
    if not python_files:
        return
    python_bin = wave.python
    command = (
        f"test -x {shlex.quote(python_bin)} || python_bin=/usr/bin/python3; "
        f"${{python_bin:-{shlex.quote(python_bin)}}} -m py_compile "
        + " ".join(shlex.quote(path) for path in python_files)
    )
    code, _, error = _run(client, command, password=password, sudo=True)
    if code != 0:
        raise RuntimeError(f"{wave.name} py_compile failed: {error.strip()}")


def _apply_clickhouse_schema(client: Any, remote_root: str, password: str) -> None:
    schema_path = posixpath.join(remote_root, "sql/18_security_analytics_schema.sql")
    command = (
        "set -a; "
        "[ ! -f /etc/siem/storage.env ] || . /etc/siem/storage.env; "
        "set +a; "
        "host=\"${SIEM_CH_HOST:-127.0.0.1}\"; "
        "port=\"${SIEM_CH_PORT:-9000}\"; "
        "user=\"${SIEM_CH_USER:-default}\"; "
        "clickhouse-client --host \"$host\" --port \"$port\" --user \"$user\" "
        "--password \"${SIEM_CH_PASSWORD:-}\" --multiquery "
        f"< {shlex.quote(schema_path)}"
    )
    code, _, error = _run(client, command, password=password, sudo=True, timeout=300)
    if code != 0:
        raise RuntimeError(f"ClickHouse security analytics schema failed: {error.strip()}")
    verify_query = (
        "SELECT count() FROM system.columns "
        "WHERE database='siem' AND table='events' "
        "AND name IN ('community_id','file_sha256','container_id','vulnerability_id','rule_name','evidence_id')"
    )
    verify = (
        "set -a; [ ! -f /etc/siem/storage.env ] || . /etc/siem/storage.env; set +a; "
        "host=\"${SIEM_CH_HOST:-127.0.0.1}\"; port=\"${SIEM_CH_PORT:-9000}\"; user=\"${SIEM_CH_USER:-default}\"; "
        "clickhouse-client --host \"$host\" --port \"$port\" --user \"$user\" "
        f"--password \"${{SIEM_CH_PASSWORD:-}}\" --query {shlex.quote(verify_query)}"
    )
    code, output, error = _run(client, verify, password=password, sudo=True)
    if code != 0 or output.strip() != "6":
        raise RuntimeError(f"ClickHouse schema verification failed: count={output.strip()} error={error.strip()}")


def _restart_units(client: Any, units: tuple[str, ...], password: str) -> list[str]:
    restarted: list[str] = []
    for unit in units:
        exists_code, _, _ = _run(client, f"systemctl cat {shlex.quote(unit)} >/dev/null 2>&1", password=password, sudo=True)
        if exists_code != 0:
            continue
        active_code, _, _ = _run(client, f"systemctl is-active --quiet {shlex.quote(unit)}", password=password, sudo=True)
        if active_code != 0:
            continue
        code, _, error = _run(
            client,
            f"systemctl restart {shlex.quote(unit)} && systemctl is-active --quiet {shlex.quote(unit)}",
            password=password,
            sudo=True,
        )
        if code != 0:
            raise RuntimeError(f"Unable to restart {unit}: {error.strip()}")
        restarted.append(unit)
        time.sleep(1)
    if not restarted:
        raise RuntimeError("No active service units were found for rolling restart")
    return restarted


def _deploy_wave(wave: HostWave, remote_root: str) -> dict[str, Any]:
    host = _required_env(wave.host_env, wave.default_host)
    user = _required_env(wave.user_env, "rdegon")
    password = _required_env(wave.password_env)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup_root = f"/var/backups/siem/security-analytics-{timestamp}"
    client = _connect(host, user, password)
    sftp = client.open_sftp()
    try:
        for relative_path in wave.files:
            local_path = ROOT / relative_path
            if not local_path.exists():
                raise FileNotFoundError(local_path)
            remote_path = posixpath.join(remote_root.rstrip("/"), relative_path)
            _mkdir_sftp(sftp, posixpath.dirname(f"/tmp/{local_path.name}"))
            _upload_file(
                client,
                sftp,
                local_path=local_path,
                remote_path=remote_path,
                backup_root=backup_root,
                password=password,
            )
        _compile(client, wave, remote_root, password)
        if wave.name == "storage":
            _apply_clickhouse_schema(client, remote_root, password)
        restarted = _restart_units(client, wave.units, password)
        return {
            "name": wave.name,
            "host": host,
            "files": list(wave.files),
            "restarted": restarted,
            "backup_root": backup_root,
        }
    finally:
        sftp.close()
        client.close()


def main() -> int:
    remote_root = _required_env("SIEM_REMOTE_ROOT", DEFAULT_REMOTE_ROOT)
    results: list[dict[str, Any]] = []
    for wave in WAVES:
        result = _deploy_wave(wave, remote_root)
        results.append(result)
        print(
            f"wave={result['name']} host={result['host']} files={len(result['files'])} "
            f"restarted={','.join(result['restarted'])} backup={result['backup_root']}"
        )
    print("security_analytics_wave=success")
    return 0


if __name__ == "__main__":
    sys.exit(main())
