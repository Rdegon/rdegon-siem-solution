from __future__ import annotations

import json
import os
import posixpath
import shlex
import sys
import time
from datetime import datetime, timezone

import paramiko


REMOTE_CLICKHOUSE_TUNING = "/etc/clickhouse-server/config.d/siem-memory-tuning.xml"
REMOTE_STORAGE_ENV = "/etc/siem/storage.env"
CLICKHOUSE_SERVICE_UNITS = (
    "clickhouse-server",
    "siem-writer",
    "siem-writer@2",
    "siem-stream-corr",
    "siem-batch-corr",
    "siem-alert-agg",
)

DEFAULT_MAX_SERVER_MEMORY_USAGE = 16 * 1024 * 1024 * 1024
DEFAULT_MARK_CACHE_SIZE = 1024 * 1024 * 1024
DEFAULT_UNCOMPRESSED_CACHE_SIZE = 1024 * 1024 * 1024
DEFAULT_MAX_SERVER_MEMORY_USAGE_TO_RAM_RATIO = "0.6"
DEFAULT_CLICKHOUSE_APP_USER = "siem_admin"


def _required_env(name: str, *, default: str | None = None) -> str:
    value = str(os.getenv(name, default or "") or "").strip()
    if value:
        return value
    raise SystemExit(f"Missing required environment variable: {name}")


def _run_command(
    client: paramiko.SSHClient,
    command: str,
    *,
    sudo_password: str = "",
    use_sudo: bool = False,
) -> tuple[int, str, str]:
    wrapped = f"sudo -S -p '' bash -lc {shlex.quote(command)}" if use_sudo else command
    stdin, stdout, stderr = client.exec_command(wrapped, get_pty=use_sudo)
    if use_sudo:
        stdin.write(f"{sudo_password}\n")
        stdin.flush()
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    code = stdout.channel.recv_exit_status()
    return code, out, err


def _connect_client(host: str, user: str, password: str) -> paramiko.SSHClient:
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
            if attempt == 5:
                break
            print(f"ssh connect attempt {attempt}/5 failed: {exc}")
            time.sleep(3)
    raise RuntimeError(f"Unable to connect to {host}: {last_error}")


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


def _render_memory_tuning_xml(
    *,
    max_server_memory_usage: int,
    max_server_memory_usage_to_ram_ratio: str,
    mark_cache_size: int,
    uncompressed_cache_size: int,
) -> str:
    return (
        "<clickhouse>\n"
        f"  <max_server_memory_usage>{int(max_server_memory_usage)}</max_server_memory_usage>\n"
        f"  <max_server_memory_usage_to_ram_ratio>{max_server_memory_usage_to_ram_ratio}</max_server_memory_usage_to_ram_ratio>\n"
        f"  <mark_cache_size>{int(mark_cache_size)}</mark_cache_size>\n"
        f"  <uncompressed_cache_size>{int(uncompressed_cache_size)}</uncompressed_cache_size>\n"
        "</clickhouse>\n"
    )


def _render_clickhouse_metrics_grants_sql(app_user: str) -> str:
    user = str(app_user or DEFAULT_CLICKHOUSE_APP_USER).strip() or DEFAULT_CLICKHOUSE_APP_USER
    return (
        f"GRANT SELECT(metric, value) ON system.asynchronous_metrics TO {user};\n"
        f"GRANT SELECT(name, value) ON system.metrics TO {user};\n"
        f"GRANT SELECT(name, value) ON system.server_settings TO {user};\n"
    )


def _mkdir_remote(sftp: paramiko.SFTPClient, path: str) -> None:
    parts = [part for part in path.split("/") if part]
    current = ""
    for part in parts:
        current = f"{current}/{part}"
        try:
            sftp.stat(current)
        except OSError:
            sftp.mkdir(current)


def _upload_text(
    sftp: paramiko.SFTPClient,
    *,
    content: str,
    remote_temp_path: str,
) -> None:
    _mkdir_remote(sftp, posixpath.dirname(remote_temp_path))
    with sftp.open(remote_temp_path, "w") as handle:
        handle.write(content)


def _backup_path(
    client: paramiko.SSHClient,
    path: str,
    backup_root: str,
    *,
    sudo_password: str = "",
    use_sudo: bool = False,
) -> None:
    command = (
        f"if [ -e {shlex.quote(path)} ]; then "
        f"mkdir -p {shlex.quote(backup_root)} && "
        f"cp -a {shlex.quote(path)} {shlex.quote(posixpath.join(backup_root, posixpath.basename(path)))}; "
        "fi"
    )
    code, _, err = _run_command(client, command, sudo_password=sudo_password, use_sudo=use_sudo)
    if code != 0:
        raise RuntimeError(f"Backup failed for {path}: {err.strip()}")


def _set_remote_env_values(
    client: paramiko.SSHClient,
    env_path: str,
    updates: dict[str, str],
    *,
    sudo_password: str,
) -> None:
    payload = json.dumps(updates, ensure_ascii=False)
    script = f"""
import json
from pathlib import Path

path = Path({env_path!r})
updates = json.loads({payload!r})
lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
positions = {{}}
for index, line in enumerate(lines):
    if "=" not in line or line.lstrip().startswith("#"):
        continue
    key = line.split("=", 1)[0].strip()
    if key:
        positions[key] = index
for key, value in updates.items():
    rendered = f"{{key}}={{value}}"
    if key in positions:
        lines[positions[key]] = rendered
    else:
        lines.append(rendered)
path.write_text("\\n".join(lines).rstrip() + "\\n", encoding="utf-8")
"""
    command = f"python3 - <<'PY'\n{script}\nPY"
    code, _, err = _run_command(client, command, sudo_password=sudo_password, use_sudo=True)
    if code != 0:
        raise RuntimeError(f"Unable to update {env_path}: {err.strip()}")


def main() -> int:
    host = _required_env("SIEM_VM3_HOST")
    user = _required_env("SIEM_VM3_USER")
    password = _required_env("SIEM_VM3_PASSWORD")
    max_server_memory_usage = int(
        _required_env("SIEM_VM3_CH_MAX_SERVER_MEMORY_USAGE_BYTES", default=str(DEFAULT_MAX_SERVER_MEMORY_USAGE))
    )
    max_server_memory_usage_to_ram_ratio = _required_env(
        "SIEM_VM3_CH_MAX_SERVER_MEMORY_USAGE_TO_RAM_RATIO",
        default=DEFAULT_MAX_SERVER_MEMORY_USAGE_TO_RAM_RATIO,
    )
    mark_cache_size = int(_required_env("SIEM_VM3_CH_MARK_CACHE_SIZE_BYTES", default=str(DEFAULT_MARK_CACHE_SIZE)))
    uncompressed_cache_size = int(
        _required_env("SIEM_VM3_CH_UNCOMPRESSED_CACHE_SIZE_BYTES", default=str(DEFAULT_UNCOMPRESSED_CACHE_SIZE))
    )
    clickhouse_app_user = _required_env("SIEM_VM3_CH_APP_USER", default=DEFAULT_CLICKHOUSE_APP_USER)
    backup_root = f"/tmp/siem-storage-memory-backup-{datetime.now(tz=timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"

    xml_payload = _render_memory_tuning_xml(
        max_server_memory_usage=max_server_memory_usage,
        max_server_memory_usage_to_ram_ratio=max_server_memory_usage_to_ram_ratio,
        mark_cache_size=mark_cache_size,
        uncompressed_cache_size=uncompressed_cache_size,
    )
    grants_sql = _render_clickhouse_metrics_grants_sql(clickhouse_app_user)

    client = _connect_client(host, user, password)
    sftp = client.open_sftp()
    try:
        print(f"backup_root={backup_root}")
        _backup_path(client, REMOTE_CLICKHOUSE_TUNING, backup_root, sudo_password=password, use_sudo=True)
        _backup_path(client, REMOTE_STORAGE_ENV, backup_root, sudo_password=password, use_sudo=True)

        remote_temp_path = f"/home/{user}/.siem-tmp/siem-memory-tuning.xml"
        _upload_text(sftp, content=xml_payload, remote_temp_path=remote_temp_path)

        install_cmd = (
            f"install -D -m 0644 {shlex.quote(remote_temp_path)} {shlex.quote(REMOTE_CLICKHOUSE_TUNING)}"
        )
        code, out, err = _run_command(client, install_cmd, sudo_password=password, use_sudo=True)
        cleaned_out = _strip_sudo_echo(out, password).strip()
        if cleaned_out:
            print(cleaned_out)
        if code != 0:
            raise RuntimeError(f"Unable to install ClickHouse tuning config: {err.strip()}")

        grants_cmd = f"clickhouse-client --multiquery --query {shlex.quote(grants_sql)}"
        code, out, err = _run_command(client, grants_cmd)
        if code != 0:
            raise RuntimeError(f"Unable to grant ClickHouse metrics access to {clickhouse_app_user}: {err.strip()}")
        cleaned_out = _strip_sudo_echo(out, password).strip()
        if cleaned_out:
            print(cleaned_out)

        _set_remote_env_values(
            client,
            REMOTE_STORAGE_ENV,
            {
                "SIEM_VM3_CH_MAX_SERVER_MEMORY_USAGE_BYTES": str(max_server_memory_usage),
                "SIEM_VM3_CH_MAX_SERVER_MEMORY_USAGE_TO_RAM_RATIO": str(max_server_memory_usage_to_ram_ratio),
                "SIEM_VM3_CH_MARK_CACHE_SIZE_BYTES": str(mark_cache_size),
                "SIEM_VM3_CH_UNCOMPRESSED_CACHE_SIZE_BYTES": str(uncompressed_cache_size),
                "SIEM_VM3_CH_APP_USER": str(clickhouse_app_user),
            },
            sudo_password=password,
        )

        restart_cmd = "systemctl restart " + " ".join(CLICKHOUSE_SERVICE_UNITS)
        code, out, err = _run_command(client, restart_cmd, sudo_password=password, use_sudo=True)
        cleaned_out = _strip_sudo_echo(out, password).strip()
        if cleaned_out:
            print(cleaned_out)
        if code != 0:
            raise RuntimeError(f"Unable to restart storage services: {err.strip()}")

        active_cmd = "systemctl is-active " + " ".join(CLICKHOUSE_SERVICE_UNITS)
        code, out, err = _run_command(client, active_cmd, sudo_password=password, use_sudo=True)
        active_out = _strip_sudo_echo(out, password)
        states = [line.strip() for line in active_out.splitlines() if line.strip()]
        if code != 0 or states != ["active"] * len(CLICKHOUSE_SERVICE_UNITS):
            raise RuntimeError(f"Unexpected storage service state: stdout={states} stderr={err.strip()}")

        print("clickhouse_memory_tuning=applied")
        print(f"max_server_memory_usage={max_server_memory_usage}")
        print(f"mark_cache_size={mark_cache_size}")
        print(f"uncompressed_cache_size={uncompressed_cache_size}")
        print(f"clickhouse_metrics_grants_user={clickhouse_app_user}")
        print("storage_services=active")
        return 0
    finally:
        sftp.close()
        client.close()


if __name__ == "__main__":
    sys.exit(main())
