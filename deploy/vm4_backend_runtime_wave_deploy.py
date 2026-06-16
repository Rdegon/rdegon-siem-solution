from __future__ import annotations

import os
import posixpath
import shlex
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import paramiko


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REMOTE_ROOT = "/opt/siem/siem-solution"


@dataclass(frozen=True)
class FileMapping:
    local_rel: str
    remote_rel: str


FILE_MAPPINGS: tuple[FileMapping, ...] = (
    FileMapping("main.py", "services/web/main.py"),
    FileMapping("requirements-web.txt", "services/web/requirements-web.txt"),
    FileMapping("config.py", "services/web/app/config.py"),
    FileMapping("auth.py", "services/web/app/routes/auth.py"),
    FileMapping("login.html", "services/web/app/templates/login.html"),
    FileMapping("alerts.py", "services/web/app/routes/alerts.py"),
    FileMapping("backup_runtime.py", "services/web/app/backup_runtime.py"),
    FileMapping("asset_catalog_runtime.py", "services/web/app/asset_catalog_runtime.py"),
    FileMapping("clickhouse_runtime.py", "services/web/app/clickhouse_runtime.py"),
    FileMapping("content_runtime.py", "services/web/app/content_runtime.py"),
    FileMapping("content_store.py", "services/web/app/content_store.py"),
    FileMapping("control_plane_access_ops.py", "services/web/app/control_plane_access_ops.py"),
    FileMapping("control_plane_case_ops.py", "services/web/app/control_plane_case_ops.py"),
    FileMapping("control_plane_connector_ops.py", "services/web/app/control_plane_connector_ops.py"),
    FileMapping("control_plane_content_ops.py", "services/web/app/control_plane_content_ops.py"),
    FileMapping("control_plane_health.py", "services/web/app/control_plane_health.py"),
    FileMapping("control_plane_response_ops.py", "services/web/app/control_plane_response_ops.py"),
    FileMapping("deps.py", "services/web/app/deps.py"),
    FileMapping("operational_filters.py", "services/web/app/operational_filters.py"),
    FileMapping("deps_platform_ops.py", "services/web/app/deps_platform_ops.py"),
    FileMapping("deps_runtime_docs_ops.py", "services/web/app/deps_runtime_docs_ops.py"),
    FileMapping("enterprise_control_plane.py", "services/web/app/enterprise_control_plane.py"),
    FileMapping("health_surfaces.py", "services/web/app/health_surfaces.py"),
    FileMapping("host_runtime_pipeline.py", "services/web/app/host_runtime_pipeline.py"),
    FileMapping("host_runtime_runtime.py", "services/web/app/host_runtime_runtime.py"),
    FileMapping("ingest_runtime.py", "services/web/app/ingest_runtime.py"),
    FileMapping("security.py", "services/web/app/security.py"),
    FileMapping("source_discovery.py", "services/web/app/source_discovery.py"),
    FileMapping("storage_ha_runtime.py", "services/web/app/storage_ha_runtime.py"),
    FileMapping("stream_state_runtime.py", "services/web/app/stream_state_runtime.py"),
    FileMapping("transport_health_runtime.py", "services/web/app/transport_health_runtime.py"),
    FileMapping("vulnerability_query_runtime.py", "services/web/app/vulnerability_query_runtime.py"),
    FileMapping("vuln_runtime.py", "services/web/app/vuln_runtime.py"),
    FileMapping("console.py", "services/web/app/routes/console.py"),
    FileMapping("console_assets_routes.py", "services/web/app/routes/console_assets_routes.py"),
    FileMapping("console_auth_routes.py", "services/web/app/routes/console_auth_routes.py"),
    FileMapping("console_dashboard_routes.py", "services/web/app/routes/console_dashboard_routes.py"),
    FileMapping("console_docs_routes.py", "services/web/app/routes/console_docs_routes.py"),
    FileMapping("console_health_routes.py", "services/web/app/routes/console_health_routes.py"),
    FileMapping("console_operations_routes.py", "services/web/app/routes/console_operations_routes.py"),
    FileMapping("console_response_routes.py", "services/web/app/routes/console_response_routes.py"),
    FileMapping("services/__init__.py", "services/__init__.py"),
    FileMapping("services/stream_state.py", "services/stream_state.py"),
    FileMapping("services/transport_runtime.py", "services/transport_runtime.py"),
    FileMapping("deploy/env_file_runtime.py", "deploy/env_file_runtime.py"),
    FileMapping("deploy/publish_runtime_docs.py", "deploy/publish_runtime_docs.py"),
    FileMapping("deploy/system_cleanup.py", "deploy/system_cleanup.py"),
    FileMapping("retention_runner.py", "retention_runner.py"),
)


def _required_env(name: str, *, default: str | None = None) -> str:
    value = str(os.getenv(name, default or "") or "").strip()
    if value:
        return value
    raise SystemExit(f"Missing required environment variable: {name}")


def _remote_path(remote_root: str, rel_path: str) -> str:
    return posixpath.join(remote_root.rstrip("/"), rel_path.replace("\\", "/"))


def _connect(host: str, user: str, password: str) -> paramiko.SSHClient:
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


def _run(client: paramiko.SSHClient, command: str, *, sudo_password: str = "", use_sudo: bool = False) -> tuple[int, str, str]:
    wrapped = f"sudo -S -p '' bash -lc {shlex.quote(command)}" if use_sudo else command
    stdin, stdout, stderr = client.exec_command(wrapped, get_pty=use_sudo)
    if use_sudo:
        stdin.write(f"{sudo_password}\n")
        stdin.flush()
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    code = stdout.channel.recv_exit_status()
    return code, out, err


def _mkdir_remote(sftp: paramiko.SFTPClient, path: str) -> None:
    parts = [part for part in path.split("/") if part]
    current = ""
    for part in parts:
        current = f"{current}/{part}"
        try:
            sftp.stat(current)
        except OSError:
            sftp.mkdir(current)


def _resolve_local_path(mapping: FileMapping) -> Path:
    direct = ROOT / mapping.local_rel
    if direct.exists():
        return direct
    mirrored = ROOT / mapping.remote_rel
    if mirrored.exists():
        return mirrored
    raise FileNotFoundError(f"Missing local file: {mapping.local_rel}")


def _upload_file(client: paramiko.SSHClient, remote_root: str, mapping: FileMapping, *, sudo_password: str) -> None:
    local_path = _resolve_local_path(mapping)
    remote_path = _remote_path(remote_root, mapping.remote_rel)
    temp_path = f"/tmp/{Path(mapping.remote_rel).name}"
    sftp = client.open_sftp()
    try:
        _mkdir_remote(sftp, posixpath.dirname(temp_path))
        sftp.put(str(local_path), temp_path)
    finally:
        sftp.close()
    command = (
        f"install -d -m 0755 {shlex.quote(posixpath.dirname(remote_path))} && "
        f"install -m 0644 {shlex.quote(temp_path)} {shlex.quote(remote_path)} && "
        f"rm -f {shlex.quote(temp_path)}"
    )
    code, _, err = _run(client, command, sudo_password=sudo_password, use_sudo=True)
    if code != 0:
        raise RuntimeError(f"Unable to install {remote_path}: {err.strip()}")


def main() -> int:
    host = _required_env("SIEM_VM4_HOST", default="192.168.1.39")
    user = _required_env("SIEM_VM4_USER", default="rdegon")
    password = _required_env("SIEM_VM4_PASSWORD")
    remote_root = _required_env("SIEM_REMOTE_ROOT", default=DEFAULT_REMOTE_ROOT)
    backup_root = f"/tmp/siem-vm4-backend-wave-backup-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
    client = _connect(host, user, password)
    try:
        code, _, err = _run(client, f"mkdir -p {shlex.quote(backup_root)}", sudo_password=password, use_sudo=True)
        if code != 0:
            raise RuntimeError(f"Unable to create backup root: {err.strip()}")
        for mapping in FILE_MAPPINGS:
            remote_path = _remote_path(remote_root, mapping.remote_rel)
            backup_command = (
                f"if [ -f {shlex.quote(remote_path)} ]; then "
                f"install -d -m 0755 {shlex.quote(posixpath.dirname(posixpath.join(backup_root, mapping.remote_rel)))} && "
                f"cp {shlex.quote(remote_path)} {shlex.quote(posixpath.join(backup_root, mapping.remote_rel))}; "
                f"fi"
            )
            _run(client, backup_command, sudo_password=password, use_sudo=True)
            _upload_file(client, remote_root, mapping, sudo_password=password)
        compile_targets = " ".join(
            shlex.quote(_remote_path(remote_root, mapping.remote_rel))
            for mapping in FILE_MAPPINGS
            if mapping.remote_rel.endswith(".py")
        )
        code, out, err = _run(client, f"python3 -m py_compile {compile_targets}", sudo_password=password, use_sudo=True)
        if code != 0:
            raise RuntimeError(f"Remote py_compile failed:\n{out}\n{err}")
        code, out, err = _run(
            client,
            f"cd {shlex.quote(remote_root)} && systemctl restart siem-web && systemctl is-active siem-web",
            sudo_password=password,
            use_sudo=True,
        )
        if code != 0 or "active" not in out:
            raise RuntimeError(f"siem-web restart failed:\n{out}\n{err}")
        print(f"backup_root={backup_root}")
        print("vm4_backend_runtime_wave_deploy=success")
        return 0
    finally:
        client.close()


if __name__ == "__main__":
    raise SystemExit(main())
