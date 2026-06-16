from __future__ import annotations

import json
import os
import posixpath
import shlex
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import paramiko


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REMOTE_ROOT = "/opt/siem/siem-solution"
REMOTE_STORAGE_ENV = "/etc/siem/storage.env"
SYSTEMD_WRITER_TEMPLATE = "/etc/systemd/system/siem-writer@.service"
WRITER_TEMPLATE_LOCAL = ROOT / "deploy/vm3/siem-writer@.service"
WRITER_SCALEOUT_INSTANCE_IDS = ("2",)
WRITER_SCALEOUT_UNITS = tuple(f"siem-writer@{instance_id}" for instance_id in WRITER_SCALEOUT_INSTANCE_IDS)


@dataclass(frozen=True)
class FileMapping:
    local_rel: str
    remote_rel: str


FILE_MAPPINGS: tuple[FileMapping, ...] = (
    FileMapping("services/redis_runtime.py", "services/redis_runtime.py"),
    FileMapping("services/transport_runtime.py", "services/transport_runtime.py"),
    FileMapping("services/stream_state.py", "services/stream_state.py"),
    FileMapping("writer_worker.py", "services/writer/worker.py"),
    FileMapping("stream_worker.py", "services/stream_corr/worker.py"),
    FileMapping("docs/architecture.md", "docs/architecture.md"),
    FileMapping("docs/README.md", "docs/README.md"),
)


def _required_env(name: str, *, default: str | None = None) -> str:
    value = os.getenv(name, default or "").strip()
    if value:
        return value
    raise SystemExit(f"Missing required environment variable: {name}")


def _resolve_local_path(mapping: FileMapping) -> Path:
    direct = ROOT / mapping.local_rel
    if direct.exists():
        return direct
    mirrored = ROOT / mapping.remote_rel
    if mirrored.exists():
        return mirrored
    raise FileNotFoundError(f"Missing local file: {direct}")


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


def _emit_console_text(text: str) -> None:
    payload = str(text or "")
    if not payload:
        return
    try:
        sys.stdout.write(payload)
    except UnicodeEncodeError:
        sys.stdout.buffer.write(payload.encode("utf-8", errors="replace"))
    if not payload.endswith("\n"):
        sys.stdout.write("\n")


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


def _remote_temp_path(user: str, filename: str) -> str:
    return f"/home/{user}/.siem-tmp/{filename}"


def _backup_path(client: paramiko.SSHClient, path: str, backup_root: str, *, sudo_password: str = "", use_sudo: bool = False) -> None:
    command = (
        f"if [ -e {shlex.quote(path)} ]; then "
        f"mkdir -p {shlex.quote(backup_root)} && "
        f"cp -a {shlex.quote(path)} {shlex.quote(posixpath.join(backup_root, posixpath.basename(path)))}; "
        "fi"
    )
    code, _, err = _run_command(client, command, sudo_password=sudo_password, use_sudo=use_sudo)
    if code != 0:
        raise RuntimeError(f"Backup failed for {path}: {err.strip()}")


def _set_remote_env_values(client: paramiko.SSHClient, env_path: str, updates: dict[str, str], *, sudo_password: str) -> None:
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
    remote_root = _required_env("SIEM_VM3_BASE_DIR", default=DEFAULT_REMOTE_ROOT)
    time_mode = str(os.getenv("SIEM_STREAM_CORR_TIME_MODE", "event") or "event").strip().lower()
    shadow_compare = str(os.getenv("SIEM_STREAM_CORR_SHADOW_COMPARE", "true") or "true").strip().lower()
    allowed_lateness_sec = str(int(os.getenv("SIEM_STREAM_CORR_ALLOWED_LATENESS_SEC", "600") or "600"))
    watermark_lag_sec = str(int(os.getenv("SIEM_STREAM_CORR_WATERMARK_LAG_SEC", "300") or "300"))
    state_backend = str(os.getenv("SIEM_STREAM_STATE_BACKEND", "sqlite") or "sqlite").strip().lower()
    sqlite_path = str(os.getenv("SIEM_STREAM_STATE_SQLITE_PATH", "/var/lib/siem-stream-corr/runtime-state.db") or "/var/lib/siem-stream-corr/runtime-state.db").strip()
    service_user = str(os.getenv("SIEM_VM3_SERVICE_USER", "rdegon") or "rdegon").strip()
    backup_root = f"/tmp/siem-stream-corr-backup-{datetime.now(tz=timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"

    client = _connect_client(host, user, password)
    sftp = client.open_sftp()
    try:
        print(f"remote_root={remote_root}")
        print(f"backup_root={backup_root}")

        for mapping in FILE_MAPPINGS:
            local_path = _resolve_local_path(mapping)
            remote_path = posixpath.join(remote_root.rstrip("/"), mapping.remote_rel)
            temp_path = _remote_temp_path(user, Path(mapping.remote_rel).name)
            _backup_path(client, remote_path, backup_root)
            _upload_text(
                sftp,
                content=local_path.read_text(encoding="utf-8"),
                remote_temp_path=temp_path,
            )
            install_cmd = (
                f"install -d -m 0755 {shlex.quote(posixpath.dirname(remote_path))} && "
                f"install -m 0644 {shlex.quote(temp_path)} {shlex.quote(remote_path)} && "
                f"rm -f {shlex.quote(temp_path)}"
            )
            code, out, err = _run_command(client, install_cmd, sudo_password=password, use_sudo=True)
            install_out = _strip_sudo_echo(out, password)
            if install_out.strip():
                _emit_console_text(install_out)
            if code != 0:
                raise RuntimeError(f"Failed to install {remote_path}: {err.strip()}")
            print(f"uploaded {mapping.local_rel} -> {remote_path}")

        if not WRITER_TEMPLATE_LOCAL.exists():
            raise FileNotFoundError(f"Missing local writer scale-out template: {WRITER_TEMPLATE_LOCAL}")
        _backup_path(client, SYSTEMD_WRITER_TEMPLATE, backup_root, sudo_password=password, use_sudo=True)
        template_temp_path = _remote_temp_path(user, "siem-writer@.service")
        _upload_text(
            sftp,
            content=WRITER_TEMPLATE_LOCAL.read_text(encoding="utf-8"),
            remote_temp_path=template_temp_path,
        )

        _backup_path(client, REMOTE_STORAGE_ENV, backup_root, sudo_password=password, use_sudo=True)
        _set_remote_env_values(
            client,
            REMOTE_STORAGE_ENV,
            {
                "SIEM_STREAM_CORR_TIME_MODE": time_mode,
                "SIEM_STREAM_CORR_SHADOW_COMPARE": shadow_compare,
                "SIEM_STREAM_CORR_ALLOWED_LATENESS_SEC": allowed_lateness_sec,
                "SIEM_STREAM_CORR_WATERMARK_LAG_SEC": watermark_lag_sec,
                "SIEM_STREAM_STATE_BACKEND": state_backend,
                "SIEM_STREAM_STATE_SQLITE_PATH": sqlite_path,
            },
            sudo_password=password,
        )

        if state_backend == "sqlite" and sqlite_path:
            sqlite_dir = posixpath.dirname(sqlite_path)
            mkdir_cmd = (
                f"install -d -m 0755 -o {shlex.quote(service_user)} -g {shlex.quote(service_user)} "
                f"{shlex.quote(sqlite_dir)}"
            )
            code, out, err = _run_command(client, mkdir_cmd, sudo_password=password, use_sudo=True)
            mkdir_out = _strip_sudo_echo(out, password)
            if mkdir_out.strip():
                _emit_console_text(mkdir_out)
            if code != 0:
                raise RuntimeError(f"Unable to create SQLite runtime state directory {sqlite_dir}: {err.strip()}")

        compile_cmd = (
            f"cd {shlex.quote(remote_root)} && "
            "/opt/siem/venv-storage/bin/python -m py_compile "
            "services/redis_runtime.py services/transport_runtime.py services/stream_state.py "
            "services/writer/worker.py services/stream_corr/worker.py"
        )
        code, out, err = _run_command(client, compile_cmd)
        if out.strip():
            _emit_console_text(out)
        if code != 0:
            raise RuntimeError(f"Remote py_compile failed: {err.strip()}")

        install_template_cmd = f"install -m 0644 {shlex.quote(template_temp_path)} {shlex.quote(SYSTEMD_WRITER_TEMPLATE)}"
        restart_cmd = (
            f"{install_template_cmd} && "
            "systemctl daemon-reload && "
            f"systemctl enable --now {' '.join(WRITER_SCALEOUT_UNITS)} && "
            f"systemctl restart siem-writer {' '.join(WRITER_SCALEOUT_UNITS)} siem-stream-corr"
        )
        code, out, err = _run_command(client, restart_cmd, sudo_password=password, use_sudo=True)
        restart_out = _strip_sudo_echo(out, password)
        if restart_out.strip():
            _emit_console_text(restart_out)
        if code != 0:
            raise RuntimeError(f"VM3 service restart failed: {err.strip()}")

        active_cmd = f"systemctl is-active clickhouse-server siem-writer {' '.join(WRITER_SCALEOUT_UNITS)} siem-stream-corr"
        active_states: list[str] = []
        for _ in range(20):
            code, out, err = _run_command(client, active_cmd, sudo_password=password, use_sudo=True)
            active_out = _strip_sudo_echo(out, password)
            active_states = [line.strip() for line in active_out.splitlines() if line.strip()]
            if code == 0 and active_states == ["active", "active", *["active"] * len(WRITER_SCALEOUT_UNITS), "active"]:
                break
            time.sleep(2)
        else:
            raise RuntimeError(f"VM3 service activation failed: stdout={active_states} stderr={err.strip()}")

        print("clickhouse-server status=active")
        print("siem-writer status=active")
        for unit in WRITER_SCALEOUT_UNITS:
            print(f"{unit} status=active")
        print("siem-stream-corr status=active")
        print("deployment=success")
        print(f"backup_root={backup_root}")
        return 0
    finally:
        sftp.close()
        client.close()


if __name__ == "__main__":
    sys.exit(main())
