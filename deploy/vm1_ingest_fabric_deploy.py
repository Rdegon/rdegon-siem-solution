from __future__ import annotations

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
    FileMapping("deploy/kafka_cluster_layout.py", "deploy/kafka_cluster_layout.py"),
    FileMapping("deploy/kafka_wave_prepare.py", "deploy/kafka_wave_prepare.py"),
    FileMapping("services/ingest/__init__.py", "services/ingest/__init__.py"),
    FileMapping("services/ingest/app.py", "services/ingest/app.py"),
    FileMapping("services/ingest/config.py", "services/ingest/config.py"),
    FileMapping("services/ingest/logging_conf.py", "services/ingest/logging_conf.py"),
    FileMapping("services/ingest/print_config.py", "services/ingest/print_config.py"),
    FileMapping("services/ingest/redis_client.py", "services/ingest/redis_client.py"),
    FileMapping("services/ingest/runtime_state.py", "services/ingest/runtime_state.py"),
    FileMapping("services/ingest/requirements.txt", "services/ingest/requirements.txt"),
    FileMapping("services/ingest/syslog_server.py", "services/ingest/syslog_server.py"),
)


def _required_env(name: str, *, default: str | None = None) -> str:
    value = os.getenv(name, default or "").strip()
    if value:
        return value
    raise SystemExit(f"Missing required environment variable: {name}")


def _remote_path(remote_root: str, rel_path: str) -> str:
    return posixpath.join(remote_root.rstrip("/"), rel_path.replace("\\", "/"))


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


def _connect_client(host: str, user: str, password: str, *, attempts: int = 5, delay_seconds: float = 3.0) -> paramiko.SSHClient:
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
            print(f"ssh connect attempt {attempt}/{attempts} failed: {exc}")
            time.sleep(delay_seconds)
    raise RuntimeError(f"Unable to connect to {host} after {attempts} attempts: {last_error}")


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


def _backup_file(client: paramiko.SSHClient, remote_path: str, backup_root: str) -> None:
    remote_dir = posixpath.dirname(remote_path)
    rel_dir = posixpath.relpath(remote_dir, "/")
    target_dir = posixpath.join(backup_root, rel_dir)
    target_file = posixpath.join(target_dir, posixpath.basename(remote_path))
    command = (
        f"if [ -f {shlex.quote(remote_path)} ]; then "
        f"mkdir -p {shlex.quote(target_dir)} && "
        f"cp {shlex.quote(remote_path)} {shlex.quote(target_file)}; "
        f"fi"
    )
    code, _, err = _run_command(client, command)
    if code != 0:
        raise RuntimeError(f"Failed to back up {remote_path}: {err.strip()}")


def main() -> int:
    host = _required_env("SIEM_VM1_HOST")
    user = _required_env("SIEM_VM1_USER")
    password = _required_env("SIEM_VM1_PASSWORD")
    remote_root = _required_env("SIEM_VM1_BASE_DIR", default=DEFAULT_REMOTE_ROOT)
    backup_root = f"/tmp/siem-ingest-backup-{datetime.now(tz=timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"

    client = _connect_client(host, user, password)
    sftp = client.open_sftp()
    try:
        print(f"remote_root={remote_root}")
        print(f"backup_root={backup_root}")

        for mapping in FILE_MAPPINGS:
            local_path = ROOT / mapping.local_rel
            if not local_path.exists():
                raise FileNotFoundError(f"Missing local file: {local_path}")
            remote_path = _remote_path(remote_root, mapping.remote_rel)
            temp_path = _remote_temp_path(user, Path(mapping.remote_rel).name)
            _backup_file(client, remote_path, backup_root)
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
            code, _, err = _run_command(client, install_cmd, sudo_password=password, use_sudo=True)
            if code != 0:
                raise RuntimeError(f"Failed to install {remote_path}: {err.strip()}")
            print(f"uploaded {mapping.local_rel} -> {remote_path}")

        override_local = Path(__file__).resolve().parent / "vm1" / "siem-ingest.override.conf"
        override_temp = _remote_temp_path(user, "siem-ingest.override.conf")
        _upload_text(
            sftp,
            content=override_local.read_text(encoding="utf-8").replace("\r\n", "\n").replace("\r", "\n"),
            remote_temp_path=override_temp,
        )
        override_install_cmd = (
            "install -d -m 0755 /etc/systemd/system/siem-ingest.service.d && "
            f"install -m 0644 {shlex.quote(override_temp)} /etc/systemd/system/siem-ingest.service.d/override.conf && "
            f"rm -f {shlex.quote(override_temp)}"
        )
        code, _, err = _run_command(client, override_install_cmd, sudo_password=password, use_sudo=True)
        if code != 0:
            raise RuntimeError(f"Failed to install VM1 ingest override: {err.strip()}")
        print("installed deploy/vm1/siem-ingest.override.conf -> /etc/systemd/system/siem-ingest.service.d/override.conf")

        code, _, err = _run_command(client, "systemctl daemon-reload", sudo_password=password, use_sudo=True)
        if code != 0:
            raise RuntimeError(f"Failed to daemon-reload systemd: {err.strip()}")

        compile_cmd = (
            f"cd {shlex.quote(remote_root)} && "
            "export PYTHONPYCACHEPREFIX=/tmp/siem-pycache && "
            "python3 -m py_compile "
            "services/__init__.py "
            "services/redis_runtime.py "
            "services/transport_runtime.py "
            "services/ingest/__init__.py "
            "services/ingest/app.py "
            "services/ingest/config.py "
            "services/ingest/logging_conf.py "
            "services/ingest/print_config.py "
            "services/ingest/redis_client.py "
            "services/ingest/runtime_state.py "
            "services/ingest/syslog_server.py "
            "deploy/kafka_cluster_layout.py "
            "deploy/kafka_wave_prepare.py"
        )
        code, out, err = _run_command(client, compile_cmd)
        print(out, end="")
        if code != 0:
            raise RuntimeError(f"Remote py_compile failed: {err.strip()}")

        kafka_prepare_cmd = (
            f"cd {shlex.quote(remote_root)} && "
            f"SIEM_NODE_PASSWORD={shlex.quote(password)} "
            "SIEM_KAFKA_NODE_ID=1 "
            "SIEM_KAFKA_EXPECT_HOST=siem-ingest "
            "python3 deploy/kafka_wave_prepare.py"
        )
        code, out, err = _run_command(client, kafka_prepare_cmd)
        print(out, end="")
        if code != 0:
            raise RuntimeError(f"VM1 Kafka prepare failed: {err.strip()}")

        state_dir_cmd = "install -d -m 0755 -o rdegon -g rdegon /home/rdegon/.siem-state"
        code, _, err = _run_command(client, state_dir_cmd, sudo_password=password, use_sudo=True)
        if code != 0:
            raise RuntimeError(f"Failed to prepare ingest runtime state directory: {err.strip()}")

        active_cmd = "systemctl is-active siem-ingest"
        stop_cmd = "systemctl stop siem-ingest"
        code, out, err = _run_command(client, stop_cmd, sudo_password=password, use_sudo=True)
        stop_out = _strip_sudo_echo(out, password)
        if stop_out.strip():
            print(stop_out, end="")
        if code != 0:
            raise RuntimeError(f"Failed to stop siem-ingest: {err.strip()}")

        last_state = ""
        for _ in range(30):
            code, out, err = _run_command(client, active_cmd, sudo_password=password, use_sudo=True)
            active_out = _strip_sudo_echo(out, password)
            last_state = next((line.strip() for line in active_out.splitlines() if line.strip()), "")
            if last_state in {"inactive", "failed"}:
                break
            time.sleep(2)
        else:
            kill_cmd = "systemctl kill --signal=SIGKILL siem-ingest"
            code, _, err = _run_command(client, kill_cmd, sudo_password=password, use_sudo=True)
            if code != 0:
                raise RuntimeError(f"Failed to kill stuck siem-ingest: {err.strip()}")
            time.sleep(2)

        start_cmd = "systemctl start siem-ingest"
        code, out, err = _run_command(client, start_cmd, sudo_password=password, use_sudo=True)
        start_out = _strip_sudo_echo(out, password)
        if start_out.strip():
            print(start_out, end="")
        if code != 0:
            raise RuntimeError(f"Failed to start siem-ingest: {err.strip()}")

        active_state = ""
        for _ in range(30):
            code, out, err = _run_command(client, active_cmd, sudo_password=password, use_sudo=True)
            active_out = _strip_sudo_echo(out, password)
            active_state = next((line.strip() for line in active_out.splitlines() if line.strip()), "")
            if code == 0 and active_state == "active":
                break
            time.sleep(2)
        else:
            raise RuntimeError(f"siem-ingest is not active after clean start: stdout={active_out.strip()} stderr={err.strip()}")
        print(f"siem-ingest status={active_state}")
        print("deployment=success")
        print(f"backup_root={backup_root}")
        return 0
    finally:
        sftp.close()
        client.close()


if __name__ == "__main__":
    sys.exit(main())
