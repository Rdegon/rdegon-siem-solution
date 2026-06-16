from __future__ import annotations

import os
import posixpath
import secrets
import shlex
import sys
import time
from dataclasses import dataclass
from pathlib import Path

import paramiko

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from deploy.vm1_kafka_shadow_prepare import INGEST_SYNC_MAPPINGS
from deploy.vm3_kafka_shadow_writer_prepare import SHADOW_SYNC_PATHS

DEFAULT_REMOTE_ROOT = "/opt/siem/siem-solution"


@dataclass(frozen=True)
class HostSpec:
    host: str
    user: str
    password: str


def _required_env(name: str, *, default: str | None = None) -> str:
    value = str(os.getenv(name, default or "") or "").strip()
    if value:
        return value
    raise SystemExit(f"Missing required environment variable: {name}")


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
            print(f"kafka_shadow_wave ssh retry host={host} attempt={attempt}/{attempts} error={exc}")
            time.sleep(delay_seconds)
    raise RuntimeError(f"Unable to connect to {host}: {last_error}")


def _run_command(client: paramiko.SSHClient, command: str, *, sudo_password: str = "", use_sudo: bool = False) -> tuple[int, str, str]:
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


def _mkdir_remote(sftp: paramiko.SFTPClient, path: str) -> None:
    parts = [part for part in path.split("/") if part]
    current = ""
    for part in parts:
        current = f"{current}/{part}"
        try:
            sftp.stat(current)
        except OSError:
            sftp.mkdir(current)


def _upload_with_install(
    client: paramiko.SSHClient,
    sftp: paramiko.SFTPClient,
    *,
    local_path: Path,
    remote_path: str,
    sudo_password: str,
    mode: str = "0644",
) -> None:
    temp_path = f"/tmp/{Path(remote_path).name}.{secrets.token_hex(4)}"
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
        raise RuntimeError(f"Unable to install {remote_path}: {err.strip()}")


def _remote_path(remote_root: str, rel_path: str) -> str:
    return posixpath.join(remote_root.rstrip("/"), rel_path.replace("\\", "/"))


def _upload_repo_file(
    client: paramiko.SSHClient,
    sftp: paramiko.SFTPClient,
    *,
    local_rel: str | Path,
    remote_root: str,
    sudo_password: str,
    mode: str = "0644",
) -> None:
    local_path = ROOT / Path(local_rel)
    if not local_path.exists():
        raise FileNotFoundError(local_path)
    remote_path = _remote_path(remote_root, str(Path(local_rel)).replace("\\", "/"))
    _upload_with_install(client, sftp, local_path=local_path, remote_path=remote_path, sudo_password=sudo_password, mode=mode)
    print(f"uploaded {local_path.relative_to(ROOT)} -> {remote_path}")


def _run_remote_prepare(
    client: paramiko.SSHClient,
    *,
    remote_root: str,
    script_rel: str,
    env: dict[str, str],
) -> None:
    env_prefix = " ".join(f"{key}={shlex.quote(value)}" for key, value in env.items())
    command = f"cd {shlex.quote(remote_root)} && {env_prefix} python3 {shlex.quote(script_rel)}"
    code, out, err = _run_command(client, command)
    if out.strip():
        print(out, end="")
    if code != 0:
        raise RuntimeError(f"Remote prepare failed for {script_rel}: {err.strip()}")


def _deploy_vm1(vm1: HostSpec, *, remote_root: str, expected_host: str) -> None:
    client = _connect_client(vm1.host, vm1.user, vm1.password)
    sftp = client.open_sftp()
    try:
        for mapping in INGEST_SYNC_MAPPINGS:
            _upload_repo_file(
                client,
                sftp,
                local_rel=mapping.source,
                remote_root=remote_root,
                sudo_password=vm1.password,
            )
        _upload_repo_file(
            client,
            sftp,
            local_rel=Path("deploy/vm1_kafka_shadow_prepare.py"),
            remote_root=remote_root,
            sudo_password=vm1.password,
            mode="0755",
        )
        _run_remote_prepare(
            client,
            remote_root=remote_root,
            script_rel="deploy/vm1_kafka_shadow_prepare.py",
            env={
                "SIEM_VM1_PASSWORD": vm1.password,
                "SIEM_VM1_EXPECT_HOST": expected_host,
            },
        )
    finally:
        sftp.close()
        client.close()


def _cutover_vm1(vm1: HostSpec, *, remote_root: str, expected_host: str) -> None:
    client = _connect_client(vm1.host, vm1.user, vm1.password)
    sftp = client.open_sftp()
    try:
        _upload_repo_file(
            client,
            sftp,
            local_rel=Path("deploy/vm1_kafka_cutover.py"),
            remote_root=remote_root,
            sudo_password=vm1.password,
            mode="0755",
        )
        _run_remote_prepare(
            client,
            remote_root=remote_root,
            script_rel="deploy/vm1_kafka_cutover.py",
            env={
                "SIEM_VM1_PASSWORD": vm1.password,
                "SIEM_VM1_EXPECT_HOST": expected_host,
            },
        )
    finally:
        sftp.close()
        client.close()


def _deploy_vm3(vm3: HostSpec, *, remote_root: str, expected_host: str) -> None:
    client = _connect_client(vm3.host, vm3.user, vm3.password)
    sftp = client.open_sftp()
    try:
        for relative in SHADOW_SYNC_PATHS:
            _upload_repo_file(
                client,
                sftp,
                local_rel=relative,
                remote_root=remote_root,
                sudo_password=vm3.password,
            )
        for relative in (
            Path("deploy/vm3_kafka_shadow_writer_prepare.py"),
            Path("deploy/vm3/siem-writer-shadow.service"),
        ):
            _upload_repo_file(
                client,
                sftp,
                local_rel=relative,
                remote_root=remote_root,
                sudo_password=vm3.password,
                mode="0755" if relative.name.endswith(".py") else "0644",
            )
        _run_remote_prepare(
            client,
            remote_root=remote_root,
            script_rel="deploy/vm3_kafka_shadow_writer_prepare.py",
            env={
                "SIEM_VM3_PASSWORD": vm3.password,
                "SIEM_VM3_EXPECT_HOST": expected_host,
            },
        )
    finally:
        sftp.close()
        client.close()


def main() -> int:
    remote_root = _required_env("SIEM_REMOTE_ROOT", default=DEFAULT_REMOTE_ROOT)
    vm1 = HostSpec(
        host=_required_env("SIEM_VM1_HOST"),
        user=_required_env("SIEM_VM1_USER"),
        password=_required_env("SIEM_VM1_PASSWORD"),
    )
    vm3 = HostSpec(
        host=_required_env("SIEM_VM3_HOST"),
        user=_required_env("SIEM_VM3_USER"),
        password=_required_env("SIEM_VM3_PASSWORD"),
    )
    _deploy_vm1(vm1, remote_root=remote_root, expected_host=_required_env("SIEM_VM1_EXPECT_HOST", default="siem-ingest"))
    _deploy_vm3(vm3, remote_root=remote_root, expected_host=_required_env("SIEM_VM3_EXPECT_HOST", default="siem-storage"))
    _cutover_vm1(vm1, remote_root=remote_root, expected_host=_required_env("SIEM_VM1_EXPECT_HOST", default="siem-ingest"))
    print("deployment=success")
    return 0


if __name__ == "__main__":
    sys.exit(main())
