from __future__ import annotations

import base64
import hashlib
import json
import os
import posixpath
import shlex
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import paramiko


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_VM1_TLS_CERT_PATH = "/etc/siem/tls/ingest.crt"
DEFAULT_VM4_TLS_CA_PATH = "/etc/siem/tls/ingest-ca.crt"
DEFAULT_VM4_ENV_PATH = "/etc/siem/web.env"
PASSWORD_HASH_SCHEME = "pbkdf2_sha256"
PASSWORD_HASH_ITERATIONS = 390_000


@dataclass(frozen=True)
class SshTarget:
    host: str
    user: str
    password: str


def _required_env(name: str, *, default: str | None = None) -> str:
    value = str(os.getenv(name, default or "") or "").strip()
    if value:
        return value
    raise SystemExit(f"Missing required environment variable: {name}")


def _connect(target: SshTarget) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        target.host,
        username=target.user,
        password=target.password,
        timeout=20,
        banner_timeout=20,
        auth_timeout=20,
        look_for_keys=False,
        allow_agent=False,
    )
    return client


def _run(
    client: paramiko.SSHClient,
    command: str,
    *,
    sudo_password: str = "",
    use_sudo: bool = False,
    stdin_text: str = "",
) -> tuple[int, str, str]:
    wrapped = f"sudo -S -p '' bash -lc {shlex.quote(command)}" if use_sudo else command
    stdin, stdout, stderr = client.exec_command(wrapped, get_pty=use_sudo)
    if use_sudo:
        stdin.write(f"{sudo_password}\n")
    if stdin_text:
        stdin.write(stdin_text)
    stdin.flush()
    try:
        stdin.channel.shutdown_write()
    except Exception:  # noqa: BLE001
        pass
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    code = stdout.channel.recv_exit_status()
    return code, out, err


def _strip_password_echo(text: str, password: str) -> str:
    cleaned: list[str] = []
    for raw_line in str(text or "").replace("\r", "\n").split("\n"):
        line = raw_line.strip("\x00")
        if not line.strip():
            continue
        if line.strip() == password or line.strip().endswith("password for rdegon:"):
            continue
        cleaned.append(line)
    return "\n".join(cleaned).strip()


def _fetch_text(client: paramiko.SSHClient, path: str, *, sudo_password: str = "", use_sudo: bool = False) -> str:
    code, out, err = _run(client, f"cat {shlex.quote(path)}", sudo_password=sudo_password, use_sudo=use_sudo)
    cleaned = _strip_password_echo(out, sudo_password)
    if code != 0:
        raise RuntimeError(f"Unable to read {path}: {err.strip() or cleaned}")
    return cleaned


def _backup_file(client: paramiko.SSHClient, remote_path: str, backup_root: str, *, sudo_password: str) -> None:
    remote_dir = posixpath.dirname(remote_path)
    rel_dir = posixpath.relpath(remote_dir, "/")
    target_dir = posixpath.join(backup_root, rel_dir)
    target_file = posixpath.join(target_dir, posixpath.basename(remote_path))
    command = (
        f"mkdir -p {shlex.quote(target_dir)} && "
        f"if [ -f {shlex.quote(remote_path)} ]; then cp {shlex.quote(remote_path)} {shlex.quote(target_file)}; fi"
    )
    code, _, err = _run(client, command, sudo_password=sudo_password, use_sudo=True)
    if code != 0:
        raise RuntimeError(f"Unable to back up {remote_path}: {err.strip()}")


def _upload_text_as_root(
    client: paramiko.SSHClient,
    text: str,
    target_path: str,
    *,
    sudo_password: str,
    mode: str = "0644",
) -> None:
    remote_tmp = f"/tmp/{posixpath.basename(target_path)}.{datetime.now(tz=timezone.utc).strftime('%Y%m%d%H%M%S')}"
    sftp = client.open_sftp()
    try:
        with sftp.open(remote_tmp, "w") as handle:
            handle.write(text)
    finally:
        sftp.close()
    install_cmd = f"install -D -m {mode} {shlex.quote(remote_tmp)} {shlex.quote(target_path)} && rm -f {shlex.quote(remote_tmp)}"
    code, out, err = _run(client, install_cmd, sudo_password=sudo_password, use_sudo=True)
    cleaned = _strip_password_echo(out, sudo_password)
    if code != 0:
        raise RuntimeError(f"Unable to install {target_path}: {err.strip() or cleaned}")


def _parse_env(text: str) -> OrderedDict[str, str]:
    values: OrderedDict[str, str] = OrderedDict()
    for raw_line in str(text or "").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value
    return values


def _serialize_env(values: OrderedDict[str, str]) -> str:
    return "\n".join(f"{key}={value}" for key, value in values.items()) + "\n"


def _encode_hash_component(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _hash_password(password: str) -> str:
    safe_password = str(password or "")
    if not safe_password:
        return ""
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", safe_password.encode("utf-8"), salt, PASSWORD_HASH_ITERATIONS)
    return f"{PASSWORD_HASH_SCHEME}${PASSWORD_HASH_ITERATIONS}${_encode_hash_component(salt)}${_encode_hash_component(digest)}"


def _operator_users_override() -> list[dict[str, object]]:
    raw = str(os.getenv("SIEM_OPERATOR_WEB_USERS_JSON", "") or "").strip()
    if not raw:
        return []
    payload = json.loads(raw)
    if not isinstance(payload, list):
        raise RuntimeError("SIEM_OPERATOR_WEB_USERS_JSON must be a JSON array when provided")
    return [item for item in payload if isinstance(item, dict)]


def _operator_admin_password_override() -> str:
    return str(os.getenv("SIEM_OPERATOR_ADMIN_PASSWORD", "") or "").strip()


def _normalize_hashed_users(
    *,
    users: list[dict[str, object]],
    admin_password: str,
    admin_password_hash: str,
) -> dict[str, str]:
    hashed_users: list[dict[str, str]] = []
    for item in users:
        username = str(item.get("username") or "").strip()
        role = str(item.get("role") or "viewer").strip().lower() or "viewer"
        password_hash = str(item.get("password_hash") or item.get("passwordHash") or "").strip()
        password = str(item.get("password") or "")
        if not username:
            continue
        if not password_hash and password:
            password_hash = _hash_password(password)
        if password_hash:
            hashed_users.append({"username": username, "password_hash": password_hash, "role": role})
    admin_hash = str(admin_password_hash or "").strip()
    if not admin_hash and admin_password:
        admin_hash = _hash_password(admin_password)
    return {
        "web_users_json": json.dumps(hashed_users, ensure_ascii=False, separators=(",", ":")),
        "admin_password_hash": admin_hash,
    }


def main() -> int:
    vm1 = SshTarget(
        host=_required_env("SIEM_VM1_HOST", default="192.168.1.35"),
        user=_required_env("SIEM_VM1_USER", default="rdegon"),
        password=_required_env("SIEM_VM1_PASSWORD", default=""),
    )
    vm4 = SshTarget(
        host=_required_env("SIEM_VM4_HOST", default="192.168.1.39"),
        user=_required_env("SIEM_VM4_USER", default="rdegon"),
        password=_required_env("SIEM_VM4_PASSWORD", default=""),
    )
    vm1_cert_path = _required_env("SIEM_VM1_TLS_CERT_PATH", default=DEFAULT_VM1_TLS_CERT_PATH)
    vm4_ca_path = _required_env("SIEM_VM4_INGEST_CA_PATH", default=DEFAULT_VM4_TLS_CA_PATH)
    vm4_env_path = _required_env("SIEM_VM4_WEB_ENV_PATH", default=DEFAULT_VM4_ENV_PATH)
    backup_root = f"/tmp/siem-web-security-hardening-{datetime.now(tz=timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"

    vm1_client = _connect(vm1)
    vm4_client = _connect(vm4)
    try:
        ingest_cert = _fetch_text(vm1_client, vm1_cert_path, sudo_password=vm1.password, use_sudo=True)
        web_env_text = _fetch_text(vm4_client, vm4_env_path, sudo_password=vm4.password, use_sudo=True)
        env_map = _parse_env(web_env_text)
        users = json.loads(env_map.get("SIEM_WEB_USERS_JSON", "[]") or "[]")
        if not isinstance(users, list):
            raise RuntimeError("SIEM_WEB_USERS_JSON on VM4 must be a JSON array")
        if not users:
            users = _operator_users_override()
        hashed_payload = _normalize_hashed_users(
            users=users,
            admin_password=str(env_map.get("SIEM_ADMIN_DEFAULT_PASSWORD", "") or "") or _operator_admin_password_override(),
            admin_password_hash=str(env_map.get("SIEM_ADMIN_DEFAULT_PASSWORD_HASH", "") or ""),
        )
        if not hashed_payload["admin_password_hash"]:
            raise RuntimeError("Unable to derive SIEM_ADMIN_DEFAULT_PASSWORD_HASH; provide SIEM_OPERATOR_ADMIN_PASSWORD if live env has already been scrubbed")
        if not str(hashed_payload["web_users_json"] or "").strip() or hashed_payload["web_users_json"] == "[]":
            raise RuntimeError("Unable to derive hashed SIEM_WEB_USERS_JSON; provide SIEM_OPERATOR_WEB_USERS_JSON if live env has already been scrubbed")

        _backup_file(vm4_client, vm4_env_path, backup_root, sudo_password=vm4.password)
        _backup_file(vm4_client, vm4_ca_path, backup_root, sudo_password=vm4.password)

        env_map["SIEM_ADMIN_DEFAULT_PASSWORD_HASH"] = str(hashed_payload.get("admin_password_hash") or "").strip()
        env_map.pop("SIEM_ADMIN_DEFAULT_PASSWORD", None)
        env_map["SIEM_WEB_USERS_JSON"] = str(hashed_payload.get("web_users_json") or "[]")
        env_map["SIEM_AUTH_RATE_LIMIT_WINDOW_SECONDS"] = str(os.getenv("SIEM_AUTH_RATE_LIMIT_WINDOW_SECONDS", "300") or "300")
        env_map["SIEM_AUTH_RATE_LIMIT_MAX_ATTEMPTS"] = str(os.getenv("SIEM_AUTH_RATE_LIMIT_MAX_ATTEMPTS", "5") or "5")
        env_map["SIEM_AUTH_RATE_LIMIT_LOCKOUT_SECONDS"] = str(os.getenv("SIEM_AUTH_RATE_LIMIT_LOCKOUT_SECONDS", "900") or "900")
        env_map["SIEM_INGEST_TLS_VERIFY"] = str(os.getenv("SIEM_INGEST_TLS_VERIFY", "ca_file") or "ca_file")
        env_map["SIEM_INGEST_TLS_CA_FILE"] = vm4_ca_path

        _upload_text_as_root(vm4_client, ingest_cert, vm4_ca_path, sudo_password=vm4.password, mode="0644")
        _upload_text_as_root(vm4_client, _serialize_env(env_map), vm4_env_path, sudo_password=vm4.password, mode="0600")

        restart_cmd = "systemctl restart siem-web && systemctl is-active siem-web"
        code, out, err = _run(vm4_client, restart_cmd, sudo_password=vm4.password, use_sudo=True)
        cleaned = _strip_password_echo(out, vm4.password)
        if code != 0 or "active" not in cleaned:
            raise RuntimeError(f"siem-web failed to restart after security hardening: {err.strip() or cleaned}")

        print(f"backup_root={backup_root}")
        print(f"vm4_env_path={vm4_env_path}")
        print(f"vm4_ca_path={vm4_ca_path}")
        print("local_auth_storage=hashed")
        print("ingest_tls_verify=ca_file")
        print("siem-web=active")
        return 0
    finally:
        vm1_client.close()
        vm4_client.close()


if __name__ == "__main__":
    raise SystemExit(main())
