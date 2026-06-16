from __future__ import annotations

import json
import os
import posixpath
import shlex
import sys
import time
from datetime import datetime, timezone

import paramiko


DEFAULT_REMOTE_ROOT = "/opt/siem/siem-solution"
REMOTE_WEB_ENV = "/etc/siem/web.env"
REMOTE_WEB_VENV = "/opt/siem/venv-web"
REMOTE_MONGOD_CONF = "/etc/mongod.conf"
RUNTIME_DOCS_ROOT = "/opt/siem/runtime-docs"
TARGET_CPU_MODEL = "x86-64-v3"
DEFAULT_VM4_VMID = "107"


def _required_env(name: str, *, default: str | None = None) -> str:
    value = os.getenv(name, default or "").strip()
    if value:
        return value
    raise SystemExit(f"Missing required environment variable: {name}")


def _validate_identifier(value: str, label: str) -> str:
    safe = str(value or "").strip()
    if not safe or not safe.replace("_", "").replace("-", "").isalnum() or not safe[0].isalpha():
        raise SystemExit(f"Unsafe {label}: {value!r}")
    return safe


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


def _connect_client(host: str, user: str, password: str, *, attempts: int = 5, delay_seconds: int = 3) -> paramiko.SSHClient:
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
    raise RuntimeError(f"Unable to connect to {host}: {last_error}")


def _parse_cpu_flags(lscpu_output: str) -> set[str]:
    for raw_line in str(lscpu_output or "").replace("\r", "\n").split("\n"):
        line = raw_line.strip()
        if line.lower().startswith("flags:"):
            return {part.strip().lower() for part in line.split(":", 1)[1].split() if part.strip()}
    return set()


def _guest_has_avx(client: paramiko.SSHClient) -> bool:
    code, out, err = _run_command(client, "lscpu | grep '^Flags:' || true")
    if code != 0:
        raise RuntimeError(f"Unable to query guest CPU flags: {err.strip()}")
    return "avx" in _parse_cpu_flags(out)


def _parse_qm_cpu_model(config_output: str) -> str:
    for raw_line in str(config_output or "").replace("\r", "\n").split("\n"):
        line = raw_line.strip()
        if line.startswith("cpu:"):
            return line.split(":", 1)[1].strip()
    return ""


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


def _ensure_vm4_cpu_profile(
    *,
    host: str,
    user: str,
    password: str,
    proxmox_host: str,
    proxmox_user: str,
    proxmox_password: str,
    vmid: str,
) -> str:
    proxmox = _connect_client(proxmox_host, proxmox_user, proxmox_password)
    backup_root = f"/tmp/siem-vm4-cpu-profile-backup-{datetime.now(tz=timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
    try:
        backup_cmd = f"mkdir -p {shlex.quote(backup_root)} && qm config {shlex.quote(vmid)} > {shlex.quote(posixpath.join(backup_root, f'vm-{vmid}.conf'))}"
        code, _, err = _run_command(proxmox, backup_cmd)
        if code != 0:
            raise RuntimeError(f"Unable to back up Proxmox VM config for {vmid}: {err.strip()}")

        code, out, err = _run_command(proxmox, f"qm config {shlex.quote(vmid)}")
        if code != 0:
            raise RuntimeError(f"Unable to read Proxmox VM config for {vmid}: {err.strip()}")
        current_model = _parse_qm_cpu_model(out)
        if current_model != TARGET_CPU_MODEL:
            code, _, err = _run_command(proxmox, f"qm set {shlex.quote(vmid)} --cpu {shlex.quote(TARGET_CPU_MODEL)}")
            if code != 0:
                raise RuntimeError(f"Unable to set VM{vmid} CPU model to {TARGET_CPU_MODEL}: {err.strip()}")
            print(f"vm4_cpu_model_updated={current_model or 'unknown'}->{TARGET_CPU_MODEL}")
        else:
            print(f"vm4_cpu_model_already={TARGET_CPU_MODEL}")

        code, _, err = _run_command(proxmox, f"qm shutdown {shlex.quote(vmid)} --timeout 120")
        if code != 0 and "already stopped" not in str(err or "").lower():
            raise RuntimeError(f"Unable to shut down VM{vmid} before CPU-profile change: {err.strip()}")
        for _ in range(30):
            code, out, err = _run_command(proxmox, f"qm status {shlex.quote(vmid)}")
            if code != 0:
                raise RuntimeError(f"Unable to read VM{vmid} status: {err.strip()}")
            if "stopped" in out.lower():
                break
            time.sleep(4)
        else:
            code, _, err = _run_command(proxmox, f"qm stop {shlex.quote(vmid)}")
            if code != 0:
                raise RuntimeError(f"Unable to force-stop VM{vmid}: {err.strip()}")
            time.sleep(5)

        code, _, err = _run_command(proxmox, f"qm start {shlex.quote(vmid)}")
        if code != 0 and "already running" not in str(err or "").lower():
            raise RuntimeError(f"Unable to start VM{vmid}: {err.strip()}")
    finally:
        proxmox.close()

    time.sleep(10)
    refreshed = _connect_client(host, user, password, attempts=20, delay_seconds=6)
    try:
        if not _guest_has_avx(refreshed):
            raise RuntimeError(
                f"VM{vmid} still does not expose AVX after CPU-profile change to {TARGET_CPU_MODEL}; "
                "MongoDB content-store cutover remains blocked"
            )
    finally:
        refreshed.close()
    return backup_root


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
lines = path.read_text(encoding='utf-8').splitlines() if path.exists() else []
positions = {{}}
for index, line in enumerate(lines):
    if '=' not in line or line.lstrip().startswith('#'):
        continue
    key = line.split('=', 1)[0].strip()
    if key:
        positions[key] = index
for key, value in updates.items():
    rendered = f"{{key}}={{value}}"
    if key in positions:
        lines[positions[key]] = rendered
    else:
        lines.append(rendered)
path.write_text("\\n".join(lines).rstrip() + "\\n", encoding='utf-8')
"""
    command = f"python3 - <<'PY'\n{script}\nPY"
    code, _, err = _run_command(client, command, sudo_password=sudo_password, use_sudo=True)
    if code != 0:
        raise RuntimeError(f"Unable to update {env_path}: {err.strip()}")


def main() -> int:
    host = _required_env("SIEM_VM4_HOST")
    user = _required_env("SIEM_VM4_USER")
    password = _required_env("SIEM_VM4_PASSWORD")
    remote_root = _required_env("SIEM_VM4_BASE_DIR", default=DEFAULT_REMOTE_ROOT)
    mongo_db = _validate_identifier(os.getenv("SIEM_VM4_MONGO_DB", "siem_content"), "Mongo database")
    mongo_user = _validate_identifier(os.getenv("SIEM_VM4_MONGO_USER", "siem_content"), "Mongo user")
    mongo_password = _required_env("SIEM_VM4_MONGO_PASSWORD")
    mongo_uri = f"mongodb://{mongo_user}:{mongo_password}@127.0.0.1:27017/{mongo_db}?authSource={mongo_db}"
    backup_root = f"/tmp/siem-web-content-store-backup-{datetime.now(tz=timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
    proxmox_host = str(os.getenv("SIEM_PROXMOX_HOST", "") or "").strip()
    proxmox_user = str(os.getenv("SIEM_PROXMOX_USER", "") or "").strip()
    proxmox_password = str(os.getenv("SIEM_PROXMOX_PASSWORD", "") or "").strip()
    vm4_vmid = str(os.getenv("SIEM_VM4_VMID", DEFAULT_VM4_VMID) or DEFAULT_VM4_VMID).strip()

    client = _connect_client(host, user, password)
    try:
        print(f"remote_root={remote_root}")
        print(f"backup_root={backup_root}")

        if not _guest_has_avx(client):
            client.close()
            if not (proxmox_host and proxmox_user and proxmox_password):
                raise RuntimeError(
                    "VM4 guest CPU does not expose AVX, and no Proxmox credentials were provided for auto-remediation. "
                    "Set SIEM_PROXMOX_HOST, SIEM_PROXMOX_USER, SIEM_PROXMOX_PASSWORD, and optionally SIEM_VM4_VMID."
                )
            cpu_backup_root = _ensure_vm4_cpu_profile(
                host=host,
                user=user,
                password=password,
                proxmox_host=proxmox_host,
                proxmox_user=proxmox_user,
                proxmox_password=proxmox_password,
                vmid=vm4_vmid,
            )
            print(f"vm4_cpu_profile_backup={cpu_backup_root}")
            client = _connect_client(host, user, password, attempts=10, delay_seconds=5)
            print(f"vm4_cpu_profile_ready={TARGET_CPU_MODEL}")

        _backup_path(client, REMOTE_WEB_ENV, backup_root, sudo_password=password, use_sudo=True)
        _backup_path(client, REMOTE_MONGOD_CONF, backup_root, sudo_password=password, use_sudo=True)
        _backup_path(client, RUNTIME_DOCS_ROOT, backup_root, sudo_password=password, use_sudo=True)

        install_cmd = (
            "set -eu && "
            "if ! command -v mongod >/dev/null 2>&1; then "
            "  apt-get update -y && "
            "  DEBIAN_FRONTEND=noninteractive apt-get install -y mongodb-org; "
            "fi && "
            "systemctl enable --now mongod"
        )
        code, out, err = _run_command(client, install_cmd, sudo_password=password, use_sudo=True)
        cleaned_out = _strip_sudo_echo(out, password)
        if cleaned_out.strip():
            print(cleaned_out, end="")
        if code != 0:
            raise RuntimeError(f"MongoDB install/start failed: {err.strip()}")

        active_cmd = "systemctl is-active mongod || true"
        code, out, err = _run_command(client, active_cmd, sudo_password=password, use_sudo=True)
        mongod_state = next((line.strip() for line in out.splitlines() if line.strip() and line.strip() != password), "")
        if mongod_state != "active":
            journal_cmd = "journalctl -u mongod -n 40 --no-pager || true"
            _, journal_out, _ = _run_command(client, journal_cmd, sudo_password=password, use_sudo=True)
            status_cmd = "systemctl disable --now mongod || true; systemctl reset-failed mongod || true"
            _run_command(client, status_cmd, sudo_password=password, use_sudo=True)
            details = str(journal_out or "").lower()
            if "signal=ill" in details or "status=4/ill" in details:
                raise RuntimeError(
                    "MongoDB server binary is incompatible with the current VM4 CPU model "
                    "(illegal instruction / missing CPU features). Live Mongo cutover is blocked until "
                    "the VM CPU model or Mongo version is changed."
                )
            raise RuntimeError(f"mongod did not become active after install/start: state={mongod_state}")

        provision_cmd = (
            f"cd {shlex.quote(posixpath.join(remote_root, 'services/web'))} && "
            f"{shlex.quote(posixpath.join(REMOTE_WEB_VENV, 'bin', 'python'))} - <<'PY'\n"
            "from pymongo import MongoClient\n"
            "client = MongoClient('mongodb://127.0.0.1:27017', serverSelectionTimeoutMS=2000)\n"
            f"db = client[{mongo_db!r}]\n"
            f"user = {mongo_user!r}\n"
            f"password = {mongo_password!r}\n"
            "try:\n"
            "    info = db.command('usersInfo', user)\n"
            "except Exception:\n"
            "    info = {'users': []}\n"
            "if info.get('users'):\n"
            "    db.command('updateUser', user, pwd=password, roles=[{'role': 'readWrite', 'db': db.name}])\n"
            "else:\n"
            "    db.command('createUser', user, pwd=password, roles=[{'role': 'readWrite', 'db': db.name}])\n"
            "print('mongo_user=ready')\n"
            "PY"
        )
        code, out, err = _run_command(client, provision_cmd)
        if out.strip():
            print(out, end="")
        if code != 0:
            raise RuntimeError(f"MongoDB user provisioning failed: {err.strip()}")

        conf_patch = f"""
from pathlib import Path

path = Path({REMOTE_MONGOD_CONF!r})
text = path.read_text(encoding='utf-8')
if 'security:' in text:
    lines = text.splitlines()
    updated = []
    in_security = False
    auth_written = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith('security:'):
            in_security = True
            updated.append('security:')
            continue
        if in_security and stripped and not line.startswith(' '):
            if not auth_written:
                updated.append('  authorization: enabled')
                auth_written = True
            in_security = False
        if in_security and stripped.startswith('authorization:'):
            updated.append('  authorization: enabled')
            auth_written = True
            continue
        updated.append(line)
    if in_security and not auth_written:
        updated.append('  authorization: enabled')
    text = "\\n".join(updated).rstrip() + "\\n"
else:
    text = text.rstrip() + "\\n\\nsecurity:\\n  authorization: enabled\\n"
path.write_text(text, encoding='utf-8')
"""
        conf_cmd = f"python3 - <<'PY'\n{conf_patch}\nPY"
        code, _, err = _run_command(client, conf_cmd, sudo_password=password, use_sudo=True)
        if code != 0:
            raise RuntimeError(f"Unable to patch {REMOTE_MONGOD_CONF}: {err.strip()}")

        restart_cmd = "systemctl restart mongod"
        code, out, err = _run_command(client, restart_cmd, sudo_password=password, use_sudo=True)
        cleaned_out = _strip_sudo_echo(out, password)
        if cleaned_out.strip():
            print(cleaned_out, end="")
        if code != 0:
            raise RuntimeError(f"mongod restart failed: {err.strip()}")

        verify_cmd = (
            f"cd {shlex.quote(posixpath.join(remote_root, 'services/web'))} && "
            f"{shlex.quote(posixpath.join(REMOTE_WEB_VENV, 'bin', 'python'))} - <<'PY'\n"
            "from pymongo import MongoClient\n"
            f"client = MongoClient({mongo_uri!r}, serverSelectionTimeoutMS=3000)\n"
            "client.admin.command('ping')\n"
            "print('mongo_auth=ok')\n"
            "PY"
        )
        code, out, err = _run_command(client, verify_cmd)
        if out.strip():
            print(out, end="")
        if code != 0:
            raise RuntimeError(f"MongoDB auth verification failed: {err.strip()}")

        _set_remote_env_values(
            client,
            REMOTE_WEB_ENV,
            {
                "SIEM_CONTENT_STORE_BACKEND": "mongo",
                "SIEM_MONGO_URI": mongo_uri,
                "SIEM_MONGO_DB": mongo_db,
            },
            sudo_password=password,
        )

        migrate_cmd = (
            f"cd {shlex.quote(posixpath.join(remote_root, 'services/web'))} && "
            f"set -a && source {shlex.quote(REMOTE_WEB_ENV)} && set +a && "
            f"{shlex.quote(posixpath.join(REMOTE_WEB_VENV, 'bin', 'python'))} - <<'PY'\n"
            "from app.deps import migrate_content_store, content_storage_status\n"
            "report = migrate_content_store()\n"
            "status = content_storage_status()\n"
            "print('migration_status=' + str(report.get('migration_status') or ''))\n"
            "print('backend=' + str(status.get('backend') or ''))\n"
            "print('requested_backend=' + str(status.get('requested_backend') or ''))\n"
            "print('collection_counts=' + str(status.get('collection_counts') or {}))\n"
            "PY"
        )
        code, out, err = _run_command(client, migrate_cmd, sudo_password=password, use_sudo=True)
        cleaned_out = _strip_sudo_echo(out, password)
        if cleaned_out.strip():
            print(cleaned_out, end="")
        if code != 0:
            raise RuntimeError(f"Content store migration failed: {err.strip()}")

        web_restart_cmd = "systemctl restart siem-web"
        code, out, err = _run_command(client, web_restart_cmd, sudo_password=password, use_sudo=True)
        cleaned_out = _strip_sudo_echo(out, password)
        if cleaned_out.strip():
            print(cleaned_out, end="")
        if code != 0:
            raise RuntimeError(f"siem-web restart failed: {err.strip()}")

        active_cmd = "systemctl is-active mongod siem-web"
        states: list[str] = []
        for _ in range(20):
            code, out, err = _run_command(client, active_cmd, sudo_password=password, use_sudo=True)
            states = [line.strip() for line in out.splitlines() if line.strip()]
            if code == 0 and states == ["active", "active"]:
                break
            time.sleep(2)
        else:
            raise RuntimeError(f"Service activation failed: stdout={states} stderr={err.strip()}")

        print("mongo_content_store=enabled")
        print("mongod status=active")
        print("siem-web status=active")
        print("cutover=success")
        print(f"backup_root={backup_root}")
        return 0
    finally:
        client.close()


if __name__ == "__main__":
    sys.exit(main())
