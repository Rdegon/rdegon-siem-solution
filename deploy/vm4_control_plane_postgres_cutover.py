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


def _required_env(name: str, *, default: str | None = None) -> str:
    value = os.getenv(name, default or "").strip()
    if value:
        return value
    raise SystemExit(f"Missing required environment variable: {name}")


def _validate_pg_identifier(value: str, label: str) -> str:
    safe = str(value or "").strip()
    if not safe or not safe.replace("_", "").isalnum() or not safe[0].isalpha():
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
text = "\\n".join(lines).rstrip() + "\\n"
path.write_text(text, encoding="utf-8")
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
    pg_db = _validate_pg_identifier(os.getenv("SIEM_VM4_PG_DB", "siem_control_plane"), "Postgres database")
    pg_user = _validate_pg_identifier(os.getenv("SIEM_VM4_PG_USER", "siem_control"), "Postgres user")
    pg_password = _required_env("SIEM_VM4_PG_PASSWORD")
    pg_port = str(int(os.getenv("SIEM_VM4_PG_PORT", "5432") or "5432"))
    backup_root = f"/tmp/siem-web-postgres-cutover-{datetime.now(tz=timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"

    client = _connect_client(host, user, password)
    try:
        print(f"remote_root={remote_root}")
        print(f"backup_root={backup_root}")

        _backup_path(client, REMOTE_WEB_ENV, backup_root, sudo_password=password, use_sudo=True)
        _backup_path(
            client,
            posixpath.join(remote_root, "services/web/app/runtime-control-plane"),
            backup_root,
            sudo_password=password,
            use_sudo=True,
        )

        install_cmd = (
            "set -eu && "
            "if ! command -v psql >/dev/null 2>&1; then "
            "  apt-get update -y && "
            "  DEBIAN_FRONTEND=noninteractive apt-get install -y postgresql postgresql-contrib; "
            "fi && "
            "systemctl enable --now postgresql"
        )
        code, out, err = _run_command(client, install_cmd, sudo_password=password, use_sudo=True)
        if out.strip():
            print(out, end="")
        if code != 0:
            raise RuntimeError(f"Postgres install/start failed: {err.strip()}")

        role_exists_sql = shlex.quote(f"SELECT 1 FROM pg_roles WHERE rolname = '{pg_user}'")
        create_role_sql = shlex.quote(f"CREATE ROLE {pg_user} LOGIN PASSWORD '{pg_password}';")
        alter_role_sql = shlex.quote(f"ALTER ROLE {pg_user} WITH LOGIN PASSWORD '{pg_password}';")
        db_exists_sql = shlex.quote(f"SELECT 1 FROM pg_database WHERE datname = '{pg_db}'")
        provision_cmd = (
            "set -eu && "
            f"if ! sudo -u postgres psql -tAc {role_exists_sql} | grep -q 1; then "
            f"  sudo -u postgres psql -c {create_role_sql} ; "
            "fi && "
            f"sudo -u postgres psql -c {alter_role_sql} && "
            f"if ! sudo -u postgres psql -tAc {db_exists_sql} | grep -q 1; then "
            f"  sudo -u postgres createdb -O {shlex.quote(pg_user)} {shlex.quote(pg_db)} ; "
            "fi"
        )
        code, out, err = _run_command(client, provision_cmd, sudo_password=password, use_sudo=True)
        if out.strip():
            print(out, end="")
        if code != 0:
            raise RuntimeError(f"Postgres role/database provisioning failed: {err.strip()}")

        web_root = posixpath.join(remote_root.rstrip("/"), "services/web")
        pip_cmd = (
            f"cd {shlex.quote(web_root)} && "
            f"{shlex.quote(posixpath.join(REMOTE_WEB_VENV, 'bin', 'pip'))} install -r requirements-web.txt"
        )
        code, out, err = _run_command(client, pip_cmd)
        if out.strip():
            print(out, end="")
        if code != 0:
            raise RuntimeError(f"venv-web dependency install failed: {err.strip()}")

        _set_remote_env_values(
            client,
            REMOTE_WEB_ENV,
            {
                "SIEM_CONTROL_PLANE_BACKEND": "postgres",
                "SIEM_PG_HOST": "127.0.0.1",
                "SIEM_PG_PORT": pg_port,
                "SIEM_PG_DB": pg_db,
                "SIEM_PG_USER": pg_user,
                "SIEM_PG_PASSWORD": pg_password,
            },
            sudo_password=password,
        )

        migrate_cmd = (
            f"cd {shlex.quote(web_root)} && "
            f"set -a && source {shlex.quote(REMOTE_WEB_ENV)} && set +a && "
            f"{shlex.quote(posixpath.join(REMOTE_WEB_VENV, 'bin', 'python'))} - <<'PY'\n"
            "from app.enterprise_control_plane import control_plane_storage_status, migrate_filesystem_snapshot_to_active_store\n"
            "report = migrate_filesystem_snapshot_to_active_store(actor='vm4-postgres-cutover', force=True)\n"
            "status = control_plane_storage_status()\n"
            "print('migration_status=' + str(report.get('migration_status') or ''))\n"
            "print('backend=' + str(status.get('backend') or ''))\n"
            "print('last_migration_at=' + str(status.get('last_migration_at') or ''))\n"
            "print('collections=' + str(status.get('collection_counts') or {}))\n"
            "PY"
        )
        code, out, err = _run_command(client, migrate_cmd, sudo_password=password, use_sudo=True)
        if out.strip():
            print(out, end="")
        if code != 0:
            raise RuntimeError(f"Control-plane migration failed: {err.strip()}")

        restart_cmd = "systemctl restart siem-web"
        code, out, err = _run_command(client, restart_cmd, sudo_password=password, use_sudo=True)
        if out.strip():
            print(out, end="")
        if code != 0:
            raise RuntimeError(f"siem-web restart failed: {err.strip()}")

        active_cmd = "systemctl is-active siem-web"
        service_state = ""
        for _ in range(20):
            code, out, err = _run_command(client, active_cmd, sudo_password=password, use_sudo=True)
            service_state = next((line.strip() for line in out.splitlines() if line.strip()), "")
            if code == 0 and service_state == "active":
                break
            time.sleep(2)
        else:
            raise RuntimeError(f"siem-web failed to become active: stdout={service_state} stderr={err.strip()}")

        print("postgres_control_plane=enabled")
        print("siem-web status=active")
        print("cutover=success")
        print(f"backup_root={backup_root}")
        return 0
    finally:
        client.close()


if __name__ == "__main__":
    sys.exit(main())
