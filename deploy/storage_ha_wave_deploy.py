from __future__ import annotations

import base64
import json
import os
import posixpath
import re
import secrets
import shlex
import string
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

try:
    import paramiko
except ModuleNotFoundError:  # pragma: no cover - exercised in CI/unit imports
    paramiko = None  # type: ignore[assignment]


ROOT = Path(__file__).resolve().parents[1]
REMOTE_STORAGE_HA_ENV = "/etc/siem/storage-ha.env"
REMOTE_WEB_ENV = "/etc/siem/web.env"
REMOTE_STORAGE_ENV = "/etc/siem/storage.env"
REMOTE_VM5_STANDBY_ENV = "/etc/siem/storage-standby.env"
TARGET_CPU_MODEL = "x86-64-v3"
DEFAULT_REPLICA_SET = "siem-rs"
CLICKHOUSE_REPO_KEY_ID = "3E4AD4719DDE9A38"
CLICKHOUSE_REPO_KEYRING = "/etc/apt/keyrings/clickhouse.gpg"
CLICKHOUSE_REPO_LIST = "/etc/apt/sources.list.d/clickhouse.list"

if TYPE_CHECKING:  # pragma: no cover
    import paramiko as _paramiko
SYNC_TABLES = (
    "active_list_items",
    "alerts_agg",
    "alerts_raw",
    "alert_history",
    "cmdb_assets",
    "correlation_rules_batch",
    "correlation_rules_stream",
    "detection_rule_catalog",
    "filter_rules",
    "normalizer_rules",
    "stream_corr_runtime_status",
    "threat_intel_iocs",
    "vuln_asset_bindings",
    "vuln_findings",
    "vuln_scan_runs",
)
BOOTSTRAP_TABLES = (
    "events",
    "events_cold",
    *SYNC_TABLES,
)
OPTIONAL_BOOTSTRAP_TABLES = {
    "events_cold",
}
DEFAULT_EVENTS_BOOTSTRAP_LOOKBACK_HOURS = 6
REMOTE_VM5_FILES = (
    ("writer_worker.py", "/opt/siem/siem-solution/services/writer/worker.py", "0644"),
    ("services/__init__.py", "/opt/siem/siem-solution/services/__init__.py", "0644"),
    ("services/redis_runtime.py", "/opt/siem/siem-solution/services/redis_runtime.py", "0644"),
    ("services/transport_runtime.py", "/opt/siem/siem-solution/services/transport_runtime.py", "0644"),
    ("deploy/vm5_clickhouse_standby_sync.py", "/opt/siem/siem-solution/deploy/vm5_clickhouse_standby_sync.py", "0755"),
    ("deploy/vm5/siem-writer-standby.service", "/etc/systemd/system/siem-writer-standby.service", "0644"),
    ("deploy/vm5/siem-clickhouse-standby-sync.service", "/etc/systemd/system/siem-clickhouse-standby-sync.service", "0644"),
    ("deploy/vm5/siem-clickhouse-standby-sync.timer", "/etc/systemd/system/siem-clickhouse-standby-sync.timer", "0644"),
)


@dataclass(frozen=True)
class HostSpec:
    host: str
    user: str
    password: str


def _required_env(name: str, *, default: str | None = None) -> str:
    raw = os.getenv(name)
    if raw is not None and str(raw).strip():
        return str(raw).strip()
    if default is not None and str(default).strip():
        return str(default).strip()
    raise SystemExit(f"Missing required environment variable: {name}")


def _split_ssh_host_port(host: str) -> tuple[str, int]:
    value = str(host or "").strip()
    if not value:
        raise RuntimeError("Empty SSH host value")
    if value.count(":") == 1:
        candidate_host, candidate_port = value.rsplit(":", 1)
        if candidate_host and candidate_port.isdigit():
            return candidate_host, 22 if candidate_port == "8006" else int(candidate_port)
    return value, 22


def _connect_client(host: str, user: str, password: str, *, attempts: int = 8, delay_seconds: float = 5.0) -> paramiko.SSHClient:
    if paramiko is None:
        raise RuntimeError("paramiko is required to execute the storage HA wave")
    connect_host, connect_port = _split_ssh_host_port(host)
    last_error: Exception | None = None
    for attempt in range(1, attempts + 1):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                connect_host,
                port=connect_port,
                username=user,
                password=password,
                timeout=25,
                banner_timeout=25,
                auth_timeout=25,
                look_for_keys=False,
                allow_agent=False,
            )
            return client
        except Exception as exc:  # noqa: BLE001
            last_error = exc
            client.close()
            if attempt == attempts:
                break
            print(f"storage_ha ssh retry host={connect_host}:{connect_port} attempt={attempt}/{attempts} error={exc}")
            time.sleep(delay_seconds)
    raise RuntimeError(f"Unable to connect to {connect_host}:{connect_port}: {last_error}")


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


def _strip_sudo_echo(text: str, sudo_password: str) -> str:
    if not sudo_password:
        return text
    return "\n".join(line for line in str(text or "").splitlines() if line.strip() != sudo_password)


def _parse_env(text: str) -> dict[str, str]:
    payload: dict[str, str] = {}
    for raw_line in str(text or "").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        payload[key.strip()] = value.strip()
    return payload


def _merge_env_text(existing_text: str, updates: dict[str, str]) -> str:
    lines = existing_text.splitlines() if existing_text.strip() else []
    positions: dict[str, int] = {}
    for index, line in enumerate(lines):
        if "=" not in line or line.lstrip().startswith("#"):
            continue
        key = line.split("=", 1)[0].strip()
        if key:
            positions[key] = index
    for key, value in updates.items():
        rendered = f"{key}={value}"
        if key in positions:
            lines[positions[key]] = rendered
        else:
            lines.append(rendered)
    return "\n".join(lines).rstrip() + "\n"


def _last_nonempty_line(text: str) -> str:
    for line in reversed(str(text or "").splitlines()):
        if line.strip():
            return line.strip()
    return ""


def _command_failure_text(out: str, err: str, *, sudo_password: str = "") -> str:
    cleaned_out = _strip_sudo_echo(out, sudo_password).strip()
    cleaned_err = _strip_sudo_echo(err, sudo_password).strip()
    if cleaned_out and cleaned_err:
        return f"{cleaned_out}\n{cleaned_err}"
    return cleaned_out or cleaned_err


def _generate_mongo_keyfile_text(length: int = 768) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _normalize_mongo_keyfile_b64(value: str) -> str:
    raw = str(value or "").strip()
    if raw:
        try:
            decoded = base64.b64decode(raw, validate=True).decode("ascii", errors="strict")
        except Exception:  # noqa: BLE001
            decoded = ""
        if decoded and 6 <= len(decoded) <= 1024 and all(char.isascii() and char.isalnum() for char in decoded):
            return base64.b64encode(decoded.encode("ascii")).decode("ascii")
    return base64.b64encode(_generate_mongo_keyfile_text().encode("ascii")).decode("ascii")


def _allow_ufw_tcp_rule(client: paramiko.SSHClient, *, sudo_password: str, source_host: str, port: int) -> None:
    code, out, err = _run_command(client, "command -v ufw >/dev/null 2>&1 && ufw status", sudo_password=sudo_password, use_sudo=True)
    if code != 0 or "Status: active" not in out:
        return
    command = f"ufw allow from {shlex.quote(source_host)} to any port {port} proto tcp"
    code, _, err = _run_command(client, command, sudo_password=sudo_password, use_sudo=True)
    if code != 0:
        raise RuntimeError(f"Unable to open ufw port {port} for {source_host}: {err.strip()}")


def _configure_storage_firewall(
    *,
    vm1_client: paramiko.SSHClient,
    vm4_client: paramiko.SSHClient,
    vm5_client: paramiko.SSHClient,
    vm1_host: str,
    vm4_host: str,
    vm5_host: str,
    vm1_password: str,
    vm4_password: str,
    vm5_password: str,
) -> None:
    for source in (vm1_host, vm4_host):
        _allow_ufw_tcp_rule(vm4_client, sudo_password=vm4_password, source_host=source, port=5432)
    _allow_ufw_tcp_rule(vm1_client, sudo_password=vm1_password, source_host=vm4_host, port=5432)
    mongo_members = (vm1_host, vm4_host, vm5_host)
    for target_client, target_password in (
        (vm1_client, vm1_password),
        (vm4_client, vm4_password),
        (vm5_client, vm5_password),
    ):
        for source in mongo_members:
            _allow_ufw_tcp_rule(target_client, sudo_password=target_password, source_host=source, port=27017)


def _configure_clickhouse_standby_network(
    client: paramiko.SSHClient,
    *,
    sudo_password: str,
    host_ip: str,
    allowed_sources: tuple[str, ...],
) -> None:
    listen_xml = f"<clickhouse><listen_host>127.0.0.1</listen_host><listen_host>{host_ip}</listen_host></clickhouse>\n"
    _write_remote_text(client, "/etc/clickhouse-server/config.d/listen.xml", listen_xml, mode="0644", sudo_password=sudo_password)
    for source in allowed_sources:
        _allow_ufw_tcp_rule(client, sudo_password=sudo_password, source_host=source, port=8123)
        _allow_ufw_tcp_rule(client, sudo_password=sudo_password, source_host=source, port=9000)
    code, _, err = _run_command(client, "systemctl restart clickhouse-server && systemctl is-active clickhouse-server", sudo_password=sudo_password, use_sudo=True)
    if code != 0:
        raise RuntimeError(f"Unable to restart ClickHouse standby after network config: {err.strip()}")


def _read_remote_file(client: paramiko.SSHClient, path: str, *, sudo_password: str = "", use_sudo: bool = False) -> str:
    code, out, err = _run_command(client, f"cat {shlex.quote(path)}", sudo_password=sudo_password, use_sudo=use_sudo)
    cleaned = _strip_sudo_echo(out, sudo_password)
    if code != 0:
        raise RuntimeError(f"Unable to read remote file {path}: {err.strip()}")
    return cleaned


def _write_remote_text(client: paramiko.SSHClient, path: str, content: str, *, mode: str = "0600", sudo_password: str) -> None:
    payload = base64.b64encode(content.encode("utf-8")).decode("ascii")
    script = (
        "import base64\n"
        "from pathlib import Path\n"
        f"path = Path({path!r})\n"
        "path.parent.mkdir(parents=True, exist_ok=True)\n"
        f"path.write_bytes(base64.b64decode({payload!r}))\n"
        f"path.chmod(0o{mode})\n"
    )
    code, _, err = _run_command(client, f"python3 - <<'PY'\n{script}\nPY", sudo_password=sudo_password, use_sudo=True)
    if code != 0:
        raise RuntimeError(f"Unable to write remote file {path}: {err.strip()}")


def _mkdir_remote(sftp: paramiko.SFTPClient, path: str) -> None:
    parts = [part for part in path.split("/") if part]
    current = ""
    for part in parts:
        current = f"{current}/{part}"
        try:
            sftp.stat(current)
        except OSError:
            sftp.mkdir(current)


def _upload_file(client: paramiko.SSHClient, local_path: Path, remote_path: str, *, mode: str, sudo_password: str) -> None:
    if not local_path.exists():
        raise FileNotFoundError(f"Missing required local file: {local_path}")
    temp_path = f"/tmp/{Path(remote_path).name}.{secrets.token_hex(4)}"
    sftp = client.open_sftp()
    try:
        _mkdir_remote(sftp, posixpath.dirname(temp_path))
        sftp.put(str(local_path), temp_path)
    finally:
        sftp.close()
    command = (
        f"install -d -m 0755 {shlex.quote(posixpath.dirname(remote_path))} && "
        f"install -m {mode} {shlex.quote(temp_path)} {shlex.quote(remote_path)} && "
        f"rm -f {shlex.quote(temp_path)}"
    )
    code, _, err = _run_command(client, command, sudo_password=sudo_password, use_sudo=True)
    if code != 0:
        raise RuntimeError(f"Unable to install {remote_path}: {err.strip()}")


def render_control_plane_pg_dsn(*, primary_host: str, standby_host: str, db: str, user: str, password: str) -> str:
    return (
        f"host={primary_host},{standby_host} "
        "port=5432,5432 "
        f"dbname={db} user={user} password={password} "
        "target_session_attrs=read-write connect_timeout=2"
    )


def render_mongo_replica_uri(*, hosts: tuple[str, str, str], db: str, user: str, password: str, replica_set: str) -> str:
    members = ",".join(f"{host}:27017" for host in hosts)
    return f"mongodb://{user}:{password}@{members}/{db}?authSource={db}&replicaSet={replica_set}"


def render_clickhouse_hosts(*, primary_host: str, standby_host: str) -> str:
    return f"{primary_host}:8123,{standby_host}:8123"


def _ensure_storage_ha_env(client: paramiko.SSHClient, *, sudo_password: str) -> dict[str, str]:
    code, out, _ = _run_command(client, f"cat {shlex.quote(REMOTE_STORAGE_HA_ENV)} || true", sudo_password=sudo_password, use_sudo=True)
    existing = _strip_sudo_echo(out, sudo_password) if code == 0 else ""
    payload = _parse_env(existing)
    merged = _merge_env_text(
        existing,
        {
            "SIEM_PG_REPL_USER": payload.get("SIEM_PG_REPL_USER", "siem_repl"),
            "SIEM_PG_REPL_PASSWORD": payload.get("SIEM_PG_REPL_PASSWORD", secrets.token_urlsafe(24)),
            "SIEM_MONGO_ADMIN_USER": payload.get("SIEM_MONGO_ADMIN_USER", "siem_root"),
            "SIEM_MONGO_ADMIN_PASSWORD": payload.get("SIEM_MONGO_ADMIN_PASSWORD", secrets.token_urlsafe(24)),
            "SIEM_MONGO_KEYFILE_B64": _normalize_mongo_keyfile_b64(payload.get("SIEM_MONGO_KEYFILE_B64", "")),
            "SIEM_MONGO_REPLICA_SET": payload.get("SIEM_MONGO_REPLICA_SET", DEFAULT_REPLICA_SET),
        },
    )
    _write_remote_text(client, REMOTE_STORAGE_HA_ENV, merged, mode="0600", sudo_password=sudo_password)
    return _parse_env(merged)


def _parse_qm_cpu(config_text: str) -> str:
    for raw_line in str(config_text or "").splitlines():
        line = raw_line.strip()
        if line.startswith("cpu:"):
            return line.split(":", 1)[1].strip()
    return ""


def _guest_has_avx(client: paramiko.SSHClient) -> bool:
    code, out, err = _run_command(client, "lscpu | grep '^Flags:' || true")
    if code != 0:
        raise RuntimeError(f"Unable to query CPU flags: {err.strip()}")
    text = f" {str(out or '').lower()} "
    return " avx " in text


def _wait_for_ssh(host: HostSpec, *, attempts: int = 30, delay_seconds: float = 6.0) -> None:
    last_error: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            client = _connect_client(host.host, host.user, host.password, attempts=1)
            client.close()
            return
        except Exception as exc:  # noqa: BLE001
            last_error = exc
            if attempt == attempts:
                break
            print(f"storage_ha ssh wait host={host.host} attempt={attempt}/{attempts}")
            time.sleep(delay_seconds)
    raise RuntimeError(f"Host did not become reachable over SSH: {host.host} error={last_error}")


def _ensure_cpu_model(proxmox: paramiko.SSHClient, *, vmid: str, host: HostSpec) -> None:
    code, out, err = _run_command(proxmox, f"qm config {shlex.quote(vmid)}")
    if code != 0:
        raise RuntimeError(f"Unable to query qm config for {vmid}: {err.strip()}")
    if _parse_qm_cpu(out) == TARGET_CPU_MODEL:
        client = _connect_client(host.host, host.user, host.password, attempts=3)
        try:
            if _guest_has_avx(client):
                print(f"cpu_model host={host.host} status=ready model={TARGET_CPU_MODEL}")
                return
        finally:
            client.close()
    code, _, err = _run_command(proxmox, f"qm set {shlex.quote(vmid)} --cpu {shlex.quote(TARGET_CPU_MODEL)}")
    if code != 0:
        raise RuntimeError(f"Unable to set CPU model for {vmid}: {err.strip()}")
    _run_command(proxmox, f"qm reboot {shlex.quote(vmid)}")
    _wait_for_ssh(host)
    client = _connect_client(host.host, host.user, host.password)
    try:
        if not _guest_has_avx(client):
            raise RuntimeError(f"Guest {host.host} still lacks AVX after CPU model update")
    finally:
        client.close()


def _ensure_postgres_install(client: paramiko.SSHClient, *, sudo_password: str) -> str:
    code, _, _ = _run_command(client, "command -v psql >/dev/null 2>&1", sudo_password=sudo_password, use_sudo=True)
    if code != 0:
        install_cmd = (
            "export DEBIAN_FRONTEND=noninteractive && "
            "apt-get update -y && "
            "apt-get install -y postgresql postgresql-contrib"
        )
        code, _, err = _run_command(client, install_cmd, sudo_password=sudo_password, use_sudo=True)
        if code != 0:
            raise RuntimeError(f"Unable to install PostgreSQL: {err.strip()}")
    code, out, err = _run_command(client, "psql -V | awk '{print $3}'")
    if code != 0:
        raise RuntimeError(f"Unable to detect PostgreSQL version: {err.strip()}")
    return str(out or "").strip().split(".", 1)[0]


def _pg_hba_path(major: str) -> str:
    return f"/etc/postgresql/{major}/main/pg_hba.conf"


def _pg_data_dir(major: str) -> str:
    return f"/var/lib/postgresql/{major}/main"


def _configure_postgres_primary(
    client: paramiko.SSHClient,
    *,
    sudo_password: str,
    primary_host: str,
    standby_host: str,
    replication_user: str,
    replication_password: str,
) -> str:
    major = _ensure_postgres_install(client, sudo_password=sudo_password)
    code, _, err = _run_command(client, "systemctl enable --now postgresql", sudo_password=sudo_password, use_sudo=True)
    if code != 0:
        raise RuntimeError(f"Unable to enable PostgreSQL: {err.strip()}")
    tune_cmd = (
        "sudo -u postgres psql -c \"ALTER SYSTEM SET listen_addresses='*';\" && "
        "sudo -u postgres psql -c \"ALTER SYSTEM SET wal_level='replica';\" && "
        "sudo -u postgres psql -c \"ALTER SYSTEM SET max_wal_senders='10';\" && "
        "sudo -u postgres psql -c \"ALTER SYSTEM SET max_replication_slots='10';\" && "
        "sudo -u postgres psql -c \"ALTER SYSTEM SET hot_standby='on';\""
    )
    code, _, err = _run_command(client, tune_cmd, sudo_password=sudo_password, use_sudo=True)
    if code != 0:
        raise RuntimeError(f"Unable to tune PostgreSQL primary: {err.strip()}")
    script = (
        "from pathlib import Path\n"
        f"path = Path({_pg_hba_path(major)!r})\n"
        "lines = path.read_text(encoding='utf-8').splitlines()\n"
        f"entries = [\n"
        f"    'host replication {replication_user} {standby_host}/32 scram-sha-256',\n"
        f"    'host all all {primary_host}/32 scram-sha-256',\n"
        f"    'host all all {standby_host}/32 scram-sha-256',\n"
        "]\n"
        "for entry in entries:\n"
        "    if entry not in lines:\n"
        "        lines.append(entry)\n"
        "path.write_text('\\n'.join(lines).rstrip() + '\\n', encoding='utf-8')\n"
    )
    code, _, err = _run_command(client, f"python3 - <<'PY'\n{script}\nPY", sudo_password=sudo_password, use_sudo=True)
    if code != 0:
        raise RuntimeError(f"Unable to update pg_hba.conf: {err.strip()}")
    role_sql = (
        f"DO $$ BEGIN "
        f"IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{replication_user}') THEN "
        f"CREATE ROLE {replication_user} WITH REPLICATION LOGIN PASSWORD '{replication_password}'; "
        f"ELSE ALTER ROLE {replication_user} WITH REPLICATION LOGIN PASSWORD '{replication_password}'; "
        f"END IF; END $$;"
    )
    code, _, err = _run_command(client, f"sudo -u postgres psql -c {shlex.quote(role_sql)}", sudo_password=sudo_password, use_sudo=True)
    if code != 0:
        raise RuntimeError(f"Unable to provision PostgreSQL replication role: {err.strip()}")
    code, out, err = _run_command(client, "systemctl restart postgresql && sudo -u postgres psql -tAc 'SELECT pg_is_in_recovery()' 2>/dev/null", sudo_password=sudo_password, use_sudo=True)
    if code != 0 or _last_nonempty_line(out) != "f":
        raise RuntimeError(f"PostgreSQL primary verification failed: stdout={out.strip()} stderr={err.strip()}")
    return major


def _configure_postgres_standby(
    client: paramiko.SSHClient,
    *,
    sudo_password: str,
    primary_host: str,
    standby_host: str,
    replication_user: str,
    replication_password: str,
    major: str,
) -> None:
    _ensure_postgres_install(client, sudo_password=sudo_password)
    data_dir = _pg_data_dir(major)
    stale_backup_pattern = f"^/usr/lib/postgresql/.*/bin/pg_basebackup .* -h {primary_host} .* -U {replication_user}( |$)"
    command = (
        f"pkill -u postgres -f {shlex.quote(stale_backup_pattern)} || true && "
        "systemctl stop postgresql || true && "
        f"rm -rf {shlex.quote(data_dir)} && "
        f"install -d -o postgres -g postgres -m 0700 {shlex.quote(data_dir)} && "
        f"sudo -u postgres env PGPASSWORD={shlex.quote(replication_password)} pg_basebackup "
        f"-h {shlex.quote(primary_host)} -D {shlex.quote(data_dir)} "
        f"-U {shlex.quote(replication_user)} -Fp -Xs -P -R && "
        "systemctl enable --now postgresql && "
        "sudo -u postgres psql -tAc 'SELECT pg_is_in_recovery()'"
    )
    code, out, err = _run_command(client, command, sudo_password=sudo_password, use_sudo=True)
    if code != 0 or _last_nonempty_line(out) != "t":
        raise RuntimeError(f"PostgreSQL standby verification failed: stdout={out.strip()} stderr={err.strip()}")
    hba_script = (
        "from pathlib import Path\n"
        f"path = Path({_pg_hba_path(major)!r})\n"
        "lines = path.read_text(encoding='utf-8').splitlines()\n"
        f"entries = [\n"
        f"    'host all all {primary_host}/32 scram-sha-256',\n"
        f"    'host all all {standby_host}/32 scram-sha-256',\n"
        "]\n"
        "for entry in entries:\n"
        "    if entry not in lines:\n"
        "        lines.append(entry)\n"
        "path.write_text('\\n'.join(lines).rstrip() + '\\n', encoding='utf-8')\n"
    )
    code, _, err = _run_command(client, f"python3 - <<'PY'\n{hba_script}\nPY", sudo_password=sudo_password, use_sudo=True)
    if code != 0:
        raise RuntimeError(f"Unable to update PostgreSQL standby pg_hba.conf: {err.strip()}")
    tune_cmd = (
        "sudo -u postgres psql -c \"ALTER SYSTEM SET hot_standby='on';\" && "
        "sudo -u postgres psql -c \"ALTER SYSTEM SET listen_addresses='*';\" && "
        "systemctl restart postgresql && "
        "sudo -u postgres psql -tAc 'SELECT pg_is_in_recovery()'"
    )
    code, out, err = _run_command(client, tune_cmd, sudo_password=sudo_password, use_sudo=True)
    if code != 0 or _last_nonempty_line(out) != "t":
        raise RuntimeError(f"PostgreSQL standby reload failed: stdout={out.strip()} stderr={err.strip()}")


def _remote_find_files(client: paramiko.SSHClient, pattern: str) -> list[str]:
    code, out, err = _run_command(client, f"find /etc/apt /etc/apt/keyrings /usr/share/keyrings -maxdepth 3 -type f 2>/dev/null | grep -Ei {shlex.quote(pattern)} || true")
    if code != 0:
        raise RuntimeError(f"Unable to enumerate repo files with pattern {pattern}: {err.strip()}")
    return [line.strip() for line in out.splitlines() if line.strip()]


def _copy_remote_file(source_client: paramiko.SSHClient, target_client: paramiko.SSHClient, source_path: str, target_path: str, *, target_sudo_password: str) -> None:
    code, out, err = _run_command(source_client, f"base64 -w0 {shlex.quote(source_path)}")
    if code != 0:
        raise RuntimeError(f"Unable to read source file {source_path}: {err.strip()}")
    payload = str(out or "").strip()
    script = (
        "import base64\n"
        "from pathlib import Path\n"
        f"path = Path({target_path!r})\n"
        "path.parent.mkdir(parents=True, exist_ok=True)\n"
        f"path.write_bytes(base64.b64decode({payload!r}))\n"
    )
    code, _, err = _run_command(target_client, f"python3 - <<'PY'\n{script}\nPY", sudo_password=target_sudo_password, use_sudo=True)
    if code != 0:
        raise RuntimeError(f"Unable to copy remote file to {target_path}: {err.strip()}")


def _copy_repo_files(source_client: paramiko.SSHClient, target_client: paramiko.SSHClient, *, pattern: str, target_sudo_password: str) -> None:
    for source_path in _remote_find_files(source_client, pattern):
        _copy_remote_file(source_client, target_client, source_path, source_path, target_sudo_password=target_sudo_password)


def _ensure_mongodb_install(source_vm4: paramiko.SSHClient, target_client: paramiko.SSHClient, *, sudo_password: str) -> None:
    code, _, _ = _run_command(target_client, "command -v mongod >/dev/null 2>&1", sudo_password=sudo_password, use_sudo=True)
    if code == 0:
        return
    _copy_repo_files(source_vm4, target_client, pattern="mongo|mongodb", target_sudo_password=sudo_password)
    install_cmd = "export DEBIAN_FRONTEND=noninteractive && apt-get update -y && apt-get install -y mongodb-org"
    code, _, err = _run_command(target_client, install_cmd, sudo_password=sudo_password, use_sudo=True)
    if code != 0:
        raise RuntimeError(f"Unable to install MongoDB: {err.strip()}")


def _render_mongod_conf(*, host_ip: str, replica_set: str, auth_enabled: bool) -> str:
    security_lines = f"  authorization: {'enabled' if auth_enabled else 'disabled'}\n"
    if auth_enabled:
        security_lines += "  keyFile: /etc/mongod.keyfile\n"
    return (
        "storage:\n"
        "  dbPath: /var/lib/mongodb\n"
        "systemLog:\n"
        "  destination: file\n"
        "  logAppend: true\n"
        "  path: /var/log/mongodb/mongod.log\n"
        "net:\n"
        "  port: 27017\n"
        f"  bindIp: 127.0.0.1,{host_ip}\n"
        "processManagement:\n"
        "  timeZoneInfo: /usr/share/zoneinfo\n"
        "replication:\n"
        f"  replSetName: {replica_set}\n"
        "security:\n"
        f"{security_lines}"
    )


def _run_mongosh_eval(
    client: paramiko.SSHClient,
    *,
    sudo_password: str,
    script: str,
    uri: str = "",
    attempts: int = 8,
    delay_seconds: float = 5.0,
) -> str:
    remote_script_path = "/tmp/siem-storage-ha-mongosh.js"
    _write_remote_text(client, remote_script_path, script, mode="0600", sudo_password=sudo_password)
    if uri:
        command = f"mongosh {shlex.quote(uri)} --quiet {shlex.quote(remote_script_path)}"
    else:
        command = f"mongosh --quiet {shlex.quote(remote_script_path)}"
    last_out = ""
    last_err = ""
    for attempt in range(1, attempts + 1):
        code, out, err = _run_command(client, command, sudo_password=sudo_password, use_sudo=True)
        cleaned_out = _strip_sudo_echo(out, sudo_password).strip()
        cleaned_err = _strip_sudo_echo(err, sudo_password).strip()
        if code == 0:
            return cleaned_out
        last_out = cleaned_out
        last_err = cleaned_err
        if attempt < attempts:
            time.sleep(delay_seconds)
    raise RuntimeError(f"mongosh eval failed: stdout={last_out} stderr={last_err}")


def _resolve_remote_secret_env_values(
    client: paramiko.SSHClient,
    *,
    sudo_password: str,
    env_path: str,
    env_names: tuple[str, ...],
) -> dict[str, str]:
    requested = [str(name).strip() for name in env_names if str(name).strip()]
    if not requested:
        return {}
    remote_script = (
        "import json\n"
        "import os\n"
        "import sys\n"
        "from pathlib import Path\n"
        "for candidate in (\n"
        "    '/opt/siem/siem-solution',\n"
        "    '/opt/siem/siem-solution/services/web/app',\n"
        "    '/opt/siem/siem-solution/app',\n"
        "):\n"
        "    if Path(candidate).exists() and candidate not in sys.path:\n"
        "        sys.path.insert(0, candidate)\n"
        "import secret_runtime\n"
        "def parse_env(text):\n"
        "    payload = {}\n"
        "    for raw_line in text.splitlines():\n"
        "        line = raw_line.strip()\n"
        "        if not line or line.startswith('#') or '=' not in line:\n"
        "            continue\n"
        "        key, value = line.split('=', 1)\n"
        "        payload[key.strip()] = value.strip().strip('\"').strip(\"'\")\n"
        "    return payload\n"
        f"payload = parse_env(Path({env_path!r}).read_text(encoding='utf-8', errors='replace'))\n"
        "for key, value in payload.items():\n"
        "    os.environ[str(key)] = str(value)\n"
        f"names = json.loads({json.dumps(requested)!r})\n"
        "resolved = {}\n"
        "for name in names:\n"
        "    value, _, _ = secret_runtime.resolve_secret_value(name)\n"
        "    if value:\n"
        "        resolved[str(name)] = str(value)\n"
        "print(json.dumps(resolved, ensure_ascii=False))\n"
    )
    code, out, err = _run_command(client, f"python3 - <<'PY'\n{remote_script}\nPY", sudo_password=sudo_password, use_sudo=True)
    cleaned_out = _strip_sudo_echo(out, sudo_password).strip()
    cleaned_err = _strip_sudo_echo(err, sudo_password).strip()
    if code != 0:
        raise RuntimeError(f"Unable to resolve remote secret env values from {env_path}: stdout={cleaned_out} stderr={cleaned_err}")
    try:
        return {str(key): str(value) for key, value in json.loads(cleaned_out or "{}").items() if str(value)}
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Unable to parse remote secret env values from {env_path}: {cleaned_out}") from exc


def _configure_mongod_node(
    client: paramiko.SSHClient,
    *,
    sudo_password: str,
    host_ip: str,
    replica_set: str,
    keyfile_b64: str,
    auth_enabled: bool,
) -> None:
    keyfile_text = base64.b64decode(keyfile_b64).decode("utf-8", errors="strict")
    _write_remote_text(client, "/etc/mongod.keyfile", keyfile_text, mode="0400", sudo_password=sudo_password)
    _write_remote_text(client, "/etc/mongod.conf", _render_mongod_conf(host_ip=host_ip, replica_set=replica_set, auth_enabled=auth_enabled), mode="0644", sudo_password=sudo_password)
    code, _, err = _run_command(client, "chown mongodb:mongodb /etc/mongod.keyfile /etc/mongod.conf && systemctl enable --now mongod && systemctl restart mongod", sudo_password=sudo_password, use_sudo=True)
    if code != 0:
        raise RuntimeError(f"Unable to configure mongod on {host_ip}: {err.strip()}")


def _configure_mongo_replicaset(
    vm4_client: paramiko.SSHClient,
    vm1_client: paramiko.SSHClient,
    vm5_client: paramiko.SSHClient,
    *,
    vm4_password: str,
    vm1_password: str,
    vm5_password: str,
    vm4_host: str,
    vm1_host: str,
    vm5_host: str,
    app_db: str,
    app_user: str,
    app_password: str,
    admin_user: str,
    admin_password: str,
    replica_set: str,
    keyfile_b64: str,
) -> None:
    def js_string(value: str) -> str:
        return json.dumps(str(value))

    _ensure_mongodb_install(vm4_client, vm1_client, sudo_password=vm1_password)
    _ensure_mongodb_install(vm4_client, vm5_client, sudo_password=vm5_password)
    _configure_mongod_node(vm4_client, sudo_password=vm4_password, host_ip=vm4_host, replica_set=replica_set, keyfile_b64=keyfile_b64, auth_enabled=False)
    _configure_mongod_node(vm1_client, sudo_password=vm1_password, host_ip=vm1_host, replica_set=replica_set, keyfile_b64=keyfile_b64, auth_enabled=False)
    _configure_mongod_node(vm5_client, sudo_password=vm5_password, host_ip=vm5_host, replica_set=replica_set, keyfile_b64=keyfile_b64, auth_enabled=False)
    time.sleep(10)
    rs_script = (
        "cfg = {\n"
        f"  _id: {js_string(replica_set)},\n"
        "  members: [\n"
        f"    {{ _id: 0, host: {js_string(f'{vm4_host}:27017')}, priority: 2 }},\n"
        f"    {{ _id: 1, host: {js_string(f'{vm1_host}:27017')}, priority: 1 }},\n"
        f"    {{ _id: 2, host: {js_string(f'{vm5_host}:27017')}, priority: 1 }},\n"
        "  ]\n"
        "};\n"
        "try { rs.status(); current = rs.conf(); current.members = cfg.members; current.version = (current.version || 1) + 1; rs.reconfig(current, { force: true }); }\n"
        "catch (err) { rs.initiate(cfg); }\n"
        "quit(0);\n"
    )
    _run_mongosh_eval(vm4_client, sudo_password=vm4_password, script=rs_script)
    time.sleep(15)
    user_script = (
        "db = db.getSiblingDB('admin');\n"
        f"if (db.getUser({js_string(admin_user)})) {{ db.updateUser({js_string(admin_user)}, {{ pwd: {js_string(admin_password)}, roles: [{{ role: 'root', db: 'admin' }}] }}); }} else {{ db.createUser({{ user: {js_string(admin_user)}, pwd: {js_string(admin_password)}, roles: [{{ role: 'root', db: 'admin' }}] }}); }}\n"
        f"content = db.getSiblingDB({js_string(app_db)});\n"
        f"if (content.getUser({js_string(app_user)})) {{ content.updateUser({js_string(app_user)}, {{ pwd: {js_string(app_password)}, roles: [{{ role: 'readWrite', db: {js_string(app_db)} }}] }}); }} else {{ content.createUser({{ user: {js_string(app_user)}, pwd: {js_string(app_password)}, roles: [{{ role: 'readWrite', db: {js_string(app_db)} }}] }}); }}\n"
        "quit(0);\n"
    )
    _run_mongosh_eval(vm4_client, sudo_password=vm4_password, script=user_script, attempts=10, delay_seconds=6.0)
    _configure_mongod_node(vm1_client, sudo_password=vm1_password, host_ip=vm1_host, replica_set=replica_set, keyfile_b64=keyfile_b64, auth_enabled=True)
    _configure_mongod_node(vm5_client, sudo_password=vm5_password, host_ip=vm5_host, replica_set=replica_set, keyfile_b64=keyfile_b64, auth_enabled=True)
    time.sleep(5)
    _configure_mongod_node(vm4_client, sudo_password=vm4_password, host_ip=vm4_host, replica_set=replica_set, keyfile_b64=keyfile_b64, auth_enabled=True)
    time.sleep(15)
    uri = render_mongo_replica_uri(hosts=(vm4_host, vm1_host, vm5_host), db=app_db, user=app_user, password=app_password, replica_set=replica_set)
    verify_out = _run_mongosh_eval(
        vm4_client,
        sudo_password=vm4_password,
        script="printjson(db.runCommand({ping:1}).ok);\nquit(0);\n",
        uri=uri,
        attempts=10,
        delay_seconds=6.0,
    )
    if "1" not in verify_out:
        raise RuntimeError(f"Mongo replica-set verification failed: stdout={verify_out}")


def _remote_clickhouse_version(source_vm3: paramiko.SSHClient) -> str:
    code, out, err = _run_command(source_vm3, "clickhouse-server --version | awk '{print $4}'")
    if code != 0:
        raise RuntimeError(f"Unable to detect ClickHouse version on VM3: {err.strip()}")
    version = str(out or "").strip()
    if not version:
        raise RuntimeError("Unable to detect ClickHouse version on VM3: empty output")
    return version


def _ensure_clickhouse_repo(target_vm5: paramiko.SSHClient, *, sudo_password: str) -> None:
    bootstrap_cmd = (
        "export DEBIAN_FRONTEND=noninteractive && "
        "apt-get install -y gnupg ca-certificates curl >/dev/null 2>&1 && "
        f"install -d -m 0755 {shlex.quote(posixpath.dirname(CLICKHOUSE_REPO_KEYRING))} && "
        f"rm -f {shlex.quote(CLICKHOUSE_REPO_KEYRING)} && "
        f"gpg --batch --keyserver hkps://keyserver.ubuntu.com --recv-keys {shlex.quote(CLICKHOUSE_REPO_KEY_ID)} >/dev/null 2>&1 && "
        f"gpg --batch --export {shlex.quote(CLICKHOUSE_REPO_KEY_ID)} > {shlex.quote(CLICKHOUSE_REPO_KEYRING)} && "
        f"printf '%s\\n' 'deb [signed-by={CLICKHOUSE_REPO_KEYRING}] https://packages.clickhouse.com/deb stable main' > {shlex.quote(CLICKHOUSE_REPO_LIST)} && "
        "apt-get update -y >/dev/null 2>&1"
    )
    code, _, err = _run_command(target_vm5, bootstrap_cmd, sudo_password=sudo_password, use_sudo=True)
    if code != 0:
        raise RuntimeError(f"Unable to bootstrap ClickHouse repository on VM5: {err.strip()}")


def _ensure_clickhouse_install(source_vm3: paramiko.SSHClient, target_vm5: paramiko.SSHClient, *, sudo_password: str) -> None:
    code, _, _ = _run_command(target_vm5, "command -v clickhouse-client >/dev/null 2>&1", sudo_password=sudo_password, use_sudo=True)
    if code != 0:
        _ensure_clickhouse_repo(target_vm5, sudo_password=sudo_password)
        version = _remote_clickhouse_version(source_vm3)
        install_cmd = (
            "export DEBIAN_FRONTEND=noninteractive && "
            f"apt-get install -y clickhouse-common-static={shlex.quote(version)} "
            f"clickhouse-client={shlex.quote(version)} "
            f"clickhouse-server={shlex.quote(version)}"
        )
        code, _, err = _run_command(target_vm5, install_cmd, sudo_password=sudo_password, use_sudo=True)
        if code != 0:
            raise RuntimeError(f"Unable to install ClickHouse on VM5: {err.strip()}")
    code, _, err = _run_command(target_vm5, "systemctl enable --now clickhouse-server", sudo_password=sudo_password, use_sudo=True)
    if code != 0:
        raise RuntimeError(f"Unable to enable ClickHouse on VM5: {err.strip()}")


def _remote_clickhouse_schema(vm3_client: paramiko.SSHClient, *, sudo_password: str) -> dict[str, str]:
    script = (
        "from pathlib import Path\n"
        "import json\n"
        "from clickhouse_driver import Client\n"
        "env = {}\n"
        "for raw_line in Path('/etc/siem/storage.env').read_text(encoding='utf-8').splitlines():\n"
        "    line = raw_line.strip()\n"
        "    if not line or line.startswith('#') or '=' not in line:\n"
        "        continue\n"
        "    key, value = line.split('=', 1)\n"
        "    env[key.strip()] = value.strip()\n"
        "client = Client(host=env.get('SIEM_CH_HOST', '127.0.0.1'), port=int(env.get('SIEM_CH_PORT', '9000')), user=env.get('SIEM_CH_USER', 'siem_admin'), password=env.get('SIEM_CH_PASSWORD', ''), database=env.get('SIEM_CH_DB', 'siem'))\n"
        "payload = {}\n"
        "for row in client.execute('SHOW TABLES FROM siem'):\n"
        "    table = row[0]\n"
        "    payload[table] = client.execute(f'SHOW CREATE TABLE siem.{table}')[0][0]\n"
        "print(json.dumps(payload, ensure_ascii=False))\n"
    )
    code, out, err = _run_command(vm3_client, f"/opt/siem/venv-storage/bin/python - <<'PY'\n{script}\nPY", sudo_password=sudo_password, use_sudo=True)
    if code != 0:
        raise RuntimeError(f"Unable to query ClickHouse schema from VM3: {err.strip()}")
    cleaned = _strip_sudo_echo(out, sudo_password).strip()
    return json.loads(cleaned or "{}")


def _extract_clickhouse_uuid(metadata_text: str) -> str:
    match = re.search(r"UUID\s+'([0-9a-fA-F-]{36})'", str(metadata_text or ""))
    return str(match.group(1)) if match else ""


def _is_clickhouse_broken_table_failure(message: str) -> bool:
    lowered = str(message or "").lower()
    return any(
        marker in lowered
        for marker in (
            "too_many_unexpected_data_parts",
            "async_load_wait_failed",
            "suspiciously many",
            "broken parts",
        )
    )


def _is_clickhouse_not_enough_space_failure(message: str) -> bool:
    lowered = str(message or "").lower()
    return "not_enough_space" in lowered or "not enough space" in lowered


def _events_bootstrap_lookback_hours() -> int:
    raw = str(os.getenv("SIEM_CH_STANDBY_BOOTSTRAP_EVENTS_LOOKBACK_HOURS") or "").strip()
    if not raw:
        return DEFAULT_EVENTS_BOOTSTRAP_LOOKBACK_HOURS
    try:
        return max(1, min(168, int(raw)))
    except ValueError:
        return DEFAULT_EVENTS_BOOTSTRAP_LOOKBACK_HOURS


def _reclaim_clickhouse_standby_space(client: paramiko.SSHClient, *, sudo_password: str) -> None:
    cleanup_cmd = """
set -euo pipefail
journalctl --vacuum-size=200M >/dev/null 2>&1 || true
apt-get clean >/dev/null 2>&1 || true
find /var/log/clickhouse-server -type f -name '*.log' -exec truncate -s 0 {} + >/dev/null 2>&1 || true
find /var/lib/clickhouse/tmp -mindepth 1 -maxdepth 2 -exec rm -rf {} + >/dev/null 2>&1 || true
find /var/lib/clickhouse/store -path '*/detached/*' -mindepth 1 -exec rm -rf {} + >/dev/null 2>&1 || true
find /var/lib/clickhouse/data -path '*/detached/*' -mindepth 1 -exec rm -rf {} + >/dev/null 2>&1 || true
df -Pm /var/lib/clickhouse 2>/dev/null | tail -n 1 || true
"""
    code, out, err = _run_command(client, cleanup_cmd, sudo_password=sudo_password, use_sudo=True)
    if code != 0:
        detail = _command_failure_text(out, err, sudo_password=sudo_password)
        print(f"storage_ha_wave warning=standby_space_cleanup_failed detail={detail[:240]!r}")
        return
    cleaned = _strip_sudo_echo(out, sudo_password).strip()
    if cleaned:
        print(f"storage_ha_wave standby_space_after_cleanup={cleaned}")


def _purge_clickhouse_table_files(
    client: paramiko.SSHClient,
    *,
    db_name: str,
    table_name: str,
    sudo_password: str,
) -> None:
    metadata_path = f"/var/lib/clickhouse/metadata/{db_name}/{table_name}.sql"
    code, out, err = _run_command(
        client,
        f"test -f {shlex.quote(metadata_path)} && cat {shlex.quote(metadata_path)} || true",
        sudo_password=sudo_password,
        use_sudo=True,
    )
    if code != 0:
        detail = _command_failure_text(out, err, sudo_password=sudo_password)
        raise RuntimeError(f"Unable to inspect ClickHouse metadata for {db_name}.{table_name}: {detail}")
    metadata_text = _strip_sudo_echo(out, sudo_password)
    table_uuid = _extract_clickhouse_uuid(metadata_text)
    store_cleanup = ""
    if table_uuid:
        store_dir = f"/var/lib/clickhouse/store/{table_uuid[:3]}/{table_uuid}"
        store_cleanup = f"rm -rf {shlex.quote(store_dir)} && "
    cleanup_cmd = (
        "systemctl stop clickhouse-server >/dev/null 2>&1 || true && "
        f"rm -f {shlex.quote(metadata_path)} && "
        f"rm -rf {shlex.quote(f'/var/lib/clickhouse/data/{db_name}/{table_name}')} && "
        f"{store_cleanup}"
        "systemctl start clickhouse-server && systemctl is-active clickhouse-server"
    )
    code, out, err = _run_command(client, cleanup_cmd, sudo_password=sudo_password, use_sudo=True)
    if code != 0:
        detail = _command_failure_text(out, err, sudo_password=sudo_password)
        raise RuntimeError(f"Unable to purge ClickHouse standby files for {db_name}.{table_name}: {detail}")


def _reset_clickhouse_table_for_bootstrap(
    client: paramiko.SSHClient,
    *,
    db_name: str,
    table_name: str,
    ddl: str,
    sudo_password: str,
) -> None:
    drop_query = f"DROP TABLE IF EXISTS {db_name}.{table_name} SYNC"
    code, out, err = _run_command(
        client,
        f"clickhouse-client --query {shlex.quote(drop_query)}",
        sudo_password=sudo_password,
        use_sudo=True,
    )
    detail = _command_failure_text(out, err, sudo_password=sudo_password)
    if code != 0:
        if _is_clickhouse_broken_table_failure(detail):
            _purge_clickhouse_table_files(
                client,
                db_name=db_name,
                table_name=table_name,
                sudo_password=sudo_password,
            )
        else:
            raise RuntimeError(f"Unable to drop ClickHouse standby table {db_name}.{table_name}: {detail}")
    normalized = str(ddl).replace(
        f"CREATE TABLE {db_name}.{table_name}",
        f"CREATE TABLE IF NOT EXISTS {db_name}.{table_name}",
        1,
    )
    temp_sql = f"/tmp/{table_name}.bootstrap.sql"
    _write_remote_text(client, temp_sql, normalized + "\n", mode="0644", sudo_password=sudo_password)
    code, out, err = _run_command(
        client,
        f"clickhouse-client --multiquery < {shlex.quote(temp_sql)}",
        sudo_password=sudo_password,
        use_sudo=True,
    )
    if code != 0:
        detail = _command_failure_text(out, err, sudo_password=sudo_password)
        raise RuntimeError(f"Unable to apply ClickHouse standby DDL for {table_name}: {detail}")


def _bootstrap_clickhouse_standby(
    vm3_client: paramiko.SSHClient,
    vm5_client: paramiko.SSHClient,
    *,
    vm3_password: str,
    vm5_password: str,
    vm4_host: str,
    vm5_host: str,
    primary_env: dict[str, str],
) -> None:
    _ensure_clickhouse_install(vm3_client, vm5_client, sudo_password=vm5_password)
    _configure_clickhouse_standby_network(
        vm5_client,
        sudo_password=vm5_password,
        host_ip=vm5_host,
        allowed_sources=(str(primary_env.get("SIEM_CH_HOST") or "127.0.0.1"), vm4_host),
    )
    _reclaim_clickhouse_standby_space(vm5_client, sudo_password=vm5_password)
    schema = _remote_clickhouse_schema(vm3_client, sudo_password=vm3_password)
    db_name = str(primary_env.get("SIEM_CH_DB") or "siem")
    ch_user = str(primary_env.get("SIEM_CH_USER") or "siem_admin")
    ch_password = str(primary_env.get("SIEM_CH_PASSWORD") or "")
    ch_port = str(primary_env.get("SIEM_CH_PORT") or "9000")
    create_user_sql = f"CREATE USER IF NOT EXISTS {ch_user} IDENTIFIED BY '{ch_password}';"
    init_cmd = (
        f"clickhouse-client --query {shlex.quote(f'CREATE DATABASE IF NOT EXISTS {db_name};')} && "
        f"clickhouse-client --query {shlex.quote(create_user_sql)} && "
        f"clickhouse-client --query {shlex.quote(f'GRANT ALL ON {db_name}.* TO {ch_user};')} && "
        f"clickhouse-client --query {shlex.quote(f'GRANT REMOTE, CREATE TEMPORARY TABLE ON *.* TO {ch_user};')}"
    )
    code, _, err = _run_command(vm5_client, init_cmd, sudo_password=vm5_password, use_sudo=True)
    if code != 0:
        raise RuntimeError(f"Unable to initialize ClickHouse standby user/database: {err.strip()}")
    bootstrap_tables = tuple(table_name for table_name in BOOTSTRAP_TABLES if table_name in schema)
    for table_name in bootstrap_tables:
        _reset_clickhouse_table_for_bootstrap(
            vm5_client,
            db_name=db_name,
            table_name=table_name,
            ddl=schema[table_name],
            sudo_password=vm5_password,
        )
    for table_name in bootstrap_tables:
        if table_name in OPTIONAL_BOOTSTRAP_TABLES:
            print(
                "storage_ha_wave warning="
                f"skipped_optional_clickhouse_bootstrap table={table_name} reason=deferred_cold_history"
            )
            continue
        remote_source = (
            f"remote('{primary_env.get('SIEM_CH_HOST', '127.0.0.1')}:{ch_port}', "
            f"'{db_name}', '{table_name}', '{ch_user}', '{ch_password}')"
        )
        select_sql = f"SELECT * FROM {remote_source}"
        if table_name == "events":
            select_sql = f"{select_sql} WHERE ts >= now() - INTERVAL {_events_bootstrap_lookback_hours()} HOUR"
        query = (
            f"TRUNCATE TABLE IF EXISTS {db_name}.{table_name}; "
            f"INSERT INTO {db_name}.{table_name} {select_sql}"
        )
        code, out, err = _run_command(vm5_client, f"clickhouse-client --multiquery --query {shlex.quote(query)}", sudo_password=vm5_password, use_sudo=True)
        if code != 0:
            detail = _command_failure_text(out, err, sudo_password=vm5_password)
            if table_name in OPTIONAL_BOOTSTRAP_TABLES and _is_clickhouse_not_enough_space_failure(detail):
                print(
                    "storage_ha_wave warning="
                    f"skipped_optional_clickhouse_bootstrap table={table_name} reason=not_enough_space"
                )
                continue
            raise RuntimeError(f"Unable to bootstrap ClickHouse standby data for {table_name}: {detail}")


def _configure_vm5_standby_runtime(vm5_client: paramiko.SSHClient, *, sudo_password: str, primary_env: dict[str, str], primary_host: str) -> None:
    existing = ""
    code, out, _ = _run_command(vm5_client, f"cat {shlex.quote(REMOTE_VM5_STANDBY_ENV)} || true", sudo_password=sudo_password, use_sudo=True)
    if code == 0:
        existing = _strip_sudo_echo(out, sudo_password)
    merged = _merge_env_text(
        existing,
        {
            "SIEM_INSTANCE_NAME": "siem-writer-standby",
            "SIEM_TRANSPORT_BACKEND": "kafka",
            "SIEM_TRANSPORT_CONSUMER_BACKEND": "kafka",
            "SIEM_KAFKA_BOOTSTRAP_SERVERS": str(primary_env.get("SIEM_KAFKA_BOOTSTRAP_SERVERS") or "192.168.1.35:9092,192.168.1.37:9092,192.168.1.40:9092"),
            "SIEM_KAFKA_SECURITY_PROTOCOL": str(primary_env.get("SIEM_KAFKA_SECURITY_PROTOCOL") or "PLAINTEXT"),
            "SIEM_KAFKA_EXPECTED_BROKERS": str(primary_env.get("SIEM_KAFKA_EXPECTED_BROKERS") or "3"),
            "SIEM_KAFKA_EXPECTED_CONTROLLERS": str(primary_env.get("SIEM_KAFKA_EXPECTED_CONTROLLERS") or "3"),
            "SIEM_KAFKA_TOPIC_FILTERED": str(primary_env.get("SIEM_KAFKA_TOPIC_FILTERED") or "siem.filtered"),
            "SIEM_WRITER_GROUP": "writer-standby",
            "SIEM_WRITER_CONSUMER": "writer-standby-1",
            "SIEM_CH_HOST": "127.0.0.1",
            "SIEM_CH_PORT": "9000",
            "SIEM_CH_DB": str(primary_env.get("SIEM_CH_DB") or "siem"),
            "SIEM_CH_USER": str(primary_env.get("SIEM_CH_USER") or "siem_admin"),
            "SIEM_CH_PASSWORD": str(primary_env.get("SIEM_CH_PASSWORD") or ""),
            "SIEM_PRIMARY_CH_HOST": primary_host,
            "SIEM_PRIMARY_CH_PORT": "9000",
            "SIEM_SYNC_TABLES": ",".join(SYNC_TABLES),
        },
    )
    _write_remote_text(vm5_client, REMOTE_VM5_STANDBY_ENV, merged, mode="0600", sudo_password=sudo_password)
    for local_rel, remote_path, mode in REMOTE_VM5_FILES:
        _upload_file(vm5_client, ROOT / local_rel, remote_path, mode=mode, sudo_password=sudo_password)
    venv_cmd = (
        "python3 -m venv /opt/siem/venv-storage >/dev/null 2>&1 || true && "
        "/opt/siem/venv-storage/bin/python -m pip install --disable-pip-version-check -q clickhouse-driver aiokafka redis"
    )
    code, _, err = _run_command(vm5_client, venv_cmd, sudo_password=sudo_password, use_sudo=True)
    if code != 0:
        raise RuntimeError(f"Unable to prepare VM5 standby virtualenv: {err.strip()}")
    enable_cmd = (
        "systemctl daemon-reload && "
        "systemctl enable --now siem-writer-standby siem-clickhouse-standby-sync.timer && "
        "systemctl start siem-clickhouse-standby-sync.service"
    )
    code, _, err = _run_command(vm5_client, enable_cmd, sudo_password=sudo_password, use_sudo=True)
    if code != 0:
        raise RuntimeError(f"Unable to enable VM5 standby services: {err.strip()}")


def _retire_redis_node(client: paramiko.SSHClient, *, sudo_password: str) -> None:
    command = _redis_retirement_command()
    code, _, err = _run_command(client, command, sudo_password=sudo_password, use_sudo=True)
    if code != 0:
        raise RuntimeError(f"Unable to retire Redis on node: {err.strip()}")


def _retire_redis_vm2(proxmox: paramiko.SSHClient, vmid: str) -> None:
    command = _redis_retirement_command()
    code, _, err = _run_command(proxmox, f"qm guest exec {shlex.quote(vmid)} -- bash -lc {shlex.quote(command)}")
    if code != 0:
        raise RuntimeError(f"Unable to retire Redis on VM2: {err.strip()}")


def _redis_retirement_command() -> str:
    return (
        "export DEBIAN_FRONTEND=noninteractive; "
        "systemctl disable --now redis-server >/dev/null 2>&1 || true; "
        "systemctl disable --now siem-redis-sentinel >/dev/null 2>&1 || true; "
        "systemctl mask redis-server >/dev/null 2>&1 || true; "
        "timeout 90s apt-get -o Dpkg::Lock::Timeout=20 purge -y redis-server redis-tools >/dev/null 2>&1 || true; "
        "apt-get clean >/dev/null 2>&1 || true"
    )


def _update_vm4_web_env(
    vm4_client: paramiko.SSHClient,
    *,
    sudo_password: str,
    db: str,
    user: str,
    password: str,
    pg_dsn: str,
    mongo_uri: str,
    clickhouse_hosts: str,
) -> None:
    existing = _read_remote_file(vm4_client, REMOTE_WEB_ENV, sudo_password=sudo_password, use_sudo=True)
    merged = _merge_env_text(
        existing,
        {
            "SIEM_PG_DB": db,
            "SIEM_PG_USER": user,
            "SIEM_PG_PASSWORD": password,
            "SIEM_CONTROL_PLANE_PG_DSN": pg_dsn,
            "SIEM_CH_HOSTS": clickhouse_hosts,
            "SIEM_MONGO_URI": mongo_uri,
        },
    )
    _write_remote_text(vm4_client, REMOTE_WEB_ENV, merged, mode="0600", sudo_password=sudo_password)
    code, _, err = _run_command(vm4_client, "systemctl restart siem-web", sudo_password=sudo_password, use_sudo=True)
    if code != 0:
        raise RuntimeError(f"Unable to restart siem-web: {err.strip()}")


def _mongo_password_from_uri(uri: str) -> str:
    try:
        auth = str(uri.split("://", 1)[1].split("@", 1)[0])
        return auth.split(":", 1)[1]
    except Exception:  # noqa: BLE001
        return ""


def main() -> int:
    proxmox = HostSpec(_required_env("SIEM_PROXMOX_HOST"), _required_env("SIEM_PROXMOX_USER"), _required_env("SIEM_PROXMOX_PASSWORD"))
    vm1 = HostSpec(_required_env("SIEM_VM1_HOST"), _required_env("SIEM_VM1_USER"), _required_env("SIEM_VM1_PASSWORD"))
    vm3 = HostSpec(_required_env("SIEM_VM3_HOST"), _required_env("SIEM_VM3_USER"), _required_env("SIEM_VM3_PASSWORD"))
    vm4 = HostSpec(_required_env("SIEM_VM4_HOST"), _required_env("SIEM_VM4_USER"), _required_env("SIEM_VM4_PASSWORD"))
    vm5 = HostSpec(_required_env("SIEM_VM5_HOST"), _required_env("SIEM_VM5_USER"), _required_env("SIEM_VM5_PASSWORD"))
    vm1_vmid = _required_env("SIEM_VM1_VMID", default="104")
    vm2_vmid = _required_env("SIEM_VM2_VMID", default="105")
    vm5_vmid = _required_env("SIEM_VM5_VMID", default="108")

    proxmox_client = _connect_client(proxmox.host, proxmox.user, proxmox.password)
    vm4_client = _connect_client(vm4.host, vm4.user, vm4.password)
    try:
        storage_ha_env = _ensure_storage_ha_env(vm4_client, sudo_password=vm4.password)
        _ensure_cpu_model(proxmox_client, vmid=vm1_vmid, host=vm1)
        _ensure_cpu_model(proxmox_client, vmid=vm5_vmid, host=vm5)
    finally:
        vm4_client.close()
        proxmox_client.close()

    proxmox_client = _connect_client(proxmox.host, proxmox.user, proxmox.password)
    vm1_client = _connect_client(vm1.host, vm1.user, vm1.password)
    vm3_client = _connect_client(vm3.host, vm3.user, vm3.password)
    vm4_client = _connect_client(vm4.host, vm4.user, vm4.password)
    vm5_client = _connect_client(vm5.host, vm5.user, vm5.password)
    try:
        storage_ha_env = _parse_env(_read_remote_file(vm4_client, REMOTE_STORAGE_HA_ENV, sudo_password=vm4.password, use_sudo=True))
        web_env = _parse_env(_read_remote_file(vm4_client, REMOTE_WEB_ENV, sudo_password=vm4.password, use_sudo=True))
        resolved_web_env = _resolve_remote_secret_env_values(
            vm4_client,
            sudo_password=vm4.password,
            env_path=REMOTE_WEB_ENV,
            env_names=("SIEM_MONGO_URI", "SIEM_PG_PASSWORD"),
        )
        effective_web_env = dict(web_env)
        effective_web_env.update(resolved_web_env)
        primary_storage_env = _parse_env(_read_remote_file(vm3_client, REMOTE_STORAGE_ENV, sudo_password=vm3.password, use_sudo=True))
        _configure_storage_firewall(
            vm1_client=vm1_client,
            vm4_client=vm4_client,
            vm5_client=vm5_client,
            vm1_host=vm1.host,
            vm4_host=vm4.host,
            vm5_host=vm5.host,
            vm1_password=vm1.password,
            vm4_password=vm4.password,
            vm5_password=vm5.password,
        )
        pg_major = _configure_postgres_primary(
            vm4_client,
            sudo_password=vm4.password,
            primary_host=vm4.host,
            standby_host=vm1.host,
            replication_user=storage_ha_env["SIEM_PG_REPL_USER"],
            replication_password=storage_ha_env["SIEM_PG_REPL_PASSWORD"],
        )
        _configure_postgres_standby(
            vm1_client,
            sudo_password=vm1.password,
            primary_host=vm4.host,
            standby_host=vm1.host,
            replication_user=storage_ha_env["SIEM_PG_REPL_USER"],
            replication_password=storage_ha_env["SIEM_PG_REPL_PASSWORD"],
            major=pg_major,
        )
        _configure_mongo_replicaset(
            vm4_client,
            vm1_client,
            vm5_client,
            vm4_password=vm4.password,
            vm1_password=vm1.password,
            vm5_password=vm5.password,
            vm4_host=vm4.host,
            vm1_host=vm1.host,
            vm5_host=vm5.host,
            app_db=str(effective_web_env.get("SIEM_MONGO_DB") or "siem_content"),
            app_user="siem_content",
            app_password=_mongo_password_from_uri(str(effective_web_env.get("SIEM_MONGO_URI") or "")),
            admin_user=storage_ha_env["SIEM_MONGO_ADMIN_USER"],
            admin_password=storage_ha_env["SIEM_MONGO_ADMIN_PASSWORD"],
            replica_set=storage_ha_env["SIEM_MONGO_REPLICA_SET"],
            keyfile_b64=storage_ha_env["SIEM_MONGO_KEYFILE_B64"],
        )
        _bootstrap_clickhouse_standby(
            vm3_client,
            vm5_client,
            vm3_password=vm3.password,
            vm5_password=vm5.password,
            vm4_host=vm4.host,
            vm5_host=vm5.host,
            primary_env=primary_storage_env,
        )
        _configure_vm5_standby_runtime(vm5_client, sudo_password=vm5.password, primary_env=primary_storage_env, primary_host=vm3.host)
        _update_vm4_web_env(
            vm4_client,
            sudo_password=vm4.password,
            db=str(effective_web_env.get("SIEM_PG_DB") or "siem_control_plane"),
            user=str(effective_web_env.get("SIEM_PG_USER") or "siem_control"),
            password=str(effective_web_env.get("SIEM_PG_PASSWORD") or ""),
            pg_dsn=render_control_plane_pg_dsn(
                primary_host=vm4.host,
                standby_host=vm1.host,
                db=str(effective_web_env.get("SIEM_PG_DB") or "siem_control_plane"),
                user=str(effective_web_env.get("SIEM_PG_USER") or "siem_control"),
                password=str(effective_web_env.get("SIEM_PG_PASSWORD") or ""),
            ),
            mongo_uri=render_mongo_replica_uri(
                hosts=(vm4.host, vm1.host, vm5.host),
                db=str(effective_web_env.get("SIEM_MONGO_DB") or "siem_content"),
                user="siem_content",
                password=_mongo_password_from_uri(str(effective_web_env.get("SIEM_MONGO_URI") or "")),
                replica_set=storage_ha_env["SIEM_MONGO_REPLICA_SET"],
            ),
            clickhouse_hosts=render_clickhouse_hosts(primary_host=vm3.host, standby_host=vm5.host),
        )
        _retire_redis_node(vm1_client, sudo_password=vm1.password)
        _retire_redis_node(vm3_client, sudo_password=vm3.password)
        _retire_redis_node(vm5_client, sudo_password=vm5.password)
        _retire_redis_vm2(proxmox_client, vm2_vmid)
        print("storage_ha_wave=success")
        print(f"postgres_primary={vm4.host}")
        print(f"postgres_standby={vm1.host}")
        print(f"mongo_replica_set={storage_ha_env['SIEM_MONGO_REPLICA_SET']}")
        print(f"clickhouse_hosts={render_clickhouse_hosts(primary_host=vm3.host, standby_host=vm5.host)}")
        return 0
    finally:
        for client in (vm1_client, vm3_client, vm4_client, vm5_client, proxmox_client):
            client.close()


if __name__ == "__main__":
    sys.exit(main())
