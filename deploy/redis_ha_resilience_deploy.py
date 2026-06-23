from __future__ import annotations

import json
import os
import posixpath
import re
import shlex
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import paramiko

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from deploy.vm2_processing_resilience_deploy import PROCESSING_SERVICE_UNITS


DEFAULT_REMOTE_ROOT = "/opt/siem/siem-solution"
REDIS_CONF = "/etc/redis/redis.conf"
SENTINEL_CONF = "/etc/redis/siem-sentinel.conf"
SENTINEL_UNIT = "/etc/systemd/system/siem-redis-sentinel.service"
VM1_INGEST_ENV = "/etc/siem/ingest.env"
VM2_PROCESSING_ENV = "/etc/siem/processing.env"
VM3_STORAGE_ENV = "/etc/siem/storage.env"


@dataclass(frozen=True)
class HostSpec:
    host: str
    user: str
    password: str
    repo_root: str


@dataclass(frozen=True)
class FileMapping:
    local_rel: str
    remote_rel: str


VM1_FILE_MAPPINGS: tuple[FileMapping, ...] = (
    FileMapping("services/__init__.py", "services/__init__.py"),
    FileMapping("services/redis_runtime.py", "services/redis_runtime.py"),
    FileMapping("services/ingest/redis_client.py", "services/ingest/redis_client.py"),
)

VM2_FILE_MAPPINGS: tuple[FileMapping, ...] = (
    FileMapping("services/__init__.py", "services/__init__.py"),
    FileMapping("services/redis_runtime.py", "services/redis_runtime.py"),
    FileMapping("services/normalizer/worker.py", "services/normalizer/worker.py"),
    FileMapping("services/filter/worker.py", "services/filter/worker.py"),
)

VM3_FILE_MAPPINGS: tuple[FileMapping, ...] = (
    FileMapping("services/redis_runtime.py", "services/redis_runtime.py"),
    FileMapping("services/writer/__init__.py", "services/writer/__init__.py"),
    FileMapping("services/writer/worker.py", "services/writer/worker.py"),
    FileMapping("services/stream_corr/__init__.py", "services/stream_corr/__init__.py"),
    FileMapping("services/stream_corr/config.py", "services/stream_corr/config.py"),
    FileMapping("services/stream_corr/logging_conf.py", "services/stream_corr/logging_conf.py"),
    FileMapping("services/stream_corr/rules.py", "services/stream_corr/rules.py"),
    FileMapping("services/stream_corr/worker.py", "services/stream_corr/worker.py"),
)


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
            print(f"ssh connect attempt {attempt}/5 failed for {host}: {exc}")
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
        line = re.sub(r"^\[sudo\] password for [^:]+:\s*", "", line)
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


def _upload_text(
    sftp: paramiko.SFTPClient,
    *,
    content: str,
    remote_temp_path: str,
) -> None:
    _mkdir_remote(sftp, posixpath.dirname(remote_temp_path))
    with sftp.open(remote_temp_path, "w") as handle:
        handle.write(content)


def _remote_temp_path(host: HostSpec, filename: str) -> str:
    return f"/home/{host.user}/.siem-tmp/{filename}"


def _upload_repo_files(
    client: paramiko.SSHClient,
    sftp: paramiko.SFTPClient,
    host: HostSpec,
    mappings: tuple[FileMapping, ...],
    backup_root: str,
) -> None:
    for mapping in mappings:
        local_path = ROOT / mapping.local_rel
        if not local_path.exists():
            raise FileNotFoundError(f"Missing local file: {local_path}")
        remote_path = posixpath.join(host.repo_root.rstrip("/"), mapping.remote_rel)
        _backup_path(client, remote_path, backup_root, sudo_password=host.password, use_sudo=True)
        _mkdir_remote(sftp, posixpath.dirname(remote_path))
        with sftp.open(remote_path, "w") as handle:
            handle.write(local_path.read_text(encoding="utf-8"))
        print(f"uploaded {mapping.local_rel} -> {host.host}:{remote_path}")


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


def _render_master_redis_conf(bind_ip: str, password: str) -> str:
    return (
        "bind 127.0.0.1 " + bind_ip + "\n"
        "protected-mode yes\n"
        "port 6379\n"
        "tcp-backlog 511\n"
        "timeout 0\n"
        "tcp-keepalive 300\n"
        "daemonize no\n"
        "supervised systemd\n"
        "pidfile /run/redis/redis-server.pid\n"
        "loglevel notice\n"
        "logfile /var/log/redis/redis-server.log\n"
        "databases 16\n"
        "dir /var/lib/redis\n"
        "dbfilename dump.rdb\n"
        "appendonly yes\n"
        "appendfsync everysec\n"
        "auto-aof-rewrite-percentage 100\n"
        "auto-aof-rewrite-min-size 64mb\n"
        f"requirepass {password}\n"
        f"masterauth {password}\n"
    )


def _render_replica_redis_conf(bind_ip: str, master_ip: str, password: str) -> str:
    return (
        "bind 127.0.0.1 " + bind_ip + "\n"
        "protected-mode yes\n"
        "port 6379\n"
        "tcp-backlog 511\n"
        "timeout 0\n"
        "tcp-keepalive 300\n"
        "daemonize no\n"
        "supervised systemd\n"
        "pidfile /run/redis/redis-server.pid\n"
        "loglevel notice\n"
        "logfile /var/log/redis/redis-server.log\n"
        "databases 16\n"
        "dir /var/lib/redis\n"
        "dbfilename dump.rdb\n"
        "appendonly yes\n"
        "appendfsync everysec\n"
        "auto-aof-rewrite-percentage 100\n"
        "auto-aof-rewrite-min-size 64mb\n"
        f"requirepass {password}\n"
        f"masterauth {password}\n"
        f"replicaof {master_ip} 6379\n"
        "replica-read-only yes\n"
    )


def _render_sentinel_conf(bind_ip: str, master_name: str, master_ip: str, password: str, quorum: int, port: int) -> str:
    return (
        "bind " + bind_ip + " 127.0.0.1\n"
        f"port {port}\n"
        "daemonize no\n"
        "supervised systemd\n"
        "pidfile /run/redis/siem-redis-sentinel.pid\n"
        "logfile /var/log/redis/siem-redis-sentinel.log\n"
        "dir /var/lib/redis\n"
        f"sentinel monitor {master_name} {master_ip} 6379 {quorum}\n"
        f"sentinel auth-user {master_name} default\n"
        f"sentinel auth-pass {master_name} {password}\n"
        f"sentinel down-after-milliseconds {master_name} 5000\n"
        f"sentinel failover-timeout {master_name} 15000\n"
        f"sentinel parallel-syncs {master_name} 1\n"
    )


def _render_sentinel_unit() -> str:
    return """[Unit]
Description=SIEM Redis Sentinel
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
User=redis
Group=redis
RuntimeDirectory=redis
RuntimeDirectoryMode=2755
ExecStart=/usr/bin/redis-server /etc/redis/siem-sentinel.conf --sentinel
ExecStop=/bin/kill -s TERM $MAINPID
TimeoutStopSec=0
Restart=always
RestartSec=3
UMask=007
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
"""


def _ensure_redis_package(client: paramiko.SSHClient, *, sudo_password: str) -> None:
    command = (
        "if ! command -v redis-server >/dev/null 2>&1; then "
        "DEBIAN_FRONTEND=noninteractive apt-get update && "
        "DEBIAN_FRONTEND=noninteractive apt-get install -y redis-server; "
        "fi"
    )
    code, out, err = _run_command(client, command, sudo_password=sudo_password, use_sudo=True)
    if code != 0:
        raise RuntimeError(f"Unable to ensure redis-server package: {err.strip()}")


def _install_with_sudo(
    client: paramiko.SSHClient,
    local_temp_path: str,
    remote_path: str,
    *,
    mode: str,
    sudo_password: str,
) -> None:
    command = f"install -m {mode} {shlex.quote(local_temp_path)} {shlex.quote(remote_path)}"
    code, _, err = _run_command(client, command, sudo_password=sudo_password, use_sudo=True)
    if code != 0:
        raise RuntimeError(f"Unable to install {remote_path}: {err.strip()}")


def _wait_for_active_services(
    client: paramiko.SSHClient,
    services: list[str],
    *,
    sudo_password: str,
    attempts: int = 20,
    delay_seconds: float = 2.0,
) -> list[str]:
    last_states: list[str] = []
    last_err = ""
    for _ in range(attempts):
        code, out, err = _run_command(
            client,
            f"systemctl is-active {' '.join(services)}",
            sudo_password=sudo_password,
            use_sudo=True,
        )
        cleaned = _strip_sudo_echo(out, sudo_password)
        states = [line.strip() for line in cleaned.splitlines() if line.strip()]
        if len(states) >= len(services):
            states = states[-len(services):]
        last_states = states
        last_err = err.strip()
        if code == 0 and states == ["active"] * len(services):
            return states
        time.sleep(delay_seconds)
    raise RuntimeError(f"Service activation failed: services={services} stdout={last_states} stderr={last_err}")


def _allow_ufw_rules(
    client: paramiko.SSHClient,
    *,
    sudo_password: str,
    rules: list[tuple[str, int]],
) -> None:
    if not rules:
        return
    lines = ["if command -v ufw >/dev/null 2>&1; then"]
    for source, port in rules:
        lines.append(f"ufw allow from {shlex.quote(source)} to any port {int(port)} proto tcp >/dev/null 2>&1 || true")
    lines.append("fi")
    command = "\n".join(lines)
    code, _, err = _run_command(client, command, sudo_password=sudo_password, use_sudo=True)
    if code != 0:
        raise RuntimeError(f"Unable to apply UFW rules: {err.strip()}")


def _clear_stale_sentinel_processes(
    client: paramiko.SSHClient,
    *,
    sudo_password: str,
) -> None:
    command = (
        "python3 - <<'PY'\n"
        "import os\n"
        "import signal\n"
        "import subprocess\n"
        "proc = subprocess.run(['ps', '-eo', 'pid,args'], capture_output=True, text=True, check=True)\n"
        "killed = []\n"
        "for raw_line in proc.stdout.splitlines()[1:]:\n"
        "    line = raw_line.strip()\n"
        "    if not line:\n"
        "        continue\n"
        "    pid_text, _, args = line.partition(' ')\n"
        "    if not pid_text or '[sentinel]' not in args or 'redis-server' not in args:\n"
        "        continue\n"
        "    try:\n"
        "        pid = int(pid_text)\n"
        "    except ValueError:\n"
        "        continue\n"
        "    try:\n"
        "        os.kill(pid, signal.SIGTERM)\n"
        "    except ProcessLookupError:\n"
        "        continue\n"
        "    killed.append(pid)\n"
        "print(' '.join(str(pid) for pid in killed))\n"
        "PY"
    )
    code, out, err = _run_command(client, command, sudo_password=sudo_password, use_sudo=True)
    cleaned = _strip_sudo_echo(out, sudo_password).strip()
    if code != 0 and err.strip():
        raise RuntimeError(f"Unable to clear stale sentinel processes: stdout={cleaned} stderr={err.strip()}")
    if cleaned:
        print(f"cleared_stale_sentinel_pids={cleaned}")


def _configure_vm2_master(
    client: paramiko.SSHClient,
    sftp: paramiko.SFTPClient,
    host: HostSpec,
    *,
    redis_client_sources: tuple[str, ...],
    sentinel_peer_sources: tuple[str, ...],
    redis_password: str,
    master_name: str,
    sentinel_port: int,
    sentinel_quorum: int,
    sentinel_nodes_csv: str,
    backup_root: str,
) -> None:
    _ensure_redis_package(client, sudo_password=host.password)
    for path in (REDIS_CONF, VM2_PROCESSING_ENV, SENTINEL_CONF, SENTINEL_UNIT):
        _backup_path(client, path, backup_root, sudo_password=host.password, use_sudo=True)

    _upload_repo_files(client, sftp, host, VM2_FILE_MAPPINGS, backup_root)

    temp_redis = _remote_temp_path(host, "siem-vm2-redis.conf")
    temp_sentinel = _remote_temp_path(host, "siem-vm2-sentinel.conf")
    temp_unit = _remote_temp_path(host, "siem-vm2-sentinel.service")
    _upload_text(sftp, content=_render_master_redis_conf(host.host, redis_password), remote_temp_path=temp_redis)
    _upload_text(
        sftp,
        content=_render_sentinel_conf(host.host, master_name, host.host, redis_password, sentinel_quorum, sentinel_port),
        remote_temp_path=temp_sentinel,
    )
    _upload_text(sftp, content=_render_sentinel_unit(), remote_temp_path=temp_unit)

    _install_with_sudo(client, temp_redis, REDIS_CONF, mode="0640", sudo_password=host.password)
    _install_with_sudo(client, temp_sentinel, SENTINEL_CONF, mode="0660", sudo_password=host.password)
    _install_with_sudo(client, temp_unit, SENTINEL_UNIT, mode="0644", sudo_password=host.password)
    _clear_stale_sentinel_processes(client, sudo_password=host.password)
    _allow_ufw_rules(
        client,
        sudo_password=host.password,
        rules=[*[(source, 6379) for source in redis_client_sources], *[(source, sentinel_port) for source in sentinel_peer_sources]],
    )
    _set_remote_env_values(
        client,
        VM2_PROCESSING_ENV,
        {
            "SIEM_REDIS_SENTINEL_ENABLED": "true",
            "SIEM_REDIS_SENTINEL_MASTER": master_name,
            "SIEM_REDIS_SENTINEL_NODES": sentinel_nodes_csv,
        },
        sudo_password=host.password,
    )

    command = (
        "mkdir -p /var/lib/redis /var/log/redis && "
        "chown -R redis:redis /var/lib/redis /var/log/redis && "
        "chown redis:redis /etc/redis/siem-sentinel.conf && "
        "systemctl daemon-reload && "
        "systemctl enable redis-server siem-redis-sentinel && "
        "systemctl stop siem-redis-sentinel || true && "
        "systemctl reset-failed siem-redis-sentinel || true && "
        "systemctl restart redis-server && "
        "sleep 3 && "
        "systemctl restart siem-redis-sentinel && "
        f"systemctl restart {' '.join(PROCESSING_SERVICE_UNITS)}"
    )
    code, out, err = _run_command(client, command, sudo_password=host.password, use_sudo=True)
    cleaned = _strip_sudo_echo(out, host.password)
    if code != 0:
        raise RuntimeError(f"VM2 Redis HA activation failed: stdout={cleaned.strip()} stderr={err.strip()}")
    _wait_for_active_services(
        client,
        ["redis-server", "siem-redis-sentinel", *PROCESSING_SERVICE_UNITS],
        sudo_password=host.password,
    )
    print("vm2_redis_ha=ok")


def _configure_vm3_replica(
    client: paramiko.SSHClient,
    sftp: paramiko.SFTPClient,
    host: HostSpec,
    *,
    redis_client_sources: tuple[str, ...],
    sentinel_peer_sources: tuple[str, ...],
    master_ip: str,
    redis_password: str,
    master_name: str,
    sentinel_port: int,
    sentinel_quorum: int,
    sentinel_nodes_csv: str,
    backup_root: str,
) -> None:
    _ensure_redis_package(client, sudo_password=host.password)
    for path in (REDIS_CONF, VM3_STORAGE_ENV, SENTINEL_CONF, SENTINEL_UNIT):
        _backup_path(client, path, backup_root, sudo_password=host.password, use_sudo=True)

    _upload_repo_files(client, sftp, host, VM3_FILE_MAPPINGS, backup_root)

    temp_redis = _remote_temp_path(host, "siem-vm3-redis.conf")
    temp_sentinel = _remote_temp_path(host, "siem-vm3-sentinel.conf")
    temp_unit = _remote_temp_path(host, "siem-vm3-sentinel.service")
    _upload_text(sftp, content=_render_replica_redis_conf(host.host, master_ip, redis_password), remote_temp_path=temp_redis)
    _upload_text(
        sftp,
        content=_render_sentinel_conf(host.host, master_name, master_ip, redis_password, sentinel_quorum, sentinel_port),
        remote_temp_path=temp_sentinel,
    )
    _upload_text(sftp, content=_render_sentinel_unit(), remote_temp_path=temp_unit)

    _install_with_sudo(client, temp_redis, REDIS_CONF, mode="0640", sudo_password=host.password)
    _install_with_sudo(client, temp_sentinel, SENTINEL_CONF, mode="0660", sudo_password=host.password)
    _install_with_sudo(client, temp_unit, SENTINEL_UNIT, mode="0644", sudo_password=host.password)
    _clear_stale_sentinel_processes(client, sudo_password=host.password)
    _allow_ufw_rules(
        client,
        sudo_password=host.password,
        rules=[*[(source, 6379) for source in redis_client_sources], *[(source, sentinel_port) for source in sentinel_peer_sources]],
    )
    _set_remote_env_values(
        client,
        VM3_STORAGE_ENV,
        {
            "SIEM_REDIS_SENTINEL_ENABLED": "true",
            "SIEM_REDIS_SENTINEL_MASTER": master_name,
            "SIEM_REDIS_SENTINEL_NODES": sentinel_nodes_csv,
        },
        sudo_password=host.password,
    )

    compile_cmd = (
        f"cd {shlex.quote(host.repo_root)} && "
        "/opt/siem/venv-storage/bin/python -m py_compile "
        "services/redis_runtime.py services/writer/worker.py services/stream_corr/worker.py"
    )
    code, _, err = _run_command(client, compile_cmd)
    if code != 0:
        raise RuntimeError(f"VM3 py_compile failed: {err.strip()}")

    command = (
        "mkdir -p /var/lib/redis /var/log/redis && "
        "chown -R redis:redis /var/lib/redis /var/log/redis && "
        "chown redis:redis /etc/redis/siem-sentinel.conf && "
        "systemctl daemon-reload && "
        "systemctl enable redis-server siem-redis-sentinel && "
        "systemctl stop siem-redis-sentinel || true && "
        "systemctl reset-failed siem-redis-sentinel || true && "
        "systemctl restart redis-server && "
        "sleep 3 && "
        "systemctl restart siem-redis-sentinel && "
        "systemctl restart siem-writer siem-stream-corr"
    )
    code, out, err = _run_command(client, command, sudo_password=host.password, use_sudo=True)
    cleaned = _strip_sudo_echo(out, host.password)
    if code != 0:
        raise RuntimeError(f"VM3 Redis HA activation failed: stdout={cleaned.strip()} stderr={err.strip()}")
    _wait_for_active_services(
        client,
        ["redis-server", "siem-redis-sentinel", "clickhouse-server", "siem-writer", "siem-stream-corr"],
        sudo_password=host.password,
    )
    print("vm3_redis_ha=ok")


def _configure_vm4_sentinel(
    client: paramiko.SSHClient,
    sftp: paramiko.SFTPClient,
    host: HostSpec,
    *,
    sentinel_peer_sources: tuple[str, ...],
    master_ip: str,
    redis_password: str,
    master_name: str,
    sentinel_port: int,
    sentinel_quorum: int,
    backup_root: str,
) -> None:
    _ensure_redis_package(client, sudo_password=host.password)
    for path in (SENTINEL_CONF, SENTINEL_UNIT):
        _backup_path(client, path, backup_root, sudo_password=host.password, use_sudo=True)

    temp_sentinel = _remote_temp_path(host, "siem-vm4-sentinel.conf")
    temp_unit = _remote_temp_path(host, "siem-vm4-sentinel.service")
    _upload_text(
        sftp,
        content=_render_sentinel_conf(host.host, master_name, master_ip, redis_password, sentinel_quorum, sentinel_port),
        remote_temp_path=temp_sentinel,
    )
    _upload_text(sftp, content=_render_sentinel_unit(), remote_temp_path=temp_unit)

    _install_with_sudo(client, temp_sentinel, SENTINEL_CONF, mode="0660", sudo_password=host.password)
    _install_with_sudo(client, temp_unit, SENTINEL_UNIT, mode="0644", sudo_password=host.password)
    _clear_stale_sentinel_processes(client, sudo_password=host.password)
    _allow_ufw_rules(
        client,
        sudo_password=host.password,
        rules=[(source, sentinel_port) for source in sentinel_peer_sources],
    )
    command = (
        "mkdir -p /var/lib/redis /var/log/redis && "
        "chown -R redis:redis /var/lib/redis /var/log/redis && "
        "chown redis:redis /etc/redis/siem-sentinel.conf && "
        "systemctl daemon-reload && "
        "systemctl disable --now redis-server || true && "
        "systemctl enable siem-redis-sentinel && "
        "systemctl stop siem-redis-sentinel || true && "
        "systemctl reset-failed siem-redis-sentinel || true && "
        "systemctl restart siem-redis-sentinel"
    )
    code, out, err = _run_command(client, command, sudo_password=host.password, use_sudo=True)
    cleaned = _strip_sudo_echo(out, host.password)
    if code != 0:
        raise RuntimeError(f"VM4 sentinel activation failed: stdout={cleaned.strip()} stderr={err.strip()}")
    _wait_for_active_services(
        client,
        ["siem-redis-sentinel", "siem-web", "nginx"],
        sudo_password=host.password,
    )
    print("vm4_redis_sentinel=ok")


def _configure_vm1_ingest(
    client: paramiko.SSHClient,
    sftp: paramiko.SFTPClient,
    host: HostSpec,
    *,
    master_name: str,
    sentinel_nodes_csv: str,
    backup_root: str,
) -> None:
    _backup_path(client, VM1_INGEST_ENV, backup_root, sudo_password=host.password, use_sudo=True)
    _upload_repo_files(client, sftp, host, VM1_FILE_MAPPINGS, backup_root)
    _set_remote_env_values(
        client,
        VM1_INGEST_ENV,
        {
            "SIEM_REDIS_SENTINEL_ENABLED": "true",
            "SIEM_REDIS_SENTINEL_MASTER": master_name,
            "SIEM_REDIS_SENTINEL_NODES": sentinel_nodes_csv,
        },
        sudo_password=host.password,
    )
    compile_cmd = (
        f"cd {shlex.quote(host.repo_root)} && "
        "python3 -m py_compile "
        "services/__init__.py services/redis_runtime.py services/ingest/redis_client.py"
    )
    code, _, err = _run_command(client, compile_cmd)
    if code != 0:
        raise RuntimeError(f"VM1 py_compile failed: {err.strip()}")
    command = "systemctl restart siem-ingest"
    code, out, err = _run_command(client, command, sudo_password=host.password, use_sudo=True)
    cleaned = _strip_sudo_echo(out, host.password)
    if code != 0:
        raise RuntimeError(f"VM1 ingest HA activation failed: stdout={cleaned.strip()} stderr={err.strip()}")
    _wait_for_active_services(client, ["siem-ingest", "nginx"], sudo_password=host.password)
    print("vm1_ingest_sentinel=ok")


def main() -> int:
    vm1 = HostSpec(
        host=_required_env("SIEM_VM1_HOST"),
        user=_required_env("SIEM_VM1_USER"),
        password=_required_env("SIEM_VM1_PASSWORD"),
        repo_root=_required_env("SIEM_VM1_BASE_DIR", default=DEFAULT_REMOTE_ROOT),
    )
    vm2 = HostSpec(
        host=_required_env("SIEM_VM2_HOST", default="192.168.1.37"),
        user=_required_env("SIEM_VM2_USER", default="rdegon"),
        password=_required_env("SIEM_VM2_PASSWORD"),
        repo_root=_required_env("SIEM_VM2_BASE_DIR", default=DEFAULT_REMOTE_ROOT),
    )
    vm3 = HostSpec(
        host=_required_env("SIEM_VM3_HOST"),
        user=_required_env("SIEM_VM3_USER"),
        password=_required_env("SIEM_VM3_PASSWORD"),
        repo_root=_required_env("SIEM_VM3_BASE_DIR", default=DEFAULT_REMOTE_ROOT),
    )
    vm4 = HostSpec(
        host=_required_env("SIEM_VM4_HOST"),
        user=_required_env("SIEM_VM4_USER"),
        password=_required_env("SIEM_VM4_PASSWORD"),
        repo_root=_required_env("SIEM_VM4_BASE_DIR", default=DEFAULT_REMOTE_ROOT),
    )
    master_name = _required_env("SIEM_REDIS_SENTINEL_MASTER", default="siem-master")
    sentinel_port = int(_required_env("SIEM_REDIS_SENTINEL_PORT", default="26379"))
    sentinel_quorum = int(_required_env("SIEM_REDIS_SENTINEL_QUORUM", default="2"))
    sentinel_nodes_csv = _required_env(
        "SIEM_REDIS_SENTINEL_NODES",
        default=f"{vm2.host}:{sentinel_port},{vm3.host}:{sentinel_port},{vm4.host}:{sentinel_port}",
    )

    backup_stamp = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    redis_password = ""

    vm2_client = _connect_client(vm2.host, vm2.user, vm2.password)
    vm2_sftp = vm2_client.open_sftp()
    try:
        code, out, err = _run_command(
            vm2_client,
            "python3 - <<'PY'\n"
            "from pathlib import Path\n"
            "text = Path('/etc/siem/processing.env').read_text(encoding='utf-8')\n"
            "for raw_line in text.splitlines():\n"
            "    if raw_line.startswith('SIEM_REDIS_PASSWORD='):\n"
            "        print(raw_line.split('=', 1)[1].strip())\n"
            "        break\n"
            "PY",
            sudo_password=vm2.password,
            use_sudo=True,
        )
        cleaned = _strip_sudo_echo(out, vm2.password).strip()
        if code != 0 or not cleaned:
            raise RuntimeError(f"Unable to read live Redis password from VM2: stdout={cleaned} stderr={err.strip()}")
        redis_password = cleaned.splitlines()[-1].strip()
        backup_root = f"/tmp/siem-redis-ha-backup-{backup_stamp}"
        print(f"backup_root={backup_root}")
        _configure_vm2_master(
            vm2_client,
            vm2_sftp,
            vm2,
            redis_client_sources=(vm1.host, vm2.host, vm3.host, vm4.host),
            sentinel_peer_sources=(vm1.host, vm3.host, vm4.host),
            redis_password=redis_password,
            master_name=master_name,
            sentinel_port=sentinel_port,
            sentinel_quorum=sentinel_quorum,
            sentinel_nodes_csv=sentinel_nodes_csv,
            backup_root=posixpath.join(backup_root, "vm2"),
        )
    finally:
        vm2_sftp.close()
        vm2_client.close()

    vm3_client = _connect_client(vm3.host, vm3.user, vm3.password)
    vm3_sftp = vm3_client.open_sftp()
    try:
        _configure_vm3_replica(
            vm3_client,
            vm3_sftp,
            vm3,
            redis_client_sources=(vm1.host, vm2.host, vm3.host, vm4.host),
            sentinel_peer_sources=(vm1.host, vm2.host, vm4.host),
            master_ip=vm2.host,
            redis_password=redis_password,
            master_name=master_name,
            sentinel_port=sentinel_port,
            sentinel_quorum=sentinel_quorum,
            sentinel_nodes_csv=sentinel_nodes_csv,
            backup_root=posixpath.join(backup_root, "vm3"),
        )
    finally:
        vm3_sftp.close()
        vm3_client.close()

    vm4_client = _connect_client(vm4.host, vm4.user, vm4.password)
    vm4_sftp = vm4_client.open_sftp()
    try:
        _configure_vm4_sentinel(
            vm4_client,
            vm4_sftp,
            vm4,
            sentinel_peer_sources=(vm1.host, vm2.host, vm3.host),
            master_ip=vm2.host,
            redis_password=redis_password,
            master_name=master_name,
            sentinel_port=sentinel_port,
            sentinel_quorum=sentinel_quorum,
            backup_root=posixpath.join(backup_root, "vm4"),
        )
    finally:
        vm4_sftp.close()
        vm4_client.close()

    vm1_client = _connect_client(vm1.host, vm1.user, vm1.password)
    vm1_sftp = vm1_client.open_sftp()
    try:
        _configure_vm1_ingest(
            vm1_client,
            vm1_sftp,
            vm1,
            master_name=master_name,
            sentinel_nodes_csv=sentinel_nodes_csv,
            backup_root=posixpath.join(backup_root, "vm1"),
        )
    finally:
        vm1_sftp.close()
        vm1_client.close()

    print("deployment=success")
    print(f"sentinel_master={master_name}")
    print(f"sentinel_nodes={sentinel_nodes_csv}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
