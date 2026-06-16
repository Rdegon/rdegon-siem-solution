from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


LIVE_REPO_DIR = Path("/opt/siem/siem-solution")
WORKSPACE_REPO_DIR = Path.cwd()
SHADOW_ENV = Path("/etc/siem/storage-kafka-shadow.env")
SHADOW_SERVICE = Path("/etc/systemd/system/siem-writer-shadow.service")
SHADOW_SYNC_PATHS = [
    Path("services/__init__.py"),
    Path("services/redis_runtime.py"),
    Path("services/transport_runtime.py"),
    Path("writer_worker.py"),
]


def _required_env(name: str, *, default: str | None = None) -> str:
    value = str(os.getenv(name, default or "") or "").strip()
    if value:
        return value
    raise SystemExit(f"Missing required environment variable: {name}")


def _run(command: str, *, sudo_password: str = "", use_sudo: bool = False, timeout: int = 300) -> tuple[int, str, str]:
    wrapped = f"sudo -S -p '' bash -lc {shlex.quote(command)}" if use_sudo else command
    proc = subprocess.run(
        ["bash", "-lc", wrapped],
        input=f"{sudo_password}\n" if use_sudo else None,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return proc.returncode, proc.stdout, proc.stderr


def _strip_sudo_echo(text: str, sudo_password: str) -> str:
    if not sudo_password:
        return text
    cleaned: list[str] = []
    for raw_line in str(text or "").replace("\r", "\n").split("\n"):
        if raw_line.strip() == sudo_password:
            continue
        cleaned.append(raw_line)
    return "\n".join(cleaned)


def _sync_shadow_runtime(workspace_repo_dir: Path, live_repo_dir: Path) -> None:
    for relative in SHADOW_SYNC_PATHS:
        source = workspace_repo_dir / relative
        destination = live_repo_dir / relative
        if not source.exists():
            raise SystemExit(f"Missing required workspace path for VM3 shadow writer sync: {source}")
        if source.resolve() == destination.resolve():
            continue
        if source.is_dir():
            shutil.copytree(source, destination, dirs_exist_ok=True)
            continue
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)


def render_shadow_env(existing_text: str = "") -> str:
    desired = {
        "SIEM_INSTANCE_NAME": "siem-writer-shadow",
        "SIEM_TRANSPORT_BACKEND": "kafka",
        "SIEM_TRANSPORT_CONSUMER_BACKEND": "kafka",
        "SIEM_KAFKA_BOOTSTRAP_SERVERS": "192.168.1.35:9092,192.168.1.37:9092,192.168.1.40:9092",
        "SIEM_KAFKA_SECURITY_PROTOCOL": "PLAINTEXT",
        "SIEM_KAFKA_EXPECTED_BROKERS": "3",
        "SIEM_KAFKA_EXPECTED_CONTROLLERS": "3",
        "SIEM_KAFKA_DEFAULT_REPLICATION_FACTOR": "3",
        "SIEM_KAFKA_MIN_INSYNC_REPLICAS": "2",
        "SIEM_KAFKA_TOPIC_FILTERED": "siem.filtered",
        "SIEM_WRITER_GROUP": "writer-shadow",
        "SIEM_WRITER_CONSUMER": "writer-shadow-1",
        "SIEM_EVENTS_TABLE": "siem.events_shadow",
    }
    lines = existing_text.splitlines() if existing_text.strip() else []
    positions: dict[str, int] = {}
    for index, line in enumerate(lines):
        if "=" not in line or line.lstrip().startswith("#"):
            continue
        key = line.split("=", 1)[0].strip()
        if key:
            positions[key] = index
    for key, value in desired.items():
        rendered = f"{key}={value}"
        if key in positions:
            lines[positions[key]] = rendered
        else:
            lines.append(rendered)
    return "\n".join(lines).rstrip() + "\n"


def render_shadow_dependency_install_command() -> str:
    return (
        "PIP_DEFAULT_TIMEOUT=120 "
        "/opt/siem/venv-storage/bin/python -m pip install "
        "--disable-pip-version-check --retries 10 --default-timeout 120 "
        "aiokafka==0.10.0 clickhouse-driver redis"
    )


def render_vm3_storage_access_command() -> str:
    allow_hosts = ("192.168.1.35", "192.168.1.37", "192.168.1.39", "192.168.1.40")
    commands: list[str] = []
    for host in allow_hosts:
        commands.append(f"ufw allow from {host} to any port 9000 proto tcp >/dev/null 2>&1 || true")
        commands.append(f"ufw allow from {host} to any port 8123 proto tcp >/dev/null 2>&1 || true")
    return (
        "if command -v ufw >/dev/null 2>&1 && ufw status | head -n 1 | grep -qi active; then "
        + " && ".join(commands)
        + "; fi"
    )


def main() -> int:
    sudo_password = _required_env("SIEM_VM3_PASSWORD")
    expected_host = _required_env("SIEM_VM3_EXPECT_HOST", default="siem-storage")

    code, out, err = _run("hostname")
    hostname = out.strip()
    if code != 0 or not hostname:
        raise SystemExit(f"Unable to read local hostname: {err.strip()}")
    if hostname != expected_host:
        raise SystemExit(f"This deploy script must run on {expected_host}, got {hostname}")

    verify_presence_cmd = f"test -d {shlex.quote(str(LIVE_REPO_DIR))} && test -f /etc/siem/storage.env"
    code, out, err = _run(verify_presence_cmd, sudo_password=sudo_password, use_sudo=True)
    if code != 0:
        raise SystemExit(f"Missing required VM3 files: {err.strip()}")

    backup_root = f"/tmp/siem-vm3-kafka-shadow-backup-{datetime.now(tz=timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
    backup_cmd = (
        f"mkdir -p {shlex.quote(backup_root)} && "
        f"if [ -f {shlex.quote(str(SHADOW_ENV))} ]; then cp {shlex.quote(str(SHADOW_ENV))} {shlex.quote(backup_root + '/storage-kafka-shadow.env')}; fi && "
        f"if [ -f {shlex.quote(str(SHADOW_SERVICE))} ]; then cp {shlex.quote(str(SHADOW_SERVICE))} {shlex.quote(backup_root + '/siem-writer-shadow.service')}; fi && "
        f"cp {shlex.quote(str(LIVE_REPO_DIR / 'writer_worker.py'))} {shlex.quote(backup_root + '/writer_worker.py')}"
    )
    code, out, err = _run(backup_cmd, sudo_password=sudo_password, use_sudo=True)
    if code != 0:
        raise SystemExit(f"Failed to back up VM3 shadow-writer files: {err.strip()}")

    code, out, err = _run(f"cat {shlex.quote(str(SHADOW_ENV))} || true", sudo_password=sudo_password, use_sudo=True)
    existing_env_text = _strip_sudo_echo(out, sudo_password)

    temp_root = Path.cwd() / ".tmp"
    temp_root.mkdir(parents=True, exist_ok=True)
    temp_env = temp_root / "siem-storage-kafka-shadow.env"
    temp_unit = temp_root / "siem-writer-shadow.service"
    temp_env.write_text(render_shadow_env(existing_env_text), encoding="utf-8")
    temp_unit.write_text((WORKSPACE_REPO_DIR / "deploy/vm3/siem-writer-shadow.service").read_text(encoding="utf-8"), encoding="utf-8")

    _sync_shadow_runtime(WORKSPACE_REPO_DIR, LIVE_REPO_DIR)

    code, out, err = _run(render_vm3_storage_access_command(), sudo_password=sudo_password, use_sudo=True, timeout=180)
    cleaned = _strip_sudo_echo(out, sudo_password)
    if cleaned.strip():
        print(cleaned, end="")
    if code != 0:
        raise SystemExit(f"Failed to align VM3 storage firewall rules: {err.strip()}")

    create_shadow_table_cmd = (
        "/opt/siem/venv-storage/bin/python - <<'PY'\n"
        "from pathlib import Path\n"
        "from clickhouse_driver import Client\n"
        "env = {}\n"
        "for raw_line in Path('/etc/siem/storage.env').read_text(encoding='utf-8').splitlines():\n"
        "    line = raw_line.strip()\n"
        "    if not line or line.startswith('#') or '=' not in line:\n"
        "        continue\n"
        "    key, value = line.split('=', 1)\n"
        "    env[key.strip()] = value.strip()\n"
        "client = Client(\n"
        "    host=env.get('SIEM_CH_HOST', '127.0.0.1'),\n"
        "    port=int(env.get('SIEM_CH_PORT', '9000')),\n"
        "    user=env.get('SIEM_CH_USER', 'siem_admin'),\n"
        "    password=env.get('SIEM_CH_PASSWORD', ''),\n"
        "    database=env.get('SIEM_CH_DB', 'siem'),\n"
        ")\n"
        "ddl = client.execute(\"SHOW CREATE TABLE siem.events\")[0][0]\n"
        "shadow = ddl.replace('CREATE TABLE siem.events', 'CREATE TABLE IF NOT EXISTS siem.events_shadow', 1)\n"
        "client.execute(shadow)\n"
        "print('events_shadow_table=ok')\n"
        "PY\n"
    )

    dependency_cmd = (
        f"cd {shlex.quote(str(LIVE_REPO_DIR))} && "
        + render_shadow_dependency_install_command()
        + " && "
        + "/opt/siem/venv-storage/bin/python -m py_compile writer_worker.py services/__init__.py services/redis_runtime.py services/transport_runtime.py"
    )
    code, out, err = _run(dependency_cmd, sudo_password=sudo_password, use_sudo=True, timeout=900)
    cleaned = _strip_sudo_echo(out, sudo_password)
    if cleaned.strip():
        print(cleaned, end="")
    if code != 0:
        raise SystemExit(f"Failed to apply VM3 Kafka shadow writer changes: {err.strip()}")

    code, out, err = _run(create_shadow_table_cmd, sudo_password=sudo_password, use_sudo=True, timeout=300)
    cleaned = _strip_sudo_echo(out, sudo_password)
    if cleaned.strip():
        print(cleaned, end="")
    if code != 0:
        raise SystemExit(f"Failed to bootstrap VM3 Kafka shadow table: {err.strip()}")

    install_service_cmd = (
        f"install -m 0600 {shlex.quote(str(temp_env))} {shlex.quote(str(SHADOW_ENV))} && "
        f"install -m 0644 {shlex.quote(str(temp_unit))} {shlex.quote(str(SHADOW_SERVICE))} && "
        "systemctl daemon-reload && systemctl enable --now siem-writer-shadow"
    )
    code, out, err = _run(install_service_cmd, sudo_password=sudo_password, use_sudo=True, timeout=300)
    cleaned = _strip_sudo_echo(out, sudo_password)
    if cleaned.strip():
        print(cleaned, end="")
    if code != 0:
        raise SystemExit(f"Failed to install VM3 Kafka shadow writer service: {err.strip()}")

    verify_cmd = (
        "/opt/siem/venv-storage/bin/python - <<'PY'\n"
        "from pathlib import Path\n"
        "from clickhouse_driver import Client\n"
        "shadow_env = Path('/etc/siem/storage-kafka-shadow.env').read_text(encoding='utf-8')\n"
        "for needle in [\n"
        "    'SIEM_TRANSPORT_BACKEND=kafka',\n"
        "    'SIEM_TRANSPORT_CONSUMER_BACKEND=kafka',\n"
        "    'SIEM_EVENTS_TABLE=siem.events_shadow',\n"
        "    'SIEM_WRITER_GROUP=writer-shadow',\n"
        "]:\n"
        "    if needle not in shadow_env:\n"
        "        raise SystemExit(f'missing shadow writer env setting: {needle}')\n"
        "env = {}\n"
        "for raw_line in Path('/etc/siem/storage.env').read_text(encoding='utf-8').splitlines():\n"
        "    line = raw_line.strip()\n"
        "    if not line or line.startswith('#') or '=' not in line:\n"
        "        continue\n"
        "    key, value = line.split('=', 1)\n"
        "    env[key.strip()] = value.strip()\n"
        "client = Client(host=env.get('SIEM_CH_HOST', '127.0.0.1'), port=int(env.get('SIEM_CH_PORT', '9000')), user=env.get('SIEM_CH_USER', 'siem_admin'), password=env.get('SIEM_CH_PASSWORD', ''), database=env.get('SIEM_CH_DB', 'siem'))\n"
        "rows = client.execute(\"EXISTS TABLE siem.events_shadow\")\n"
        "if not rows or rows[0][0] != 1:\n"
        "    raise SystemExit('shadow events table was not created')\n"
        "print('vm3_kafka_shadow_writer=ok')\n"
        "PY\n"
    )
    code, out, err = _run(verify_cmd, sudo_password=sudo_password, use_sudo=True, timeout=300)
    cleaned = _strip_sudo_echo(out, sudo_password)
    if cleaned.strip():
        print(cleaned, end="")
    if code != 0:
        raise SystemExit(f"VM3 Kafka shadow writer verification failed: stdout={cleaned.strip()} stderr={err.strip()}")

    code, out, err = _run("systemctl is-active siem-writer-shadow", sudo_password=sudo_password, use_sudo=True)
    cleaned = _strip_sudo_echo(out, sudo_password)
    if code != 0 or "active" not in cleaned:
        raise SystemExit(f"siem-writer-shadow is not active: stdout={cleaned.strip()} stderr={err.strip()}")

    print("siem-writer-shadow status=active")
    print("deployment=success")
    print(f"backup_root={backup_root}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
