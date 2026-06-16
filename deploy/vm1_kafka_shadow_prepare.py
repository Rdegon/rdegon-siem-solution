from __future__ import annotations

import os
import shlex
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


INGEST_ENV = Path("/etc/siem/ingest.env")
LIVE_REPO_DIR = Path("/opt/siem/siem-solution")
WORKSPACE_REPO_DIR = Path.cwd()


@dataclass(frozen=True)
class SyncMapping:
    source: Path
    destination: Path


INGEST_SYNC_MAPPINGS = [
    SyncMapping(Path("services/__init__.py"), Path("services/__init__.py")),
    SyncMapping(Path("services/redis_runtime.py"), Path("services/redis_runtime.py")),
    SyncMapping(Path("services/transport_runtime.py"), Path("services/transport_runtime.py")),
    SyncMapping(Path("services/ingest/__init__.py"), Path("services/ingest/__init__.py")),
    SyncMapping(Path("services/ingest/app.py"), Path("services/ingest/app.py")),
    SyncMapping(Path("services/ingest/config.py"), Path("services/ingest/config.py")),
    SyncMapping(Path("services/ingest/logging_conf.py"), Path("services/ingest/logging_conf.py")),
    SyncMapping(Path("services/ingest/print_config.py"), Path("services/ingest/print_config.py")),
    SyncMapping(Path("services/ingest/redis_client.py"), Path("services/ingest/redis_client.py")),
    SyncMapping(Path("services/ingest/requirements.txt"), Path("services/ingest/requirements.txt")),
    SyncMapping(Path("services/ingest/syslog_server.py"), Path("services/ingest/syslog_server.py")),
]


def _required_env(name: str, *, default: str | None = None) -> str:
    value = str(os.getenv(name, default or "") or "").strip()
    if value:
        return value
    raise SystemExit(f"Missing required environment variable: {name}")


def _run(command: str, *, sudo_password: str = "", use_sudo: bool = False) -> tuple[int, str, str]:
    wrapped = f"sudo -S -p '' bash -lc {shlex.quote(command)}" if use_sudo else command
    proc = subprocess.run(
        ["bash", "-lc", wrapped],
        input=f"{sudo_password}\n" if use_sudo else None,
        capture_output=True,
        text=True,
        timeout=240,
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


def render_ingest_sync_commands(
    workspace_repo_dir: Path = WORKSPACE_REPO_DIR,
    live_repo_dir: Path = LIVE_REPO_DIR,
    *,
    require_existing: bool = True,
) -> str:
    commands: list[str] = []
    for mapping in INGEST_SYNC_MAPPINGS:
        source = workspace_repo_dir / mapping.source
        destination = live_repo_dir / mapping.destination
        if require_existing and not source.exists():
            raise SystemExit(f"Missing required workspace path for VM1 ingest sync: {source}")
        if source.resolve() == destination.resolve():
            continue
        commands.append(f"install -d -m 0755 {shlex.quote(str(destination.parent))}")
        commands.append(f"install -m 0644 {shlex.quote(str(source))} {shlex.quote(str(destination))}")
    return " && ".join(commands)


def render_ingest_env(existing_text: str = "", *, transport_backend: str = "dual") -> str:
    desired = {
        "SIEM_INSTANCE_NAME": "siem-ingest-vm1",
        "SIEM_TRANSPORT_BACKEND": str(transport_backend or "dual").strip().lower() or "dual",
        "SIEM_KAFKA_BOOTSTRAP_SERVERS": "192.168.1.35:9092,192.168.1.37:9092,192.168.1.40:9092",
        "SIEM_KAFKA_SECURITY_PROTOCOL": "PLAINTEXT",
        "SIEM_KAFKA_EXPECTED_BROKERS": "3",
        "SIEM_KAFKA_EXPECTED_CONTROLLERS": "3",
        "SIEM_KAFKA_DEFAULT_REPLICATION_FACTOR": "3",
        "SIEM_KAFKA_MIN_INSYNC_REPLICAS": "2",
        "SIEM_KAFKA_TOPIC_RAW": "siem.raw",
        "SIEM_KAFKA_TOPIC_NORMALIZED": "siem.normalized",
        "SIEM_KAFKA_TOPIC_FILTERED": "siem.filtered",
        "SIEM_KAFKA_TOPIC_DLQ": "siem.dlq",
        "SIEM_KAFKA_TOPIC_REPLAY": "siem.replay",
        "SIEM_KAFKA_TOPIC_TRANSPORT_AUDIT": "siem.transport.audit",
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


def main() -> int:
    sudo_password = _required_env("SIEM_VM1_PASSWORD")
    expected_host = _required_env("SIEM_VM1_EXPECT_HOST", default="siem-ingest")

    code, out, err = _run("hostname")
    hostname = out.strip()
    if code != 0 or not hostname:
        raise SystemExit(f"Unable to read local hostname: {err.strip()}")
    if hostname != expected_host:
        raise SystemExit(f"This deploy script must run on {expected_host}, got {hostname}")

    verify_presence_cmd = f"test -f {shlex.quote(str(INGEST_ENV))} && test -d {shlex.quote(str(LIVE_REPO_DIR))}"
    code, out, err = _run(verify_presence_cmd, sudo_password=sudo_password, use_sudo=True)
    if code != 0:
        raise SystemExit(f"Missing required VM1 files: {err.strip()}")

    backup_root = f"/tmp/siem-vm1-kafka-shadow-backup-{datetime.now(tz=timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
    backup_cmd = (
        f"mkdir -p {shlex.quote(backup_root)} && "
        f"cp {shlex.quote(str(INGEST_ENV))} {shlex.quote(backup_root + '/ingest.env')} && "
        f"cp -R {shlex.quote(str(LIVE_REPO_DIR / 'services' / 'ingest'))} {shlex.quote(backup_root + '/ingest')}"
    )
    code, out, err = _run(backup_cmd, sudo_password=sudo_password, use_sudo=True)
    if code != 0:
        raise SystemExit(f"Failed to back up VM1 ingest files: {err.strip()}")

    code, out, err = _run(f"cat {shlex.quote(str(INGEST_ENV))}", sudo_password=sudo_password, use_sudo=True)
    ingest_env_text = _strip_sudo_echo(out, sudo_password)
    if code != 0:
        raise SystemExit(f"Unable to read {INGEST_ENV}: {err.strip()}")
    temp_root = Path.cwd() / ".tmp"
    temp_root.mkdir(parents=True, exist_ok=True)
    temp_env_path = temp_root / "siem-vm1-ingest.env"
    temp_env_path.write_text(render_ingest_env(ingest_env_text), encoding="utf-8")

    install_steps = [f"cd {shlex.quote(str(LIVE_REPO_DIR))}"]
    sync_commands = render_ingest_sync_commands(WORKSPACE_REPO_DIR, LIVE_REPO_DIR)
    if sync_commands:
        install_steps.append(sync_commands)
    install_steps.extend(
        [
            "/opt/siem/venv-ingest/bin/python -m pip install --disable-pip-version-check -q -r services/ingest/requirements.txt",
            "/opt/siem/venv-ingest/bin/python -m py_compile "
            "services/__init__.py services/redis_runtime.py services/transport_runtime.py "
            "services/ingest/__init__.py services/ingest/app.py services/ingest/config.py "
            "services/ingest/logging_conf.py services/ingest/print_config.py services/ingest/redis_client.py "
            "services/ingest/syslog_server.py",
            f"install -m 0600 {shlex.quote(str(temp_env_path))} {shlex.quote(str(INGEST_ENV))}",
            "systemctl restart siem-ingest",
        ]
    )
    install_cmd = " && ".join(install_steps)
    code, out, err = _run(install_cmd, sudo_password=sudo_password, use_sudo=True)
    cleaned = _strip_sudo_echo(out, sudo_password)
    if cleaned.strip():
        print(cleaned, end="")
    if code != 0:
        raise SystemExit(f"Failed to apply VM1 Kafka shadow changes: {err.strip()}")

    verify_cmd = (
        "python3 - <<'PY'\n"
        "from pathlib import Path\n"
        "env_text = Path('/etc/siem/ingest.env').read_text(encoding='utf-8')\n"
        "for needle in [\n"
        "    'SIEM_TRANSPORT_BACKEND=dual',\n"
        "    'SIEM_KAFKA_BOOTSTRAP_SERVERS=192.168.1.35:9092,192.168.1.37:9092,192.168.1.40:9092',\n"
        "    'SIEM_KAFKA_SECURITY_PROTOCOL=PLAINTEXT',\n"
        "    'SIEM_KAFKA_TOPIC_RAW=siem.raw',\n"
        "]:\n"
        "    if needle not in env_text:\n"
        "        raise SystemExit(f'missing ingest env setting: {needle}')\n"
        "print('vm1_ingest_shadow_prepare=ok')\n"
        "PY"
    )
    code, out, err = _run(verify_cmd, sudo_password=sudo_password, use_sudo=True)
    cleaned = _strip_sudo_echo(out, sudo_password)
    if cleaned.strip():
        print(cleaned, end="")
    if code != 0:
        raise SystemExit(f"VM1 Kafka shadow verification failed: stdout={cleaned.strip()} stderr={err.strip()}")

    code, out, err = _run("systemctl is-active siem-ingest", sudo_password=sudo_password, use_sudo=True)
    cleaned = _strip_sudo_echo(out, sudo_password)
    if code != 0 or "active" not in cleaned:
        raise SystemExit(f"siem-ingest is not active after Kafka shadow prepare: stdout={cleaned.strip()} stderr={err.strip()}")

    print("siem-ingest status=active")
    print("deployment=success")
    print(f"backup_root={backup_root}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
