from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


PROCESSING_ENV = Path("/etc/siem/processing.env")
LIVE_REPO_DIR = Path("/opt/siem/siem-solution")
WORKSPACE_REPO_DIR = Path.cwd()
SYSTEMD_NORMALIZER_TEMPLATE = Path("/etc/systemd/system/siem-normalizer@.service")
SYSTEMD_FILTER_TEMPLATE = Path("/etc/systemd/system/siem-filter@.service")
SYSTEMD_WAIT_ONLINE_OVERRIDE = Path("/etc/systemd/system/systemd-networkd-wait-online.service.d/override.conf")
SCALEOUT_TEMPLATE_MAPPINGS = {
    Path("deploy/vm5/siem-normalizer@.service"): SYSTEMD_NORMALIZER_TEMPLATE,
    Path("deploy/vm5/siem-filter@.service"): SYSTEMD_FILTER_TEMPLATE,
    Path("deploy/vm5/systemd-networkd-wait-online.override.conf"): SYSTEMD_WAIT_ONLINE_OVERRIDE,
}
SCALEOUT_INSTANCE_IDS = ("1", "2")
PROCESSING_SERVICE_UNITS = tuple(
    unit
    for instance in SCALEOUT_INSTANCE_IDS
    for unit in (f"siem-normalizer@{instance}", f"siem-filter@{instance}")
)
PROCESSING_SYNC_PATHS = [
    Path("services/__init__.py"),
    Path("services/redis_runtime.py"),
    Path("services/transport_runtime.py"),
    Path("services/normalizer"),
    Path("services/filter"),
]


def _required_env(name: str, *, default: str | None = None) -> str:
    value = str(os.getenv(name, default or "") or "").strip()
    if value:
        return value
    raise SystemExit(f"Missing required environment variable: {name}")


def _parse_bool(value: object) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _run(command: str, *, sudo_password: str = "", use_sudo: bool = False) -> tuple[int, str, str]:
    wrapped = f"sudo -S -p '' bash -lc {shlex.quote(command)}" if use_sudo else command
    proc = subprocess.run(
        ["bash", "-lc", wrapped],
        input=f"{sudo_password}\n" if use_sudo else None,
        capture_output=True,
        text=True,
        timeout=120,
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


def _install_copy_command(source: Path, destination: Path, *, mode: str) -> str:
    return f"install -D -m {mode} {shlex.quote(str(source))} {shlex.quote(str(destination))}"


def render_processing_env(existing_text: str = "") -> str:
    desired = {
        "SIEM_ENV": "prod",
        "SIEM_INSTANCE_NAME": "siem-processing-vm5",
        "SIEM_TRANSPORT_BACKEND": "kafka",
        "SIEM_TRANSPORT_CONSUMER_BACKEND": "kafka",
        "SIEM_KAFKA_BOOTSTRAP_SERVERS": "192.168.1.35:9092,192.168.1.37:9092,192.168.1.40:9092",
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


def render_redis_retirement_command() -> str:
    return (
        "systemctl disable --now redis-server >/dev/null 2>&1 || true && "
        "systemctl mask redis-server >/dev/null 2>&1 || true && "
        "apt-get purge -y redis-server redis-tools >/dev/null 2>&1 || true && "
        "apt-get autoremove -y >/dev/null 2>&1 || true"
    )


def _sync_processing_runtime(workspace_repo_dir: Path, live_repo_dir: Path) -> None:
    for relative in PROCESSING_SYNC_PATHS:
        source = workspace_repo_dir / relative
        destination = live_repo_dir / relative
        if not source.exists():
            raise SystemExit(f"Missing required workspace path for VM5 processing sync: {source}")
        if source.resolve() == destination.resolve():
            continue
        if source.is_dir():
            shutil.copytree(source, destination, dirs_exist_ok=True)
            continue
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)


def _sync_scaleout_templates(workspace_repo_dir: Path) -> list[tuple[Path, Path]]:
    copied: list[tuple[Path, Path]] = []
    for relative_source, destination in SCALEOUT_TEMPLATE_MAPPINGS.items():
        source = workspace_repo_dir / relative_source
        if not source.exists():
            raise SystemExit(f"Missing required VM5 systemd template: {source}")
        if source.resolve() == destination.resolve():
            continue
        copied.append((source, destination))
    return copied


def main() -> int:
    sudo_password = _required_env("SIEM_VM5_PASSWORD")
    expected_host = _required_env("SIEM_VM5_EXPECT_HOST", default="siem-transport")
    enable_processing = _parse_bool(os.getenv("SIEM_VM5_ENABLE_PROCESSING", "0"))

    code, out, err = _run("hostname")
    hostname = out.strip()
    if code != 0 or not hostname:
        raise SystemExit(f"Unable to read local hostname: {err.strip()}")
    if hostname != expected_host:
        raise SystemExit(f"This deploy script must run on {expected_host}, got {hostname}")

    verify_presence_cmd = f"test -d {shlex.quote(str(LIVE_REPO_DIR))}"
    code, out, err = _run(verify_presence_cmd, sudo_password=sudo_password, use_sudo=True)
    if code != 0:
        raise SystemExit(f"Missing required VM5 repo root: {err.strip()}")

    backup_root = f"/tmp/siem-vm5-processing-backup-{datetime.now(tz=timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
    backup_cmd = (
        f"mkdir -p {shlex.quote(backup_root)} && "
        f"if [ -f {shlex.quote(str(PROCESSING_ENV))} ]; then cp {shlex.quote(str(PROCESSING_ENV))} {shlex.quote(backup_root + '/processing.env')}; fi && "
        f"if [ -f {shlex.quote(str(SYSTEMD_NORMALIZER_TEMPLATE))} ]; then cp {shlex.quote(str(SYSTEMD_NORMALIZER_TEMPLATE))} {shlex.quote(backup_root + '/siem-normalizer@.service')}; fi && "
        f"if [ -f {shlex.quote(str(SYSTEMD_FILTER_TEMPLATE))} ]; then cp {shlex.quote(str(SYSTEMD_FILTER_TEMPLATE))} {shlex.quote(backup_root + '/siem-filter@.service')}; fi && "
        f"if [ -f {shlex.quote(str(SYSTEMD_WAIT_ONLINE_OVERRIDE))} ]; then cp {shlex.quote(str(SYSTEMD_WAIT_ONLINE_OVERRIDE))} {shlex.quote(backup_root + '/systemd-networkd-wait-online.override.conf')}; fi"
    )
    code, out, err = _run(backup_cmd, sudo_password=sudo_password, use_sudo=True)
    if code != 0:
        raise SystemExit(f"Failed to back up VM5 processing files: {err.strip()}")

    existing_env_text = ""
    code, out, err = _run(f"cat {shlex.quote(str(PROCESSING_ENV))} || true", sudo_password=sudo_password, use_sudo=True)
    existing_env_text = _strip_sudo_echo(out, sudo_password)
    new_env_text = render_processing_env(existing_env_text)

    temp_root = Path.cwd() / ".tmp"
    temp_root.mkdir(parents=True, exist_ok=True)
    temp_env_path = temp_root / "siem-vm5-processing.env"
    temp_env_path.write_text(new_env_text, encoding="utf-8")

    _sync_processing_runtime(WORKSPACE_REPO_DIR, LIVE_REPO_DIR)
    scaleout_templates = _sync_scaleout_templates(WORKSPACE_REPO_DIR)
    scaleout_install_cmd = " && ".join(
        _install_copy_command(source, destination, mode="0644")
        for source, destination in scaleout_templates
    )

    install_cmd = (
        f"cd {shlex.quote(str(LIVE_REPO_DIR))} && "
        "/opt/siem/venv-processing/bin/python -m pip install --disable-pip-version-check -q "
        "-r services/normalizer/requirements.txt -r services/filter/requirements.txt && "
        "/opt/siem/venv-processing/bin/python -m py_compile "
        "services/__init__.py services/redis_runtime.py services/transport_runtime.py "
        "services/normalizer/config.py services/normalizer/worker.py "
        "services/filter/config.py services/filter/worker.py && "
        f"install -d -m 0755 {shlex.quote(str(PROCESSING_ENV.parent))} && "
        f"{_install_copy_command(temp_env_path, PROCESSING_ENV, mode='0600')} && "
        f"{scaleout_install_cmd} && "
        "systemctl daemon-reload && "
        "systemctl reset-failed systemd-networkd-wait-online.service || true && "
        "systemctl start systemd-networkd-wait-online.service || true && "
        + render_redis_retirement_command()
    )
    if enable_processing:
        install_cmd += f" && systemctl enable --now {' '.join(PROCESSING_SERVICE_UNITS)}"
    code, out, err = _run(install_cmd, sudo_password=sudo_password, use_sudo=True)
    cleaned = _strip_sudo_echo(out, sudo_password)
    if cleaned.strip():
        print(cleaned, end="")
    if code != 0:
        raise SystemExit(f"Failed to apply VM5 processing prepare changes: {err.strip()}")

    verify_cmd = (
        "python3 - <<'PY'\n"
        "from pathlib import Path\n"
        "env_text = Path('/etc/siem/processing.env').read_text(encoding='utf-8')\n"
        "for needle in [\n"
        "    'SIEM_TRANSPORT_BACKEND=kafka',\n"
        "    'SIEM_TRANSPORT_CONSUMER_BACKEND=kafka',\n"
        "    'SIEM_KAFKA_BOOTSTRAP_SERVERS=192.168.1.35:9092,192.168.1.37:9092,192.168.1.40:9092',\n"
        "    'SIEM_KAFKA_EXPECTED_BROKERS=3',\n"
        "    'SIEM_KAFKA_MIN_INSYNC_REPLICAS=2',\n"
        "]:\n"
        "    if needle not in env_text:\n"
        "        raise SystemExit(f'missing processing env setting: {needle}')\n"
        "for path in [\n"
        "    Path('/etc/systemd/system/siem-normalizer@.service'),\n"
        "    Path('/etc/systemd/system/siem-filter@.service'),\n"
        "]:\n"
        "    text = path.read_text(encoding='utf-8')\n"
        "    if 'ExecStart=/opt/siem/venv-processing/bin/python -m services.' not in text:\n"
        "        raise SystemExit(f'missing module ExecStart in {path}')\n"
        "wait_online = Path('/etc/systemd/system/systemd-networkd-wait-online.service.d/override.conf')\n"
        "wait_text = wait_online.read_text(encoding='utf-8')\n"
        "if '--interface=ens19' not in wait_text:\n"
        "    raise SystemExit('missing ens19 wait-online override')\n"
        "if Path('/lib/systemd/system/redis-server.service').exists() and Path('/etc/systemd/system/redis-server.service').exists():\n"
        "    raise SystemExit('redis-server unit override still present on VM5')\n"
        "print('vm5_processing_prepare=ok')\n"
        f"print('vm5_processing_units={','.join(PROCESSING_SERVICE_UNITS)}')\n"
        "PY"
    )
    if enable_processing:
        verify_cmd = f"systemctl is-active {' '.join(PROCESSING_SERVICE_UNITS)} && " + verify_cmd
    code, out, err = _run(verify_cmd, sudo_password=sudo_password, use_sudo=True)
    cleaned = _strip_sudo_echo(out, sudo_password)
    if cleaned.strip():
        print(cleaned, end="")
    if code != 0:
        raise SystemExit(f"VM5 processing prepare verification failed: stdout={cleaned.strip()} stderr={err.strip()}")

    print(f"processing_mode={'active' if enable_processing else 'prepared_only'}")
    print(f"backup_root={backup_root}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
