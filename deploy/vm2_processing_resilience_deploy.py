from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


PROCESSING_ENV = Path("/etc/siem/processing.env")
NETPLAN_FILE = Path("/etc/netplan/01-siem.yaml")
LEGACY_NETPLAN_FILE = Path("/etc/netplan/01-siem-net.yaml")
RESOLVED_CONF = Path("/etc/systemd/resolved.conf")
LIVE_REPO_DIR = Path("/opt/siem/siem-solution")
LIVE_SERVICES_DIR = LIVE_REPO_DIR / "services"
WORKSPACE_REPO_DIR = Path.cwd()
RUNNER_SERVICE = "actions.runner.Rdegon-siem-solution.siem-vm2.service"
DEFAULT_COMMAND_TIMEOUT_SEC = 120
INSTALL_COMMAND_TIMEOUT_SEC = 900
VERIFY_COMMAND_TIMEOUT_SEC = 180
SYSTEMD_NORMALIZER_TEMPLATE = Path("/etc/systemd/system/siem-normalizer@.service")
SYSTEMD_FILTER_TEMPLATE = Path("/etc/systemd/system/siem-filter@.service")
SCALEOUT_TEMPLATE_MAPPINGS = {
    Path("deploy/vm2/siem-normalizer@.service"): SYSTEMD_NORMALIZER_TEMPLATE,
    Path("deploy/vm2/siem-filter@.service"): SYSTEMD_FILTER_TEMPLATE,
}
SCALEOUT_INSTANCE_IDS = ("2",)
SCALEOUT_NORMALIZER_UNITS = tuple(f"siem-normalizer@{instance}" for instance in SCALEOUT_INSTANCE_IDS)
SCALEOUT_FILTER_UNITS = tuple(f"siem-filter@{instance}" for instance in SCALEOUT_INSTANCE_IDS)
PRIMARY_PROCESSING_UNITS = ("siem-normalizer", "siem-filter")
PROCESSING_SERVICE_UNITS = PRIMARY_PROCESSING_UNITS + SCALEOUT_NORMALIZER_UNITS + SCALEOUT_FILTER_UNITS
WORKER_RUNTIME_MARKERS = (
    "create_transport_consumer(",
    "create_transport_producer(",
    "await self._consumer.poll(",
    "await self._consumer.ack(",
)
DNS_HEALTH_HOSTS = [
    "github.com",
    "broker.actions.githubusercontent.com",
    "pipelinesghubeus9.actions.githubusercontent.com",
]
PROCESSING_SYNC_PATHS = [
    Path("services/__init__.py"),
    Path("services/redis_runtime.py"),
    Path("services/transport_runtime.py"),
    Path("deploy/kafka_cluster_layout.py"),
    Path("deploy/kafka_wave_prepare.py"),
    Path("services/normalizer"),
    Path("services/filter"),
]
VM2_NETPLAN_CONTENT = """network:
  version: 2
  renderer: networkd
  ethernets:
    ens19:
      dhcp4: false
      addresses:
        - 192.168.1.37/24
      routes:
        - to: default
          via: 192.168.1.1
      nameservers:
        addresses: [192.168.1.1]
      optional: true
"""
VM2_RESOLVED_CONF_CONTENT = """[Resolve]
DNS=192.168.1.1 1.1.1.1 8.8.8.8
FallbackDNS=1.1.1.1 8.8.8.8
Domains=~.
DNSStubListener=yes
"""

DEFAULT_VM2_EXPECTED_HOSTS = ("siem-processing", "siem-transport")


def _resolve_bash_path() -> str:
    discovered = shutil.which("bash")
    if discovered:
        return discovered
    windows_fallback = Path.home() / "tools" / "PortableGit" / "bin" / "bash.exe"
    home_text = str(Path.home()).replace("\\", "/")
    if windows_fallback.exists() or (":/" in home_text and "/Users/" in home_text):
        return str(windows_fallback)
    raise SystemExit("Unable to locate bash executable for vm2 processing deploy")


def _required_env(name: str, *, default: str | None = None) -> str:
    value = str(os.getenv(name, default or "") or "").strip()
    if value:
        return value
    raise SystemExit(f"Missing required environment variable: {name}")


def _expected_hosts(raw: str | None = None) -> tuple[str, ...]:
    source = str(raw or "").strip()
    if not source:
        return DEFAULT_VM2_EXPECTED_HOSTS
    parsed = tuple(item.strip() for item in source.split(",") if item.strip())
    return parsed or DEFAULT_VM2_EXPECTED_HOSTS


def _run(
    command: str,
    *,
    sudo_password: str = "",
    use_sudo: bool = False,
    timeout: int = DEFAULT_COMMAND_TIMEOUT_SEC,
) -> tuple[int, str, str]:
    wrapped = f"sudo -S -p '' bash -lc {shlex.quote(command)}" if use_sudo else command
    proc = subprocess.run(
        [_resolve_bash_path(), "-lc", wrapped],
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


def _install_copy_command(source: Path, destination: Path, *, mode: str) -> str:
    return f"install -m {mode} {shlex.quote(str(source))} {shlex.quote(str(destination))}"


def _service_status_command(*units: str) -> str:
    return f"systemctl is-active {' '.join(units)}"


def update_redis_conf(text: str) -> str:
    desired = {
        "appendonly": "yes",
        "appendfsync": "everysec",
        "auto-aof-rewrite-percentage": "100",
        "auto-aof-rewrite-min-size": "64mb",
    }
    lines = text.splitlines() if str(text or "").strip() else []
    positions: dict[str, int] = {}
    for index, line in enumerate(lines):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        parts = line.split(None, 1)
        key = parts[0].strip() if parts else ""
        if key:
            positions[key] = index
    for key, value in desired.items():
        rendered = f"{key} {value}"
        if key in positions:
            lines[positions[key]] = rendered
        else:
            lines.append(rendered)
    return "\n".join(lines).rstrip() + "\n"


def _build_dependency_install_command(*, running_inside_actions: bool = False, force_pip_install: bool = False) -> str:
    if running_inside_actions and not force_pip_install:
        return "echo processing_pip_install=skipped_in_github_actions"
    return (
        "/opt/siem/venv-processing/bin/python -m pip install --disable-pip-version-check -q "
        "-r services/normalizer/requirements.txt -r services/filter/requirements.txt"
    )


def _build_redis_service_command(*, running_inside_actions: bool = False, purge_packages: bool = False) -> str:
    command = (
        "if systemctl is-active --quiet redis-server; then true; else systemctl start redis-server; fi"
        if running_inside_actions
        else "systemctl restart --no-block redis-server"
    )
    if purge_packages:
        command += " && systemctl disable --now redis-server || true"
        command += " && DEBIAN_FRONTEND=noninteractive apt-get purge -y redis-server redis-tools || true"
        command += " && DEBIAN_FRONTEND=noninteractive apt-get autoremove -y || true"
    return command


def _build_processing_service_command(*, running_inside_actions: bool = False) -> str:
    units = " ".join(PROCESSING_SERVICE_UNITS)
    command = (
        "systemctl enable ssh && "
        f"systemctl enable {units}"
    )
    if not running_inside_actions:
        command += " && netplan apply && systemctl restart systemd-resolved && resolvectl flush-caches || true"
    command += f" && {_build_redis_service_command(running_inside_actions=running_inside_actions)}"
    command += f" && systemctl restart --no-block {units}"
    if not running_inside_actions:
        command += f" && systemctl restart {RUNNER_SERVICE}"
    return command


def _build_stale_process_cleanup_command() -> str:
    return (
        "pkill -f vm2_processing_resilience_deploy.py || true && "
        "pkill -f retry_run.py || true && "
        "systemctl restart redis-server || true && "
        "echo vm2_stale_process_cleanup=ok"
    )


def _sync_processing_runtime(
    workspace_repo_dir: Path,
    live_repo_dir: Path,
    *,
    temp_root: Path,
    sudo_password: str,
) -> None:
    staged_root = temp_root / "processing-runtime"
    if staged_root.exists():
        shutil.rmtree(staged_root)
    staged_root.mkdir(parents=True, exist_ok=True)
    for relative in PROCESSING_SYNC_PATHS:
        source = workspace_repo_dir / relative
        destination = live_repo_dir / relative
        staged = staged_root / relative
        if not source.exists():
            raise SystemExit(f"Missing required workspace path for processing runtime sync: {source}")
        if source.is_dir():
            shutil.copytree(source, staged, dirs_exist_ok=True)
            sync_cmd = (
                f"rm -rf {shlex.quote(str(destination))} && "
                f"mkdir -p {shlex.quote(str(destination.parent))} && "
                f"cp -R {shlex.quote(str(staged))} {shlex.quote(str(destination))}"
            )
            code, _, err = _run(sync_cmd, sudo_password=sudo_password, use_sudo=True, timeout=INSTALL_COMMAND_TIMEOUT_SEC)
            if code != 0:
                raise SystemExit(f"Failed to sync VM2 runtime directory {destination}: {err.strip()}")
            continue
        staged.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, staged)
        install_cmd = _install_copy_command(staged, destination, mode="0644")
        code, _, err = _run(install_cmd, sudo_password=sudo_password, use_sudo=True, timeout=INSTALL_COMMAND_TIMEOUT_SEC)
        if code != 0:
            raise SystemExit(f"Failed to sync VM2 runtime file {destination}: {err.strip()}")


def _sync_scaleout_templates(workspace_repo_dir: Path) -> list[tuple[Path, Path]]:
    copied: list[tuple[Path, Path]] = []
    for relative_source, destination in SCALEOUT_TEMPLATE_MAPPINGS.items():
        source = workspace_repo_dir / relative_source
        if not source.exists():
            raise SystemExit(f"Missing required systemd template for processing scale-out: {source}")
        copied.append((source, destination))
    return copied


def main() -> int:
    sudo_password = _required_env("SIEM_VM2_PASSWORD")
    expected_hosts = _expected_hosts(os.getenv("SIEM_VM2_EXPECT_HOST", ",".join(DEFAULT_VM2_EXPECTED_HOSTS)))
    running_inside_actions = str(os.getenv("GITHUB_ACTIONS", "")).strip().lower() == "true"

    verify_presence_cmd = (
        f"test -f {shlex.quote(str(PROCESSING_ENV))} && "
        f"test -f {shlex.quote(str(NETPLAN_FILE))} && "
        f"test -f {shlex.quote(str(RESOLVED_CONF))} && "
        f"test -d {shlex.quote(str(LIVE_REPO_DIR))}"
    )
    code, _, err = _run(verify_presence_cmd, sudo_password=sudo_password, use_sudo=True)
    if code != 0:
        raise SystemExit(f"Missing one or more required VM2 files: {err.strip()}")

    code, out, err = _run("hostname")
    hostname = out.strip()
    if code != 0 or not hostname:
        raise SystemExit(f"Unable to read local hostname: {err.strip()}")
    if hostname not in expected_hosts:
        raise SystemExit(f"This deploy script must run on one of {expected_hosts}, got {hostname}")

    backup_root = f"/tmp/siem-vm2-processing-backup-{datetime.now(tz=timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
    backup_cmd = (
        f"mkdir -p {shlex.quote(backup_root)} && "
        f"cp {shlex.quote(str(PROCESSING_ENV))} {shlex.quote(backup_root + '/processing.env')} && "
        f"cp {shlex.quote(str(NETPLAN_FILE))} {shlex.quote(backup_root + '/01-siem.yaml')} && "
        f"cp {shlex.quote(str(RESOLVED_CONF))} {shlex.quote(backup_root + '/resolved.conf')} && "
        f"cp -R {shlex.quote(str(LIVE_SERVICES_DIR / 'normalizer'))} {shlex.quote(backup_root + '/normalizer')} && "
        f"cp -R {shlex.quote(str(LIVE_SERVICES_DIR / 'filter'))} {shlex.quote(backup_root + '/filter')} && "
        f"if [ -f {shlex.quote(str(SYSTEMD_NORMALIZER_TEMPLATE))} ]; then cp {shlex.quote(str(SYSTEMD_NORMALIZER_TEMPLATE))} {shlex.quote(backup_root + '/siem-normalizer@.service')}; fi && "
        f"if [ -f {shlex.quote(str(SYSTEMD_FILTER_TEMPLATE))} ]; then cp {shlex.quote(str(SYSTEMD_FILTER_TEMPLATE))} {shlex.quote(backup_root + '/siem-filter@.service')}; fi && "
        f"if [ -f {shlex.quote(str(LIVE_SERVICES_DIR / '__init__.py'))} ]; then cp {shlex.quote(str(LIVE_SERVICES_DIR / '__init__.py'))} {shlex.quote(backup_root + '/services.__init__.py')}; fi && "
        f"if [ -f {shlex.quote(str(LEGACY_NETPLAN_FILE))} ]; then cp {shlex.quote(str(LEGACY_NETPLAN_FILE))} {shlex.quote(backup_root + '/01-siem-net.yaml')}; fi"
    )
    code, _, err = _run(backup_cmd, sudo_password=sudo_password, use_sudo=True)
    if code != 0:
        raise SystemExit(f"Failed to back up VM2 processing files: {err.strip()}")

    temp_root = Path.cwd() / ".tmp"
    temp_root.mkdir(parents=True, exist_ok=True)
    temp_netplan_path = temp_root / "siem-vm2-netplan.yaml"
    temp_netplan_path.write_text(VM2_NETPLAN_CONTENT, encoding="utf-8")
    temp_resolved_path = temp_root / "siem-vm2-resolved.conf"
    temp_resolved_path.write_text(VM2_RESOLVED_CONF_CONTENT, encoding="utf-8")
    _sync_processing_runtime(
        WORKSPACE_REPO_DIR,
        LIVE_REPO_DIR,
        temp_root=temp_root,
        sudo_password=sudo_password,
    )
    scaleout_templates = _sync_scaleout_templates(WORKSPACE_REPO_DIR)
    scaleout_install_cmd = " && ".join(
        _install_copy_command(source, destination, mode="0644")
        for source, destination in scaleout_templates
    )

    install_cmd = (
        f"cd {shlex.quote(str(LIVE_REPO_DIR))} && "
        f"{_build_dependency_install_command(running_inside_actions=running_inside_actions)} && "
        "/opt/siem/venv-processing/bin/python -m py_compile "
        "services/__init__.py services/redis_runtime.py services/transport_runtime.py "
        "services/normalizer/config.py services/normalizer/worker.py "
        "services/filter/config.py services/filter/worker.py && "
        f"{_install_copy_command(temp_netplan_path, NETPLAN_FILE, mode='0600')} && "
        f"{_install_copy_command(temp_resolved_path, RESOLVED_CONF, mode='0644')} && "
        f"rm -f {shlex.quote(str(LEGACY_NETPLAN_FILE))} && "
        f"{scaleout_install_cmd} && "
        "systemctl daemon-reload && "
        f"systemctl enable --now {' '.join(PROCESSING_SERVICE_UNITS)}"
    )
    if running_inside_actions:
        install_cmd += " && netplan generate"
        install_cmd += f" && systemctl restart {' '.join(PROCESSING_SERVICE_UNITS)}"
        install_cmd += f" && {_build_redis_service_command(running_inside_actions=True, purge_packages=True)}"
    else:
        install_cmd += " && netplan generate"
        install_cmd += " && netplan apply"
        install_cmd += " && systemctl restart systemd-resolved"
        install_cmd += " && resolvectl flush-caches || true"
        install_cmd += f" && systemctl restart {' '.join(PROCESSING_SERVICE_UNITS)}"
        install_cmd += f" && {_build_redis_service_command(running_inside_actions=False, purge_packages=True)}"
        install_cmd += f" && systemctl restart ssh {RUNNER_SERVICE}"
    code, out, err = _run(install_cmd, sudo_password=sudo_password, use_sudo=True, timeout=INSTALL_COMMAND_TIMEOUT_SEC)
    cleaned = _strip_sudo_echo(out, sudo_password)
    if cleaned.strip():
        print(cleaned, end="")
    if code != 0:
        raise SystemExit(f"Failed to apply VM2 processing resilience changes: {err.strip()}")
    if running_inside_actions:
        print("runner_restart=skipped_in_github_actions")
        print("network_reload=skipped_in_github_actions")

    kafka_prepare_cmd = (
        f"cd {shlex.quote(str(LIVE_REPO_DIR))} && "
        f"SIEM_NODE_PASSWORD={shlex.quote(sudo_password)} "
        "SIEM_KAFKA_NODE_ID=2 "
        "SIEM_KAFKA_EXPECT_HOST=siem-processing "
        "python3 deploy/kafka_wave_prepare.py"
    )
    code, out, err = _run(kafka_prepare_cmd, timeout=INSTALL_COMMAND_TIMEOUT_SEC)
    if out.strip():
        print(out, end="")
    if code != 0:
        raise SystemExit(f"Failed to apply VM2 Kafka tuning: {err.strip()}")

    verify_cmd = (
        f"{_service_status_command(*PROCESSING_SERVICE_UNITS, 'ssh', RUNNER_SERVICE, 'siem-kafka')} && "
        "python3 - <<'PY'\n"
        "import json\n"
        "import shutil\n"
        "import subprocess\n"
        "from pathlib import Path\n"
        "redis_state = {\n"
        "    'redis_server_active': subprocess.run(['systemctl', 'is-active', 'redis-server'], capture_output=True, text=True).stdout.strip(),\n"
        "    'redis_cli_present': bool(shutil.which('redis-cli')),\n"
        "    'redis_pkg_present': subprocess.run(['dpkg-query', '-W', '-f=${Status}', 'redis-server'], capture_output=True, text=True).returncode == 0,\n"
        "}\n"
        "if redis_state['redis_server_active'] not in {'inactive', 'unknown', 'failed'}:\n"
        "    raise SystemExit(json.dumps(redis_state, sort_keys=True))\n"
        "if redis_state['redis_cli_present'] or redis_state['redis_pkg_present']:\n"
        "    raise SystemExit(json.dumps(redis_state, sort_keys=True))\n"
        "for path in [\n"
        "    Path('/opt/siem/siem-solution/services/normalizer/worker.py'),\n"
        "    Path('/opt/siem/siem-solution/services/filter/worker.py'),\n"
        "    Path('/etc/systemd/system/siem-normalizer@.service'),\n"
        "    Path('/etc/systemd/system/siem-filter@.service'),\n"
        "]:\n"
        "    payload = path.read_text(encoding='utf-8')\n"
        "    if path.suffix == '.service':\n"
        "        if 'Requires=redis-server' in payload or 'After=network-online.target redis-server' in payload:\n"
        "            raise SystemExit(f'redis dependency still present in {path}')\n"
        "        if 'ExecStart=/opt/siem/venv-processing/bin/python -m services.' not in payload:\n"
        "            raise SystemExit(f'scale-out template is missing python module launch: {path}')\n"
        "        continue\n"
        f"    required_markers = {WORKER_RUNTIME_MARKERS!r}\n"
        "    missing = [marker for marker in required_markers if marker not in payload]\n"
        "    if missing:\n"
        "        raise SystemExit(f'worker is missing transport runtime markers {missing}: {path}')\n"
        "processing_env = Path('/etc/siem/processing.env').read_text(encoding='utf-8')\n"
        "required = {\n"
        "    'SIEM_TRANSPORT_BACKEND=kafka',\n"
        "    'SIEM_TRANSPORT_CONSUMER_BACKEND=kafka',\n"
        "    'SIEM_KAFKA_BOOTSTRAP_SERVERS=',\n"
        "}\n"
        "missing = [needle for needle in required if needle not in processing_env]\n"
        "if missing:\n"
        "    raise SystemExit('missing env settings: ' + ', '.join(missing))\n"
        "netplan = Path('/etc/netplan/01-siem.yaml').read_text(encoding='utf-8')\n"
        "if 'addresses: [192.168.1.1]' not in netplan:\n"
        "    raise SystemExit('missing VM2 LAN DNS pin')\n"
        "if Path('/etc/netplan/01-siem-net.yaml').exists():\n"
        "    raise SystemExit('legacy netplan file still present')\n"
        "resolved = Path('/etc/systemd/resolved.conf').read_text(encoding='utf-8')\n"
        "if 'DNS=192.168.1.1' not in resolved:\n"
        "    raise SystemExit('missing resolved primary DNS pin')\n"
        "kafka_env = Path('/etc/siem/kafka/kafka.env').read_text(encoding='utf-8')\n"
        "if 'KAFKA_HEAP_OPTS=-Xms256m -Xmx512m' not in kafka_env:\n"
        "    raise SystemExit('missing Kafka heap tuning in /etc/siem/kafka/kafka.env')\n"
        f"for host in {DNS_HEALTH_HOSTS!r}:\n"
        "    proc = subprocess.run(['getent', 'ahostsv4', host], capture_output=True, text=True)\n"
        "    if proc.returncode != 0 or not proc.stdout.strip():\n"
        "        raise SystemExit(f'dns resolution failed for {host}: {proc.stdout!r} {proc.stderr!r}')\n"
        "print(json.dumps(redis_state, sort_keys=True))\n"
        "print('processing_runtime=ok')\n"
        "print('kafka_runtime=ok')\n"
        f"print('processing_scaleout_units={','.join(PROCESSING_SERVICE_UNITS)}')\n"
        "print('vm2_dns=ok')\n"
        "PY"
    )
    code, out, err = _run(verify_cmd, sudo_password=sudo_password, use_sudo=True, timeout=VERIFY_COMMAND_TIMEOUT_SEC)
    cleaned = _strip_sudo_echo(out, sudo_password)
    if cleaned.strip():
        print(cleaned, end="")
    if code != 0:
        raise SystemExit(f"VM2 resilience verification failed: stdout={cleaned.strip()} stderr={err.strip()}")

    print("vm2_redis_retired=ok")
    print("deployment=success")
    print(f"backup_root={backup_root}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
