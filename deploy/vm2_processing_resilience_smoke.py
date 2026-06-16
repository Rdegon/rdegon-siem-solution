from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
from pathlib import Path


PROCESSING_ENV = Path("/etc/siem/processing.env")
NETPLAN_FILE = Path("/etc/netplan/01-siem.yaml")
VULN_NORMALIZER_MARKERS = (
    "vuln.greenbone",
    "openvas",
)
WORKER_RUNTIME_MARKERS = (
    "create_transport_consumer(",
    "create_transport_producer(",
    "await self._consumer.poll(",
    "await self._consumer.ack(",
)
DEFAULT_VM2_EXPECTED_HOSTS = ("siem-processing", "siem-transport")


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


def main() -> int:
    sudo_password = _required_env("SIEM_VM2_PASSWORD")
    expected_hosts = _expected_hosts(os.getenv("SIEM_VM2_EXPECT_HOST", ",".join(DEFAULT_VM2_EXPECTED_HOSTS)))

    code, out, err = _run("hostname")
    hostname = out.strip()
    if code != 0 or hostname not in expected_hosts:
        raise SystemExit(f"Unexpected local hostname for VM2 smoke: {hostname!r} expected={expected_hosts!r} stderr={err.strip()}")

    code, _, err = _run(
        f"test -f {shlex.quote(str(PROCESSING_ENV))} && test -f {shlex.quote(str(NETPLAN_FILE))}",
        sudo_password=sudo_password,
        use_sudo=True,
    )
    if code != 0:
        raise SystemExit(f"Missing required VM2 files: stderr={err.strip()}")

    status_cmd = "systemctl is-active siem-normalizer siem-filter siem-normalizer@2 siem-filter@2 ssh actions.runner.Rdegon-siem-solution.siem-vm2.service"
    code, out, err = _run(status_cmd, sudo_password=sudo_password, use_sudo=True)
    cleaned = [line.strip() for line in _strip_sudo_echo(out, sudo_password).splitlines() if line.strip()]
    if code != 0 or cleaned != ["active", "active", "active", "active", "active", "active"]:
        raise SystemExit(f"Unexpected VM2 service state: stdout={cleaned} stderr={err.strip()}")
    code, out, err = _run(
        "systemctl is-active actions.runner.Rdegon-siem-solution.siem-vm5.service || true",
        sudo_password=sudo_password,
        use_sudo=True,
    )
    peer_runner_state = _strip_sudo_echo(out, sudo_password).strip()
    if peer_runner_state not in {"inactive", "unknown", "failed", ""}:
        raise SystemExit(f"Unexpected duplicate VM5 runner on VM2: state={peer_runner_state} stderr={err.strip()}")

    redis_retire_check = (
        "python3 - <<'PY'\n"
        "import json\n"
        "import shutil\n"
        "import subprocess\n"
        "payload = {\n"
        "    'redis_server_active': subprocess.run(['systemctl', 'is-active', 'redis-server'], capture_output=True, text=True).stdout.strip(),\n"
        "    'redis_server_enabled': subprocess.run(['systemctl', 'is-enabled', 'redis-server'], capture_output=True, text=True).stdout.strip(),\n"
        "    'redis_cli_present': bool(shutil.which('redis-cli')),\n"
        "    'redis_pkg_present': subprocess.run(['dpkg-query', '-W', '-f=${Status}', 'redis-server'], capture_output=True, text=True).returncode == 0,\n"
        "}\n"
        "print(json.dumps(payload, ensure_ascii=True))\n"
        "PY"
    )
    code, out, err = _run(redis_retire_check, sudo_password=sudo_password, use_sudo=True)
    cleaned_out = _strip_sudo_echo(out, sudo_password).strip()
    if code != 0 or not cleaned_out:
        raise SystemExit(f"Unable to query Redis retirement status: stdout={cleaned_out} stderr={err.strip()}")
    payload = json.loads(cleaned_out)
    if payload.get("redis_server_active") not in {"inactive", "unknown", "failed"}:
        raise SystemExit(f"Redis service is still active on VM2: {payload}")
    if payload.get("redis_cli_present") or payload.get("redis_pkg_present"):
        raise SystemExit(f"Redis package footprint is still present on VM2: {payload}")

    runtime_check = (
        "python3 - <<'PY'\n"
        "import json\n"
        "from pathlib import Path\n"
        "state = {}\n"
        "for path in [\n"
        "    Path('/opt/siem/siem-solution/services/normalizer/worker.py'),\n"
        "    Path('/opt/siem/siem-solution/services/filter/worker.py'),\n"
        "    Path('/etc/systemd/system/siem-normalizer@.service'),\n"
        "    Path('/etc/systemd/system/siem-filter@.service'),\n"
        "]:\n"
        "    text = path.read_text(encoding='utf-8')\n"
        "    if path.suffix == '.service':\n"
        "        state[str(path)] = {\n"
        "            'module_exec': 'ExecStart=/opt/siem/venv-processing/bin/python -m services.' in text,\n"
        "            'redis_dependency_removed': 'Requires=redis-server' not in text and 'After=network-online.target redis-server' not in text,\n"
        "        }\n"
        "    else:\n"
        "        state[str(path)] = {\n"
        f"            'transport_markers_present': all(marker in text for marker in {WORKER_RUNTIME_MARKERS!r}),\n"
        "        }\n"
        "print(json.dumps(state, ensure_ascii=True, sort_keys=True))\n"
        "PY"
    )
    code, out, err = _run(runtime_check, sudo_password=sudo_password, use_sudo=True)
    cleaned_out = _strip_sudo_echo(out, sudo_password).strip()
    if code != 0 or not cleaned_out:
        raise SystemExit(f"Unable to query VM2 processing runtime state: stdout={cleaned_out} stderr={err.strip()}")
    runtime_payload = json.loads(cleaned_out)
    missing_runtime = []
    for path, checks in runtime_payload.items():
        if path.endswith(".service"):
            if not checks.get("module_exec") or not checks.get("redis_dependency_removed"):
                missing_runtime.append(path)
            continue
        if not checks.get("transport_markers_present"):
            missing_runtime.append(path)
    if missing_runtime:
        raise SystemExit(f"VM2 processing runtime is not on transport abstraction path: {missing_runtime}")

    dns_check = (
        "python3 - <<'PY'\n"
        "import json\n"
        "import subprocess\n"
        "from pathlib import Path\n"
        "netplan = Path('/etc/netplan/01-siem.yaml').read_text(encoding='utf-8')\n"
        "state = {\n"
        "    'legacy_netplan_present': Path('/etc/netplan/01-siem-net.yaml').exists(),\n"
        "    'netplan_has_lan_dns_pin': 'addresses: [192.168.1.1]' in netplan,\n"
        "    'netplan_mode': oct(Path('/etc/netplan/01-siem.yaml').stat().st_mode & 0o777),\n"
        "}\n"
        "for host in ['github.com', 'broker.actions.githubusercontent.com', 'pipelinesghubeus9.actions.githubusercontent.com']:\n"
        "    proc = subprocess.run(['getent', 'ahostsv4', host], capture_output=True, text=True)\n"
        "    state[f'resolve::{host}'] = bool(proc.returncode == 0 and proc.stdout.strip())\n"
        "print(json.dumps(state, ensure_ascii=True, sort_keys=True))\n"
        "PY"
    )
    code, out, err = _run(dns_check, sudo_password=sudo_password, use_sudo=True)
    cleaned_out = _strip_sudo_echo(out, sudo_password).strip()
    if code != 0 or not cleaned_out:
        raise SystemExit(f"Unable to query VM2 DNS state: stdout={cleaned_out} stderr={err.strip()}")
    dns_payload = json.loads(cleaned_out)
    if dns_payload.get("legacy_netplan_present"):
        raise SystemExit(f"Legacy netplan file is still present: {dns_payload}")
    if not dns_payload.get("netplan_has_lan_dns_pin"):
        raise SystemExit(f"VM2 netplan is missing LAN DNS pin: {dns_payload}")
    if dns_payload.get("netplan_mode") != "0o600":
        raise SystemExit(f"VM2 netplan file mode is not hardened: {dns_payload}")
    unresolved = [key for key, value in dns_payload.items() if key.startswith("resolve::") and not value]
    if unresolved:
        raise SystemExit(f"VM2 DNS resolution failed for: {unresolved}")

    print("smoke=success")
    print(f"redis_retired={json.dumps(payload, ensure_ascii=True)}")
    print(f"processing_runtime={json.dumps(runtime_payload, ensure_ascii=True, sort_keys=True)}")
    print(f"dns_state={json.dumps(dns_payload, ensure_ascii=True, sort_keys=True)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
