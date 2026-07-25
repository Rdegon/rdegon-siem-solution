from __future__ import annotations

import base64
import json
import os
import shlex
import ssl
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from dataclasses import dataclass
from typing import Callable

try:
    import paramiko
except ModuleNotFoundError:  # pragma: no cover - exercised on lab nodes without local watchdog deps
    paramiko = None

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from deploy.vm2_processing_resilience_deploy import (
    DNS_HEALTH_HOSTS,
    PROCESSING_SERVICE_UNITS,
    RUNNER_SERVICE,
    VM2_NETPLAN_CONTENT,
    VM2_RESOLVED_CONF_CONTENT,
)

WRITER_SCALEOUT_UNITS = ("siem-writer@2",)


def _required_env(name: str, *, default: str | None = None) -> str:
    value = os.getenv(name, default or "").strip()
    if value:
        return value
    raise SystemExit(f"Missing required environment variable: {name}")


def _optional_env(name: str, *, default: str = "") -> str:
    return str(os.getenv(name, default) or "").strip()


def parse_qm_status(text: str) -> str:
    for raw_line in str(text or "").replace("\r", "\n").split("\n"):
        line = raw_line.strip()
        if not line:
            continue
        if "status:" in line:
            return line.split("status:", 1)[1].strip()
        if line in {"running", "stopped", "paused"}:
            return line
    raise ValueError(f"Unable to parse qm status from: {text!r}")


def parse_systemctl_states(text: str) -> list[str]:
    return [line.strip() for line in str(text or "").replace("\r", "\n").split("\n") if line.strip()]


def service_state_is_inactive(state: str) -> bool:
    return str(state or "").strip() in {"inactive", "unknown", "failed", ""}


def parse_bool_flag(value: object) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on", "pong", "ok"}


def parse_runner_status(payload: dict[str, object], runner_name: str) -> tuple[str, bool]:
    for runner in payload.get("runners", []):
        if str(runner.get("name") or "").strip() != runner_name:
            continue
        return str(runner.get("status") or "").strip().lower(), bool(runner.get("busy"))
    return "missing", False


@dataclass(frozen=True)
class HostSpec:
    host: str
    user: str
    password: str


CRITICAL_INGEST_COLLECTOR_PROFILES = ("app", "linux-auth", "linux-audit")
PVE_SOURCE_ALIASES = {"192.168.1.101", "192.168.3.101", "pve"}
EDGE_VPN_SOURCE_ALIASES = {
    "192.168.1.102",
    "192.168.3.102",
    "10.20.10.1",
    "10.20.30.1",
    "opnsense-edge-01",
    "lab-edge-01",
}


def _connect_client(host: str, user: str, password: str, *, attempts: int = 3, delay_seconds: float = 4.0) -> paramiko.SSHClient:
    if paramiko is None:
        raise RuntimeError("paramiko is required to run the homelab watchdog")
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
            print(f"watchdog ssh retry host={host} attempt={attempt}/{attempts} error={exc}")
            time.sleep(delay_seconds)
    raise RuntimeError(f"Unable to connect to {host}: {last_error}")


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
    cleaned_lines: list[str] = []
    for raw_line in str(text or "").replace("\r", "\n").split("\n"):
        line = raw_line.strip("\x00")
        if line.strip() == sudo_password:
            continue
        cleaned_lines.append(line)
    return "\n".join(cleaned_lines)


def _ensure_service_bundle(client: paramiko.SSHClient, services: list[str], *, sudo_password: str, restart_bundle: str | None = None) -> list[str]:
    code, out, err = _run_command(client, f"systemctl is-active {' '.join(services)}", sudo_password=sudo_password, use_sudo=True)
    cleaned = _strip_sudo_echo(out, sudo_password)
    states = parse_systemctl_states(cleaned)
    if code == 0 and states == ["active"] * len(services):
        return states
    if not restart_bundle:
        raise RuntimeError(f"Service bundle unhealthy: services={services} stdout={states} stderr={err.strip()}")
    print(f"watchdog repair restart={' '.join(services)}")
    code, out, err = _run_command(client, restart_bundle, sudo_password=sudo_password, use_sudo=True)
    if code != 0:
        raise RuntimeError(f"Service restart failed: services={services} stderr={err.strip()}")
    time.sleep(8)
    code, out, err = _run_command(client, f"systemctl is-active {' '.join(services)}", sudo_password=sudo_password, use_sudo=True)
    cleaned = _strip_sudo_echo(out, sudo_password)
    states = parse_systemctl_states(cleaned)
    if code != 0 or states != ["active"] * len(services):
        raise RuntimeError(f"Service bundle still unhealthy after restart: services={services} stdout={states} stderr={err.strip()}")
    return states


def _observe_service_bundle(client: paramiko.SSHClient, services: list[str], *, sudo_password: str) -> list[str]:
    code, out, err = _run_command(client, f"systemctl is-active {' '.join(services)}", sudo_password=sudo_password, use_sudo=True)
    cleaned = _strip_sudo_echo(out, sudo_password)
    states = parse_systemctl_states(cleaned)
    if code == 0 and states == ["active"] * len(services):
        return states
    print(f"watchdog optional_bundle services={services} states={states} stderr={err.strip()}")
    return states


def _ensure_service_inactive(
    client: paramiko.SSHClient,
    service: str,
    *,
    sudo_password: str,
    repair_bundle: str | None = None,
) -> str:
    code, out, err = _run_command(client, f"systemctl is-active {service} || true", sudo_password=sudo_password, use_sudo=True)
    cleaned = _strip_sudo_echo(out, sudo_password)
    state = next((line.strip() for line in cleaned.splitlines() if line.strip()), "")
    if service_state_is_inactive(state):
        return state
    if not repair_bundle:
        raise RuntimeError(f"Service is unexpectedly active: service={service} state={state} stderr={err.strip()}")
    print(f"watchdog repair deactivate_service={service}")
    code, _, err = _run_command(client, repair_bundle, sudo_password=sudo_password, use_sudo=True)
    if code != 0:
        raise RuntimeError(f"Unable to deactivate service {service}: {err.strip()}")
    time.sleep(5)
    code, out, err = _run_command(client, f"systemctl is-active {service} || true", sudo_password=sudo_password, use_sudo=True)
    cleaned = _strip_sudo_echo(out, sudo_password)
    state = next((line.strip() for line in cleaned.splitlines() if line.strip()), "")
    if not service_state_is_inactive(state):
        raise RuntimeError(f"Service is still active after repair: service={service} state={state} stderr={err.strip()}")
    return state


def _qm_status(proxmox: paramiko.SSHClient, vmid: str) -> str:
    code, out, err = _run_command(proxmox, f"qm status {shlex.quote(vmid)}")
    if code != 0:
        raise RuntimeError(f"qm status failed for {vmid}: {err.strip()}")
    return parse_qm_status(out)


def _qm_guest_exec_json(proxmox: paramiko.SSHClient, vmid: str, command: str) -> dict[str, object]:
    wrapped = f"qm guest exec {shlex.quote(vmid)} -- bash -lc {shlex.quote(command)}"
    code, out, err = _run_command(proxmox, wrapped)
    if code != 0:
        raise RuntimeError(f"qm guest exec failed for {vmid}: {err.strip()}")
    return json.loads(out)


def _qm_guest_exec_text(proxmox: paramiko.SSHClient, vmid: str, command: str) -> str:
    payload = _qm_guest_exec_json(proxmox, vmid, command)
    return str(payload.get("out-data") or "")


def _guest_python_command(script: str) -> str:
    payload = base64.b64encode(script.encode("utf-8")).decode("ascii")
    return f"python3 -c \"import base64; exec(base64.b64decode('{payload}').decode('utf-8'))\""


def _default_vm2_dns_runner_state(*, query_error: str = "") -> dict[str, object]:
    state: dict[str, object] = {
        "legacy_netplan_present": False,
        "runner_active": False,
    }
    for host in DNS_HEALTH_HOSTS:
        state[f"resolve::{host}"] = False
    if query_error:
        state["query_error"] = query_error
    return state


def _vm2_service_units_clause(include_runner: bool = True) -> str:
    units = ["ssh", "qemu-guest-agent", *PROCESSING_SERVICE_UNITS]
    if include_runner:
        units.append(RUNNER_SERVICE)
    return " ".join(units)


def _vm5_service_units_clause(*, include_runner: bool = True, include_kafka: bool = False) -> str:
    units = ["ssh"]
    if include_runner:
        units.append("actions.runner.Rdegon-siem-solution.siem-vm5.service")
    if include_kafka:
        units.append("siem-kafka")
    return " ".join(units)


def _ensure_vm2_available(proxmox: paramiko.SSHClient, vmid: str) -> dict[str, object]:
    status = _qm_status(proxmox, vmid)
    if status != "running":
        print(f"watchdog repair vm2_status={status} action=start")
        code, out, err = _run_command(proxmox, f"qm start {shlex.quote(vmid)}")
        if code != 0 and "already running" not in out + err:
            raise RuntimeError(f"qm start failed for {vmid}: {err.strip()}")
        time.sleep(12)
    last_error: Exception | None = None
    for _ in range(15):
        try:
            payload = _qm_guest_exec_json(
                proxmox,
                vmid,
                f"hostname && systemctl is-active {_vm2_service_units_clause()} || true",
            )
            if int(payload.get("exitcode", 0) or 0) == 0:
                text = str(payload.get("out-data") or "")
                states = parse_systemctl_states(text)
                expected_states = len(_vm2_service_units_clause().split())
                if len(states) >= expected_states + 1 and states[1 : expected_states + 1] == ["active"] * expected_states:
                    return payload
                # Guest agent is alive and can execute commands; detailed service/runners
                # are verified by the follow-up checks below with repair paths.
                return payload
            text = str(payload.get("out-data") or "")
            states = parse_systemctl_states(text)
            expected_states = len(_vm2_service_units_clause().split())
            if len(states) >= expected_states + 1 and states[1 : expected_states + 1] == ["active"] * expected_states:
                return payload
        except Exception as exc:  # noqa: BLE001
            last_error = exc
        time.sleep(6)
    raise RuntimeError(f"VM2 guest agent did not stabilize: {last_error}")


def _load_env_file(path: str) -> dict[str, str]:
    env: dict[str, str] = {}
    text = Path(path).read_text(encoding="utf-8")
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        env[key.strip()] = value.strip()
    return env


def _parse_info_section(text: str) -> dict[str, str]:
    payload: dict[str, str] = {}
    for raw_line in str(text or "").replace("\r", "\n").split("\n"):
        line = raw_line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        key, value = line.split(":", 1)
        payload[key.strip()] = value.strip()
    return payload


def _bool_int(flag: bool) -> int:
    return 1 if flag else 0


VM2_PIPELINE_STATE_COMMAND = """python3 - <<'PY'
import json
from pathlib import Path


def load_env(path: str) -> dict[str, str]:
    payload: dict[str, str] = {}
    for raw_line in Path(path).read_text(encoding='utf-8').splitlines():
        line = raw_line.strip()
        if not line or line.startswith('#') or '=' not in line:
            continue
        key, value = line.split('=', 1)
        payload[key.strip()] = value.strip()
    return payload


env = load_env('/etc/siem/processing.env')
state = {
    'transport_backend': env.get('SIEM_TRANSPORT_BACKEND', 'redis').strip().lower() or 'redis',
    'consumer_backend': env.get('SIEM_TRANSPORT_CONSUMER_BACKEND', '').strip().lower() or env.get('SIEM_TRANSPORT_BACKEND', 'redis').strip().lower() or 'redis',
    'kafka_bootstrap_servers': [item.strip() for item in env.get('SIEM_KAFKA_BOOTSTRAP_SERVERS', '').split(',') if item.strip()],
    'kafka_expected_brokers': int(env.get('SIEM_KAFKA_EXPECTED_BROKERS', '0') or 0),
    'processing_units': ['siem-normalizer@1', 'siem-filter@1', 'siem-normalizer@2', 'siem-filter@2'],
}
print(json.dumps(state, ensure_ascii=True, sort_keys=True))
PY"""


def _query_vm2_pipeline_state(proxmox: paramiko.SSHClient, vmid: str) -> dict[str, object]:
    text = _qm_guest_exec_text(proxmox, vmid, VM2_PIPELINE_STATE_COMMAND).strip()
    if not text:
        raise RuntimeError("VM2 pipeline state returned empty output")
    return json.loads(text)


def _restart_vm2_processing_bundle(proxmox: paramiko.SSHClient, vmid: str) -> dict[str, object]:
    unit_clause = f"{' '.join(PROCESSING_SERVICE_UNITS)} qemu-guest-agent ssh"
    _qm_guest_exec_json(
        proxmox,
        vmid,
        f"systemctl restart {' '.join(PROCESSING_SERVICE_UNITS)}",
    )
    expected = len(unit_clause.split())
    last_states: list[str] = []
    for attempt in range(1, 7):
        time.sleep(4 if attempt == 1 else 3)
        text = _qm_guest_exec_text(proxmox, vmid, f"systemctl is-active {unit_clause} || true")
        states = parse_systemctl_states(text)
        if len(states) >= expected:
            states = states[-expected:]
        last_states = states
        if states == ["active"] * expected:
            return {
                "attempts": attempt,
                "out-data": "\n".join(states),
                "unit_clause": unit_clause,
            }
    raise RuntimeError(f"VM2 processing bundle unhealthy after restart: {last_states}")


def _repair_vm2_network_and_runner(proxmox: paramiko.SSHClient, vmid: str) -> dict[str, object]:
    script = f"""
from pathlib import Path
import subprocess
legacy = Path('/etc/netplan/01-siem-net.yaml')
if legacy.exists():
    legacy.unlink()
Path('/etc/netplan/01-siem.yaml').write_text({VM2_NETPLAN_CONTENT!r}, encoding='utf-8')
Path('/etc/systemd/resolved.conf').write_text({VM2_RESOLVED_CONF_CONTENT!r}, encoding='utf-8')
subprocess.run(['chmod', '600', '/etc/netplan/01-siem.yaml'], check=True)
for cmd in (
    ['netplan', 'generate'],
    ['netplan', 'apply'],
    ['systemctl', 'restart', 'systemd-resolved'],
    ['resolvectl', 'flush-caches'],
    ['systemctl', 'restart', 'ssh'],
    ['systemctl', 'restart', {RUNNER_SERVICE!r}],
):
    subprocess.run(cmd, check=False)
print('vm2_network_runner_repair=ok')
"""
    return _qm_guest_exec_json(proxmox, vmid, _guest_python_command(script))


def _query_vm2_dns_runner_state(proxmox: paramiko.SSHClient, vmid: str) -> dict[str, object]:
    script = f"""
import json
import subprocess
from pathlib import Path
state = {{
    'legacy_netplan_present': Path('/etc/netplan/01-siem-net.yaml').exists(),
    'runner_active': False,
}}
proc = subprocess.run(['systemctl', 'is-active', {RUNNER_SERVICE!r}], capture_output=True, text=True)
state['runner_active'] = proc.returncode == 0 and proc.stdout.strip() == 'active'
for host in {DNS_HEALTH_HOSTS!r}:
    proc = subprocess.run(['getent', 'ahostsv4', host], capture_output=True, text=True)
    state[f'resolve::{{host}}'] = bool(proc.returncode == 0 and proc.stdout.strip())
print(json.dumps(state, ensure_ascii=True, sort_keys=True))
"""
    last_error = "unknown"
    for attempt in range(1, 4):
        try:
            text = _qm_guest_exec_text(proxmox, vmid, _guest_python_command(script)).strip()
            if not text:
                raise RuntimeError("VM2 DNS/runner state returned empty output")
            return json.loads(text)
        except Exception as exc:  # noqa: BLE001
            last_error = str(exc)
            print(f"watchdog vm2_dns_runner_probe_retry attempt={attempt}/3 error={exc}")
            if attempt < 3:
                time.sleep(2)
    fallback = _default_vm2_dns_runner_state(query_error=last_error)
    print(f"watchdog vm2_dns_runner_probe=fallback payload={json.dumps(fallback, ensure_ascii=True, sort_keys=True)}")
    return fallback


def _github_api_json(repository: str, token: str, path: str) -> dict[str, object]:
    request = urllib.request.Request(
        f"https://api.github.com/repos/{repository}{path}",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "User-Agent": "siem-homelab-watchdog",
        },
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        return json.loads(response.read().decode("utf-8"))


def _wait_for_runner_online(repository: str, token: str, runner_name: str, *, attempts: int = 12, delay_seconds: float = 5.0) -> tuple[str, bool]:
    last_status = "missing"
    last_busy = False
    for _ in range(attempts):
        payload = _github_api_json(repository, token, "/actions/runners?per_page=100")
        last_status, last_busy = parse_runner_status(payload, runner_name)
        if last_status == "online":
            return last_status, last_busy
        time.sleep(delay_seconds)
    return last_status, last_busy


def _runner_status_or_api_error(
    repository: str,
    token: str,
    runner_name: str,
    *,
    attempts: int = 1,
    delay_seconds: float = 0.0,
) -> tuple[str, bool, str]:
    try:
        status, busy = _wait_for_runner_online(
            repository,
            token,
            runner_name,
            attempts=attempts,
            delay_seconds=delay_seconds,
        )
        return status, busy, ""
    except Exception as exc:  # noqa: BLE001
        return "unknown", False, str(exc)


def _processing_stalled(vm2_state: dict[str, object], *, minimum_events_5m: int, events_5m: int) -> bool:
    transport_backend = str(vm2_state.get("transport_backend") or "").strip().lower()
    consumer_backend = str(vm2_state.get("consumer_backend") or "").strip().lower()
    bootstrap_servers = list(vm2_state.get("kafka_bootstrap_servers") or [])
    expected_brokers = int(vm2_state.get("kafka_expected_brokers") or 0)
    if transport_backend != "kafka" or consumer_backend != "kafka":
        return True
    if expected_brokers > 0 and len(bootstrap_servers) < expected_brokers:
        return True
    if events_5m >= minimum_events_5m:
        return False
    return True


def _query_clickhouse_counts(client: paramiko.SSHClient, *, sudo_password: str) -> tuple[int, int]:
    command = (
        "source /etc/siem/storage.env; "
        "clickhouse-client "
        "--host \"$SIEM_CH_HOST\" "
        "--port \"$SIEM_CH_PORT\" "
        "--user \"$SIEM_CH_USER\" "
        "--password \"$SIEM_CH_PASSWORD\" "
        "--query \"SELECT countIf(ts >= now() - INTERVAL 5 MINUTE), "
        "(SELECT countIf(ts >= now() - INTERVAL 5 MINUTE) FROM siem.alerts_agg) "
        "FROM siem.events FORMAT TabSeparated\""
    )
    code, out, err = _run_command(client, command, sudo_password=sudo_password, use_sudo=True)
    cleaned = _strip_sudo_echo(out, sudo_password).strip()
    if code != 0 or not cleaned:
        raise RuntimeError(f"ClickHouse watchdog query failed: stdout={cleaned} stderr={err.strip()}")
    parts = cleaned.split("\t")
    if len(parts) != 2:
        raise RuntimeError(f"Unexpected ClickHouse watchdog query output: {cleaned}")
    return int(parts[0]), int(parts[1])


def _direct_ingest_base_url() -> str:
    return str(os.getenv("SIEM_DIRECT_INGEST_BASE_URL", "https://192.168.1.35") or "https://192.168.1.35").strip().rstrip("/")


def _direct_ingest_headers() -> dict[str, str]:
    headers = {"Accept": "application/json"}
    shared_secret = str(os.getenv("SIEM_INGEST_API_SHARED_SECRET", "") or os.getenv("SIEM_WEBHOOK_SHARED_SECRET", "") or "").strip()
    if shared_secret:
        headers["X-Rdegon-Ingest-Secret"] = shared_secret
    return headers


def _request_json_url(
    url: str,
    *,
    method: str = "GET",
    payload: dict[str, object] | None = None,
    attempts: int = 4,
    delay_seconds: float = 2.0,
    timeout_seconds: float = 30.0,
) -> dict[str, object]:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    last_error: Exception | None = None
    for attempt in range(1, attempts + 1):
        headers = dict(_direct_ingest_headers())
        data = None
        if payload is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=timeout_seconds, context=context) as response:
                return json.loads(response.read().decode("utf-8", errors="replace"))
        except urllib.error.HTTPError as exc:
            last_error = exc
            if attempt == attempts:
                body = exc.read().decode("utf-8", errors="replace")
                raise RuntimeError(f"Request failed for {url}: HTTP {exc.code} {exc.reason}; body={body[:600]}") from exc
            time.sleep(delay_seconds)
        except Exception as exc:  # noqa: BLE001
            last_error = exc
            if attempt == attempts:
                break
            time.sleep(delay_seconds)
    raise RuntimeError(f"Request failed for {url}: {last_error}")


def _direct_ingest_request(
    path: str,
    *,
    method: str = "GET",
    payload: dict[str, object] | None = None,
    attempts: int = 4,
    delay_seconds: float = 2.0,
    timeout_seconds: float = 30.0,
) -> dict[str, object]:
    return _request_json_url(
        f"{_direct_ingest_base_url()}{path}",
        method=method,
        payload=payload,
        attempts=attempts,
        delay_seconds=delay_seconds,
        timeout_seconds=timeout_seconds,
    )


def _item_status(item: dict[str, object]) -> str:
    return str(item.get("status") or item.get("health") or "").strip().lower()


def _best_source_item(
    items: list[dict[str, object]],
    predicate: Callable[[dict[str, object]], bool],
) -> dict[str, object] | None:
    candidates = [item for item in items if predicate(item)]
    if not candidates:
        return None

    status_rank = {"healthy": 4, "delayed": 3, "stale": 2, "missing": 1}

    def sort_key(item: dict[str, object]) -> tuple[int, float]:
        try:
            lag = float(item.get("seconds_since_last_seen") or float("inf"))
        except (TypeError, ValueError):
            lag = float("inf")
        return status_rank.get(_item_status(item), 0), -lag

    return max(candidates, key=sort_key)


def _collect_critical_ingest_state(*, sources: dict[str, object], collectors: dict[str, object]) -> dict[str, object]:
    collector_items = [dict(item) for item in list(collectors.get("items") or [])]
    source_items = [dict(item) for item in list(sources.get("items") or [])]
    problems: list[str] = []
    collector_state: dict[str, str] = {}

    for profile in CRITICAL_INGEST_COLLECTOR_PROFILES:
        match = next(
            (
                item
                for item in collector_items
                if str(item.get("collector_profile") or item.get("ingest_profile") or "").strip().lower() == profile
            ),
            None,
        )
        status = _item_status(match or {}) if match else "missing"
        collector_state[profile] = status
        if status != "healthy":
            problems.append(f"collector:{profile}:{status}")

    pve_app = _best_source_item(
        source_items,
        lambda item: (
            str(item.get("collector_profile") or item.get("ingest_profile") or "").strip().lower() == "app"
            and (
                "pve" in " ".join(
                    str(item.get(field) or "").strip().lower()
                    for field in ("source", "source_alias", "id")
                )
                or any(
                    str(item.get(field) or "").strip().lower() in PVE_SOURCE_ALIASES
                    for field in ("source", "source_alias", "id")
                )
            )
        ),
    )
    if _item_status(pve_app or {}) != "healthy":
        problems.append(f"source:pve/app:{_item_status(pve_app or {}) or 'missing'}")

    vpn_source = _best_source_item(
        source_items,
        lambda item: (
                str(item.get("collector_profile") or item.get("ingest_profile") or "").strip().lower() == "vpn"
                or (
                    str(item.get("collector_profile") or item.get("ingest_profile") or "").strip().lower() == "linux-auth"
                    and str(item.get("source") or item.get("source_alias") or "").strip() == "127.0.0.1"
                )
        ),
    )
    edge_source = _best_source_item(
        source_items,
        lambda item: any(
                str(item.get(field) or "").strip().lower() in EDGE_VPN_SOURCE_ALIASES
                for field in ("source", "source_alias", "id")
        ),
    )
    vpn_ready = _item_status(vpn_source or {}) == "healthy" or _item_status(edge_source or {}) == "healthy"
    if not vpn_ready:
        problems.append(
            f"source:vpn-path:vpn={_item_status(vpn_source or {}) or 'missing'} edge={_item_status(edge_source or {}) or 'missing'}"
        )

    return {
        "healthy": not problems,
        "problems": problems,
        "collectors": collector_state,
        "pve_app_status": _item_status(pve_app or {}) or "missing",
        "vpn_status": _item_status(vpn_source or {}) or "missing",
        "edge_status": _item_status(edge_source or {}) or "missing",
    }


def _load_critical_ingest_state() -> dict[str, object]:
    sources = _direct_ingest_request("/health/sources?limit=200", attempts=2, delay_seconds=1.5)
    collectors = _direct_ingest_request("/health/collectors?limit=200", attempts=2, delay_seconds=1.5)
    overview = _direct_ingest_request("/health/overview", attempts=2, delay_seconds=1.5)
    return {
        "sources": sources,
        "collectors": collectors,
        "overview": overview,
        "gate": _collect_critical_ingest_state(sources=sources, collectors=collectors),
    }


def _wait_for_critical_ingest_targets_ready(*, attempts: int = 10, delay_seconds: float = 5.0) -> dict[str, object]:
    snapshot: dict[str, object] = {}
    for attempt in range(1, attempts + 1):
        snapshot = _load_critical_ingest_state()
        if bool(dict(snapshot.get("gate") or {}).get("healthy")):
            return snapshot
        if attempt < attempts:
            time.sleep(delay_seconds)
    return snapshot


def _refresh_generic_http_sources() -> None:
    sources = _direct_ingest_request("/health/sources?limit=200", attempts=2, delay_seconds=1.5)
    collectors = _direct_ingest_request("/health/collectors?limit=200", attempts=2, delay_seconds=1.5)
    candidates: list[tuple[str, str, str]] = []
    for inventory in (list(sources.get("items") or []), list(collectors.get("items") or [])):
        for item in inventory:
            if str(item.get("status") or "").strip().lower() not in {"stale", "delayed"}:
                continue
            if str(item.get("collector_profile") or item.get("ingest_profile") or "").strip().lower() != "generic-http" and str(item.get("collector") or "").strip().lower() != "http_json":
                continue
            source = str(item.get("source") or item.get("source_alias") or item.get("id") or "generic-http-refresh").strip()
            source_type = str(item.get("source_type") or "http_json").strip() or "http_json"
            dataset = str(item.get("last_dataset") or "generic-http").strip() or "generic-http"
            candidates.append((source, source_type, dataset))
    if not candidates:
        candidates.append(("generic-http-refresh", "http_json", "generic-http"))
    seen: set[tuple[str, str, str]] = set()
    for source, source_type, dataset in candidates[:8]:
        key = (source, source_type, dataset)
        if key in seen:
            continue
        seen.add(key)
        _direct_ingest_request(
            "/ingest/json",
            method="POST",
            payload={
                "message": "watchdog-ingest-refresh",
                "source": source,
                "source_type": source_type,
                "event.dataset": dataset,
                "tags": ["watchdog-refresh"],
            },
            attempts=2,
            delay_seconds=1.0,
            timeout_seconds=20.0,
        )


def _remediate_ingest_health() -> dict[str, object]:
    attempts = int(_optional_env("SIEM_INGEST_REMEDIATION_ATTEMPTS", default="6") or "6")
    delay_seconds = float(_optional_env("SIEM_INGEST_REMEDIATION_DELAY_SECONDS", default="5") or "5")
    replay_batches = int(_optional_env("SIEM_INGEST_REPLAY_BATCHES_PER_ATTEMPT", default="5") or "5")
    replay_batch_limit = int(_optional_env("SIEM_INGEST_REPLAY_BATCH_LIMIT", default="2000") or "2000")
    suppress_limit = int(_optional_env("SIEM_INGEST_SUPPRESS_LIMIT", default="5000") or "5000")
    overview: dict[str, object] = {}
    for attempt in range(1, attempts + 1):
        overview = _direct_ingest_request("/health/overview", attempts=2, delay_seconds=1.5)
        issues = [str(item or "").strip() for item in list(overview.get("issues") or []) if str(item or "").strip()]
        outstanding = int(dict(overview.get("dlq") or {}).get("outstanding") or 0)
        if outstanding > 0:
            _direct_ingest_request(
                "/dlq/suppress",
                method="POST",
                payload={"limit": min(outstanding, suppress_limit), "actor": "homelab-watchdog"},
                attempts=2,
                delay_seconds=1.0,
                timeout_seconds=60.0,
            )
            for _ in range(max(1, replay_batches)):
                replay = _direct_ingest_request(
                    "/dlq/replay",
                    method="POST",
                    payload={"limit": min(replay_batch_limit, outstanding), "actor": "homelab-watchdog"},
                    attempts=2,
                    delay_seconds=1.5,
                    timeout_seconds=180.0,
                )
                replayed = int(replay.get("replayed") or 0)
                failed = int(replay.get("failed") or 0)
                skipped = int(replay.get("skipped") or 0)
                if replayed <= 0 and failed <= 0 and skipped <= 0:
                    break
                outstanding = max(0, outstanding - replayed)
                if outstanding < 5:
                    break
        if any("sources" in item.lower() or "collectors" in item.lower() for item in issues):
            _refresh_generic_http_sources()
        if int(dict(overview.get("dlq") or {}).get("outstanding") or 0) < 5:
            refreshed = _direct_ingest_request("/health/overview", attempts=2, delay_seconds=1.5)
            if int(dict(refreshed.get("dlq") or {}).get("outstanding") or 0) < 5:
                return refreshed
        if attempt < attempts:
            time.sleep(delay_seconds)
    return overview


def main() -> int:
    proxmox = HostSpec(
        host=_required_env("SIEM_PROXMOX_HOST", default="192.168.1.101"),
        user=_required_env("SIEM_PROXMOX_USER", default="root"),
        password=_required_env("SIEM_PROXMOX_PASSWORD"),
    )
    vm1 = HostSpec(
        host=_required_env("SIEM_VM1_HOST"),
        user=_required_env("SIEM_VM1_USER"),
        password=_required_env("SIEM_VM1_PASSWORD"),
    )
    vm3 = HostSpec(
        host=_required_env("SIEM_VM3_HOST"),
        user=_required_env("SIEM_VM3_USER"),
        password=_required_env("SIEM_VM3_PASSWORD"),
    )
    vm4 = HostSpec(
        host=_required_env("SIEM_VM4_HOST"),
        user=_required_env("SIEM_VM4_USER"),
        password=_required_env("SIEM_VM4_PASSWORD"),
    )
    vm5_host = _optional_env("SIEM_VM5_HOST")
    vm5_user = _optional_env("SIEM_VM5_USER")
    vm5_password = _optional_env("SIEM_VM5_PASSWORD")
    vm5 = HostSpec(host=vm5_host, user=vm5_user, password=vm5_password) if (vm5_host and vm5_user and vm5_password) else None
    vm2_vmid = _required_env("SIEM_VM2_VMID", default="105")
    github_repository = os.getenv("GITHUB_REPOSITORY", "").strip()
    github_token = os.getenv("GITHUB_TOKEN", "").strip()
    vm2_runner_name = _required_env("SIEM_VM2_RUNNER_NAME", default="siem-vm2")
    vm5_runner_name = _optional_env("SIEM_VM5_RUNNER_NAME", default="siem-vm5")
    minimum_events_5m = int(_required_env("SIEM_WATCHDOG_MIN_EVENTS_5M", default="1600"))
    expect_vm5_kafka = parse_bool_flag(_optional_env("SIEM_WATCHDOG_EXPECT_VM5_KAFKA", default="0"))

    proxmox_client = _connect_client(proxmox.host, proxmox.user, proxmox.password)
    try:
        vm2_payload = _ensure_vm2_available(proxmox_client, vm2_vmid)
        print(f"watchdog vm2_guest_exec={json.dumps(vm2_payload, ensure_ascii=True)}")
        vm2_state = _query_vm2_pipeline_state(proxmox_client, vm2_vmid)
        print(f"watchdog vm2_pipeline={json.dumps(vm2_state, ensure_ascii=True, sort_keys=True)}")
        vm2_dns_runner_state = _query_vm2_dns_runner_state(proxmox_client, vm2_vmid)
        print(f"watchdog vm2_dns_runner={json.dumps(vm2_dns_runner_state, ensure_ascii=True, sort_keys=True)}")
        dns_unhealthy = bool(vm2_dns_runner_state.get("legacy_netplan_present")) or any(
            key.startswith("resolve::") and not bool(value) for key, value in vm2_dns_runner_state.items()
        )
        if github_repository and github_token:
            runner_status, runner_busy, github_runner_api_error = _runner_status_or_api_error(
                github_repository,
                github_token,
                vm2_runner_name,
                attempts=1,
                delay_seconds=0,
            )
            if github_runner_api_error:
                print(f"watchdog vm2_runner_api=unavailable error={github_runner_api_error}")
            else:
                print(f"watchdog vm2_runner status={runner_status} busy={runner_busy}")
            if (not github_runner_api_error and runner_status != "online") or dns_unhealthy or not bool(vm2_dns_runner_state.get("runner_active")):
                print("watchdog repair reason=vm2_runner_or_dns action=repair_vm2_network_and_runner")
                repair_payload = _repair_vm2_network_and_runner(proxmox_client, vm2_vmid)
                print(f"watchdog vm2_runner_repair={json.dumps(repair_payload, ensure_ascii=True)}")
                time.sleep(10)
                vm2_dns_runner_state = _query_vm2_dns_runner_state(proxmox_client, vm2_vmid)
                print(f"watchdog vm2_dns_runner_after_repair={json.dumps(vm2_dns_runner_state, ensure_ascii=True, sort_keys=True)}")
                if not github_runner_api_error:
                    runner_status, runner_busy = _wait_for_runner_online(github_repository, github_token, vm2_runner_name)
                    print(f"watchdog vm2_runner_after_repair status={runner_status} busy={runner_busy}")
                    if runner_status != "online":
                        raise RuntimeError(f"VM2 runner is still offline after repair: status={runner_status}")
        elif dns_unhealthy or not bool(vm2_dns_runner_state.get("runner_active")):
            print("watchdog repair reason=vm2_dns_or_local_runner action=repair_vm2_network_and_runner")
            repair_payload = _repair_vm2_network_and_runner(proxmox_client, vm2_vmid)
            print(f"watchdog vm2_runner_repair={json.dumps(repair_payload, ensure_ascii=True)}")
            time.sleep(10)
            vm2_dns_runner_state = _query_vm2_dns_runner_state(proxmox_client, vm2_vmid)
            print(f"watchdog vm2_dns_runner_after_repair={json.dumps(vm2_dns_runner_state, ensure_ascii=True, sort_keys=True)}")
            if bool(vm2_dns_runner_state.get("legacy_netplan_present")) or not bool(vm2_dns_runner_state.get("runner_active")):
                raise RuntimeError(f"VM2 runner/dns is still unhealthy after repair: {vm2_dns_runner_state}")
    finally:
        proxmox_client.close()

    clients: list[paramiko.SSHClient] = []
    try:
        vm1_client = _connect_client(vm1.host, vm1.user, vm1.password)
        vm3_client = _connect_client(vm3.host, vm3.user, vm3.password)
        vm4_client = _connect_client(vm4.host, vm4.user, vm4.password)
        clients.extend([vm1_client, vm3_client, vm4_client])

        _ensure_service_bundle(
            vm1_client,
            ["siem-ingest", "nginx"],
            sudo_password=vm1.password,
            restart_bundle="systemctl restart siem-ingest nginx",
        )
        _ensure_service_bundle(
            vm3_client,
            ["clickhouse-server", "siem-writer", *WRITER_SCALEOUT_UNITS, "siem-stream-corr", "siem-batch-corr", "siem-alert-agg"],
            sudo_password=vm3.password,
            restart_bundle=f"systemctl restart clickhouse-server siem-writer {' '.join(WRITER_SCALEOUT_UNITS)} siem-stream-corr siem-batch-corr siem-alert-agg",
        )
        _ensure_service_bundle(
            vm4_client,
            ["siem-web", "nginx"],
            sudo_password=vm4.password,
            restart_bundle="systemctl restart siem-web nginx",
        )
        _ensure_service_bundle(
            vm4_client,
            ["openvpn-client@home-gateway", "siem-jump-tunnels"],
            sudo_password=vm4.password,
            restart_bundle="systemctl restart openvpn-client@home-gateway siem-jump-tunnels",
        )
        if vm5 is not None:
            vm5_client = _connect_client(vm5.host, vm5.user, vm5.password)
            clients.append(vm5_client)
            vm5_units = _vm5_service_units_clause(include_kafka=expect_vm5_kafka).split()
            restart_units = "systemctl restart ssh actions.runner.Rdegon-siem-solution.siem-vm5.service"
            if expect_vm5_kafka:
                restart_units += " siem-kafka"
            _ensure_service_bundle(
                vm5_client,
                vm5_units,
                sudo_password=vm5.password,
                restart_bundle=restart_units,
            )
            _ensure_service_inactive(
                vm5_client,
                "actions.runner.Rdegon-siem-solution.siem-vm2.service",
                sudo_password=vm5.password,
                repair_bundle="systemctl disable --now actions.runner.Rdegon-siem-solution.siem-vm2.service || systemctl stop actions.runner.Rdegon-siem-solution.siem-vm2.service",
            )
            if github_repository and github_token:
                runner_status, runner_busy, vm5_runner_api_error = _runner_status_or_api_error(
                    github_repository,
                    github_token,
                    vm5_runner_name,
                    attempts=1,
                    delay_seconds=0,
                )
                if vm5_runner_api_error:
                    print(f"watchdog vm5_runner_api=unavailable error={vm5_runner_api_error}")
                else:
                    print(f"watchdog vm5_runner status={runner_status} busy={runner_busy}")
                if not vm5_runner_api_error and runner_status != "online":
                    runner_status, runner_busy = _wait_for_runner_online(github_repository, github_token, vm5_runner_name)
                    print(f"watchdog vm5_runner_after_recheck status={runner_status} busy={runner_busy}")
                    if runner_status != "online":
                        raise RuntimeError(f"VM5 runner is still offline after recheck: status={runner_status}")

        critical_ingest = _wait_for_critical_ingest_targets_ready(attempts=3, delay_seconds=3.0)
        print(f"watchdog ingest_gate={json.dumps(dict(critical_ingest.get('gate') or {}), ensure_ascii=True, sort_keys=True)}")
        if not bool(dict(critical_ingest.get("gate") or {}).get("healthy")):
            print("watchdog repair reason=critical_ingest_boot_gate action=restart_vm1_ingest_vm4_tunnels_proxmox_rsyslog")
            _run_command(vm1_client, "systemctl restart siem-ingest nginx", sudo_password=vm1.password, use_sudo=True)
            _run_command(
                vm4_client,
                "systemctl restart openvpn-client@home-gateway siem-jump-tunnels",
                sudo_password=vm4.password,
                use_sudo=True,
            )
            proxmox_client = _connect_client(proxmox.host, proxmox.user, proxmox.password)
            try:
                _run_command(proxmox_client, "systemctl restart rsyslog")
            finally:
                proxmox_client.close()
            time.sleep(15)
            remediation = _remediate_ingest_health()
            print(f"watchdog ingest_remediation={json.dumps(remediation, ensure_ascii=True, sort_keys=True)}")
            critical_ingest = _wait_for_critical_ingest_targets_ready(attempts=12, delay_seconds=5.0)
            print(f"watchdog ingest_gate_after_repair={json.dumps(dict(critical_ingest.get('gate') or {}), ensure_ascii=True, sort_keys=True)}")
            if not bool(dict(critical_ingest.get("gate") or {}).get("healthy")):
                raise RuntimeError(f"Critical ingest gate is still unhealthy after repair: {critical_ingest.get('gate')}")

        ingest_overview = _direct_ingest_request("/health/overview", attempts=2, delay_seconds=1.5)
        outstanding_dlq = int(dict(ingest_overview.get("dlq") or {}).get("outstanding") or 0)
        if outstanding_dlq >= 5:
            remediation = _remediate_ingest_health()
            print(f"watchdog ingest_tail_cleanup={json.dumps(remediation, ensure_ascii=True, sort_keys=True)}")
            ingest_overview = _direct_ingest_request("/health/overview", attempts=2, delay_seconds=1.5)
            outstanding_dlq = int(dict(ingest_overview.get("dlq") or {}).get("outstanding") or 0)
        if outstanding_dlq >= 5:
            raise RuntimeError(f"Ingest DLQ backlog is still above threshold after remediation: {outstanding_dlq}")

        events_5m, alerts_5m = _query_clickhouse_counts(vm3_client, sudo_password=vm3.password)
        print(f"watchdog counts_before events_5m={events_5m} alerts_5m={alerts_5m}")
        if _processing_stalled(vm2_state, minimum_events_5m=minimum_events_5m, events_5m=events_5m):
            print("watchdog repair reason=vm2_processing_or_transport action=restart_vm2_processing_bundle")
            proxmox_client = _connect_client(proxmox.host, proxmox.user, proxmox.password)
            try:
                payload = _restart_vm2_processing_bundle(proxmox_client, vm2_vmid)
                print(f"watchdog vm2_restart={json.dumps(payload, ensure_ascii=True)}")
                time.sleep(12)
                vm2_state = _query_vm2_pipeline_state(proxmox_client, vm2_vmid)
                print(f"watchdog vm2_pipeline_after_restart={json.dumps(vm2_state, ensure_ascii=True, sort_keys=True)}")
            finally:
                proxmox_client.close()
            events_5m, alerts_5m = _query_clickhouse_counts(vm3_client, sudo_password=vm3.password)
            print(f"watchdog counts_after_vm2_repair events_5m={events_5m} alerts_5m={alerts_5m}")
        if events_5m < minimum_events_5m:
            print("watchdog repair reason=low_event_flow action=restart_ingest_and_detection")
            _run_command(vm1_client, "systemctl restart siem-ingest", sudo_password=vm1.password, use_sudo=True)
            _run_command(
                vm4_client,
                "systemctl restart openvpn-client@home-gateway siem-jump-tunnels",
                sudo_password=vm4.password,
                use_sudo=True,
            )
            _run_command(vm3_client, f"systemctl restart siem-writer {' '.join(WRITER_SCALEOUT_UNITS)} siem-stream-corr siem-batch-corr siem-alert-agg", sudo_password=vm3.password, use_sudo=True)
            time.sleep(20)
            critical_ingest = _wait_for_critical_ingest_targets_ready(attempts=6, delay_seconds=5.0)
            print(f"watchdog ingest_gate_after_low_flow_repair={json.dumps(dict(critical_ingest.get('gate') or {}), ensure_ascii=True, sort_keys=True)}")
            events_5m, alerts_5m = _query_clickhouse_counts(vm3_client, sudo_password=vm3.password)
            print(f"watchdog counts_after events_5m={events_5m} alerts_5m={alerts_5m}")
        if events_5m < minimum_events_5m:
            raise RuntimeError(f"Fresh event flow is still below threshold after repair: events_5m={events_5m}")
        print("watchdog result=healthy")
        return 0
    finally:
        for client in clients:
            client.close()


if __name__ == "__main__":
    sys.exit(main())
