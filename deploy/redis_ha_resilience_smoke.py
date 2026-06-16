from __future__ import annotations

import json
import os
import re
import shlex
import sys
import time
from pathlib import Path

import paramiko

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from deploy.vm2_processing_resilience_deploy import PROCESSING_SERVICE_UNITS, RUNNER_SERVICE


def _required_env(name: str, *, default: str | None = None) -> str:
    value = str(os.getenv(name, default or "") or "").strip()
    if value:
        return value
    raise SystemExit(f"Missing required environment variable: {name}")


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
        line = re.sub(r"^\[sudo\] password for [^:]+:\s*", "", line)
        cleaned_lines.append(line)
    return "\n".join(cleaned_lines)


def _service_states(
    client: paramiko.SSHClient,
    services: list[str],
    *,
    sudo_password: str,
    attempts: int = 15,
    delay_seconds: float = 2.0,
) -> list[str]:
    last_states: list[str] = []
    last_err = ""
    for _ in range(max(1, attempts)):
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
    raise RuntimeError(f"Unexpected service state for {services}: stdout={last_states} stderr={last_err}")


def _load_env(client: paramiko.SSHClient, path: str, *, sudo_password: str) -> dict[str, str]:
    command = (
        "python3 - <<'PY'\n"
        "from pathlib import Path\n"
        "payload = {}\n"
        f"for raw_line in Path({path!r}).read_text(encoding='utf-8').splitlines():\n"
        "    line = raw_line.strip()\n"
        "    if not line or line.startswith('#') or '=' not in line:\n"
        "        continue\n"
        "    key, value = line.split('=', 1)\n"
        "    payload[key.strip()] = value.strip()\n"
        "print(__import__('json').dumps(payload, ensure_ascii=True, sort_keys=True))\n"
        "PY"
    )
    code, out, err = _run_command(client, command, sudo_password=sudo_password, use_sudo=True)
    cleaned = _strip_sudo_echo(out, sudo_password).strip()
    if code != 0 or not cleaned:
        raise RuntimeError(f"Unable to read env file {path}: stdout={cleaned} stderr={err.strip()}")
    return json.loads(cleaned)


def _query_sentinel_master(
    client: paramiko.SSHClient,
    *,
    sudo_password: str,
    master_name: str,
    sentinel_port: int,
) -> dict[str, str]:
    command = (
        "python3 - <<'PY'\n"
        "import json, subprocess\n"
        f"proc = subprocess.run(['redis-cli', '-p', {str(sentinel_port)!r}, '--raw', 'SENTINEL', 'master', {master_name!r}], capture_output=True, text=True)\n"
        "if proc.returncode != 0:\n"
        "    raise SystemExit(proc.stderr.strip() or 'redis-cli sentinel master failed')\n"
        "lines = [line.strip() for line in proc.stdout.splitlines() if line.strip()]\n"
        "payload = {}\n"
        "for index in range(0, len(lines), 2):\n"
        "    key = lines[index]\n"
        "    value = lines[index + 1] if index + 1 < len(lines) else ''\n"
        "    payload[key] = value\n"
        "print(json.dumps(payload, ensure_ascii=True, sort_keys=True))\n"
        "PY"
    )
    code, out, err = _run_command(client, command)
    cleaned = out.strip()
    if code != 0 or not cleaned:
        raise RuntimeError(f"Unable to query Sentinel master view: stdout={cleaned} stderr={err.strip()}")
    return json.loads(cleaned)


def _query_replication(
    client: paramiko.SSHClient,
    *,
    sudo_password: str,
    host: str,
    port: int,
    password: str,
) -> dict[str, str]:
    command = (
        "python3 - <<'PY'\n"
        "import json, subprocess\n"
        f"cmd = ['redis-cli', '-h', {host!r}, '-p', {str(port)!r}, '--raw']\n"
        f"password = {password!r}\n"
        "if password:\n"
        "    cmd.extend(['-a', password])\n"
        "cmd.extend(['INFO', 'replication'])\n"
        "proc = subprocess.run(cmd, capture_output=True, text=True)\n"
        "if proc.returncode != 0:\n"
        "    raise SystemExit(proc.stderr.strip() or 'redis-cli INFO replication failed')\n"
        "payload = {}\n"
        "for raw_line in proc.stdout.splitlines():\n"
        "    line = raw_line.strip()\n"
        "    if not line or line.startswith('#') or ':' not in line:\n"
        "        continue\n"
        "    key, value = line.split(':', 1)\n"
        "    payload[key.strip()] = value.strip()\n"
        "print(json.dumps(payload, ensure_ascii=True, sort_keys=True))\n"
        "PY"
    )
    code, out, err = _run_command(client, command)
    cleaned = out.strip()
    if code != 0 or not cleaned:
        raise RuntimeError(f"Unable to query Redis replication info from {host}:{port}: stdout={cleaned} stderr={err.strip()}")
    return json.loads(cleaned)


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
        raise RuntimeError(f"ClickHouse flow query failed: stdout={cleaned} stderr={err.strip()}")
    events_text, alerts_text = cleaned.split("\t", 1)
    return int(events_text), int(alerts_text)


def main() -> int:
    vm1_host = _required_env("SIEM_VM1_HOST")
    vm1_user = _required_env("SIEM_VM1_USER")
    vm1_password = _required_env("SIEM_VM1_PASSWORD")
    vm2_host = _required_env("SIEM_VM2_HOST", default="192.168.1.37")
    vm2_user = _required_env("SIEM_VM2_USER", default="rdegon")
    vm2_password = _required_env("SIEM_VM2_PASSWORD")
    vm3_host = _required_env("SIEM_VM3_HOST")
    vm3_user = _required_env("SIEM_VM3_USER")
    vm3_password = _required_env("SIEM_VM3_PASSWORD")
    vm4_host = _required_env("SIEM_VM4_HOST")
    vm4_user = _required_env("SIEM_VM4_USER")
    vm4_password = _required_env("SIEM_VM4_PASSWORD")
    master_name = _required_env("SIEM_REDIS_SENTINEL_MASTER", default="siem-master")
    sentinel_port = int(_required_env("SIEM_REDIS_SENTINEL_PORT", default="26379"))

    vm1 = _connect_client(vm1_host, vm1_user, vm1_password)
    vm2 = _connect_client(vm2_host, vm2_user, vm2_password)
    vm3 = _connect_client(vm3_host, vm3_user, vm3_password)
    vm4 = _connect_client(vm4_host, vm4_user, vm4_password)
    try:
        _service_states(vm1, ["siem-ingest", "nginx"], sudo_password=vm1_password)
        print("vm1_services=ok")
        _service_states(
            vm2,
            ["redis-server", "siem-redis-sentinel", *PROCESSING_SERVICE_UNITS, "ssh", RUNNER_SERVICE],
            sudo_password=vm2_password,
        )
        print("vm2_services=ok")
        _service_states(
            vm3,
            ["redis-server", "siem-redis-sentinel", "clickhouse-server", "siem-writer", "siem-stream-corr"],
            sudo_password=vm3_password,
        )
        print("vm3_services=ok")
        _service_states(vm4, ["siem-redis-sentinel", "siem-web", "nginx"], sudo_password=vm4_password)
        print("vm4_services=ok")

        ingest_env = _load_env(vm1, "/etc/siem/ingest.env", sudo_password=vm1_password)
        processing_env = _load_env(vm2, "/etc/siem/processing.env", sudo_password=vm2_password)
        storage_env = _load_env(vm3, "/etc/siem/storage.env", sudo_password=vm3_password)
        for payload in (ingest_env, processing_env, storage_env):
            if payload.get("SIEM_REDIS_SENTINEL_ENABLED", "").lower() != "true":
                raise RuntimeError("Redis sentinel is not enabled in one of the live env files")
            if payload.get("SIEM_REDIS_SENTINEL_MASTER") != master_name:
                raise RuntimeError("Unexpected Redis sentinel master name in live env file")
            if not payload.get("SIEM_REDIS_SENTINEL_NODES"):
                raise RuntimeError("Missing Redis sentinel nodes in live env file")
        print("live_envs=ok")

        vm2_sentinel = _query_sentinel_master(vm2, sudo_password=vm2_password, master_name=master_name, sentinel_port=sentinel_port)
        vm3_sentinel = _query_sentinel_master(vm3, sudo_password=vm3_password, master_name=master_name, sentinel_port=sentinel_port)
        vm4_sentinel = _query_sentinel_master(vm4, sudo_password=vm4_password, master_name=master_name, sentinel_port=sentinel_port)
        sentinel_views = (vm2_sentinel, vm3_sentinel, vm4_sentinel)
        master_ips = {payload.get("ip", "") for payload in sentinel_views}
        master_ports = {payload.get("port", "") for payload in sentinel_views}
        if len(master_ips) != 1 or master_ports != {"6379"}:
            raise RuntimeError(f"Sentinel master views are inconsistent: ips={master_ips} ports={master_ports}")
        active_master_ip = next(iter(master_ips))
        if active_master_ip not in {vm2_host, vm3_host}:
            raise RuntimeError(f"Sentinel elected an unexpected Redis master host: {active_master_ip}")
        for payload in sentinel_views:
            if int(payload.get("num-slaves", "0") or 0) < 1:
                raise RuntimeError(f"Sentinel does not see a replica: {payload}")
        print(f"sentinel_quorum=ok active_master={active_master_ip}")

        redis_password = processing_env.get("SIEM_REDIS_PASSWORD", "")
        vm2_replication = _query_replication(
            vm2,
            sudo_password=vm2_password,
            host=vm2_host,
            port=6379,
            password=redis_password,
        )
        vm3_replication = _query_replication(
            vm3,
            sudo_password=vm3_password,
            host=vm3_host,
            port=6379,
            password=redis_password,
        )
        replication_by_host = {
            vm2_host: vm2_replication,
            vm3_host: vm3_replication,
        }
        active_master = replication_by_host[active_master_ip]
        replica_host = vm3_host if active_master_ip == vm2_host else vm2_host
        active_replica = replication_by_host[replica_host]
        if active_master.get("role") != "master":
            raise RuntimeError(f"Sentinel elected {active_master_ip}, but Redis role disagrees: {active_master}")
        if int(active_master.get("connected_slaves", "0") or 0) < 1:
            raise RuntimeError(f"Redis master does not report a connected replica: {active_master}")
        if active_replica.get("role") not in {"slave", "replica"}:
            raise RuntimeError(f"Redis replica host is not in replica mode: {active_replica}")
        if active_replica.get("master_link_status") != "up":
            raise RuntimeError(f"Redis replica link is not healthy: {active_replica}")
        print("replication=ok")

        events_5m = alerts_5m = -1
        for _ in range(6):
            events_5m, alerts_5m = _query_clickhouse_counts(vm3, sudo_password=vm3_password)
            if events_5m > 0:
                break
            time.sleep(5)
        if events_5m <= 0:
            raise RuntimeError(f"Fresh event flow is still flat after Redis HA rollout: events_5m={events_5m}")
        print(f"flow_events_5m={events_5m}")
        print(f"flow_alerts_5m={alerts_5m}")
        print("smoke=success")
        return 0
    finally:
        vm1.close()
        vm2.close()
        vm3.close()
        vm4.close()


if __name__ == "__main__":
    sys.exit(main())
