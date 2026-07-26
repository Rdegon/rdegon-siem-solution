from __future__ import annotations

import base64
import json
import os
import shlex
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import paramiko


ROOT = Path(__file__).resolve().parents[1]
REMOTE_ROOT = "/opt/siem/siem-solution"
CH_COLUMNS = ("community_id", "file_sha256", "container_id", "vulnerability_id", "rule_name", "evidence_id")


@dataclass(frozen=True)
class GuestWave:
    vmid: int
    name: str
    files: tuple[str, ...]
    units: tuple[str, ...]
    python_candidates: tuple[str, ...]
    env_path: str
    env_updates: tuple[tuple[str, str], ...]
    env_remove: tuple[str, ...]
    static_member_units: tuple[tuple[str, str], ...]
    batch_restart: bool = False
    apply_schema: bool = False


WAVES = (
    GuestWave(
        vmid=106,
        name="siem-storage",
        files=("services/transport_runtime.py", "services/writer/worker.py", "sql/18_security_analytics_schema.sql"),
        units=("siem-writer.service", "siem-writer@2.service"),
        python_candidates=("/opt/siem/venv-storage/bin/python", "/usr/bin/python3"),
        env_path="/etc/siem/storage.env",
        env_updates=(
            ("SIEM_KAFKA_STATIC_MEMBERSHIP", "true"),
            ("SIEM_KAFKA_SESSION_TIMEOUT_MS", "45000"),
            ("SIEM_KAFKA_HEARTBEAT_INTERVAL_MS", "10000"),
        ),
        env_remove=(),
        static_member_units=(
            ("siem-writer.service", "siem-storage-vm3-writer-primary"),
            ("siem-writer@.service", "siem-storage-vm3-writer-%i"),
        ),
        apply_schema=True,
    ),
    GuestWave(
        vmid=105,
        name="siem-processing",
        files=(
            "services/transport_runtime.py",
            "services/normalizer/normalizer_core.py",
            "services/normalizer/security_tool_normalizers.py",
        ),
        units=(
            "siem-normalizer.service",
            "siem-normalizer@1.service",
            "siem-normalizer@2.service",
            "siem-normalizer@3.service",
            "siem-filter.service",
            "siem-filter@1.service",
            "siem-filter@2.service",
            "siem-filter@3.service",
        ),
        python_candidates=("/opt/siem/venv-processing/bin/python", "/usr/bin/python3"),
        env_path="/etc/siem/processing.env",
        env_updates=(
            ("SIEM_KAFKA_STATIC_MEMBERSHIP", "true"),
            ("SIEM_KAFKA_SESSION_TIMEOUT_MS", "45000"),
            ("SIEM_KAFKA_HEARTBEAT_INTERVAL_MS", "10000"),
        ),
        env_remove=("SIEM_NORMALIZER_CONSUMER", "SIEM_FILTER_CONSUMER"),
        static_member_units=(
            ("siem-normalizer.service", "siem-processing-vm2-normalizer-primary"),
            ("siem-normalizer@.service", "siem-processing-vm2-normalizer-%i"),
            ("siem-filter.service", "siem-processing-vm2-filter-primary"),
            ("siem-filter@.service", "siem-processing-vm2-filter-%i"),
        ),
        batch_restart=True,
    ),
    GuestWave(
        vmid=108,
        name="siem-transport",
        files=(
            "services/transport_runtime.py",
            "services/normalizer/normalizer_core.py",
            "services/normalizer/security_tool_normalizers.py",
        ),
        units=(
            "siem-normalizer.service",
            "siem-normalizer@1.service",
            "siem-normalizer@2.service",
            "siem-normalizer@3.service",
            "siem-filter.service",
            "siem-filter@1.service",
            "siem-filter@2.service",
            "siem-filter@3.service",
        ),
        python_candidates=("/opt/siem/venv-transport/bin/python", "/usr/bin/python3"),
        env_path="/etc/siem/processing.env",
        env_updates=(
            ("SIEM_KAFKA_STATIC_MEMBERSHIP", "true"),
            ("SIEM_KAFKA_SESSION_TIMEOUT_MS", "45000"),
            ("SIEM_KAFKA_HEARTBEAT_INTERVAL_MS", "10000"),
        ),
        env_remove=("SIEM_NORMALIZER_CONSUMER", "SIEM_FILTER_CONSUMER"),
        static_member_units=(
            ("siem-normalizer.service", "siem-processing-vm5-normalizer-primary"),
            ("siem-normalizer@.service", "siem-processing-vm5-normalizer-%i"),
            ("siem-filter.service", "siem-processing-vm5-filter-primary"),
            ("siem-filter@.service", "siem-processing-vm5-filter-%i"),
        ),
        batch_restart=True,
    ),
)


def _required_env(name: str, default: str = "") -> str:
    value = str(os.getenv(name, default) or "").strip()
    if not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value


def _connect() -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        _required_env("SIEM_PROXMOX_HOST", "192.168.3.101"),
        username=_required_env("SIEM_PROXMOX_USER", "root"),
        password=_required_env("SIEM_PROXMOX_PASSWORD"),
        timeout=30,
        banner_timeout=30,
        auth_timeout=30,
        look_for_keys=False,
        allow_agent=False,
    )
    return client


def _run_host(client: paramiko.SSHClient, command: str, timeout: int = 300) -> tuple[int, str, str]:
    _, stdout, stderr = client.exec_command(command, timeout=timeout)
    output = stdout.read().decode("utf-8", errors="replace")
    error = stderr.read().decode("utf-8", errors="replace")
    return stdout.channel.recv_exit_status(), output, error


def _guest_exec(client: paramiko.SSHClient, vmid: int, command: str, timeout: int = 300) -> str:
    host_command = f"qm guest exec {vmid} --timeout {timeout} -- /bin/bash -lc {shlex.quote(command)}"
    code, output, error = _run_host(client, host_command, timeout=timeout + 30)
    if code != 0:
        raise RuntimeError(f"QGA command transport failed on VM{vmid}: {error.strip()}")
    try:
        payload = json.loads(output or "{}")
    except ValueError as exc:
        raise RuntimeError(f"Invalid QGA response on VM{vmid}: {output[:500]}") from exc
    exit_code = int(payload.get("exitcode") or 0)
    stdout = str(payload.get("out-data") or "")
    stderr = str(payload.get("err-data") or "")
    if exit_code != 0:
        raise RuntimeError(f"QGA command failed on VM{vmid}: {stderr.strip() or stdout.strip()}")
    return stdout


def _guest_write(client: paramiko.SSHClient, vmid: int, remote_path: str, content: bytes, backup_root: str) -> None:
    temp_b64 = f"/tmp/siem-security-analytics-{Path(remote_path).name}.b64"
    temp_file = f"/tmp/siem-security-analytics-{Path(remote_path).name}"
    backup_path = f"{backup_root}/{remote_path.lstrip('/').replace('/', '__')}"
    _guest_exec(
        client,
        vmid,
        f"install -d -m 0750 {shlex.quote(backup_root)} {shlex.quote(str(Path(remote_path).parent))} && "
        f"if [ -f {shlex.quote(remote_path)} ]; then cp -a {shlex.quote(remote_path)} {shlex.quote(backup_path)}; fi && "
        f": > {shlex.quote(temp_b64)}",
    )
    encoded = base64.b64encode(content).decode("ascii")
    chunk_size = 32_000
    for offset in range(0, len(encoded), chunk_size):
        chunk = encoded[offset : offset + chunk_size]
        _guest_exec(client, vmid, f"printf %s {shlex.quote(chunk)} >> {shlex.quote(temp_b64)}")
    _guest_exec(
        client,
        vmid,
        f"base64 -d {shlex.quote(temp_b64)} > {shlex.quote(temp_file)} && "
        f"install -m 0644 {shlex.quote(temp_file)} {shlex.quote(remote_path)} && "
        f"rm -f {shlex.quote(temp_b64)} {shlex.quote(temp_file)}",
    )


def _compile(client: paramiko.SSHClient, wave: GuestWave) -> None:
    python_files = [f"{REMOTE_ROOT}/{relative}" for relative in wave.files if relative.endswith(".py")]
    if not python_files:
        return
    candidates = " ".join(shlex.quote(item) for item in wave.python_candidates)
    command = (
        f"for candidate in {candidates}; do "
        "if [ -x \"$candidate\" ]; then python_bin=\"$candidate\"; break; fi; "
        "done; test -n \"$python_bin\"; "
        "\"$python_bin\" -m py_compile "
        + " ".join(shlex.quote(item) for item in python_files)
    )
    _guest_exec(client, wave.vmid, command)


def _update_env(client: paramiko.SSHClient, wave: GuestWave, backup_root: str) -> None:
    payload = base64.b64encode(json.dumps(dict(wave.env_updates), separators=(",", ":")).encode("utf-8")).decode("ascii")
    remove_payload = base64.b64encode(json.dumps(list(wave.env_remove), separators=(",", ":")).encode("utf-8")).decode("ascii")
    script = (
        "import base64,json\n"
        "from pathlib import Path\n"
        f"path=Path({wave.env_path!r})\n"
        f"updates=json.loads(base64.b64decode({payload!r}).decode('utf-8'))\n"
        f"remove=set(json.loads(base64.b64decode({remove_payload!r}).decode('utf-8')))\n"
        "lines=path.read_text(encoding='utf-8').splitlines() if path.exists() else []\n"
        "lines=[line for line in lines if line.split('=',1)[0].strip() not in remove]\n"
        "positions={line.split('=',1)[0].strip():i for i,line in enumerate(lines) "
        "if '=' in line and not line.lstrip().startswith('#')}\n"
        "for key,value in updates.items():\n"
        "    rendered=f'{key}={value}'\n"
        "    if key in positions: lines[positions[key]]=rendered\n"
        "    else: lines.append(rendered)\n"
        "path.write_text('\\n'.join(lines).rstrip()+'\\n',encoding='utf-8')\n"
    )
    backup_path = f"{backup_root}/{wave.env_path.lstrip('/').replace('/', '__')}"
    _guest_exec(
        client,
        wave.vmid,
        f"install -d -m 0750 {shlex.quote(backup_root)} && "
        f"cp -a {shlex.quote(wave.env_path)} {shlex.quote(backup_path)} && "
        f"python3 -c {shlex.quote(script)} && chmod 0600 {shlex.quote(wave.env_path)}",
    )


def _install_static_member_dropins(client: paramiko.SSHClient, wave: GuestWave) -> None:
    for unit, instance_id in wave.static_member_units:
        dropin_dir = f"/etc/systemd/system/{unit}.d"
        dropin_path = f"{dropin_dir}/60-static-kafka-member.conf"
        content = (
            "[Service]\n"
            f'Environment="SIEM_KAFKA_GROUP_INSTANCE_ID={instance_id}"\n'
        )
        encoded = base64.b64encode(content.encode("utf-8")).decode("ascii")
        _guest_exec(
            client,
            wave.vmid,
            f"install -d -m 0755 {shlex.quote(dropin_dir)} && "
            f"echo {shlex.quote(encoded)} | base64 -d > {shlex.quote(dropin_path)} && "
            f"chmod 0644 {shlex.quote(dropin_path)}",
        )
    _guest_exec(client, wave.vmid, "systemctl daemon-reload")


def _apply_schema(client: paramiko.SSHClient, wave: GuestWave) -> None:
    schema_path = f"{REMOTE_ROOT}/sql/18_security_analytics_schema.sql"
    query = (
        "SELECT count() FROM system.columns WHERE database='siem' AND table='events' AND name IN ("
        + ",".join(f"'{column}'" for column in CH_COLUMNS)
        + ")"
    )
    command = (
        "set -a; [ ! -f /etc/siem/storage.env ] || . /etc/siem/storage.env; set +a; "
        "host=\"${SIEM_CH_HOST:-127.0.0.1}\"; port=\"${SIEM_CH_PORT:-9000}\"; user=\"${SIEM_CH_USER:-default}\"; "
        "clickhouse-client --host \"$host\" --port \"$port\" --user \"$user\" "
        "--password \"${SIEM_CH_PASSWORD:-}\" --multiquery "
        f"< {shlex.quote(schema_path)} && "
        "clickhouse-client --host \"$host\" --port \"$port\" --user \"$user\" "
        f"--password \"${{SIEM_CH_PASSWORD:-}}\" --query {shlex.quote(query)}"
    )
    output = _guest_exec(client, wave.vmid, command, timeout=600)
    if output.strip().splitlines()[-1:] != [str(len(CH_COLUMNS))]:
        raise RuntimeError(f"ClickHouse schema verification failed on VM{wave.vmid}: {output.strip()}")


def _rolling_restart(client: paramiko.SSHClient, wave: GuestWave) -> list[str]:
    active_units: list[str] = []
    for unit in wave.units:
        state = _guest_exec(
            client,
            wave.vmid,
            f"if systemctl cat {shlex.quote(unit)} >/dev/null 2>&1 && "
            f"systemctl is-active --quiet {shlex.quote(unit)}; then echo active; else echo skip; fi",
        ).strip()
        enabled = _guest_exec(
            client,
            wave.vmid,
            f"if systemctl is-enabled --quiet {shlex.quote(unit)} 2>/dev/null; then echo enabled; else echo disabled; fi",
        ).strip()
        if state != "active" and enabled != "enabled":
            continue
        active_units.append(unit)
    if not active_units:
        raise RuntimeError(f"No active units found on VM{wave.vmid}")
    if wave.batch_restart:
        unit_args = " ".join(shlex.quote(unit) for unit in active_units)
        _guest_exec(
            client,
            wave.vmid,
            f"systemctl restart {unit_args} && systemctl is-active --quiet {unit_args}",
            timeout=600,
        )
        return active_units

    restarted: list[str] = []
    for unit in active_units:
        _guest_exec(
            client,
            wave.vmid,
            f"systemctl restart {shlex.quote(unit)} && systemctl is-active --quiet {shlex.quote(unit)}",
        )
        restarted.append(unit)
        time.sleep(1)
    return restarted


def main() -> int:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    client = _connect()
    try:
        for wave in WAVES:
            backup_root = f"/var/backups/siem/security-analytics-{timestamp}"
            for relative_path in wave.files:
                local_path = ROOT / relative_path
                if not local_path.exists():
                    raise FileNotFoundError(local_path)
                _guest_write(
                    client,
                    wave.vmid,
                    f"{REMOTE_ROOT}/{relative_path}",
                    local_path.read_bytes(),
                    backup_root,
                )
            _update_env(client, wave, backup_root)
            _install_static_member_dropins(client, wave)
            _compile(client, wave)
            if wave.apply_schema:
                _apply_schema(client, wave)
            restarted = _rolling_restart(client, wave)
            print(
                f"vmid={wave.vmid} name={wave.name} files={len(wave.files)} "
                f"restarted={','.join(restarted)} backup={backup_root}"
            )
    finally:
        client.close()
    print("security_analytics_qga_wave=success")
    return 0


if __name__ == "__main__":
    sys.exit(main())
