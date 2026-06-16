from __future__ import annotations

import base64
import json
import os
import posixpath
import shlex
import sys
import time
from dataclasses import dataclass
from pathlib import Path

import paramiko


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REMOTE_ROOT = "/opt/siem/siem-solution"
POLICY_FILE = "correlation_rule_packs/host_runtime_policy_v1.json"


@dataclass(frozen=True)
class HostSpec:
    env_prefix: str
    host_name: str
    role: str
    host_ip: str
    services: tuple[str, ...]


HOSTS: tuple[HostSpec, ...] = (
    HostSpec("SIEM_VM1", "siem-ingest", "ingest", "192.168.1.35", ("siem-ingest", "nginx")),
    HostSpec("SIEM_VM2", "siem-processing", "processing", "192.168.1.37", ("siem-normalizer", "siem-normalizer@2", "siem-filter", "siem-filter@2")),
    HostSpec("SIEM_VM3", "siem-storage", "storage", "192.168.1.38", ("clickhouse-server", "siem-writer", "siem-writer@2", "siem-stream-corr", "siem-batch-corr", "siem-alert-agg")),
    HostSpec("SIEM_VM4", "siem-web", "control-plane", "192.168.1.39", ("siem-web", "nginx", "openvpn-client@home-gateway", "siem-jump-tunnels")),
    HostSpec("SIEM_VM5", "siem-transport", "transport", "192.168.1.40", ("siem-kafka", "siem-normalizer@1", "siem-normalizer@2", "siem-filter@1", "siem-filter@2")),
)

COMMON_FILES = (
    ("host_runtime_pipeline.py", "host_runtime_pipeline.py", "0644"),
    ("deploy/host_runtime_agent.py", "deploy/host_runtime_agent.py", "0755"),
    (POLICY_FILE, "correlation_rule_packs/host_runtime_policy_v1.json", "0644"),
    ("deploy/common/siem-host-runtime-agent.service", "/etc/systemd/system/siem-host-runtime-agent.service", "0644"),
    ("deploy/common/siem-host-runtime-agent.timer", "/etc/systemd/system/siem-host-runtime-agent.timer", "0644"),
    ("deploy/common/90-siem-memory.conf", "/etc/systemd/journald.conf.d/90-siem-memory.conf", "0644"),
    ("deploy/common/siem-log-maintenance.sh", "/usr/local/bin/siem-log-maintenance.sh", "0755"),
    ("deploy/common/siem-log-maintenance.service", "/etc/systemd/system/siem-log-maintenance.service", "0644"),
    ("deploy/common/siem-log-maintenance.timer", "/etc/systemd/system/siem-log-maintenance.timer", "0644"),
)

VM4_ONLY_FILES = (
    ("host_runtime_runtime.py", "host_runtime_runtime.py", "0644"),
    ("host_runtime_runtime.py", "services/web/app/host_runtime_runtime.py", "0644"),
    ("deploy/host_runtime_monitor.py", "deploy/host_runtime_monitor.py", "0755"),
    ("deploy/publish_host_runtime_rules.py", "deploy/publish_host_runtime_rules.py", "0755"),
    ("deploy/vm4/siem-host-runtime-monitor.service", "/etc/systemd/system/siem-host-runtime-monitor.service", "0644"),
    ("deploy/vm4/siem-host-runtime-monitor.timer", "/etc/systemd/system/siem-host-runtime-monitor.timer", "0644"),
)
VM4_WEB_PYTHON = "/opt/siem/venv-web/bin/python"


def _required_env(name: str, *, default: str | None = None) -> str:
    value = str(os.getenv(name, default or "") or "").strip()
    if value:
        return value
    raise SystemExit(f"Missing required environment variable: {name}")


def _connect(
    host: str,
    user: str,
    password: str,
    *,
    attempts: int = 5,
    delay_seconds: float = 4.0,
) -> paramiko.SSHClient:
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
            print(f"host_runtime_connect_retry host={host} attempt={attempt}/{attempts} error={exc}")
            time.sleep(delay_seconds)
    raise RuntimeError(f"Unable to connect to {host}: {last_error}")


def _run(client: paramiko.SSHClient, command: str, *, sudo_password: str = "", use_sudo: bool = False) -> tuple[int, str, str]:
    wrapped = f"sudo -S -p '' bash -lc {shlex.quote(command)}" if use_sudo else command
    stdin, stdout, stderr = client.exec_command(wrapped, get_pty=use_sudo)
    if use_sudo:
        stdin.write(f"{sudo_password}\n")
        stdin.flush()
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    code = stdout.channel.recv_exit_status()
    return code, out, err


def _write_remote_text(client: paramiko.SSHClient, path: str, content: str, *, mode: str, sudo_password: str) -> None:
    payload = base64.b64encode(content.encode("utf-8")).decode("ascii")
    script = (
        "import base64\n"
        "from pathlib import Path\n"
        f"path = Path({path!r})\n"
        "path.parent.mkdir(parents=True, exist_ok=True)\n"
        f"path.write_bytes(base64.b64decode({payload!r}))\n"
        f"path.chmod(0o{mode})\n"
    )
    code, _, err = _run(client, f"python3 - <<'PY'\n{script}\nPY", sudo_password=sudo_password, use_sudo=True)
    if code != 0:
        raise RuntimeError(f"Unable to write {path}: {err.strip()}")


def _mkdir_remote(sftp: paramiko.SFTPClient, path: str) -> None:
    parts = [part for part in path.split("/") if part]
    current = ""
    for part in parts:
        current = f"{current}/{part}"
        try:
            sftp.stat(current)
        except OSError:
            sftp.mkdir(current)


def _upload_file(client: paramiko.SSHClient, local_rel: str, remote_path: str, *, mode: str, remote_root: str, sudo_password: str) -> None:
    local_path = ROOT / local_rel
    if not local_path.exists():
        raise FileNotFoundError(str(local_path))
    effective_remote = remote_path if remote_path.startswith("/") else posixpath.join(remote_root.rstrip("/"), remote_path)
    temp_path = f"/tmp/{Path(effective_remote).name}"
    sftp = client.open_sftp()
    try:
        _mkdir_remote(sftp, posixpath.dirname(temp_path))
        sftp.put(str(local_path), temp_path)
    finally:
        sftp.close()
    command = (
        f"install -d -m 0755 {shlex.quote(posixpath.dirname(effective_remote))} && "
        f"install -m {mode} {shlex.quote(temp_path)} {shlex.quote(effective_remote)} && "
        f"rm -f {shlex.quote(temp_path)}"
    )
    code, _, err = _run(client, command, sudo_password=sudo_password, use_sudo=True)
    if code != 0:
        raise RuntimeError(f"Unable to install {effective_remote}: {err.strip()}")


def _host_runtime_env(spec: HostSpec, *, ingest_url: str, tls_verify: str, timeout_seconds: str) -> str:
    return (
        f"SIEM_HOST_RUNTIME_HOSTNAME={spec.host_name}\n"
        f"SIEM_HOST_RUNTIME_ROLE={spec.role}\n"
        f"SIEM_HOST_RUNTIME_SERVICES={','.join(spec.services)}\n"
        f"SIEM_HOST_RUNTIME_INGEST_URL={ingest_url}\n"
        f"SIEM_HOST_RUNTIME_INGEST_TLS_VERIFY={tls_verify}\n"
        f"SIEM_HOST_RUNTIME_TIMEOUT_SECONDS={timeout_seconds}\n"
        "SIEM_HOST_RUNTIME_DELIVERY_ATTEMPTS=4\n"
        "SIEM_HOST_RUNTIME_STATE_PATH=/var/lib/siem-host-runtime/state.json\n"
        f"SIEM_HOST_RUNTIME_POLICY_PATH={remote_root_placeholder('/opt/siem/siem-solution/correlation_rule_packs/host_runtime_policy_v1.json')}\n"
    )


def _host_runtime_monitor_env(*, ingest_url: str, tls_verify: str, timeout_seconds: str) -> str:
    targets = [
        {"host_name": spec.host_name, "host_role": spec.role, "host_ip": spec.host_ip}
        for spec in HOSTS
    ]
    return (
        f"SIEM_HOST_RUNTIME_INGEST_URL={ingest_url}\n"
        f"SIEM_HOST_RUNTIME_INGEST_TLS_VERIFY={tls_verify}\n"
        f"SIEM_HOST_RUNTIME_TIMEOUT_SECONDS={timeout_seconds}\n"
        "SIEM_HOST_RUNTIME_DELIVERY_ATTEMPTS=4\n"
        "SIEM_HOST_RUNTIME_STALE_AFTER_SECONDS=420\n"
        "SIEM_HOST_RUNTIME_MONITOR_STATE_PATH=/var/lib/siem-host-runtime/monitor-state.json\n"
        f"SIEM_HOST_RUNTIME_POLICY_PATH={remote_root_placeholder('/opt/siem/siem-solution/correlation_rule_packs/host_runtime_policy_v1.json')}\n"
        f"SIEM_HOST_RUNTIME_TARGETS_JSON={json.dumps(targets, ensure_ascii=False)}\n"
    )


def remote_root_placeholder(path: str) -> str:
    return str(path)


def _agent_ingest_target(spec: HostSpec, *, ingest_url: str, tls_verify: str, local_ingest_url: str) -> tuple[str, str]:
    if spec.env_prefix == "SIEM_VM1":
        return str(local_ingest_url or "http://127.0.0.1:8443/ingest/json").strip(), "disabled"
    return ingest_url, tls_verify


def main() -> int:
    remote_root = _required_env("SIEM_REMOTE_ROOT", default=DEFAULT_REMOTE_ROOT)
    ingest_url = _required_env("SIEM_HOST_RUNTIME_INGEST_URL", default="https://192.168.1.35/ingest/json")
    tls_verify = _required_env("SIEM_HOST_RUNTIME_INGEST_TLS_VERIFY", default="disabled")
    timeout_seconds = _required_env("SIEM_HOST_RUNTIME_TIMEOUT_SECONDS", default="20")
    local_ingest_url = _required_env("SIEM_HOST_RUNTIME_LOCAL_INGEST_URL", default="http://127.0.0.1:8443/ingest/json")
    for spec in HOSTS:
        host = _required_env(f"{spec.env_prefix}_HOST", default=spec.host_ip)
        user = _required_env(f"{spec.env_prefix}_USER", default="rdegon")
        password = _required_env(f"{spec.env_prefix}_PASSWORD")
        agent_ingest_url, agent_tls_verify = _agent_ingest_target(
            spec,
            ingest_url=ingest_url,
            tls_verify=tls_verify,
            local_ingest_url=local_ingest_url,
        )
        client = _connect(host, user, password)
        try:
            for local_rel, remote_path, mode in COMMON_FILES:
                _upload_file(client, local_rel, remote_path, mode=mode, remote_root=remote_root, sudo_password=password)
            _write_remote_text(
                client,
                "/etc/siem/host-runtime.env",
                _host_runtime_env(
                    spec,
                    ingest_url=agent_ingest_url,
                    tls_verify=agent_tls_verify,
                    timeout_seconds=timeout_seconds,
                ),
                mode="0600",
                sudo_password=password,
            )
            if spec.env_prefix == "SIEM_VM4":
                for local_rel, remote_path, mode in VM4_ONLY_FILES:
                    _upload_file(client, local_rel, remote_path, mode=mode, remote_root=remote_root, sudo_password=password)
                _write_remote_text(
                    client,
                    "/etc/siem/host-runtime-monitor.env",
                    _host_runtime_monitor_env(ingest_url=ingest_url, tls_verify=tls_verify, timeout_seconds=timeout_seconds),
                    mode="0600",
                    sudo_password=password,
                )
            code, _, err = _run(
                client,
                "journalctl --rotate || true && "
                "journalctl --vacuum-size=256M || true && "
                "systemctl restart systemd-journald || true && "
                "systemctl enable siem-log-maintenance.timer && "
                "systemctl restart siem-log-maintenance.timer && "
                "systemctl start siem-log-maintenance.service && "
                "systemctl restart rsyslog || true && "
                "systemctl daemon-reload && "
                "systemctl enable siem-host-runtime-agent.timer && "
                "systemctl restart siem-host-runtime-agent.timer && "
                "systemctl start siem-host-runtime-agent.service",
                sudo_password=password,
                use_sudo=True,
            )
            if code != 0:
                raise RuntimeError(f"Unable to activate host runtime agent on {host}: {err.strip()}")
            if spec.env_prefix == "SIEM_VM4":
                publish_rules_cmd = (
                    f"cd {shlex.quote(remote_root)} && "
                    f"{shlex.quote(VM4_WEB_PYTHON)} - <<'PY'\n"
                    "import os\n"
                    "import runpy\n"
                    "from pathlib import Path\n"
                    "for raw_line in Path('/etc/siem/web.env').read_text(encoding='utf-8').splitlines():\n"
                    "    line = raw_line.strip()\n"
                    "    if not line or line.startswith('#') or '=' not in raw_line:\n"
                    "        continue\n"
                    "    key, value = raw_line.split('=', 1)\n"
                    "    key = key.strip()\n"
                    "    if key:\n"
                    "        os.environ.setdefault(key, value)\n"
                    "runpy.run_path('deploy/publish_host_runtime_rules.py', run_name='__main__')\n"
                    "PY"
                )
                code, _, err = _run(
                    client,
                    publish_rules_cmd,
                    sudo_password=password,
                    use_sudo=True,
                )
                if code != 0:
                    raise RuntimeError(f"Unable to publish host runtime rules on {host}: {err.strip()}")
                code, _, err = _run(
                    client,
                    "systemctl restart siem-web && "
                    "systemctl enable siem-host-runtime-monitor.timer && "
                    "systemctl restart siem-host-runtime-monitor.timer && "
                    "systemctl start siem-host-runtime-monitor.service",
                    sudo_password=password,
                    use_sudo=True,
                )
                if code != 0:
                    raise RuntimeError(f"Unable to activate host runtime monitor on {host}: {err.strip()}")
            print(f"host_runtime_deploy host={spec.host_name} result=success")
        finally:
            client.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
