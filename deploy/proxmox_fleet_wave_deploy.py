from __future__ import annotations

import argparse
import base64
import json
import os
import shlex
import sys
import textwrap
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import paramiko


ROOT = Path(__file__).resolve().parents[1]
REMOTE_ROOT = "/opt/siem/siem-solution"
INGEST_CA_PATH = "/etc/siem/pki/ingest-ca.crt"
PROXMOX_HOST = "192.168.3.101"
VM4_HOST = "10.20.10.107"
VM4_WEB_PYTHON = "/opt/siem/venv-web/bin/python"
NAVIDROME_VERSION = "0.60.3"
NAVIDROME_URL = f"https://github.com/navidrome/navidrome/releases/download/v{NAVIDROME_VERSION}/navidrome_{NAVIDROME_VERSION}_linux_amd64.tar.gz"
NMAP_EXPOSURE_TARGETS: tuple[str, ...] = (
    "10.20.10.104",
    "10.20.10.105",
    "10.20.10.106",
    "10.20.10.107",
    "10.20.10.108",
    "10.20.10.127",
    "10.20.10.128",
    "10.20.10.131",
    "10.20.10.132",
    "10.20.10.133",
    "10.20.20.100",
    "10.20.20.120",
    "10.20.20.121",
    "10.20.20.130",
    "10.20.30.122",
    "10.20.30.123",
    "10.20.30.124",
    "10.20.30.125",
    "10.20.30.126",
    "10.20.30.129",
)


@dataclass(frozen=True)
class GuestSpec:
    vmid: int
    guest_type: str
    name: str
    role: str
    services: tuple[str, ...]
    needs_docker: bool = False
    needs_navidrome: bool = False
    needs_openvas_log: bool = False
    needs_openclaw: bool = False
    needs_nmap_exporter: bool = False


GUESTS: tuple[GuestSpec, ...] = (
    GuestSpec(100, "lxc", "minecraft-01", "guest", ("minecraft", "minecraft-admin-console", "nftables", "rsyslog")),
    GuestSpec(102, "qemu", "lab-edge-01", "edge-router", ("suricata", "unbound", "nftables", "auditd", "rsyslog")),
    GuestSpec(120, "lxc", "nextcloud-siem", "business-app", ("apache2", "mariadb", "redis-server", "fail2ban", "webmin", "ssh", "rsyslog")),
    GuestSpec(
        121,
        "lxc",
        "navidrome-01",
        "media-node",
        ("navidrome", "ssh", "rsyslog"),
        needs_navidrome=True,
    ),
    GuestSpec(
        122,
        "qemu",
        "vuln-mgr-01",
        "vulnerability-manager",
        ("docker", "rdegon-vuln-scan.timer", "auditd", "ssh", "rsyslog"),
        needs_docker=True,
        needs_openvas_log=True,
        needs_nmap_exporter=True,
    ),
    GuestSpec(123, "qemu", "pilot-web-01", "pilot-web", ("docker", "pilot-gitea", "auditd", "ssh", "rsyslog"), needs_docker=True),
    GuestSpec(124, "qemu", "pilot-db-01", "pilot-db", ("postgresql@14-main", "auditd", "ssh", "rsyslog")),
    GuestSpec(125, "qemu", "pilot-cache-01", "pilot-cache", ("docker", "pilot-valkey", "auditd", "ssh", "rsyslog"), needs_docker=True),
    GuestSpec(126, "qemu", "openclaw-gateway", "openclaw-gateway", ("openclaw-gateway", "openclaw-vless", "auditd", "systemd-resolved", "ssh.socket", "rsyslog"), needs_openclaw=True),
    GuestSpec(130, "qemu", "gamepanel-01", "guest", ("docker", "wings", "nginx", "auditd", "rsyslog")),
)


COMMON_REMOTE_FILES: tuple[tuple[str, str, str], ...] = (
    ("services/web/app/host_runtime_pipeline.py", f"{REMOTE_ROOT}/host_runtime_pipeline.py", "0644"),
    ("deploy/host_runtime_agent.py", f"{REMOTE_ROOT}/deploy/host_runtime_agent.py", "0755"),
    ("correlation_rule_packs/host_runtime_policy_v1.json", f"{REMOTE_ROOT}/correlation_rule_packs/host_runtime_policy_v1.json", "0644"),
    ("deploy/common/siem-host-runtime-agent.service", "/etc/systemd/system/siem-host-runtime-agent.service", "0644"),
    ("deploy/common/siem-host-runtime-agent.timer", "/etc/systemd/system/siem-host-runtime-agent.timer", "0644"),
    ("deploy/common/10-siem-imfile.conf", "/etc/rsyslog.d/10-siem-imfile.conf", "0644"),
    ("deploy/common/90-siem-memory.conf", "/etc/systemd/journald.conf.d/90-siem-memory.conf", "0644"),
    ("deploy/common/siem-log-maintenance.sh", "/usr/local/bin/siem-log-maintenance.sh", "0755"),
    ("deploy/common/siem-log-maintenance.service", "/etc/systemd/system/siem-log-maintenance.service", "0644"),
    ("deploy/common/siem-log-maintenance.timer", "/etc/systemd/system/siem-log-maintenance.timer", "0644"),
    ("deploy/common/90-siem-forward.conf", "/etc/rsyslog.d/90-siem-forward.conf", "0644"),
)


def _stdout_setup() -> None:
    for stream_name in ("stdout", "stderr"):
        stream = getattr(sys, stream_name, None)
        if stream is not None and hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass


def _env(name: str, default: str = "") -> str:
    return str(os.getenv(name, default) or default).strip()


def _required_env(name: str) -> str:
    value = _env(name)
    if value:
        return value
    raise SystemExit(f"Missing required environment variable: {name}")


def _connect(host: str, user: str, password: str) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        host,
        username=user,
        password=password,
        timeout=30,
        banner_timeout=30,
        auth_timeout=30,
        look_for_keys=False,
        allow_agent=False,
    )
    return client


def _run(client: paramiko.SSHClient, command: str) -> tuple[int, str, str]:
    stdin, stdout, stderr = client.exec_command(command)
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    return stdout.channel.recv_exit_status(), out, err


def _run_sudo(client: paramiko.SSHClient, command: str, *, sudo_password: str) -> tuple[int, str, str]:
    stdin, stdout, stderr = client.exec_command(f"sudo -S -p '' bash -lc {shlex.quote(command)}", get_pty=True)
    stdin.write(f"{sudo_password}\n")
    stdin.flush()
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    return stdout.channel.recv_exit_status(), out, err


def _strip_sudo_echo(text: str, sudo_password: str) -> str:
    if not sudo_password:
        return text
    return "\n".join(line for line in str(text or "").splitlines() if line.strip() != sudo_password)


def _extract_json_payload(text: str) -> str:
    lines = [line.strip() for line in str(text or "").splitlines() if line.strip()]
    for line in reversed(lines):
        if line.startswith("{") or line.startswith("["):
            return line
    return str(text or "").strip()


def _require_success(code: int, out: str, err: str, message: str) -> str:
    if code != 0:
        raise RuntimeError(f"{message}\nstdout={out}\nstderr={err}")
    return out


def _guest_exec(proxmox: paramiko.SSHClient, spec: GuestSpec, command: str, *, timeout: int = 240) -> str:
    if spec.guest_type == "lxc":
        code, out, err = _run(proxmox, f"pct exec {spec.vmid} -- bash -lc {shlex.quote(command)}")
        return _require_success(code, out, err, f"Guest command failed for {spec.name}: {command}")
    code, out, err = _run(proxmox, f"qm guest exec {spec.vmid} --timeout {int(timeout)} -- /bin/bash -lc {shlex.quote(command)}")
    raw = _require_success(code, out, err, f"Guest command failed for {spec.name}: {command}")
    payload = json.loads(raw or "{}")
    exitcode = int(payload.get("exitcode") or 0)
    stdout = str(payload.get("out-data") or "")
    stderr = str(payload.get("err-data") or "")
    if exitcode != 0:
        raise RuntimeError(f"Guest command failed for {spec.name}: {command}\nstdout={stdout}\nstderr={stderr}")
    return stdout


def _guest_write_text(proxmox: paramiko.SSHClient, spec: GuestSpec, path: str, content: str, *, mode: str = "0644") -> None:
    payload = base64.b64encode(content.encode("utf-8")).decode("ascii")
    script = (
        "python3 - <<'PY'\n"
        "import base64\n"
        "import os\n"
        "from pathlib import Path\n"
        f"path = Path({path!r})\n"
        "path.parent.mkdir(parents=True, exist_ok=True)\n"
        f"path.write_bytes(base64.b64decode({payload!r}))\n"
        f"os.chmod(path, 0o{mode})\n"
        "PY"
    )
    _guest_exec(proxmox, spec, script, timeout=240)


def _host_write_text(client: paramiko.SSHClient, path: str, content: str, *, mode: str = "0644") -> None:
    payload = base64.b64encode(content.encode("utf-8")).decode("ascii")
    script = (
        "python3 - <<'PY'\n"
        "import base64\n"
        "import os\n"
        "from pathlib import Path\n"
        f"path = Path({path!r})\n"
        "path.parent.mkdir(parents=True, exist_ok=True)\n"
        f"path.write_bytes(base64.b64decode({payload!r}))\n"
        f"os.chmod(path, 0o{mode})\n"
        "PY"
    )
    code, out, err = _run(client, script)
    _require_success(code, out, err, f"Unable to write host file {path}")


def _repo_text(rel_path: str) -> str:
    return (ROOT / rel_path).read_text(encoding="utf-8")


def _install_proxmox_host_housekeeping(proxmox: paramiko.SSHClient) -> None:
    _host_write_text(proxmox, "/etc/systemd/journald.conf.d/90-siem-memory.conf", _repo_text("deploy/common/90-siem-memory.conf"), mode="0644")
    _host_write_text(proxmox, "/usr/local/bin/siem-log-maintenance.sh", _repo_text("deploy/common/siem-log-maintenance.sh"), mode="0755")
    _host_write_text(proxmox, "/etc/systemd/system/siem-log-maintenance.service", _repo_text("deploy/common/siem-log-maintenance.service"), mode="0644")
    _host_write_text(proxmox, "/etc/systemd/system/siem-log-maintenance.timer", _repo_text("deploy/common/siem-log-maintenance.timer"), mode="0644")
    code, out, err = _run(
        proxmox,
        "journalctl --rotate || true && "
        "journalctl --vacuum-size=256M || true && "
        "systemctl restart systemd-journald || true && "
        "systemctl daemon-reload && "
        "systemctl enable siem-log-maintenance.timer && "
        "systemctl restart siem-log-maintenance.timer && "
        "systemctl start siem-log-maintenance.service",
    )
    _require_success(code, out, err, "Unable to activate Proxmox host log maintenance")


def _install_common_monitoring_bundle(proxmox: paramiko.SSHClient, spec: GuestSpec) -> None:
    needs_linux_audit = spec.guest_type == "qemu"
    packages = ["python3", "curl", "ca-certificates", "rsyslog", "logrotate"]
    if needs_linux_audit:
        packages.extend(["auditd", "audispd-plugins"])
    _guest_exec(
        proxmox,
        spec,
        "export DEBIAN_FRONTEND=noninteractive && apt-get update && apt-get install -y " + " ".join(packages),
        timeout=1200,
    )
    _guest_exec(
        proxmox,
        spec,
        f"install -d -m 0755 /etc/siem /var/lib/siem-host-runtime {shlex.quote(REMOTE_ROOT)} {shlex.quote(REMOTE_ROOT + '/deploy')} {shlex.quote(REMOTE_ROOT + '/correlation_rule_packs')}",
        timeout=120,
    )
    for local_rel, remote_path, mode in COMMON_REMOTE_FILES:
        _guest_write_text(proxmox, spec, remote_path, _repo_text(local_rel), mode=mode)
    ingest_spec = GuestSpec(104, "qemu", "siem-ingest", "ingest", ())
    ingest_certificate = _guest_exec(
        proxmox,
        ingest_spec,
        "cat /etc/siem/tls/ingest.crt",
        timeout=60,
    )
    if "BEGIN CERTIFICATE" not in ingest_certificate:
        raise RuntimeError("Unable to read the trusted SIEM ingest certificate from VM104")
    _guest_write_text(proxmox, spec, INGEST_CA_PATH, ingest_certificate, mode="0644")
    if spec.vmid == 130:
        _guest_write_text(
            proxmox,
            spec,
            "/etc/rsyslog.d/60-gamepanel-siem.conf",
            _repo_text("deploy/common/60-gamepanel-siem.conf"),
            mode="0644",
        )
    env_text = (
        f"SIEM_HOST_RUNTIME_HOSTNAME={spec.name}\n"
        f"SIEM_HOST_RUNTIME_ROLE={spec.role}\n"
        f"SIEM_HOST_RUNTIME_SERVICES={','.join(spec.services)}\n"
        "SIEM_HOST_RUNTIME_INGEST_URL=https://10.20.10.104/ingest/json\n"
        "SIEM_HOST_RUNTIME_INGEST_TLS_VERIFY=required\n"
        f"SIEM_HOST_RUNTIME_INGEST_CA_FILE={INGEST_CA_PATH}\n"
        "SIEM_HOST_RUNTIME_TIMEOUT_SECONDS=20\n"
        "SIEM_HOST_RUNTIME_DELIVERY_ATTEMPTS=4\n"
        "SIEM_HOST_RUNTIME_STATE_PATH=/var/lib/siem-host-runtime/state.json\n"
        f"SIEM_HOST_RUNTIME_POLICY_PATH={REMOTE_ROOT}/correlation_rule_packs/host_runtime_policy_v1.json\n"
    )
    _guest_write_text(proxmox, spec, "/etc/siem/host-runtime.env", env_text, mode="0600")
    if needs_linux_audit:
        _guest_write_text(proxmox, spec, "/etc/rsyslog.d/91-siem-audit-imfile.conf", _repo_text("deploy/common/91-siem-audit-imfile.conf"), mode="0644")
        _guest_write_text(proxmox, spec, "/etc/audit/rules.d/50-siem-linux-audit.rules", _repo_text("deploy/common/50-siem-linux-audit.rules"), mode="0640")
    if spec.needs_openvas_log:
        _guest_write_text(proxmox, spec, "/etc/rsyslog.d/92-openvas-container-imfile.conf", _repo_text("deploy/common/92-openvas-container-imfile.conf"), mode="0644")
    service_cmd = ""
    if needs_linux_audit:
        service_cmd = "(augenrules --load || true) && systemctl enable auditd --now && systemctl restart auditd && "
    _guest_exec(
        proxmox,
        spec,
        "journalctl --rotate || true && "
        "journalctl --vacuum-size=256M || true && "
        "systemctl daemon-reload && "
        "systemctl restart systemd-journald || true && "
        "systemctl enable siem-log-maintenance.timer && "
        "systemctl restart siem-log-maintenance.timer && "
        "systemctl start siem-log-maintenance.service && "
        "systemctl enable rsyslog --now && "
        f"{service_cmd}"
        "systemctl restart rsyslog && "
        "systemctl enable siem-host-runtime-agent.timer && "
        "systemctl restart siem-host-runtime-agent.timer && "
        "systemctl start siem-host-runtime-agent.service",
        timeout=300,
    )


def _ensure_docker(proxmox: paramiko.SSHClient, spec: GuestSpec) -> None:
    _guest_exec(
        proxmox,
        spec,
        "if command -v docker >/dev/null 2>&1; then "
        "  systemctl enable docker --now; "
        "else "
        "  export DEBIAN_FRONTEND=noninteractive && apt-get update && apt-get install -y docker.io && systemctl enable docker --now; "
        "fi",
        timeout=1200,
    )


def _set_navidrome_hostname(proxmox: paramiko.SSHClient) -> None:
    code, out, err = _run(proxmox, "pct set 121 --hostname navidrome-01")
    _require_success(code, out, err, "Unable to rename CT121 to navidrome-01")


def _ensure_navidrome(proxmox: paramiko.SSHClient, spec: GuestSpec) -> None:
    _guest_exec(
        proxmox,
        spec,
        "id -u navidrome >/dev/null 2>&1 || useradd --system --home /var/lib/navidrome --create-home --shell /usr/sbin/nologin navidrome && "
        "install -d -m 0755 -o navidrome -g navidrome /var/lib/navidrome /var/lib/navidrome/music /var/lib/navidrome/data /opt/navidrome",
        timeout=240,
    )
    _guest_exec(
        proxmox,
        spec,
        textwrap.dedent(
            f"""
            if [ ! -x /opt/navidrome/navidrome ]; then
              tmpdir=$(mktemp -d)
              cd "$tmpdir"
              curl -fsSL {shlex.quote(NAVIDROME_URL)} -o navidrome.tar.gz
              tar -xzf navidrome.tar.gz
              install -m 0755 navidrome /opt/navidrome/navidrome
              install -m 0644 LICENSE /opt/navidrome/LICENSE || true
              install -m 0644 README.md /opt/navidrome/README.md || true
              chown -R navidrome:navidrome /opt/navidrome
              rm -rf "$tmpdir"
            fi
            """
        ).strip(),
        timeout=1200,
    )
    _guest_write_text(proxmox, spec, "/etc/systemd/system/navidrome.service", _repo_text("deploy/common/navidrome.service"), mode="0644")
    _guest_exec(
        proxmox,
        spec,
        "systemctl daemon-reload && "
        "systemctl enable navidrome --now && "
        "systemctl restart navidrome && "
        "systemctl is-active navidrome && "
        "for attempt in $(seq 1 20); do "
        "  curl -fsS http://127.0.0.1:4533/ >/dev/null && exit 0; "
        "  sleep 3; "
        "done; "
        "exit 1",
        timeout=240,
    )


def _deploy_nmap_exporter(proxmox: paramiko.SSHClient, spec: GuestSpec) -> None:
    targets_text = "# Secondary Nmap exposure scan targets.\n" + "\n".join(NMAP_EXPOSURE_TARGETS) + "\n"
    env_text = (
        "RDEGON_SIEM_BASE_URL=https://192.168.3.102\n"
        "RDEGON_SIEM_VULN_INGEST_URL=https://10.20.10.104:9445/\n"
        "RDEGON_VULN_TARGETS_FILE=/opt/rdegon-siem-vuln/targets.txt\n"
        "RDEGON_VULN_REPORT_DIR=/opt/rdegon-siem-vuln/reports\n"
        "RDEGON_VULN_NMAP_ARGS=-Pn -sV -T4 --top-ports 200 --max-retries 2 --host-timeout 3m\n"
    )
    _guest_exec(
        proxmox,
        spec,
        "export DEBIAN_FRONTEND=noninteractive && apt-get update && apt-get install -y nmap",
        timeout=1200,
    )
    _guest_exec(
        proxmox,
        spec,
        "install -d -m 0755 /opt/rdegon-siem-vuln /opt/rdegon-siem-vuln/reports /etc/default",
        timeout=120,
    )
    _guest_write_text(proxmox, spec, "/opt/rdegon-siem-vuln/rdegon-vuln-reporter.py", _repo_text("deploy/vuln/rdegon-vuln-reporter.py"), mode="0755")
    _guest_write_text(proxmox, spec, "/etc/systemd/system/rdegon-vuln-scan.service", _repo_text("deploy/vuln/rdegon-vuln-scan.service"), mode="0644")
    _guest_write_text(proxmox, spec, "/etc/systemd/system/rdegon-vuln-scan.timer", _repo_text("deploy/vuln/rdegon-vuln-scan.timer"), mode="0644")
    _guest_write_text(proxmox, spec, "/etc/default/rdegon-vuln-scan", env_text, mode="0600")
    _guest_write_text(proxmox, spec, "/opt/rdegon-siem-vuln/targets.txt", targets_text, mode="0644")
    _guest_exec(
        proxmox,
        spec,
        "systemctl daemon-reload && "
        "systemctl enable rdegon-vuln-scan.timer --now && "
        "systemctl start rdegon-vuln-scan.service && "
        "systemctl restart rdegon-vuln-scan.timer && "
        "systemctl is-active rdegon-vuln-scan.timer",
        timeout=240,
    )


def _deploy_pilot_gitea(proxmox: paramiko.SSHClient, spec: GuestSpec) -> None:
    _ensure_docker(proxmox, spec)
    _guest_write_text(proxmox, spec, "/etc/systemd/system/pilot-gitea.service", _repo_text("deploy/common/pilot-gitea.service"), mode="0644")
    _guest_exec(
        proxmox,
        spec,
        "systemctl daemon-reload && "
        "systemctl enable pilot-gitea --now && "
        "systemctl restart pilot-gitea && "
        "systemctl is-active pilot-gitea && "
        "for attempt in $(seq 1 30); do "
        "  curl -fsS http://127.0.0.1:3000/ >/dev/null && exit 0; "
        "  sleep 3; "
        "done; "
        "exit 1",
        timeout=1200,
    )


def _deploy_pilot_valkey(proxmox: paramiko.SSHClient, spec: GuestSpec) -> None:
    _ensure_docker(proxmox, spec)
    _guest_write_text(proxmox, spec, "/etc/systemd/system/pilot-valkey.service", _repo_text("deploy/common/pilot-valkey.service"), mode="0644")
    _guest_exec(
        proxmox,
        spec,
        "systemctl disable --now redis-server >/dev/null 2>&1 || true && "
        "systemctl daemon-reload && "
        "systemctl enable pilot-valkey --now && "
        "systemctl restart pilot-valkey && "
        "systemctl is-active pilot-valkey && "
        "for attempt in $(seq 1 20); do "
        "  docker exec pilot-valkey sh -lc 'valkey-cli ping | grep -q PONG' && exit 0; "
        "  sleep 3; "
        "done; "
        "exit 1",
        timeout=1200,
    )


def _wire_openvas_logs(proxmox: paramiko.SSHClient, spec: GuestSpec) -> None:
    log_path = _guest_exec(proxmox, spec, "docker inspect -f '{{.LogPath}}' openvas", timeout=120).strip()
    if not log_path:
        raise RuntimeError("Unable to discover OpenVAS container log path")
    _guest_exec(
        proxmox,
        spec,
        f"ln -sf {shlex.quote(log_path)} /var/log/openvas-container.log && systemctl restart rsyslog",
        timeout=120,
    )


def _deploy_openclaw_runtime(proxmox: paramiko.SSHClient, spec: GuestSpec) -> None:
    _guest_write_text(proxmox, spec, "/etc/systemd/system/openclaw-gateway.service", _repo_text("deploy/common/openclaw-gateway.service"), mode="0644")
    _guest_write_text(proxmox, spec, "/etc/systemd/system/openclaw-vless.service", _repo_text("deploy/common/openclaw-vless.service"), mode="0644")
    _guest_write_text(
        proxmox,
        spec,
        "/etc/systemd/system/systemd-resolved.service.d/90-siem-debug.conf",
        _repo_text("deploy/common/90-systemd-resolved-debug.conf"),
        mode="0644",
    )
    uid = int((_guest_exec(proxmox, spec, "id -u openclaw", timeout=60).strip() or "1000"))
    audit_rules = textwrap.dedent(
        f"""
        -w /home/openclaw/.openclaw -p wa -k openclaw_config
        -w /home/openclaw/.config/xray -p wa -k openclaw_config
        -w /home/openclaw/bin -p wa -k openclaw_binary
        -w /etc/systemd/system/openclaw-gateway.service -p wa -k openclaw_service
        -w /etc/systemd/system/openclaw-vless.service -p wa -k openclaw_service
        -a always,exit -F arch=b64 -S execve -F euid={uid} -k openclaw_exec
        -a always,exit -F arch=b64 -S connect -F euid={uid} -k openclaw_connect
        -a always,exit -F arch=b64 -S sendto -F euid={uid} -k openclaw_send
        """
    ).strip() + "\n"
    _guest_write_text(proxmox, spec, "/etc/audit/rules.d/50-siem-openclaw.rules", audit_rules, mode="0640")
    _guest_exec(
        proxmox,
        spec,
        "systemctl --user -M openclaw@ disable --now openclaw-gateway.service openclaw-vless.service >/dev/null 2>&1 || true && "
        "systemctl daemon-reload && "
        "systemctl enable openclaw-gateway openclaw-vless && "
        "systemctl restart systemd-resolved && "
        "(augenrules --load || true) && "
        "systemctl enable auditd --now && "
        "systemctl restart auditd && "
        "systemctl restart rsyslog && "
        "systemctl restart openclaw-gateway openclaw-vless && "
        "systemctl is-active openclaw-gateway && "
        "systemctl is-active openclaw-vless && "
        "systemctl is-active auditd",
        timeout=360,
    )


def _sync_vm4_runtime(
    vm4_password: str,
    *,
    proxmox_host: str,
    proxmox_user: str,
    proxmox_password: str,
    start_greenbone_wave: bool,
) -> dict[str, Any]:
    client = _connect(VM4_HOST, "rdegon", vm4_password)
    try:
        sync_script = (
            f"cd {shlex.quote(REMOTE_ROOT)} && {shlex.quote(VM4_WEB_PYTHON)} - <<'PY'\n"
            "import importlib.util\n"
            "import json\n"
            "import os\n"
            "import sys\n"
            "import types\n"
            "from pathlib import Path\n"
            "for raw_line in Path('/etc/siem/web.env').read_text(encoding='utf-8').splitlines():\n"
            "    line = raw_line.strip()\n"
            "    if not line or line.startswith('#') or '=' not in raw_line:\n"
            "        continue\n"
            "    key, value = raw_line.split('=', 1)\n"
            "    key = key.strip()\n"
            "    if key:\n"
            "        os.environ.setdefault(key, value)\n"
            f"os.environ['SIEM_PROXMOX_HOST'] = {proxmox_host!r}\n"
            f"os.environ['SIEM_PROXMOX_USER'] = {proxmox_user!r}\n"
            f"os.environ['SIEM_PROXMOX_PASSWORD'] = {proxmox_password!r}\n"
            "APP_ROOT = Path('services/web/app').resolve()\n"
            "PACKAGE = 'proxmox_fleet_wave_pkg'\n"
            "if PACKAGE not in sys.modules:\n"
            "    package = types.ModuleType(PACKAGE)\n"
            "    package.__path__ = [str(APP_ROOT)]\n"
            "    sys.modules[PACKAGE] = package\n"
            "def load(name):\n"
            "    full_name = f'{PACKAGE}.{name}'\n"
            "    if full_name in sys.modules:\n"
            "        return sys.modules[full_name]\n"
            "    spec = importlib.util.spec_from_file_location(full_name, APP_ROOT / f'{name}.py')\n"
            "    if spec is None or spec.loader is None:\n"
            "        raise RuntimeError(f'Unable to load {name} from {APP_ROOT}')\n"
            "    module = importlib.util.module_from_spec(spec)\n"
            "    sys.modules[full_name] = module\n"
            "    spec.loader.exec_module(module)\n"
            "    return module\n"
            "p = load('proxmox_fleet_runtime')\n"
            "vuln_store = load('vuln_store')\n"
            "payload = {\n"
            "  'fleet_sync': p.sync_proxmox_fleet_inventory(actor='proxmox-fleet-wave'),\n"
            "  'cmdb_sync': p.sync_proxmox_fleet_to_cmdb(actor='proxmox-fleet-wave'),\n"
            "  'vuln_sync': vuln_store.sync_vulnerability_targets(limit=500),\n"
            "  'report_import': vuln_store.import_greenbone_reports(limit=50),\n"
            "  'fleet_coverage': p.build_proxmox_fleet_vuln_coverage(days=30),\n"
            "}\n"
            "print(json.dumps(payload, ensure_ascii=False))\n"
            "PY"
        )
        code, out, err = _run_sudo(client, sync_script, sudo_password=vm4_password)
        sync_out = _strip_sudo_echo(_require_success(code, out, err, "Unable to sync fleet state on VM4"), vm4_password)
        payload = json.loads(_extract_json_payload(sync_out))
        if start_greenbone_wave:
            wave_cmd = (
                f"cd {shlex.quote(REMOTE_ROOT)} && "
                f"{shlex.quote(VM4_WEB_PYTHON)} - <<'PY'\n"
                "import os\n"
                "import runpy\n"
                "import sys\n"
                "from pathlib import Path\n"
                "for raw_line in Path('/etc/siem/web.env').read_text(encoding='utf-8').splitlines():\n"
                "    line = raw_line.strip()\n"
                "    if not line or line.startswith('#') or '=' not in raw_line:\n"
                "        continue\n"
                "    key, value = raw_line.split('=', 1)\n"
                "    key = key.strip()\n"
                "    if key:\n"
                "        os.environ.setdefault(key, value)\n"
                "sys.argv = [\n"
                "    'deploy/vuln/rdegon_greenbone_start_wave.py',\n"
                "    '--limit', '100',\n"
                "    '--wait-seconds', '180',\n"
                "    '--import-limit', '50',\n"
                "]\n"
                "runpy.run_path('deploy/vuln/rdegon_greenbone_start_wave.py', run_name='__main__')\n"
                "PY"
            )
            code, out, err = _run_sudo(client, wave_cmd, sudo_password=vm4_password)
            wave_out = _strip_sudo_echo(_require_success(code, out, err, "Unable to run Greenbone start wave"), vm4_password)
            payload["greenbone_wave"] = json.loads(_extract_json_payload(wave_out))
        return payload
    finally:
        client.close()


def main() -> int:
    _stdout_setup()
    parser = argparse.ArgumentParser(description="Deploy Proxmox-backed fleet monitoring and pilot services.")
    parser.add_argument("--skip-vm4-sync", action="store_true")
    parser.add_argument("--skip-greenbone-wave", action="store_true")
    args = parser.parse_args()

    proxmox_host = _env("SIEM_PROXMOX_HOST", PROXMOX_HOST)
    proxmox_user = _env("SIEM_PROXMOX_USER", "root")
    proxmox_password = _required_env("SIEM_PROXMOX_PASSWORD")
    proxmox = _connect(proxmox_host, proxmox_user, proxmox_password)
    vm4_password = _required_env("SIEM_VM4_PASSWORD")
    results: dict[str, Any] = {"guests": []}
    try:
        _install_proxmox_host_housekeeping(proxmox)
        _set_navidrome_hostname(proxmox)
        for spec in GUESTS:
            _install_common_monitoring_bundle(proxmox, spec)
            if spec.needs_docker and spec.vmid not in {123, 125}:
                _ensure_docker(proxmox, spec)
            if spec.needs_navidrome:
                _ensure_navidrome(proxmox, spec)
            if spec.needs_nmap_exporter:
                _deploy_nmap_exporter(proxmox, spec)
            if spec.vmid == 123:
                _deploy_pilot_gitea(proxmox, spec)
            if spec.vmid == 125:
                _deploy_pilot_valkey(proxmox, spec)
            if spec.needs_openvas_log:
                _wire_openvas_logs(proxmox, spec)
            if spec.needs_openclaw:
                _deploy_openclaw_runtime(proxmox, spec)
            results["guests"].append({"vmid": spec.vmid, "name": spec.name, "status": "ok"})
    finally:
        proxmox.close()
    if not args.skip_vm4_sync:
        results["vm4"] = _sync_vm4_runtime(
            vm4_password,
            proxmox_host=proxmox_host,
            proxmox_user=proxmox_user,
            proxmox_password=proxmox_password,
            start_greenbone_wave=not args.skip_greenbone_wave,
        )
    print(json.dumps(results, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
