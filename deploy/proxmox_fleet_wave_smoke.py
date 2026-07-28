from __future__ import annotations

import json
import os
import shlex
import ssl
import sys
from dataclasses import dataclass
from http.cookiejar import CookieJar
from urllib.parse import urlencode
from urllib.request import HTTPCookieProcessor, HTTPSHandler, Request, build_opener

import paramiko


PROXMOX_HOST = "192.168.3.101"


@dataclass(frozen=True)
class GuestCheck:
    vmid: int
    guest_type: str
    name: str
    command: str


CHECKS: tuple[GuestCheck, ...] = (
    GuestCheck(
        120,
        "lxc",
        "nextcloud-siem",
        "systemctl is-active siem-host-runtime-agent.timer apache2 mariadb redis-server cron rsyslog "
        "&& curl -kfsS -o /dev/null https://127.0.0.1/",
    ),
    GuestCheck(
        121,
        "lxc",
        "navidrome-01",
        "systemctl is-active siem-host-runtime-agent.timer navidrome rsyslog "
        "&& curl -fsS http://127.0.0.1:4533/ >/dev/null",
    ),
    GuestCheck(122, "qemu", "vuln-mgr-01", "systemctl is-active siem-host-runtime-agent.timer docker auditd rsyslog && docker ps --format '{{.Names}}' | grep -qx openvas"),
    GuestCheck(123, "qemu", "pilot-web-01", "systemctl is-active siem-host-runtime-agent.timer docker pilot-gitea auditd rsyslog && curl -fsS http://127.0.0.1:3000/ >/dev/null"),
    GuestCheck(124, "qemu", "pilot-db-01", "systemctl is-active siem-host-runtime-agent.timer postgresql@14-main auditd rsyslog"),
    GuestCheck(125, "qemu", "pilot-cache-01", "systemctl is-active siem-host-runtime-agent.timer docker pilot-valkey auditd rsyslog && docker exec pilot-valkey sh -lc 'valkey-cli ping | grep -q PONG'"),
    GuestCheck(
        127,
        "qemu",
        "soc-ndr-01",
        "systemctl is-active opensearch arkimecapture.service arkimeviewer.service "
        "siem-zeek@enp6s19.service siem-zeek@enp6s20.service siem-zeek@enp6s21.service "
        "siem-zeek@enp6s22.service siem-zeek@enp6s23.service "
        "siem-security-sensor-forwarder@zeek.service "
        "siem-security-sensor-forwarder@arkime.service "
        "siem-arkime-metrics-exporter.timer",
    ),
    GuestCheck(
        128,
        "lxc",
        "soc-dfir-01",
        "systemctl is-active velociraptor.service siem-velociraptor-flow-exporter.timer "
        "siem-security-sensor-forwarder@velociraptor.service",
    ),
    GuestCheck(
        129,
        "lxc",
        "soc-analysis-01",
        "systemctl is-active clamav-daemon siem-clamav-update.timer "
        "siem-static-analysis.service siem-security-sensor-forwarder@static-analysis.service",
    ),
    GuestCheck(
        130,
        "qemu",
        "gamepanel-01",
        "systemctl is-active docker wings nginx siem-security-sensor-forwarder@falco.service "
        "&& (systemctl is-active --quiet falco-modern-bpf.service "
        "|| systemctl is-active --quiet falco-bpf.service "
        "|| systemctl is-active --quiet falco-kmod.service "
        "|| systemctl is-active --quiet falco.service)",
    ),
    GuestCheck(
        131,
        "qemu",
        "soc-ti-01",
        "systemctl is-active docker siem-misp-exporter.timer siem-misp-feed-cache.timer "
        "siem-security-sensor-forwarder@misp.service",
    ),
    GuestCheck(
        132,
        "lxc",
        "soc-pki-01",
        "systemctl is-active step-ca.service siem-journal-event-exporter@step-ca.timer "
        "siem-security-sensor-forwarder@step-ca.service",
    ),
    GuestCheck(
        133,
        "lxc",
        "soc-evidence-01",
        "systemctl is-active minio.service siem-minio-audit-receiver.service "
        "siem-minio-certificate-renew.timer siem-security-sensor-forwarder@minio.service",
    ),
)

EXPECTED_STOPPED_QEMU: tuple[tuple[int, str], ...] = (
    (101, "win-test"),
    (126, "openclaw-gateway"),
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
        timeout=20,
        banner_timeout=20,
        auth_timeout=20,
        look_for_keys=False,
        allow_agent=False,
    )
    return client


def _run(client: paramiko.SSHClient, command: str) -> tuple[int, str, str]:
    stdin, stdout, stderr = client.exec_command(command)
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    return stdout.channel.recv_exit_status(), out, err


def _require_success(code: int, out: str, err: str, message: str) -> str:
    if code != 0:
        raise RuntimeError(f"{message}\nstdout={out}\nstderr={err}")
    return out


def _guest_exec(proxmox: paramiko.SSHClient, check: GuestCheck) -> str:
    if check.guest_type == "lxc":
        code, out, err = _run(proxmox, f"pct exec {check.vmid} -- bash -lc {shlex.quote(check.command)}")
        return _require_success(code, out, err, f"Smoke failed on {check.name}")
    code, out, err = _run(proxmox, f"qm guest exec {check.vmid} --timeout 240 -- /bin/bash -lc {shlex.quote(check.command)}")
    payload = json.loads(_require_success(code, out, err, f"Smoke failed on {check.name}") or "{}")
    exitcode = int(payload.get("exitcode") or 0)
    stdout = str(payload.get("out-data") or "")
    stderr = str(payload.get("err-data") or "")
    if exitcode != 0:
        raise RuntimeError(f"Smoke failed on {check.name}\nstdout={stdout}\nstderr={stderr}")
    return stdout


def _require_qemu_stopped(proxmox: paramiko.SSHClient, vmid: int, name: str) -> None:
    code, out, err = _run(proxmox, f"qm status {vmid}")
    state = _require_success(code, out, err, f"Unable to read state for {name}").strip()
    if state != "status: stopped":
        raise RuntimeError(f"{name} must remain stopped, got {state or 'unknown'}")


class Client:
    def __init__(self, base_url: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.jar = CookieJar()
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        self.opener = build_opener(HTTPSHandler(context=context), HTTPCookieProcessor(self.jar))

    def request(self, path: str, *, method: str = "GET", headers: dict[str, str] | None = None, data: bytes | None = None) -> tuple[int, str]:
        request = Request(f"{self.base_url}{path}", data=data, headers=headers or {}, method=method)
        with self.opener.open(request, timeout=20) as response:
            return response.status, response.read().decode("utf-8", errors="replace")


def _api_checks() -> dict[str, object]:
    base_url = _env("SIEM_WEB_BASE_URL", "https://192.168.3.102")
    username = _required_env("SIEM_WEB_ADMIN_USER")
    password = _required_env("SIEM_WEB_ADMIN_PASSWORD")
    client = Client(base_url)
    client.request("/auth/login")
    status, _ = client.request(
        "/auth/login",
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data=urlencode(
            {
                "username": username,
                "password": password,
                "auth_flow": "break_glass",
                "break_glass_reason": "proxmox fleet smoke",
                "break_glass_minutes": "15",
            }
        ).encode("utf-8"),
    )
    if status != 200:
        raise RuntimeError(f"Unable to login to {base_url}: {status}")
    _, fleet_body = client.request("/api/sources/proxmox-fleet?limit=500")
    _, runtime_body = client.request("/api/vuln/runtime?days=14")
    _, hosts_body = client.request("/api/health/hosts/runtime?hours=6&limit=20")
    fleet = json.loads(fleet_body)
    runtime = json.loads(runtime_body)
    hosts = json.loads(hosts_body)
    return {
        "fleet_metrics": fleet.get("metrics") or {},
        "fleet_sync": fleet.get("sync") or {},
        "vuln_fleet_coverage": runtime.get("fleet_coverage") or {},
        "host_runtime_metrics": hosts.get("metrics") or {},
    }


def main() -> int:
    _stdout_setup()
    proxmox = _connect(_env("SIEM_PROXMOX_HOST", PROXMOX_HOST), _env("SIEM_PROXMOX_USER", "root"), _required_env("SIEM_PROXMOX_PASSWORD"))
    results = {"guests": [], "api": {}}
    try:
        for check in CHECKS:
            _guest_exec(proxmox, check)
            results["guests"].append({"vmid": check.vmid, "name": check.name, "status": "ok"})
        for vmid, name in EXPECTED_STOPPED_QEMU:
            _require_qemu_stopped(proxmox, vmid, name)
            results["guests"].append({"vmid": vmid, "name": name, "status": "expected_stopped"})
    finally:
        proxmox.close()
    results["api"] = _api_checks()
    print(json.dumps({"smoke": "success", **results}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
