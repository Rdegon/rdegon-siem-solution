from __future__ import annotations

import json
import os
import shlex
import ssl
import sys
import urllib.request
from dataclasses import dataclass
from http.cookiejar import CookieJar
from urllib.parse import urlencode
from urllib.request import HTTPCookieProcessor, HTTPSHandler, Request, build_opener

try:
    import paramiko
except ModuleNotFoundError:  # pragma: no cover - exercised in unit-test import paths
    paramiko = None  # type: ignore[assignment]

DEFAULT_EVENTS_BOOTSTRAP_LOOKBACK_HOURS = 6


@dataclass(frozen=True)
class HostSpec:
    host: str
    user: str
    password: str


def _required_env(name: str, *, default: str | None = None) -> str:
    value = str(os.getenv(name, default or "") or "").strip()
    if value:
        return value
    raise SystemExit(f"Missing required environment variable: {name}")


def _split_ssh_host_port(host: str) -> tuple[str, int]:
    value = str(host or "").strip()
    if value.count(":") == 1:
        candidate_host, candidate_port = value.rsplit(":", 1)
        if candidate_host and candidate_port.isdigit():
            return candidate_host, 22 if candidate_port == "8006" else int(candidate_port)
    return value, 22


def _connect_client(host: str, user: str, password: str) -> paramiko.SSHClient:
    if paramiko is None:
        raise RuntimeError("paramiko is required to execute storage HA smoke")
    connect_host, connect_port = _split_ssh_host_port(host)
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(connect_host, port=connect_port, username=user, password=password, timeout=20, banner_timeout=20, auth_timeout=20, look_for_keys=False, allow_agent=False)
    return client


def _run_command(client: paramiko.SSHClient, command: str, *, sudo_password: str = "", use_sudo: bool = False) -> tuple[int, str, str]:
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
    return "\n".join(line for line in str(text or "").splitlines() if line.strip() != sudo_password)


def _last_nonempty_line(text: str) -> str:
    for line in reversed(str(text or "").splitlines()):
        if line.strip():
            return line.strip()
    return ""


def _events_bootstrap_lookback_hours() -> int:
    raw = str(os.getenv("SIEM_CH_STANDBY_BOOTSTRAP_EVENTS_LOOKBACK_HOURS") or "").strip()
    if not raw:
        return DEFAULT_EVENTS_BOOTSTRAP_LOOKBACK_HOURS
    try:
        return max(1, min(168, int(raw)))
    except ValueError:
        return DEFAULT_EVENTS_BOOTSTRAP_LOOKBACK_HOURS


def _events_count_query() -> str:
    lookback_hours = _events_bootstrap_lookback_hours()
    return f"SELECT count() FROM siem.events WHERE ts >= now() - INTERVAL {lookback_hours} HOUR FORMAT TabSeparated"


def _parse_env_text(text: str) -> dict[str, str]:
    payload: dict[str, str] = {}
    for raw_line in str(text or "").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        payload[key.strip()] = value.strip()
    return payload


def _storage_ha_payload(payload: dict[str, object]) -> dict[str, object]:
    nested = payload.get("storage_ha")
    if isinstance(nested, dict):
        return nested
    return dict(payload)


def _json_get(url: str) -> dict[str, object]:
    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=20) as response:
        return json.loads(response.read().decode("utf-8"))


class WebClient:
    def __init__(self, base_url: str) -> None:
        self.base_url = str(base_url or "").rstrip("/")
        self.jar = CookieJar()
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        self.opener = build_opener(HTTPSHandler(context=context), HTTPCookieProcessor(self.jar))

    def _csrf_token(self) -> str:
        for cookie in self.jar:
            if cookie.name == "csrf_token":
                return cookie.value
        return ""

    def request(self, path: str, *, method: str = "GET", headers: dict[str, str] | None = None, data: bytes | None = None) -> tuple[int, str]:
        prepared_headers = dict(headers or {})
        if method.upper() not in {"GET", "HEAD", "OPTIONS"}:
            token = self._csrf_token()
            if token and "X-CSRF-Token" not in prepared_headers:
                prepared_headers["X-CSRF-Token"] = token
        request = Request(f"{self.base_url}{path}", data=data, headers=prepared_headers, method=method)
        with self.opener.open(request, timeout=20) as response:
            return response.status, response.read().decode("utf-8", errors="replace")

    def login(self, username: str, password: str) -> None:
        code, _ = self.request("/auth/login")
        if code != 200:
            raise RuntimeError(f"Unable to open login page: {code}")
        payload = urlencode({"username": username, "password": password}).encode("utf-8")
        code, _ = self.request(
            "/auth/login",
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data=payload,
        )
        if code != 200:
            raise RuntimeError(f"Login failed with status {code}")


def main() -> int:
    vm1 = HostSpec(_required_env("SIEM_VM1_HOST"), _required_env("SIEM_VM1_USER"), _required_env("SIEM_VM1_PASSWORD"))
    vm3 = HostSpec(_required_env("SIEM_VM3_HOST"), _required_env("SIEM_VM3_USER"), _required_env("SIEM_VM3_PASSWORD"))
    vm4 = HostSpec(_required_env("SIEM_VM4_HOST"), _required_env("SIEM_VM4_USER"), _required_env("SIEM_VM4_PASSWORD"))
    vm5 = HostSpec(_required_env("SIEM_VM5_HOST"), _required_env("SIEM_VM5_USER"), _required_env("SIEM_VM5_PASSWORD"))
    proxmox = HostSpec(_required_env("SIEM_PROXMOX_HOST"), _required_env("SIEM_PROXMOX_USER"), _required_env("SIEM_PROXMOX_PASSWORD"))
    vm2_vmid = _required_env("SIEM_VM2_VMID", default="105")
    web_base_url = _required_env("SIEM_WEB_BASE_URL")
    web_admin_user = _required_env("SIEM_WEB_ADMIN_USER")
    web_admin_password = _required_env("SIEM_WEB_ADMIN_PASSWORD")

    vm1_client = _connect_client(vm1.host, vm1.user, vm1.password)
    vm3_client = _connect_client(vm3.host, vm3.user, vm3.password)
    vm4_client = _connect_client(vm4.host, vm4.user, vm4.password)
    vm5_client = _connect_client(vm5.host, vm5.user, vm5.password)
    proxmox_client = _connect_client(proxmox.host, proxmox.user, proxmox.password)
    web_client = WebClient(web_base_url)
    try:
        web_client.login(web_admin_user, web_admin_password)
        code, out, err = _run_command(vm4_client, "sudo -u postgres psql -tAc 'SELECT pg_is_in_recovery()'", sudo_password=vm4.password, use_sudo=True)
        if code != 0 or _last_nonempty_line(_strip_sudo_echo(out, vm4.password)) != "f":
            raise RuntimeError(f"VM4 Postgres primary verification failed: stdout={out.strip()} stderr={err.strip()}")
        code, out, err = _run_command(vm1_client, "sudo -u postgres psql -tAc 'SELECT pg_is_in_recovery()'", sudo_password=vm1.password, use_sudo=True)
        if code != 0 or _last_nonempty_line(_strip_sudo_echo(out, vm1.password)) != "t":
            raise RuntimeError(f"VM1 Postgres standby verification failed: stdout={out.strip()} stderr={err.strip()}")
        code, out, err = _run_command(vm4_client, "cat /etc/siem/storage-ha.env", sudo_password=vm4.password, use_sudo=True)
        if code != 0:
            raise RuntimeError(f"Unable to read storage-ha env: {err.strip()}")
        storage_env = _parse_env_text(_strip_sudo_echo(out, vm4.password))
        admin_user = str(storage_env.get("SIEM_MONGO_ADMIN_USER") or "").strip()
        admin_password = str(storage_env.get("SIEM_MONGO_ADMIN_PASSWORD") or "").strip()
        replica_set = str(storage_env.get("SIEM_MONGO_REPLICA_SET") or "siem-rs").strip() or "siem-rs"
        mongo_uri = f"mongodb://{admin_user}:{admin_password}@127.0.0.1:27017/admin?replicaSet={replica_set}"
        code, out, err = _run_command(vm4_client, f"mongosh {shlex.quote(mongo_uri)} --quiet --eval 'JSON.stringify(rs.status().members.map(m => ({{name: m.name, stateStr: m.stateStr}})))'", sudo_password=vm4.password, use_sudo=True)
        if code != 0:
            raise RuntimeError(f"Unable to query Mongo replica-set: stdout={out.strip()} stderr={err.strip()}")
        members = json.loads(_strip_sudo_echo(str(out or "").strip(), vm4.password) or "[]")
        if not any(str(item.get("stateStr") or "") == "PRIMARY" for item in members):
            raise RuntimeError(f"Mongo replica-set has no PRIMARY: {members}")
        if sum(1 for item in members if str(item.get("stateStr") or "") == "SECONDARY") < 2:
            raise RuntimeError(f"Mongo replica-set lacks secondaries: {members}")
        code, out, err = _run_command(vm5_client, "systemctl is-active clickhouse-server siem-writer-standby siem-clickhouse-standby-sync.timer", sudo_password=vm5.password, use_sudo=True)
        states = [line.strip() for line in _strip_sudo_echo(out, vm5.password).splitlines() if line.strip()]
        if code != 0 or states != ["active", "active", "active"]:
            raise RuntimeError(f"VM5 standby services unhealthy: {states} stderr={err.strip()}")
        recent_events_query = _events_count_query()
        code, out, err = _run_command(vm3_client, f"source /etc/siem/storage.env && clickhouse-client --host \"$SIEM_CH_HOST\" --port \"$SIEM_CH_PORT\" --user \"$SIEM_CH_USER\" --password \"$SIEM_CH_PASSWORD\" --query {shlex.quote(recent_events_query)}", sudo_password=vm3.password, use_sudo=True)
        primary_events = int(_last_nonempty_line(_strip_sudo_echo(out, vm3.password)) or 0)
        code, out, err = _run_command(vm5_client, f"source /etc/siem/storage-standby.env && clickhouse-client --host \"$SIEM_CH_HOST\" --port \"$SIEM_CH_PORT\" --user \"$SIEM_CH_USER\" --password \"$SIEM_CH_PASSWORD\" --query {shlex.quote(recent_events_query)}", sudo_password=vm5.password, use_sudo=True)
        standby_events = int(_last_nonempty_line(_strip_sudo_echo(out, vm5.password)) or 0)
        if standby_events <= 0 or standby_events < int(primary_events * 0.8):
            raise RuntimeError(
                "Standby ClickHouse appears under-seeded for recent window: "
                f"lookback_hours={_events_bootstrap_lookback_hours()} primary={primary_events} standby={standby_events}"
            )
        for client, password, label in ((vm1_client, vm1.password, "vm1"), (vm3_client, vm3.password, "vm3"), (vm5_client, vm5.password, "vm5")):
            code, out, err = _run_command(client, "systemctl is-active redis-server || true", sudo_password=password, use_sudo=True)
            state = _strip_sudo_echo(out, password).strip()
            if state not in {"inactive", "unknown", "failed", ""}:
                raise RuntimeError(f"Redis still active on {label}: {state}")
        code, out, err = _run_command(proxmox_client, f"qm guest exec {shlex.quote(vm2_vmid)} -- bash -lc {shlex.quote('systemctl is-active redis-server || true')}")
        if code != 0:
            raise RuntimeError(f"Unable to query VM2 Redis state: {err.strip()}")
        vm2_state = json.loads(out).get("out-data", "").strip()
        if vm2_state not in {"inactive", "unknown", "failed", ""}:
            raise RuntimeError(f"Redis still active on VM2: {vm2_state}")
        status, body = web_client.request("/api/health/storage-ha")
        if status != 200:
            raise RuntimeError(f"Storage HA endpoint returned {status}")
        storage_ha_payload = json.loads(body)
        storage_ha = _storage_ha_payload(storage_ha_payload)
        if not bool(storage_ha.get("clickhouse", {}).get("healthy")):
            raise RuntimeError(f"Storage HA endpoint reports ClickHouse unhealthy: {storage_ha_payload}")
        if not bool(storage_ha.get("postgres", {}).get("healthy")):
            raise RuntimeError(f"Storage HA endpoint reports Postgres unhealthy: {storage_ha_payload}")
        if not bool(storage_ha.get("mongo", {}).get("healthy")):
            raise RuntimeError(f"Storage HA endpoint reports Mongo unhealthy: {storage_ha_payload}")
        status, body = web_client.request("/api/health/transport")
        if status != 200:
            raise RuntimeError(f"Transport endpoint returned {status}")
        transport = json.loads(body)
        if str(transport.get("transport_backend") or "") != "kafka":
            raise RuntimeError(f"Transport backend regressed: {transport}")
        print(f"primary_events={primary_events}")
        print(f"standby_events={standby_events}")
        print("smoke=success")
        return 0
    finally:
        for client in (vm1_client, vm3_client, vm4_client, vm5_client, proxmox_client):
            client.close()


if __name__ == "__main__":
    sys.exit(main())
