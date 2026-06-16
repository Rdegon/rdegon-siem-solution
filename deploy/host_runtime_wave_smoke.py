from __future__ import annotations

import json
import os
import ssl
import sys
import time

import paramiko
from http.cookiejar import CookieJar
from urllib.parse import urlencode
from urllib.request import HTTPCookieProcessor, HTTPSHandler, Request, build_opener


HOSTS = (
    ("SIEM_VM1", "192.168.1.35", "siem-host-runtime-agent.timer"),
    ("SIEM_VM2", "192.168.1.37", "siem-host-runtime-agent.timer"),
    ("SIEM_VM3", "192.168.1.38", "siem-host-runtime-agent.timer"),
    ("SIEM_VM4", "192.168.1.39", "siem-host-runtime-agent.timer siem-host-runtime-monitor.timer"),
    ("SIEM_VM5", "192.168.1.40", "siem-host-runtime-agent.timer"),
)


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
            print(f"host_runtime_smoke_retry host={host} attempt={attempt}/{attempts} error={exc}")
            time.sleep(delay_seconds)
    raise RuntimeError(f"Unable to connect to {host}: {last_error}")


def _run(client: paramiko.SSHClient, command: str) -> str:
    stdin, stdout, stderr = client.exec_command(command)
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    code = stdout.channel.recv_exit_status()
    if code != 0:
        raise RuntimeError(f"{command}\nstdout={out}\nstderr={err}")
    return out


def _resolve_base_url() -> str:
    explicit = str(os.getenv("SIEM_WEB_BASE_URL", "") or "").strip()
    if explicit:
        return explicit.rstrip("/")
    vm4_host = str(os.getenv("SIEM_VM4_HOST", "") or "").strip()
    if vm4_host:
        return f"https://{vm4_host}".rstrip("/")
    return "https://192.168.1.39"


class Client:
    def __init__(self, base_url: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.jar = CookieJar()
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        self.opener = build_opener(HTTPSHandler(context=context), HTTPCookieProcessor(self.jar))

    def csrf_token(self) -> str:
        for cookie in self.jar:
            if cookie.name == "csrf_token":
                return cookie.value
        return ""

    def request(self, path: str, *, method: str = "GET", headers: dict[str, str] | None = None, data: bytes | None = None) -> tuple[int, str]:
        prepared_headers = dict(headers or {})
        if method.upper() not in {"GET", "HEAD", "OPTIONS"}:
            csrf_token = self.csrf_token()
            if csrf_token and "X-CSRF-Token" not in prepared_headers:
                prepared_headers["X-CSRF-Token"] = csrf_token
        request = Request(f"{self.base_url}{path}", data=data, headers=prepared_headers, method=method)
        with self.opener.open(request, timeout=20) as response:
            return response.status, response.read().decode("utf-8", errors="replace")


def _assert_api_green(*, expected_targets: int) -> None:
    username = _required_env("SIEM_WEB_ADMIN_USER")
    password = _required_env("SIEM_WEB_ADMIN_PASSWORD")
    client = Client(_resolve_base_url())
    client.request("/auth/login")
    login_payload = urlencode({"username": username, "password": password}).encode("utf-8")
    status, _ = client.request(
        "/auth/login",
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data=login_payload,
    )
    if status != 200:
        raise RuntimeError(f"Unable to authenticate to host runtime API: {status}")

    last_payload: dict[str, object] = {}
    for attempt in range(1, 13):
        status, body = client.request("/api/health/hosts/runtime?hours=6&limit=10")
        if status != 200:
            raise RuntimeError(f"/api/health/hosts/runtime returned {status}")
        last_payload = json.loads(body)
        metrics = dict(last_payload.get("metrics") or {})
        targets = list(last_payload.get("targets") or [])
        if (
            int(metrics.get("stale_targets") or 0) == 0
            and int(metrics.get("snapshot_events") or 0) >= expected_targets
            and len(targets) >= expected_targets
            and all(not bool(item.get("stale")) and str(item.get("last_seen_ts") or "").strip() for item in targets[:expected_targets])
        ):
            print(json.dumps({"host_runtime_api": "healthy", "metrics": metrics}, ensure_ascii=False))
            return
        if attempt < 12:
            time.sleep(10)
    raise RuntimeError(f"Host runtime API did not turn green after retries: {last_payload}")


def main() -> int:
    results = []
    for prefix, default_host, units in HOSTS:
        host = _required_env(f"{prefix}_HOST", default=default_host)
        user = _required_env(f"{prefix}_USER", default="rdegon")
        password = _required_env(f"{prefix}_PASSWORD")
        client = _connect(host, user, password)
        try:
            _run(client, f"systemctl is-active {units}")
            results.append({"host": host, "units": units.split(), "status": "active"})
        finally:
            client.close()
    _assert_api_green(expected_targets=len(HOSTS))
    print(json.dumps({"hosts": results, "smoke": "success"}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
