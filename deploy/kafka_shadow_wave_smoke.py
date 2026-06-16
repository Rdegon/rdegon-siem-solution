from __future__ import annotations

import json
import os
import posixpath
import secrets
import shlex
import ssl
import sys
import time
from dataclasses import dataclass
from http.cookiejar import CookieJar
from pathlib import Path
from urllib.parse import urlencode
from urllib.request import HTTPCookieProcessor, HTTPSHandler, Request, build_opener

import paramiko


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REMOTE_ROOT = "/opt/siem/siem-solution"


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


def _connect_client(host: str, user: str, password: str, *, attempts: int = 5, delay_seconds: float = 3.0) -> paramiko.SSHClient:
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
            print(f"kafka_shadow_wave_smoke ssh retry host={host} attempt={attempt}/{attempts} error={exc}")
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


def _mkdir_remote(sftp: paramiko.SFTPClient, path: str) -> None:
    parts = [part for part in path.split("/") if part]
    current = ""
    for part in parts:
        current = f"{current}/{part}"
        try:
            sftp.stat(current)
        except OSError:
            sftp.mkdir(current)


def _upload_file(
    client: paramiko.SSHClient,
    sftp: paramiko.SFTPClient,
    *,
    local_rel: str,
    remote_root: str,
    sudo_password: str,
    mode: str = "0755",
) -> None:
    local_path = ROOT / local_rel
    if not local_path.exists():
        raise FileNotFoundError(local_path)
    remote_path = posixpath.join(remote_root.rstrip("/"), local_rel.replace("\\", "/"))
    temp_path = f"/tmp/{Path(remote_path).name}.{secrets.token_hex(4)}"
    _mkdir_remote(sftp, posixpath.dirname(temp_path))
    sftp.put(str(local_path), temp_path)
    code, out, err = _run_command(
        client,
        f"install -D -m {mode} {temp_path} {remote_path} && rm -f {temp_path}",
        sudo_password=sudo_password,
        use_sudo=True,
    )
    if code != 0:
        raise RuntimeError(f"Unable to install {remote_path}: {err.strip() or out.strip()}")


def _run_remote_smoke(client: paramiko.SSHClient, *, remote_root: str, script_rel: str, env: dict[str, str]) -> None:
    env_prefix = " ".join(f"{key}={shlex.quote(value)}" for key, value in env.items())
    command = f"cd {shlex.quote(remote_root)} && {env_prefix} python3 {shlex.quote(script_rel)}"
    code, out, err = _run_command(client, command)
    if out.strip():
        print(out, end="")
    if code != 0:
        raise RuntimeError(f"Remote smoke failed for {script_rel}: {err.strip()}")


def _run_node_smoke(host: HostSpec, *, remote_root: str, script_rel: str, env: dict[str, str]) -> None:
    client = _connect_client(host.host, host.user, host.password)
    sftp = client.open_sftp()
    try:
        _upload_file(client, sftp, local_rel=script_rel, remote_root=remote_root, sudo_password=host.password)
        _run_remote_smoke(client, remote_root=remote_root, script_rel=script_rel, env=env)
    finally:
        sftp.close()
        client.close()


def _assert_transport_green(base_url: str, username: str, password: str, *, attempts: int = 12, delay_seconds: float = 10.0) -> None:
    client = Client(base_url)
    client.request("/auth/login")
    login_payload = urlencode({"username": username, "password": password}).encode("utf-8")
    code, _ = client.request(
        "/auth/login",
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data=login_payload,
    )
    if code != 200:
        raise RuntimeError(f"Unable to authenticate to {base_url}: {code}")
    last_payload: dict[str, object] = {}
    for attempt in range(1, attempts + 1):
        code, body = client.request("/api/health/transport")
        if code != 200:
            raise RuntimeError(f"/api/health/transport returned {code}")
        last_payload = json.loads(body)
        if bool(last_payload.get("healthy")) and bool(last_payload.get("shadow_pipeline_healthy")) and str(last_payload.get("shadow_pipeline_status") or "") == "healthy":
            print("transport_shadow_status=healthy")
            return
        if attempt < attempts:
            time.sleep(delay_seconds)
    raise RuntimeError(f"Transport health did not turn green after retries: {last_payload}")


def main() -> int:
    remote_root = _required_env("SIEM_REMOTE_ROOT", default=DEFAULT_REMOTE_ROOT)
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
    _run_node_smoke(
        vm1,
        remote_root=remote_root,
        script_rel="deploy/vm1_kafka_shadow_smoke.py",
        env={
            "SIEM_VM1_PASSWORD": vm1.password,
            "SIEM_VM1_EXPECT_HOST": _required_env("SIEM_VM1_EXPECT_HOST", default="siem-ingest"),
        },
    )
    _run_node_smoke(
        vm3,
        remote_root=remote_root,
        script_rel="deploy/vm3_kafka_shadow_writer_smoke.py",
        env={
            "SIEM_VM3_PASSWORD": vm3.password,
            "SIEM_VM3_EXPECT_HOST": _required_env("SIEM_VM3_EXPECT_HOST", default="siem-storage"),
            "SIEM_KAFKA_REQUIRE_SHADOW_FLOW": "1",
        },
    )
    _assert_transport_green(
        _resolve_base_url(),
        _required_env("SIEM_WEB_ADMIN_USER"),
        _required_env("SIEM_WEB_ADMIN_PASSWORD"),
    )
    print("smoke=success")
    return 0


if __name__ == "__main__":
    sys.exit(main())
