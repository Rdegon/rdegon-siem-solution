from __future__ import annotations

import json
import os
import shlex
import sys
import time
import urllib.request
from dataclasses import dataclass

import paramiko


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
            time.sleep(delay_seconds)
    raise RuntimeError(f"Unable to connect to {host}: {last_error}")


def _run_command(client: paramiko.SSHClient, command: str) -> tuple[int, str, str]:
    stdin, stdout, stderr = client.exec_command(command, get_pty=True)
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    code = stdout.channel.recv_exit_status()
    return code, out, err


def _qm_status(client: paramiko.SSHClient, vmid: str) -> str:
    code, out, err = _run_command(client, f"qm status {shlex.quote(vmid)}")
    if code != 0:
        raise RuntimeError(f"qm status failed for {vmid}: {err.strip()}")
    for raw_line in out.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if "status:" in line:
            return line.split("status:", 1)[1].strip()
        if line in {"running", "stopped", "paused"}:
            return line
    raise RuntimeError(f"Unable to parse qm status for {vmid}: {out!r}")


def _qm_guest_exec_text(client: paramiko.SSHClient, vmid: str, command: str) -> str:
    code, out, err = _run_command(client, f"qm guest exec {shlex.quote(vmid)} -- bash -lc {shlex.quote(command)}")
    if code != 0:
        raise RuntimeError(f"qm guest exec failed for {vmid}: {err.strip()}")
    payload = json.loads(out)
    return str(payload.get("out-data") or "")


def _parse_runner_status(payload: dict[str, object], runner_name: str) -> str:
    for runner in payload.get("runners", []):
        if str(runner.get("name") or "").strip() == runner_name:
            return str(runner.get("status") or "").strip().lower()
    return "missing"


def _github_runners(repository: str, token: str) -> dict[str, object]:
    request = urllib.request.Request(
        f"https://api.github.com/repos/{repository}/actions/runners",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        body = response.read().decode("utf-8", errors="replace").strip()
    return json.loads(body) if body else {}


def main() -> int:
    proxmox = HostSpec(
        host=_required_env("SIEM_PROXMOX_HOST"),
        user=_required_env("SIEM_PROXMOX_USER"),
        password=_required_env("SIEM_PROXMOX_PASSWORD"),
    )
    vm5 = HostSpec(
        host=_required_env("SIEM_VM5_HOST", default="192.168.1.40"),
        user=_required_env("SIEM_VM5_USER", default="rdegon"),
        password=_required_env("SIEM_VM5_PASSWORD"),
    )
    vmid = _required_env("SIEM_VM5_VMID", default="108")
    expected_host = _required_env("SIEM_VM5_HOSTNAME", default="siem-transport")
    runner_name = _required_env("SIEM_VM5_RUNNER_NAME", default="siem-vm5")

    proxmox_client = _connect_client(proxmox.host, proxmox.user, proxmox.password)
    try:
        status = _qm_status(proxmox_client, vmid)
        if status != "running":
            raise RuntimeError(f"VM5 is not running: {status}")
        guest_text = _qm_guest_exec_text(
            proxmox_client,
            vmid,
            "hostname; echo ---; cat /etc/netplan/01-siem.yaml; echo ---; systemctl is-active qemu-guest-agent ssh || true",
        )
    finally:
        proxmox_client.close()

    if expected_host not in guest_text:
        raise RuntimeError(f"VM5 guest hostname mismatch: {guest_text!r}")
    if "192.168.1.40/24" not in guest_text:
        raise RuntimeError("VM5 guest netplan does not include 192.168.1.40/24")
    if guest_text.count("active") < 2:
        raise RuntimeError(f"VM5 guest services are not active: {guest_text!r}")

    vm5_client = _connect_client(vm5.host, vm5.user, vm5.password)
    try:
        code, out, err = _run_command(vm5_client, "hostname; echo ---; systemctl is-active qemu-guest-agent ssh || true")
        if code != 0:
            raise RuntimeError(f"VM5 SSH smoke failed: {err.strip()}")
        if expected_host not in out:
            raise RuntimeError(f"VM5 SSH hostname mismatch: {out!r}")
        if out.count("active") < 2:
            raise RuntimeError(f"VM5 SSH service state unhealthy: {out!r}")
    finally:
        vm5_client.close()

    github_repository = str(os.getenv("GITHUB_REPOSITORY", "") or "").strip()
    github_token = str(os.getenv("GITHUB_TOKEN", "") or "").strip()
    if github_repository and github_token:
        payload = _github_runners(github_repository, github_token)
        runner_status = _parse_runner_status(payload, runner_name)
        if runner_status != "online":
            raise RuntimeError(f"VM5 runner is not online: {runner_status}")
        print(f"vm5_runner={runner_name} status={runner_status}")

    print(f"vm5_vmid={vmid}")
    print(f"vm5_host={vm5.host}")
    print("smoke=success")
    return 0


if __name__ == "__main__":
    sys.exit(main())
