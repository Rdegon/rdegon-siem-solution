from __future__ import annotations

import os
import shlex
import sys
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
    raise RuntimeError(f"Unable to connect to {host}: {last_error}")


def _run_command(client: paramiko.SSHClient, command: str) -> tuple[int, str, str]:
    stdin, stdout, stderr = client.exec_command(command, get_pty=True)
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    code = stdout.channel.recv_exit_status()
    return code, out, err


def main() -> int:
    vm5 = HostSpec(
        host=_required_env("SIEM_VM5_HOST", default="192.168.1.40"),
        user=_required_env("SIEM_VM5_USER", default="rdegon"),
        password=_required_env("SIEM_VM5_PASSWORD"),
    )
    remote_root = _required_env("SIEM_VM5_BASE_DIR", default="/opt/siem/siem-solution")
    expected_host = _required_env("SIEM_VM5_EXPECT_HOST", default="siem-transport")
    runner_service = _required_env("SIEM_VM5_RUNNER_SERVICE", default="actions.runner.Rdegon-siem-solution.siem-vm5.service")

    client = _connect_client(vm5.host, vm5.user, vm5.password)
    try:
        processing_cmd = (
            f"cd {shlex.quote(remote_root)} && "
            f"SIEM_VM5_PASSWORD={shlex.quote(vm5.password)} "
            f"SIEM_VM5_EXPECT_HOST={shlex.quote(expected_host)} "
            "SIEM_VM5_ENABLE_PROCESSING=1 "
            "python3 deploy/vm5_processing_smoke.py"
        )
        code, out, err = _run_command(client, processing_cmd)
        if out.strip():
            print(out, end="")
        if code != 0:
            raise RuntimeError(f"VM5 processing smoke failed: {err.strip()}")

        kafka_cmd = (
            f"cd {shlex.quote(remote_root)} && "
            f"SIEM_NODE_PASSWORD={shlex.quote(vm5.password)} "
            f"SIEM_KAFKA_EXPECT_HOST={shlex.quote(expected_host)} "
            "python3 deploy/kafka_wave_smoke.py"
        )
        code, out, err = _run_command(client, kafka_cmd)
        if out.strip():
            print(out, end="")
        if code != 0:
            raise RuntimeError(f"VM5 Kafka smoke failed: {err.strip()}")

        code, out, err = _run_command(client, f"systemctl is-active ssh qemu-guest-agent {shlex.quote(runner_service)} || true")
        states = [line.strip() for line in out.splitlines() if line.strip()]
        if states != ["active", "active", "active"]:
            raise RuntimeError(f"VM5 runner/service state unexpected: {states} stderr={err.strip()}")
        code, out, err = _run_command(client, "systemctl is-active actions.runner.Rdegon-siem-solution.siem-vm2.service || true")
        duplicate_runner_state = next((line.strip() for line in out.splitlines() if line.strip()), "")
        if duplicate_runner_state not in {"inactive", "unknown", "failed", ""}:
            raise RuntimeError(f"VM5 still runs duplicated VM2 runner service: {duplicate_runner_state} stderr={err.strip()}")

        print("smoke=success")
        return 0
    finally:
        client.close()


if __name__ == "__main__":
    sys.exit(main())
