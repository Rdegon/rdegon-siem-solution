from __future__ import annotations

import json
import os
import shlex
import sys
import time

import paramiko


DEFAULT_VM3_VMID = "106"
DEFAULT_VM3_MEMORY_MIB = 28672
DEFAULT_VM3_BALLOON_MIB = 24576
DEFAULT_VM3_MAX_REPORTED_MEMORY_BYTES = DEFAULT_VM3_MEMORY_MIB * 1024 * 1024
DEFAULT_VM3_MIN_AVAILABLE_MEMORY_BYTES = 12 * 1024 * 1024 * 1024
REMOTE_STORAGE_UNITS = (
    "qemu-guest-agent",
    "clickhouse-server",
    "siem-writer",
    "siem-writer@2",
    "siem-stream-corr",
    "siem-batch-corr",
    "siem-alert-agg",
)


def _required_env(name: str, *, default: str | None = None) -> str:
    value = str(os.getenv(name) or default or "").strip()
    if value:
        return value
    raise SystemExit(f"Missing required environment variable: {name}")


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


def _connect_client(host: str, user: str, password: str) -> paramiko.SSHClient:
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


def _strip_sudo_echo(text: str, sudo_password: str) -> str:
    if not sudo_password:
        return text
    cleaned_lines: list[str] = []
    for raw_line in str(text or "").replace("\r", "\n").split("\n"):
        line = raw_line.strip("\x00")
        if line.strip() == sudo_password:
            continue
        cleaned_lines.append(line)
    return "\n".join(cleaned_lines)


def _parse_qm_config_value(config_output: str, key: str) -> str:
    prefix = f"{key}:"
    for raw_line in str(config_output or "").replace("\r", "\n").split("\n"):
        line = raw_line.strip()
        if line.startswith(prefix):
            return line.split(":", 1)[1].strip()
    return ""


def _parse_free_bytes(output: str) -> dict[str, int]:
    for raw_line in str(output or "").splitlines():
        line = raw_line.strip()
        if not line.startswith("Mem:"):
            continue
        parts = [part for part in line.split() if part]
        if len(parts) < 7:
            break
        return {
            "total": int(parts[1]),
            "used": int(parts[2]),
            "free": int(parts[3]),
            "shared": int(parts[4]),
            "buff_cache": int(parts[5]),
            "available": int(parts[6]),
        }
    raise ValueError(f"Unable to parse free -b output: {output}")


def _query_vm_status(proxmox: paramiko.SSHClient, vmid: str) -> dict[str, object]:
    code, out, err = _run_command(
        proxmox,
        f"pvesh get /nodes/pve/qemu/{shlex.quote(vmid)}/status/current --output-format json",
    )
    if code != 0:
        raise RuntimeError(f"Unable to query VM{vmid} status: {err.strip()}")
    return json.loads(str(out or "{}").strip() or "{}")


def main() -> int:
    vm3_host = _required_env("SIEM_VM3_HOST")
    vm3_user = _required_env("SIEM_VM3_USER")
    vm3_password = _required_env("SIEM_VM3_PASSWORD")
    proxmox_host = _required_env("SIEM_PROXMOX_HOST")
    proxmox_user = _required_env("SIEM_PROXMOX_USER")
    proxmox_password = _required_env("SIEM_PROXMOX_PASSWORD")
    vm3_vmid = _required_env("SIEM_VM3_VMID", default=DEFAULT_VM3_VMID)
    expected_balloon_mib = int(_required_env("SIEM_VM3_PROXMOX_BALLOON_MIB", default=str(DEFAULT_VM3_BALLOON_MIB)))
    max_reported_memory_bytes = int(
        _required_env(
            "SIEM_VM3_PROXMOX_MAX_REPORTED_MEMORY_BYTES",
            default=str(DEFAULT_VM3_MAX_REPORTED_MEMORY_BYTES),
        )
    )
    max_guest_total_bytes = int(_required_env("SIEM_VM3_MAX_GUEST_TOTAL_BYTES", default="0"))
    min_available_memory_bytes = int(
        _required_env("SIEM_VM3_MIN_AVAILABLE_MEMORY_BYTES", default=str(DEFAULT_VM3_MIN_AVAILABLE_MEMORY_BYTES))
    )

    proxmox = _connect_client(proxmox_host, proxmox_user, proxmox_password)
    guest = _connect_client(vm3_host, vm3_user, vm3_password)
    try:
        code, config_out, err = _run_command(proxmox, f"qm config {shlex.quote(vm3_vmid)}")
        if code != 0:
            raise RuntimeError(f"Unable to query VM{vm3_vmid} config: {err.strip()}")
        current_balloon = int(_parse_qm_config_value(config_out, "balloon") or 0)
        current_agent = _parse_qm_config_value(config_out, "agent")
        if current_agent != "1":
            raise RuntimeError(f"VM{vm3_vmid} does not have Proxmox guest agent enabled in config")
        if current_balloon != expected_balloon_mib:
            raise RuntimeError(f"Unexpected VM{vm3_vmid} balloon target: {current_balloon} != {expected_balloon_mib}")

        vm_status = {}
        for _ in range(6):
            vm_status = _query_vm_status(proxmox, vm3_vmid)
            host_reported_memory_bytes = int(vm_status.get("mem") or 0)
            if host_reported_memory_bytes <= max_reported_memory_bytes:
                break
            time.sleep(5)
        else:
            raise RuntimeError(
                f"VM{vm3_vmid} host-reported memory stayed above the ceiling: {host_reported_memory_bytes} > {max_reported_memory_bytes}"
            )

        code, out, err = _run_command(
            proxmox,
            f"qm guest exec {shlex.quote(vm3_vmid)} -- bash -lc {shlex.quote('hostname && systemctl is-active qemu-guest-agent')}",
        )
        if code != 0:
            raise RuntimeError(f"Proxmox guest exec failed for VM{vm3_vmid}: {err.strip()}")

        unit_clause = " ".join(REMOTE_STORAGE_UNITS)
        code, out, err = _run_command(guest, f"systemctl is-active {unit_clause}", sudo_password=vm3_password, use_sudo=True)
        active_out = _strip_sudo_echo(out, vm3_password)
        states = [line.strip() for line in active_out.splitlines() if line.strip()]
        if code != 0 or states != ["active"] * len(REMOTE_STORAGE_UNITS):
            raise RuntimeError(f"Unexpected VM3 storage/qga service state: stdout={states} stderr={err.strip()}")

        code, out, err = _run_command(guest, "free -b")
        if code != 0:
            raise RuntimeError(f"Unable to query VM3 memory: {err.strip()}")
        guest_memory = _parse_free_bytes(out)
        if max_guest_total_bytes > 0 and guest_memory["total"] > max_guest_total_bytes:
            raise RuntimeError(
                f"VM3 guest total memory stayed above the ceiling: {guest_memory['total']} > {max_guest_total_bytes}"
            )
        if guest_memory["available"] < min_available_memory_bytes:
            raise RuntimeError(
                f"VM3 guest available memory is too low: {guest_memory['available']} < {min_available_memory_bytes}"
            )

        print(f"host_reported_memory_bytes={host_reported_memory_bytes}")
        print(f"guest_total_bytes={guest_memory['total']}")
        print(f"guest_available_bytes={guest_memory['available']}")
        print(f"vm3_balloon_min_mib={current_balloon}")
        print("smoke=success")
        return 0
    finally:
        guest.close()
        proxmox.close()


if __name__ == "__main__":
    sys.exit(main())
