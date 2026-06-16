from __future__ import annotations

import json
import os
import posixpath
import shlex
import sys
import time
from datetime import datetime, timezone

import paramiko


DEFAULT_VM3_VMID = "106"
DEFAULT_VM3_MEMORY_MIB = 28672
DEFAULT_VM3_BALLOON_MIB = 24576
# The storage node keeps a large page cache under sustained ClickHouse load, so
# host-reported memory should be validated against the configured Proxmox
# ceiling instead of the lower balloon floor.
DEFAULT_VM3_MAX_REPORTED_MEMORY_BYTES = DEFAULT_VM3_MEMORY_MIB * 1024 * 1024
DEFAULT_VM3_MIN_AVAILABLE_MEMORY_BYTES = 12 * 1024 * 1024 * 1024
REMOTE_STORAGE_UNITS = (
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


def _connect_client(host: str, user: str, password: str, *, attempts: int = 5, delay_seconds: int = 3) -> paramiko.SSHClient:
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
            print(f"ssh connect attempt {attempt}/{attempts} failed: {exc}")
            time.sleep(delay_seconds)
    raise RuntimeError(f"Unable to connect to {host}: {last_error}")


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


def _safe_print(text: str) -> None:
    rendered = str(text or "")
    encoding = getattr(sys.stdout, "encoding", None) or "utf-8"
    print(rendered.encode(encoding, errors="replace").decode(encoding, errors="replace"))


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


def _backup_vm_config(proxmox: paramiko.SSHClient, vmid: str) -> str:
    backup_root = f"/tmp/siem-vm3-memory-alignment-{datetime.now(tz=timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
    backup_cmd = (
        f"mkdir -p {shlex.quote(backup_root)} && "
        f"qm config {shlex.quote(vmid)} > {shlex.quote(posixpath.join(backup_root, f'vm-{vmid}.conf'))}"
    )
    code, _, err = _run_command(proxmox, backup_cmd)
    if code != 0:
        raise RuntimeError(f"Unable to back up Proxmox VM config for {vmid}: {err.strip()}")
    return backup_root


def _query_vm_status(proxmox: paramiko.SSHClient, vmid: str) -> dict[str, object]:
    code, out, err = _run_command(
        proxmox,
        f"pvesh get /nodes/pve/qemu/{shlex.quote(vmid)}/status/current --output-format json",
    )
    if code != 0:
        raise RuntimeError(f"Unable to query VM{vmid} status: {err.strip()}")
    return json.loads(str(out or "{}").strip() or "{}")


def _ensure_guest_agent(guest: paramiko.SSHClient, sudo_password: str) -> None:
    code, out, _ = _run_command(guest, "dpkg-query -W -f='${Status}' qemu-guest-agent 2>/dev/null || true")
    installed = "install ok installed" in str(out or "").lower()
    if not installed:
        install_cmd = (
            "export DEBIAN_FRONTEND=noninteractive && "
            "apt-get update && "
            "apt-get install -y qemu-guest-agent"
        )
        code, out, err = _run_command(guest, install_cmd, sudo_password=sudo_password, use_sudo=True)
        cleaned_out = _strip_sudo_echo(out, sudo_password).strip()
        if cleaned_out:
            _safe_print(cleaned_out)
        if code != 0:
            raise RuntimeError(f"Unable to install qemu-guest-agent on VM3: {err.strip()}")
    start_cmd = (
        "mkdir -p /etc/systemd/system/multi-user.target.wants && "
        "ln -sf /lib/systemd/system/qemu-guest-agent.service "
        "/etc/systemd/system/multi-user.target.wants/qemu-guest-agent.service && "
        "systemctl daemon-reload && "
        "systemctl restart qemu-guest-agent && "
        "systemctl is-active qemu-guest-agent"
    )
    code, out, err = _run_command(guest, start_cmd, sudo_password=sudo_password, use_sudo=True)
    cleaned_out = _strip_sudo_echo(out, sudo_password).strip()
    if cleaned_out:
        _safe_print(cleaned_out)
    if code != 0:
        raise RuntimeError(f"Unable to start qemu-guest-agent on VM3: {err.strip()}")


def _ensure_storage_services_healthy(guest: paramiko.SSHClient, sudo_password: str) -> None:
    unit_clause = " ".join(REMOTE_STORAGE_UNITS)
    code, out, err = _run_command(guest, f"systemctl is-active {unit_clause}", sudo_password=sudo_password, use_sudo=True)
    active_out = _strip_sudo_echo(out, sudo_password)
    states = [line.strip() for line in active_out.splitlines() if line.strip()]
    if code != 0 or states != ["active"] * len(REMOTE_STORAGE_UNITS):
        raise RuntimeError(f"Unexpected VM3 storage service state: stdout={states} stderr={err.strip()}")


def _query_guest_memory(guest: paramiko.SSHClient) -> dict[str, int]:
    code, out, err = _run_command(guest, "free -b")
    if code != 0:
        raise RuntimeError(f"Unable to query VM3 memory: {err.strip()}")
    return _parse_free_bytes(out)


def main() -> int:
    vm3_host = _required_env("SIEM_VM3_HOST")
    vm3_user = _required_env("SIEM_VM3_USER")
    vm3_password = _required_env("SIEM_VM3_PASSWORD")
    proxmox_host = _required_env("SIEM_PROXMOX_HOST")
    proxmox_user = _required_env("SIEM_PROXMOX_USER")
    proxmox_password = _required_env("SIEM_PROXMOX_PASSWORD")
    vm3_vmid = _required_env("SIEM_VM3_VMID", default=DEFAULT_VM3_VMID)
    target_memory_mib = int(_required_env("SIEM_VM3_PROXMOX_MEMORY_MIB", default=str(DEFAULT_VM3_MEMORY_MIB)))
    target_balloon_mib = int(_required_env("SIEM_VM3_PROXMOX_BALLOON_MIB", default=str(DEFAULT_VM3_BALLOON_MIB)))
    max_reported_memory_bytes = int(
        _required_env(
            "SIEM_VM3_PROXMOX_MAX_REPORTED_MEMORY_BYTES",
            default=str(DEFAULT_VM3_MAX_REPORTED_MEMORY_BYTES),
        )
    )
    min_available_memory_bytes = int(
        _required_env(
            "SIEM_VM3_MIN_AVAILABLE_MEMORY_BYTES",
            default=str(DEFAULT_VM3_MIN_AVAILABLE_MEMORY_BYTES),
        )
    )

    proxmox = _connect_client(proxmox_host, proxmox_user, proxmox_password)
    guest = _connect_client(vm3_host, vm3_user, vm3_password)
    try:
        backup_root = _backup_vm_config(proxmox, vm3_vmid)
        print(f"backup_root={backup_root}")

        code, config_out, err = _run_command(proxmox, f"qm config {shlex.quote(vm3_vmid)}")
        if code != 0:
            raise RuntimeError(f"Unable to read VM{vm3_vmid} config: {err.strip()}")
        current_memory_mib = int(_parse_qm_config_value(config_out, "memory") or 0)
        current_balloon_mib = int(_parse_qm_config_value(config_out, "balloon") or current_memory_mib)
        current_agent = _parse_qm_config_value(config_out, "agent")

        if current_agent != "1":
            code, _, err = _run_command(proxmox, f"qm set {shlex.quote(vm3_vmid)} --agent 1")
            if code != 0:
                raise RuntimeError(f"Unable to enable Proxmox guest agent for VM{vm3_vmid}: {err.strip()}")
            print("proxmox_guest_agent_flag=enabled")
        else:
            print("proxmox_guest_agent_flag=already-enabled")

        if current_memory_mib != target_memory_mib:
            code, _, err = _run_command(
                proxmox,
                f"qm set {shlex.quote(vm3_vmid)} --memory {shlex.quote(str(target_memory_mib))}",
            )
            if code != 0:
                raise RuntimeError(f"Unable to set VM{vm3_vmid} memory to {target_memory_mib} MiB: {err.strip()}")
            print(f"vm3_memory_mib={current_memory_mib}->{target_memory_mib}")
        else:
            print(f"vm3_memory_mib={target_memory_mib}")

        if current_balloon_mib != target_balloon_mib:
            code, _, err = _run_command(
                proxmox,
                f"qm set {shlex.quote(vm3_vmid)} --balloon {shlex.quote(str(target_balloon_mib))}",
            )
            if code != 0:
                raise RuntimeError(f"Unable to set VM{vm3_vmid} balloon to {target_balloon_mib} MiB: {err.strip()}")
            print(f"vm3_balloon_min_mib={current_balloon_mib}->{target_balloon_mib}")
        else:
            print(f"vm3_balloon_min_mib={target_balloon_mib}")

        _ensure_guest_agent(guest, vm3_password)
        _ensure_storage_services_healthy(guest, vm3_password)

        # Proactively deflate the guest to the target balloon floor so the host no longer
        # sees the storage node pinned near the full 28 GiB allocation because of page cache.
        code, out, err = _run_command(
            proxmox,
            f"printf 'balloon {target_balloon_mib}\\ninfo balloon\\n' | qm monitor {shlex.quote(vm3_vmid)}",
        )
        if code != 0:
            raise RuntimeError(f"Unable to apply live balloon target for VM{vm3_vmid}: {err.strip()}")
        monitor_out = str(out or "").strip()
        if monitor_out:
            _safe_print(monitor_out)

        host_reported_memory_bytes = 0
        for _ in range(18):
            time.sleep(5)
            vm_status = _query_vm_status(proxmox, vm3_vmid)
            host_reported_memory_bytes = int(vm_status.get("mem") or 0)
            if host_reported_memory_bytes <= max_reported_memory_bytes:
                break
        if host_reported_memory_bytes > max_reported_memory_bytes:
            raise RuntimeError(
                "VM3 host-reported memory stayed above the configured ceiling: "
                f"{host_reported_memory_bytes} > {max_reported_memory_bytes}"
            )

        guest_memory = _query_guest_memory(guest)
        if guest_memory["available"] < min_available_memory_bytes:
            raise RuntimeError(
                f"VM3 available memory is too low after balloon alignment: {guest_memory['available']} < {min_available_memory_bytes}"
            )

        # Confirm that Proxmox guest exec works once qemu-guest-agent is installed.
        code, out, err = _run_command(
            proxmox,
            f"qm guest exec {shlex.quote(vm3_vmid)} -- bash -lc {shlex.quote('hostname && systemctl is-active qemu-guest-agent')}",
        )
        if code != 0:
            raise RuntimeError(f"Unable to validate qemu-guest-agent through Proxmox for VM{vm3_vmid}: {err.strip()}")
        print(str(out or "").strip())
        print(f"host_reported_memory_bytes={host_reported_memory_bytes}")
        print(f"guest_total_bytes={guest_memory['total']}")
        print(f"guest_available_bytes={guest_memory['available']}")
        print("vm3_proxmox_memory_alignment=success")
        return 0
    finally:
        guest.close()
        proxmox.close()


if __name__ == "__main__":
    sys.exit(main())
