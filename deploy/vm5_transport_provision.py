from __future__ import annotations

import base64
import json
import os
import shlex
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

try:
    import paramiko
except ModuleNotFoundError:  # pragma: no cover - exercised in CI/unit imports
    paramiko = None  # type: ignore[assignment]

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from deploy.github_runner_provision import (
    DEFAULT_INSTALL_ROOT,
    DEFAULT_RUNNER_ASSET,
    DEFAULT_RUNNER_URL,
    RunnerTarget,
    _get_registration_token,
    provision_runner,
)


DEFAULT_TEMPLATE_VMID = "105"
DEFAULT_VM5_VMID = "108"
DEFAULT_VM5_NAME = "SIEM-Transport"
DEFAULT_VM5_HOSTNAME = "siem-transport"
DEFAULT_VM5_HOST = "192.168.1.40"
DEFAULT_VM5_ADDRESS = "192.168.1.40/24"
DEFAULT_VM5_GATEWAY = "192.168.1.1"
DEFAULT_VM5_DNS = "192.168.1.1"
DEFAULT_VM5_MEMORY_MB = "12288"
DEFAULT_VM5_CORES = "4"
DEFAULT_VM5_SOCKETS = "1"
DEFAULT_VM5_CPU = "x86-64-v3"
DEFAULT_VM5_TAGS = "SIEM-Dev"
DEFAULT_VM5_INTERFACE = "ens19"
DEFAULT_VM5_RUNNER_NAME = "siem-vm5"

if TYPE_CHECKING:  # pragma: no cover
    import paramiko as _paramiko


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
    if paramiko is None:
        raise RuntimeError("paramiko is required to provision VM5")
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
            print(f"vm5_transport ssh retry host={host} attempt={attempt}/{attempts} error={exc}")
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


def render_vm5_netplan(
    *,
    interface_name: str = DEFAULT_VM5_INTERFACE,
    address_cidr: str = DEFAULT_VM5_ADDRESS,
    gateway: str = DEFAULT_VM5_GATEWAY,
    dns_server: str = DEFAULT_VM5_DNS,
) -> str:
    return (
        "network:\n"
        "  version: 2\n"
        "  renderer: networkd\n"
        "  ethernets:\n"
        f"    {interface_name}:\n"
        "      dhcp4: false\n"
        "      addresses:\n"
        f"        - {address_cidr}\n"
        "      routes:\n"
        "        - to: default\n"
        f"          via: {gateway}\n"
        "      nameservers:\n"
        f"        addresses: [{dns_server}]\n"
        "      optional: true\n"
    )


def render_vm5_resolved_conf(*, dns_server: str = DEFAULT_VM5_DNS) -> str:
    return (
        "[Resolve]\n"
        f"DNS={dns_server}\n"
        "FallbackDNS=1.1.1.1 8.8.8.8\n"
        "Domains=~.\n"
        "DNSStubListener=yes\n"
    )


def _guest_python_command(script: str) -> str:
    payload = base64.b64encode(script.encode("utf-8")).decode("ascii")
    return f"python3 -c \"import base64; exec(base64.b64decode('{payload}').decode('utf-8'))\""


def build_guest_personalization_script(
    *,
    hostname: str,
    netplan_content: str,
    resolved_conf_content: str,
) -> str:
    return f"""
from pathlib import Path
import subprocess

hostname = {hostname!r}
netplan_content = {netplan_content!r}
resolved_conf_content = {resolved_conf_content!r}

Path('/etc/hostname').write_text(hostname + '\\n', encoding='utf-8')
Path('/etc/netplan/01-siem.yaml').write_text(netplan_content, encoding='utf-8')
legacy = Path('/etc/netplan/01-siem-net.yaml')
if legacy.exists():
    legacy.unlink()
Path('/etc/systemd/resolved.conf').write_text(resolved_conf_content, encoding='utf-8')
hosts_path = Path('/etc/hosts')
hosts_lines = hosts_path.read_text(encoding='utf-8').splitlines() if hosts_path.exists() else []
filtered = [line for line in hosts_lines if 'siem-processing' not in line and 'siem-transport' not in line]
filtered.append('127.0.1.1 ' + hostname)
hosts_path.write_text('\\n'.join(filtered).rstrip() + '\\n', encoding='utf-8')

subprocess.run(['chmod', '600', '/etc/netplan/01-siem.yaml'], check=True)
subprocess.run(['hostnamectl', 'set-hostname', hostname], check=True)
subprocess.run(['netplan', 'generate'], check=True)
subprocess.run(['netplan', 'apply'], check=True)
subprocess.run(['systemctl', 'restart', 'systemd-resolved'], check=True)
subprocess.run(['systemctl', 'restart', 'ssh'], check=True)
subprocess.run(['systemctl', 'restart', 'qemu-guest-agent'], check=True)
print('vm5_guest_personalization=ok')
"""


def _guest_exec_require_success(
    client: paramiko.SSHClient,
    vmid: str,
    command: str,
    *,
    attempts: int = 6,
    delay_seconds: float = 3.0,
) -> dict[str, object]:
    last_error: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            payload = _qm_guest_exec_json(client, vmid, command)
            exitcode = int(payload.get("exitcode") or 0)
            if exitcode != 0:
                raise RuntimeError(f"exitcode={exitcode} payload={payload}")
            return payload
        except Exception as exc:  # noqa: BLE001
            last_error = exc
            if attempt == attempts:
                break
            print(f"vm5 guest-exec retry attempt={attempt}/{attempts} command={command[:72]!r} error={exc}")
            time.sleep(delay_seconds)
    raise RuntimeError(f"qm guest exec command failed for {vmid}: {last_error}")


def _guest_write_file(client: paramiko.SSHClient, vmid: str, *, path: str, content: str, mode: str = "0644") -> None:
    script = (
        "from pathlib import Path\n"
        f"path = Path({path!r})\n"
        f"path.write_text({content!r}, encoding='utf-8')\n"
        f"path.chmod(0o{mode})\n"
        f"print('wrote:{path}')\n"
    )
    _guest_exec_require_success(client, vmid, _guest_python_command(script))


def resolve_runner_install_mode(
    *,
    install_runner: bool,
    pat: str,
    target_runner_name: str,
    current_runner_name: str,
    running_inside_actions: bool,
) -> str:
    if not install_runner:
        return "skipped"
    if not str(pat or "").strip():
        return "skipped_no_pat"
    if running_inside_actions and str(current_runner_name or "").strip() == str(target_runner_name or "").strip():
        return "skipped_self_hosted_job"
    return "installed"


def _qm_exists(client: paramiko.SSHClient, vmid: str) -> bool:
    code, _, _ = _run_command(client, f"qm status {shlex.quote(vmid)}")
    return code == 0


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


def _qm_guest_exec_json(client: paramiko.SSHClient, vmid: str, command: str) -> dict[str, object]:
    code, out, err = _run_command(client, f"qm guest exec {shlex.quote(vmid)} -- bash -lc {shlex.quote(command)}")
    if code != 0:
        raise RuntimeError(f"qm guest exec failed for {vmid}: {err.strip()}")
    return json.loads(out)


def _wait_for_guest_exec(client: paramiko.SSHClient, vmid: str, *, attempts: int = 30, delay_seconds: float = 6.0) -> None:
    last_error: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            payload = _qm_guest_exec_json(client, vmid, "hostname; systemctl is-active qemu-guest-agent ssh || true")
            text = str(payload.get("out-data") or "")
            if text.strip():
                return
        except Exception as exc:  # noqa: BLE001
            last_error = exc
        print(f"vm5 guest-exec wait attempt={attempt}/{attempts}")
        time.sleep(delay_seconds)
    raise RuntimeError(f"VM5 guest exec did not become ready: {last_error}")


def _wait_for_ssh(spec: HostSpec, *, attempts: int = 25, delay_seconds: float = 6.0) -> None:
    last_error: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            client = _connect_client(spec.host, spec.user, spec.password, attempts=1)
            try:
                code, out, err = _run_command(client, "hostname")
                if code == 0 and out.strip():
                    return
                last_error = RuntimeError(err.strip() or "empty hostname output")
            finally:
                client.close()
        except Exception as exc:  # noqa: BLE001
            last_error = exc
        print(f"vm5 ssh wait attempt={attempt}/{attempts} host={spec.host}")
        time.sleep(delay_seconds)
    raise RuntimeError(f"VM5 SSH did not become ready on {spec.host}: {last_error}")


def _ensure_vm5_instance(client: paramiko.SSHClient, *, template_vmid: str, vmid: str, name: str, memory_mb: str, cores: str, sockets: str, cpu_model: str, tags: str) -> str:
    if not _qm_exists(client, vmid):
        clone_cmd = f"qm clone {shlex.quote(template_vmid)} {shlex.quote(vmid)} --full 1 --name {shlex.quote(name)}"
        code, out, err = _run_command(client, clone_cmd)
        if code != 0:
            raise RuntimeError(f"qm clone failed for VM5: {err.strip()}")
        mode = "created"
    else:
        mode = "existing"

    set_cmd = (
        f"qm set {shlex.quote(vmid)} "
        f"--name {shlex.quote(name)} "
        f"--memory {shlex.quote(memory_mb)} "
        f"--cores {shlex.quote(cores)} "
        f"--sockets {shlex.quote(sockets)} "
        f"--cpu {shlex.quote(cpu_model)} "
        "--onboot 1 --agent enabled=1 "
        f"--tags {shlex.quote(tags)}"
    )
    code, out, err = _run_command(client, set_cmd)
    if code != 0:
        raise RuntimeError(f"qm set failed for VM5: {err.strip()}")
    return mode


def _ensure_vm5_running(client: paramiko.SSHClient, vmid: str) -> None:
    status = _qm_status(client, vmid)
    if status == "running":
        return
    code, out, err = _run_command(client, f"qm start {shlex.quote(vmid)}")
    if code != 0 and "already running" not in (out + err):
        raise RuntimeError(f"qm start failed for VM5: {err.strip()}")


def _personalize_guest(client: paramiko.SSHClient, vmid: str, *, hostname: str, netplan_content: str, resolved_conf_content: str) -> None:
    _guest_write_file(client, vmid, path="/etc/hostname", content=hostname + "\n", mode="0644")
    _guest_write_file(client, vmid, path="/etc/netplan/01-siem.yaml", content=netplan_content, mode="0600")
    _guest_write_file(client, vmid, path="/etc/systemd/resolved.conf", content=resolved_conf_content, mode="0644")

    hosts_script = (
        "from pathlib import Path\n"
        f"hostname = {hostname!r}\n"
        "hosts_path = Path('/etc/hosts')\n"
        "hosts_lines = hosts_path.read_text(encoding='utf-8').splitlines() if hosts_path.exists() else []\n"
        "filtered = [line for line in hosts_lines if 'siem-processing' not in line and 'siem-transport' not in line]\n"
        "filtered.append('127.0.1.1 ' + hostname)\n"
        "hosts_path.write_text('\\n'.join(filtered).rstrip() + '\\n', encoding='utf-8')\n"
        "legacy = Path('/etc/netplan/01-siem-net.yaml')\n"
        "if legacy.exists():\n"
        "    legacy.unlink()\n"
        "print('vm5_hosts_rewritten=ok')\n"
    )
    _guest_exec_require_success(client, vmid, _guest_python_command(hosts_script))

    for command in (
        f"hostnamectl set-hostname {shlex.quote(hostname)}",
        "netplan generate",
        "netplan apply",
        "systemctl restart systemd-resolved",
        "systemctl restart ssh",
    ):
        _guest_exec_require_success(client, vmid, f"bash -lc {shlex.quote(command)}")

    payload = _guest_exec_require_success(
        client,
        vmid,
        "bash -lc 'hostname; echo ---; systemctl is-active qemu-guest-agent ssh || true'",
    )
    text = str(payload.get("out-data") or "")
    if hostname not in text or text.count("active") < 2:
        raise RuntimeError(f"Unexpected VM5 guest personalization verification output: {text!r}")


def main() -> int:
    proxmox = HostSpec(
        host=_required_env("SIEM_PROXMOX_HOST"),
        user=_required_env("SIEM_PROXMOX_USER"),
        password=_required_env("SIEM_PROXMOX_PASSWORD"),
    )
    vm5 = HostSpec(
        host=_required_env("SIEM_VM5_HOST", default=DEFAULT_VM5_HOST),
        user=_required_env("SIEM_VM5_USER", default="rdegon"),
        password=_required_env("SIEM_VM5_PASSWORD"),
    )
    vmid = _required_env("SIEM_VM5_VMID", default=DEFAULT_VM5_VMID)
    template_vmid = _required_env("SIEM_VM5_TEMPLATE_VMID", default=DEFAULT_TEMPLATE_VMID)
    vm_name = _required_env("SIEM_VM5_NAME", default=DEFAULT_VM5_NAME)
    hostname = _required_env("SIEM_VM5_HOSTNAME", default=DEFAULT_VM5_HOSTNAME)
    address_cidr = _required_env("SIEM_VM5_ADDRESS", default=DEFAULT_VM5_ADDRESS)
    gateway = _required_env("SIEM_VM5_GATEWAY", default=DEFAULT_VM5_GATEWAY)
    dns_server = _required_env("SIEM_VM5_DNS", default=DEFAULT_VM5_DNS)
    memory_mb = _required_env("SIEM_VM5_MEMORY_MB", default=DEFAULT_VM5_MEMORY_MB)
    cores = _required_env("SIEM_VM5_CORES", default=DEFAULT_VM5_CORES)
    sockets = _required_env("SIEM_VM5_SOCKETS", default=DEFAULT_VM5_SOCKETS)
    cpu_model = _required_env("SIEM_VM5_CPU", default=DEFAULT_VM5_CPU)
    tags = _required_env("SIEM_VM5_TAGS", default=DEFAULT_VM5_TAGS)
    runner_name = _required_env("SIEM_VM5_RUNNER_NAME", default=DEFAULT_VM5_RUNNER_NAME)
    install_runner = str(os.getenv("SIEM_VM5_INSTALL_RUNNER", "1") or "1").strip().lower() in {"1", "true", "yes", "on"}
    running_inside_actions = str(os.getenv("GITHUB_ACTIONS", "")).strip().lower() == "true"
    current_runner_name = str(os.getenv("RUNNER_NAME") or os.getenv("GITHUB_RUNNER_NAME") or "").strip()

    proxmox_client = _connect_client(proxmox.host, proxmox.user, proxmox.password)
    try:
        clone_mode = _ensure_vm5_instance(
            proxmox_client,
            template_vmid=template_vmid,
            vmid=vmid,
            name=vm_name,
            memory_mb=memory_mb,
            cores=cores,
            sockets=sockets,
            cpu_model=cpu_model,
            tags=tags,
        )
        _ensure_vm5_running(proxmox_client, vmid)
        _wait_for_guest_exec(proxmox_client, vmid)
        _personalize_guest(
            proxmox_client,
            vmid,
            hostname=hostname,
            netplan_content=render_vm5_netplan(address_cidr=address_cidr, gateway=gateway, dns_server=dns_server),
            resolved_conf_content=render_vm5_resolved_conf(dns_server=dns_server),
        )
    finally:
        proxmox_client.close()

    _wait_for_ssh(vm5)

    pat = str(os.getenv("GITHUB_PAT", "") or "").strip()
    runner_mode = resolve_runner_install_mode(
        install_runner=install_runner,
        pat=pat,
        target_runner_name=runner_name,
        current_runner_name=current_runner_name,
        running_inside_actions=running_inside_actions,
    )
    if runner_mode == "installed":
        owner = _required_env("GITHUB_REPO_OWNER", default="Rdegon")
        repo = _required_env("GITHUB_REPO_NAME", default="siem-solution")
        repo_url = f"https://github.com/{owner}/{repo}"
        registration_token = _get_registration_token(owner, repo, pat)
        provision_runner(
            RunnerTarget(
                host=vm5.host,
                user=vm5.user,
                password=vm5.password,
                name=runner_name,
                labels=f"siem-homelab,{runner_name}",
                install_root=_required_env("RUNNER_INSTALL_ROOT", default=DEFAULT_INSTALL_ROOT),
            ),
            repo_url=repo_url,
            registration_token=registration_token,
            runner_asset_url=_required_env("GITHUB_RUNNER_ASSET_URL", default=DEFAULT_RUNNER_URL),
            runner_asset_name=_required_env("GITHUB_RUNNER_ASSET_NAME", default=DEFAULT_RUNNER_ASSET),
        )

    print(f"vm5_vmid={vmid}")
    print(f"vm5_name={vm_name}")
    print(f"vm5_host={vm5.host}")
    print(f"clone_mode={clone_mode}")
    print(f"runner_mode={runner_mode}")
    print("provision=success")
    return 0


if __name__ == "__main__":
    sys.exit(main())
