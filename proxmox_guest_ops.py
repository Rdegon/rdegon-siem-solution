from __future__ import annotations

import json
import os
import shlex
from typing import Any

try:
    import paramiko
except ModuleNotFoundError:  # pragma: no cover - runtime dependency is installed during VM4 deploy
    paramiko = None  # type: ignore[assignment]

try:
    from .deploy.env_file_runtime import maybe_load_runtime_env
except ImportError:  # pragma: no cover - runtime fallback
    try:
        from deploy.env_file_runtime import maybe_load_runtime_env  # type: ignore[no-redef]
    except ImportError:  # pragma: no cover - test fallback
        def maybe_load_runtime_env() -> dict[str, str]:
            return {}


_RUNTIME_ENV_LOADED = False


def _ensure_runtime_env() -> None:
    global _RUNTIME_ENV_LOADED
    if _RUNTIME_ENV_LOADED:
        return
    maybe_load_runtime_env()
    _RUNTIME_ENV_LOADED = True


def _ssh_host() -> str:
    _ensure_runtime_env()
    return str(os.getenv("SIEM_PROXMOX_SSH_HOST") or os.getenv("SIEM_PROXMOX_HOST") or "").strip()


def _ssh_user() -> str:
    _ensure_runtime_env()
    raw = str(os.getenv("SIEM_PROXMOX_SSH_USER") or os.getenv("SIEM_PROXMOX_USER") or "root").strip()
    return raw.split("@", 1)[0].strip() or "root"


def _ssh_password() -> str:
    _ensure_runtime_env()
    return str(os.getenv("SIEM_PROXMOX_SSH_PASSWORD") or os.getenv("SIEM_PROXMOX_PASSWORD") or "").strip()


def proxmox_guest_exec_configured() -> bool:
    return bool(paramiko is not None and _ssh_host() and _ssh_user() and _ssh_password())


def _connect() -> Any:
    if paramiko is None:
        raise RuntimeError("paramiko is not installed in the current runtime")
    host = _ssh_host()
    user = _ssh_user()
    password = _ssh_password()
    if not host or not user or not password:
        raise RuntimeError("Proxmox guest-exec SSH bridge is not configured")
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


def _run(client: Any, command: str) -> tuple[int, str, str]:
    stdin, stdout, stderr = client.exec_command(command)
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    return int(stdout.channel.recv_exit_status() or 0), out, err


def guest_exec(vmid: int, guest_type: str, command: str, *, timeout: int = 240) -> str:
    with _connect() as client:
        if str(guest_type or "").strip().lower() == "lxc":
            code, out, err = _run(client, f"pct exec {int(vmid)} -- bash -lc {shlex.quote(command)}")
            if code != 0:
                raise RuntimeError(f"Guest command failed for CT{int(vmid)}\nstdout={out}\nstderr={err}")
            return out
        code, out, err = _run(client, f"qm guest exec {int(vmid)} --timeout {int(timeout)} -- /bin/bash -lc {shlex.quote(command)}")
        if code != 0:
            raise RuntimeError(f"Guest command failed for VM{int(vmid)}\nstdout={out}\nstderr={err}")
        payload = json.loads(out or "{}")
        exitcode = int(payload.get("exitcode") or 0)
        stdout_text = str(payload.get("out-data") or "")
        stderr_text = str(payload.get("err-data") or "")
        if exitcode != 0:
            raise RuntimeError(
                f"Guest command failed for VM{int(vmid)}\nstdout={stdout_text}\nstderr={stderr_text}"
            )
        return stdout_text
