from __future__ import annotations

import json
import os
import shlex

import paramiko


HOSTS = (
    ("SIEM_VM2", "192.168.1.37"),
    ("SIEM_VM3", "192.168.1.38"),
    ("SIEM_VM5", "192.168.1.40"),
)


def _required_env(name: str, *, default: str | None = None) -> str:
    value = str(os.getenv(name, default or "") or "").strip()
    if value:
        return value
    raise SystemExit(f"Missing required environment variable: {name}")


def _connect(host: str, user: str, password: str) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(host, username=user, password=password, timeout=20, banner_timeout=20, auth_timeout=20, look_for_keys=False, allow_agent=False)
    return client


def _run(client: paramiko.SSHClient, command: str, *, sudo_password: str) -> str:
    wrapped = f"sudo -S -p '' bash -lc {shlex.quote(command)}"
    stdin, stdout, stderr = client.exec_command(wrapped, get_pty=True)
    stdin.write(f"{sudo_password}\n")
    stdin.flush()
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    code = stdout.channel.recv_exit_status()
    if code != 0:
        raise RuntimeError(f"{command}\nstdout={out}\nstderr={err}")
    return out


def main() -> int:
    results = []
    cleanup_script = r"""
set -e
systemctl stop redis-server siem-redis-sentinel 2>/dev/null || true
systemctl disable redis-server siem-redis-sentinel 2>/dev/null || true
systemctl mask redis-server siem-redis-sentinel 2>/dev/null || true
if command -v ufw >/dev/null 2>&1 && ufw status | grep -q 'Status: active'; then
  numbers="$(ufw status numbered | grep -E '6379|26379' | sed -E 's/^\[ *([0-9]+)\].*/\1/' | sort -rn)"
  for number in $numbers; do
    ufw --force delete "$number" >/dev/null 2>&1 || true
  done
fi
ss -lntp | grep -E '6379|26379' || true
"""
    for prefix, default_host in HOSTS:
        host = _required_env(f"{prefix}_HOST", default=default_host)
        user = _required_env(f"{prefix}_USER", default="rdegon")
        password = _required_env(f"{prefix}_PASSWORD")
        client = _connect(host, user, password)
        try:
            listeners = _run(client, cleanup_script, sudo_password=password)
            results.append({"host": host, "listeners": listeners.strip()})
        finally:
            client.close()
    print(json.dumps({"retired_hosts": results}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
