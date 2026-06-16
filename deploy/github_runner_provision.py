from __future__ import annotations

import json
import os
import posixpath
import shlex
import sys
import time
import urllib.request
from dataclasses import dataclass

import paramiko


DEFAULT_RUNNER_VERSION = "2.333.0"
DEFAULT_RUNNER_ASSET = f"actions-runner-linux-x64-{DEFAULT_RUNNER_VERSION}.tar.gz"
DEFAULT_RUNNER_URL = f"https://github.com/actions/runner/releases/download/v{DEFAULT_RUNNER_VERSION}/{DEFAULT_RUNNER_ASSET}"
DEFAULT_INSTALL_ROOT = "/opt/actions-runners"


@dataclass(frozen=True)
class RunnerTarget:
    host: str
    user: str
    password: str
    name: str
    labels: str
    install_root: str

    @property
    def runner_dir(self) -> str:
        return posixpath.join(self.install_root.rstrip("/"), self.name)

    @property
    def service_name(self) -> str:
        return f"actions.runner.Rdegon-siem-solution.{self.name}.service"


def _required_env(name: str, *, default: str | None = None) -> str:
    value = os.getenv(name, default or "").strip()
    if value:
        return value
    raise SystemExit(f"Missing required environment variable: {name}")


def _get_registration_token(owner: str, repo: str, pat: str) -> str:
    request = urllib.request.Request(
        f"https://api.github.com/repos/{owner}/{repo}/actions/runners/registration-token",
        method="POST",
        headers={
            "Authorization": f"Bearer {pat}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        payload = json.load(response)
    token = str(payload.get("token") or "").strip()
    if not token:
        raise RuntimeError("GitHub API did not return a runner registration token")
    return token


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
            print(f"ssh connect attempt {attempt}/{attempts} failed: {exc}")
            time.sleep(delay_seconds)
    raise RuntimeError(f"Unable to connect to {host} after {attempts} attempts: {last_error}")


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


def _strip_sudo_echo(text: str, sudo_password: str) -> str:
    if not sudo_password:
        return text
    cleaned: list[str] = []
    for raw_line in str(text or "").replace("\r", "\n").split("\n"):
        line = raw_line.strip("\x00")
        if line.strip() == sudo_password:
            continue
        cleaned.append(line)
    return "\n".join(cleaned)


def _safe_emit(text: str) -> None:
    if not text:
        return
    try:
        print(text, end="" if text.endswith("\n") else "\n")
    except UnicodeEncodeError:
        encoded = text.encode(sys.stdout.encoding or "utf-8", errors="replace").decode(sys.stdout.encoding or "utf-8", errors="replace")
        print(encoded, end="" if encoded.endswith("\n") else "\n")


def provision_runner(
    target: RunnerTarget,
    *,
    repo_url: str,
    registration_token: str,
    runner_asset_url: str,
    runner_asset_name: str,
) -> None:
    client = _connect_client(target.host, target.user, target.password)
    try:
        bootstrap_cmd = f"""
set -euo pipefail
install_root={shlex.quote(target.install_root)}
runner_dir={shlex.quote(target.runner_dir)}
asset_name={shlex.quote(runner_asset_name)}
asset_url={shlex.quote(runner_asset_url)}
mkdir -p "$install_root"
mkdir -p "$runner_dir"
cd "$runner_dir"
if [ ! -f "./bin/Runner.Listener" ]; then
  if [ ! -f "$asset_name" ]; then
    curl -fsSL "$asset_url" -o "$asset_name"
  fi
  tar xzf "$asset_name"
fi
chown -R {shlex.quote(target.user)}:{shlex.quote(target.user)} "$install_root"
"""
        code, out, err = _run_command(client, bootstrap_cmd, sudo_password=target.password, use_sudo=True)
        out = _strip_sudo_echo(out, target.password)
        if out.strip():
            _safe_emit(out)
        if code != 0:
            raise RuntimeError(f"runner bootstrap failed on {target.host}: {err.strip()}")

        configure_cmd = f"""
set -euo pipefail
cd {shlex.quote(target.runner_dir)}
if [ ! -f ".runner" ]; then
  ./config.sh --unattended --replace \
    --url {shlex.quote(repo_url)} \
    --token {shlex.quote(registration_token)} \
    --name {shlex.quote(target.name)} \
    --labels {shlex.quote(target.labels)} \
    --work _work
fi
"""
        code, out, err = _run_command(client, configure_cmd)
        if out.strip():
            _safe_emit(out)
        if code != 0:
            raise RuntimeError(f"runner config failed on {target.host}: {err.strip()}")

        service_cmd = f"""
set -euo pipefail
cd {shlex.quote(target.runner_dir)}
service_file=/etc/systemd/system/{shlex.quote(target.service_name)}
if [ ! -f "$service_file" ]; then
  ./svc.sh install {shlex.quote(target.user)}
fi
systemctl restart {shlex.quote(target.service_name)} || ./svc.sh start
systemctl is-active {shlex.quote(target.service_name)}
"""
        code, out, err = _run_command(client, service_cmd, sudo_password=target.password, use_sudo=True)
        out = _strip_sudo_echo(out, target.password)
        if out.strip():
            _safe_emit(out)
        if code != 0 or "active" not in out:
            raise RuntimeError(f"runner service failed on {target.host}: stdout={out.strip()} stderr={err.strip()}")
        print(f"runner={target.name} host={target.host} service={target.service_name} status=active")
    finally:
        client.close()


def main() -> int:
    owner = _required_env("GITHUB_REPO_OWNER", default="Rdegon")
    repo = _required_env("GITHUB_REPO_NAME", default="siem-solution")
    pat = _required_env("GITHUB_PAT")
    target = RunnerTarget(
        host=_required_env("RUNNER_TARGET_HOST"),
        user=_required_env("RUNNER_TARGET_USER"),
        password=_required_env("RUNNER_TARGET_PASSWORD"),
        name=_required_env("RUNNER_NAME"),
        labels=_required_env("RUNNER_LABELS"),
        install_root=_required_env("RUNNER_INSTALL_ROOT", default=DEFAULT_INSTALL_ROOT),
    )
    runner_asset_url = _required_env("GITHUB_RUNNER_ASSET_URL", default=DEFAULT_RUNNER_URL)
    runner_asset_name = _required_env("GITHUB_RUNNER_ASSET_NAME", default=DEFAULT_RUNNER_ASSET)
    repo_url = f"https://github.com/{owner}/{repo}"
    registration_token = _get_registration_token(owner, repo, pat)
    provision_runner(
        target,
        repo_url=repo_url,
        registration_token=registration_token,
        runner_asset_url=runner_asset_url,
        runner_asset_name=runner_asset_name,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
