from __future__ import annotations

import argparse
import json
import os
import shlex
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import paramiko
except ModuleNotFoundError:  # pragma: no cover - unit import fallback
    paramiko = None  # type: ignore[assignment]


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SSH_KEY = ROOT.parent / ".codex_tmp" / "vpnadmin_ed25519"


@dataclass(frozen=True)
class HostProfile:
    name: str
    host: str
    units: tuple[str, ...]
    env: dict[str, str]
    restart_units: tuple[str, ...] = ()


BALANCED_PROFILE: tuple[HostProfile, ...] = (
    HostProfile(
        name="SIEM_VM1",
        host="192.168.1.35",
        units=("siem-ingest.service",),
        env={
            "SIEM_INGEST_HTTP_PUBLISH_BATCH_SIZE": "500",
            "SIEM_KAFKA_PRODUCER_LINGER_MS": "10",
            "SIEM_KAFKA_PRODUCER_MAX_BATCH_SIZE": "65536",
            "SIEM_KAFKA_PRODUCER_MAX_REQUEST_SIZE": "4194304",
        },
        restart_units=("siem-ingest.service",),
    ),
    HostProfile(
        name="SIEM_VM2",
        host="192.168.1.37",
        units=("siem-normalizer.service", "siem-normalizer@.service", "siem-filter.service", "siem-filter@.service"),
        env={
            "SIEM_NORMALIZER_BATCH_SIZE": "500",
            "SIEM_FILTER_BATCH_SIZE": "500",
            "SIEM_KAFKA_MAX_POLL_INTERVAL_MS": "900000",
        },
        restart_units=(
            "siem-normalizer.service",
            "siem-normalizer@1.service",
            "siem-normalizer@2.service",
            "siem-normalizer@3.service",
            "siem-filter.service",
            "siem-filter@1.service",
            "siem-filter@2.service",
            "siem-filter@3.service",
        ),
    ),
    HostProfile(
        name="SIEM_VM3",
        host="192.168.1.38",
        units=("siem-writer.service", "siem-writer@.service", "siem-stream-corr.service"),
        env={
            "SIEM_WRITER_BATCH_SIZE": "1000",
            "SIEM_CH_PORT": "9000",
            "SIEM_CH_TIMEOUT_SECS": "30",
            "SIEM_STREAM_CORR_RUNTIME_STATUS_INTERVAL_SEC": "15",
            "SIEM_STREAM_CORR_HEARTBEAT_YIELD_EVERY": "100",
            "SIEM_KAFKA_MAX_POLL_INTERVAL_MS": "1800000",
        },
        restart_units=("siem-writer.service", "siem-writer@2.service", "siem-stream-corr.service"),
    ),
    HostProfile(
        name="SIEM_VM5",
        host="192.168.1.40",
        units=("siem-normalizer.service", "siem-normalizer@.service", "siem-filter.service", "siem-filter@.service", "siem-writer-standby.service"),
        env={
            "SIEM_NORMALIZER_BATCH_SIZE": "500",
            "SIEM_FILTER_BATCH_SIZE": "500",
            "SIEM_WRITER_BATCH_SIZE": "1000",
            "SIEM_CH_PORT": "9000",
            "SIEM_CH_TIMEOUT_SECS": "30",
            "SIEM_KAFKA_MAX_POLL_INTERVAL_MS": "900000",
        },
        restart_units=(
            "siem-normalizer.service",
            "siem-normalizer@1.service",
            "siem-normalizer@2.service",
            "siem-normalizer@3.service",
            "siem-filter.service",
            "siem-filter@1.service",
            "siem-filter@2.service",
            "siem-filter@3.service",
            "siem-writer-standby.service",
        ),
    ),
)

AGGRESSIVE_OVERRIDES: dict[str, dict[str, str]] = {
    "SIEM_VM1": {
        "SIEM_INGEST_HTTP_PUBLISH_BATCH_SIZE": "2000",
        "SIEM_KAFKA_PRODUCER_LINGER_MS": "5",
        "SIEM_KAFKA_PRODUCER_MAX_BATCH_SIZE": "262144",
        "SIEM_KAFKA_PRODUCER_MAX_REQUEST_SIZE": "8388608",
        "SIEM_KAFKA_PRODUCER_SEND_WINDOW": "2000",
    },
    "SIEM_VM2": {"SIEM_NORMALIZER_BATCH_SIZE": "1000", "SIEM_FILTER_BATCH_SIZE": "1000"},
    "SIEM_VM3": {"SIEM_WRITER_BATCH_SIZE": "2000"},
    "SIEM_VM5": {"SIEM_NORMALIZER_BATCH_SIZE": "1000", "SIEM_FILTER_BATCH_SIZE": "1000", "SIEM_WRITER_BATCH_SIZE": "2000"},
}


def profile_items(profile: str) -> list[HostProfile]:
    items = [HostProfile(item.name, item.host, item.units, dict(item.env), item.restart_units) for item in BALANCED_PROFILE]
    if profile == "aggressive":
        updated: list[HostProfile] = []
        for item in items:
            env = dict(item.env)
            env.update(AGGRESSIVE_OVERRIDES.get(item.name, {}))
            updated.append(HostProfile(item.name, item.host, item.units, env, item.restart_units))
        return updated
    return items


def _systemd_escape(value: str) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"')


def render_dropin(env: dict[str, str]) -> str:
    lines = ["[Service]"]
    for key in sorted(env):
        lines.append(f'Environment="{_systemd_escape(key)}={_systemd_escape(env[key])}"')
    return "\n".join(lines) + "\n"


def _connect(host: str, user: str, key_path: str) -> Any:
    if paramiko is None:
        raise RuntimeError("paramiko is required for --execute")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        host,
        username=user,
        key_filename=key_path,
        timeout=20,
        banner_timeout=20,
        auth_timeout=20,
        look_for_keys=False,
        allow_agent=False,
    )
    return client


def _run(client: Any, command: str, *, timeout_sec: float = 60.0, sudo_password: str = "") -> tuple[int, str, str]:
    stdin, stdout, stderr = client.exec_command(command, timeout=timeout_sec, get_pty=bool(sudo_password))
    if sudo_password:
        stdin.write(f"{sudo_password}\n")
        stdin.flush()
    stdin.close()
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    return stdout.channel.recv_exit_status(), out, err


def _strip_sudo_echo(text: str, sudo_password: str) -> str:
    if not sudo_password:
        return text
    cleaned: list[str] = []
    normalized = str(text or "").replace("\r\n", "\n").replace("\r", "\n")
    for raw_line in normalized.split("\n"):
        if raw_line.strip().strip("\x00") == sudo_password:
            continue
        cleaned.append(raw_line)
    return "\n".join(cleaned)


def _install_dropin_command(unit: str, payload: str, *, sudo_prefix: str) -> str:
    remote_tmp = f"/tmp/siem-stock-eps-{unit.replace('/', '_').replace('@', '_')}.conf"
    target = f"/etc/systemd/system/{unit}.d/50-stock-eps.conf"
    return (
        f"cat > {shlex.quote(remote_tmp)} <<'EOF'\n"
        f"{payload}"
        "EOF\n"
        f"{sudo_prefix} install -D -m 0644 {shlex.quote(remote_tmp)} {shlex.quote(target)} && "
        f"rm -f {shlex.quote(remote_tmp)}"
    )


def _sudo_password_for_host(host_name: str, fallback_env: str) -> str:
    specific = f"{host_name}_PASSWORD"
    value = str(os.getenv(specific, "") or "").strip()
    if value:
        return value
    if fallback_env:
        return str(os.getenv(fallback_env, "") or "").strip()
    return ""


def apply_profile(args: argparse.Namespace) -> dict[str, Any]:
    selected = profile_items(str(args.profile))
    key_path = str(Path(args.ssh_key).expanduser())
    result: dict[str, Any] = {
        "profile": args.profile,
        "mode": "execute" if args.execute else "dry-run",
        "restart": bool(args.restart),
        "started_at_utc": datetime.now(timezone.utc).isoformat(),
        "hosts": [],
    }
    for item in selected:
        host_result: dict[str, Any] = {
            "name": item.name,
            "host": item.host,
            "units": list(item.units),
            "restart_units": list(item.restart_units),
            "env": dict(sorted(item.env.items())),
            "dropin": render_dropin(item.env),
            "commands": [],
        }
        sudo_password = _sudo_password_for_host(item.name, str(args.sudo_password_env or ""))
        sudo_prefix = "sudo -S -p ''" if sudo_password else "sudo -n"
        host_result["sudo_mode"] = "password" if sudo_password else "nopasswd"
        for unit in item.units:
            host_result["commands"].append(_install_dropin_command(unit, render_dropin(item.env), sudo_prefix=sudo_prefix))
        if args.restart:
            host_result["commands"].append(f"{sudo_prefix} systemctl daemon-reload")
            if item.restart_units:
                restart_script = " ".join(shlex.quote(unit) for unit in item.restart_units)
                host_result["commands"].append(
                    "for unit in "
                    f"{restart_script}; do "
                    f"systemctl cat \"$unit\" >/dev/null 2>&1 && {sudo_prefix} systemctl try-restart \"$unit\" || true; "
                    "done"
                )
                host_result["commands"].append(
                    "systemctl is-active " + " ".join(shlex.quote(unit) for unit in item.restart_units) + " || true"
                )
        if args.execute:
            client = _connect(item.host, args.user, key_path)
            try:
                executed: list[dict[str, Any]] = []
                for command in host_result["commands"]:
                    code, out, err = _run(
                        client,
                        command,
                        timeout_sec=max(30.0, float(args.command_timeout_sec)),
                        sudo_password=sudo_password,
                    )
                    executed.append(
                        {
                            "command": command,
                            "code": code,
                            "out": _strip_sudo_echo(out, sudo_password).strip(),
                            "err": _strip_sudo_echo(err, sudo_password).strip(),
                        }
                    )
                    if code != 0:
                        host_result["status"] = "failed"
                        break
                    time.sleep(0.2)
                host_result["executed"] = executed
                host_result.setdefault("status", "success")
            except Exception as exc:  # noqa: BLE001
                host_result["status"] = "failed"
                host_result["error"] = str(exc)
            finally:
                client.close()
        result["hosts"].append(host_result)
    result["finished_at_utc"] = datetime.now(timezone.utc).isoformat()
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Apply stock EPS performance profile through systemd drop-ins.")
    parser.add_argument("--profile", choices=("balanced", "aggressive"), default="balanced")
    parser.add_argument("--execute", action="store_true", help="Install drop-ins over SSH. Default is dry-run JSON only.")
    parser.add_argument("--restart", action="store_true", help="Restart affected non-template services after install.")
    parser.add_argument("--ssh-key", default=str(DEFAULT_SSH_KEY))
    parser.add_argument("--user", default=os.getenv("SIEM_SSH_USER", "rdegon"))
    parser.add_argument(
        "--sudo-password-env",
        default="",
        help="Optional fallback env var for sudo password. Per-host SIEM_VM1_PASSWORD/SIEM_VM2_PASSWORD/etc. take precedence.",
    )
    parser.add_argument("--command-timeout-sec", type=float, default=60.0)
    parser.add_argument("--output", default="")
    args = parser.parse_args(argv)

    payload = apply_profile(args)
    rendered = json.dumps(payload, ensure_ascii=False, indent=2)
    if str(args.output or "").strip():
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    failed = [item for item in payload.get("hosts", []) if dict(item).get("status") == "failed"]
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
