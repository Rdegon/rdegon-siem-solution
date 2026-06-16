from __future__ import annotations

import os
import shlex
import subprocess
import sys


def _required_env(name: str, *, default: str | None = None) -> str:
    value = str(os.getenv(name, default or "") or "").strip()
    if value:
        return value
    raise SystemExit(f"Missing required environment variable: {name}")


def _run(command: str, *, sudo_password: str = "", use_sudo: bool = False, timeout: int = 180) -> tuple[int, str, str]:
    wrapped = f"sudo -S -p '' bash -lc {shlex.quote(command)}" if use_sudo else command
    proc = subprocess.run(
        ["bash", "-lc", wrapped],
        input=f"{sudo_password}\n" if use_sudo else None,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return proc.returncode, proc.stdout, proc.stderr


def _strip_sudo_echo(text: str, sudo_password: str) -> str:
    if not sudo_password:
        return text
    cleaned: list[str] = []
    for raw_line in str(text or "").replace("\r", "\n").split("\n"):
        if raw_line.strip() == sudo_password:
            continue
        cleaned.append(raw_line)
    return "\n".join(cleaned)


def main() -> int:
    sudo_password = _required_env("SIEM_VM1_PASSWORD")
    expected_host = _required_env("SIEM_VM1_EXPECT_HOST", default="siem-ingest")

    code, out, err = _run("hostname")
    hostname = out.strip()
    if code != 0 or not hostname:
        raise SystemExit(f"Unable to read local hostname: {err.strip()}")
    if hostname != expected_host:
        raise SystemExit(f"This smoke script must run on {expected_host}, got {hostname}")

    verify_cmd = (
        "python3 - <<'PY'\n"
        "from pathlib import Path\n"
        "env_text = Path('/etc/siem/ingest.env').read_text(encoding='utf-8')\n"
        "for needle in [\n"
        "    'SIEM_TRANSPORT_BACKEND=kafka',\n"
        "    'SIEM_KAFKA_BOOTSTRAP_SERVERS=192.168.1.35:9092,192.168.1.37:9092,192.168.1.40:9092',\n"
        "    'SIEM_KAFKA_SECURITY_PROTOCOL=PLAINTEXT',\n"
        "]:\n"
        "    if needle not in env_text:\n"
        "        raise SystemExit(f'missing ingest env setting: {needle}')\n"
        "print('vm1_ingest_kafka_env=ok')\n"
        "PY"
    )
    code, out, err = _run(verify_cmd, sudo_password=sudo_password, use_sudo=True)
    cleaned = _strip_sudo_echo(out, sudo_password)
    if cleaned.strip():
        print(cleaned, end="")
    if code != 0:
        raise SystemExit(f"VM1 Kafka shadow smoke failed: stdout={cleaned.strip()} stderr={err.strip()}")

    code, out, err = _run("systemctl is-active siem-ingest", sudo_password=sudo_password, use_sudo=True)
    cleaned = _strip_sudo_echo(out, sudo_password)
    if code != 0 or "active" not in cleaned:
        raise SystemExit(f"siem-ingest is not active: stdout={cleaned.strip()} stderr={err.strip()}")
    print("siem-ingest status=active")
    print("smoke=success")
    return 0


if __name__ == "__main__":
    sys.exit(main())
