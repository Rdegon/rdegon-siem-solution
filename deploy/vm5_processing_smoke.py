from __future__ import annotations

import os
import shlex
import subprocess
import sys
from pathlib import Path


PROCESSING_ENV = Path("/etc/siem/processing.env")
SYSTEMD_NORMALIZER_TEMPLATE = Path("/etc/systemd/system/siem-normalizer@.service")
SYSTEMD_FILTER_TEMPLATE = Path("/etc/systemd/system/siem-filter@.service")
PROCESSING_SERVICE_UNITS = ("siem-normalizer@1", "siem-filter@1", "siem-normalizer@2", "siem-filter@2")


def _required_env(name: str, *, default: str | None = None) -> str:
    value = str(os.getenv(name, default or "") or "").strip()
    if value:
        return value
    raise SystemExit(f"Missing required environment variable: {name}")


def _parse_bool(value: object) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _run(command: str, *, sudo_password: str = "", use_sudo: bool = False) -> tuple[int, str, str]:
    wrapped = f"sudo -S -p '' bash -lc {shlex.quote(command)}" if use_sudo else command
    proc = subprocess.run(
        ["bash", "-lc", wrapped],
        input=f"{sudo_password}\n" if use_sudo else None,
        capture_output=True,
        text=True,
        timeout=120,
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
    sudo_password = _required_env("SIEM_VM5_PASSWORD")
    expected_host = _required_env("SIEM_VM5_EXPECT_HOST", default="siem-transport")
    enable_processing = _parse_bool(os.getenv("SIEM_VM5_ENABLE_PROCESSING", "0"))

    code, out, err = _run("hostname")
    hostname = out.strip()
    if code != 0 or hostname != expected_host:
        raise SystemExit(f"Unexpected local hostname for VM5 smoke: {hostname!r} stderr={err.strip()}")

    verify_cmd = (
        "python3 - <<'PY'\n"
        "from pathlib import Path\n"
        "for path in [\n"
        "    Path('/etc/siem/processing.env'),\n"
        "    Path('/etc/systemd/system/siem-normalizer@.service'),\n"
        "    Path('/etc/systemd/system/siem-filter@.service'),\n"
        "]:\n"
        "    if not path.exists():\n"
        "        raise SystemExit(f'missing required VM5 processing file: {path}')\n"
        "env_text = Path('/etc/siem/processing.env').read_text(encoding='utf-8')\n"
        "for needle in ['SIEM_TRANSPORT_BACKEND=kafka', 'SIEM_TRANSPORT_CONSUMER_BACKEND=kafka', 'SIEM_KAFKA_BOOTSTRAP_SERVERS=']:\n"
        "    if needle not in env_text:\n"
        "        raise SystemExit(f'missing env marker: {needle}')\n"
        "for path in [Path('/etc/systemd/system/siem-normalizer@.service'), Path('/etc/systemd/system/siem-filter@.service')]:\n"
        "    text = path.read_text(encoding='utf-8')\n"
        "    if 'ExecStart=/opt/siem/venv-processing/bin/python -m services.' not in text:\n"
        "        raise SystemExit(f'missing module ExecStart in {path}')\n"
        "redis_unit = Path('/lib/systemd/system/redis-server.service')\n"
        "if redis_unit.exists():\n"
        "    raise SystemExit('redis package still installed on VM5')\n"
        "print('vm5_processing_prepare_files=ok')\n"
        "PY"
    )
    code, out, err = _run(verify_cmd, sudo_password=sudo_password, use_sudo=True)
    cleaned = _strip_sudo_echo(out, sudo_password)
    if cleaned.strip():
        print(cleaned, end="")
    if code != 0:
        raise SystemExit(f"VM5 processing smoke failed: stdout={cleaned.strip()} stderr={err.strip()}")

    if enable_processing:
        code, out, err = _run(f"systemctl is-active {' '.join(PROCESSING_SERVICE_UNITS)}", sudo_password=sudo_password, use_sudo=True)
        cleaned = [line.strip() for line in _strip_sudo_echo(out, sudo_password).splitlines() if line.strip()]
        if code != 0 or cleaned != ["active"] * len(PROCESSING_SERVICE_UNITS):
            raise SystemExit(f"Unexpected VM5 service state: stdout={cleaned} stderr={err.strip()}")
        print("vm5_processing=active")
    else:
        print("vm5_processing=prepared_only")

    code, out, err = _run("systemctl is-active redis-server || true", sudo_password=sudo_password, use_sudo=True)
    cleaned = _strip_sudo_echo(out, sudo_password).strip()
    if cleaned not in {"inactive", "unknown", "failed", ""}:
        raise SystemExit(f"redis-server still appears active on VM5: stdout={cleaned} stderr={err.strip()}")
    print(f"vm5_redis_state={cleaned or 'absent'}")

    print("smoke=success")
    return 0


if __name__ == "__main__":
    sys.exit(main())
