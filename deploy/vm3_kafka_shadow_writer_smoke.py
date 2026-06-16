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


def _bool_flag(value: str | None) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _run(command: str, *, sudo_password: str = "", use_sudo: bool = False, timeout: int = 300) -> tuple[int, str, str]:
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
    sudo_password = _required_env("SIEM_VM3_PASSWORD")
    expected_host = _required_env("SIEM_VM3_EXPECT_HOST", default="siem-storage")
    require_shadow_flow = _bool_flag(os.getenv("SIEM_KAFKA_REQUIRE_SHADOW_FLOW"))

    code, out, err = _run("hostname")
    hostname = out.strip()
    if code != 0 or not hostname:
        raise SystemExit(f"Unable to read local hostname: {err.strip()}")
    if hostname != expected_host:
        raise SystemExit(f"This smoke script must run on {expected_host}, got {hostname}")

    verify_cmd = (
        "/opt/siem/venv-storage/bin/python - <<'PY'\n"
        "import socket\n"
        "from pathlib import Path\n"
        "from clickhouse_driver import Client\n"
        "shadow_env = Path('/etc/siem/storage-kafka-shadow.env').read_text(encoding='utf-8')\n"
        "for needle in [\n"
        "    'SIEM_TRANSPORT_BACKEND=kafka',\n"
        "    'SIEM_TRANSPORT_CONSUMER_BACKEND=kafka',\n"
        "    'SIEM_EVENTS_TABLE=siem.events_shadow',\n"
        "]:\n"
        "    if needle not in shadow_env:\n"
        "        raise SystemExit(f'missing shadow env setting: {needle}')\n"
        "env = {}\n"
        "for raw_line in Path('/etc/siem/storage.env').read_text(encoding='utf-8').splitlines():\n"
        "    line = raw_line.strip()\n"
        "    if not line or line.startswith('#') or '=' not in line:\n"
        "        continue\n"
        "    key, value = line.split('=', 1)\n"
        "    env[key.strip()] = value.strip()\n"
        "for broker in ['192.168.1.35', '192.168.1.37', '192.168.1.40']:\n"
        "    sock = socket.socket()\n"
        "    sock.settimeout(3)\n"
        "    try:\n"
        "        sock.connect((broker, 9092))\n"
        "    except Exception as exc:\n"
        "        raise SystemExit(f'unable to reach kafka broker {broker}: {exc}')\n"
        "    finally:\n"
        "        sock.close()\n"
        "client = Client(host=env.get('SIEM_CH_HOST', '127.0.0.1'), port=int(env.get('SIEM_CH_PORT', '9000')), user=env.get('SIEM_CH_USER', 'siem_admin'), password=env.get('SIEM_CH_PASSWORD', ''), database=env.get('SIEM_CH_DB', 'siem'))\n"
        "rows = client.execute(\"EXISTS TABLE siem.events_shadow\")\n"
        "if not rows or rows[0][0] != 1:\n"
        "    raise SystemExit('shadow events table missing')\n"
        "counts = client.execute(\"SELECT countIf(ts >= now() - INTERVAL 5 MINUTE), countIf(ts >= now() - INTERVAL 15 MINUTE), max(ts) FROM siem.events_shadow\")[0]\n"
        "shadow_5m = int(counts[0] or 0)\n"
        "shadow_15m = int(counts[1] or 0)\n"
        "shadow_max_ts = str(counts[2] or '')\n"
        "print(f'shadow_events_5m={shadow_5m}')\n"
        "print(f'shadow_events_15m={shadow_15m}')\n"
        "print(f'shadow_max_ts={shadow_max_ts}')\n"
        "print('vm3_kafka_shadow_table=ok')\n"
        "PY"
    )
    code, out, err = _run(verify_cmd, sudo_password=sudo_password, use_sudo=True)
    verify_cleaned = _strip_sudo_echo(out, sudo_password)
    if verify_cleaned.strip():
        print(verify_cleaned, end="")
    if code != 0:
        raise SystemExit(f"VM3 Kafka shadow writer smoke failed: stdout={verify_cleaned.strip()} stderr={err.strip()}")

    code, out, err = _run("systemctl is-active siem-writer-shadow", sudo_password=sudo_password, use_sudo=True)
    cleaned = _strip_sudo_echo(out, sudo_password)
    if code != 0 or "active" not in cleaned:
        raise SystemExit(f"siem-writer-shadow is not active: stdout={cleaned.strip()} stderr={err.strip()}")
    print("siem-writer-shadow status=active")
    if require_shadow_flow:
        shadow_15m = 0
        shadow_max_ts = ""
        for raw_line in verify_cleaned.replace("\r", "\n").split("\n"):
            line = raw_line.strip()
            if line.startswith("shadow_events_15m="):
                shadow_15m = int(line.split("=", 1)[1] or 0)
            elif line.startswith("shadow_max_ts="):
                shadow_max_ts = line.split("=", 1)[1].strip()
        if shadow_15m <= 0 or not shadow_max_ts:
            raise SystemExit("Kafka shadow flow is required but no recent shadow events were observed")
    print("smoke=success")
    return 0


if __name__ == "__main__":
    sys.exit(main())
