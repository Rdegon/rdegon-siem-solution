from __future__ import annotations

import os
import shlex
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from deploy.kafka_wave_prepare import (  # noqa: E402
    KAFKA_BINARY,
    KAFKA_CLIENT_PROPERTIES,
    KAFKA_CLUSTER_ID_FILE,
    KAFKA_ENV_FILE,
    KAFKA_SERVER_PROPERTIES,
    KAFKA_SYSTEMD_UNIT,
)


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


def require_quorum_check(value: str | None) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def main() -> int:
    sudo_password = _required_env("SIEM_NODE_PASSWORD")
    expected_host = str(os.getenv("SIEM_KAFKA_EXPECT_HOST", "") or "").strip()
    require_quorum = require_quorum_check(os.getenv("SIEM_KAFKA_REQUIRE_QUORUM"))

    code, out, err = _run("hostname")
    hostname = out.strip()
    if code != 0 or not hostname:
        raise SystemExit(f"Unable to read local hostname: {err.strip()}")
    if expected_host and hostname != expected_host:
        raise SystemExit(f"This smoke script must run on {expected_host}, got {hostname}")

    verify_cmd = (
        "python3 - <<'PY'\n"
        "from pathlib import Path\n"
        f"for path in [{str(KAFKA_SERVER_PROPERTIES)!r}, {str(KAFKA_ENV_FILE)!r}, {str(KAFKA_SYSTEMD_UNIT)!r}, {str(KAFKA_CLUSTER_ID_FILE)!r}, {str(KAFKA_CLIENT_PROPERTIES)!r}]:\n"
        "    item = Path(path)\n"
        "    if not item.exists():\n"
        "        raise SystemExit(f'missing required kafka prepare file: {path}')\n"
        f"props = Path({str(KAFKA_SERVER_PROPERTIES)!r}).read_text(encoding='utf-8')\n"
        f"env = Path({str(KAFKA_ENV_FILE)!r}).read_text(encoding='utf-8')\n"
        f"cluster_id = Path({str(KAFKA_CLUSTER_ID_FILE)!r}).read_text(encoding='utf-8').strip()\n"
        "for needle in ['process.roles=broker,controller', 'controller.quorum.voters=', 'min.insync.replicas=2']:\n"
        "    if needle not in props:\n"
        "        raise SystemExit(f'missing server.properties setting: {needle}')\n"
        "for needle in ['SIEM_KAFKA_BOOTSTRAP_SERVERS=', 'SIEM_KAFKA_EXPECTED_BROKERS=3', 'SIEM_KAFKA_CLUSTER_ID=']:\n"
        "    if needle not in env:\n"
        "        raise SystemExit(f'missing kafka.env setting: {needle}')\n"
        "if not cluster_id:\n"
        "    raise SystemExit('cluster.id file is empty')\n"
        "print('kafka_prepare_files=ok')\n"
        "PY"
    )
    code, out, err = _run(verify_cmd, sudo_password=sudo_password, use_sudo=True)
    cleaned = _strip_sudo_echo(out, sudo_password)
    if cleaned.strip():
        print(cleaned, end="")
    if code != 0:
        raise SystemExit(f"Kafka prepare smoke failed: stdout={cleaned.strip()} stderr={err.strip()}")

    code, out, err = _run("java -version 2>&1 | head -n 1", sudo_password=sudo_password, use_sudo=True)
    cleaned = _strip_sudo_echo(out, sudo_password)
    if code != 0 or "openjdk version" not in cleaned.lower():
        raise SystemExit(f"Java runtime is not ready: stdout={cleaned.strip()} stderr={err.strip()}")
    print(f"java={cleaned.strip()}")

    code, out, err = _run(f"test -x {shlex.quote(str(KAFKA_BINARY))}", sudo_password=sudo_password, use_sudo=True)
    if code != 0:
        raise SystemExit(f"Kafka binary missing at {KAFKA_BINARY}")

    cleaned = ""
    err = ""
    for _ in range(18):
        code, out, err = _run("systemctl is-active siem-kafka", sudo_password=sudo_password, use_sudo=True)
        cleaned = _strip_sudo_echo(out, sudo_password).strip()
        if cleaned == "active":
            break
        time.sleep(5)
    else:
        raise SystemExit(f"Kafka service is not active: stdout={cleaned.strip()} stderr={err.strip()}")
    print("kafka_service=active")

    if require_quorum:
        quorum_cmd = f"{shlex.quote(str(KAFKA_HOME := Path('/opt/kafka') / 'bin/kafka-metadata-quorum.sh'))} --bootstrap-server 127.0.0.1:9092 describe --status"
        cleaned = ""
        err = ""
        for _ in range(18):
            code, out, err = _run(quorum_cmd, sudo_password=sudo_password, use_sudo=True, timeout=120)
            cleaned = _strip_sudo_echo(out, sudo_password)
            if code == 0 and ("ClusterId:" in cleaned or "LeaderId:" in cleaned):
                break
            time.sleep(5)
        else:
            raise SystemExit(f"Kafka quorum status failed: stdout={cleaned.strip()} stderr={err.strip()}")
        print("kafka_quorum=ok")
    else:
        print("kafka_quorum=skipped")
    print("smoke=success")
    return 0


if __name__ == "__main__":
    sys.exit(main())
