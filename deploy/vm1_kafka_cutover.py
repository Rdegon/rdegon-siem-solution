from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from deploy.vm1_kafka_shadow_prepare import LIVE_REPO_DIR, INGEST_ENV, render_ingest_env


WORKSPACE_REPO_DIR = Path.cwd()


def _required_env(name: str, *, default: str | None = None) -> str:
    value = str(os.getenv(name, default or "") or "").strip()
    if value:
        return value
    raise SystemExit(f"Missing required environment variable: {name}")


def _run(command: str, *, sudo_password: str = "", use_sudo: bool = False, timeout: int = 240) -> tuple[int, str, str]:
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


def _post_smoke_event() -> dict[str, object]:
    payload = [
        {
            "message": "kafka-cutover-smoke",
            "source": "vm1-kafka-cutover",
            "source_type": "synthetic",
            "event.dataset": "smoke",
            "tags": ["synthetic", "smoke", "kafka-cutover"],
        }
    ]
    request = urllib.request.Request(
        "http://127.0.0.1:8443/ingest/json",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    last_error: Exception | None = None
    for attempt in range(1, 7):
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                raw = response.read().decode("utf-8", errors="replace")
            return json.loads(raw) if raw else {}
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last_error = exc
            if attempt >= 6:
                raise
            time.sleep(2.0)
    if last_error is not None:
        raise last_error
    return {}


def main() -> int:
    sudo_password = _required_env("SIEM_VM1_PASSWORD")
    expected_host = _required_env("SIEM_VM1_EXPECT_HOST", default="siem-ingest")

    code, out, err = _run("hostname")
    hostname = out.strip()
    if code != 0 or not hostname:
        raise SystemExit(f"Unable to read local hostname: {err.strip()}")
    if hostname != expected_host:
        raise SystemExit(f"This cutover script must run on {expected_host}, got {hostname}")

    verify_presence_cmd = f"test -f {shlex.quote(str(INGEST_ENV))} && test -d {shlex.quote(str(LIVE_REPO_DIR))}"
    code, _, err = _run(verify_presence_cmd, sudo_password=sudo_password, use_sudo=True)
    if code != 0:
        raise SystemExit(f"Missing required VM1 files: {err.strip()}")

    backup_root = f"/tmp/siem-vm1-kafka-cutover-{datetime.now(tz=timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
    backup_cmd = (
        f"mkdir -p {shlex.quote(backup_root)} && "
        f"cp {shlex.quote(str(INGEST_ENV))} {shlex.quote(backup_root + '/ingest.env')}"
    )
    code, _, err = _run(backup_cmd, sudo_password=sudo_password, use_sudo=True)
    if code != 0:
        raise SystemExit(f"Failed to back up {INGEST_ENV}: {err.strip()}")

    code, out, err = _run(f"cat {shlex.quote(str(INGEST_ENV))}", sudo_password=sudo_password, use_sudo=True)
    ingest_env_text = _strip_sudo_echo(out, sudo_password)
    if code != 0:
        raise SystemExit(f"Unable to read {INGEST_ENV}: {err.strip()}")

    temp_root = WORKSPACE_REPO_DIR / ".tmp"
    temp_root.mkdir(parents=True, exist_ok=True)
    temp_env_path = temp_root / "siem-vm1-kafka-cutover.env"
    temp_env_path.write_text(render_ingest_env(ingest_env_text, transport_backend="kafka"), encoding="utf-8")

    install_cmd = (
        f"install -m 0600 {shlex.quote(str(temp_env_path))} {shlex.quote(str(INGEST_ENV))} && "
        "systemctl restart siem-ingest"
    )
    code, out, err = _run(install_cmd, sudo_password=sudo_password, use_sudo=True)
    cleaned = _strip_sudo_echo(out, sudo_password)
    if cleaned.strip():
        print(cleaned, end="")
    if code != 0:
        raise SystemExit(f"Failed to apply Kafka-only ingest env: {err.strip()}")

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
        "print('vm1_ingest_kafka_cutover_env=ok')\n"
        "PY"
    )
    code, out, err = _run(verify_cmd, sudo_password=sudo_password, use_sudo=True)
    cleaned = _strip_sudo_echo(out, sudo_password)
    if cleaned.strip():
        print(cleaned, end="")
    if code != 0:
        raise SystemExit(f"VM1 Kafka cutover verification failed: stdout={cleaned.strip()} stderr={err.strip()}")

    code, out, err = _run("systemctl is-active siem-ingest", sudo_password=sudo_password, use_sudo=True)
    cleaned = _strip_sudo_echo(out, sudo_password)
    if code != 0 or "active" not in cleaned:
        raise SystemExit(f"siem-ingest is not active after cutover: stdout={cleaned.strip()} stderr={err.strip()}")

    result = _post_smoke_event()
    if int(result.get("ingested") or 0) < 1:
        raise SystemExit(f"Local Kafka-only ingest smoke did not ingest data: {result}")

    print("siem-ingest status=active")
    print("kafka_cutover_smoke=ok")
    print("cutover=success")
    print(f"backup_root={backup_root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
