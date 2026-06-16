from __future__ import annotations

import os
import json
import shlex
import sys
import time

import paramiko


def _required_env(name: str, *, default: str | None = None) -> str:
    value = os.getenv(name, default or "").strip()
    if value:
        return value
    raise SystemExit(f"Missing required environment variable: {name}")


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
    cleaned_lines: list[str] = []
    for raw_line in str(text or "").replace("\r", "\n").split("\n"):
        line = raw_line.strip("\x00")
        if line.strip() == sudo_password:
            continue
        cleaned_lines.append(line)
    return "\n".join(cleaned_lines)


def main() -> int:
    host = _required_env("SIEM_VM3_HOST")
    user = _required_env("SIEM_VM3_USER")
    password = _required_env("SIEM_VM3_PASSWORD")
    expected_mode = str(os.getenv("SIEM_STREAM_CORR_TIME_MODE", "event") or "event").strip().lower()
    expected_shadow = str(os.getenv("SIEM_STREAM_CORR_SHADOW_COMPARE", "true") or "true").strip().lower() in {"1", "true", "yes", "on"}
    expected_state_backend = str(os.getenv("SIEM_STREAM_STATE_BACKEND", "sqlite") or "sqlite").strip().lower()
    expected_sqlite_path = str(os.getenv("SIEM_STREAM_STATE_SQLITE_PATH", "/var/lib/siem-stream-corr/runtime-state.db") or "/var/lib/siem-stream-corr/runtime-state.db").strip()
    expected_writer_scaleout = tuple(
        f"siem-writer@{part.strip()}"
        for part in str(os.getenv("SIEM_WRITER_SCALEOUT_INSTANCE_IDS", "2") or "2").split(",")
        if part.strip()
    )

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
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
    try:
        service_units = ["clickhouse-server", "siem-writer", *expected_writer_scaleout, "siem-stream-corr"]
        code, out, err = _run_command(
            client,
            f"systemctl is-active {' '.join(service_units)}",
            sudo_password=password,
            use_sudo=True,
        )
        active_out = _strip_sudo_echo(out, password)
        states = [line.strip() for line in active_out.splitlines() if line.strip()]
        if code != 0 or states != ["active"] * len(service_units):
            raise RuntimeError(f"Unexpected service state: stdout={states} stderr={err.strip()}")
        print("services=active")

        template_query_cmd = (
            "python3 - <<'PY'\n"
            "from pathlib import Path\n"
            "import json\n"
            "template = Path('/etc/systemd/system/siem-writer@.service').read_text(encoding='utf-8')\n"
            "payload = {\n"
            "  'template_ok': int('SIEM_WRITER_CONSUMER=writer-%i' in template and '/services/writer/worker.py' in template),\n"
            "}\n"
            "print(json.dumps(payload, ensure_ascii=True, sort_keys=True))\n"
            "PY"
        )
        code, out, err = _run_command(client, template_query_cmd, sudo_password=password, use_sudo=True)
        template_out = _strip_sudo_echo(out, password).strip()
        if code != 0 or not template_out:
            raise RuntimeError(f"Writer template verification failed: stdout={template_out} stderr={err.strip()}")
        template_payload = json.loads(template_out)
        if int(template_payload.get("template_ok", 0)) != 1:
            raise RuntimeError("Writer scale-out template is missing the expected consumer override or exec path")
        print("writer_scaleout_template=ok")

        query_cmd = (
            "set -a && source /etc/siem/storage.env && set +a && "
            "/opt/siem/venv-storage/bin/python - <<'PY'\n"
            "from clickhouse_driver import Client\n"
            "import os\n"
            "client = Client(\n"
            "    host=os.getenv('SIEM_CH_HOST', '127.0.0.1'),\n"
            "    port=int(os.getenv('SIEM_CH_PORT', '9000')),\n"
            "    user=os.getenv('SIEM_CH_USER', 'siem_admin'),\n"
            "    password=os.getenv('SIEM_CH_PASSWORD', ''),\n"
            "    database=os.getenv('SIEM_CH_DB', 'siem'),\n"
            ")\n"
            "rows = client.execute('SELECT transport_backend, state_backend, mode, shadow_compare, late_events_total, timestamp_fallback_total, shadow_compare_mismatches_total FROM siem.stream_corr_runtime_status ORDER BY observed_ts DESC LIMIT 1')\n"
            "if not rows:\n"
            "    raise SystemExit(5)\n"
            "row = rows[0]\n"
            "print(f\"transport_backend={row[0]}\")\n"
            "print(f\"state_backend_runtime={row[1]}\")\n"
            "print(f\"mode={row[2]}\")\n"
            "print(f\"shadow_compare={int(row[3])}\")\n"
            "print(f\"late_events_total={int(row[4])}\")\n"
            "print(f\"timestamp_fallback_total={int(row[5])}\")\n"
            "print(f\"shadow_compare_mismatches_total={int(row[6])}\")\n"
            "PY"
        )

        runtime_lines: list[str] = []
        for _ in range(15):
            code, out, err = _run_command(client, query_cmd, sudo_password=password, use_sudo=True)
            query_out = _strip_sudo_echo(out, password)
            runtime_lines = [line.strip() for line in query_out.splitlines() if line.strip()]
            if code == 0 and runtime_lines:
                break
            time.sleep(4)
        else:
            raise RuntimeError(f"Stream correlation runtime snapshot unavailable: stdout={runtime_lines} stderr={err.strip()}")

        payload = {}
        for line in runtime_lines:
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            payload[key.strip()] = value.strip()
        if payload.get("mode") != expected_mode:
            raise RuntimeError(f"Unexpected stream correlation mode: {payload.get('mode')} != {expected_mode}")
        if int(payload.get("shadow_compare", "0")) != (1 if expected_shadow else 0):
            raise RuntimeError("Unexpected shadow_compare flag")
        if payload.get("state_backend_runtime") != expected_state_backend:
            raise RuntimeError("Unexpected runtime state backend snapshot")

        state_cmd = (
            "python3 - <<'PY'\n"
            "from pathlib import Path\n"
            "payload = {}\n"
            "for line in Path('/etc/siem/storage.env').read_text(encoding='utf-8').splitlines():\n"
            "    if '=' not in line or line.lstrip().startswith('#'):\n"
            "        continue\n"
            "    key, value = line.split('=', 1)\n"
            "    payload[key.strip()] = value.strip()\n"
            "backend = payload.get('SIEM_STREAM_STATE_BACKEND', '')\n"
            "sqlite_path = payload.get('SIEM_STREAM_STATE_SQLITE_PATH', '')\n"
            "exists = int(bool(sqlite_path) and Path(sqlite_path).exists())\n"
            "print(f'state_backend={backend}')\n"
            "print(f'sqlite_path={sqlite_path}')\n"
            "print(f'sqlite_exists={exists}')\n"
            "PY"
        )
        code, out, err = _run_command(client, state_cmd, sudo_password=password, use_sudo=True)
        state_out = _strip_sudo_echo(out, password)
        if code != 0 or not state_out.strip():
            raise RuntimeError(f"Unable to read stream state settings: stdout={state_out} stderr={err.strip()}")
        state_payload: dict[str, str] = {}
        for line in state_out.splitlines():
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            state_payload[key.strip()] = value.strip()
        if state_payload.get("state_backend") != expected_state_backend:
            raise RuntimeError(f"Unexpected stream state backend: {state_payload.get('state_backend')} != {expected_state_backend}")
        if expected_state_backend == "sqlite":
            if state_payload.get("sqlite_path") != expected_sqlite_path:
                raise RuntimeError("Unexpected SQLite runtime state path")
            if state_payload.get("sqlite_exists") != "1":
                raise RuntimeError("SQLite runtime state file is missing")

        print("stream_corr_runtime=ok")
        print(f"transport_backend={payload.get('transport_backend')}")
        print(f"mode={payload.get('mode')}")
        print(f"shadow_compare={payload.get('shadow_compare')}")
        print(f"state_backend={state_payload.get('state_backend')}")
        print(f"writer_scaleout_units={','.join(expected_writer_scaleout)}")
        print("smoke=success")
        return 0
    finally:
        client.close()


if __name__ == "__main__":
    sys.exit(main())
