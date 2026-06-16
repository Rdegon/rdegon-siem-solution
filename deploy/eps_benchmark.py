from __future__ import annotations

import json
import os
import shlex
import ssl
import sys
import time
import urllib.request
from dataclasses import dataclass

try:
    import paramiko
except ModuleNotFoundError:  # pragma: no cover - exercised in unit-test import paths
    paramiko = None  # type: ignore[assignment]


DEFAULT_STAGES = (500, 1000, 2000, 4000)


@dataclass(frozen=True)
class HostSpec:
    host: str
    user: str
    password: str


def _required_env(name: str, *, default: str | None = None) -> str:
    value = str(os.getenv(name, default or "") or "").strip()
    if value:
        return value
    raise SystemExit(f"Missing required environment variable: {name}")


def parse_eps_stages(value: str | None) -> tuple[int, ...]:
    if not str(value or "").strip():
        return DEFAULT_STAGES
    return tuple(max(1, int(item.strip())) for item in str(value).split(",") if item.strip()) or DEFAULT_STAGES


def summarize_eps_results(results: list[dict[str, object]]) -> dict[str, object]:
    successful = [item for item in results if float(item.get("delivery_ratio") or 0.0) >= 0.995]
    best = max(successful or results, key=lambda item: int(item.get("eps_target") or 0), default={})
    return {"best_sustained_eps": int(best.get("eps_target") or 0), "best_delivery_ratio": float(best.get("delivery_ratio") or 0.0), "stages": results}


def _connect_client(host: str, user: str, password: str) -> paramiko.SSHClient:
    if paramiko is None:
        raise RuntimeError("paramiko is required to execute EPS benchmark")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(host, username=user, password=password, timeout=20, banner_timeout=20, auth_timeout=20, look_for_keys=False, allow_agent=False)
    return client


def _run_command(client: paramiko.SSHClient, command: str, *, sudo_password: str = "", use_sudo: bool = False) -> tuple[int, str, str]:
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
    return "\n".join(line for line in str(text or "").splitlines() if line.strip() != sudo_password)


def _last_nonempty_line(text: str) -> str:
    for line in reversed(str(text or "").splitlines()):
        if line.strip():
            return line.strip()
    return ""


def _query_event_count(client: paramiko.SSHClient, *, sudo_password: str, run_id: str, stage_id: int) -> int:
    escaped = f"{run_id}:{stage_id}".replace("'", "''")
    command = (
        "source /etc/siem/storage.env && "
        "clickhouse-client --host \"$SIEM_CH_HOST\" --port \"$SIEM_CH_PORT\" --user \"$SIEM_CH_USER\" --password \"$SIEM_CH_PASSWORD\" "
        f"--query \"SELECT count() FROM siem.events WHERE ts >= now() - INTERVAL 30 MINUTE AND message LIKE '{escaped}:%' FORMAT TabSeparated\""
    )
    code, out, err = _run_command(client, command, sudo_password=sudo_password, use_sudo=True)
    if code != 0:
        raise RuntimeError(f"Unable to query benchmark count: {err.strip()}")
    return int(_last_nonempty_line(_strip_sudo_echo(out, sudo_password)) or 0)


def _post_events(url: str, *, secret: str, batch: list[dict[str, object]]) -> None:
    context = ssl._create_unverified_context()  # noqa: SLF001
    request = urllib.request.Request(
        url,
        method="POST",
        data=json.dumps(batch).encode("utf-8"),
        headers={"Content-Type": "application/json", "X-Rdegon-Ingest-Secret": secret},
    )
    with urllib.request.urlopen(request, context=context, timeout=30):
        return


def main() -> int:
    ingest_url = _required_env("SIEM_BENCHMARK_INGEST_URL", default="https://192.168.1.35/ingest/json")
    ingest_secret = _required_env("SIEM_INGEST_API_SHARED_SECRET")
    stage_duration_sec = int(_required_env("SIEM_BENCHMARK_STAGE_DURATION_SEC", default="20"))
    batch_size = int(_required_env("SIEM_BENCHMARK_BATCH_SIZE", default="200"))
    stages = parse_eps_stages(os.getenv("SIEM_BENCHMARK_STAGES"))
    vm3 = HostSpec(_required_env("SIEM_VM3_HOST"), _required_env("SIEM_VM3_USER"), _required_env("SIEM_VM3_PASSWORD"))
    run_id = f"eps-probe-{int(time.time())}"
    vm3_client = _connect_client(vm3.host, vm3.user, vm3.password)
    try:
        results: list[dict[str, object]] = []
        print(json.dumps({"run_id": run_id, "stages": stages, "stage_duration_sec": stage_duration_sec, "batch_size": batch_size}, ensure_ascii=True, sort_keys=True))
        for eps_target in stages:
            total_events = eps_target * stage_duration_sec
            sent = 0
            started = time.perf_counter()
            while sent < total_events:
                chunk = min(batch_size, total_events - sent)
                batch = [
                    {
                        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        "message": f"{run_id}:{eps_target}:{sent + idx}",
                        "event.original": f"{run_id}:{eps_target}:{sent + idx}",
                        "host.name": "eps-bench",
                        "event.category": "benchmark",
                        "event.type": "synthetic",
                        "severity": "low",
                    }
                    for idx in range(chunk)
                ]
                _post_events(ingest_url, secret=ingest_secret, batch=batch)
                sent += chunk
                expected_elapsed = sent / eps_target
                elapsed = max(0.001, time.perf_counter() - started)
                if expected_elapsed > elapsed:
                    time.sleep(expected_elapsed - elapsed)
            send_elapsed = max(0.001, time.perf_counter() - started)
            time.sleep(8)
            stored = _query_event_count(vm3_client, sudo_password=vm3.password, run_id=run_id, stage_id=eps_target)
            stage_result = {
                "eps_target": eps_target,
                "stage_duration_sec": stage_duration_sec,
                "actual_duration_sec": round(send_elapsed, 3),
                "achieved_eps": round(sent / send_elapsed, 2) if send_elapsed else 0.0,
                "sent": sent,
                "stored": stored,
                "delivery_ratio": round(stored / sent, 4) if sent else 0.0,
            }
            results.append(stage_result)
            print(json.dumps(stage_result, ensure_ascii=True, sort_keys=True))
        print(json.dumps(summarize_eps_results(results), ensure_ascii=True, sort_keys=True))
        return 0
    finally:
        vm3_client.close()


if __name__ == "__main__":
    sys.exit(main())
