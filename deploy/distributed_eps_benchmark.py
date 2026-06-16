from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import shlex
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    import paramiko
except ModuleNotFoundError:  # pragma: no cover - unit-test import path
    paramiko = None  # type: ignore[assignment]


ROOT = Path(__file__).resolve().parents[1]
WORKER_PATH = ROOT / "deploy" / "eps_worker.py"
DEFAULT_STAGES = (1000, 2500, 5000)
DEFAULT_INJECTORS = ("SIEM_VM1", "SIEM_VM2", "SIEM_VM4", "SIEM_VM5")


@dataclass(frozen=True)
class HostSpec:
    prefix: str
    host: str
    user: str
    password: str


def _required_env(name: str, *, default: str | None = None) -> str:
    value = str(os.getenv(name, default or "") or "").strip()
    if value:
        return value
    raise SystemExit(f"Missing required environment variable: {name}")


def parse_stages(value: str | None) -> tuple[int, ...]:
    if not str(value or "").strip():
        return DEFAULT_STAGES
    return tuple(max(1, int(item.strip())) for item in str(value).split(",") if item.strip()) or DEFAULT_STAGES


def _connect_client(host: str, user: str, password: str) -> paramiko.SSHClient:
    if paramiko is None:
        raise RuntimeError("paramiko is required for distributed EPS benchmark")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(host, username=user, password=password, timeout=20, banner_timeout=20, auth_timeout=20, look_for_keys=False, allow_agent=False)
    return client


def _run(client: paramiko.SSHClient, command: str, *, sudo_password: str = "", use_sudo: bool = False) -> tuple[int, str, str]:
    wrapped = f"sudo -S -p '' bash -lc {shlex.quote(command)}" if use_sudo else command
    stdin, stdout, stderr = client.exec_command(wrapped, get_pty=use_sudo)
    if use_sudo:
        stdin.write(f"{sudo_password}\n")
        stdin.flush()
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    code = stdout.channel.recv_exit_status()
    return code, out, err


def split_stage_target(total_eps: int, workers: int) -> list[int]:
    workers = max(1, int(workers))
    base = total_eps // workers
    remainder = total_eps % workers
    return [base + (1 if index < remainder else 0) for index in range(workers)]


def _upload_worker(client: paramiko.SSHClient, worker_path: Path) -> str:
    remote_path = f"/tmp/{worker_path.name}"
    sftp = client.open_sftp()
    try:
        sftp.put(str(worker_path), remote_path)
    finally:
        sftp.close()
    _run(client, f"chmod +x {shlex.quote(remote_path)}")
    return remote_path


def _query_event_count(client: paramiko.SSHClient, *, sudo_password: str, run_id: str, stage_id: int) -> int:
    escaped = f"{run_id}:{stage_id}".replace("'", "''")
    command = (
        "source /etc/siem/storage.env && "
        "clickhouse-client --host \"$SIEM_CH_HOST\" --port \"$SIEM_CH_PORT\" --user \"$SIEM_CH_USER\" --password \"$SIEM_CH_PASSWORD\" "
        f"--query \"SELECT count() FROM siem.events WHERE ts >= now() - INTERVAL 30 MINUTE AND message LIKE '{escaped}:%' FORMAT TabSeparated\""
    )
    code, out, err = _run(client, command, sudo_password=sudo_password, use_sudo=True)
    if code != 0:
        raise RuntimeError(f"Unable to query benchmark count: {err.strip()}")
    return int(str(out or "").strip().splitlines()[-1] or 0)


def _query_kafka_lag(client: paramiko.SSHClient) -> int | None:
    command = "command -v kafka-consumer-groups.sh >/dev/null 2>&1 && kafka-consumer-groups.sh --bootstrap-server 127.0.0.1:9092 --all-groups --describe 2>/dev/null || true"
    code, out, _ = _run(client, command)
    if code != 0:
        return None
    lag_values: list[int] = []
    for line in str(out or "").splitlines():
        columns = [part for part in line.split() if part]
        if not columns or columns[0].startswith("GROUP") or "LAG" in columns:
            continue
        last = columns[-1]
        if last.isdigit():
            lag_values.append(int(last))
    return max(lag_values) if lag_values else None


def run_stage(
    *,
    run_id: str,
    stage_eps: int,
    duration_sec: int,
    batch_size: int,
    request_timeout_sec: float,
    ingest_url: str,
    ingest_secret: str,
    injectors: list[HostSpec],
    vm3: HostSpec,
) -> dict[str, Any]:
    per_worker = split_stage_target(stage_eps, len(injectors))
    started = time.time()
    worker_results: list[dict[str, Any]] = []

    def _run_remote(index: int, host: HostSpec) -> dict[str, Any]:
        client = _connect_client(host.host, host.user, host.password)
        try:
            remote_worker = _upload_worker(client, WORKER_PATH)
            command = (
                f"python3 {shlex.quote(remote_worker)} "
                f"--ingest-url {shlex.quote(ingest_url)} "
                f"--ingest-secret {shlex.quote(ingest_secret)} "
                f"--run-id {shlex.quote(run_id)} "
                f"--stage-id {int(stage_eps)} "
                f"--worker-id {shlex.quote(host.prefix.lower())} "
                f"--eps-target {int(per_worker[index])} "
                f"--duration-sec {int(duration_sec)} "
                f"--batch-size {int(batch_size)} "
                f"--request-timeout-sec {float(request_timeout_sec)}"
            )
            code, out, err = _run(client, command)
            if code != 0:
                raise RuntimeError(f"{host.prefix} worker failed: {err.strip()}")
            payload = json.loads(str(out or "").strip().splitlines()[-1])
            payload["injector"] = host.prefix
            return payload
        finally:
            client.close()

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(injectors)) as pool:
        futures = [pool.submit(_run_remote, index, host) for index, host in enumerate(injectors)]
        for future in concurrent.futures.as_completed(futures):
            try:
                worker_results.append(future.result())
            except Exception as exc:  # noqa: BLE001
                worker_results.append({"injector": "unknown", "status": "error", "error": str(exc), "sent": 0, "achieved_eps": 0.0})

    load_duration = max((float(item.get("duration_sec") or 0.0) for item in worker_results), default=max(0.001, time.time() - started))
    observation_started = time.time()
    vm3_client = _connect_client(vm3.host, vm3.user, vm3.password)
    try:
        time.sleep(8)
        stored = _query_event_count(vm3_client, sudo_password=vm3.password, run_id=run_id, stage_id=stage_eps)
    finally:
        vm3_client.close()

    kafka_probe_host = injectors[-1]
    kafka_client = _connect_client(kafka_probe_host.host, kafka_probe_host.user, kafka_probe_host.password)
    try:
        kafka_lag = _query_kafka_lag(kafka_client)
    finally:
        kafka_client.close()

    sent = sum(int(item.get("sent") or 0) for item in worker_results)
    duration = max(0.001, time.time() - started)
    observation_duration = max(0.0, time.time() - observation_started)
    worker_errors = [str(item.get("error") or "") for item in worker_results if str(item.get("status") or "") == "error"]
    stage_latency_p95 = max((float(dict(item.get("latency") or {}).get("p95_ms") or 0.0) for item in worker_results), default=0.0)
    stage_latency_p50 = max((float(dict(item.get("latency") or {}).get("p50_ms") or 0.0) for item in worker_results), default=0.0)
    stage_latency_max = max((float(dict(item.get("latency") or {}).get("max_ms") or 0.0) for item in worker_results), default=0.0)
    return {
        "eps_target_total": int(stage_eps),
        "duration_sec": int(duration_sec),
        "actual_duration_sec": round(duration, 3),
        "load_duration_sec": round(load_duration, 3),
        "observation_duration_sec": round(observation_duration, 3),
        "workers": worker_results,
        "sent": sent,
        "stored": stored,
        "delivery_ratio": round(stored / sent, 4) if sent else 0.0,
        "achieved_eps": round(sent / max(0.001, load_duration), 2),
        "largest_consumer_lag": kafka_lag,
        "alert_latency_sec": None,
        "latency": {
            "p50_ms": round(stage_latency_p50, 1),
            "p95_ms": round(stage_latency_p95, 1),
            "max_ms": round(stage_latency_max, 1),
        },
        "status": "failed" if worker_errors else "success",
        "errors": worker_errors,
    }


def summarize_results(results: list[dict[str, Any]]) -> dict[str, Any]:
    successful = [item for item in results if str(item.get("status") or "success") == "success" and float(item.get("delivery_ratio") or 0.0) >= 0.995]
    best = max(
        successful or results,
        key=lambda item: float(item.get("achieved_eps") or item.get("eps_target_total") or 0.0),
        default={},
    )
    return {
        "best_sustained_eps": int(round(float(best.get("achieved_eps") or best.get("eps_target_total") or 0.0))),
        "best_target_eps": int(best.get("eps_target_total") or 0),
        "best_delivery_ratio": float(best.get("delivery_ratio") or 0.0),
        "max_observed_consumer_lag": max((int(item.get("largest_consumer_lag") or 0) for item in results), default=0),
        "stages": results,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run a distributed EPS benchmark across VM1/VM2/VM4/VM5")
    parser.add_argument("--ingest-url", default=_required_env("SIEM_BENCHMARK_INGEST_URL", default="https://192.168.1.35/ingest/json"))
    parser.add_argument("--duration-sec", type=int, default=int(_required_env("SIEM_BENCHMARK_STAGE_DURATION_SEC", default="20")))
    parser.add_argument("--batch-size", type=int, default=int(_required_env("SIEM_BENCHMARK_BATCH_SIZE", default="200")))
    parser.add_argument("--request-timeout-sec", type=float, default=float(_required_env("SIEM_BENCHMARK_REQUEST_TIMEOUT_SEC", default="30")))
    parser.add_argument("--stages", default=str(os.getenv("SIEM_BENCHMARK_STAGES") or ""))
    args = parser.parse_args(argv)

    injectors = [
        HostSpec(prefix, _required_env(f"{prefix}_HOST"), _required_env(f"{prefix}_USER"), _required_env(f"{prefix}_PASSWORD"))
        for prefix in DEFAULT_INJECTORS
    ]
    vm3 = HostSpec("SIEM_VM3", _required_env("SIEM_VM3_HOST"), _required_env("SIEM_VM3_USER"), _required_env("SIEM_VM3_PASSWORD"))
    ingest_secret = _required_env("SIEM_INGEST_API_SHARED_SECRET")
    run_id = f"distributed-eps-{int(time.time())}"
    stages = parse_stages(args.stages)
    results: list[dict[str, Any]] = []
    print(json.dumps({"run_id": run_id, "stages": stages, "injectors": [item.prefix for item in injectors]}, ensure_ascii=True, sort_keys=True))
    for stage in stages:
        result = run_stage(
            run_id=run_id,
            stage_eps=int(stage),
            duration_sec=int(args.duration_sec),
            batch_size=int(args.batch_size),
            request_timeout_sec=float(args.request_timeout_sec),
            ingest_url=str(args.ingest_url),
            ingest_secret=ingest_secret,
            injectors=injectors,
            vm3=vm3,
        )
        results.append(result)
        print(json.dumps(result, ensure_ascii=True, sort_keys=True))
    print(json.dumps(summarize_results(results), ensure_ascii=True, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
