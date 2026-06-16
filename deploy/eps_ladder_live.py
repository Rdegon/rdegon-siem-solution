from __future__ import annotations

import argparse
import concurrent.futures
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
except ModuleNotFoundError as exc:  # pragma: no cover
    raise SystemExit("paramiko is required for live EPS ladder tests") from exc


ROOT = Path(__file__).resolve().parents[1]
WORKER_PATH = ROOT / "deploy" / "eps_worker.py"
DEFAULT_INJECTORS = (
    ("SIEM_VM1", "192.168.1.35"),
    ("SIEM_VM2", "192.168.1.37"),
    ("SIEM_VM4", "192.168.1.39"),
    ("SIEM_VM5", "192.168.1.40"),
)
DEFAULT_VM3 = "192.168.1.38"
DEFAULT_KAFKA = "192.168.1.35"


@dataclass(frozen=True)
class HostSpec:
    name: str
    host: str
    user: str


def _connect(host: str, user: str, key_path: str) -> paramiko.SSHClient:
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


def _run(client: paramiko.SSHClient, command: str, *, timeout_sec: float | None = None) -> tuple[int, str, str]:
    stdin, stdout, stderr = client.exec_command(command, timeout=timeout_sec)
    stdin.close()
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    code = stdout.channel.recv_exit_status()
    return code, out, err


def _upload(client: paramiko.SSHClient, local: Path, remote: str) -> None:
    sftp = client.open_sftp()
    try:
        sftp.put(str(local), remote)
        sftp.chmod(remote, 0o700)
    finally:
        sftp.close()


def _write_secret_file(client: paramiko.SSHClient, remote: str, secret: str) -> None:
    sftp = client.open_sftp()
    try:
        with sftp.open(remote, "w") as handle:
            handle.write(secret)
        sftp.chmod(remote, 0o600)
    finally:
        sftp.close()


def _split_stage_target(total_eps: int, workers: int) -> list[int]:
    base = int(total_eps) // max(1, workers)
    remainder = int(total_eps) % max(1, workers)
    return [base + (1 if idx < remainder else 0) for idx in range(max(1, workers))]


def _clickhouse_count(*, vm3: HostSpec, key_path: str, run_id: str, stage: int) -> int:
    marker = f"{run_id}:{int(stage)}".replace("'", "''")
    query = (
        "SELECT count() FROM siem.events "
        f"WHERE ts >= now() - INTERVAL 2 HOUR AND message LIKE '{marker}:%' FORMAT TabSeparated"
    )
    command = f"clickhouse-client --query {shlex.quote(query)}"
    client = _connect(vm3.host, vm3.user, key_path)
    try:
        code, out, err = _run(client, command, timeout_sec=30)
    finally:
        client.close()
    if code != 0:
        raise RuntimeError(f"ClickHouse count failed: {err.strip()}")
    return int(str(out or "0").strip().splitlines()[-1] or 0)


def _clickhouse_stage_eps(*, vm3: HostSpec, key_path: str, run_id: str, stage: int) -> dict[str, Any]:
    marker = f"{run_id}:{int(stage)}".replace("'", "''")
    query = (
        "SELECT count() AS events, min(ts) AS first_ts, max(ts) AS last_ts, "
        "round(count() / greatest(1, dateDiff('second', min(ts), max(ts))), 2) AS stored_eps "
        "FROM siem.events "
        f"WHERE ts >= now() - INTERVAL 2 HOUR AND message LIKE '{marker}:%' FORMAT JSONEachRow"
    )
    client = _connect(vm3.host, vm3.user, key_path)
    try:
        code, out, err = _run(client, f"clickhouse-client --query {shlex.quote(query)}", timeout_sec=30)
    finally:
        client.close()
    if code != 0:
        return {"error": err.strip()}
    line = str(out or "").strip().splitlines()
    return json.loads(line[-1]) if line else {}


def _kafka_lag(*, kafka: HostSpec, key_path: str) -> dict[str, Any]:
    command = (
        "/opt/siem/kafka_2.13-3.7.1/bin/kafka-consumer-groups.sh "
        "--bootstrap-server 127.0.0.1:9092 --all-groups --describe 2>/dev/null"
    )
    client = _connect(kafka.host, kafka.user, key_path)
    try:
        code, out, err = _run(client, command, timeout_sec=45)
    finally:
        client.close()
    if code != 0:
        return {"ok": False, "error": err.strip(), "max_primary_lag": None, "max_all_lag": None}
    rows: list[dict[str, Any]] = []
    for line in str(out or "").splitlines():
        parts = line.split()
        if len(parts) < 6 or parts[0] == "GROUP":
            continue
        try:
            lag = int(parts[5])
            partition = int(parts[2])
        except ValueError:
            continue
        rows.append({"group": parts[0], "topic": parts[1], "partition": partition, "lag": lag})
    primary = [row for row in rows if row["group"] != "writer-standby"]
    standby = [row for row in rows if row["group"] == "writer-standby"]
    return {
        "ok": True,
        "max_primary_lag": max((int(row["lag"]) for row in primary), default=0),
        "max_standby_lag": max((int(row["lag"]) for row in standby), default=0),
        "max_all_lag": max((int(row["lag"]) for row in rows), default=0),
        "rows": rows,
    }


def _service_snapshot(*, key_path: str, hosts: list[HostSpec]) -> dict[str, Any]:
    checks = {
        "SIEM_VM1": "systemctl is-active siem-ingest siem-kafka nginx; df -h / /var/lib/siem-kafka 2>/dev/null",
        "SIEM_VM2": "systemctl is-active siem-normalizer siem-normalizer@1 siem-normalizer@2 siem-filter siem-filter@1 siem-filter@2 siem-kafka; df -h / /var/lib/siem-kafka 2>/dev/null",
        "SIEM_VM3": "systemctl is-active clickhouse-server siem-writer siem-writer@2 siem-stream-corr siem-batch-corr siem-alert-agg; df -h /",
        "SIEM_VM4": "systemctl is-active siem-web nginx postgresql mongod 2>/dev/null || true; df -h /",
        "SIEM_VM5": "systemctl is-active siem-kafka siem-normalizer siem-normalizer@1 siem-normalizer@2 siem-filter siem-filter@1 siem-filter@2 siem-writer-standby 2>/dev/null || true; df -h / /var/lib/siem-kafka 2>/dev/null",
    }
    snapshot: dict[str, Any] = {}
    for host in hosts:
        command = checks.get(host.name, "hostname; df -h /")
        try:
            client = _connect(host.host, host.user, key_path)
            try:
                code, out, err = _run(client, command, timeout_sec=20)
            finally:
                client.close()
            snapshot[host.name] = {"host": host.host, "code": code, "out": out.strip(), "err": err.strip()}
        except Exception as exc:  # noqa: BLE001
            snapshot[host.name] = {"host": host.host, "error": str(exc)}
    return snapshot


def _run_worker(
    *,
    host: HostSpec,
    key_path: str,
    remote_worker: str,
    remote_secret: str,
    ingest_url: str,
    run_id: str,
    stage: int,
    worker_id: str,
    eps_target: int,
    duration_sec: int,
    batch_size: int,
    request_timeout_sec: float,
) -> dict[str, Any]:
    client = _connect(host.host, host.user, key_path)
    try:
        command = (
            f"python3 {shlex.quote(remote_worker)} "
            f"--ingest-url {shlex.quote(ingest_url)} "
            f"--ingest-secret-file {shlex.quote(remote_secret)} "
            f"--run-id {shlex.quote(run_id)} "
            f"--stage-id {int(stage)} "
            f"--worker-id {shlex.quote(worker_id)} "
            f"--eps-target {int(eps_target)} "
            f"--duration-sec {int(duration_sec)} "
            f"--batch-size {int(batch_size)} "
            f"--request-timeout-sec {float(request_timeout_sec)}"
        )
        code, out, err = _run(client, command, timeout_sec=max(120, duration_sec + int(request_timeout_sec) * 20))
        if code != 0:
            return {"injector": host.name, "status": "error", "sent": 0, "achieved_eps": 0.0, "error": err.strip() or out.strip()}
        payload = json.loads(str(out or "").strip().splitlines()[-1])
        payload["injector"] = host.name
        payload["status"] = str(payload.get("status") or "success")
        return payload
    except Exception as exc:  # noqa: BLE001
        return {"injector": host.name, "status": "error", "sent": 0, "achieved_eps": 0.0, "error": str(exc)}
    finally:
        client.close()


def _prepare_host(host: HostSpec, *, key_path: str, run_id: str, secret: str) -> tuple[str, str]:
    remote_worker = f"/tmp/eps_worker_{run_id}.py"
    remote_secret = f"/tmp/eps_secret_{run_id}"
    client = _connect(host.host, host.user, key_path)
    try:
        _upload(client, WORKER_PATH, remote_worker)
        _write_secret_file(client, remote_secret, secret)
    finally:
        client.close()
    return remote_worker, remote_secret


def _cleanup_host(host: HostSpec, *, key_path: str, paths: tuple[str, str]) -> None:
    client = _connect(host.host, host.user, key_path)
    try:
        for path in paths:
            _run(client, f"rm -f {shlex.quote(path)}", timeout_sec=10)
    finally:
        client.close()


def run_ladder(args: argparse.Namespace) -> dict[str, Any]:
    secret = str(os.getenv("SIEM_INGEST_API_SHARED_SECRET") or "").strip()
    if not secret:
        raise SystemExit("SIEM_INGEST_API_SHARED_SECRET must be set")
    stages = [int(item.strip()) for item in str(args.stages).split(",") if item.strip()]
    if not stages:
        raise SystemExit("No stages requested")
    run_id = args.run_id or f"eps-ladder-{int(time.time())}"
    key_path = str(Path(args.ssh_key).expanduser())
    injectors = [HostSpec(name, host, args.user) for name, host in DEFAULT_INJECTORS]
    vm3 = HostSpec("SIEM_VM3", args.vm3_host, args.user)
    kafka = HostSpec("SIEM_VM1", args.kafka_host, args.user)
    all_hosts = [*injectors, vm3]

    prepared: dict[str, tuple[str, str]] = {}
    started_at = datetime.now(timezone.utc).isoformat()
    report: dict[str, Any] = {
        "run_id": run_id,
        "started_at_utc": started_at,
        "profile": {
            "stages": stages,
            "duration_sec": int(args.duration_sec),
            "batch_size": int(args.batch_size),
            "request_timeout_sec": float(args.request_timeout_sec),
            "ingest_url": args.ingest_url,
        "injectors": [host.name for host in injectors],
        "workers_per_host": int(args.workers_per_host),
        },
        "preflight": {
            "services": _service_snapshot(key_path=key_path, hosts=all_hosts),
            "kafka_lag": _kafka_lag(kafka=kafka, key_path=key_path),
        },
        "stages": [],
    }
    try:
        for host in injectors:
            prepared[host.name] = _prepare_host(host, key_path=key_path, run_id=run_id, secret=secret)
        for stage in stages:
            stage_started = time.time()
            worker_slots = [
                (host, slot_index)
                for host in injectors
                for slot_index in range(max(1, int(args.workers_per_host)))
            ]
            per_worker = _split_stage_target(stage, len(worker_slots))
            before_lag = _kafka_lag(kafka=kafka, key_path=key_path)
            worker_results: list[dict[str, Any]] = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=len(worker_slots)) as pool:
                futures = [
                    pool.submit(
                        _run_worker,
                        host=host,
                        key_path=key_path,
                        remote_worker=prepared[host.name][0],
                        remote_secret=prepared[host.name][1],
                        ingest_url=args.ingest_url,
                        run_id=run_id,
                        stage=stage,
                        worker_id=f"{host.name.lower()}_w{slot_index + 1}",
                        eps_target=per_worker[index],
                        duration_sec=int(args.duration_sec),
                        batch_size=int(args.batch_size),
                        request_timeout_sec=float(args.request_timeout_sec),
                    )
                    for index, (host, slot_index) in enumerate(worker_slots)
                ]
                for future in concurrent.futures.as_completed(futures):
                    worker_results.append(future.result())
            sent = sum(int(item.get("sent") or 0) for item in worker_results)
            load_duration = max((float(item.get("duration_sec") or 0.0) for item in worker_results), default=max(0.001, time.time() - stage_started))
            stored = 0
            observe_deadline = time.time() + float(args.observe_timeout_sec)
            while time.time() <= observe_deadline:
                stored = _clickhouse_count(vm3=vm3, key_path=key_path, run_id=run_id, stage=stage)
                if sent and stored >= sent:
                    break
                time.sleep(5)
            after_lag = _kafka_lag(kafka=kafka, key_path=key_path)
            stage_eps = _clickhouse_stage_eps(vm3=vm3, key_path=key_path, run_id=run_id, stage=stage)
            errors = [str(item.get("error") or "") for item in worker_results if str(item.get("status") or "") == "error"]
            latency = {
                "p50_ms": max((float(dict(item.get("latency") or {}).get("p50_ms") or 0.0) for item in worker_results), default=0.0),
                "p95_ms": max((float(dict(item.get("latency") or {}).get("p95_ms") or 0.0) for item in worker_results), default=0.0),
                "max_ms": max((float(dict(item.get("latency") or {}).get("max_ms") or 0.0) for item in worker_results), default=0.0),
            }
            stage_result = {
                "eps_target_total": int(stage),
                "duration_sec": int(args.duration_sec),
                "batch_size": int(args.batch_size),
                "sent": sent,
                "stored": stored,
                "delivery_ratio": round(stored / sent, 4) if sent else 0.0,
                "load_duration_sec": round(load_duration, 3),
                "actual_duration_sec": round(time.time() - stage_started, 3),
                "achieved_eps": round(sent / max(0.001, load_duration), 2),
                "latency": latency,
                "before_kafka_lag": before_lag,
                "after_kafka_lag": after_lag,
                "clickhouse_stage": stage_eps,
                "workers": sorted(worker_results, key=lambda item: str(item.get("injector") or "")),
                "status": "success" if not errors else "failed",
                "errors": errors,
            }
            report["stages"].append(stage_result)
            print(json.dumps(stage_result, ensure_ascii=True, sort_keys=True), flush=True)
        report["postflight"] = {
            "services": _service_snapshot(key_path=key_path, hosts=all_hosts),
            "kafka_lag": _kafka_lag(kafka=kafka, key_path=key_path),
        }
    finally:
        for host in injectors:
            paths = prepared.get(host.name)
            if paths:
                try:
                    _cleanup_host(host, key_path=key_path, paths=paths)
                except Exception:
                    pass
    report["finished_at_utc"] = datetime.now(timezone.utc).isoformat()
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run live EPS ladder through production HTTP ingest and Kafka transport")
    parser.add_argument("--stages", default="500,750,1000,1250,1500")
    parser.add_argument("--duration-sec", type=int, default=20)
    parser.add_argument("--batch-size", type=int, default=200)
    parser.add_argument("--workers-per-host", type=int, default=1)
    parser.add_argument("--request-timeout-sec", type=float, default=60.0)
    parser.add_argument("--observe-timeout-sec", type=float, default=90.0)
    parser.add_argument("--ingest-url", default="https://192.168.1.35/ingest/json")
    parser.add_argument("--ssh-key", default=str(ROOT.parent / ".codex_tmp" / "vpnadmin_ed25519"))
    parser.add_argument("--user", default="rdegon")
    parser.add_argument("--vm3-host", default=DEFAULT_VM3)
    parser.add_argument("--kafka-host", default=DEFAULT_KAFKA)
    parser.add_argument("--run-id", default="")
    parser.add_argument("--output", default="")
    args = parser.parse_args(argv)
    report = run_ladder(args)
    output = Path(args.output) if str(args.output or "").strip() else ROOT / "runtime-control-plane" / f"{report['run_id']}.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"output": str(output), "run_id": report["run_id"]}, ensure_ascii=True, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
