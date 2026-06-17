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
    raise SystemExit("paramiko is required for live collector EPS tests") from exc

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from deploy.eps_ladder_live import (  # noqa: E402
    DEFAULT_INJECTORS,
    DEFAULT_VM3,
    DEFAULT_WEB_SMOKE_PATHS,
    DEFAULT_WEB_URL,
    HostSpec,
    _connect,
    _kafka_lag,
    _run,
    _service_snapshot,
    _split_stage_target,
    _upload,
    _web_smoke,
    _write_secret_file,
)


ROOT = Path(__file__).resolve().parents[1]
WORKER_PATH = ROOT / "deploy" / "collector_eps_worker.py"
DEFAULT_KAFKA = "192.168.1.35"
DEFAULT_COLLECTOR_TARGETS: tuple[dict[str, str], ...] = (
    {"name": "generic-http", "kind": "http", "endpoint": "https://192.168.1.35/ingest/json"},
    {"name": "windows-base-http", "kind": "http", "endpoint": "https://192.168.1.35:9440/"},
    {"name": "windows-security-http", "kind": "http", "endpoint": "https://192.168.1.35:9441/"},
    {"name": "windows-sysmon-http", "kind": "http", "endpoint": "https://192.168.1.35:9442/"},
    {"name": "windows-powershell-http", "kind": "http", "endpoint": "https://192.168.1.35:9443/"},
    {"name": "app-json-http", "kind": "http", "endpoint": "https://192.168.1.35:9444/"},
    {"name": "vulnscanner-http", "kind": "http", "endpoint": "https://192.168.1.35:9445/"},
    {"name": "vpn-http", "kind": "http", "endpoint": "https://192.168.1.35:9446/"},
    {"name": "syslog-linux-auth", "kind": "syslog", "endpoint": "tcp://192.168.1.35:1514"},
    {"name": "syslog-linux-audit", "kind": "syslog", "endpoint": "tcp://192.168.1.35:1515"},
    {"name": "syslog-network", "kind": "syslog", "endpoint": "tcp://192.168.1.35:1516"},
    {"name": "syslog-vpn", "kind": "syslog", "endpoint": "tcp://192.168.1.35:1517"},
    {"name": "syslog-app", "kind": "syslog", "endpoint": "tcp://192.168.1.35:1518"},
)


@dataclass(frozen=True)
class WorkerSlot:
    host: HostSpec
    target: dict[str, str]
    slot_index: int


def _ssh_control_retry(
    label: str,
    callback,
    *,
    attempts: int = 4,
    delay_sec: float = 2.0,
) -> Any:
    last_error: Exception | None = None
    for attempt in range(1, max(1, int(attempts)) + 1):
        try:
            return callback()
        except Exception as exc:  # noqa: BLE001
            last_error = exc
            if attempt >= max(1, int(attempts)):
                break
            time.sleep(max(0.0, float(delay_sec)))
    raise RuntimeError(f"{label} failed after {attempts} attempts: {last_error}") from last_error


def _select_targets(names: str) -> list[dict[str, str]]:
    requested = {item.strip() for item in str(names or "").split(",") if item.strip()}
    targets = [dict(item) for item in DEFAULT_COLLECTOR_TARGETS if not requested or item["name"] in requested]
    if not targets:
        raise SystemExit(f"No collector targets matched: {names}")
    return targets


def _clickhouse_scalar(*, vm3: HostSpec, key_path: str, query: str, timeout_sec: float = 30.0) -> str:
    command = f"clickhouse-client --query {shlex.quote(query)}"

    def query_once() -> str:
        client = _connect(vm3.host, vm3.user, key_path)
        try:
            code, out, err = _run(client, command, timeout_sec=timeout_sec)
        finally:
            client.close()
        if code != 0:
            raise RuntimeError(err.strip() or out.strip())
        return str(out or "").strip()

    return str(_ssh_control_retry("ClickHouse collector query", query_once))


def _clickhouse_count(*, vm3: HostSpec, key_path: str, run_id: str, stage: int) -> int:
    marker = f"{run_id}:{int(stage)}".replace("'", "''")
    query = (
        "SELECT count() FROM siem.events "
        f"WHERE ts >= now() - INTERVAL 2 HOUR AND position(message, '{marker}') > 0 FORMAT TabSeparated"
    )
    out = _clickhouse_scalar(vm3=vm3, key_path=key_path, query=query)
    return int((out.splitlines()[-1:] or ["0"])[0] or 0)


def _clickhouse_stage_eps(*, vm3: HostSpec, key_path: str, run_id: str, stage: int) -> dict[str, Any]:
    marker = f"{run_id}:{int(stage)}".replace("'", "''")
    query = (
        "SELECT count() AS events, min(ts) AS first_ts, max(ts) AS last_ts, "
        "round(count() / greatest(1, dateDiff('second', min(ts), max(ts))), 2) AS stored_eps "
        "FROM siem.events "
        f"WHERE ts >= now() - INTERVAL 2 HOUR AND position(message, '{marker}') > 0 FORMAT JSONEachRow"
    )
    try:
        out = _clickhouse_scalar(vm3=vm3, key_path=key_path, query=query)
        line = out.splitlines()[-1:] or []
        return json.loads(line[0]) if line else {}
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc)}


def _clickhouse_collector_coverage(*, vm3: HostSpec, key_path: str, run_id: str, stage: int) -> list[dict[str, Any]]:
    marker = f"{run_id}:{int(stage)}".replace("'", "''")
    query = (
        "SELECT extract(message, '"
        f"{marker}:"
        "([^:]+):') AS target_name, count() AS events "
        "FROM siem.events "
        f"WHERE ts >= now() - INTERVAL 2 HOUR AND position(message, '{marker}') > 0 "
        "GROUP BY target_name ORDER BY target_name FORMAT JSONEachRow"
    )
    try:
        out = _clickhouse_scalar(vm3=vm3, key_path=key_path, query=query)
        return [json.loads(line) for line in out.splitlines() if line.strip()]
    except Exception as exc:  # noqa: BLE001
        return [{"error": str(exc)}]


def _prepare_host(host: HostSpec, *, key_path: str, run_id: str, secret: str) -> tuple[str, str]:
    remote_worker = f"/tmp/collector_eps_worker_{run_id}.py"
    remote_secret = f"/tmp/collector_eps_secret_{run_id}"
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


def _run_worker(
    *,
    host: HostSpec,
    key_path: str,
    remote_worker: str,
    remote_secret: str,
    target: dict[str, str],
    run_id: str,
    stage: int,
    worker_id: str,
    eps_target: int,
    duration_sec: int,
    batch_size: int,
    request_timeout_sec: float,
    start_at_epoch: float,
) -> dict[str, Any]:
    client = _ssh_control_retry(
        f"{host.name} {target['name']} worker SSH connect",
        lambda: _connect(host.host, host.user, key_path),
        attempts=6,
        delay_sec=1.5,
    )
    try:
        command = (
            f"python3 {shlex.quote(remote_worker)} "
            f"--target-kind {shlex.quote(target['kind'])} "
            f"--target-name {shlex.quote(target['name'])} "
            f"--endpoint {shlex.quote(target['endpoint'])} "
            f"--ingest-secret-file {shlex.quote(remote_secret)} "
            f"--run-id {shlex.quote(run_id)} "
            f"--stage-id {int(stage)} "
            f"--worker-id {shlex.quote(worker_id)} "
            f"--eps-target {int(eps_target)} "
            f"--duration-sec {int(duration_sec)} "
            f"--batch-size {int(batch_size)} "
            f"--request-timeout-sec {float(request_timeout_sec)} "
            f"--start-at-epoch {float(start_at_epoch)}"
        )
        code, out, err = _run(client, command, timeout_sec=max(120, duration_sec + int(request_timeout_sec) * 20))
        if code != 0:
            return {
                "injector": host.name,
                "target_name": target["name"],
                "target_kind": target["kind"],
                "status": "error",
                "sent": 0,
                "achieved_eps": 0.0,
                "error": err.strip() or out.strip(),
            }
        payload = json.loads(str(out or "").strip().splitlines()[-1])
        payload["injector"] = host.name
        payload["status"] = str(payload.get("status") or "success")
        return payload
    except Exception as exc:  # noqa: BLE001
        return {
            "injector": host.name,
            "target_name": target["name"],
            "target_kind": target["kind"],
            "status": "error",
            "sent": 0,
            "achieved_eps": 0.0,
            "error": str(exc),
        }
    finally:
        client.close()


def run_ladder(args: argparse.Namespace) -> dict[str, Any]:
    secret = str(os.getenv("SIEM_INGEST_API_SHARED_SECRET") or "").strip()
    if not secret:
        raise SystemExit("SIEM_INGEST_API_SHARED_SECRET must be set")
    stages = [int(item.strip()) for item in str(args.stages).split(",") if item.strip()]
    if not stages:
        raise SystemExit("No stages requested")
    run_id = args.run_id or f"collector-eps-{int(time.time())}"
    key_path = str(Path(args.ssh_key).expanduser())
    targets = _select_targets(str(args.targets or ""))
    injectors = [HostSpec(name, host, args.user) for name, host in DEFAULT_INJECTORS]
    vm3 = HostSpec("SIEM_VM3", args.vm3_host, args.user)
    kafka = HostSpec("SIEM_VM1", args.kafka_host, args.user)
    all_hosts = [*injectors, vm3]
    web_paths = [item.strip() for item in str(args.web_smoke_paths or "").split(",") if item.strip()]

    prepared: dict[str, tuple[str, str]] = {}
    report: dict[str, Any] = {
        "run_id": run_id,
        "started_at_utc": datetime.now(timezone.utc).isoformat(),
        "profile": {
            "stages": stages,
            "duration_sec": int(args.duration_sec),
            "batch_size": int(args.batch_size),
            "request_timeout_sec": float(args.request_timeout_sec),
            "injectors": [host.name for host in injectors],
            "workers_per_target_per_host": int(args.workers_per_target_per_host),
            "targets": targets,
            "web_url": "" if args.skip_web_smoke else args.web_url,
            "web_smoke_paths": [] if args.skip_web_smoke else web_paths,
        },
        "preflight": {
            "services": _service_snapshot(key_path=key_path, hosts=all_hosts),
            "kafka_lag": _kafka_lag(kafka=kafka, key_path=key_path),
            "web_smoke": {}
            if args.skip_web_smoke
            else _web_smoke(base_url=args.web_url, paths=web_paths, timeout_sec=float(args.web_timeout_sec)),
        },
        "stages": [],
    }
    try:
        for host in injectors:
            prepared[host.name] = _prepare_host(host, key_path=key_path, run_id=run_id, secret=secret)
        for stage in stages:
            stage_started = time.time()
            start_at_epoch = time.time() + max(0.0, float(args.start_delay_sec))
            worker_slots = [
                WorkerSlot(host=host, target=target, slot_index=slot_index)
                for target in targets
                for host in injectors
                for slot_index in range(max(1, int(args.workers_per_target_per_host)))
            ]
            per_worker = _split_stage_target(stage, len(worker_slots))
            before_lag = _kafka_lag(kafka=kafka, key_path=key_path)
            worker_results: list[dict[str, Any]] = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=len(worker_slots)) as pool:
                futures = [
                    pool.submit(
                        _run_worker,
                        host=slot.host,
                        key_path=key_path,
                        remote_worker=prepared[slot.host.name][0],
                        remote_secret=prepared[slot.host.name][1],
                        target=slot.target,
                        run_id=run_id,
                        stage=stage,
                        worker_id=f"{slot.host.name.lower()}_{slot.target['name']}_w{slot.slot_index + 1}".replace("-", "_"),
                        eps_target=per_worker[index],
                        duration_sec=int(args.duration_sec),
                        batch_size=int(args.batch_size),
                        request_timeout_sec=float(args.request_timeout_sec),
                        start_at_epoch=start_at_epoch,
                    )
                    for index, slot in enumerate(worker_slots)
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
            coverage = _clickhouse_collector_coverage(vm3=vm3, key_path=key_path, run_id=run_id, stage=stage)
            web_smoke = (
                {}
                if args.skip_web_smoke
                else _web_smoke(base_url=args.web_url, paths=web_paths, timeout_sec=float(args.web_timeout_sec))
            )
            errors = [str(item.get("error") or "") for item in worker_results if str(item.get("status") or "") == "error"]
            latency = {
                "p50_ms": max((float(dict(item.get("latency") or {}).get("p50_ms") or 0.0) for item in worker_results), default=0.0),
                "p95_ms": max((float(dict(item.get("latency") or {}).get("p95_ms") or 0.0) for item in worker_results), default=0.0),
                "max_ms": max((float(dict(item.get("latency") or {}).get("max_ms") or 0.0) for item in worker_results), default=0.0),
            }
            target_summary: dict[str, dict[str, Any]] = {}
            for item in worker_results:
                name = str(item.get("target_name") or "")
                target_summary.setdefault(name, {"sent": 0, "workers": 0, "errors": 0, "kind": item.get("target_kind")})
                target_summary[name]["sent"] += int(item.get("sent") or 0)
                target_summary[name]["workers"] += 1
                if str(item.get("status") or "") == "error":
                    target_summary[name]["errors"] += 1
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
                "collector_coverage": coverage,
                "target_summary": target_summary,
                "web_smoke": web_smoke,
                "workers": sorted(worker_results, key=lambda item: (str(item.get("target_name") or ""), str(item.get("injector") or ""))),
                "status": "success" if not errors else "failed",
                "errors": errors,
            }
            report["stages"].append(stage_result)
            print(json.dumps(stage_result, ensure_ascii=True, sort_keys=True), flush=True)
        report["postflight"] = {
            "services": _service_snapshot(key_path=key_path, hosts=all_hosts),
            "kafka_lag": _kafka_lag(kafka=kafka, key_path=key_path),
            "web_smoke": {}
            if args.skip_web_smoke
            else _web_smoke(base_url=args.web_url, paths=web_paths, timeout_sec=float(args.web_timeout_sec)),
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
    parser = argparse.ArgumentParser(description="Run live mixed collector EPS ladder through production collectors")
    parser.add_argument("--stages", default="4500")
    parser.add_argument("--duration-sec", type=int, default=60)
    parser.add_argument("--batch-size", type=int, default=100)
    parser.add_argument("--workers-per-target-per-host", type=int, default=1)
    parser.add_argument("--request-timeout-sec", type=float, default=60.0)
    parser.add_argument("--observe-timeout-sec", type=float, default=120.0)
    parser.add_argument("--start-delay-sec", type=float, default=12.0)
    parser.add_argument("--targets", default="")
    parser.add_argument("--ssh-key", default=str(ROOT.parent / ".codex_tmp" / "vpnadmin_ed25519"))
    parser.add_argument("--user", default="rdegon")
    parser.add_argument("--vm3-host", default=DEFAULT_VM3)
    parser.add_argument("--kafka-host", default=DEFAULT_KAFKA)
    parser.add_argument("--web-url", default=DEFAULT_WEB_URL)
    parser.add_argument("--web-smoke-paths", default=DEFAULT_WEB_SMOKE_PATHS)
    parser.add_argument("--web-timeout-sec", type=float, default=10.0)
    parser.add_argument("--skip-web-smoke", action="store_true")
    parser.add_argument("--run-id", default="")
    parser.add_argument("--output", default="")
    args = parser.parse_args(argv)
    report = run_ladder(args)
    output = (
        Path(args.output)
        if str(args.output or "").strip()
        else ROOT / "runtime-control-plane" / "collector-eps-live" / f"{report['run_id']}.json"
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"output": str(output), "run_id": report["run_id"]}, ensure_ascii=True, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
