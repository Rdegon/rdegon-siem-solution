from __future__ import annotations

import argparse
import http.client
import json
import os
import socket
import ssl
import sys
import time
import urllib.parse
from typing import Any


class HttpCollectorSender:
    def __init__(self, url: str, *, timeout_sec: float) -> None:
        parsed = urllib.parse.urlsplit(url)
        self._scheme = parsed.scheme.lower()
        self._host = parsed.hostname or ""
        self._port = parsed.port
        self._path = parsed.path or "/"
        if parsed.query:
            self._path = f"{self._path}?{parsed.query}"
        self._timeout_sec = max(5.0, float(timeout_sec))
        self._context = ssl._create_unverified_context() if self._scheme == "https" else None  # noqa: SLF001
        self._connection: http.client.HTTPConnection | http.client.HTTPSConnection | None = None

    def _connect(self) -> http.client.HTTPConnection | http.client.HTTPSConnection:
        if self._scheme == "https":
            self._connection = http.client.HTTPSConnection(
                self._host,
                self._port or 443,
                timeout=self._timeout_sec,
                context=self._context,
            )
        else:
            self._connection = http.client.HTTPConnection(
                self._host,
                self._port or 80,
                timeout=self._timeout_sec,
            )
        return self._connection

    def send_batch(self, *, secret: str, events: list[dict[str, Any]]) -> None:
        connection = self._connection or self._connect()
        payload = json.dumps(events, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
        connection.request(
            "POST",
            self._path,
            body=payload,
            headers={
                "Content-Type": "application/json",
                "Content-Length": str(len(payload)),
                "Connection": "keep-alive",
                "X-Rdegon-Ingest-Secret": secret,
            },
        )
        response = connection.getresponse()
        body = response.read()
        if response.status >= 300:
            raise RuntimeError(f"collector returned {response.status}: {body.decode('utf-8', errors='replace')[:200]}")

    def close(self) -> None:
        if self._connection is not None:
            try:
                self._connection.close()
            finally:
                self._connection = None


class SyslogCollectorSender:
    def __init__(self, endpoint: str, *, timeout_sec: float) -> None:
        parsed = urllib.parse.urlsplit(endpoint)
        if parsed.scheme and parsed.scheme.lower() != "tcp":
            raise ValueError(f"unsupported syslog endpoint scheme: {parsed.scheme}")
        self._host = parsed.hostname or endpoint.split(":", 1)[0]
        self._port = int(parsed.port or endpoint.rsplit(":", 1)[-1])
        self._timeout_sec = max(5.0, float(timeout_sec))
        self._socket: socket.socket | None = None

    def _connect(self) -> socket.socket:
        self._socket = socket.create_connection((self._host, self._port), timeout=self._timeout_sec)
        self._socket.settimeout(self._timeout_sec)
        return self._socket

    def send_lines(self, lines: list[str]) -> None:
        sock = self._socket or self._connect()
        payload = "".join(lines).encode("utf-8", errors="replace")
        sock.sendall(payload)

    def close(self) -> None:
        if self._socket is not None:
            try:
                self._socket.close()
            finally:
                self._socket = None


def _percentile_ms(values: list[float], percentile: float) -> float:
    if not values:
        return 0.0
    if len(values) == 1:
        return float(values[0])
    ordered = sorted(float(item) for item in values)
    rank = max(0, min(len(ordered) - 1, int(round((percentile / 100.0) * (len(ordered) - 1)))))
    return float(ordered[rank])


def build_http_event(*, run_id: str, stage_id: int, target_name: str, worker_id: str, sequence: int) -> dict[str, Any]:
    marker = f"{run_id}:{int(stage_id)}:{target_name}:{worker_id}:{int(sequence)}"
    event: dict[str, Any] = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "message": marker,
        "event.original": marker,
        "host.name": f"collector-bench-{target_name}-{worker_id}",
        "event.category": "benchmark",
        "event.type": "synthetic",
        "event.dataset": target_name,
        "severity": "low",
        "tags": ["benchmark", "collector-mixed", "allowlist:benchmark"],
    }
    if target_name.startswith("windows-"):
        event.update(
            {
                "channel": "Security" if target_name == "windows-security-http" else "System",
                "provider": "Microsoft-Windows-Security-Auditing" if target_name == "windows-security-http" else "Service Control Manager",
                "event_id": "4624" if target_name == "windows-security-http" else "7036",
                "computer": f"collector-bench-{worker_id}",
            }
        )
    elif target_name == "vpn-http":
        event.update({"event.action": "vpn_keepalive", "user.name": "collector-load", "source.ip": "10.8.0.10"})
    elif target_name == "vulnscanner-http":
        event.update({"event.action": "scan_summary", "vuln.count": 0, "scanner.name": "collector-load"})
    elif target_name == "app-json-http":
        event.update({"service.name": "collector-load-app", "event.action": "health_check"})
    return event


def build_syslog_line(*, run_id: str, stage_id: int, target_name: str, worker_id: str, sequence: int) -> str:
    marker = f"{run_id}:{int(stage_id)}:{target_name}:{worker_id}:{int(sequence)}"
    timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    host = f"collector-bench-{target_name}-{worker_id}".replace("_", "-")
    return f"<14>1 {timestamp} {host} collector-load {os.getpid()} ID47 - {marker} systemd[1]: Started collector load validation slice.\n"


def _send_http_chunk(sender: HttpCollectorSender, *, secret: str, events: list[dict[str, Any]]) -> None:
    try:
        sender.send_batch(secret=secret, events=events)
    except Exception:
        sender.close()
        sender.send_batch(secret=secret, events=events)


def _send_syslog_chunk(sender: SyslogCollectorSender, *, lines: list[str]) -> None:
    try:
        sender.send_lines(lines)
    except Exception:
        sender.close()
        sender.send_lines(lines)


def run_worker(
    *,
    target_kind: str,
    target_name: str,
    endpoint: str,
    ingest_secret: str,
    run_id: str,
    stage_id: int,
    worker_id: str,
    eps_target: int,
    duration_sec: int,
    batch_size: int,
    request_timeout_sec: float,
    start_at_epoch: float = 0.0,
) -> dict[str, Any]:
    if start_at_epoch > 0:
        sleep_for = float(start_at_epoch) - time.time()
        if sleep_for > 0:
            time.sleep(sleep_for)
    total_events = max(1, int(eps_target)) * max(1, int(duration_sec))
    sent = 0
    started = time.perf_counter()
    latencies_ms: list[float] = []
    sender: HttpCollectorSender | SyslogCollectorSender
    if target_kind == "http":
        sender = HttpCollectorSender(endpoint, timeout_sec=request_timeout_sec)
    elif target_kind == "syslog":
        sender = SyslogCollectorSender(endpoint, timeout_sec=request_timeout_sec)
    else:
        raise ValueError(f"unsupported target kind: {target_kind}")

    try:
        while sent < total_events:
            chunk = min(max(1, int(batch_size)), total_events - sent)
            request_started = time.perf_counter()
            if target_kind == "http":
                events = [
                    build_http_event(
                        run_id=run_id,
                        stage_id=stage_id,
                        target_name=target_name,
                        worker_id=worker_id,
                        sequence=sent + idx,
                    )
                    for idx in range(chunk)
                ]
                _send_http_chunk(sender, secret=ingest_secret, events=events)  # type: ignore[arg-type]
            else:
                lines = [
                    build_syslog_line(
                        run_id=run_id,
                        stage_id=stage_id,
                        target_name=target_name,
                        worker_id=worker_id,
                        sequence=sent + idx,
                    )
                    for idx in range(chunk)
                ]
                _send_syslog_chunk(sender, lines=lines)  # type: ignore[arg-type]
            latencies_ms.append((time.perf_counter() - request_started) * 1000.0)
            sent += chunk
            expected_elapsed = sent / max(1, int(eps_target))
            elapsed = max(0.001, time.perf_counter() - started)
            if expected_elapsed > elapsed:
                time.sleep(expected_elapsed - elapsed)
    finally:
        sender.close()

    duration = max(0.001, time.perf_counter() - started)
    return {
        "worker_id": worker_id,
        "stage_id": int(stage_id),
        "target_kind": target_kind,
        "target_name": target_name,
        "endpoint": endpoint,
        "sent": int(sent),
        "duration_sec": round(duration, 3),
        "achieved_eps": round(sent / duration, 2),
        "latency": {
            "requests": len(latencies_ms),
            "p50_ms": round(_percentile_ms(latencies_ms, 50.0), 1),
            "p95_ms": round(_percentile_ms(latencies_ms, 95.0), 1),
            "max_ms": round(max(latencies_ms, default=0.0), 1),
        },
        "status": "success",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Distributed collector EPS worker")
    parser.add_argument("--target-kind", choices=("http", "syslog"), required=True)
    parser.add_argument("--target-name", required=True)
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--ingest-secret", default="")
    parser.add_argument("--ingest-secret-file", default="")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--stage-id", type=int, required=True)
    parser.add_argument("--worker-id", required=True)
    parser.add_argument("--eps-target", type=int, required=True)
    parser.add_argument("--duration-sec", type=int, required=True)
    parser.add_argument("--batch-size", type=int, default=100)
    parser.add_argument("--request-timeout-sec", type=float, default=30.0)
    parser.add_argument("--start-at-epoch", type=float, default=0.0)
    args = parser.parse_args(argv)
    ingest_secret = str(args.ingest_secret or "").strip()
    if not ingest_secret and str(args.ingest_secret_file or "").strip():
        with open(str(args.ingest_secret_file), "r", encoding="utf-8") as handle:
            ingest_secret = handle.read().strip()
    if not ingest_secret:
        ingest_secret = str(os.getenv("SIEM_INGEST_API_SHARED_SECRET") or "").strip()
    if args.target_kind == "http" and not ingest_secret:
        raise SystemExit("Missing ingest secret for HTTP collector target")

    result = run_worker(
        target_kind=str(args.target_kind),
        target_name=str(args.target_name),
        endpoint=str(args.endpoint),
        ingest_secret=ingest_secret,
        run_id=str(args.run_id),
        stage_id=int(args.stage_id),
        worker_id=str(args.worker_id),
        eps_target=int(args.eps_target),
        duration_sec=int(args.duration_sec),
        batch_size=int(args.batch_size),
        request_timeout_sec=float(args.request_timeout_sec),
        start_at_epoch=float(args.start_at_epoch),
    )
    print(json.dumps(result, ensure_ascii=True, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
