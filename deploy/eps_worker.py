from __future__ import annotations

import argparse
import http.client
import json
import os
import ssl
import sys
import time
import urllib.parse
from typing import Any


class IngestPoster:
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

    def _request_once(self, *, secret: str, batch: list[dict[str, Any]]) -> None:
        connection = self._connection or self._connect()
        payload = json.dumps(batch).encode("utf-8")
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
            raise RuntimeError(f"ingest returned {response.status}: {body.decode('utf-8', errors='replace')[:200]}")

    def post(self, *, secret: str, batch: list[dict[str, Any]]) -> None:
        try:
            self._request_once(secret=secret, batch=batch)
        except Exception:
            self.close()
            self._request_once(secret=secret, batch=batch)

    def close(self) -> None:
        if self._connection is not None:
            try:
                self._connection.close()
            finally:
                self._connection = None


def _percentile_ms(values: list[float], percentile: float) -> float:
    if not values:
        return 0.0
    if len(values) == 1:
        return float(values[0])
    ordered = sorted(float(item) for item in values)
    rank = max(0, min(len(ordered) - 1, int(round((percentile / 100.0) * (len(ordered) - 1)))))
    return float(ordered[rank])


def run_worker(
    *,
    ingest_url: str,
    ingest_secret: str,
    run_id: str,
    stage_id: int,
    worker_id: str,
    eps_target: int,
    duration_sec: int,
    batch_size: int,
    request_timeout_sec: float,
) -> dict[str, Any]:
    total_events = max(1, int(eps_target)) * max(1, int(duration_sec))
    sent = 0
    started = time.perf_counter()
    latencies_ms: list[float] = []
    poster = IngestPoster(ingest_url, timeout_sec=request_timeout_sec)
    try:
        while sent < total_events:
            chunk = min(max(1, int(batch_size)), total_events - sent)
            batch = [
                {
                    "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "message": f"{run_id}:{stage_id}:{worker_id}:{sent + idx}",
                    "event.original": f"{run_id}:{stage_id}:{worker_id}:{sent + idx}",
                    "host.name": f"eps-bench-{worker_id}",
                    "event.category": "benchmark",
                    "event.type": "synthetic",
                    "event.dataset": "benchmark",
                    "severity": "low",
                    "tags": ["benchmark", "distributed", "allowlist:benchmark"],
                }
                for idx in range(chunk)
            ]
            request_started = time.perf_counter()
            poster.post(secret=ingest_secret, batch=batch)
            latencies_ms.append((time.perf_counter() - request_started) * 1000.0)
            sent += chunk
            expected_elapsed = sent / max(1, int(eps_target))
            elapsed = max(0.001, time.perf_counter() - started)
            if expected_elapsed > elapsed:
                time.sleep(expected_elapsed - elapsed)
    finally:
        poster.close()
    duration = max(0.001, time.perf_counter() - started)
    return {
        "worker_id": worker_id,
        "stage_id": int(stage_id),
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
    parser = argparse.ArgumentParser(description="Distributed EPS worker")
    parser.add_argument("--ingest-url", required=True)
    parser.add_argument("--ingest-secret", default="")
    parser.add_argument("--ingest-secret-file", default="")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--stage-id", type=int, required=True)
    parser.add_argument("--worker-id", required=True)
    parser.add_argument("--eps-target", type=int, required=True)
    parser.add_argument("--duration-sec", type=int, required=True)
    parser.add_argument("--batch-size", type=int, default=200)
    parser.add_argument("--request-timeout-sec", type=float, default=30.0)
    args = parser.parse_args(argv)
    ingest_secret = str(args.ingest_secret or "").strip()
    if not ingest_secret and str(args.ingest_secret_file or "").strip():
        with open(str(args.ingest_secret_file), "r", encoding="utf-8") as handle:
            ingest_secret = handle.read().strip()
    if not ingest_secret:
        ingest_secret = str(os.getenv("SIEM_INGEST_API_SHARED_SECRET") or "").strip()
    if not ingest_secret:
        raise SystemExit("Missing ingest secret; set --ingest-secret, --ingest-secret-file, or SIEM_INGEST_API_SHARED_SECRET")
    result = run_worker(
        ingest_url=args.ingest_url,
        ingest_secret=ingest_secret,
        run_id=args.run_id,
        stage_id=args.stage_id,
        worker_id=args.worker_id,
        eps_target=args.eps_target,
        duration_sec=args.duration_sec,
        batch_size=args.batch_size,
        request_timeout_sec=args.request_timeout_sec,
    )
    print(json.dumps(result, ensure_ascii=True, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
