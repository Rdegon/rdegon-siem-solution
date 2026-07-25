from __future__ import annotations

import json
import os
import sys
import time
from typing import Callable

import paramiko


LOCAL_INGEST_BASE_URL = "http://127.0.0.1:8443"
CRITICAL_COLLECTOR_PROFILES = ("app", "linux-auth", "linux-audit")
PVE_SOURCE_ALIASES = {"192.168.1.101", "192.168.3.101", "pve"}
EDGE_VPN_SOURCE_ALIASES = {
    "192.168.1.102",
    "192.168.3.102",
    "10.20.10.1",
    "10.20.30.1",
    "opnsense-edge-01",
    "lab-edge-01",
}


def _required_env(name: str) -> str:
    value = os.getenv(name, "").strip()
    if value:
        return value
    raise SystemExit(f"Missing required environment variable: {name}")


def _connect_client(host: str, user: str, password: str) -> paramiko.SSHClient:
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
    return client


def _run(client: paramiko.SSHClient, command: str) -> str:
    stdin, stdout, stderr = client.exec_command(command, timeout=30)
    try:
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
        code = stdout.channel.recv_exit_status()
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(f"Command timed out or failed: {command}\nerror={exc}") from exc
    if code != 0:
        raise RuntimeError(f"Command failed: {command}\nstdout={out}\nstderr={err}")
    return out


def _load_json_with_retry(
    client: paramiko.SSHClient,
    command: str,
    *,
    attempts: int = 12,
    delay_seconds: float = 2.0,
) -> dict[str, object]:
    last_error: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            return json.loads(_run(client, command))
        except Exception as exc:  # noqa: BLE001
            last_error = exc
            if attempt == attempts:
                break
            time.sleep(delay_seconds)
    raise RuntimeError(f"JSON command did not stabilize: {command}\nlast_error={last_error}")


def _curl_json(path: str, *, secret: str = "") -> str:
    header_part = f"-H 'X-Rdegon-Ingest-Secret: {secret}' " if secret else ""
    return f"curl -s --connect-timeout 5 --max-time 15 {header_part}'{LOCAL_INGEST_BASE_URL}{path}'"


def _shared_secret_header(secret: str) -> str:
    return f'-H "X-Rdegon-Ingest-Secret: {secret}" ' if secret else ""


def _smoke_suppress_limit() -> int:
    try:
        limit = int(str(os.getenv("SIEM_VM1_SMOKE_SUPPRESS_LIMIT", "250") or "250"))
    except ValueError:
        limit = 250
    return max(1, min(5000, limit))


def _item_status(item: dict[str, object]) -> str:
    return str(item.get("status") or item.get("health") or "").strip().lower()


def _best_source_item(
    items: list[dict[str, object]],
    predicate: Callable[[dict[str, object]], bool],
) -> dict[str, object] | None:
    candidates = [item for item in items if predicate(item)]
    if not candidates:
        return None
    status_rank = {"healthy": 4, "delayed": 3, "stale": 2, "missing": 1}

    def sort_key(item: dict[str, object]) -> tuple[int, float]:
        try:
            lag = float(item.get("seconds_since_last_seen") or float("inf"))
        except (TypeError, ValueError):
            lag = float("inf")
        return status_rank.get(_item_status(item), 0), -lag

    return max(candidates, key=sort_key)


def _assert_critical_collectors(collectors: dict[str, object]) -> None:
    items = [dict(item) for item in list(collectors.get("items") or [])]
    for profile in CRITICAL_COLLECTOR_PROFILES:
        match = next(
            (
                item
                for item in items
                if str(item.get("collector_profile") or item.get("ingest_profile") or "").strip().lower() == profile
            ),
            None,
        )
        if not match:
            raise RuntimeError(f"Missing critical collector profile in ingest health: {profile}")
        if _item_status(match) != "healthy":
            raise RuntimeError(f"Critical collector profile is not healthy: {profile} => {match}")


def _assert_critical_sources(sources: dict[str, object]) -> None:
    items = [dict(item) for item in list(sources.get("items") or [])]
    pve_app = _best_source_item(
        items,
        lambda item: (
            str(item.get("collector_profile") or item.get("ingest_profile") or "").strip().lower() == "app"
            and (
                "pve" in " ".join(
                    str(item.get(field) or "").strip().lower()
                    for field in ("source", "source_alias", "id")
                )
                or any(
                    str(item.get(field) or "").strip().lower() in PVE_SOURCE_ALIASES
                    for field in ("source", "source_alias", "id")
                )
            )
        ),
    )
    if not pve_app or _item_status(pve_app) != "healthy":
        raise RuntimeError(f"Critical source pve/app is not healthy: {pve_app}")

    vpn_source = _best_source_item(
        items,
        lambda item: (
                str(item.get("collector_profile") or item.get("ingest_profile") or "").strip().lower() == "vpn"
                or (
                    str(item.get("collector_profile") or item.get("ingest_profile") or "").strip().lower() == "linux-auth"
                    and str(item.get("source") or item.get("source_alias") or "").strip() == "127.0.0.1"
                )
        ),
    )
    edge_source = _best_source_item(
        items,
        lambda item: any(
                str(item.get(field) or "").strip().lower() in EDGE_VPN_SOURCE_ALIASES
                for field in ("source", "source_alias", "id")
        ),
    )
    if (not vpn_source or _item_status(vpn_source) != "healthy") and (
        not edge_source or _item_status(edge_source) != "healthy"
    ):
        raise RuntimeError(f"Critical vpn path is not healthy: vpn_source={vpn_source} edge_source={edge_source}")


def main() -> int:
    host = _required_env("SIEM_VM1_HOST")
    user = _required_env("SIEM_VM1_USER")
    password = _required_env("SIEM_VM1_PASSWORD")
    secret = os.getenv("SIEM_INGEST_API_SHARED_SECRET", "").strip()

    client = _connect_client(host, user, password)
    try:
        health = _load_json_with_retry(client, _curl_json("/health"))
        if health.get("status") != "ok":
            raise RuntimeError("/health did not return ok")
        print("/health ok")

        overview = _load_json_with_retry(client, _curl_json("/health/overview", secret=secret))
        if "metrics" not in overview or "dlq" not in overview or "streams" not in overview:
            raise RuntimeError("/health/overview missing metrics, dlq, or streams")
        print("/health/overview ok")

        transport = _load_json_with_retry(client, _curl_json("/health/transport", secret=secret))
        for field in ("backend", "cutover_stage", "raw_target", "streams"):
            if field not in transport:
                raise RuntimeError(f"/health/transport missing field: {field}")
        print("/health/transport ok")

        _run(
            client,
            f"curl -s --connect-timeout 5 --max-time 15 -X POST {LOCAL_INGEST_BASE_URL}/ingest/json "
            "-H 'Content-Type: application/json' "
            "--data '[{\"message\":\"smoke-ok\",\"source\":\"vm1-smoke\",\"source_type\":\"synthetic\",\"event.dataset\":\"smoke\",\"tags\":[\"synthetic\",\"smoke\"]}, \"broken-item\"]'",
        )
        time.sleep(1)

        sources = _load_json_with_retry(client, _curl_json("/health/sources?limit=200", secret=secret))
        collectors = _load_json_with_retry(client, _curl_json("/health/collectors?limit=200", secret=secret))
        dlq = _load_json_with_retry(client, _curl_json("/dlq/events?limit=20", secret=secret))
        if "items" not in sources or "items" not in collectors or "items" not in dlq:
            raise RuntimeError("ingest runtime endpoints missing items")
        _assert_critical_collectors(collectors)
        _assert_critical_sources(sources)
        for _ in range(12):
            if dlq.get("items"):
                break
            time.sleep(1)
            dlq = _load_json_with_retry(client, _curl_json("/dlq/events?limit=20", secret=secret))
        else:
            raise RuntimeError("Expected at least one DLQ item after smoke ingest")
        print("/health/sources ok")
        print("/health/collectors ok")
        print("/dlq/events ok")

        suppress = _load_json_with_retry(
            client,
            f"curl -s --connect-timeout 5 --max-time 30 -X POST {LOCAL_INGEST_BASE_URL}/dlq/suppress "
            f"{_shared_secret_header(secret)}"
            "-H 'Content-Type: application/json' "
            f"--data '{{\"limit\":{_smoke_suppress_limit()},\"actor\":\"vm1-smoke\"}}'",
        )
        if "suppressed" not in suppress:
            raise RuntimeError("/dlq/suppress missing suppression result")
        print("/dlq/suppress ok")

        replay = _load_json_with_retry(
            client,
            f"curl -s --connect-timeout 5 --max-time 15 -X POST {LOCAL_INGEST_BASE_URL}/dlq/replay "
            f"{_shared_secret_header(secret)}"
            "-H 'Content-Type: application/json' "
            "--data '{\"limit\":1,\"actor\":\"vm1-smoke\"}'",
        )
        if "replayed" not in replay:
            raise RuntimeError("/dlq/replay missing replay result")
        print("/dlq/replay ok")
        print("smoke=success")
        return 0
    finally:
        client.close()


if __name__ == "__main__":
    sys.exit(main())
