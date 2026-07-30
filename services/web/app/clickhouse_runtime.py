from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime
from threading import RLock, get_ident
from time import monotonic, time
from typing import Any

try:
    import clickhouse_connect
except Exception:  # noqa: BLE001
    clickhouse_connect = None  # type: ignore[assignment]

try:
    from .config import CONFIG as _CONFIG
except Exception:  # noqa: BLE001
    try:
        from config import CONFIG as _CONFIG  # type: ignore[no-redef]
    except Exception:  # noqa: BLE001
        _CONFIG = None  # type: ignore[assignment]

try:
    from .secret_runtime import resolve_secret_value
except Exception:  # noqa: BLE001
    try:
        from secret_runtime import resolve_secret_value  # type: ignore[no-redef]
    except Exception:  # noqa: BLE001
        resolve_secret_value = None  # type: ignore[assignment]


@dataclass(frozen=True)
class ClickHouseEndpoint:
    host: str
    port: int


_CLIENT_CACHE: dict[tuple[str, int, str, str, str, int], Any] = {}
_CLIENT_HEALTHCHECK_AT: dict[tuple[str, int, str, str, str, int], float] = {}
_CACHE_LOCK = RLock()
_PREFERRED_INDEX = 0
_ROUTING_CHECK_AT = 0.0


class _FallbackClickHouseConfig:
    def __init__(self) -> None:
        self.host = str(os.environ.get("SIEM_CH_HOST") or "127.0.0.1")
        self.port = int(str(os.environ.get("SIEM_CH_PORT") or "8123"))
        self.user = str(os.environ.get("SIEM_CH_USER") or "default")
        explicit_password = str(os.environ.get("SIEM_CH_PASSWORD") or "")
        resolved_password = explicit_password
        if resolve_secret_value is not None:
            try:
                resolved_password, _, _ = resolve_secret_value("SIEM_CH_PASSWORD", explicit_value=explicit_password)
            except Exception:  # noqa: BLE001
                resolved_password = explicit_password
        self.password = str(resolved_password or explicit_password or "")
        self.db = str(os.environ.get("SIEM_CH_DB") or "default")


def _ch_config():
    configured = getattr(_CONFIG, "ch", None)
    if configured is not None:
        return configured
    return _FallbackClickHouseConfig()


def _host_list_text(env: dict[str, str] | None = None) -> str:
    env_map = env or os.environ
    return str(env_map.get("SIEM_CH_HOSTS", "") or "").strip()


def _parse_endpoint(text: str, default_port: int) -> ClickHouseEndpoint:
    raw = str(text or "").strip()
    if not raw:
        raise ValueError("Empty ClickHouse endpoint")
    if ":" in raw:
        host, port_text = raw.rsplit(":", 1)
        host = host.strip()
        port_text = port_text.strip()
        if not host:
            raise ValueError(f"Invalid ClickHouse endpoint: {text!r}")
        try:
            port = int(port_text)
        except ValueError as exc:
            raise ValueError(f"Invalid ClickHouse port in endpoint: {text!r}") from exc
        return ClickHouseEndpoint(host=host, port=port)
    return ClickHouseEndpoint(host=raw, port=int(default_port))


def configured_clickhouse_endpoints(env: dict[str, str] | None = None) -> tuple[ClickHouseEndpoint, ...]:
    configured = _host_list_text(env)
    cfg = _ch_config()
    default_endpoint = ClickHouseEndpoint(host=str(cfg.host), port=int(cfg.port))
    if not configured:
        return (default_endpoint,)
    endpoints: list[ClickHouseEndpoint] = []
    seen: set[tuple[str, int]] = set()
    for item in configured.split(","):
        endpoint = _parse_endpoint(item, default_endpoint.port)
        key = (endpoint.host, endpoint.port)
        if key in seen:
            continue
        seen.add(key)
        endpoints.append(endpoint)
    if not endpoints:
        return (default_endpoint,)
    if (default_endpoint.host, default_endpoint.port) not in seen:
        endpoints.insert(0, default_endpoint)
    return tuple(endpoints)


def _cache_key(endpoint: ClickHouseEndpoint) -> tuple[str, int, str, str, str]:
    cfg = _ch_config()
    return (endpoint.host, int(endpoint.port), str(cfg.user), str(cfg.password), str(cfg.db))


def _timeout_seconds(name: str, default: str) -> int:
    try:
        return max(1, int(str(os.environ.get(name, default) or default)))
    except ValueError:
        return max(1, int(default))


def _healthcheck_ttl_seconds() -> float:
    try:
        return max(0.0, min(30.0, float(str(os.environ.get("SIEM_CH_HEALTHCHECK_TTL_SECONDS", "2") or "2"))))
    except ValueError:
        return 2.0


def _routing_ttl_seconds() -> float:
    try:
        return max(1.0, min(30.0, float(str(os.environ.get("SIEM_CH_ROUTING_TTL_SECONDS", "5") or "5"))))
    except ValueError:
        return 5.0


def _max_replica_lag_seconds() -> int:
    try:
        return max(0, int(str(os.environ.get("SIEM_CH_MAX_READ_REPLICA_LAG_SECONDS", "30") or "30")))
    except ValueError:
        return 30


def _build_client(endpoint: ClickHouseEndpoint) -> Any:
    if clickhouse_connect is None:
        raise RuntimeError("clickhouse_connect_unavailable")
    cfg = _ch_config()
    return clickhouse_connect.get_client(
        host=endpoint.host,
        port=int(endpoint.port),
        username=cfg.user,
        password=cfg.password,
        database=cfg.db,
        connect_timeout=_timeout_seconds("SIEM_CH_CONNECT_TIMEOUT_SECONDS", "3"),
        send_receive_timeout=_timeout_seconds("SIEM_CH_SEND_RECEIVE_TIMEOUT_SECONDS", "20"),
    )


def clear_clickhouse_runtime_cache() -> None:
    global _PREFERRED_INDEX, _ROUTING_CHECK_AT
    with _CACHE_LOCK:
        _CLIENT_CACHE.clear()
        _CLIENT_HEALTHCHECK_AT.clear()
        _PREFERRED_INDEX = 0
        _ROUTING_CHECK_AT = 0.0


def _thread_cache_key(endpoint: ClickHouseEndpoint) -> tuple[str, int, str, str, str, int]:
    return (*_cache_key(endpoint), get_ident())


def _client_for_endpoint(endpoint: ClickHouseEndpoint) -> tuple[Any, tuple[str, int, str, str, str, int]]:
    key = _thread_cache_key(endpoint)
    with _CACHE_LOCK:
        client = _CLIENT_CACHE.get(key)
    if client is None:
        client = _build_client(endpoint)
        with _CACHE_LOCK:
            _CLIENT_CACHE[key] = client
    return client, key


def _drop_cached_client(key: tuple[str, int, str, str, str, int]) -> None:
    with _CACHE_LOCK:
        _CLIENT_CACHE.pop(key, None)
        _CLIENT_HEALTHCHECK_AT.pop(key, None)


def _refresh_preferred_route(
    endpoints: tuple[ClickHouseEndpoint, ...],
) -> tuple[int | None, list[dict[str, Any]], list[dict[str, Any]]]:
    global _PREFERRED_INDEX, _ROUTING_CHECK_AT
    reachable: list[dict[str, Any]] = []
    failed: list[dict[str, Any]] = []
    for index, endpoint in enumerate(endpoints):
        key: tuple[str, int, str, str, str, int] | None = None
        try:
            client, key = _client_for_endpoint(endpoint)
            latest_event_epoch = _coerce_epoch(
                client.command("SELECT toUnixTimestamp(max(ts)) FROM siem.events")
            )
            reachable.append(
                {
                    "index": index,
                    "endpoint": endpoint,
                    "client": client,
                    "latest_event_epoch": latest_event_epoch,
                }
            )
            with _CACHE_LOCK:
                _CLIENT_HEALTHCHECK_AT[key] = monotonic()
        except Exception as exc:  # noqa: BLE001
            if key is not None:
                _drop_cached_client(key)
            failed.append(
                {
                    "index": index,
                    "endpoint": endpoint,
                    "error": f"{type(exc).__name__}:{exc}",
                }
            )

    selected_index: int | None = None
    epochs = [
        int(item["latest_event_epoch"])
        for item in reachable
        if item.get("latest_event_epoch") is not None
    ]
    newest_epoch = max(epochs) if epochs else None
    allowed_lag = _max_replica_lag_seconds()
    for item in reachable:
        epoch = item.get("latest_event_epoch")
        item["replication_lag_seconds"] = (
            max(0, int(newest_epoch - int(epoch)))
            if newest_epoch is not None and epoch is not None
            else None
        )
        item["data_fresh"] = (
            newest_epoch is None
            or (
                item["replication_lag_seconds"] is not None
                and int(item["replication_lag_seconds"]) <= allowed_lag
            )
        )
        if selected_index is None and item["data_fresh"]:
            selected_index = int(item["index"])
    if selected_index is None and reachable:
        selected_index = int(reachable[0]["index"])

    with _CACHE_LOCK:
        if selected_index is not None:
            _PREFERRED_INDEX = selected_index
        _ROUTING_CHECK_AT = monotonic()
    return selected_index, reachable, failed


def get_clickhouse_client() -> Any:
    global _PREFERRED_INDEX
    endpoints = configured_clickhouse_endpoints()
    last_error: Exception | None = None
    with _CACHE_LOCK:
        start_index = _PREFERRED_INDEX % max(1, len(endpoints))
        routing_check_at = _ROUTING_CHECK_AT
    if len(endpoints) > 1 and monotonic() - routing_check_at >= _routing_ttl_seconds():
        selected_index, reachable, failed = _refresh_preferred_route(endpoints)
        if selected_index is not None:
            selected = next(
                (item for item in reachable if int(item["index"]) == selected_index),
                None,
            )
            if selected is not None:
                return selected["client"]
        if failed:
            last_error = RuntimeError(str(failed[-1]["error"]))
        with _CACHE_LOCK:
            start_index = _PREFERRED_INDEX % max(1, len(endpoints))
    for offset in range(len(endpoints)):
        index = (start_index + offset) % len(endpoints)
        endpoint = endpoints[index]
        key = _thread_cache_key(endpoint)
        now = monotonic()
        with _CACHE_LOCK:
            client = _CLIENT_CACHE.get(key)
            last_healthcheck = _CLIENT_HEALTHCHECK_AT.get(key, 0.0)
        if client is not None and now - last_healthcheck < _healthcheck_ttl_seconds():
            with _CACHE_LOCK:
                _PREFERRED_INDEX = index
            return client
        try:
            if client is None:
                client, key = _client_for_endpoint(endpoint)
            client.command("SELECT 1")
            with _CACHE_LOCK:
                _CLIENT_HEALTHCHECK_AT[key] = monotonic()
                _PREFERRED_INDEX = index
            return client
        except Exception as exc:  # noqa: BLE001
            last_error = exc
            _drop_cached_client(key)
    raise RuntimeError(f"All ClickHouse endpoints failed: {last_error}") from last_error


def clickhouse_failover_status() -> dict[str, Any]:
    endpoints = configured_clickhouse_endpoints()
    selected_index, reachable, failed = _refresh_preferred_route(endpoints)
    healthy_endpoints: list[dict[str, Any]] = []
    failed_endpoints: list[dict[str, Any]] = []
    now_epoch = int(time())
    for item in reachable:
        endpoint = item["endpoint"]
        latest_event_epoch = item.get("latest_event_epoch")
        healthy_endpoints.append(
            {
                "host": endpoint.host,
                "port": int(endpoint.port),
                "preferred": int(item["index"]) == selected_index,
                "data_fresh": bool(item.get("data_fresh")),
                "latest_event_epoch": latest_event_epoch,
                "latest_event_age_seconds": (
                    max(0, now_epoch - int(latest_event_epoch))
                    if latest_event_epoch is not None
                    else None
                ),
                "replication_lag_seconds": item.get("replication_lag_seconds"),
            }
        )
    for item in failed:
        endpoint = item["endpoint"]
        failed_endpoints.append(
            {
                "host": endpoint.host,
                "port": int(endpoint.port),
                "error": item["error"],
                "preferred": int(item["index"]) == selected_index,
            }
        )
    active_endpoint = next(
        (item for item in healthy_endpoints if item["preferred"]),
        healthy_endpoints[0] if healthy_endpoints else None,
    )
    return {
        "configured_hosts": [{"host": item.host, "port": int(item.port)} for item in endpoints],
        "active_endpoint": active_endpoint,
        "healthy": bool(active_endpoint and active_endpoint.get("data_fresh")),
        "healthy_endpoints": healthy_endpoints,
        "failed_endpoints": failed_endpoints,
        "replica_hosts_total": max(0, len(endpoints) - 1),
    }


def _coerce_epoch(value: Any) -> int | None:
    if value in (None, "", "None"):
        return None
    if isinstance(value, datetime):
        return int(value.timestamp())
    try:
        return int(value)
    except Exception:  # noqa: BLE001
        return None


def _probe_clickhouse_endpoint(endpoint: ClickHouseEndpoint) -> dict[str, Any]:
    client = _build_client(endpoint)
    client.command("SELECT 1")
    latest_event_epoch = _coerce_epoch(client.command("SELECT toUnixTimestamp(max(ts)) FROM siem.events"))
    events_5m = int(client.command("SELECT count() FROM siem.events WHERE ts >= now() - INTERVAL 5 MINUTE") or 0)
    events_15m = int(client.command("SELECT count() FROM siem.events WHERE ts >= now() - INTERVAL 15 MINUTE") or 0)
    alerts_5m = int(client.command("SELECT count() FROM siem.alerts_raw WHERE ts >= now() - INTERVAL 5 MINUTE") or 0)
    payload = {
        "host": endpoint.host,
        "port": int(endpoint.port),
        "healthy": True,
        "latest_event_epoch": latest_event_epoch,
        "events_5m": events_5m,
        "events_15m": events_15m,
        "alerts_5m": alerts_5m,
    }
    try:
        shadow_table_exists = int(client.command("EXISTS TABLE siem.events_shadow") or 0) == 1
    except Exception as exc:  # noqa: BLE001
        payload["shadow_table_exists"] = False
        payload["shadow_events_5m"] = 0
        payload["shadow_events_15m"] = 0
        payload["shadow_latest_event_epoch"] = None
        payload["shadow_query_error"] = f"{type(exc).__name__}:{exc}"
        return payload
    payload["shadow_table_exists"] = shadow_table_exists
    if not shadow_table_exists:
        payload["shadow_events_5m"] = 0
        payload["shadow_events_15m"] = 0
        payload["shadow_latest_event_epoch"] = None
        return payload
    try:
        payload["shadow_events_5m"] = int(client.command("SELECT count() FROM siem.events_shadow WHERE ts >= now() - INTERVAL 5 MINUTE") or 0)
        payload["shadow_events_15m"] = int(client.command("SELECT count() FROM siem.events_shadow WHERE ts >= now() - INTERVAL 15 MINUTE") or 0)
        payload["shadow_latest_event_epoch"] = _coerce_epoch(client.command("SELECT toUnixTimestamp(max(ts)) FROM siem.events_shadow"))
    except Exception as exc:  # noqa: BLE001
        payload["shadow_events_5m"] = 0
        payload["shadow_events_15m"] = 0
        payload["shadow_latest_event_epoch"] = None
        payload["shadow_query_error"] = f"{type(exc).__name__}:{exc}"
    return payload


def clickhouse_replication_snapshot() -> dict[str, Any]:
    endpoints = configured_clickhouse_endpoints()
    nodes: list[dict[str, Any]] = []
    failed_nodes: list[dict[str, Any]] = []
    for endpoint in endpoints:
        try:
            nodes.append(_probe_clickhouse_endpoint(endpoint))
        except Exception as exc:  # noqa: BLE001
            failed_nodes.append({"host": endpoint.host, "port": int(endpoint.port), "healthy": False, "error": f"{type(exc).__name__}:{exc}"})
    if not nodes:
        return {"healthy": False, "nodes": [], "failed_nodes": failed_nodes, "replication_lag_seconds_max": None}
    primary_epoch = max((item.get("latest_event_epoch") or 0) for item in nodes)
    for item in nodes:
        epoch = item.get("latest_event_epoch")
        item["replication_lag_seconds"] = max(0, int(primary_epoch - epoch)) if epoch is not None else None
    lag_values = [int(item["replication_lag_seconds"]) for item in nodes if item.get("replication_lag_seconds") is not None]
    return {
        "healthy": bool(nodes),
        "nodes": nodes,
        "failed_nodes": failed_nodes,
        "replication_lag_seconds_max": max(lag_values) if lag_values else 0,
    }
