from __future__ import annotations

import importlib
import os
from typing import Any, Mapping
from datetime import datetime, timezone
from urllib.parse import parse_qs, parse_qsl, urlencode, urlparse

try:
    from .clickhouse_runtime import clickhouse_failover_status, clickhouse_replication_snapshot
except ImportError:  # pragma: no cover - local test/runtime fallback
    from clickhouse_runtime import clickhouse_failover_status, clickhouse_replication_snapshot  # type: ignore[no-redef]

try:
    from .config import CONFIG as _CONFIG
except Exception:  # noqa: BLE001
    try:
        from config import CONFIG as _CONFIG  # type: ignore[no-redef]
    except Exception:  # noqa: BLE001
        _CONFIG = None  # type: ignore[assignment]

try:
    from pymongo import MongoClient
except Exception:  # noqa: BLE001
    MongoClient = None


def _env_map(env: Mapping[str, str] | None = None) -> dict[str, str]:
    return dict(env or os.environ)


def _int_env(env_map: Mapping[str, str], name: str, default: int) -> int:
    try:
        return max(0, int(str(env_map.get(name) or default).strip()))
    except Exception:  # noqa: BLE001
        return default


def _mongo_default_uri() -> str:
    if _CONFIG is not None and getattr(_CONFIG, "mongo_uri", ""):
        return str(_CONFIG.mongo_uri)
    return str(os.environ.get("SIEM_MONGO_URI") or "").strip()


def _postgres_dsn(env_map: Mapping[str, str]) -> str:
    direct = str(env_map.get("SIEM_CONTROL_PLANE_PG_DSN", "") or "").strip()
    if direct:
        return direct
    host = str(env_map.get("SIEM_CONTROL_PLANE_PG_HOST") or env_map.get("SIEM_PG_HOST") or "").strip()
    database = str(env_map.get("SIEM_CONTROL_PLANE_PG_DB") or env_map.get("SIEM_PG_DB") or "").strip()
    user = str(env_map.get("SIEM_CONTROL_PLANE_PG_USER") or env_map.get("SIEM_PG_USER") or "").strip()
    password = str(env_map.get("SIEM_CONTROL_PLANE_PG_PASSWORD") or env_map.get("SIEM_PG_PASSWORD") or "").strip()
    if not all((host, database, user, password)):
        return ""
    port = str(env_map.get("SIEM_CONTROL_PLANE_PG_PORT") or env_map.get("SIEM_PG_PORT") or "5432").strip() or "5432"
    return f"host={host} port={port} dbname={database} user={user} password={password} connect_timeout=2"


def _parse_libpq_hosts(dsn: str) -> list[tuple[str, int]]:
    text = str(dsn or "").strip()
    if not text:
        return []
    if text.startswith("postgresql://") or text.startswith("postgres://"):
        parsed = urlparse(text)
        host = str(parsed.hostname or "").strip()
        port = int(parsed.port or 5432)
        return [(host, port)] if host else []
    tokens: dict[str, str] = {}
    for chunk in text.split():
        if "=" not in chunk:
            continue
        key, value = chunk.split("=", 1)
        tokens[str(key).strip()] = str(value).strip()
    hosts = [item.strip() for item in str(tokens.get("host") or "").split(",") if item.strip()]
    ports_raw = [item.strip() for item in str(tokens.get("port") or "5432").split(",") if item.strip()]
    if not hosts:
        return []
    ports: list[int] = []
    for index, host in enumerate(hosts):
        try:
            ports.append(int(ports_raw[index] if index < len(ports_raw) else ports_raw[-1]))
        except Exception:  # noqa: BLE001
            ports.append(5432)
    return list(zip(hosts, ports))


def _sanitize_probe_dsn(dsn: str) -> str:
    text = str(dsn or "").strip()
    if not text:
        return ""
    if text.startswith("postgresql://") or text.startswith("postgres://"):
        parsed = urlparse(text)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params.pop("target_session_attrs", None)
        query_items: list[tuple[str, str]] = []
        for key, values in params.items():
            for value in values:
                query_items.append((key, value))
        query = "&".join(f"{key}={value}" for key, value in query_items)
        return parsed._replace(query=query).geturl()
    filtered_chunks = []
    for chunk in text.split():
        if "=" not in chunk:
            filtered_chunks.append(chunk)
            continue
        key, _value = chunk.split("=", 1)
        if str(key).strip() == "target_session_attrs":
            continue
        filtered_chunks.append(chunk)
    return " ".join(filtered_chunks)


def _probe_postgres_host(host: str, port: int, dsn: str) -> dict[str, Any]:
    try:
        psycopg = importlib.import_module("psycopg")
    except Exception as exc:  # noqa: BLE001
        return {"host": host, "port": port, "healthy": False, "error": f"psycopg_unavailable:{exc}"}
    connect_dsn = _sanitize_probe_dsn(dsn)
    if not (dsn.startswith("postgresql://") or dsn.startswith("postgres://")):
        connect_dsn = f"{connect_dsn} host={host} port={port} connect_timeout=2"
    try:
        with psycopg.connect(connect_dsn, autocommit=True) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT pg_is_in_recovery(), inet_server_addr()::text, inet_server_port(), "
                    "COALESCE(EXTRACT(EPOCH FROM now() - pg_last_xact_replay_timestamp()), 0), "
                    "COALESCE(pg_last_wal_receive_lsn() = pg_last_wal_replay_lsn(), false)"
                )
                row = cursor.fetchone() or (False, host, port, 0, False)
    except Exception as exc:  # noqa: BLE001
        return {"host": host, "port": port, "healthy": False, "error": f"{type(exc).__name__}:{exc}"}
    wal_receive_replay_synced = bool(row[4]) if len(row) > 4 else False
    replay_lag_seconds = 0.0 if bool(row[0]) and wal_receive_replay_synced else float(row[3] or 0)
    return {
        "host": host,
        "port": int(port),
        "healthy": True,
        "in_recovery": bool(row[0]),
        "server_addr": str(row[1] or host),
        "server_port": int(row[2] or port),
        "role": "standby" if bool(row[0]) else "primary",
        "replay_lag_seconds": replay_lag_seconds,
        "wal_receive_replay_synced": wal_receive_replay_synced,
    }


def _datetime_to_epoch(value: Any) -> int | None:
    if isinstance(value, datetime):
        aware = value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
        return int(aware.timestamp())
    return None


def _probe_mongo_host(uri: str, host: str, port: int) -> dict[str, Any]:
    if MongoClient is None:
        return {"host": host, "port": port, "healthy": False, "error": "pymongo_unavailable"}
    parsed = urlparse(uri)
    netloc = str(parsed.netloc or "")
    credentials = ""
    if "@" in netloc:
        credentials, _ = netloc.split("@", 1)
        credentials = f"{credentials}@"
    query_items = [(key, value) for key, value in parse_qsl(parsed.query, keep_blank_values=True) if key != "directConnection"]
    query_items.append(("directConnection", "true"))
    direct_uri = parsed._replace(
        netloc=f"{credentials}{host}:{port}",
        query=urlencode(query_items),
    ).geturl()
    try:
        client = MongoClient(direct_uri, serverSelectionTimeoutMS=2000, connectTimeoutMS=2000, socketTimeoutMS=2000)
        hello = client.admin.command("hello")
    except Exception as exc:  # noqa: BLE001
        return {"host": host, "port": port, "healthy": False, "error": f"{type(exc).__name__}:{exc}"}
    finally:
        try:
            client.close()  # type: ignore[name-defined]
        except Exception:
            pass
    return {
        "host": host,
        "port": int(port),
        "healthy": True,
        "role": "secondary" if bool(hello.get("secondary")) else ("primary" if bool(hello.get("isWritablePrimary")) else "unknown"),
        "set_name": str(hello.get("setName") or ""),
        "last_write_epoch": _datetime_to_epoch(((hello.get("lastWrite") or {}).get("lastWriteDate"))),
    }


def parsed_netloc_from_uri(uri: str) -> str:
    parsed = urlparse(uri)
    return str(parsed.netloc or "")


def _parse_mongo_hosts(uri: str) -> tuple[list[tuple[str, int]], str]:
    parsed = urlparse(uri)
    netloc = str(parsed.netloc or "")
    if "@" in netloc:
        netloc = netloc.split("@", 1)[1]
    hosts: list[tuple[str, int]] = []
    for chunk in netloc.split(","):
        item = chunk.strip()
        if not item:
            continue
        if ":" in item:
            host, port_text = item.rsplit(":", 1)
            try:
                port = int(port_text)
            except ValueError:
                port = 27017
            hosts.append((host.strip(), port))
        else:
            hosts.append((item, 27017))
    params = parse_qs(parsed.query)
    replica_set = str((params.get("replicaSet") or [""])[0] or "")
    return hosts, replica_set


def build_storage_ha_status(
    *,
    platform_status: Mapping[str, Any],
    control_plane_status: Mapping[str, Any] | None = None,
    content_status: Mapping[str, Any] | None = None,
    env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    env_map = _env_map(env)
    control_status = dict(control_plane_status or {})
    content_store_status = dict(content_status or platform_status.get("content_store_status") or {})
    clickhouse_status = {**clickhouse_failover_status(), **clickhouse_replication_snapshot()}

    dsn = _postgres_dsn(env_map)
    pg_hosts = _parse_libpq_hosts(dsn)
    postgres_nodes = [_probe_postgres_host(host, port, dsn) for host, port in pg_hosts]
    postgres_primary = next((item for item in postgres_nodes if item.get("role") == "primary"), None)
    postgres_standby = next((item for item in postgres_nodes if item.get("role") == "standby"), None)

    mongo_uri = str(env_map.get("SIEM_MONGO_URI") or _mongo_default_uri() or "").strip()
    mongo_hosts, mongo_replica_set = _parse_mongo_hosts(mongo_uri)
    mongo_nodes = [_probe_mongo_host(mongo_uri, host, port) for host, port in mongo_hosts]
    mongo_primary = next((item for item in mongo_nodes if item.get("role") == "primary"), None)
    mongo_secondary = next((item for item in mongo_nodes if item.get("role") == "secondary"), None)
    mongo_primary_epoch = int((mongo_primary or {}).get("last_write_epoch") or 0)
    mongo_lags = [
        max(0, mongo_primary_epoch - int(item.get("last_write_epoch") or mongo_primary_epoch))
        for item in mongo_nodes
        if item.get("healthy") and item.get("last_write_epoch") is not None and mongo_primary_epoch
    ]
    if mongo_secondary is not None and mongo_primary_epoch:
        mongo_secondary["replication_lag_seconds"] = max(0, mongo_primary_epoch - int(mongo_secondary.get("last_write_epoch") or mongo_primary_epoch))

    clickhouse_lag_threshold = _int_env(env_map, "SIEM_STORAGE_HA_CLICKHOUSE_REPLICATION_LAG_THRESHOLD_SECONDS", 300)
    postgres_lag_threshold = _int_env(env_map, "SIEM_STORAGE_HA_POSTGRES_REPLAY_LAG_THRESHOLD_SECONDS", 300)
    mongo_lag_threshold = _int_env(env_map, "SIEM_STORAGE_HA_MONGO_REPLICATION_LAG_THRESHOLD_SECONDS", 120)
    clickhouse_lag = clickhouse_status.get("replication_lag_seconds_max")
    postgres_lag = (postgres_standby or {}).get("replay_lag_seconds")
    postgres_synced = bool((postgres_standby or {}).get("wal_receive_replay_synced"))
    mongo_lag = max(mongo_lags) if mongo_lags else 0
    clickhouse_lag_ok = clickhouse_lag in {None, 0} or int(clickhouse_lag) <= clickhouse_lag_threshold
    postgres_lag_ok = postgres_synced or postgres_lag in {None, 0, 0.0} or float(postgres_lag) <= postgres_lag_threshold
    mongo_lag_ok = int(mongo_lag) <= mongo_lag_threshold
    clickhouse_healthy = bool(clickhouse_status.get("healthy", False) and clickhouse_lag_ok)
    postgres_healthy = bool(
        postgres_primary
        and postgres_standby
        and bool(postgres_primary.get("healthy"))
        and bool(postgres_standby.get("healthy"))
        and postgres_lag_ok
    )
    mongo_healthy = bool(
        mongo_primary
        and mongo_secondary
        and bool(mongo_primary.get("healthy"))
        and bool(mongo_secondary.get("healthy"))
        and mongo_lag_ok
    )
    alarms: list[str] = []
    if not clickhouse_healthy:
        alarms.append("clickhouse_unhealthy")
    if not clickhouse_lag_ok:
        alarms.append(f"clickhouse_replication_lag={int(clickhouse_lag)}s")
    if not postgres_healthy:
        alarms.append("postgres_unhealthy")
    if not postgres_lag_ok:
        alarms.append(f"postgres_replay_lag={int(float(postgres_lag))}s")
    if not mongo_healthy:
        alarms.append("mongo_unhealthy")
    if not mongo_lag_ok:
        alarms.append(f"mongo_replication_lag={int(mongo_lag)}s")

    return {
        "clickhouse": {
            **clickhouse_status,
            "primary_expected": str((clickhouse_status.get("configured_hosts") or [{"host": os.environ.get("SIEM_CH_HOST") or "127.0.0.1"}])[0].get("host") or (os.environ.get("SIEM_CH_HOST") or "127.0.0.1")),
            "standby_present": int(clickhouse_status.get("replica_hosts_total") or 0) > 0,
            "configured": bool(clickhouse_status.get("configured_hosts")),
            "replication_lag_ok": clickhouse_lag_ok,
            "replication_lag_threshold_seconds": clickhouse_lag_threshold,
        },
        "postgres": {
            "configured": bool(dsn and pg_hosts),
            "primary": postgres_primary,
            "standby": postgres_standby,
            "nodes": postgres_nodes,
            "backend": str(control_status.get("backend") or ("postgres" if dsn else "")),
            "requested_backend": str(control_status.get("requested_backend") or env_map.get("SIEM_CONTROL_PLANE_BACKEND") or ("postgres" if dsn else "")),
            "healthy": postgres_healthy,
            "replay_lag_ok": postgres_lag_ok,
            "replay_lag_threshold_seconds": postgres_lag_threshold,
        },
        "mongo": {
            "configured": bool(mongo_uri and mongo_hosts),
            "replica_set": mongo_replica_set,
            "primary": mongo_primary,
            "secondary": mongo_secondary,
            "nodes": mongo_nodes,
            "backend": str(content_store_status.get("backend") or ("mongo" if mongo_uri else "")),
            "requested_backend": str(content_store_status.get("requested_backend") or env_map.get("SIEM_CONTENT_STORE_BACKEND") or ("mongo" if mongo_uri else "")),
            "healthy": mongo_healthy,
            "replication_lag_seconds_max": int(mongo_lag),
            "replication_lag_ok": mongo_lag_ok,
            "replication_lag_threshold_seconds": mongo_lag_threshold,
        },
        "alarms": alarms,
        "failover_ready": bool(clickhouse_healthy and postgres_healthy and mongo_healthy),
        "controlled_switchover_ready": bool(clickhouse_healthy and postgres_healthy and mongo_healthy),
    }
