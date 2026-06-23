from __future__ import annotations

from datetime import datetime, timezone
import os
from typing import Any, Mapping


def _value(env: Mapping[str, str], name: str, default: str) -> str:
    return str(env.get(name, default) or default).strip()


def _int_value(env: Mapping[str, str], name: str, default: int) -> int:
    raw = _value(env, name, str(default))
    try:
        return max(1, int(raw))
    except ValueError:
        return default


def _backend(env: Mapping[str, str]) -> str:
    backend = _value(env, "SIEM_TRANSPORT_BACKEND", "kafka").lower()
    if backend not in {"redis", "dual", "kafka"}:
        return "kafka"
    return backend


def _consumer_backend(env: Mapping[str, str], backend: str) -> str:
    default = "kafka" if backend == "dual" else backend
    value = _value(env, "SIEM_TRANSPORT_CONSUMER_BACKEND", default).lower()
    if value not in {"redis", "kafka"}:
        return default
    return value


def _cutover_stage(backend: str) -> str:
    if backend == "kafka":
        return "kafka_only"
    if backend == "dual":
        return "dual_write"
    return "redis_only"


def _auth_mode(env: Mapping[str, str]) -> str:
    security_protocol = _value(env, "SIEM_KAFKA_SECURITY_PROTOCOL", "PLAINTEXT").upper()
    username = _value(env, "SIEM_KAFKA_SASL_USERNAME", "")
    password = _value(env, "SIEM_KAFKA_SASL_PASSWORD", "")
    has_sasl = bool(username and password)
    if "SSL" in security_protocol and has_sasl:
        return "scram_tls"
    if "SSL" in security_protocol:
        return "tls"
    if has_sasl:
        return "scram_plaintext"
    return "plaintext"


def _parse_iso8601(value: Any) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def build_shadow_transport_status(
    *,
    shadow_table_exists: bool,
    main_events_5m: int,
    main_events_15m: int,
    shadow_events_5m: int,
    shadow_events_15m: int,
    shadow_last_event_ts: Any,
    freshness_window_sec: int = 900,
    now: datetime | None = None,
) -> dict[str, Any]:
    now_utc = (now or datetime.now(tz=timezone.utc)).astimezone(timezone.utc)
    shadow_dt = _parse_iso8601(shadow_last_event_ts)
    shadow_last_iso = shadow_dt.isoformat().replace("+00:00", "Z") if shadow_dt else ""
    shadow_last_age_sec = max(0, int((now_utc - shadow_dt).total_seconds())) if shadow_dt else None
    ratio_5m = round(shadow_events_5m / main_events_5m, 4) if main_events_5m > 0 else None
    ratio_15m = round(shadow_events_15m / main_events_15m, 4) if main_events_15m > 0 else None
    issues: list[str] = []

    if not shadow_table_exists:
        status = "missing"
        healthy = False
        issues.append("Kafka shadow table is missing")
    elif main_events_15m <= 0:
        status = "idle"
        healthy = True
    elif shadow_events_15m <= 0:
        status = "empty"
        healthy = False
        issues.append("Kafka shadow pipeline has no events in the last 15 minutes")
    elif shadow_last_age_sec is None:
        status = "pending"
        healthy = False
        issues.append("Kafka shadow pipeline has no observed event timestamp")
    elif shadow_last_age_sec > freshness_window_sec:
        status = "stale"
        healthy = False
        issues.append(f"Kafka shadow pipeline is stale (last event {shadow_last_age_sec}s ago)")
    else:
        status = "healthy"
        healthy = True

    return {
        "available": True,
        "healthy": healthy,
        "status": status,
        "issues": issues,
        "freshness_window_sec": int(freshness_window_sec),
        "main_events_5m": int(main_events_5m),
        "main_events_15m": int(main_events_15m),
        "shadow_events_5m": int(shadow_events_5m),
        "shadow_events_15m": int(shadow_events_15m),
        "shadow_last_event_ts": shadow_last_iso,
        "shadow_last_event_age_sec": shadow_last_age_sec,
        "shadow_to_main_ratio_5m": ratio_5m,
        "shadow_to_main_ratio_15m": ratio_15m,
        "shadow_table_exists": bool(shadow_table_exists),
    }


def transport_health_snapshot(env: Mapping[str, str] | None = None) -> dict[str, Any]:
    env_map = env or os.environ
    backend = _backend(env_map)
    consumer_backend = _consumer_backend(env_map, backend)
    bootstrap_servers = [item.strip() for item in _value(env_map, "SIEM_KAFKA_BOOTSTRAP_SERVERS", "127.0.0.1:9092").split(",") if item.strip()]
    configured_topics = {
        "raw": _value(env_map, "SIEM_KAFKA_TOPIC_RAW", "siem.raw"),
        "normalized": _value(env_map, "SIEM_KAFKA_TOPIC_NORMALIZED", "siem.normalized"),
        "filtered": _value(env_map, "SIEM_KAFKA_TOPIC_FILTERED", "siem.filtered"),
        "dlq": _value(env_map, "SIEM_KAFKA_TOPIC_DLQ", "siem.dlq"),
        "replay": _value(env_map, "SIEM_KAFKA_TOPIC_REPLAY", "siem.replay"),
        "transport_audit": _value(env_map, "SIEM_KAFKA_TOPIC_TRANSPORT_AUDIT", "siem.transport.audit"),
    }
    configured_streams = {
        "raw": _value(env_map, "SIEM_REDIS_STREAM_RAW", "siem:raw"),
        "normalized": _value(env_map, "SIEM_REDIS_STREAM_NORMALIZED", "siem:normalized"),
        "filtered": _value(env_map, "SIEM_REDIS_STREAM_FILTERED", "siem:filtered"),
        "dlq": _value(env_map, "SIEM_REDIS_STREAM_DLQ", "siem:raw:dlq"),
        "replay": _value(env_map, "SIEM_REDIS_STREAM_REPLAY", "siem:replay"),
        "transport_audit": _value(env_map, "SIEM_REDIS_STREAM_TRANSPORT_AUDIT", "siem:transport:audit"),
    }
    use_kafka = backend in {"dual", "kafka"}

    def _target(alias: str) -> str:
        return configured_topics[alias] if use_kafka else configured_streams[alias]

    return {
        "backend": backend,
        "consumer_backend": consumer_backend,
        "cutover_stage": _cutover_stage(backend),
        "kafka_enabled": use_kafka or consumer_backend == "kafka",
        "kafka_clients_available": None,
        "kafka_configured": bool(bootstrap_servers),
        "kafka_bootstrap_servers": bootstrap_servers,
        "kafka_auth_mode": _auth_mode(env_map),
        "kafka_security_protocol": _value(env_map, "SIEM_KAFKA_SECURITY_PROTOCOL", "PLAINTEXT").upper(),
        "kafka_expected_brokers": _int_value(env_map, "SIEM_KAFKA_EXPECTED_BROKERS", 3),
        "kafka_expected_controllers": _int_value(env_map, "SIEM_KAFKA_EXPECTED_CONTROLLERS", 3),
        "kafka_default_replication_factor": _int_value(env_map, "SIEM_KAFKA_DEFAULT_REPLICATION_FACTOR", 3),
        "kafka_min_insync_replicas": _int_value(env_map, "SIEM_KAFKA_MIN_INSYNC_REPLICAS", 2),
        "configured_topics": configured_topics,
        "configured_streams": configured_streams,
        "raw_target": _target("raw"),
        "normalized_target": _target("normalized"),
        "filtered_target": _target("filtered"),
        "dlq_target": _target("dlq"),
        "replay_target": _target("replay"),
        "transport_audit_target": _target("transport_audit"),
        "redis_streams_active": backend in {"redis", "dual"},
        "kafka_shadow_ready": bool((use_kafka or consumer_backend == "kafka") and bootstrap_servers),
    }
