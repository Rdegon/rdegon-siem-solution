from __future__ import annotations

import os
from typing import Any, Mapping

try:
    from .backup_runtime import backup_runtime_status
except ImportError:  # pragma: no cover - local test/runtime fallback
    from backup_runtime import backup_runtime_status  # type: ignore[no-redef]

try:
    from .services.stream_state import stream_state_runtime_status as local_stream_state_runtime_status
except ImportError:  # pragma: no cover - local test/runtime fallback
    from services.stream_state import stream_state_runtime_status as local_stream_state_runtime_status  # type: ignore[no-redef]

try:
    from .services.transport_runtime import transport_health_snapshot as local_transport_health_snapshot
except ImportError:  # pragma: no cover - local test/runtime fallback
    from services.transport_runtime import transport_health_snapshot as local_transport_health_snapshot  # type: ignore[no-redef]

try:
    from .storage_ha_runtime import build_storage_ha_status
except ImportError:  # pragma: no cover - local test/runtime fallback
    from storage_ha_runtime import build_storage_ha_status  # type: ignore[no-redef]

DEFAULT_STREAM_STATE_SQLITE_PATH = "/var/lib/siem-stream-corr/runtime-state.db"


def _env_map(env: Mapping[str, str] | None = None) -> dict[str, str]:
    return dict(env or os.environ)


def _transport_stage_for_backend(backend: str) -> str:
    if backend == "kafka":
        return "kafka_only"
    if backend == "dual":
        return "dual_write"
    return "redis_only"


def resolve_stream_state_status(platform_status: Mapping[str, Any], env: Mapping[str, str] | None = None) -> dict[str, Any]:
    env_map = _env_map(env)
    runtime = dict(local_stream_state_runtime_status(env_map))
    stream_corr = dict(platform_status.get("stream_correlation") or {})
    platform_backend = str(
        stream_corr.get("state_backend")
        or platform_status.get("stream_state_backend")
        or runtime.get("backend")
        or "sqlite"
    ).strip().lower()
    if platform_backend != "sqlite":
        return runtime
    runtime["backend"] = "sqlite"
    runtime["healthy"] = bool(runtime.get("healthy", False) or stream_corr.get("available", False) or stream_corr.get("status") == "active")
    runtime["sqlite_path"] = str(runtime.get("sqlite_path") or env_map.get("SIEM_STREAM_STATE_SQLITE_PATH") or DEFAULT_STREAM_STATE_SQLITE_PATH)
    runtime["sqlite_node"] = str(runtime.get("sqlite_node") or env_map.get("SIEM_STREAM_STATE_SQLITE_NODE") or "vm3")
    runtime["sqlite_exists"] = bool(runtime.get("sqlite_exists", False) or runtime.get("stored_offsets_total") or stream_corr.get("available", False))
    if not runtime.get("last_offset_ts"):
        runtime["last_offset_ts"] = str(stream_corr.get("observed_ts") or "")
    return runtime


def resolve_transport_health_snapshot(
    *,
    ingest_transport: Mapping[str, Any],
    platform_status: Mapping[str, Any],
    env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    env_map = _env_map(env)
    desired = dict(local_transport_health_snapshot(env_map))
    backend = str(ingest_transport.get("backend") or platform_status.get("transport_backend") or desired.get("backend") or "kafka").strip().lower()
    consumer_backend = str(ingest_transport.get("consumer_backend") or desired.get("consumer_backend") or backend).strip().lower()
    if backend in {"dual", "kafka"}:
        desired["backend"] = backend
        desired["consumer_backend"] = consumer_backend
        desired["cutover_stage"] = str(ingest_transport.get("cutover_stage") or _transport_stage_for_backend(backend))
        desired["kafka_enabled"] = True
        desired["kafka_configured"] = bool(ingest_transport.get("kafka_configured") or desired.get("kafka_configured") or ingest_transport.get("kafka_bootstrap_servers"))
        if ingest_transport.get("kafka_bootstrap_servers"):
            desired["kafka_bootstrap_servers"] = list(ingest_transport.get("kafka_bootstrap_servers") or [])
        if ingest_transport.get("configured_topics"):
            desired["configured_topics"] = dict(ingest_transport.get("configured_topics") or {})
        desired["redis_streams_active"] = backend in {"redis", "dual"}
    return desired


def build_transport_health_payload(
    *,
    ingest_transport: Mapping[str, Any],
    platform_status: Mapping[str, Any],
    env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    desired_transport = resolve_transport_health_snapshot(
        ingest_transport=ingest_transport,
        platform_status=platform_status,
        env=env,
    )
    stream_corr = dict(platform_status.get("stream_correlation") or {})
    shadow_transport = dict(platform_status.get("transport_shadow_status") or {})
    state_runtime = resolve_stream_state_status(platform_status, env=env)
    backend = str(ingest_transport.get("backend") or desired_transport.get("backend") or "kafka")
    configured_topics = dict(ingest_transport.get("configured_topics") or desired_transport.get("configured_topics") or {})
    bootstrap_servers = list(ingest_transport.get("kafka_bootstrap_servers") or desired_transport.get("kafka_bootstrap_servers") or [])
    shadow_required = bool(stream_corr.get("shadow_compare"))
    kafka_cluster_healthy = bool(backend in {"dual", "kafka"} and bool(ingest_transport.get("kafka_configured") or desired_transport.get("kafka_configured")))
    issues: list[str] = []
    if backend == "redis":
        issues.append("Transport backend is still on Redis")
    if backend == "dual":
        issues.append("Transport cutover remains in dual-write mode")
    if backend in {"dual", "kafka"} and not kafka_cluster_healthy:
        issues.append("Kafka transport is not fully configured")
    if not bool(state_runtime.get("healthy", False)):
        issues.append("Stream state backend is unhealthy")
    if not bool(platform_status.get("content_store_healthy", False)):
        issues.append("Content store backend is unhealthy")
    if shadow_required and not bool(shadow_transport.get("healthy", False)):
        issues.extend(
            [str(item).strip() for item in (shadow_transport.get("issues") or []) if str(item).strip()]
            or ["Kafka shadow pipeline is unhealthy"]
        )
    return {
        "generated_ts": str(platform_status.get("last_event_ts") or stream_corr.get("observed_ts") or ""),
        "transport_backend": backend,
        "transport_cutover_stage": str(ingest_transport.get("cutover_stage") or desired_transport.get("cutover_stage") or _transport_stage_for_backend(backend)),
        "kafka_cluster_healthy": kafka_cluster_healthy,
        "broker_quorum": (
            f"{int(desired_transport.get('kafka_expected_brokers') or 0)} configured"
            if backend in {"dual", "kafka"}
            else "not_enabled"
        ),
        "largest_consumer_lag": None,
        "stream_state_backend": str(stream_corr.get("state_backend") or state_runtime.get("backend") or platform_status.get("stream_state_backend") or "sqlite"),
        "content_store_backend": str(platform_status.get("content_store_backend") or "filesystem"),
        "content_store_healthy": bool(platform_status.get("content_store_healthy", False)),
        "shadow_compare_status": "enabled" if bool(stream_corr.get("shadow_compare")) else "disabled",
        "shadow_pipeline_status": str(shadow_transport.get("status") or "unavailable"),
        "shadow_pipeline_healthy": bool(shadow_transport.get("healthy", False)),
        "kafka_bootstrap_servers": bootstrap_servers,
        "kafka_auth_mode": str(ingest_transport.get("kafka_auth_mode") or desired_transport.get("kafka_auth_mode") or "plaintext"),
        "configured_topics": configured_topics,
        "healthy": not issues,
        "issues": issues,
        "desired_transport": desired_transport,
        "ingest": dict(ingest_transport or {}),
        "stream_correlation": stream_corr,
        "transport_shadow": shadow_transport,
        "stream_state": {
            **state_runtime,
            "backend": str(stream_corr.get("state_backend") or state_runtime.get("backend") or "sqlite"),
        },
    }


def build_storage_health_payload(
    platform_status: Mapping[str, Any],
    *,
    control_plane_status: Mapping[str, Any] | None = None,
    content_status: Mapping[str, Any] | None = None,
    env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    storage_memory = dict(platform_status.get("storage_memory") or {})
    clickhouse_runtime = dict(platform_status.get("clickhouse_runtime") or {})
    clickhouse_ok = bool(platform_status.get("clickhouse_ok", False) or clickhouse_runtime.get("healthy", False))
    return {
        "generated_ts": str(platform_status.get("last_event_ts") or storage_memory.get("observed_ts") or ""),
        "clickhouse_ok": clickhouse_ok,
        "clickhouse_runtime": clickhouse_runtime,
        "events_5m": int(platform_status.get("events_5m") or 0),
        "alerts_24h": int(platform_status.get("alerts_24h") or 0),
        "storage_memory": storage_memory,
        "storage_ha": build_storage_ha_status(
            platform_status=platform_status,
            control_plane_status=control_plane_status,
            content_status=content_status,
            env=env,
        ),
    }


def build_backup_health_payload(
    *,
    control_plane_status: Mapping[str, Any],
    content_status: Mapping[str, Any],
    platform_status: Mapping[str, Any],
    env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    state_runtime = resolve_stream_state_status(platform_status, env=env)
    payload = backup_runtime_status(
        control_plane_status=control_plane_status,
        content_status=content_status,
        stream_state_status=state_runtime,
        platform_status=platform_status,
        env=env,
    )
    payload["storage_ha"] = build_storage_ha_status(
        platform_status=platform_status,
        control_plane_status=control_plane_status,
        content_status=content_status,
        env=env,
    )
    return payload
