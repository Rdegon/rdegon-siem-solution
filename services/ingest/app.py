"""
HTTP and TCP ingest service for separated collector profiles.
"""

from __future__ import annotations

import asyncio
import logging
import os
from typing import Any, Dict, List

from fastapi import Body, FastAPI, HTTPException, Query, Request
try:
    from redis.asyncio import Redis
except ModuleNotFoundError:  # pragma: no cover - local test fallback
    Redis = Any  # type: ignore[assignment,misc]

from .config import IngestSettings
from .logging_conf import configure_logging
from .redis_client import (
    IngestBackpressureError,
    build_ingest_overview,
    build_transport_overview,
    create_redis_client,
    list_collector_health,
    list_dlq_events,
    list_source_health,
    push_dead_letter_event,
    push_raw_event,
    push_raw_events_batch,
    record_ingest_acceptance_batch,
    replay_dlq_events,
    suppress_non_operational_dlq_events,
)
from .syslog_server import create_syslog_servers
from services.transport_runtime import create_transport_producer, transport_settings_from_object

logger = logging.getLogger(__name__)

_settings: IngestSettings | None = None
_redis: Redis | None = None
_transport_producer: Any | None = None
_syslog_servers: List[Any] = []


def _get_settings() -> IngestSettings:
    global _settings
    if _settings is None:
        _settings = IngestSettings.load()
    return _settings


def _get_redis() -> Redis:
    global _redis
    if _redis is None:
        raise RuntimeError("Redis client not initialized")
    return _redis


def _get_transport_producer() -> Any:
    global _transport_producer
    if _transport_producer is None:
        raise RuntimeError("Transport producer not initialized")
    return _transport_producer


app = FastAPI(title="SIEM Ingest Service", version="0.3.0")


@app.on_event("startup")
async def on_startup() -> None:
    configure_logging()
    settings = _get_settings()

    logger.info(
        "Starting SIEM Ingest Service",
        extra={"extra": {"env": settings.env, "instance": settings.instance_name}},
    )

    global _redis, _transport_producer, _syslog_servers
    _redis = create_redis_client(settings)
    _transport_producer = create_transport_producer(settings)
    _syslog_servers = await create_syslog_servers(settings, _redis, _transport_producer)


@app.on_event("shutdown")
async def on_shutdown() -> None:
    global _redis, _transport_producer, _syslog_servers

    for server in _syslog_servers:
        await server.stop()
    _syslog_servers = []

    if _redis is not None:
        await _redis.close()
        _redis = None
    if _transport_producer is not None:
        await _transport_producer.close()
        _transport_producer = None


def _ingest_admin_secret() -> str:
    return str(
        os.getenv("SIEM_INGEST_API_SHARED_SECRET", "").strip()
        or os.getenv("SIEM_WEBHOOK_SHARED_SECRET", "").strip()
    )


def _require_admin_secret(request: Request) -> None:
    expected_secret = _ingest_admin_secret()
    if not expected_secret:
        return
    presented_secret = str(request.headers.get("x-rdegon-ingest-secret") or "").strip()
    if presented_secret != expected_secret:
        raise HTTPException(status_code=403, detail="invalid_ingest_runtime_secret")


@app.get("/health")
async def health() -> dict:
    settings = _get_settings()
    redis = _get_redis()
    runtime_state_backend = str(getattr(settings, "runtime_state_backend", "redis") or "redis").strip().lower()

    try:
        pong = await redis.ping()
    except Exception as exc:  # noqa: BLE001
        logger.error("Ingest runtime state ping failed", extra={"extra": {"error": str(exc), "backend": runtime_state_backend}})
        raise HTTPException(status_code=503, detail="ingest_runtime_state_unhealthy") from exc

    return {
        "status": "ok",
        "env": settings.env,
        "instance": settings.instance_name,
        "runtime_state_backend": runtime_state_backend,
        "runtime_state": "ok" if pong else "failed",
        "redis": "retired" if runtime_state_backend != "redis" else ("ok" if pong else "failed"),
        "syslog_profiles": settings.syslog_profiles(),
        "transport": build_transport_overview(settings),
    }


@app.get("/health/overview")
async def health_overview(request: Request) -> dict[str, Any]:
    _require_admin_secret(request)
    return await build_ingest_overview(_get_redis(), _get_settings())


@app.get("/health/transport")
async def health_transport(request: Request) -> dict[str, Any]:
    _require_admin_secret(request)
    overview = await build_ingest_overview(_get_redis(), _get_settings())
    transport = dict(overview.get("transport") or {})
    transport["generated_ts"] = str(overview.get("generated_ts") or "")
    transport["streams"] = dict(overview.get("streams") or {})
    transport["issues"] = list(overview.get("issues") or [])
    return transport


@app.get("/health/sources")
async def health_sources(
    request: Request,
    limit: int = Query(200, ge=1, le=500),
    include_excluded: bool = Query(False),
) -> dict[str, Any]:
    _require_admin_secret(request)
    return await list_source_health(_get_redis(), limit=limit, include_excluded=include_excluded)


@app.get("/health/collectors")
async def health_collectors(
    request: Request,
    limit: int = Query(200, ge=1, le=500),
    include_excluded: bool = Query(False),
) -> dict[str, Any]:
    _require_admin_secret(request)
    return await list_collector_health(_get_redis(), limit=limit, include_excluded=include_excluded)


@app.get("/dlq/events")
async def dlq_events(
    request: Request,
    limit: int = Query(200, ge=1, le=500),
) -> dict[str, Any]:
    _require_admin_secret(request)
    return await list_dlq_events(_get_redis(), count=limit)


@app.post("/dlq/replay")
async def dlq_replay(
    request: Request,
    payload: dict[str, Any] = Body(default={}),
) -> dict[str, Any]:
    _require_admin_secret(request)
    ids = payload.get("ids") or []
    if not isinstance(ids, list):
        raise HTTPException(status_code=400, detail="ids_must_be_list")
    limit = int(payload.get("limit") or 20)
    actor = str(payload.get("actor") or "api")
    return await replay_dlq_events(
        _get_redis(),
        ids=[str(item) for item in ids if str(item).strip()],
        limit=max(1, min(2_000, limit)),
        actor=actor,
        settings=_get_settings(),
        producer=_get_transport_producer(),
    )


@app.post("/dlq/suppress")
async def dlq_suppress(
    request: Request,
    payload: dict[str, Any] = Body(default={}),
) -> dict[str, Any]:
    _require_admin_secret(request)
    actor = str(payload.get("actor") or "api")
    limit = int(payload.get("limit") or 100_000)
    return await suppress_non_operational_dlq_events(
        _get_redis(),
        actor=actor,
        limit=max(1, min(500_000, limit)),
    )


async def _ingest_json(
    request: Request,
    payload: Any,
    *,
    default_source_type: str,
    collector: str,
    collector_profile: str,
    ingest_profile: str,
) -> dict:
    redis = _get_redis()

    source_ip = request.client.host if request.client else ""
    if isinstance(payload, list):
        events: List[Any] = payload
    elif isinstance(payload, dict):
        events = [payload]
    else:
        dlq_id = await push_dead_letter_event(
            redis,
            payload,
            reason="payload_must_be_object_or_list",
            source_ip=source_ip,
            collector=collector,
            collector_profile=collector_profile,
            ingest_path=request.url.path,
            metadata={
                "source_type": default_source_type,
                "collector": collector,
                "collector_profile": collector_profile,
                "ingest_profile": ingest_profile,
                "event.dataset": ingest_profile,
            },
        )
        return {
            "status": "dlq_only",
            "ingested": 0,
            "rejected": 1,
            "collector_profile": collector_profile,
            "dlq_ids": [dlq_id],
        }

    count = 0
    rejected = 0
    dlq_ids: list[str] = []

    def _build_event(raw: dict[str, Any]) -> dict[str, Any]:
        event: Dict[str, Any] = dict(raw)
        event.setdefault("source", source_ip)
        event.setdefault("source_type", default_source_type)
        event.setdefault("collector", collector)
        event.setdefault("collector_profile", collector_profile)
        event.setdefault("ingest_profile", ingest_profile)
        event.setdefault("ingest_path", request.url.path)
        event.setdefault("listener_port", request.url.port or 0)
        event.setdefault("observer.collector", collector)
        event.setdefault("observer.profile", collector_profile)
        event.setdefault("observer.listener_port", str(request.url.port or 0))
        event.setdefault("observer.ingest_path", request.url.path)
        event.setdefault("event.dataset", ingest_profile)
        return event

    async def _ingest_event(raw: Any) -> tuple[int, int, list[str], dict[str, Any] | None]:
        if not isinstance(raw, dict):
            dlq_id = await push_dead_letter_event(
                redis,
                raw,
                reason="payload_item_not_object",
                source_ip=source_ip,
                collector=collector,
                collector_profile=collector_profile,
                ingest_path=request.url.path,
                metadata={
                    "source_type": default_source_type,
                    "collector": collector,
                    "collector_profile": collector_profile,
                    "ingest_profile": ingest_profile,
                    "event.dataset": ingest_profile,
                },
            )
            return 0, 1, [dlq_id], None

        event = _build_event(raw)

        try:
            stream_id = await push_raw_event(
                redis,
                event,
                settings=_get_settings(),
                producer=_get_transport_producer(),
                record_runtime_bookkeeping=False,
            )
            return 1, 0, [], {"event": event, "stream_id": stream_id, "replayed": False}
        except IngestBackpressureError as exc:
            return 0, 1, [exc.dlq_id], None

    transport = transport_settings_from_object(_get_settings())
    producer = _get_transport_producer()
    if transport.backend == "kafka" and hasattr(producer, "publish_many"):
        publish_batch_size = max(1, min(2_000, int(os.getenv("SIEM_INGEST_HTTP_PUBLISH_BATCH_SIZE", "250") or "250")))
        for index in range(0, len(events), publish_batch_size):
            chunk = events[index : index + publish_batch_size]
            events_to_publish: list[dict[str, Any]] = []
            for raw in chunk:
                if not isinstance(raw, dict):
                    dlq_id = await push_dead_letter_event(
                        redis,
                        raw,
                        reason="payload_item_not_object",
                        source_ip=source_ip,
                        collector=collector,
                        collector_profile=collector_profile,
                        ingest_path=request.url.path,
                        metadata={
                            "source_type": default_source_type,
                            "collector": collector,
                            "collector_profile": collector_profile,
                            "ingest_profile": ingest_profile,
                            "event.dataset": ingest_profile,
                        },
                    )
                    rejected += 1
                    dlq_ids.append(dlq_id)
                    continue
                events_to_publish.append(_build_event(raw))
            if not events_to_publish:
                continue
            accepted_batch = await push_raw_events_batch(
                redis,
                events_to_publish,
                settings=_get_settings(),
                producer=producer,
            )
            count += len(accepted_batch)
            await record_ingest_acceptance_batch(redis, accepted_batch, settings=_get_settings())
    else:
        parallelism = max(1, min(64, int(os.getenv("SIEM_INGEST_HTTP_BATCH_PARALLELISM", "16") or "16")))
        for index in range(0, len(events), parallelism):
            chunk = events[index : index + parallelism]
            chunk_results = await asyncio.gather(*(_ingest_event(raw) for raw in chunk))
            accepted_batch: list[dict[str, Any]] = []
            for accepted_count, rejected_count, chunk_dlq_ids, batch_record in chunk_results:
                count += int(accepted_count)
                rejected += int(rejected_count)
                dlq_ids.extend(chunk_dlq_ids)
                if batch_record:
                    accepted_batch.append(batch_record)
            if accepted_batch:
                await record_ingest_acceptance_batch(redis, accepted_batch, settings=_get_settings())

    logger.info(
        "Ingested events via HTTP",
        extra={
            "extra": {
                "count": count,
                "rejected": rejected,
                "source_ip": source_ip,
                "path": request.url.path,
                "collector_profile": collector_profile,
            }
        },
    )

    status = "ok"
    if rejected and count:
        status = "partial_ok"
    elif rejected and not count:
        status = "dlq_only"
    return {
        "status": status,
        "ingested": count,
        "rejected": rejected,
        "collector_profile": collector_profile,
        "dlq_ids": dlq_ids,
    }


@app.post("/ingest/json")
async def ingest_json(request: Request, payload: Any = Body(...)) -> dict:
    return await _ingest_json(
        request,
        payload,
        default_source_type="http_json",
        collector="http_json",
        collector_profile="generic-http",
        ingest_profile="generic-http",
    )


@app.post("/ingest/windows/base")
async def ingest_windows_base(request: Request, payload: Any = Body(...)) -> dict:
    return await _ingest_json(
        request,
        payload,
        default_source_type="windows_event_json",
        collector="windows_http",
        collector_profile="windows-base-http",
        ingest_profile="windows-base-http",
    )


@app.post("/ingest/windows/security")
async def ingest_windows_security(request: Request, payload: Any = Body(...)) -> dict:
    return await _ingest_json(
        request,
        payload,
        default_source_type="windows_event_json",
        collector="windows_http",
        collector_profile="windows-security-http",
        ingest_profile="windows-security-http",
    )


@app.post("/ingest/windows/sysmon")
async def ingest_windows_sysmon(request: Request, payload: Any = Body(...)) -> dict:
    return await _ingest_json(
        request,
        payload,
        default_source_type="windows_event_json",
        collector="windows_http",
        collector_profile="windows-sysmon-http",
        ingest_profile="windows-sysmon-http",
    )


@app.post("/ingest/windows/powershell")
async def ingest_windows_powershell(request: Request, payload: Any = Body(...)) -> dict:
    return await _ingest_json(
        request,
        payload,
        default_source_type="windows_event_json",
        collector="windows_http",
        collector_profile="windows-powershell-http",
        ingest_profile="windows-powershell-http",
    )


@app.post("/ingest/app/json")
async def ingest_app_json(request: Request, payload: Any = Body(...)) -> dict:
    return await _ingest_json(
        request,
        payload,
        default_source_type="http_json",
        collector="app_http",
        collector_profile="app-json-http",
        ingest_profile="app-json-http",
    )


@app.post("/ingest/vpn/json")
async def ingest_vpn_json(request: Request, payload: Any = Body(...)) -> dict:
    return await _ingest_json(
        request,
        payload,
        default_source_type="http_json",
        collector="vpn_http",
        collector_profile="vpn-http",
        ingest_profile="vpn-http",
    )


@app.post("/ingest/vulnscanner/json")
async def ingest_vulnscanner_json(request: Request, payload: Any = Body(...)) -> dict:
    return await _ingest_json(
        request,
        payload,
        default_source_type="http_json",
        collector="vulnscanner_http",
        collector_profile="vulnscanner-http",
        ingest_profile="vulnscanner-http",
    )
