from __future__ import annotations

import json
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Lock

from fastapi import APIRouter, Depends, Query
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from ..content_runtime import content_storage_status
from ..certification_runtime import certification_runtime_status
from ..deps import (
    fetch_collector_inventory,
    fetch_platform_status,
    fetch_source_inventory,
    fetch_transport_shadow_status,
)
from ..enterprise_control_plane import control_plane_storage_status
from ..health_surfaces import (
    build_backup_health_payload,
    build_storage_health_payload,
    build_transport_health_payload,
)
from ..host_runtime_runtime import fetch_host_runtime_overview
from ..ingest_runtime import get_ingest_overview, get_ingest_transport_health
from ..security import require_permissions
from ..stale_runtime_cache import StaleRuntimeCache
from ..control_plane_health import build_health_overview

router = APIRouter()

HEALTH_OVERVIEW_CACHE_TTL_SEC = int(os.getenv("SIEM_HEALTH_OVERVIEW_CACHE_TTL_SEC", "300") or "300")
HEALTH_OVERVIEW_CACHE_MAX_STALE_SEC = int(
    os.getenv("SIEM_HEALTH_OVERVIEW_CACHE_MAX_STALE_SEC", "2592000") or "2592000"
)
HEALTH_OVERVIEW_CACHE_FILE = Path(
    os.getenv("SIEM_HEALTH_OVERVIEW_CACHE_FILE", "/opt/siem/runtime-docs/health_overview_cache.json")
)
_HEALTH_OVERVIEW_CACHE_LOCK = Lock()
HOST_RUNTIME_CACHE_TTL_SEC = int(
    os.getenv("SIEM_HOST_RUNTIME_CACHE_TTL_SEC", "120") or "120"
)
HOST_RUNTIME_CACHE_MAX_STALE_SEC = int(
    os.getenv("SIEM_HOST_RUNTIME_CACHE_MAX_STALE_SEC", "86400") or "86400"
)
HOST_RUNTIME_CACHE_FILE = Path(
    os.getenv(
        "SIEM_HOST_RUNTIME_CACHE_FILE",
        "/opt/siem/runtime-docs/host_runtime_cache.json",
    )
)
_HOST_RUNTIME_CACHE_LOCK = Lock()
_HOST_RUNTIME_REFRESHING: set[str] = set()
_HEALTH_SURFACE_CACHE = StaleRuntimeCache(
    Path(
        os.getenv(
            "SIEM_HEALTH_SURFACE_CACHE_FILE",
            "/opt/siem/runtime-docs/health_surface_cache.json",
        )
    ),
    ttl_seconds=int(
        os.getenv("SIEM_HEALTH_SURFACE_CACHE_TTL_SEC", "120") or "120"
    ),
)


def _read_health_overview_cache(*, allow_stale: bool = False) -> tuple[dict, float] | None:
    if HEALTH_OVERVIEW_CACHE_TTL_SEC <= 0:
        return None
    try:
        if not HEALTH_OVERVIEW_CACHE_FILE.exists():
            return None
        age_seconds = time.time() - HEALTH_OVERVIEW_CACHE_FILE.stat().st_mtime
        maximum_age = HEALTH_OVERVIEW_CACHE_MAX_STALE_SEC if allow_stale else HEALTH_OVERVIEW_CACHE_TTL_SEC
        if age_seconds > maximum_age:
            return None
        payload = json.loads(HEALTH_OVERVIEW_CACHE_FILE.read_text(encoding="utf-8"))
        return (payload, age_seconds) if isinstance(payload, dict) else None
    except Exception:  # noqa: BLE001
        return None


def _write_health_overview_cache(payload: dict) -> None:
    if HEALTH_OVERVIEW_CACHE_TTL_SEC <= 0:
        return
    try:
        HEALTH_OVERVIEW_CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = HEALTH_OVERVIEW_CACHE_FILE.with_suffix(f".{os.getpid()}.tmp")
        tmp_path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        tmp_path.replace(HEALTH_OVERVIEW_CACHE_FILE)
    except Exception:  # noqa: BLE001
        return


def _read_host_runtime_cache(
    cache_key: str,
) -> tuple[float, dict] | None:
    try:
        if not HOST_RUNTIME_CACHE_FILE.exists():
            return None
        payload = json.loads(HOST_RUNTIME_CACHE_FILE.read_text(encoding="utf-8"))
        record = payload.get(cache_key) if isinstance(payload, dict) else None
        if not isinstance(record, dict) or not isinstance(record.get("payload"), dict):
            return None
        updated_ts = float(record.get("updated_ts") or 0)
        if time.time() - updated_ts > HOST_RUNTIME_CACHE_MAX_STALE_SEC:
            return None
        return updated_ts, dict(record["payload"])
    except Exception:  # noqa: BLE001
        return None


def _write_host_runtime_cache(cache_key: str, payload: dict) -> None:
    try:
        HOST_RUNTIME_CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        with _HOST_RUNTIME_CACHE_LOCK:
            records: dict = {}
            if HOST_RUNTIME_CACHE_FILE.exists():
                loaded = json.loads(
                    HOST_RUNTIME_CACHE_FILE.read_text(encoding="utf-8")
                )
                if isinstance(loaded, dict):
                    records = loaded
            records[cache_key] = {
                "updated_ts": time.time(),
                "payload": payload,
            }
            temporary = HOST_RUNTIME_CACHE_FILE.with_suffix(
                f".{os.getpid()}.tmp"
            )
            temporary.write_text(
                json.dumps(records, ensure_ascii=False),
                encoding="utf-8",
            )
            temporary.replace(HOST_RUNTIME_CACHE_FILE)
    except Exception:  # noqa: BLE001
        return


def _refresh_host_runtime(cache_key: str, hours: int, limit: int) -> dict:
    payload = fetch_host_runtime_overview(hours=hours, limit=limit)
    _write_host_runtime_cache(cache_key, payload)
    return payload


def _schedule_host_runtime_refresh(
    cache_key: str,
    hours: int,
    limit: int,
) -> None:
    with _HOST_RUNTIME_CACHE_LOCK:
        if cache_key in _HOST_RUNTIME_REFRESHING:
            return
        _HOST_RUNTIME_REFRESHING.add(cache_key)

    def refresh() -> None:
        try:
            _refresh_host_runtime(cache_key, hours, limit)
        finally:
            with _HOST_RUNTIME_CACHE_LOCK:
                _HOST_RUNTIME_REFRESHING.discard(cache_key)

    threading.Thread(
        target=refresh,
        name=f"siem-host-runtime-refresh-{hours}-{limit}",
        daemon=True,
    ).start()


def _build_health_overview_payload() -> dict:
    ingest_runtime = None
    ingest_runtime_error = ""
    with ThreadPoolExecutor(max_workers=4) as executor:
        platform_future = executor.submit(fetch_platform_status)
        source_future = executor.submit(fetch_source_inventory, limit=300, hours=24)
        collector_future = executor.submit(fetch_collector_inventory, hours=24)
        ingest_future = executor.submit(get_ingest_overview)
        try:
            ingest_runtime = ingest_future.result()
        except Exception as exc:  # noqa: BLE001
            ingest_runtime_error = str(exc)
        payload = build_health_overview(
            platform_status=platform_future.result(),
            source_inventory=source_future.result(),
            collector_inventory=collector_future.result(),
            ingest_runtime=ingest_runtime,
        )
    if ingest_runtime_error:
        payload.setdefault("issues", []).append(
            f"Ingest runtime unavailable: {ingest_runtime_error}"
        )
    return payload


def _refresh_health_overview_payload() -> dict:
    payload = _build_health_overview_payload()
    with _HEALTH_OVERVIEW_CACHE_LOCK:
        _write_health_overview_cache(payload)
    return payload


def schedule_health_warmup() -> bool:
    return _HEALTH_SURFACE_CACHE.schedule(
        "overview",
        _refresh_health_overview_payload,
    )


def _build_transport_payload() -> dict:
    ingest_transport = get_ingest_transport_health()
    platform_status = fetch_platform_status()
    if not platform_status.get("transport_shadow_status"):
        platform_status = {
            **platform_status,
            "transport_shadow_status": fetch_transport_shadow_status(),
        }
    return build_transport_health_payload(
        ingest_transport=ingest_transport,
        platform_status=platform_status,
    )


def _build_storage_payload() -> dict:
    return build_storage_health_payload(
        fetch_platform_status(),
        control_plane_status=control_plane_storage_status(),
        content_status=content_storage_status(),
    )


def _build_backup_payload() -> dict:
    return build_backup_health_payload(
        control_plane_status=control_plane_storage_status(),
        content_status=content_storage_status(),
        platform_status=fetch_platform_status(),
    )


@router.get("/api/health/overview", response_class=JSONResponse)
async def health_overview_api(user=Depends(require_permissions("health:view"))) -> JSONResponse:
    try:
        cached = _HEALTH_SURFACE_CACHE.get("overview")
        if cached is not None:
            payload, stale = cached
            if stale:
                schedule_health_warmup()
            return JSONResponse(payload)
        legacy = _read_health_overview_cache(allow_stale=True)
        if legacy is not None:
            payload, age_seconds = legacy
            schedule_health_warmup()
            return JSONResponse(
                {
                    **payload,
                    "cache_state": {
                        "stale": True,
                        "refreshing": True,
                        "age_seconds": round(age_seconds, 1),
                    },
                }
            )
        schedule_health_warmup()
        return JSONResponse(
            {
                "generated_ts": "",
                "issues": [],
                "secrets": {"items": []},
                "content": {"bundles": []},
                "cache_state": {
                    "stale": False,
                    "refreshing": True,
                    "age_seconds": 0,
                },
            },
            status_code=202,
        )
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=500)


@router.get("/api/health/transport", response_class=JSONResponse)
async def health_transport_api(user=Depends(require_permissions("health:view"))) -> JSONResponse:
    try:
        return JSONResponse(
            await _HEALTH_SURFACE_CACHE.get_or_refresh(
                "transport",
                _build_transport_payload,
            )
        )
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=500)


@router.get("/api/health/storage", response_class=JSONResponse)
async def health_storage_api(user=Depends(require_permissions("health:view"))) -> JSONResponse:
    try:
        return JSONResponse(
            await _HEALTH_SURFACE_CACHE.get_or_refresh(
                "storage",
                _build_storage_payload,
            )
        )
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=500)


@router.get("/api/health/storage-ha", response_class=JSONResponse)
async def health_storage_ha_api(user=Depends(require_permissions("health:view"))) -> JSONResponse:
    try:
        payload = await _HEALTH_SURFACE_CACHE.get_or_refresh(
            "storage",
            _build_storage_payload,
        )
        return JSONResponse(
            {
                "generated_ts": str(payload.get("generated_ts") or ""),
                "storage_ha": dict(payload.get("storage_ha") or {}),
            }
        )
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=500)


@router.get("/api/health/hosts/runtime", response_class=JSONResponse)
async def health_host_runtime_api(
    hours: int = Query(24, ge=1, le=168),
    limit: int = Query(50, ge=1, le=200),
    user=Depends(require_permissions("health:view")),
) -> JSONResponse:
    try:
        cache_key = f"{hours}:{limit}"
        cached = _read_host_runtime_cache(cache_key)
        if cached is not None:
            updated_ts, payload = cached
            if time.time() - updated_ts > HOST_RUNTIME_CACHE_TTL_SEC:
                _schedule_host_runtime_refresh(cache_key, hours, limit)
            return JSONResponse(payload)
        payload = await run_in_threadpool(
            _refresh_host_runtime,
            cache_key,
            hours,
            limit,
        )
        return JSONResponse(payload)
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=500)


@router.get("/api/health/backups", response_class=JSONResponse)
async def health_backups_api(user=Depends(require_permissions("health:view"))) -> JSONResponse:
    try:
        return JSONResponse(
            await _HEALTH_SURFACE_CACHE.get_or_refresh(
                "backups",
                _build_backup_payload,
            )
        )
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=500)


@router.get("/api/health/certification", response_class=JSONResponse)
async def health_certification_api(user=Depends(require_permissions("health:view"))) -> JSONResponse:
    try:
        return JSONResponse(
            await run_in_threadpool(certification_runtime_status)
        )
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=500)
