from __future__ import annotations

import json
import os
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Lock

from fastapi import APIRouter, Depends, Query
from fastapi.responses import JSONResponse

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
from ..control_plane_health import build_health_overview

router = APIRouter()

HEALTH_OVERVIEW_CACHE_TTL_SEC = int(os.getenv("SIEM_HEALTH_OVERVIEW_CACHE_TTL_SEC", "300") or "300")
HEALTH_OVERVIEW_CACHE_FILE = Path(
    os.getenv("SIEM_HEALTH_OVERVIEW_CACHE_FILE", "/opt/siem/runtime-docs/health_overview_cache.json")
)
_HEALTH_OVERVIEW_CACHE_LOCK = Lock()


def _read_health_overview_cache() -> dict | None:
    if HEALTH_OVERVIEW_CACHE_TTL_SEC <= 0:
        return None
    try:
        if not HEALTH_OVERVIEW_CACHE_FILE.exists():
            return None
        if time.time() - HEALTH_OVERVIEW_CACHE_FILE.stat().st_mtime > HEALTH_OVERVIEW_CACHE_TTL_SEC:
            return None
        payload = json.loads(HEALTH_OVERVIEW_CACHE_FILE.read_text(encoding="utf-8"))
        return payload if isinstance(payload, dict) else None
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


@router.get("/api/health/overview", response_class=JSONResponse)
async def health_overview_api(user=Depends(require_permissions("health:view"))) -> JSONResponse:
    try:
        cached = _read_health_overview_cache()
        if cached is not None:
            return JSONResponse(cached)

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
            payload.setdefault("issues", []).append(f"Ingest runtime unavailable: {ingest_runtime_error}")
        with _HEALTH_OVERVIEW_CACHE_LOCK:
            _write_health_overview_cache(payload)
        return JSONResponse(payload)
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=500)


@router.get("/api/health/transport", response_class=JSONResponse)
async def health_transport_api(user=Depends(require_permissions("health:view"))) -> JSONResponse:
    try:
        ingest_transport = get_ingest_transport_health()
        platform_status = fetch_platform_status()
        if not platform_status.get("transport_shadow_status"):
            platform_status = {**platform_status, "transport_shadow_status": fetch_transport_shadow_status()}
        return JSONResponse(build_transport_health_payload(ingest_transport=ingest_transport, platform_status=platform_status))
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=500)


@router.get("/api/health/storage", response_class=JSONResponse)
async def health_storage_api(user=Depends(require_permissions("health:view"))) -> JSONResponse:
    try:
        platform_status = fetch_platform_status()
        return JSONResponse(
            build_storage_health_payload(
                platform_status,
                control_plane_status=control_plane_storage_status(),
                content_status=content_storage_status(),
            )
        )
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=500)


@router.get("/api/health/storage-ha", response_class=JSONResponse)
async def health_storage_ha_api(user=Depends(require_permissions("health:view"))) -> JSONResponse:
    try:
        platform_status = fetch_platform_status()
        payload = build_storage_health_payload(
            platform_status,
            control_plane_status=control_plane_storage_status(),
            content_status=content_storage_status(),
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
        return JSONResponse(fetch_host_runtime_overview(hours=hours, limit=limit))
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=500)


@router.get("/api/health/backups", response_class=JSONResponse)
async def health_backups_api(user=Depends(require_permissions("health:view"))) -> JSONResponse:
    try:
        platform_status = fetch_platform_status()
        storage_status = control_plane_storage_status()
        content_status = content_storage_status()
        return JSONResponse(
            build_backup_health_payload(
                control_plane_status=storage_status,
                content_status=content_status,
                platform_status=platform_status,
            )
        )
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=500)


@router.get("/api/health/certification", response_class=JSONResponse)
async def health_certification_api(user=Depends(require_permissions("health:view"))) -> JSONResponse:
    try:
        return JSONResponse(certification_runtime_status())
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=500)
