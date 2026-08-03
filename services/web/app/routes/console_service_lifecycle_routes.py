from __future__ import annotations

from fastapi import APIRouter, Body, Depends, Header, Query
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from ..security import require_permissions
from ..service_lifecycle_runtime import (
    SERVICE_ACTIONS,
    ServiceLifecycleError,
    execute_service_action,
    get_service_instance,
    list_service_instances,
)

router = APIRouter()


@router.get("/api/service-lifecycle", response_class=JSONResponse)
async def service_lifecycle_registry_api(
    refresh_live: bool = Query(False),
    user=Depends(require_permissions("health:view")),
) -> JSONResponse:
    try:
        payload = await run_in_threadpool(list_service_instances, refresh_live=refresh_live)
        return JSONResponse(payload)
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=503)


@router.get("/api/service-lifecycle/{instance_id}", response_class=JSONResponse)
async def service_lifecycle_detail_api(
    instance_id: str,
    refresh_live: bool = Query(True),
    user=Depends(require_permissions("health:view")),
) -> JSONResponse:
    try:
        payload = await run_in_threadpool(get_service_instance, instance_id, refresh_live=refresh_live)
        return JSONResponse(payload)
    except ServiceLifecycleError as exc:
        return JSONResponse({"error": str(exc), "code": exc.code}, status_code=exc.status_code)
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=503)


@router.post("/api/service-lifecycle/{instance_id}/actions/{action}", response_class=JSONResponse)
async def service_lifecycle_action_api(
    instance_id: str,
    action: str,
    payload: dict = Body(default={}),
    idempotency_header: str = Header("", alias="Idempotency-Key"),
    user=Depends(require_permissions("response:run")),
) -> JSONResponse:
    if action not in SERVICE_ACTIONS:
        return JSONResponse({"error": "Unsupported lifecycle action", "code": "unsupported_action"}, status_code=400)
    idempotency_key = str(idempotency_header or payload.get("idempotency_key") or "").strip()
    try:
        result = await run_in_threadpool(
            execute_service_action,
            instance_id,
            action,
            actor=str(getattr(user, "username", "web") or "web"),
            idempotency_key=idempotency_key,
        )
        return JSONResponse(result)
    except ServiceLifecycleError as exc:
        return JSONResponse({"error": str(exc), "code": exc.code}, status_code=exc.status_code)
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc), "code": "internal_error"}, status_code=500)
