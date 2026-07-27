from __future__ import annotations

import logging
import uuid

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from ..security import require_permissions
from ..security_services_runtime import get_security_service, list_security_services


router = APIRouter()
logger = logging.getLogger("siem_web.security_services")


def _error_payload(label: str, exc: Exception) -> dict[str, str]:
    debug_id = uuid.uuid4().hex[:10]
    logger.exception("%s failed [%s]", label, debug_id)
    return {"error": f"{label} failed. Debug id: {debug_id}", "debug_id": debug_id}


@router.get("/api/security-services", response_class=JSONResponse)
async def security_services_api(
    user=Depends(require_permissions("health:view")),
) -> JSONResponse:
    try:
        return JSONResponse(await run_in_threadpool(list_security_services))
    except Exception as exc:  # noqa: BLE001
        return JSONResponse(_error_payload("Security services", exc), status_code=503)


@router.get("/api/security-services/{service_id}", response_class=JSONResponse)
async def security_service_detail_api(
    service_id: str,
    user=Depends(require_permissions("health:view")),
) -> JSONResponse:
    try:
        return JSONResponse(await run_in_threadpool(get_security_service, service_id))
    except KeyError:
        return JSONResponse({"error": f"Unknown security service: {service_id}"}, status_code=404)
    except Exception as exc:  # noqa: BLE001
        return JSONResponse(_error_payload("Security service detail", exc), status_code=503)
