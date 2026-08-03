from __future__ import annotations

from fastapi import APIRouter, BackgroundTasks, Body, Depends, Query, Request
from fastapi.responses import JSONResponse

from ..retroscan_runtime import (
    RetroscanCommitUnavailableError,
    RetroscanConflictError,
    RetroscanNotFoundError,
    RetroscanValidationError,
    cancel_retroscan,
    create_retroscan,
    get_retroscan,
    list_retroscans,
    retroscan_capabilities,
    run_retroscan_task,
)
from ..security import require_permissions


router = APIRouter()


def _actor(user: object) -> str:
    return str(getattr(user, "username", "web") or "web")


def _error(exc: Exception, *, status_code: int) -> JSONResponse:
    return JSONResponse(
        {
            "error": str(exc),
            "code": str(getattr(exc, "code", "retroscan_error")),
            "capabilities": retroscan_capabilities(),
        },
        status_code=status_code,
    )


@router.get("/api/retroscan/capabilities", response_class=JSONResponse)
async def retroscan_capabilities_api(
    user=Depends(require_permissions("health:view")),
) -> JSONResponse:
    return JSONResponse(retroscan_capabilities())


@router.get("/api/retroscan/runs", response_class=JSONResponse)
async def retroscan_runs_api(
    limit: int = Query(100, ge=1, le=500),
    status: str = Query(""),
    user=Depends(require_permissions("health:view")),
) -> JSONResponse:
    return JSONResponse(
        {
            "items": list_retroscans(limit=limit, status=status),
            "capabilities": retroscan_capabilities(),
        }
    )


@router.get("/api/retroscan/runs/{run_id}", response_class=JSONResponse)
async def retroscan_run_detail_api(
    run_id: str,
    user=Depends(require_permissions("health:view")),
) -> JSONResponse:
    try:
        return JSONResponse({"item": get_retroscan(run_id), "capabilities": retroscan_capabilities()})
    except RetroscanNotFoundError as exc:
        return _error(exc, status_code=404)


@router.post("/api/retroscan/runs", response_class=JSONResponse)
async def create_retroscan_api(
    request: Request,
    background_tasks: BackgroundTasks,
    payload: dict = Body(default={}),
    user=Depends(require_permissions("response:run")),
) -> JSONResponse:
    try:
        item, created = create_retroscan(
            dict(payload or {}),
            actor=_actor(user),
            idempotency_key=str(request.headers.get("idempotency-key") or ""),
        )
        if created:
            background_tasks.add_task(run_retroscan_task, item["id"])
        return JSONResponse(
            {
                "item": item,
                "created": created,
                "idempotent_replay": not created,
                "capabilities": retroscan_capabilities(),
            },
            status_code=202 if created else 200,
        )
    except RetroscanCommitUnavailableError as exc:
        return _error(exc, status_code=409)
    except RetroscanConflictError as exc:
        return _error(exc, status_code=409)
    except RetroscanValidationError as exc:
        return _error(exc, status_code=400)


@router.post("/api/retroscan/runs/{run_id}/cancel", response_class=JSONResponse)
async def cancel_retroscan_api(
    run_id: str,
    user=Depends(require_permissions("response:run")),
) -> JSONResponse:
    try:
        return JSONResponse({"item": cancel_retroscan(run_id, actor=_actor(user)), "capabilities": retroscan_capabilities()})
    except RetroscanNotFoundError as exc:
        return _error(exc, status_code=404)
