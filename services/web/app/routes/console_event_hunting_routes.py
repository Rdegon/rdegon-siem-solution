from __future__ import annotations

import logging
import uuid

from fastapi import APIRouter, Body, Depends, Header, Query
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from .auth import get_current_user
from ..event_hunting_runtime import (
    HuntingNotFoundError,
    HuntingValidationError,
    available_event_sources,
    delete_saved_search,
    event_detail,
    list_saved_searches,
    query_events,
    query_facets,
    save_saved_search,
)
from ..security import require_permissions
from ..tenant_scope_runtime import validate_tenant_scope_header


router = APIRouter()
logger = logging.getLogger("siem_web.event_hunting")


def _tenant(value: str) -> str:
    return validate_tenant_scope_header(value)[0]


def _owner(user) -> str:
    return str(getattr(user, "username", "web") or "web")


def _failure(label: str, exc: Exception, *, status_code: int = 400) -> JSONResponse:
    debug_id = uuid.uuid4().hex[:10]
    logger.exception("%s failed [%s]", label, debug_id)
    return JSONResponse(
        {"error": str(exc), "code": type(exc).__name__, "debug_id": debug_id},
        status_code=status_code,
    )


@router.get("/api/hunting/capabilities", response_class=JSONResponse)
async def hunting_capabilities_api(user=Depends(require_permissions("events:query"))) -> JSONResponse:
    try:
        return JSONResponse(jsonable_encoder(await run_in_threadpool(available_event_sources)))
    except Exception as exc:  # noqa: BLE001
        return _failure("Hunting capabilities", exc, status_code=503)


@router.post("/api/hunting/events/query", response_class=JSONResponse)
async def hunting_query_api(
    payload: dict = Body(default={}),
    x_tenant_scope: str = Header(default="main", alias="X-SIEM-Tenant-Scope"),
    user=Depends(require_permissions("events:query")),
) -> JSONResponse:
    try:
        result = await run_in_threadpool(query_events, dict(payload or {}), tenant_id=_tenant(x_tenant_scope))
        return JSONResponse(jsonable_encoder(result))
    except HuntingValidationError as exc:
        return _failure("Event hunting query", exc)
    except Exception as exc:  # noqa: BLE001
        return _failure("Event hunting query", exc, status_code=503)


@router.post("/api/hunting/events/facets", response_class=JSONResponse)
async def hunting_facets_api(
    payload: dict = Body(default={}),
    x_tenant_scope: str = Header(default="main", alias="X-SIEM-Tenant-Scope"),
    user=Depends(require_permissions("events:query")),
) -> JSONResponse:
    try:
        result = await run_in_threadpool(query_facets, dict(payload or {}), tenant_id=_tenant(x_tenant_scope))
        return JSONResponse(jsonable_encoder(result))
    except HuntingValidationError as exc:
        return _failure("Event hunting facets", exc)
    except Exception as exc:  # noqa: BLE001
        return _failure("Event hunting facets", exc, status_code=503)


@router.get("/api/hunting/events/{event_id}", response_class=JSONResponse)
async def hunting_event_detail_api(
    event_id: str,
    event_ts: str = Query(...),
    source: str = Query(default="hot"),
    x_tenant_scope: str = Header(default="main", alias="X-SIEM-Tenant-Scope"),
    user=Depends(require_permissions("events:view")),
) -> JSONResponse:
    try:
        result = await run_in_threadpool(
            event_detail,
            event_id,
            event_ts=event_ts,
            source=source,
            tenant_id=_tenant(x_tenant_scope),
        )
        return JSONResponse(jsonable_encoder(result))
    except HuntingNotFoundError as exc:
        return _failure("Event detail", exc, status_code=404)
    except HuntingValidationError as exc:
        return _failure("Event detail", exc)
    except Exception as exc:  # noqa: BLE001
        return _failure("Event detail", exc, status_code=503)


@router.get("/api/hunting/saved-searches", response_class=JSONResponse)
async def hunting_saved_searches_api(
    x_tenant_scope: str = Header(default="main", alias="X-SIEM-Tenant-Scope"),
    user=Depends(require_permissions("events:query")),
) -> JSONResponse:
    try:
        result = await run_in_threadpool(list_saved_searches, tenant_id=_tenant(x_tenant_scope), owner=_owner(user))
        return JSONResponse(jsonable_encoder(result))
    except HuntingValidationError as exc:
        return _failure("Saved searches", exc)
    except Exception as exc:  # noqa: BLE001
        return _failure("Saved searches", exc, status_code=503)


@router.post("/api/hunting/saved-searches", response_class=JSONResponse)
async def hunting_save_search_api(
    payload: dict = Body(default={}),
    x_tenant_scope: str = Header(default="main", alias="X-SIEM-Tenant-Scope"),
    user=Depends(require_permissions("search:write")),
) -> JSONResponse:
    try:
        result = await run_in_threadpool(
            save_saved_search,
            dict(payload or {}),
            tenant_id=_tenant(x_tenant_scope),
            owner=_owner(user),
        )
        return JSONResponse(jsonable_encoder(result))
    except HuntingValidationError as exc:
        status_code = 409 if "revision conflict" in str(exc).lower() else 400
        return _failure("Save search", exc, status_code=status_code)
    except Exception as exc:  # noqa: BLE001
        return _failure("Save search", exc, status_code=503)


@router.delete("/api/hunting/saved-searches/{search_id}", response_class=JSONResponse)
async def hunting_delete_search_api(
    search_id: str,
    x_tenant_scope: str = Header(default="main", alias="X-SIEM-Tenant-Scope"),
    user=Depends(require_permissions("search:write")),
) -> JSONResponse:
    try:
        result = await run_in_threadpool(
            delete_saved_search,
            search_id,
            tenant_id=_tenant(x_tenant_scope),
            owner=_owner(user),
        )
        return JSONResponse(jsonable_encoder(result))
    except HuntingNotFoundError as exc:
        return _failure("Delete search", exc, status_code=404)
    except HuntingValidationError as exc:
        return _failure("Delete search", exc)
    except Exception as exc:  # noqa: BLE001
        return _failure("Delete search", exc, status_code=503)
