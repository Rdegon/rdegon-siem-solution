
from __future__ import annotations

import logging
import uuid

from fastapi import APIRouter, Body, Depends, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from starlette.concurrency import run_in_threadpool

from .auth import canonical_ui_redirect_path, get_current_user
from ..security import require_permissions
from ..deps import EVENT_ROW_LIMIT_DEFAULT, execute_event_facets_query, execute_event_query
from ..templates import templates
from ..ui_text import ui_context

router = APIRouter()
logger = logging.getLogger("siem_web.events")


def _safe_error(label: str, exc: Exception) -> dict[str, str]:
    debug_id = uuid.uuid4().hex[:10]
    logger.exception("%s failed [%s]", label, debug_id)
    return {
        "error": f"{label} failed. Debug id: {debug_id}",
        "debug_id": debug_id,
    }


@router.get('/events', response_class=HTMLResponse)
async def events_page(
    request: Request,
    q: str = Query('', description='SQL query or expression for events_view'),
    window: str = Query('24h'),
    from_ts: str = Query(''),
    to_ts: str = Query(''),
    storage: str = Query('hot'),
    auto_refresh: str = Query('off'),
    limit: int = Query(EVENT_ROW_LIMIT_DEFAULT, ge=25, le=1000),
    user=Depends(get_current_user),
) -> HTMLResponse:
    target = canonical_ui_redirect_path(f"{request.url.path}{f'?{request.url.query}' if request.url.query else ''}")
    return RedirectResponse(url=target, status_code=307)


@router.post('/api/events/query', response_class=JSONResponse)
async def events_query_api(payload: dict = Body(default={}), user=Depends(require_permissions('events:query'))) -> JSONResponse:
    query_text = str(payload.get('query', '') or '')
    window = str(payload.get('window', '24h') or '24h')
    from_ts = str(payload.get('from_ts', '') or '')
    to_ts = str(payload.get('to_ts', '') or '')
    storage = str(payload.get('storage', 'hot') or 'hot')
    limit = int(payload.get('limit', EVENT_ROW_LIMIT_DEFAULT) or EVENT_ROW_LIMIT_DEFAULT)
    offset = int(payload.get('offset', 0) or 0)
    include_facets = bool(payload.get('include_facets') or False)
    include_count = bool(payload.get('include_count') or False)
    try:
        return JSONResponse(
            await run_in_threadpool(
                execute_event_query,
                query_text=query_text,
                window=window,
                from_ts=from_ts,
                to_ts=to_ts,
                limit=limit,
                storage=storage,
                offset=offset,
                include_facets=include_facets,
                include_count=include_count,
            )
        )
    except Exception as exc:  # noqa: BLE001
        return JSONResponse(_safe_error("Event query", exc), status_code=400)


@router.post('/api/events/facets', response_class=JSONResponse)
async def events_facets_api(payload: dict = Body(default={}), user=Depends(require_permissions('events:query'))) -> JSONResponse:
    query_text = str(payload.get('query', '') or '')
    window = str(payload.get('window', '24h') or '24h')
    from_ts = str(payload.get('from_ts', '') or '')
    to_ts = str(payload.get('to_ts', '') or '')
    storage = str(payload.get('storage', 'hot') or 'hot')
    try:
        return JSONResponse(
            await run_in_threadpool(
                execute_event_facets_query,
                query_text=query_text,
                window=window,
                from_ts=from_ts,
                to_ts=to_ts,
                storage=storage,
            )
        )
    except Exception as exc:  # noqa: BLE001
        return JSONResponse(_safe_error("Event facets", exc), status_code=400)
