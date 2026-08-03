from __future__ import annotations

import logging
import uuid

from fastapi import APIRouter, Body, Depends, Query
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from ..security import require_permissions
from ..unified_rule_runtime import (
    RuleConflictError,
    RuleInventoryError,
    RuleNotFoundError,
    get_unified_rule,
    list_unified_rules,
    publish_unified_rule,
    set_unified_rule_enabled,
)


router = APIRouter()
logger = logging.getLogger("siem_web.unified_rules")


def _actor(user) -> str:
    return str(getattr(user, "username", "web") or "web")


def _failure(label: str, exc: Exception, status_code: int) -> JSONResponse:
    debug_id = uuid.uuid4().hex[:10]
    logger.exception("%s failed [%s]", label, debug_id)
    return JSONResponse({"error": str(exc), "code": type(exc).__name__, "debug_id": debug_id}, status_code=status_code)


@router.get("/api/rules/unified", response_class=JSONResponse)
async def unified_rules_api(
    search: str = Query(default=""),
    status: str = Query(default=""),
    engine: str = Query(default=""),
    pack_id: str = Query(default=""),
    limit: int = Query(default=1000, ge=1, le=5000),
    offset: int = Query(default=0, ge=0),
    noise_days: int = Query(default=30, ge=1, le=90),
    user=Depends(require_permissions("resources:view")),
) -> JSONResponse:
    try:
        result = await run_in_threadpool(
            list_unified_rules,
            search=search,
            status=status,
            engine=engine,
            pack_id=pack_id,
            limit=limit,
            offset=offset,
            noise_days=noise_days,
        )
        return JSONResponse(jsonable_encoder(result))
    except Exception as exc:  # noqa: BLE001
        return _failure("Unified rule inventory", exc, 503)


@router.get("/api/rules/unified/{rule_identity}", response_class=JSONResponse)
async def unified_rule_detail_api(
    rule_identity: str,
    user=Depends(require_permissions("resources:view")),
) -> JSONResponse:
    try:
        return JSONResponse(jsonable_encoder(await run_in_threadpool(get_unified_rule, rule_identity)))
    except RuleNotFoundError as exc:
        return _failure("Unified rule detail", exc, 404)
    except RuleInventoryError as exc:
        return _failure("Unified rule detail", exc, 400)
    except Exception as exc:  # noqa: BLE001
        return _failure("Unified rule detail", exc, 503)


@router.post("/api/rules/unified/{rule_identity}/publish", response_class=JSONResponse)
async def publish_unified_rule_api(
    rule_identity: str,
    user=Depends(require_permissions("rules:write")),
) -> JSONResponse:
    try:
        result = await run_in_threadpool(publish_unified_rule, rule_identity, actor=_actor(user))
        return JSONResponse(jsonable_encoder(result))
    except RuleNotFoundError as exc:
        return _failure("Publish unified rule", exc, 404)
    except RuleConflictError as exc:
        return _failure("Publish unified rule", exc, 409)
    except RuleInventoryError as exc:
        return _failure("Publish unified rule", exc, 400)
    except Exception as exc:  # noqa: BLE001
        return _failure("Publish unified rule", exc, 503)


@router.post("/api/rules/unified/{rule_identity}/enabled", response_class=JSONResponse)
async def set_unified_rule_enabled_api(
    rule_identity: str,
    payload: dict = Body(default={}),
    user=Depends(require_permissions("rules:write")),
) -> JSONResponse:
    try:
        if not isinstance(payload.get("enabled"), bool):
            raise RuleInventoryError("enabled must be a boolean")
        result = await run_in_threadpool(
            set_unified_rule_enabled,
            rule_identity,
            enabled=payload["enabled"],
            actor=_actor(user),
            reason=str(payload.get("reason") or ""),
            replacement_identity=str(payload.get("replacement_identity") or ""),
        )
        return JSONResponse(jsonable_encoder(result))
    except RuleNotFoundError as exc:
        return _failure("Toggle unified rule", exc, 404)
    except RuleConflictError as exc:
        return _failure("Toggle unified rule", exc, 409)
    except RuleInventoryError as exc:
        return _failure("Toggle unified rule", exc, 400)
    except Exception as exc:  # noqa: BLE001
        return _failure("Toggle unified rule", exc, 503)
