from __future__ import annotations

import asyncio

from fastapi import APIRouter, Body, Depends
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from ..control_plane_source_policy_ops import (
    delete_source_policy,
    evaluate_source_policies,
    list_source_policies,
    save_source_policy,
)
from ..query.sources import fetch_source_inventory
from ..security import require_permissions


router = APIRouter()


def _actor(user: object) -> str:
    return str(getattr(user, "username", "web") or "web")


@router.get("/api/sources/policies", response_class=JSONResponse)
async def source_policies_api(
    user=Depends(require_permissions("assets:view")),
) -> JSONResponse:
    try:
        policies = list_source_policies()
        windows = sorted({int(item.get("window_hours") or 24) for item in policies})
        inventories = await asyncio.gather(
            *[
                run_in_threadpool(fetch_source_inventory, limit=1000, hours=hours)
                for hours in windows
            ]
        )
        inventory_by_window = {
            hours: [dict(item) for item in sources]
            for hours, sources in zip(windows, inventories, strict=True)
        }
        evaluated: list[dict] = []
        for policy in policies:
            hours = int(policy.get("window_hours") or 24)
            evaluated.extend(
                evaluate_source_policies(
                    inventory_by_window.get(hours, []),
                    policies=[policy],
                )
            )
        return JSONResponse({"items": evaluated})
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.post("/api/sources/policies", response_class=JSONResponse)
async def save_source_policy_api(
    payload: dict = Body(default={}),
    user=Depends(require_permissions("resources:write")),
) -> JSONResponse:
    try:
        return JSONResponse(save_source_policy(payload, actor=_actor(user)))
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.delete("/api/sources/policies/{policy_id}", response_class=JSONResponse)
async def delete_source_policy_api(
    policy_id: str,
    user=Depends(require_permissions("resources:write")),
) -> JSONResponse:
    try:
        return JSONResponse(delete_source_policy(policy_id, actor=_actor(user)))
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)
