from __future__ import annotations

from fastapi import APIRouter, Body, Depends, Query
from fastapi.responses import JSONResponse

from ..control_plane_response_ops import (
    approve_response_execution,
    delete_response_action,
    execute_response_action,
    get_response_analytics,
    list_response_ledger,
    list_response_dlq,
    list_response_executions,
    reject_response_execution,
    replay_response_dlq,
    retry_response_execution,
    save_response_action,
)
from ..control_plane_health import get_response_overview
from ..security import require_permissions

router = APIRouter()


@router.get("/api/response/actions", response_class=JSONResponse)
async def response_actions_api(user=Depends(require_permissions("response:view"))) -> JSONResponse:
    overview = get_response_overview()
    return JSONResponse(
        {
            "items": overview["actions"],
            "executions": overview["executions"],
            "approval_queue": overview.get("approval_queue") or [],
            "policy_packs": overview.get("policy_packs") or [],
            "ledger": overview.get("ledger") or [],
            "metrics": overview["metrics"],
            "breakdowns": overview["breakdowns"],
        }
    )


@router.post("/api/response/actions", response_class=JSONResponse)
async def save_response_action_api(
    payload: dict = Body(default={}),
    user=Depends(require_permissions("response:run")),
) -> JSONResponse:
    try:
        prepared_payload = dict(payload or {})
        prepared_payload["_audit_actor"] = str(getattr(user, "username", "web") or "web")
        return JSONResponse(save_response_action(prepared_payload))
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.post("/api/response/actions/{action_id}/execute", response_class=JSONResponse)
async def execute_response_action_api(
    action_id: str,
    payload: dict = Body(default={}),
    user=Depends(require_permissions("response:run")),
) -> JSONResponse:
    try:
        principal_context = {
            "actor": str(getattr(user, "username", "web") or "web"),
            "role": str(getattr(user, "role", "") or ""),
            "principal_type": str(getattr(user, "principal_type", "user") or "user"),
            "auth_mechanism": str(getattr(user, "auth_mechanism", "") or ""),
            "break_glass": bool(getattr(user, "break_glass", False)),
        }
        return JSONResponse(
            execute_response_action(
                action_id,
                actor=str(getattr(user, "username", "web") or "web"),
                payload=dict(payload.get("payload") or payload),
                dry_run=bool(payload.get("dry_run", True)),
                principal_context=principal_context,
            )
        )
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.delete("/api/response/actions/{action_id}", response_class=JSONResponse)
async def delete_response_action_api(
    action_id: str,
    user=Depends(require_permissions("response:run")),
) -> JSONResponse:
    try:
        return JSONResponse(delete_response_action(action_id, actor=str(getattr(user, "username", "web") or "web")))
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.post("/api/response/executions/{execution_id}/approve", response_class=JSONResponse)
async def approve_response_execution_api(
    execution_id: str,
    payload: dict = Body(default={}),
    user=Depends(require_permissions("response:run")),
) -> JSONResponse:
    try:
        return JSONResponse(
            approve_response_execution(
                execution_id,
                actor=str(getattr(user, "username", "web") or "web"),
                note=str(payload.get("note") or ""),
                actor_role=str(getattr(user, "role", "") or ""),
                principal_type=str(getattr(user, "principal_type", "user") or "user"),
                break_glass=bool(getattr(user, "break_glass", False)),
            )
        )
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.post("/api/response/executions/{execution_id}/reject", response_class=JSONResponse)
async def reject_response_execution_api(
    execution_id: str,
    payload: dict = Body(default={}),
    user=Depends(require_permissions("response:run")),
) -> JSONResponse:
    try:
        return JSONResponse(
            reject_response_execution(
                execution_id,
                actor=str(getattr(user, "username", "web") or "web"),
                reason=str(payload.get("reason") or payload.get("note") or ""),
                principal_type=str(getattr(user, "principal_type", "user") or "user"),
                break_glass=bool(getattr(user, "break_glass", False)),
            )
        )
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.get("/api/response/executions", response_class=JSONResponse)
async def response_executions_api(
    action_id: str = Query(""),
    limit: int = Query(100, ge=1, le=500),
    user=Depends(require_permissions("response:view")),
) -> JSONResponse:
    return JSONResponse({"items": list_response_executions(action_id=action_id, limit=limit)})


@router.post("/api/response/executions/{execution_id}/retry", response_class=JSONResponse)
async def retry_response_execution_api(
    execution_id: str,
    user=Depends(require_permissions("response:run")),
) -> JSONResponse:
    try:
        return JSONResponse(retry_response_execution(execution_id, actor=str(getattr(user, "username", "web") or "web")))
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.get("/api/response/dlq", response_class=JSONResponse)
async def response_dlq_api(
    limit: int = Query(100, ge=1, le=500),
    user=Depends(require_permissions("response:view")),
) -> JSONResponse:
    return JSONResponse({"items": list_response_dlq(limit=limit)})


@router.get("/api/response/analytics", response_class=JSONResponse)
async def response_analytics_api(
    limit: int = Query(200, ge=1, le=500),
    user=Depends(require_permissions("response:view")),
) -> JSONResponse:
    return JSONResponse(get_response_analytics(limit=limit))


@router.get("/api/response/ledger", response_class=JSONResponse)
async def response_ledger_api(
    limit: int = Query(200, ge=1, le=500),
    user=Depends(require_permissions("response:view")),
) -> JSONResponse:
    return JSONResponse({"items": list_response_ledger(limit=limit)})


@router.post("/api/response/dlq/{dlq_id}/replay", response_class=JSONResponse)
async def replay_response_dlq_api(
    dlq_id: str,
    user=Depends(require_permissions("response:run")),
) -> JSONResponse:
    try:
        return JSONResponse(replay_response_dlq(dlq_id, actor=str(getattr(user, "username", "web") or "web")))
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)
