from __future__ import annotations

import os

from fastapi import APIRouter, Body, Depends, Query, Request
from fastapi.responses import JSONResponse

from ..config import CONFIG
from ..content_runtime import content_storage_status
from ..control_plane_case_ops import (
    append_case_comment,
    append_case_task,
    attach_case_evidence,
    get_case,
    get_entities_overview,
    get_entity,
    list_cases,
    list_entities,
    promote_entity_to_case,
    record_risk_signal,
    save_case,
)
from ..control_plane_connector_ops import (
    delete_connector_definition,
    get_connector_definition,
    get_connectors_overview,
    record_connector_run,
    run_connector_definition,
    save_connector_definition,
)
from ..control_plane_content_ops import (
    list_content_bundles,
    list_saved_searches,
    promote_content_bundle,
    save_content_bundle,
    save_saved_search,
)
from ..control_plane_governance_ops import build_compliance_evidence_pack, build_enterprise_release_gates
from ..enterprise_control_plane import control_plane_storage_status
from ..deps import migrate_content_store
from ..security import require_permissions

router = APIRouter()


@router.get("/api/connectors", response_class=JSONResponse)
async def connectors_api(user=Depends(require_permissions("connectors:view"))) -> JSONResponse:
    return JSONResponse({"items": get_connectors_overview()["items"]})


@router.get("/api/connectors/overview", response_class=JSONResponse)
async def connectors_overview_api(user=Depends(require_permissions("connectors:view"))) -> JSONResponse:
    return JSONResponse(get_connectors_overview())


@router.get("/api/connectors/{connector_id}", response_class=JSONResponse)
async def connector_detail_api(connector_id: str, user=Depends(require_permissions("connectors:view"))) -> JSONResponse:
    item = get_connector_definition(connector_id)
    if item is None:
        return JSONResponse({"error": f"Connector not found: {connector_id}"}, status_code=404)
    return JSONResponse({"item": item})


@router.post("/api/connectors", response_class=JSONResponse)
async def save_connector_api(
    payload: dict = Body(default={}),
    user=Depends(require_permissions("connectors:write")),
) -> JSONResponse:
    try:
        prepared_payload = dict(payload or {})
        prepared_payload["_audit_actor"] = str(getattr(user, "username", "web") or "web")
        return JSONResponse(save_connector_definition(prepared_payload))
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.post("/api/connectors/{connector_id}/run", response_class=JSONResponse)
async def run_connector_api(
    connector_id: str,
    payload: dict = Body(default={}),
    user=Depends(require_permissions("connectors:run")),
) -> JSONResponse:
    try:
        return JSONResponse(
            run_connector_definition(
                connector_id,
                actor=str(getattr(user, "username", "web") or "web"),
                trigger=str(payload.get("trigger") or "manual"),
                dry_run=bool(payload.get("dry_run", True)),
                payload=dict(payload),
            )
        )
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.post("/api/connectors/{connector_id}/webhook", response_class=JSONResponse)
async def connector_webhook_preview_api(
    connector_id: str,
    request: Request,
    payload: dict | list = Body(default={}),
) -> JSONResponse:
    expected_secret = str(os.getenv("SIEM_WEBHOOK_SHARED_SECRET", "") or CONFIG.jwt_secret or "").strip()
    shared_secret = str(request.headers.get("x-rdegon-webhook-secret") or "").strip()
    if expected_secret and shared_secret != expected_secret:
        return JSONResponse({"error": "Invalid webhook secret"}, status_code=403)
    events = payload if isinstance(payload, list) else [payload]
    preview = events[:3]
    try:
        result = record_connector_run(
            connector_id,
            status="success",
            actor="webhook",
            trigger="webhook",
            dry_run=False,
            message=f"Accepted {len(events)} webhook event(s)",
            stats={"accepted_events": len(events)},
            payload_sample=preview,
        )
        return JSONResponse({"accepted_events": len(events), "preview": preview, **result})
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.get("/api/control-plane/storage", response_class=JSONResponse)
async def control_plane_storage_api(user=Depends(require_permissions("health:view"))) -> JSONResponse:
    return JSONResponse(control_plane_storage_status())


@router.get("/api/content/storage", response_class=JSONResponse)
async def content_storage_api(user=Depends(require_permissions("health:view"))) -> JSONResponse:
    try:
        status = content_storage_status()
        requested_backend = str(status.get("requested_backend") or "")
        if requested_backend == "mongo" and str(status.get("backend") or "") == "mongo":
            if str(status.get("migration_status") or "") != "completed" or not any(
                int(value or 0) > 0 for value in dict(status.get("collection_counts") or {}).values()
            ):
                status = migrate_content_store()
        return JSONResponse(status)
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=500)


@router.get("/api/content/bundles", response_class=JSONResponse)
async def content_bundles_api(user=Depends(require_permissions("content:view"))) -> JSONResponse:
    return JSONResponse({"items": list_content_bundles()})


@router.post("/api/content/bundles", response_class=JSONResponse)
async def save_content_bundle_api(
    payload: dict = Body(default={}),
    user=Depends(require_permissions("content:write")),
) -> JSONResponse:
    try:
        prepared_payload = dict(payload or {})
        prepared_payload["_audit_actor"] = str(getattr(user, "username", "web") or "web")
        return JSONResponse(save_content_bundle(prepared_payload))
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.delete("/api/connectors/{connector_id}", response_class=JSONResponse)
async def delete_connector_api(
    connector_id: str,
    user=Depends(require_permissions("connectors:write")),
) -> JSONResponse:
    try:
        return JSONResponse(delete_connector_definition(connector_id, actor=str(getattr(user, "username", "web") or "web")))
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.post("/api/content/bundles/{bundle_id}/promote", response_class=JSONResponse)
async def promote_content_bundle_api(
    bundle_id: str,
    payload: dict = Body(default={}),
    user=Depends(require_permissions("content:write")),
) -> JSONResponse:
    try:
        prepared_payload = dict(payload or {})
        prepared_payload["_audit_actor"] = str(getattr(user, "username", "web") or "web")
        return JSONResponse(promote_content_bundle(bundle_id, prepared_payload))
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.get("/api/enterprise/release-gates", response_class=JSONResponse)
async def enterprise_release_gates_api(user=Depends(require_permissions("health:view"))) -> JSONResponse:
    return JSONResponse(build_enterprise_release_gates())


@router.get("/api/compliance/evidence-pack", response_class=JSONResponse)
async def compliance_evidence_pack_api(user=Depends(require_permissions("health:view"))) -> JSONResponse:
    return JSONResponse(build_compliance_evidence_pack())


@router.get("/api/search/saved", response_class=JSONResponse)
async def saved_searches_api(user=Depends(require_permissions("events:query"))) -> JSONResponse:
    return JSONResponse({"items": list_saved_searches()})


@router.post("/api/search/saved", response_class=JSONResponse)
async def save_saved_search_api(
    payload: dict = Body(default={}),
    user=Depends(require_permissions("search:write")),
) -> JSONResponse:
    try:
        prepared_payload = dict(payload or {})
        prepared_payload["_audit_actor"] = str(getattr(user, "username", "web") or "web")
        return JSONResponse(save_saved_search(prepared_payload))
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.get("/api/cases", response_class=JSONResponse)
async def cases_api(
    status: str = Query(""),
    assignee: str = Query(""),
    q: str = Query(""),
    limit: int = Query(200, ge=1, le=500),
    user=Depends(require_permissions("cases:view")),
) -> JSONResponse:
    return JSONResponse({"items": list_cases(status=status, assignee=assignee, q=q, limit=limit)})


@router.post("/api/cases", response_class=JSONResponse)
async def save_case_api(
    payload: dict = Body(default={}),
    user=Depends(require_permissions("cases:write")),
) -> JSONResponse:
    try:
        return JSONResponse(save_case(payload, actor=str(getattr(user, "username", "web") or "web")))
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.get("/api/cases/{case_id}", response_class=JSONResponse)
async def case_detail_api(case_id: str, user=Depends(require_permissions("cases:view"))) -> JSONResponse:
    item = get_case(case_id)
    if item is None:
        return JSONResponse({"error": f"Case not found: {case_id}"}, status_code=404)
    return JSONResponse({"item": item})


@router.post("/api/cases/{case_id}/comments", response_class=JSONResponse)
async def add_case_comment_api(
    case_id: str,
    payload: dict = Body(default={}),
    user=Depends(require_permissions("cases:write")),
) -> JSONResponse:
    try:
        return JSONResponse(append_case_comment(case_id, body=str(payload.get("body") or ""), author=str(getattr(user, "username", "web") or "web")))
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.post("/api/cases/{case_id}/tasks", response_class=JSONResponse)
async def add_case_task_api(
    case_id: str,
    payload: dict = Body(default={}),
    user=Depends(require_permissions("cases:write")),
) -> JSONResponse:
    try:
        return JSONResponse(
            append_case_task(
                case_id,
                title=str(payload.get("title") or ""),
                assignee=str(payload.get("assignee") or ""),
                due_ts=str(payload.get("due_ts") or ""),
                actor=str(getattr(user, "username", "web") or "web"),
            )
        )
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.post("/api/cases/{case_id}/evidence", response_class=JSONResponse)
async def add_case_evidence_api(
    case_id: str,
    payload: dict = Body(default={}),
    user=Depends(require_permissions("cases:write")),
) -> JSONResponse:
    try:
        return JSONResponse(
            attach_case_evidence(
                case_id,
                title=str(payload.get("title") or ""),
                kind=str(payload.get("kind") or "note"),
                content=str(payload.get("content") or ""),
                actor=str(getattr(user, "username", "web") or "web"),
            )
        )
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.get("/api/entities", response_class=JSONResponse)
async def entities_api(
    entity_type: str = Query(""),
    q: str = Query(""),
    limit: int = Query(200, ge=1, le=500),
    user=Depends(require_permissions("entities:view")),
) -> JSONResponse:
    overview = get_entities_overview()
    return JSONResponse(
        {
            "items": list_entities(entity_type=entity_type, q=q, limit=limit),
            "signals": overview["signals"],
            "metrics": overview["metrics"],
            "breakdowns": overview["breakdowns"],
        }
    )


@router.post("/api/entities/signals", response_class=JSONResponse)
async def record_risk_signal_api(
    payload: dict = Body(default={}),
    user=Depends(require_permissions("entities:write")),
) -> JSONResponse:
    try:
        return JSONResponse(record_risk_signal(payload, actor=str(getattr(user, "username", "web") or "web")))
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.get("/api/entities/{entity_id}", response_class=JSONResponse)
async def entity_detail_api(entity_id: str, user=Depends(require_permissions("entities:view"))) -> JSONResponse:
    item = get_entity(entity_id)
    if item is None:
        return JSONResponse({"error": f"Entity not found: {entity_id}"}, status_code=404)
    return JSONResponse({"item": item})


@router.post("/api/entities/{entity_id}/promote", response_class=JSONResponse)
async def promote_entity_to_case_api(
    entity_id: str,
    payload: dict = Body(default={}),
    user=Depends(require_permissions("cases:write")),
) -> JSONResponse:
    try:
        return JSONResponse(
            promote_entity_to_case(
                entity_id,
                created_by=str(getattr(user, "username", "web") or "web"),
                title=str(payload.get("title") or ""),
            )
        )
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)
