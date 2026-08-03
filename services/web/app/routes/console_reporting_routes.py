from __future__ import annotations

from urllib.parse import quote

from fastapi import APIRouter, BackgroundTasks, Body, Depends, Query, Request
from fastapi.responses import JSONResponse, Response
from starlette.concurrency import run_in_threadpool

from ..control_plane_report_ops import (
    create_report_run,
    delete_report_template,
    execute_report_run,
    get_report_run,
    get_report_template,
    list_report_runs,
    list_report_templates,
    report_run_csv,
    report_run_json,
    report_run_pdf,
    reporting_capabilities,
    save_report_template,
)
from ..security import require_permissions
from ..tenant_scope_runtime import validate_tenant_scope_header


router = APIRouter()


def _actor(user: object) -> str:
    return str(getattr(user, "username", "web") or "web")


def _tenant_scope(request: Request, payload: dict | None = None) -> list[str]:
    explicit = list(dict(payload or {}).get("tenant_scope") or [])
    if explicit:
        return validate_tenant_scope_header(",".join(str(item).strip() for item in explicit if str(item).strip()))
    header = str(request.headers.get("x-siem-tenant-scope") or "main").strip()
    return validate_tenant_scope_header(header)


@router.get("/api/reporting/capabilities", response_class=JSONResponse)
async def reporting_capabilities_api(
    user=Depends(require_permissions("resources:view")),
) -> JSONResponse:
    return JSONResponse(reporting_capabilities())


@router.get("/api/reporting/templates", response_class=JSONResponse)
async def report_templates_api(
    user=Depends(require_permissions("resources:view")),
) -> JSONResponse:
    return JSONResponse({"items": list_report_templates()})


@router.get("/api/reporting/templates/{template_id}", response_class=JSONResponse)
async def report_template_detail_api(
    template_id: str,
    user=Depends(require_permissions("resources:view")),
) -> JSONResponse:
    item = get_report_template(template_id)
    if item is None:
        return JSONResponse({"error": f"Report template not found: {template_id}"}, status_code=404)
    return JSONResponse({"item": item})


@router.post("/api/reporting/templates", response_class=JSONResponse)
async def save_report_template_api(
    payload: dict = Body(default={}),
    user=Depends(require_permissions("resources:write")),
) -> JSONResponse:
    try:
        return JSONResponse(save_report_template(payload, actor=_actor(user)))
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.patch("/api/reporting/templates/{template_id}/schedule", response_class=JSONResponse)
async def update_report_schedule_api(
    template_id: str,
    payload: dict = Body(default={}),
    user=Depends(require_permissions("resources:write")),
) -> JSONResponse:
    item = get_report_template(template_id)
    if item is None:
        return JSONResponse({"error": f"Report template not found: {template_id}"}, status_code=404)
    try:
        item["schedule"] = {**dict(item.get("schedule") or {}), **dict(payload or {})}
        return JSONResponse(save_report_template(item, actor=_actor(user)))
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.delete("/api/reporting/templates/{template_id}", response_class=JSONResponse)
async def delete_report_template_api(
    template_id: str,
    user=Depends(require_permissions("resources:write")),
) -> JSONResponse:
    try:
        return JSONResponse(delete_report_template(template_id, actor=_actor(user)))
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.get("/api/reporting/runs", response_class=JSONResponse)
async def report_runs_api(
    limit: int = Query(100, ge=1, le=500),
    user=Depends(require_permissions("resources:view")),
) -> JSONResponse:
    return JSONResponse({"items": list_report_runs(limit=limit)})


@router.get("/api/reporting/runs/{run_id}", response_class=JSONResponse)
async def report_run_detail_api(
    run_id: str,
    user=Depends(require_permissions("resources:view")),
) -> JSONResponse:
    item = get_report_run(run_id)
    if item is None:
        return JSONResponse({"error": f"Generated report not found: {run_id}"}, status_code=404)
    return JSONResponse({"item": item})


@router.post("/api/reporting/templates/{template_id}/run", response_class=JSONResponse)
async def run_report_template_api(
    request: Request,
    background_tasks: BackgroundTasks,
    template_id: str,
    payload: dict = Body(default={}),
    user=Depends(require_permissions("resources:write")),
) -> JSONResponse:
    try:
        idempotency_key = str(request.headers.get("idempotency-key") or payload.get("idempotency_key") or "").strip()
        item, created = await run_in_threadpool(
            create_report_run,
            template_id,
            actor=_actor(user),
            tenant_scope=_tenant_scope(request, payload),
            idempotency_key=idempotency_key,
        )
        if created:
            background_tasks.add_task(execute_report_run, item["id"])
        return JSONResponse(
            {"item": item, "created": created, "idempotent_replay": not created},
            status_code=202 if created else 200,
        )
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.get("/api/reporting/runs/{run_id}/artifact", response_class=Response)
async def report_run_artifact_api(
    run_id: str,
    format: str = Query("json", pattern="^(json|csv|pdf)$"),  # noqa: A002
    user=Depends(require_permissions("resources:view")),
) -> Response:
    item = get_report_run(run_id)
    if item is None:
        return JSONResponse({"error": f"Generated report not found: {run_id}"}, status_code=404)
    safe_name = quote(str(item.get("name") or run_id).replace("/", "-"))
    if str(item.get("status") or "") not in {"completed", "completed_with_warnings", "failed"}:
        return JSONResponse({"error": "Report artifact is not ready"}, status_code=409)
    if format == "pdf":
        try:
            content = await run_in_threadpool(report_run_pdf, item)
        except RuntimeError as exc:
            return JSONResponse({"error": str(exc), "capabilities": reporting_capabilities()}, status_code=409)
        return Response(
            content=content,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{safe_name}.pdf"'},
        )
    if format == "csv":
        return Response(
            content=report_run_csv(item),
            media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{safe_name}.csv"'},
        )
    return Response(
        content=report_run_json(item),
        media_type="application/json; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{safe_name}.json"'},
    )
