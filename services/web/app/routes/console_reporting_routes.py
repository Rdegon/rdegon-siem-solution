from __future__ import annotations

from urllib.parse import quote

from fastapi import APIRouter, Body, Depends, Query, Request
from fastapi.responses import JSONResponse, Response
from starlette.concurrency import run_in_threadpool

from ..control_plane_report_ops import (
    delete_report_template,
    generate_report_run,
    get_report_run,
    get_report_template,
    list_report_runs,
    list_report_templates,
    report_run_csv,
    report_run_json,
    save_report_template,
)
from ..security import require_permissions


router = APIRouter()


def _actor(user: object) -> str:
    return str(getattr(user, "username", "web") or "web")


def _tenant_scope(request: Request, payload: dict | None = None) -> list[str]:
    explicit = list(dict(payload or {}).get("tenant_scope") or [])
    if explicit:
        return [str(item).strip() for item in explicit if str(item).strip()]
    header = str(request.headers.get("x-tenant-scope") or "").strip()
    return [part.strip() for part in header.split(",") if part.strip()] or ["all"]


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
    template_id: str,
    payload: dict = Body(default={}),
    user=Depends(require_permissions("resources:write")),
) -> JSONResponse:
    try:
        item = await run_in_threadpool(
            generate_report_run,
            template_id,
            actor=_actor(user),
            tenant_scope=_tenant_scope(request, payload),
        )
        return JSONResponse(item)
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.get("/api/reporting/runs/{run_id}/artifact", response_class=Response)
async def report_run_artifact_api(
    run_id: str,
    format: str = Query("json", pattern="^(json|csv)$"),  # noqa: A002
    user=Depends(require_permissions("resources:view")),
) -> Response:
    item = get_report_run(run_id)
    if item is None:
        return JSONResponse({"error": f"Generated report not found: {run_id}"}, status_code=404)
    safe_name = quote(str(item.get("name") or run_id).replace("/", "-"))
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
