from __future__ import annotations

import io
import json

from fastapi import APIRouter, Body, Depends, File, Form, Query, UploadFile
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse, StreamingResponse

from .auth import get_current_user
from ..kuma_integration_runtime import (
    export_kuma_resources,
    import_kuma_package,
    kuma_status,
    list_kuma_resources,
)
from ..resource_catalog_runtime import (
    build_collector_deployment,
    get_resource,
    list_resources,
    publish_resource,
    save_resource,
    validate_resource,
)
from ..security import require_permissions

router = APIRouter()


def _actor(user) -> str:
    return str(getattr(user, "username", "web") or "web")


@router.get("/api/resources/catalog", response_class=JSONResponse)
async def resources_catalog_api(
    kind: str = Query(default=""),
    include_runtime: bool = Query(default=True),
    user=Depends(get_current_user),
) -> JSONResponse:
    try:
        return JSONResponse(jsonable_encoder(list_resources(kind=kind, include_runtime=include_runtime)))
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.get("/api/resources/catalog/{resource_id}", response_class=JSONResponse)
async def resource_detail_api(resource_id: str, user=Depends(get_current_user)) -> JSONResponse:
    try:
        return JSONResponse(jsonable_encoder(get_resource(resource_id)))
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=404)


@router.post("/api/resources/catalog", response_class=JSONResponse)
async def save_resource_api(
    payload: dict = Body(...),
    user=Depends(require_permissions("rules:write")),
) -> JSONResponse:
    try:
        return JSONResponse(jsonable_encoder(save_resource(dict(payload or {}), actor=_actor(user))))
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.post("/api/resources/catalog/{resource_id}/validate", response_class=JSONResponse)
async def validate_resource_api(
    resource_id: str,
    user=Depends(require_permissions("rules:test")),
) -> JSONResponse:
    try:
        return JSONResponse(jsonable_encoder(validate_resource(resource_id)))
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.post("/api/resources/catalog/{resource_id}/publish", response_class=JSONResponse)
async def publish_resource_api(
    resource_id: str,
    user=Depends(require_permissions("rules:write")),
) -> JSONResponse:
    try:
        return JSONResponse(jsonable_encoder(publish_resource(resource_id, actor=_actor(user))))
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.get("/api/resources/catalog/{resource_id}/deployment", response_class=JSONResponse)
async def resource_deployment_api(
    resource_id: str,
    user=Depends(require_permissions("resources:view")),
) -> JSONResponse:
    try:
        return JSONResponse(jsonable_encoder(build_collector_deployment(resource_id)))
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.get("/api/integrations/kuma/status", response_class=JSONResponse)
async def kuma_status_api(user=Depends(get_current_user)) -> JSONResponse:
    return JSONResponse(jsonable_encoder(kuma_status()))


@router.get("/api/integrations/kuma/resources", response_class=JSONResponse)
async def kuma_resources_api(
    page: int = Query(default=1, ge=1),
    kind: list[str] = Query(default=[]),
    tenant_id: str = Query(default=""),
    name: str = Query(default=""),
    user=Depends(get_current_user),
) -> JSONResponse:
    try:
        items = list_kuma_resources(page=page, kinds=kind, tenant_id=tenant_id, name=name)
        return JSONResponse(jsonable_encoder({"items": items, "total": len(items), "page": page}))
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=502)


@router.post("/api/integrations/kuma/export")
async def kuma_export_api(
    payload: dict = Body(...),
    user=Depends(require_permissions("rules:write")),
):
    try:
        result = export_kuma_resources(
            [str(item) for item in list(payload.get("resource_ids") or [])],
            password=str(payload.get("password") or ""),
            tenant_id=str(payload.get("tenant_id") or ""),
        )
        file_name = str(payload.get("file_name") or "kuma-resources.kuma").replace('"', "")
        return StreamingResponse(
            io.BytesIO(result["content"]),
            media_type="application/octet-stream",
            headers={
                "Content-Disposition": f'attachment; filename="{file_name}"',
                "X-KUMA-File-ID": result["file_id"],
            },
        )
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=502)


@router.post("/api/integrations/kuma/import", response_class=JSONResponse)
async def kuma_import_api(
    package: UploadFile = File(...),
    password: str = Form(...),
    tenant_id: str = Form(default=""),
    actions_json: str = Form(default="{}"),
    user=Depends(require_permissions("rules:write")),
) -> JSONResponse:
    try:
        actions = json.loads(actions_json or "{}")
        if not isinstance(actions, dict):
            raise ValueError("actions_json must be an object")
        content = await package.read()
        return JSONResponse(
            jsonable_encoder(import_kuma_package(
                content,
                password=password,
                tenant_id=tenant_id,
                actions={str(key): int(value) for key, value in actions.items()},
            ))
        )
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=502)
