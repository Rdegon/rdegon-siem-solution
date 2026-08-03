from __future__ import annotations

import io

from fastapi import APIRouter, Body, Depends, File, Header, Query, UploadFile
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse, StreamingResponse
from starlette.concurrency import run_in_threadpool

from ..resource_lifecycle_runtime import (
    MAX_PACKAGE_BYTES,
    ResourceLifecycleError,
    compare_resource_versions,
    delete_unpublished_draft,
    duplicate_resource,
    export_resource_package,
    import_resource_package,
    list_resource_versions,
    rollback_resource,
)
from ..security import require_permissions

router = APIRouter()


def _actor(user) -> str:
    return str(getattr(user, "username", "web") or "web")


def _error(exc: Exception) -> JSONResponse:
    if isinstance(exc, ResourceLifecycleError):
        return JSONResponse({"error": str(exc), "code": exc.code}, status_code=exc.status_code)
    return JSONResponse({"error": str(exc), "code": "internal_error"}, status_code=500)


def _positive_int(payload: dict, field: str) -> int:
    try:
        value = int(payload.get(field) or 0)
    except (TypeError, ValueError) as exc:
        raise ResourceLifecycleError(f"{field} must be a positive integer", code="invalid_request") from exc
    if value <= 0:
        raise ResourceLifecycleError(f"{field} must be a positive integer", code="invalid_request")
    return value


@router.post("/api/resources/catalog/{resource_id}/duplicate", response_class=JSONResponse)
async def duplicate_resource_api(
    resource_id: str,
    payload: dict = Body(default={}),
    idempotency_key: str = Header("", alias="Idempotency-Key"),
    tenant_scope: str = Header("main", alias="X-Tenant-Scope"),
    user=Depends(require_permissions("resources:write")),
) -> JSONResponse:
    try:
        result = await run_in_threadpool(
            duplicate_resource,
            resource_id,
            actor=_actor(user),
            idempotency_key=str(idempotency_key or payload.get("idempotency_key") or ""),
            tenant_id=tenant_scope,
            name=str(payload.get("name") or ""),
        )
        return JSONResponse(jsonable_encoder(result), status_code=201 if not result.get("idempotent_replay") else 200)
    except Exception as exc:  # noqa: BLE001
        return _error(exc)


@router.get("/api/resources/catalog/{resource_id}/versions", response_class=JSONResponse)
async def resource_versions_api(
    resource_id: str,
    tenant_scope: str = Header("main", alias="X-Tenant-Scope"),
    user=Depends(require_permissions("resources:view")),
) -> JSONResponse:
    try:
        return JSONResponse(
            jsonable_encoder(await run_in_threadpool(list_resource_versions, resource_id, tenant_id=tenant_scope))
        )
    except Exception as exc:  # noqa: BLE001
        return _error(exc)


@router.get("/api/resources/catalog/{resource_id}/versions/compare", response_class=JSONResponse)
async def compare_resource_versions_api(
    resource_id: str,
    from_version: int = Query(..., ge=1),
    to_version: int = Query(..., ge=1),
    tenant_scope: str = Header("main", alias="X-Tenant-Scope"),
    user=Depends(require_permissions("resources:view")),
) -> JSONResponse:
    try:
        result = await run_in_threadpool(
            compare_resource_versions,
            resource_id,
            from_version=from_version,
            to_version=to_version,
            tenant_id=tenant_scope,
        )
        return JSONResponse(jsonable_encoder(result))
    except Exception as exc:  # noqa: BLE001
        return _error(exc)


@router.post("/api/resources/catalog/{resource_id}/rollback", response_class=JSONResponse)
async def rollback_resource_api(
    resource_id: str,
    payload: dict = Body(...),
    idempotency_key: str = Header("", alias="Idempotency-Key"),
    tenant_scope: str = Header("main", alias="X-Tenant-Scope"),
    user=Depends(require_permissions("resources:write")),
) -> JSONResponse:
    try:
        result = await run_in_threadpool(
            rollback_resource,
            resource_id,
            target_version=_positive_int(payload, "target_version"),
            expected_revision=_positive_int(payload, "expected_revision"),
            actor=_actor(user),
            idempotency_key=str(idempotency_key or payload.get("idempotency_key") or ""),
            tenant_id=tenant_scope,
        )
        return JSONResponse(jsonable_encoder(result), status_code=201 if not result.get("idempotent_replay") else 200)
    except Exception as exc:  # noqa: BLE001
        return _error(exc)


@router.delete("/api/resources/catalog/{resource_id}", response_class=JSONResponse)
async def delete_resource_draft_api(
    resource_id: str,
    payload: dict = Body(default={}),
    idempotency_key: str = Header("", alias="Idempotency-Key"),
    tenant_scope: str = Header("main", alias="X-Tenant-Scope"),
    user=Depends(require_permissions("resources:write")),
) -> JSONResponse:
    try:
        result = await run_in_threadpool(
            delete_unpublished_draft,
            resource_id,
            expected_revision=_positive_int(payload, "expected_revision"),
            actor=_actor(user),
            idempotency_key=str(idempotency_key or payload.get("idempotency_key") or ""),
            tenant_id=tenant_scope,
        )
        return JSONResponse(jsonable_encoder(result))
    except Exception as exc:  # noqa: BLE001
        return _error(exc)


@router.post("/api/resources/catalog/export")
async def export_resources_api(
    payload: dict = Body(...),
    tenant_scope: str = Header("main", alias="X-Tenant-Scope"),
    user=Depends(require_permissions("resources:view")),
):
    try:
        result = await run_in_threadpool(
            export_resource_package,
            [str(item) for item in list(payload.get("resource_ids") or [])],
            actor=_actor(user),
            tenant_id=tenant_scope,
        )
        file_name = f"sentinel-resources-{str(result['package_id'])[:12]}.json"
        return StreamingResponse(
            io.BytesIO(result["content"]),
            media_type="application/vnd.rdegon-sentinel.resources+json",
            headers={
                "Content-Disposition": f'attachment; filename="{file_name}"',
                "X-Sentinel-Package-ID": str(result["package_id"]),
                "X-Sentinel-Resource-Count": str(result["resource_count"]),
            },
        )
    except Exception as exc:  # noqa: BLE001
        return _error(exc)


@router.post("/api/resources/catalog/import", response_class=JSONResponse)
async def import_resources_api(
    package: UploadFile = File(...),
    idempotency_key: str = Header("", alias="Idempotency-Key"),
    tenant_scope: str = Header("main", alias="X-Tenant-Scope"),
    user=Depends(require_permissions("resources:write")),
) -> JSONResponse:
    try:
        content = await package.read(MAX_PACKAGE_BYTES + 1)
        if len(content) > MAX_PACKAGE_BYTES:
            raise ResourceLifecycleError("Package exceeds the size limit", code="package_too_large", status_code=413)
        result = await run_in_threadpool(
            import_resource_package,
            content,
            actor=_actor(user),
            idempotency_key=idempotency_key,
            tenant_id=tenant_scope,
        )
        return JSONResponse(jsonable_encoder(result), status_code=201 if not result.get("idempotent_replay") else 200)
    except Exception as exc:  # noqa: BLE001
        return _error(exc)
