from __future__ import annotations

import logging
import uuid

from fastapi import APIRouter, Body, Depends, Query
from fastapi.responses import FileResponse, JSONResponse, Response
from starlette.concurrency import run_in_threadpool

from ..security import require_permissions
from ..security_services_runtime import get_security_service, list_security_services
from ..opnsense_control_runtime import (
    get_opnsense_control_state,
    mutate_firewall,
    mutate_ids,
)
from ..remote_access_runtime import (
    create_remote_access_profile,
    delete_remote_access_profile,
    remote_access_profile_artifact,
    remote_access_state,
)


router = APIRouter()
logger = logging.getLogger("siem_web.security_services")


@router.get("/api/security-services/vpn/remote-access", response_class=JSONResponse)
async def remote_access_state_api(user=Depends(require_permissions("health:view"))) -> JSONResponse:
    return JSONResponse(await run_in_threadpool(remote_access_state))


@router.post("/api/security-services/vpn/remote-access", response_class=JSONResponse)
async def create_remote_access_profile_api(
    payload: dict = Body(default={}),
    user=Depends(require_permissions("response:run")),
) -> JSONResponse:
    try:
        return JSONResponse(await run_in_threadpool(create_remote_access_profile, payload, actor=str(getattr(user, "username", "web") or "web")))
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    except Exception as exc:  # noqa: BLE001
        return JSONResponse(_error_payload("Remote access profile", exc), status_code=502)


@router.delete("/api/security-services/vpn/remote-access/{profile_id}", response_class=JSONResponse)
async def delete_remote_access_profile_api(
    profile_id: str,
    user=Depends(require_permissions("response:run")),
) -> JSONResponse:
    try:
        return JSONResponse(await run_in_threadpool(delete_remote_access_profile, profile_id))
    except KeyError:
        return JSONResponse({"error": "Remote access profile not found"}, status_code=404)


@router.get(
    "/api/security-services/vpn/remote-access/{profile_id}/download",
    response_model=None,
)
async def download_remote_access_profile_api(
    profile_id: str,
    user=Depends(require_permissions("response:run")),
) -> Response:
    try:
        artifact, filename = await run_in_threadpool(remote_access_profile_artifact, profile_id)
        return FileResponse(
            artifact,
            media_type="application/x-openvpn-profile",
            filename=filename,
        )
    except KeyError:
        return JSONResponse({"error": "Remote access profile not found"}, status_code=404)
    except FileNotFoundError:
        return JSONResponse({"error": "Remote access profile is not ready for download"}, status_code=409)


def _error_payload(label: str, exc: Exception) -> dict[str, str]:
    debug_id = uuid.uuid4().hex[:10]
    logger.exception("%s failed [%s]", label, debug_id)
    return {"error": f"{label} failed. Debug id: {debug_id}", "debug_id": debug_id}


@router.get("/api/security-services", response_class=JSONResponse)
async def security_services_api(
    user=Depends(require_permissions("health:view")),
) -> JSONResponse:
    try:
        return JSONResponse(await run_in_threadpool(list_security_services))
    except Exception as exc:  # noqa: BLE001
        return JSONResponse(_error_payload("Security services", exc), status_code=503)


@router.get("/api/security-services/{service_id}", response_class=JSONResponse)
async def security_service_detail_api(
    service_id: str,
    user=Depends(require_permissions("health:view")),
) -> JSONResponse:
    try:
        return JSONResponse(await run_in_threadpool(get_security_service, service_id))
    except KeyError:
        return JSONResponse({"error": f"Unknown security service: {service_id}"}, status_code=404)
    except Exception as exc:  # noqa: BLE001
        return JSONResponse(_error_payload("Security service detail", exc), status_code=503)


@router.get("/api/security-services/{service_id}/control", response_class=JSONResponse)
async def security_service_control_api(
    service_id: str,
    q: str = Query("", max_length=200),
    user=Depends(require_permissions("health:view")),
) -> JSONResponse:
    try:
        return JSONResponse(
            await run_in_threadpool(
                get_opnsense_control_state,
                service_id,
                search=q,
            )
        )
    except KeyError:
        return JSONResponse(
            {"error": f"Interactive control is not available for: {service_id}"},
            status_code=404,
        )
    except Exception as exc:  # noqa: BLE001
        return JSONResponse(_error_payload("Security service control", exc), status_code=503)


@router.post("/api/security-services/ngfw/firewall/{operation}", response_class=JSONResponse)
async def security_service_firewall_mutation_api(
    operation: str,
    payload: dict = Body(default={}),
    user=Depends(require_permissions("response:run")),
) -> JSONResponse:
    try:
        return JSONResponse(
            await run_in_threadpool(
                mutate_firewall,
                operation,
                payload,
                actor=str(getattr(user, "username", "web") or "web"),
            )
        )
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    except RuntimeError as exc:
        return JSONResponse({"error": str(exc)[:800]}, status_code=409)
    except Exception as exc:  # noqa: BLE001
        return JSONResponse(_error_payload("Firewall operation", exc), status_code=502)


@router.post("/api/security-services/ips/{operation}", response_class=JSONResponse)
async def security_service_ids_mutation_api(
    operation: str,
    payload: dict = Body(default={}),
    user=Depends(require_permissions("response:run")),
) -> JSONResponse:
    try:
        return JSONResponse(
            await run_in_threadpool(
                mutate_ids,
                operation,
                payload,
                actor=str(getattr(user, "username", "web") or "web"),
            )
        )
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    except RuntimeError as exc:
        return JSONResponse({"error": str(exc)[:800]}, status_code=409)
    except Exception as exc:  # noqa: BLE001
        return JSONResponse(_error_payload("IDS operation", exc), status_code=502)
