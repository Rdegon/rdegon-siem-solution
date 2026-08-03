from __future__ import annotations

import logging
import uuid

from fastapi import APIRouter, Body, Depends, Query
from fastapi.responses import FileResponse, JSONResponse, Response
from starlette.concurrency import run_in_threadpool

from ..security import require_permissions
from ..control_plane_governance_runtime import append_audit_event
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
from ..xui_runtime import (
    XuiControllerError,
    client_profile,
    create_client,
    create_inbound,
    delete_client,
    delete_inbound,
    reset_client_traffic,
    reset_inbound_traffic,
    update_client,
    update_inbound,
    xui_state,
)


router = APIRouter()
logger = logging.getLogger("siem_web.security_services")


async def _audit_xui(
    user,
    *,
    action: str,
    object_id: str,
    summary: str,
    details: dict | None = None,
) -> None:
    await run_in_threadpool(
        append_audit_event,
        actor=str(getattr(user, "username", "web") or "web"),
        action=f"xui.{action}",
        object_type="vless_profile" if "client" in action or "profile" in action else "vless_inbound",
        object_id=str(object_id),
        summary=summary,
        details=dict(details or {}),
    )


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


@router.get("/api/security-services/vpn/vless", response_class=JSONResponse)
async def vless_control_state_api(user=Depends(require_permissions("health:view"))) -> JSONResponse:
    return JSONResponse(await run_in_threadpool(xui_state))


def _xui_error(exc: Exception) -> JSONResponse:
    if isinstance(exc, XuiControllerError):
        return JSONResponse({"error": str(exc)}, status_code=503)
    if isinstance(exc, ValueError):
        return JSONResponse({"error": str(exc)}, status_code=400)
    return JSONResponse(_error_payload("3x-ui operation", exc), status_code=502)


@router.post("/api/security-services/vpn/vless/inbounds", response_class=JSONResponse)
async def vless_create_inbound_api(
    payload: dict = Body(default={}),
    user=Depends(require_permissions("response:run")),
) -> JSONResponse:
    try:
        result = await run_in_threadpool(create_inbound, payload)
        await _audit_xui(user, action="inbound.created", object_id=str(payload.get("remark") or "new"), summary="Created VLESS inbound")
        return JSONResponse(result)
    except Exception as exc:  # noqa: BLE001
        return _xui_error(exc)


@router.put("/api/security-services/vpn/vless/inbounds/{inbound_id}", response_class=JSONResponse)
async def vless_update_inbound_api(
    inbound_id: int,
    payload: dict = Body(default={}),
    user=Depends(require_permissions("response:run")),
) -> JSONResponse:
    try:
        result = await run_in_threadpool(update_inbound, inbound_id, payload)
        await _audit_xui(user, action="inbound.updated", object_id=str(inbound_id), summary="Updated VLESS inbound", details={"fields": sorted(payload.keys())})
        return JSONResponse(result)
    except Exception as exc:  # noqa: BLE001
        return _xui_error(exc)


@router.delete("/api/security-services/vpn/vless/inbounds/{inbound_id}", response_class=JSONResponse)
async def vless_delete_inbound_api(
    inbound_id: int,
    user=Depends(require_permissions("response:run")),
) -> JSONResponse:
    try:
        result = await run_in_threadpool(delete_inbound, inbound_id)
        await _audit_xui(user, action="inbound.deleted", object_id=str(inbound_id), summary="Deleted VLESS inbound")
        return JSONResponse(result)
    except Exception as exc:  # noqa: BLE001
        return _xui_error(exc)


@router.post("/api/security-services/vpn/vless/inbounds/{inbound_id}/clients", response_class=JSONResponse)
async def vless_create_client_api(
    inbound_id: int,
    payload: dict = Body(default={}),
    user=Depends(require_permissions("response:run")),
) -> JSONResponse:
    try:
        result = await run_in_threadpool(create_client, inbound_id, payload)
        await _audit_xui(user, action="client.created", object_id=str(payload.get("email") or "new"), summary="Created VLESS profile", details={"inbound_id": inbound_id})
        return JSONResponse(result)
    except Exception as exc:  # noqa: BLE001
        return _xui_error(exc)


@router.put(
    "/api/security-services/vpn/vless/inbounds/{inbound_id}/clients/{client_id}",
    response_class=JSONResponse,
)
async def vless_update_client_api(
    inbound_id: int,
    client_id: str,
    payload: dict = Body(default={}),
    user=Depends(require_permissions("response:run")),
) -> JSONResponse:
    try:
        result = await run_in_threadpool(update_client, inbound_id, client_id, payload)
        await _audit_xui(user, action="client.updated", object_id=client_id, summary="Updated VLESS profile", details={"inbound_id": inbound_id, "fields": sorted(payload.keys())})
        return JSONResponse(result)
    except Exception as exc:  # noqa: BLE001
        return _xui_error(exc)


@router.delete(
    "/api/security-services/vpn/vless/inbounds/{inbound_id}/clients/{client_id}",
    response_class=JSONResponse,
)
async def vless_delete_client_api(
    inbound_id: int,
    client_id: str,
    user=Depends(require_permissions("response:run")),
) -> JSONResponse:
    try:
        result = await run_in_threadpool(delete_client, inbound_id, client_id)
        await _audit_xui(user, action="client.deleted", object_id=client_id, summary="Deleted VLESS profile", details={"inbound_id": inbound_id})
        return JSONResponse(result)
    except Exception as exc:  # noqa: BLE001
        return _xui_error(exc)


@router.get(
    "/api/security-services/vpn/vless/inbounds/{inbound_id}/clients/{client_id}/profile",
    response_class=JSONResponse,
)
async def vless_client_profile_api(
    inbound_id: int,
    client_id: str,
    user=Depends(require_permissions("response:run")),
) -> JSONResponse:
    try:
        result = await run_in_threadpool(client_profile, inbound_id, client_id)
        await _audit_xui(user, action="profile.read", object_id=client_id, summary="Issued VLESS profile URI", details={"inbound_id": inbound_id})
        return JSONResponse(result)
    except Exception as exc:  # noqa: BLE001
        return _xui_error(exc)


@router.post(
    "/api/security-services/vpn/vless/inbounds/{inbound_id}/clients/{client_id}/reset-traffic",
    response_class=JSONResponse,
)
async def vless_reset_client_traffic_api(
    inbound_id: int,
    client_id: str,
    user=Depends(require_permissions("response:run")),
) -> JSONResponse:
    try:
        result = await run_in_threadpool(reset_client_traffic, inbound_id, client_id)
        await _audit_xui(user, action="client.traffic_reset", object_id=client_id, summary="Reset VLESS profile traffic", details={"inbound_id": inbound_id})
        return JSONResponse(result)
    except Exception as exc:  # noqa: BLE001
        return _xui_error(exc)


@router.post(
    "/api/security-services/vpn/vless/inbounds/{inbound_id}/reset-traffic",
    response_class=JSONResponse,
)
async def vless_reset_inbound_traffic_api(
    inbound_id: int,
    user=Depends(require_permissions("response:run")),
) -> JSONResponse:
    try:
        result = await run_in_threadpool(reset_inbound_traffic, inbound_id)
        await _audit_xui(user, action="inbound.traffic_reset", object_id=str(inbound_id), summary="Reset VLESS inbound traffic")
        return JSONResponse(result)
    except Exception as exc:  # noqa: BLE001
        return _xui_error(exc)


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
