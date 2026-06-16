from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body, Depends, Query
from fastapi.responses import JSONResponse

from .auth import get_current_user
from ..control_plane_access_ops import (
    delete_access_grant,
    delete_service_account,
    delete_local_user,
    list_access_grants,
    list_access_systems,
    get_local_user,
    get_permission_inventory,
    save_access_grant,
    get_service_account,
    issue_service_account_token,
    list_break_glass_sessions,
    list_local_users,
    list_service_account_tokens,
    record_break_glass_session,
    revoke_service_account_token,
    revoke_break_glass_session,
    rotate_service_account_token,
    save_local_user,
    save_service_account,
    set_local_user_password,
)
from ..control_plane_health import get_auth_governance_overview, get_auth_overview
from ..keycloak_admin_runtime import (
    create_user as create_keycloak_user,
    delete_user as delete_keycloak_user,
    get_client as get_keycloak_client,
    get_user as get_keycloak_user,
    list_clients as list_keycloak_clients,
    list_groups as list_keycloak_groups,
    list_roles as list_keycloak_roles,
    list_users as list_keycloak_users,
    rotate_client_secret as rotate_keycloak_client_secret,
    save_client as save_keycloak_client,
    save_group as save_keycloak_group,
    save_role as save_keycloak_role,
    set_user_groups as set_keycloak_user_groups,
    set_user_password as set_keycloak_user_password,
    set_user_roles as set_keycloak_user_roles,
    status as keycloak_admin_status,
    update_user as update_keycloak_user,
)
from ..oidc_runtime import providers_inventory
from ..security import require_permissions

router = APIRouter()


def _principal_payload(user: Any) -> dict[str, Any]:
    return {
        "username": str(getattr(user, "username", "guest") or "guest"),
        "role": str(getattr(user, "role", "guest") or "guest"),
        "permissions": list(getattr(user, "permissions", []) or []),
        "principal_type": str(getattr(user, "principal_type", "user") or "user"),
        "service_account_id": str(getattr(user, "service_account_id", "") or ""),
        "auth_mechanism": str(getattr(user, "auth_mechanism", "cookie") or "cookie"),
        "issuer": str(getattr(user, "issuer", "") or ""),
        "groups": list(getattr(user, "groups", []) or []),
        "break_glass": bool(getattr(user, "break_glass", False)),
        "session_expires_ts": str(getattr(user, "session_expires_ts", "") or ""),
        "break_glass_session_id": str(getattr(user, "break_glass_session_id", "") or ""),
        "section_access": list(getattr(user, "section_access", []) or []),
        "system_grants": list(getattr(user, "system_grants", []) or []),
    }


@router.get("/api/auth/me", response_class=JSONResponse)
async def auth_me_api(user=Depends(get_current_user)) -> JSONResponse:
    return JSONResponse({"principal": _principal_payload(user)})


@router.get("/api/auth/providers", response_class=JSONResponse)
async def auth_providers_api(user=Depends(require_permissions("auth:view"))) -> JSONResponse:
    return JSONResponse({"items": providers_inventory()})


@router.get("/api/auth/governance", response_class=JSONResponse)
async def auth_governance_api(user=Depends(require_permissions("auth:view"))) -> JSONResponse:
    return JSONResponse(get_auth_governance_overview())


@router.get("/api/auth/permissions", response_class=JSONResponse)
async def auth_permissions_api(user=Depends(require_permissions("auth:view"))) -> JSONResponse:
    return JSONResponse(get_permission_inventory())


@router.get("/api/auth/access-systems", response_class=JSONResponse)
async def access_systems_api(
    grantable_only: bool = Query(False),
    user=Depends(require_permissions("auth:view")),
) -> JSONResponse:
    return JSONResponse({"items": list_access_systems(grantable_only=grantable_only)})


@router.get("/api/auth/access-grants", response_class=JSONResponse)
async def access_grants_api(
    principal_kind: str = Query(""),
    principal_id: str = Query(""),
    include_disabled: bool = Query(True),
    user=Depends(require_permissions("auth:view")),
) -> JSONResponse:
    return JSONResponse(
        {
            "items": list_access_grants(
                principal_kind=principal_kind,
                principal_id=principal_id,
                include_disabled=include_disabled,
            )
        }
    )


@router.post("/api/auth/access-grants", response_class=JSONResponse)
async def create_access_grant_api(
    payload: dict = Body(default={}),
    user=Depends(require_permissions("auth:write")),
) -> JSONResponse:
    try:
        return JSONResponse(save_access_grant(dict(payload or {}), actor=str(getattr(user, "username", "web") or "web")))
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.post("/api/auth/access-grants/{grant_id}", response_class=JSONResponse)
async def update_access_grant_api(
    grant_id: str,
    payload: dict = Body(default={}),
    user=Depends(require_permissions("auth:write")),
) -> JSONResponse:
    try:
        return JSONResponse(save_access_grant(dict(payload or {}), actor=str(getattr(user, "username", "web") or "web"), grant_id=grant_id))
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.delete("/api/auth/access-grants/{grant_id}", response_class=JSONResponse)
async def delete_access_grant_api(
    grant_id: str,
    user=Depends(require_permissions("auth:write")),
) -> JSONResponse:
    try:
        return JSONResponse(delete_access_grant(grant_id, actor=str(getattr(user, "username", "web") or "web")))
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=404)
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.get("/api/auth/keycloak/status", response_class=JSONResponse)
async def keycloak_status_api(user=Depends(require_permissions("auth:view"))) -> JSONResponse:
    return JSONResponse(keycloak_admin_status())


@router.get("/api/auth/keycloak/users", response_class=JSONResponse)
async def keycloak_users_api(
    search: str = Query(""),
    limit: int = Query(200, ge=1, le=500),
    user=Depends(require_permissions("auth:view")),
) -> JSONResponse:
    return JSONResponse({"items": list_keycloak_users(search=search, limit=limit)})


@router.post("/api/auth/keycloak/users", response_class=JSONResponse)
async def create_keycloak_user_api(
    payload: dict = Body(default={}),
    user=Depends(require_permissions("auth:write")),
) -> JSONResponse:
    try:
        return JSONResponse(create_keycloak_user(dict(payload or {}), actor=str(getattr(user, "username", "web") or "web")))
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.get("/api/auth/keycloak/users/{user_id}", response_class=JSONResponse)
async def keycloak_user_detail_api(
    user_id: str,
    user=Depends(require_permissions("auth:view")),
) -> JSONResponse:
    try:
        return JSONResponse({"item": get_keycloak_user(user_id)})
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=404)
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.post("/api/auth/keycloak/users/{user_id}", response_class=JSONResponse)
async def update_keycloak_user_api(
    user_id: str,
    payload: dict = Body(default={}),
    user=Depends(require_permissions("auth:write")),
) -> JSONResponse:
    try:
        return JSONResponse(update_keycloak_user(user_id, dict(payload or {}), actor=str(getattr(user, "username", "web") or "web")))
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=404)
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.delete("/api/auth/keycloak/users/{user_id}", response_class=JSONResponse)
async def delete_keycloak_user_api(
    user_id: str,
    user=Depends(require_permissions("auth:write")),
) -> JSONResponse:
    try:
        return JSONResponse(delete_keycloak_user(user_id, actor=str(getattr(user, "username", "web") or "web")))
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=404)
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.post("/api/auth/keycloak/users/{user_id}/password", response_class=JSONResponse)
async def set_keycloak_user_password_api(
    user_id: str,
    payload: dict = Body(default={}),
    user=Depends(require_permissions("auth:write")),
) -> JSONResponse:
    try:
        return JSONResponse(set_keycloak_user_password(user_id, dict(payload or {}), actor=str(getattr(user, "username", "web") or "web")))
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=404)
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.post("/api/auth/keycloak/users/{user_id}/groups", response_class=JSONResponse)
async def set_keycloak_user_groups_api(
    user_id: str,
    payload: dict = Body(default={}),
    user=Depends(require_permissions("auth:write")),
) -> JSONResponse:
    try:
        return JSONResponse(set_keycloak_user_groups(user_id, dict(payload or {}), actor=str(getattr(user, "username", "web") or "web")))
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=404)
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.post("/api/auth/keycloak/users/{user_id}/roles", response_class=JSONResponse)
async def set_keycloak_user_roles_api(
    user_id: str,
    payload: dict = Body(default={}),
    user=Depends(require_permissions("auth:write")),
) -> JSONResponse:
    try:
        return JSONResponse(set_keycloak_user_roles(user_id, dict(payload or {}), actor=str(getattr(user, "username", "web") or "web")))
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=404)
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.get("/api/auth/keycloak/groups", response_class=JSONResponse)
async def keycloak_groups_api(user=Depends(require_permissions("auth:view"))) -> JSONResponse:
    return JSONResponse({"items": list_keycloak_groups()})


@router.post("/api/auth/keycloak/groups", response_class=JSONResponse)
async def create_keycloak_group_api(
    payload: dict = Body(default={}),
    user=Depends(require_permissions("auth:write")),
) -> JSONResponse:
    try:
        return JSONResponse(save_keycloak_group(dict(payload or {}), actor=str(getattr(user, "username", "web") or "web")))
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.post("/api/auth/keycloak/groups/{group_id}", response_class=JSONResponse)
async def update_keycloak_group_api(
    group_id: str,
    payload: dict = Body(default={}),
    user=Depends(require_permissions("auth:write")),
) -> JSONResponse:
    try:
        return JSONResponse(save_keycloak_group(dict(payload or {}), actor=str(getattr(user, "username", "web") or "web"), group_id=group_id))
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.get("/api/auth/keycloak/roles", response_class=JSONResponse)
async def keycloak_roles_api(user=Depends(require_permissions("auth:view"))) -> JSONResponse:
    return JSONResponse({"items": list_keycloak_roles()})


@router.post("/api/auth/keycloak/roles", response_class=JSONResponse)
async def create_keycloak_role_api(
    payload: dict = Body(default={}),
    user=Depends(require_permissions("auth:write")),
) -> JSONResponse:
    try:
        return JSONResponse(save_keycloak_role(dict(payload or {}), actor=str(getattr(user, "username", "web") or "web")))
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.post("/api/auth/keycloak/roles/{role_name}", response_class=JSONResponse)
async def update_keycloak_role_api(
    role_name: str,
    payload: dict = Body(default={}),
    user=Depends(require_permissions("auth:write")),
) -> JSONResponse:
    try:
        return JSONResponse(save_keycloak_role(dict(payload or {}), actor=str(getattr(user, "username", "web") or "web"), role_name=role_name))
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.get("/api/auth/keycloak/clients", response_class=JSONResponse)
async def keycloak_clients_api(user=Depends(require_permissions("auth:view"))) -> JSONResponse:
    return JSONResponse({"items": list_keycloak_clients()})


@router.post("/api/auth/keycloak/clients", response_class=JSONResponse)
async def create_keycloak_client_api(
    payload: dict = Body(default={}),
    user=Depends(require_permissions("auth:write")),
) -> JSONResponse:
    try:
        return JSONResponse(save_keycloak_client(dict(payload or {}), actor=str(getattr(user, "username", "web") or "web")))
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.get("/api/auth/keycloak/clients/{client_id}", response_class=JSONResponse)
async def keycloak_client_detail_api(
    client_id: str,
    user=Depends(require_permissions("auth:view")),
) -> JSONResponse:
    try:
        return JSONResponse({"item": get_keycloak_client(client_id)})
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=404)
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.post("/api/auth/keycloak/clients/{client_id}", response_class=JSONResponse)
async def update_keycloak_client_api(
    client_id: str,
    payload: dict = Body(default={}),
    user=Depends(require_permissions("auth:write")),
) -> JSONResponse:
    try:
        return JSONResponse(save_keycloak_client(dict(payload or {}), actor=str(getattr(user, "username", "web") or "web"), client_id=client_id))
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.post("/api/auth/keycloak/clients/{client_id}/secret/rotate", response_class=JSONResponse)
async def rotate_keycloak_client_secret_api(
    client_id: str,
    user=Depends(require_permissions("auth:write")),
) -> JSONResponse:
    try:
        return JSONResponse(rotate_keycloak_client_secret(client_id, actor=str(getattr(user, "username", "web") or "web")))
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=404)
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.get("/api/auth/service-accounts", response_class=JSONResponse)
async def service_accounts_api(user=Depends(require_permissions("auth:view"))) -> JSONResponse:
    overview = get_auth_overview()
    inventory = get_permission_inventory()
    return JSONResponse(
        {
            "items": overview["items"],
            "metrics": overview["metrics"],
            "breakdowns": overview["breakdowns"],
            **inventory,
        }
    )


@router.post("/api/auth/service-accounts", response_class=JSONResponse)
async def save_service_account_api(
    payload: dict = Body(default={}),
    user=Depends(require_permissions("auth:write")),
) -> JSONResponse:
    try:
        return JSONResponse(save_service_account(dict(payload or {}), actor=str(getattr(user, "username", "web") or "web")))
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.get("/api/auth/service-accounts/{service_account_id}", response_class=JSONResponse)
async def service_account_detail_api(
    service_account_id: str,
    user=Depends(require_permissions("auth:view")),
) -> JSONResponse:
    item = get_service_account(service_account_id)
    if item is None:
        return JSONResponse({"error": f"Service account not found: {service_account_id}"}, status_code=404)
    return JSONResponse({"item": item, "tokens": list_service_account_tokens(service_account_id=service_account_id, include_revoked=True)})


@router.delete("/api/auth/service-accounts/{service_account_id}", response_class=JSONResponse)
async def delete_service_account_api(
    service_account_id: str,
    user=Depends(require_permissions("auth:write")),
) -> JSONResponse:
    try:
        return JSONResponse(delete_service_account(service_account_id, actor=str(getattr(user, "username", "web") or "web")))
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.get("/api/auth/service-accounts/{service_account_id}/tokens", response_class=JSONResponse)
async def service_account_tokens_api(
    service_account_id: str,
    include_revoked: bool = Query(True),
    user=Depends(require_permissions("auth:view")),
) -> JSONResponse:
    item = get_service_account(service_account_id)
    if item is None:
        return JSONResponse({"error": f"Service account not found: {service_account_id}"}, status_code=404)
    return JSONResponse({"items": list_service_account_tokens(service_account_id=service_account_id, include_revoked=include_revoked)})


@router.post("/api/auth/service-accounts/{service_account_id}/tokens", response_class=JSONResponse)
async def issue_service_account_token_api(
    service_account_id: str,
    payload: dict = Body(default={}),
    user=Depends(require_permissions("auth:write")),
) -> JSONResponse:
    try:
        return JSONResponse(
            issue_service_account_token(
                service_account_id,
                title=str(payload.get("title") or "").strip(),
                actor=str(getattr(user, "username", "web") or "web"),
                expires_days=int(payload.get("expires_days") or 90),
            )
        )
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.post("/api/auth/service-accounts/{service_account_id}/rotate", response_class=JSONResponse)
async def rotate_service_account_token_api(
    service_account_id: str,
    payload: dict = Body(default={}),
    user=Depends(require_permissions("auth:write")),
) -> JSONResponse:
    try:
        return JSONResponse(
            rotate_service_account_token(
                service_account_id,
                title=str(payload.get("title") or "").strip(),
                actor=str(getattr(user, "username", "web") or "web"),
                expires_days=int(payload.get("expires_days") or 90),
                revoke_predecessor=bool(payload.get("revoke_predecessor", True)),
                overlap_minutes=int(payload.get("overlap_minutes") or 15),
            )
        )
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.post("/api/auth/service-accounts/{service_account_id}/tokens/{token_id}/revoke", response_class=JSONResponse)
async def revoke_service_account_token_api(
    service_account_id: str,
    token_id: str,
    user=Depends(require_permissions("auth:write")),
) -> JSONResponse:
    try:
        return JSONResponse(
            {
                "item": revoke_service_account_token(
                    service_account_id,
                    token_id,
                    actor=str(getattr(user, "username", "web") or "web"),
                )
            }
        )
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.get("/api/auth/users", response_class=JSONResponse)
async def local_users_api(
    include_disabled: bool = Query(True),
    user=Depends(require_permissions("auth:view")),
) -> JSONResponse:
    inventory = get_permission_inventory()
    return JSONResponse({"items": list_local_users(include_disabled=include_disabled), **inventory})


@router.get("/api/auth/users/{username}", response_class=JSONResponse)
async def local_user_detail_api(
    username: str,
    user=Depends(require_permissions("auth:view")),
) -> JSONResponse:
    item = get_local_user(username)
    if item is None:
        return JSONResponse({"error": f"Local user not found: {username}"}, status_code=404)
    return JSONResponse({"item": item, **get_permission_inventory()})


@router.post("/api/auth/users", response_class=JSONResponse)
async def save_local_user_api(
    payload: dict = Body(default={}),
    user=Depends(require_permissions("auth:write")),
) -> JSONResponse:
    try:
        return JSONResponse(save_local_user(dict(payload or {}), actor=str(getattr(user, "username", "web") or "web")))
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.post("/api/auth/users/{username}/password", response_class=JSONResponse)
async def set_local_user_password_api(
    username: str,
    payload: dict = Body(default={}),
    user=Depends(require_permissions("auth:write")),
) -> JSONResponse:
    try:
        return JSONResponse(
            set_local_user_password(
                username,
                new_password=str(payload.get("password") or payload.get("new_password") or ""),
                actor=str(getattr(user, "username", "web") or "web"),
            )
        )
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.delete("/api/auth/users/{username}", response_class=JSONResponse)
async def delete_local_user_api(
    username: str,
    user=Depends(require_permissions("auth:write")),
) -> JSONResponse:
    try:
        return JSONResponse(delete_local_user(username, actor=str(getattr(user, "username", "web") or "web")))
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.get("/api/auth/break-glass", response_class=JSONResponse)
async def break_glass_sessions_api(
    active_only: bool = Query(False),
    limit: int = Query(100, ge=1, le=500),
    user=Depends(require_permissions("auth:view")),
) -> JSONResponse:
    items = list_break_glass_sessions(active_only=active_only, limit=limit)
    return JSONResponse(
        {
            "items": items,
            "metrics": {
                "total": len(items),
                "active": sum(1 for item in items if bool(item.get("active"))),
                "revoked": sum(1 for item in items if str(item.get("status") or "") == "revoked"),
                "expired": sum(1 for item in items if str(item.get("status") or "") == "expired"),
            },
        }
    )


@router.post("/api/auth/break-glass", response_class=JSONResponse)
async def break_glass_mutation_api(
    payload: dict = Body(default={}),
    user=Depends(require_permissions("auth:write")),
) -> JSONResponse:
    action = str(payload.get("action") or "open").strip().lower()
    actor = str(getattr(user, "username", "web") or "web")
    try:
        if action == "revoke":
            session_id = str(payload.get("session_id") or "").strip()
            if not session_id:
                raise ValueError("session_id is required")
            item = revoke_break_glass_session(
                session_id,
                actor=actor,
                reason=str(payload.get("reason") or payload.get("note") or "manual revoke"),
            )
            return JSONResponse({"item": item})
        item = record_break_glass_session(
            str(payload.get("username") or actor),
            role=str(payload.get("role") or getattr(user, "role", "admin") or "admin"),
            reason=str(payload.get("reason") or "Operator break-glass access"),
            actor=actor,
            client_ip=str(payload.get("client_ip") or ""),
            expires_minutes=int(payload.get("expires_minutes") or 60),
        )
        return JSONResponse({"item": item})
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)
