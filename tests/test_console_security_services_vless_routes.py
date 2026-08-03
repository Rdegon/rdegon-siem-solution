from __future__ import annotations

import asyncio
import os
from unittest.mock import AsyncMock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient


os.environ.setdefault("SIEM_CH_HOST", "127.0.0.1")
os.environ.setdefault("SIEM_CH_USER", "test")
os.environ.setdefault("SIEM_CH_PASSWORD", "test")
os.environ.setdefault("SIEM_ADMIN_DEFAULT_PASSWORD", "test-password")
os.environ.setdefault("SIEM_JWT_SECRET", "test-jwt-secret")

from services.web.app import security
from services.web.app.routes import console_security_services_routes as routes


def _app(user: security.User) -> FastAPI:
    app = FastAPI()
    app.include_router(routes.router)
    app.dependency_overrides[security.get_current_user] = lambda: user
    return app


def test_viewer_can_read_only_credential_free_vless_monitoring() -> None:
    payload = {
        "configured": True,
        "status": "active",
        "capabilities": ["inbounds.read", "traffic.read"],
        "inbounds": [{"id": 7, "remark": "production", "client_count": 2}],
        "clients": [],
        "client_count": 2,
        "online_count": 1,
    }
    client = TestClient(_app(security.User("viewer", "viewer")))

    with patch.object(routes, "xui_state", return_value=payload):
        response = client.get("/api/security-services/vpn/vless")

    assert response.status_code == 200
    assert response.json() == payload


def test_viewer_and_analyst_cannot_open_management_or_delete_profiles() -> None:
    viewer = TestClient(_app(security.User("viewer", "viewer")))
    analyst = TestClient(_app(security.User("analyst", "analyst")))

    assert viewer.get("/api/security-services/vpn/vless/management").status_code == 403
    assert analyst.delete("/api/security-services/vpn/vless/inbounds/7/clients/client-0123456789abcdef01234567").status_code == 403


def test_manager_without_profile_permission_does_not_receive_profile_capability() -> None:
    manager = security.User("vpn-manager", "viewer", permissions=["vpn:view", "vpn:manage"])
    client = TestClient(_app(manager))
    payload = {
        "configured": True,
        "status": "active",
        "capabilities": ["clients.update", "clients.profile"],
        "inbounds": [],
        "clients": [],
    }

    with patch.object(routes, "xui_management_state", return_value=payload):
        response = client.get("/api/security-services/vpn/vless/management")

    assert response.status_code == 200
    assert response.json()["capabilities"] == ["clients.update"]


def test_admin_can_delete_profile_with_vpn_manage_permission() -> None:
    client = TestClient(_app(security.User("admin", "admin")))
    opaque_ref = "client-0123456789abcdef01234567"
    audit = AsyncMock()

    with (
        patch.object(routes, "delete_client", return_value={"success": True}) as delete,
        patch.object(routes, "_audit_xui", audit),
    ):
        response = client.delete(f"/api/security-services/vpn/vless/inbounds/7/clients/{opaque_ref}")

    assert response.status_code == 200
    delete.assert_called_once_with(7, opaque_ref)
    audit.assert_awaited_once()


def test_xui_audit_persists_only_an_irreversible_fingerprint() -> None:
    append = patch.object(routes, "append_audit_event")
    with append as append_event, patch.object(routes, "audit_fingerprint", return_value="fp-opaque"):
        asyncio.run(
            routes._audit_xui(
                security.User("admin", "admin"),
                action="client.updated",
                object_id="raw-client-uuid",
                summary="Updated VLESS profile",
            )
        )

    assert append_event.call_args.kwargs["object_id"] == "fp-opaque"
    assert "raw-client-uuid" not in str(append_event.call_args)


def test_profile_issuance_uses_dedicated_permission() -> None:
    issuer = security.User("issuer", "viewer", permissions=["vpn:profile:issue"])
    client = TestClient(_app(issuer))
    opaque_ref = "client-0123456789abcdef01234567"

    with (
        patch.object(routes, "client_profile", return_value={"success": True, "profile": "profile-value"}),
        patch.object(routes, "_audit_xui", AsyncMock()),
    ):
        response = client.get(f"/api/security-services/vpn/vless/inbounds/7/clients/{opaque_ref}/profile")

    assert response.status_code == 200
    assert response.json()["profile"] == "profile-value"
