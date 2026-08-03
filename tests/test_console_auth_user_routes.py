from __future__ import annotations

import os
from unittest.mock import patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

os.environ.setdefault("SIEM_CH_HOST", "127.0.0.1")
os.environ.setdefault("SIEM_CH_USER", "test")
os.environ.setdefault("SIEM_CH_PASSWORD", "test")
os.environ.setdefault("SIEM_ADMIN_DEFAULT_PASSWORD", "test-password")
os.environ.setdefault("SIEM_JWT_SECRET", "test-jwt-secret")

from services.web.app import security
from services.web.app.identity_user_runtime import IdentityUserConflict
from services.web.app.keycloak_admin_runtime import KeycloakMutationConflict
from services.web.app.routes import console_auth_routes


def _app(user: security.User) -> FastAPI:
    app = FastAPI()
    app.include_router(console_auth_routes.router)
    app.dependency_overrides[security.get_current_user] = lambda: user
    return app


def test_delete_keycloak_user_returns_conflict_for_protected_admin() -> None:
    client = TestClient(_app(security.User("admin", "admin")))
    with patch.object(console_auth_routes, "delete_keycloak_user", side_effect=IdentityUserConflict("last enabled Sentinel administrator")):
        response = client.delete("/api/auth/keycloak/users/user-1")

    assert response.status_code == 409
    assert response.json()["code"] == "identity_mutation_conflict"


def test_realm_admin_conflict_is_also_returned_as_http_conflict() -> None:
    client = TestClient(_app(security.User("admin", "admin")))
    with patch.object(console_auth_routes, "delete_keycloak_user", side_effect=KeycloakMutationConflict("last enabled administrator")):
        response = client.delete("/api/auth/keycloak/users/user-1")

    assert response.status_code == 409
    assert response.json()["code"] == "identity_mutation_conflict"


def test_update_keycloak_user_forwards_actor_and_payload_to_managed_runtime() -> None:
    client = TestClient(_app(security.User("soc-admin", "admin")))
    with patch.object(console_auth_routes, "update_keycloak_user", return_value={"id": "user-1", "username": "alice", "enabled": False, "management_backend": "keycloak"}) as update:
        response = client.post("/api/auth/keycloak/users/user-1", json={"enabled": False, "siem_role": "viewer"})

    assert response.status_code == 200
    update.assert_called_once_with("user-1", {"enabled": False, "siem_role": "viewer"}, actor="soc-admin")


def test_local_fallback_rejects_deleting_current_or_last_admin() -> None:
    rows = [{"username": "break-glass", "role": "admin", "enabled": True}]
    with patch.object(console_auth_routes, "delete_local_user", side_effect=console_auth_routes.AccessMutationConflict("last enabled break-glass administrator")):
        response = TestClient(_app(security.User("operator", "admin"))).delete("/api/auth/users/break-glass")

    assert response.status_code == 409
    assert response.json()["code"] == "identity_mutation_conflict"
