from __future__ import annotations

from unittest.mock import patch

import pytest

from services.web.app import identity_user_runtime as runtime
from services.web.app import control_plane_access_ops as access_ops


def _user(*, username: str = "alice", enabled: bool = True, role: str = "analyst") -> dict:
    return {
        "id": f"id-{username}",
        "username": username,
        "enabled": enabled,
        "roles": [],
        "groups": [],
        "attributes": {},
        "siem_grant_id": f"grant-{username}",
        "siem_role": role,
        "siem_access_enabled": True,
        "siem_sections": ["access"],
    }


def test_list_users_enriches_keycloak_records_with_real_siem_grants() -> None:
    grants = [{"id": "grant-alice", "principal_id": "alice", "system_id": "siem", "role": "analyst", "enabled": True, "sections": ["events"]}]
    with patch.object(runtime.keycloak, "list_users", return_value=[{"id": "id-alice", "username": "alice", "enabled": True}]):
        with patch.object(runtime, "list_access_grants", return_value=grants):
            result = runtime.list_users(limit=10)

    assert result == [{
        "id": "id-alice",
        "username": "alice",
        "enabled": True,
        "management_backend": "keycloak",
        "siem_grant_id": "grant-alice",
        "siem_role": "analyst",
        "siem_access_enabled": True,
        "siem_sections": ["events"],
    }]


def test_create_user_persists_keycloak_identity_and_siem_grant() -> None:
    created = _user(username="bob", role="viewer")
    with patch.object(runtime.keycloak, "create_user", return_value=created) as create:
        with patch.object(runtime, "save_access_grant", return_value={"id": "grant-bob"}) as save_grant:
            with patch.object(runtime, "get_user", return_value=created):
                result = runtime.create_user(
                    {"username": "bob", "password": "Secret!23", "siem_role": "viewer", "enabled": True},
                    actor="admin",
                )

    assert result["username"] == "bob"
    create.assert_called_once()
    save_grant.assert_called_once()
    assert save_grant.call_args.args[0]["principal_id"] == "bob"
    assert save_grant.call_args.args[0]["role"] == "viewer"


def test_create_user_compensates_keycloak_and_partial_grant_on_failure() -> None:
    created = _user(username="bob", role="admin")
    with patch.object(runtime.keycloak, "create_user", return_value=created):
        with patch.object(runtime, "save_access_grant", side_effect=RuntimeError("grant sync failed")):
            with patch.object(runtime.keycloak, "_delete_user_unchecked") as delete_keycloak:
                with patch.object(runtime, "list_access_grants", return_value=[{"id": "grant-bob"}]):
                    with patch.object(runtime, "delete_access_grant") as delete_grant:
                        with pytest.raises(RuntimeError, match="grant sync failed"):
                            runtime.create_user({"username": "bob", "siem_role": "admin"}, actor="operator")

    delete_keycloak.assert_called_once_with("id-bob")
    delete_grant.assert_called_once_with("grant-bob", actor="operator")


def test_update_rejects_disabling_last_sentinel_administrator() -> None:
    current = _user(username="root-admin", role="admin")
    with patch.object(runtime, "get_user", return_value=current):
        with patch.object(runtime, "_active_platform_admins", return_value={"root-admin"}):
            with patch.object(runtime.keycloak, "update_user") as update:
                with pytest.raises(runtime.IdentityUserConflict, match="last enabled Sentinel administrator"):
                    runtime.update_user("id-root-admin", {"enabled": False}, actor="break-glass")
    update.assert_not_called()


def test_delete_rejects_current_user_before_keycloak_mutation() -> None:
    current = _user(username="alice", role="analyst")
    with patch.object(runtime, "get_user", return_value=current):
        with patch.object(runtime.keycloak, "delete_user") as delete:
            with pytest.raises(runtime.IdentityUserConflict, match="currently authenticated"):
                runtime.delete_user("id-alice", actor="alice")
    delete.assert_not_called()


def test_local_fallback_rejects_current_break_glass_user_deletion() -> None:
    rows = [{"username": "break-glass", "role": "admin", "enabled": True}]
    with patch.object(access_ops, "_collection", return_value=rows):
        with pytest.raises(access_ops.AccessMutationConflict, match="current break-glass user"):
            access_ops.delete_local_user("break-glass", actor="break-glass")


def test_local_fallback_rejects_last_admin_demotion() -> None:
    rows = [{"username": "break-glass", "role": "admin", "enabled": True, "password_hash": "hash"}]
    with patch.object(access_ops, "_collection", return_value=rows):
        with pytest.raises(access_ops.AccessMutationConflict, match="last enabled break-glass administrator"):
            access_ops.save_local_user({"username": "break-glass", "role": "viewer", "enabled": True}, actor="other-admin")
