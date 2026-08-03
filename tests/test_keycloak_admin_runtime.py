import importlib
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


class KeycloakAdminRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        sys.modules.pop("keycloak_admin_runtime", None)
        self.runtime = importlib.import_module("keycloak_admin_runtime")

    def tearDown(self) -> None:
        sys.modules.pop("keycloak_admin_runtime", None)

    def test_status_reports_inventory_when_admin_runtime_is_ready(self) -> None:
        with patch.dict(
            "os.environ",
            {
                "SIEM_KEYCLOAK_BASE_URL": "https://sso.example.test",
                "SIEM_KEYCLOAK_REALM": "siem",
                "SIEM_KEYCLOAK_ADMIN_CLIENT_ID": "siem-keycloak-admin",
            },
            clear=False,
        ):
            with patch("keycloak_admin_runtime.resolve_secret_value", return_value=("secret", "vault://keycloak", {})):
                with patch("keycloak_admin_runtime.provider_status", return_value={"healthy": True, "issues": []}):
                    with patch("keycloak_admin_runtime._token_payload", return_value=("token", "client_credentials")):
                        with patch("keycloak_admin_runtime.list_users", return_value=[{"id": "u1"}]):
                            with patch("keycloak_admin_runtime.list_groups", return_value=[{"id": "g1"}, {"id": "g2"}]):
                                with patch("keycloak_admin_runtime.list_roles", return_value=[{"name": "admin"}]):
                                    with patch("keycloak_admin_runtime.list_clients", return_value=[{"client_id": "siem-web"}]):
                                        payload = self.runtime.status()

        self.assertTrue(payload["healthy"])
        self.assertTrue(payload["admin_ready"])
        self.assertEqual(1, payload["inventory"]["users"])
        self.assertEqual(2, payload["inventory"]["groups"])

    def test_create_user_follows_detail_and_audit_flow(self) -> None:
        calls = []

        def fake_request(path_or_url: str, *, method: str = "GET", payload=None, token: str = "", form=None):
            calls.append((path_or_url, method, payload, token, form))
            if path_or_url == "/users" and method == "POST":
                return 201, {}, {"location": "https://sso.example.test/admin/realms/siem/users/user-1"}
            raise AssertionError(f"Unexpected request: {path_or_url} {method}")

        detail = {
            "id": "user-1",
            "username": "alice",
            "groups": [{"name": "siem-analyst"}],
            "roles": [{"name": "analyst"}],
        }
        with patch("keycloak_admin_runtime._auth_token", return_value="token"):
            with patch("keycloak_admin_runtime._request", side_effect=fake_request):
                with patch("keycloak_admin_runtime.set_user_password") as set_password:
                    with patch("keycloak_admin_runtime.set_user_groups") as set_groups:
                        with patch("keycloak_admin_runtime.set_user_roles") as set_roles:
                            with patch("keycloak_admin_runtime.get_user", return_value=detail):
                                with patch("keycloak_admin_runtime.append_audit_event") as append_audit_event:
                                    payload = self.runtime.create_user(
                                        {
                                            "username": "alice",
                                            "email": "alice@example.test",
                                            "password": "secret",
                                            "group_names": ["siem-analyst"],
                                            "roles": ["analyst"],
                                        },
                                        actor="tester",
                                    )

        self.assertEqual("alice", payload["username"])
        set_password.assert_called_once()
        set_groups.assert_called_once()
        set_roles.assert_called_once()
        append_audit_event.assert_called_once()
        self.assertEqual("/users", calls[0][0])

    def test_rotate_client_secret_returns_rotated_value(self) -> None:
        with patch("keycloak_admin_runtime._find_client", return_value={"id": "client-1", "clientId": "nextcloud"}):
            with patch("keycloak_admin_runtime._auth_token", return_value="token"):
                with patch("keycloak_admin_runtime._request", return_value=(200, {"type": "secret", "value": "rotated"}, {})):
                    with patch("keycloak_admin_runtime.append_audit_event") as append_audit_event:
                        payload = self.runtime.rotate_client_secret("nextcloud", actor="tester")

        self.assertEqual("nextcloud", payload["client_id"])
        self.assertEqual("rotated", payload["secret"])
        append_audit_event.assert_called_once()

    def test_update_user_applies_an_explicit_empty_role_set(self) -> None:
        current = {
            "id": "user-1",
            "username": "alice",
            "enabled": True,
            "roles": [{"id": "role-1", "name": "analyst"}],
            "groups": [],
            "attributes": {},
        }
        updated = {**current, "roles": []}
        with patch("keycloak_admin_runtime.get_user", side_effect=[current, updated]):
            with patch("keycloak_admin_runtime._auth_token", return_value="token"):
                with patch("keycloak_admin_runtime._request", return_value=(204, {}, {})):
                    with patch("keycloak_admin_runtime.set_user_roles", return_value=updated) as set_roles:
                        with patch("keycloak_admin_runtime.append_audit_event"):
                            payload = self.runtime.update_user("user-1", {"roles": []}, actor="admin")

        self.assertEqual([], payload["roles"])
        set_roles.assert_called_once_with("user-1", {"roles": []}, actor="admin")

    def test_set_user_roles_rejects_unknown_roles(self) -> None:
        with patch("keycloak_admin_runtime.list_roles", return_value=[{"id": "role-1", "name": "viewer"}]):
            with patch("keycloak_admin_runtime.get_user", return_value={"id": "user-1", "username": "alice", "roles": []}):
                with self.assertRaisesRegex(ValueError, "Unknown Keycloak realm roles"):
                    self.runtime.set_user_roles("user-1", {"roles": ["made-up-role"]}, actor="admin")

    def test_delete_user_rejects_current_principal(self) -> None:
        detail = {"id": "user-1", "username": "alice", "enabled": True, "roles": []}
        with patch("keycloak_admin_runtime.get_user", return_value=detail):
            with patch("keycloak_admin_runtime._request") as request:
                with self.assertRaisesRegex(RuntimeError, "currently authenticated"):
                    self.runtime.delete_user("user-1", actor="alice")
        request.assert_not_called()

    def test_delete_user_rejects_last_enabled_realm_admin(self) -> None:
        detail = {
            "id": "user-1",
            "username": "alice",
            "enabled": True,
            "roles": [{"id": "role-admin", "name": "admin"}],
        }
        with patch("keycloak_admin_runtime.get_user", return_value=detail):
            with patch("keycloak_admin_runtime._active_admin_users", return_value=[detail], create=True):
                with patch("keycloak_admin_runtime._request") as request:
                    with self.assertRaisesRegex(RuntimeError, "last enabled administrator"):
                        self.runtime.delete_user("user-1", actor="break-glass-admin")
        request.assert_not_called()


if __name__ == "__main__":
    unittest.main()
