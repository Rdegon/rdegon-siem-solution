import os
import tempfile
import unittest
from unittest.mock import patch

import control_plane_access_ops as access_ops


class _FakeKeycloakRuntime:
    def __init__(self) -> None:
        self.created_groups: list[str] = []
        self.applied_group_names: list[str] = []
        self._existing_groups = [{"id": "g-manual", "name": "siem-admins", "path": "/siem-admins"}]

    def list_users(self, *, search: str = "", limit: int = 50):
        if search.lower() == "alice":
            return [{"id": "kc-user-1", "username": "alice"}]
        return []

    def list_groups(self):
        return list(self._existing_groups)

    def save_group(self, payload, *, actor: str = "system", group_id: str = ""):
        group_name = str(payload.get("name") or "")
        self.created_groups.append(group_name)
        item = {"id": f"g-{group_name}", "name": group_name, "path": f"/{group_name}"}
        self._existing_groups.append(item)
        return item

    def get_user(self, user_id: str):
        return {
            "id": user_id,
            "username": "alice",
            "groups": [{"id": "g-manual", "name": "siem-admins"}],
        }

    def set_user_groups(self, user_id: str, payload, *, actor: str = "system"):
        self.applied_group_names = list(payload.get("group_names") or [])
        return {"id": user_id, "username": "alice", "groups": [{"name": name} for name in self.applied_group_names]}


class AccessGrantTests(unittest.TestCase):
    def test_list_access_systems_excludes_proxmox_from_grantable_inventory(self) -> None:
        items = access_ops.list_access_systems(grantable_only=True)
        self.assertNotIn("proxmox", {item["id"] for item in items})
        self.assertIn("siem", {item["id"] for item in items})

    def test_resolve_keycloak_principal_access_requires_explicit_siem_grant(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch.dict(os.environ, {"SIEM_CONTROL_PLANE_DIR": temp_dir}, clear=False):
                payload = access_ops.resolve_keycloak_principal_access("alice")
        self.assertFalse(payload["allowed"])
        self.assertEqual("siem_grant_missing", payload["reason"])

    def test_save_access_grant_mirrors_groups_and_resolves_permissions(self) -> None:
        runtime = _FakeKeycloakRuntime()
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch.dict(os.environ, {"SIEM_CONTROL_PLANE_DIR": temp_dir}, clear=False):
                with patch("control_plane_access_ops._keycloak_runtime", return_value=runtime):
                    saved = access_ops.save_access_grant(
                        {
                            "principal_kind": "keycloak_user",
                            "principal_id": "alice",
                            "system_id": "siem",
                            "role": "admin",
                            "sections": ["overview", "events", "access"],
                            "enabled": True,
                        },
                        actor="tester",
                    )
                    resolved = access_ops.resolve_keycloak_principal_access("alice")

        self.assertEqual("mirrored", saved["sync_status"])
        self.assertTrue(resolved["allowed"])
        self.assertEqual("admin", resolved["role"])
        self.assertEqual(["access", "events", "overview"], sorted(resolved["section_access"]))
        self.assertIn("dashboard:view", set(resolved["permissions"]))
        self.assertIn("events:view", set(resolved["permissions"]))
        self.assertIn("auth:view", set(resolved["permissions"]))
        self.assertIn("auth:write", set(resolved["permissions"]))
        self.assertIn("siem-admins", runtime.applied_group_names)
        self.assertIn("sys:siem:role:admin", runtime.applied_group_names)
        self.assertIn("sys:siem:section:overview", runtime.applied_group_names)
        self.assertIn("sys:siem:section:events", runtime.applied_group_names)
        self.assertIn("sys:siem:section:access", runtime.applied_group_names)

    def test_vuln_section_grant_includes_vulnerability_runtime_permission(self) -> None:
        runtime = _FakeKeycloakRuntime()
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch.dict(os.environ, {"SIEM_CONTROL_PLANE_DIR": temp_dir}, clear=False):
                with patch("control_plane_access_ops._keycloak_runtime", return_value=runtime):
                    access_ops.save_access_grant(
                        {
                            "principal_kind": "keycloak_user",
                            "principal_id": "alice",
                            "system_id": "siem",
                            "role": "analyst",
                            "sections": ["overview", "vuln"],
                            "enabled": True,
                        },
                        actor="tester",
                    )
                    resolved = access_ops.resolve_keycloak_principal_access("alice")

        self.assertTrue(resolved["allowed"])
        self.assertEqual(["overview", "vuln"], sorted(resolved["section_access"]))
        self.assertIn("resources:view", set(resolved["permissions"]))
        self.assertIn("vuln:operate", set(resolved["permissions"]))

    def test_nextcloud_admin_grant_adds_compatibility_groups(self) -> None:
        runtime = _FakeKeycloakRuntime()
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch.dict(os.environ, {"SIEM_CONTROL_PLANE_DIR": temp_dir}, clear=False):
                with patch("control_plane_access_ops._keycloak_runtime", return_value=runtime):
                    access_ops.save_access_grant(
                        {
                            "principal_kind": "keycloak_user",
                            "principal_id": "alice",
                            "system_id": "nextcloud",
                            "role": "admin",
                            "sections": ["files", "admin"],
                            "enabled": True,
                        },
                        actor="tester",
                    )
        self.assertIn("sys:nextcloud:role:admin", runtime.applied_group_names)
        self.assertIn("sys:nextcloud:section:files", runtime.applied_group_names)
        self.assertIn("nextcloud-users", runtime.applied_group_names)
        self.assertIn("nextcloud-admins", runtime.applied_group_names)

    def test_gitea_and_navidrome_grants_add_expected_group_mirrors(self) -> None:
        runtime = _FakeKeycloakRuntime()
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch.dict(os.environ, {"SIEM_CONTROL_PLANE_DIR": temp_dir}, clear=False):
                with patch("control_plane_access_ops._keycloak_runtime", return_value=runtime):
                    access_ops.save_access_grant(
                        {
                            "principal_kind": "keycloak_user",
                            "principal_id": "alice",
                            "system_id": "gitea",
                            "role": "admin",
                            "sections": ["repos", "admin"],
                            "enabled": True,
                        },
                        actor="tester",
                    )
                    access_ops.save_access_grant(
                        {
                            "principal_kind": "keycloak_user",
                            "principal_id": "alice",
                            "system_id": "navidrome",
                            "role": "user",
                            "sections": ["library", "sharing"],
                            "enabled": True,
                        },
                        actor="tester",
                    )
        self.assertIn("sys:gitea:role:admin", runtime.applied_group_names)
        self.assertIn("sys:gitea:section:repos", runtime.applied_group_names)
        self.assertIn("gitea-users", runtime.applied_group_names)
        self.assertIn("gitea-admins", runtime.applied_group_names)
        self.assertIn("sys:navidrome:role:user", runtime.applied_group_names)
        self.assertIn("sys:navidrome:section:library", runtime.applied_group_names)
        self.assertIn("navidrome-users", runtime.applied_group_names)


if __name__ == "__main__":
    unittest.main()
