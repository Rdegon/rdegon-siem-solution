import importlib
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
MODULE_DIR = str(ROOT)

if MODULE_DIR not in sys.path:
    sys.path.insert(0, MODULE_DIR)

if "app" not in sys.modules:
    app_module = types.ModuleType("app")
    app_module.__path__ = [MODULE_DIR]  # type: ignore[attr-defined]
    app_module.__file__ = str(ROOT / "__init__.py")
    sys.modules["app"] = app_module

host_access_runtime = importlib.import_module("app.host_access_runtime")


class HostAccessRuntimeTests(unittest.TestCase):
    def test_save_profile_writes_secret_to_vault_and_stores_only_refs(self) -> None:
        rows: list[dict[str, object]] = []

        def save_rows(_collection: str, payload: list[dict[str, object]]) -> None:
            rows.clear()
            rows.extend(payload)

        with patch.object(host_access_runtime, "load_control_plane_rows", return_value=rows), patch.object(
            host_access_runtime,
            "save_control_plane_rows",
            side_effect=save_rows,
        ), patch.object(host_access_runtime, "append_audit_event") as audit_mock, patch.object(
            host_access_runtime,
            "vault_kv_write",
            return_value={"fields": ["password", "private_key"], "status": "configured"},
        ) as vault_mock:
            saved = host_access_runtime.save_host_access_profile(
                {
                    "host_id": "fleet:siem-web",
                    "host_label": "siem-web",
                    "ip": "192.168.1.39",
                    "protocol": "ssh",
                    "username": "rdegon",
                    "password": "do-not-store",
                    "private_key_pem": "PRIVATE KEY MATERIAL",
                },
                actor="tester",
            )

        self.assertEqual("configured", saved["secret_status"])
        self.assertTrue(str(saved["credential_ref"]).startswith("vault://secret/siem/host-access/"))
        self.assertTrue(str(saved["private_key_ref"]).startswith("vault://secret/siem/host-access/"))
        self.assertEqual(["password", "private_key"], saved["secret_fields"])
        self.assertEqual(1, len(rows))
        stored = rows[0]
        self.assertNotIn("password", stored)
        self.assertNotIn("private_key_pem", stored)
        self.assertNotIn("PRIVATE KEY MATERIAL", str(stored))
        vault_mock.assert_called_once()
        written_payload = vault_mock.call_args.args[1]
        self.assertEqual("do-not-store", written_payload["password"])
        self.assertEqual("PRIVATE KEY MATERIAL", written_payload["private_key"])
        audit_mock.assert_called_once()

    def test_save_profile_accepts_reference_without_secret_material(self) -> None:
        rows: list[dict[str, object]] = []

        def save_rows(_collection: str, payload: list[dict[str, object]]) -> None:
            rows.clear()
            rows.extend(payload)

        with patch.object(host_access_runtime, "load_control_plane_rows", return_value=rows), patch.object(
            host_access_runtime,
            "save_control_plane_rows",
            side_effect=save_rows,
        ), patch.object(host_access_runtime, "append_audit_event"), patch.object(host_access_runtime, "vault_kv_write") as vault_mock:
            saved = host_access_runtime.save_host_access_profile(
                {
                    "host_id": "candidate:192-168-1-55",
                    "ip": "192.168.1.55",
                    "protocol": "rdp",
                    "username": "admin",
                    "credential_ref": "vault://secret/siem/host-access/rdp-admin?field=password",
                },
                actor="tester",
            )

        self.assertEqual("reference", saved["secret_status"])
        self.assertEqual(3389, saved["port"])
        vault_mock.assert_not_called()

    def test_list_profiles_is_redacted(self) -> None:
        with patch.object(
            host_access_runtime,
            "load_control_plane_rows",
            return_value=[
                {
                    "profile_id": "profile-1",
                    "host_id": "fleet:siem-web",
                    "ip": "192.168.1.39",
                    "protocol": "ssh",
                    "port": 22,
                    "username": "rdegon",
                    "credential_ref": "vault://secret/siem/host-access/profile-1?field=password",
                    "password": "legacy-leak",
                    "secret_status": "reference",
                }
            ],
        ):
            payload = host_access_runtime.list_host_access_profiles()

        self.assertEqual(1, payload["metrics"]["with_secret_ref"])
        item = payload["items"][0]
        self.assertNotIn("password", item)
        self.assertEqual("vault://secret/siem/host-access/profile-1?field=password", item["credential_ref"])


if __name__ == "__main__":
    unittest.main()
