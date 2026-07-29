from __future__ import annotations

import unittest
from unittest.mock import patch

from services.web.app.opnsense_control_runtime import (
    OPNsenseConfig,
    get_opnsense_control_state,
    mutate_firewall,
)


class FakeOPNsenseClient:
    def __init__(self) -> None:
        self.config = OPNsenseConfig(
            base_url="https://opnsense.local",
            api_key="key",
            api_secret="secret",
            username="",
            password="",
            verify_tls=True,
            timeout_seconds=5,
        )
        self.calls: list[tuple[str, str]] = []
        self.backups = ["config-before.xml"]
        self.rollback_rules: list[dict] | None = None
        self.ignore_toggle = False
        self.rules = [
            {
                "uuid": "11111111-1111-1111-1111-111111111111",
                "description": "SIEM managed block",
                "enabled": "1",
                "legacy": None,
                "is_automatic": None,
                "action": "block",
                "interface": "opt5",
                "direction": "in",
                "protocol": "TCP",
                "source_net": "any",
                "source_port": "",
                "destination_net": "10.20.10.104",
                "destination_port": "443",
                "log": "1",
            }
        ]

    def get(self, path: str) -> dict:
        self.calls.append(("GET", path))
        if path == "/api/firewall/filter/search_rule":
            return {"rows": self.rules, "total": len(self.rules)}
        if path == "/api/firewall/alias/search_item":
            return {"rows": [], "total": 0}
        if path == "/api/core/system/status":
            return {"subsystems": {"pf": "OK"}}
        if path == "/api/core/backup/backups/this":
            return {"items": [{"id": item} for item in self.backups]}
        raise AssertionError(path)

    def post(self, path: str, payload: dict | None = None) -> dict:
        self.calls.append(("POST", path))
        if path.startswith("/api/core/backup/revert_backup/"):
            assert self.rollback_rules is not None
            self.rules = [dict(row) for row in self.rollback_rules]
            return {"status": "reverted"}
        if path.startswith("/api/firewall/filter/toggle_rule/"):
            self.rollback_rules = [dict(row) for row in self.rules]
            if not self.ignore_toggle:
                self.rules[0]["enabled"] = "0" if self.rules[0]["enabled"] == "1" else "1"
            self.backups.insert(0, "config-rollback.xml")
            return {"result": "saved"}
        if path == "/api/firewall/filter/apply":
            return {"status": "ok"}
        raise AssertionError(path)


class OPNsenseControlRuntimeTests(unittest.TestCase):
    def test_ngfw_state_is_read_from_device(self) -> None:
        client = FakeOPNsenseClient()
        state = get_opnsense_control_state("ngfw", client=client)
        self.assertTrue(state["available"])
        self.assertEqual(1, state["firewall"]["rules_total"])
        self.assertEqual(1, state["firewall"]["managed_rules"])
        self.assertEqual("api_key", state["auth_mode"])

    @patch("services.web.app.opnsense_control_runtime.append_audit_event")
    def test_toggle_uses_backup_apply_and_verify(self, audit) -> None:
        client = FakeOPNsenseClient()
        result = mutate_firewall(
            "toggle",
            {
                "uuid": "11111111-1111-1111-1111-111111111111",
                "enabled": False,
            },
            actor="admin",
            client=client,
        )
        self.assertEqual("applied", result["status"])
        self.assertTrue(result["verified"])
        self.assertEqual("config-rollback.xml", result["rollback_backup"])
        self.assertIn(("GET", "/api/core/backup/backups/this"), client.calls)
        self.assertIn(("POST", "/api/firewall/filter/apply"), client.calls)
        audit.assert_called_once()

    @patch("services.web.app.opnsense_control_runtime.append_audit_event")
    def test_failed_verification_restores_backup(self, audit) -> None:
        client = FakeOPNsenseClient()
        client.ignore_toggle = True
        with self.assertRaisesRegex(RuntimeError, "could not be verified"):
            mutate_firewall(
                "toggle",
                {
                    "uuid": "11111111-1111-1111-1111-111111111111",
                    "enabled": False,
                },
                actor="admin",
                client=client,
            )
        self.assertIn(
            ("POST", "/api/core/backup/revert_backup/config-rollback.xml"),
            client.calls,
        )
        self.assertEqual("1", client.rules[0]["enabled"])
        audit.assert_called_once()

    @patch("services.web.app.opnsense_control_runtime.append_audit_event")
    def test_unmanaged_rule_cannot_be_changed(self, audit) -> None:
        client = FakeOPNsenseClient()
        client.rules[0]["description"] = "Allow LAN"
        with self.assertRaisesRegex(ValueError, "Only rules with an SOC or SIEM description"):
            mutate_firewall(
                "toggle",
                {
                    "uuid": "11111111-1111-1111-1111-111111111111",
                    "enabled": False,
                },
                actor="admin",
                client=client,
            )
        audit.assert_called_once()


if __name__ == "__main__":
    unittest.main()
