from __future__ import annotations

import importlib
import os
import sys
import types
import unittest
from unittest import mock
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

os.environ.setdefault("SIEM_CH_HOST", "127.0.0.1")
os.environ.setdefault("SIEM_CH_USER", "default")
os.environ.setdefault("SIEM_CH_PASSWORD", "test-password")
os.environ.setdefault("SIEM_ADMIN_DEFAULT_PASSWORD", "test-password")
os.environ.setdefault("SIEM_JWT_SECRET", "test-jwt-secret")

builder = importlib.import_module("deploy.build_assignment_detection_pack")


def _row(source_id: str, logic: str, sources: str = "auth.log/sudo") -> dict[str, str]:
    return {
        "section": "Unit test",
        "source_id": source_id,
        "title": "Unit test rule",
        "scope": "Unit test scope",
        "sources": sources,
        "logic": logic,
        "severity": "medium",
        "response": "Review event",
    }


class AssignmentDetectionPackTests(unittest.TestCase):
    def test_keyword_linux_rule_gets_guarded_stream_expr(self) -> None:
        rows = [_row("AUTH-007", "message contains 'sudo:' AND 'COMMAND='")]

        pack = builder.build_pack(rows, active_source_ids={"AUTH-007"})

        self.assertEqual(1, len(pack["stream_rules"]))
        rule = pack["stream_rules"][0]
        self.assertEqual("active", rule["status"])
        self.assertEqual("stream-expr", rule["source_format"])
        self.assertIn("allowlist:", rule["expr"])
        self.assertIn("event.provider == 'linux.sudo'", rule["expr"])
        self.assertIn("event.type == 'sudo_command'", rule["expr"])
        self.assertNotIn("auth.log/sudo", rule["expr"])

    def test_windows_structured_rule_gets_guarded_stream_expr_without_manual_publish_flag(self) -> None:
        rows = [
            _row(
                "WIN-003",
                "EventID=4624 AND LogonType=10",
                sources="Windows Security Event via agent",
            )
        ]

        pack = builder.build_pack(rows, active_source_ids={"WIN-003"})

        self.assertEqual(1, len(pack["stream_rules"]))
        rule = pack["stream_rules"][0]
        self.assertEqual("active", rule["status"])
        self.assertEqual("stream-expr", rule["source_format"])
        self.assertEqual(["windows"], rule["asset_groups"])
        self.assertIn("event.provider == 'windows.security'", rule["expr"])
        self.assertIn("auth.logon_type == '10'", rule["expr"])
        self.assertIn("RdegonSIEMCollector", rule["expr"])

    def test_windows_structured_rule_can_publish_with_manual_publish_flag(self) -> None:
        rows = [
            _row(
                "WIN-003",
                "EventID=4624 AND LogonType=10",
                sources="Windows Security Event via agent",
            )
        ]

        pack = builder.build_pack(
            rows,
            active_source_ids={"WIN-003"},
            active_overrides={"WIN-003": {"publish_generated_sigma": True}},
        )

        self.assertEqual(1, len(pack["stream_rules"]))
        rule = pack["stream_rules"][0]
        self.assertEqual("active", rule["status"])
        self.assertEqual("sigma", rule["source_format"])
        self.assertIn("event.code: '4624'", rule["sigma_yaml"])
        self.assertIn("auth.logon_type: '10'", rule["sigma_yaml"])
        self.assertNotIn("keywords:", rule["sigma_yaml"])
        self.assertEqual(["windows"], rule["asset_groups"])
        self.assertIn("asset_group.windows", rule["sigma_yaml"])

    def test_publisher_deduplicates_asset_group_tags_from_sigma(self) -> None:
        fake_deps = types.ModuleType("deps")
        fake_deps.convert_sigma_to_stream_rule = lambda *args, **kwargs: {"tags": "asset_group.windows"}
        sys.modules.pop("deploy.publish_assignment_detection_pack", None)

        with mock.patch.dict(sys.modules, {"deps": fake_deps}):
            publisher = importlib.import_module("deploy.publish_assignment_detection_pack")
            published = publisher._publish_stream_rule(
                {
                    "id": 8395,
                    "source_id": "WIN-003",
                    "status": "active",
                    "severity": "medium",
                    "sigma_yaml": "title: Unit test\n",
                    "asset_groups": ["windows"],
                },
                pack_id="unit-test",
            )

        tags = str(published["tags"]).split(",")
        self.assertEqual(1, tags.count("asset_group.windows"))

    def test_explicit_stream_expr_override_publishes_non_windows_rule(self) -> None:
        rows = [_row("AUTH-007", "message contains 'sudo:' AND 'COMMAND='")]

        pack = builder.build_pack(
            rows,
            active_overrides={
                "AUTH-007": {
                    "expr": "event.type == 'sudo_command' and event.original icontains 'COMMAND='",
                    "threshold": 2,
                }
            },
        )

        self.assertEqual(1, len(pack["stream_rules"]))
        rule = pack["stream_rules"][0]
        self.assertEqual("stream-expr", rule["source_format"])
        self.assertEqual("event.type == 'sudo_command' and event.original icontains 'COMMAND='", rule["expr"])
        self.assertEqual(2, rule["threshold"])
        self.assertNotIn("sigma_yaml", rule)

    def test_batch_override_can_extend_dedupe_window_without_widening_detection_window(self) -> None:
        rows = [_row("HB-006", "count > 3 in 5m baseline known_host inventory")]

        pack = builder.build_pack(
            rows,
            active_overrides={"HB-006": {"threshold": 4, "dedupe_window_s": 86400}},
        )

        self.assertEqual(1, len(pack["batch_rules"]))
        rule = pack["batch_rules"][0]
        self.assertEqual(300, rule["window_s"])
        self.assertIn("ts >= now() - INTERVAL {WINDOW_S} SECOND", rule["sql_template"])
        self.assertIn("ts_last >= now() - INTERVAL 86400 SECOND", rule["sql_template"])

    def test_numeric_asset_markers_do_not_match_inside_event_ids(self) -> None:
        rows = [
            _row(
                "WIN-011",
                "EventID=1102",
                sources="Windows Security Event via agent",
            )
        ]

        pack = builder.build_pack(
            rows,
            active_source_ids={"WIN-011"},
            active_overrides={"WIN-011": {"publish_generated_sigma": True}},
        )

        rule = pack["stream_rules"][0]
        self.assertEqual(["windows"], rule["asset_groups"])
        self.assertNotIn("asset_group.edge_gateway", rule["sigma_yaml"])

    def test_asset_groups_are_attached_to_catalog_rules(self) -> None:
        rows = [
            _row("PVE-001", "action in [qmcreate, create VM]", sources="Proxmox task log/syslog/API audit"),
            _row("IAM-001", "Keycloak admin login", sources="Keycloak audit"),
            _row("NC-001", "Nextcloud admin login", sources="Nextcloud app logs"),
            _row("MC-001", "Minecraft server stopped", sources="minecraft logs"),
        ]

        pack = builder.build_pack(rows)

        self.assertIn("asset_groups", pack)
        by_id = {rule["source_id"]: rule for rule in [*pack["stream_rules"], *pack["batch_rules"]]}
        self.assertIn("proxmox", by_id["PVE-001"]["asset_groups"])
        self.assertIn("identity", by_id["IAM-001"]["asset_groups"])
        self.assertIn("public_services", by_id["NC-001"]["asset_groups"])
        self.assertIn("game", by_id["MC-001"]["asset_groups"])


if __name__ == "__main__":
    unittest.main()
