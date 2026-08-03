import importlib
import os
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_DIR = ROOT / "services" / "web" / "app"


class ControlPlaneSourcePolicyOpsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.previous_control_plane_dir = os.environ.get("SIEM_CONTROL_PLANE_DIR")
        os.environ["SIEM_CONTROL_PLANE_DIR"] = self.temp_dir.name
        self.inserted_module_dir = str(MODULE_DIR) not in sys.path
        if self.inserted_module_dir:
            sys.path.insert(0, str(MODULE_DIR))
        self.previous_modules = {
            name: sys.modules.get(name)
            for name in ("control_plane_source_policy_ops", "enterprise_control_plane")
        }
        for name in ("control_plane_source_policy_ops", "enterprise_control_plane"):
            sys.modules.pop(name, None)
        self.module = importlib.import_module("control_plane_source_policy_ops")

    def tearDown(self) -> None:
        for name in ("control_plane_source_policy_ops", "enterprise_control_plane"):
            sys.modules.pop(name, None)
            if self.previous_modules[name] is not None:
                sys.modules[name] = self.previous_modules[name]
        if self.previous_control_plane_dir is None:
            os.environ.pop("SIEM_CONTROL_PLANE_DIR", None)
        else:
            os.environ["SIEM_CONTROL_PLANE_DIR"] = self.previous_control_plane_dir
        if self.inserted_module_dir and str(MODULE_DIR) in sys.path:
            sys.path.remove(str(MODULE_DIR))
        self.temp_dir.cleanup()

    def test_policy_is_persisted_and_audited(self) -> None:
        policy = self.module.save_source_policy(
            {
                "name": "Windows source freshness",
                "source_pattern": "windows",
                "window_hours": 12,
                "min_events": 5,
                "stale_after_minutes": 20,
                "notifications": ["telegram"],
            },
            actor="tester",
        )

        stored = self.module.list_source_policies()
        audit = self.module.core.list_audit_events(limit=20)

        self.assertEqual(stored[0]["id"], policy["id"])
        self.assertEqual(stored[0]["window_hours"], 12)
        self.assertIn("source_policy.saved", [item["action"] for item in audit["items"]])

    def test_live_evaluation_reports_volume_and_freshness_violations(self) -> None:
        now = datetime(2026, 7, 31, 12, 0, tzinfo=timezone.utc)
        policy = self.module.save_source_policy(
            {
                "name": "Linux telemetry baseline",
                "source_pattern": "linux",
                "min_events": 10,
                "max_events": 100,
                "stale_after_minutes": 30,
            }
        )
        result = self.module.evaluate_source_policies(
            [
                {
                    "source_name": "linux-collector-01",
                    "source_type": "Linux audit",
                    "events": 4,
                    "last_seen": "2026-07-31T10:00:00+00:00",
                },
                {
                    "source_name": "linux-collector-02",
                    "source_type": "Linux audit",
                    "events": 120,
                    "last_seen": "2026-07-31T11:55:00+00:00",
                },
            ],
            policies=[policy],
            now=now,
        )[0]

        self.assertEqual(result["evaluation_status"], "breached")
        self.assertEqual(result["matched_sources"], 2)
        self.assertEqual(result["violation_count"], 2)
        reasons = {item["source_name"]: item["reasons"] for item in result["violations"]}
        self.assertEqual(reasons["linux-collector-01"], ["below_min_events", "stale"])
        self.assertEqual(reasons["linux-collector-02"], ["above_max_events"])

    def test_unmatched_and_disabled_states_are_explicit(self) -> None:
        unmatched = self.module.evaluate_source_policies(
            [],
            policies=[
                {
                    "id": "missing",
                    "name": "Missing",
                    "source_pattern": "not-present",
                    "enabled": True,
                },
                {
                    "id": "disabled",
                    "name": "Disabled",
                    "source_pattern": "anything",
                    "enabled": False,
                },
            ],
        )

        self.assertEqual(unmatched[0]["evaluation_status"], "unmatched")
        self.assertEqual(unmatched[1]["evaluation_status"], "disabled")

    def test_wildcard_policy_matches_all_real_sources(self) -> None:
        result = self.module.evaluate_source_policies(
            [
                {"source_name": "linux-01", "source_type": "Linux audit", "events": 4, "last_seen_ts": "2026-07-31T11:59:00Z"},
                {"source_name": "windows-01", "source_type": "Windows events", "events": 8, "last_event_ts": "2026-07-31T11:59:00Z"},
            ],
            policies=[{
                "id": "all-sources",
                "name": "All sources",
                "source_pattern": "*",
                "enabled": True,
                "min_events": 1,
                "max_events": 0,
                "stale_after_minutes": 30,
            }],
            now=datetime(2026, 7, 31, 12, 0, tzinfo=timezone.utc),
        )[0]

        self.assertEqual(result["matched_sources"], 2)
        self.assertEqual(result["evaluation_status"], "healthy")


if __name__ == "__main__":
    unittest.main()
