import importlib
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_DIR = ROOT / "services" / "web" / "app"


class ControlPlaneReportOpsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.previous_control_plane_dir = os.environ.get("SIEM_CONTROL_PLANE_DIR")
        os.environ["SIEM_CONTROL_PLANE_DIR"] = self.temp_dir.name
        self.inserted_module_dir = str(MODULE_DIR) not in sys.path
        if self.inserted_module_dir:
            sys.path.insert(0, str(MODULE_DIR))
        self.previous_modules = {
            name: sys.modules.get(name)
            for name in ("control_plane_report_ops", "enterprise_control_plane")
        }
        for name in ("control_plane_report_ops", "enterprise_control_plane"):
            sys.modules.pop(name, None)
        self.module = importlib.import_module("control_plane_report_ops")

    def tearDown(self) -> None:
        for name in ("control_plane_report_ops", "enterprise_control_plane"):
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

    def test_template_is_persisted_and_audited(self) -> None:
        template = self.module.save_report_template(
            {
                "name": "Custom SOC daily",
                "period": "24h",
                "sections": ["executive_summary", "sources"],
                "formats": ["json", "csv"],
                "schedule": {
                    "enabled": True,
                    "frequency": "daily",
                    "time": "08:00",
                    "timezone": "Europe/Moscow",
                    "recipients": ["soc@example.org"],
                },
            },
            actor="tester",
        )

        fetched = self.module.get_report_template(template["id"])
        audit = self.module.core.list_audit_events(limit=20)

        self.assertEqual(fetched["name"], "Custom SOC daily")
        self.assertTrue(fetched["schedule"]["enabled"])
        self.assertIn("report_template.saved", [item["action"] for item in audit["items"]])

    def test_report_run_uses_real_section_contract_and_list_is_lightweight(self) -> None:
        template = self.module.save_report_template(
            {
                "name": "E2E report",
                "period": "12h",
                "sections": ["executive_summary", "sources"],
                "formats": ["json", "csv"],
            },
            actor="tester",
        )
        run = self.module.generate_report_run(
            template["id"],
            actor="tester",
            tenant_scope=["main"],
            loaders={
                "executive_summary": lambda: {"metrics": {"events": 42}},
                "sources": lambda: [
                    {"source": "windows", "events": 24},
                    {"source": "linux", "events": 18},
                ],
            },
        )
        summaries = self.module.list_report_runs()
        detail = self.module.get_report_run(run["id"])

        self.assertEqual(run["status"], "completed")
        self.assertEqual(run["record_count"], 3)
        self.assertEqual(run["tenant_scope"], ["main"])
        self.assertNotIn("snapshot", summaries[0])
        self.assertEqual(detail["snapshot"]["sources"][0]["source"], "windows")
        self.assertIn("executive_summary", self.module.report_run_csv(detail))
        self.assertEqual(json.loads(self.module.report_run_json(detail))["id"], run["id"])

    def test_report_run_preserves_partial_results(self) -> None:
        template = self.module.save_report_template(
            {
                "name": "Partial report",
                "period": "24h",
                "sections": ["sources", "platform"],
                "formats": ["json"],
            }
        )

        def fail_platform():
            raise RuntimeError("platform unavailable")

        run = self.module.generate_report_run(
            template["id"],
            loaders={
                "sources": lambda: [{"source": "syslog"}],
                "platform": fail_platform,
            },
        )

        self.assertEqual(run["status"], "completed_with_warnings")
        self.assertEqual(run["section_count"], 1)
        self.assertEqual(run["errors"][0]["section"], "platform")

    def test_due_scheduler_generates_each_schedule_slot_once(self) -> None:
        template = self.module.save_report_template(
            {
                "name": "Scheduled source health",
                "period": "24h",
                "sections": ["sources"],
                "formats": ["json"],
                "schedule": {
                    "enabled": True,
                    "frequency": "daily",
                    "time": "00:00",
                    "timezone": "UTC",
                },
            }
        )
        now = datetime.now(timezone.utc).replace(hour=12, minute=0, second=0, microsecond=0)
        first = self.module.run_due_report_templates(
            now=now,
            loaders={"sources": lambda: [{"source": "linux", "events": 12}]},
        )
        second = self.module.run_due_report_templates(
            now=now,
            loaders={"sources": lambda: [{"source": "linux", "events": 12}]},
        )

        self.assertEqual([template["id"]], [item["template_id"] for item in first["generated"]])
        self.assertEqual([], second["generated"])
        self.assertIn(
            {"template_id": template["id"], "reason": "slot_already_generated"},
            second["skipped"],
        )


if __name__ == "__main__":
    unittest.main()
