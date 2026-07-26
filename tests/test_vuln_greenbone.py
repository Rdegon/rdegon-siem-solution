from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET


os.environ.setdefault("SIEM_CH_HOST", "127.0.0.1")
os.environ.setdefault("SIEM_CH_USER", "default")
os.environ.setdefault("SIEM_CH_PASSWORD", "test")
os.environ.setdefault("SIEM_ADMIN_DEFAULT_PASSWORD", "test")
os.environ.setdefault("SIEM_JWT_SECRET", "test")

from services.web.app import vuln_greenbone  # noqa: E402


def _resources(tag: str, items: dict[str, str]) -> ET.Element:
    root = ET.Element(f"get_{tag}s_response")
    for name, resource_id in items.items():
        node = ET.SubElement(root, tag, {"id": resource_id})
        ET.SubElement(node, "name").text = name
        if tag == "task":
            ET.SubElement(node, "status").text = "Done"
    return root


class _FakeGmp:
    def __init__(self) -> None:
        cfg = vuln_greenbone.CONFIG.greenbone
        self.targets: dict[str, str] = {}
        self.tasks: dict[str, str] = {}
        self.deleted_tasks: list[str] = []
        self.schedules = {
            cfg.daily_schedule_name: "schedule-daily",
            cfg.weekly_schedule_name: "schedule-weekly",
        }

    def get_schedules(self):
        return _resources("schedule", self.schedules)

    def get_scan_configs(self):
        return _resources("config", {"Full and fast": "config-1"})

    def get_scanners(self):
        return _resources("scanner", {"OpenVAS Default": "scanner-1"})

    def get_port_lists(self):
        return _resources("port_list", {"All IANA assigned TCP": "ports-1"})

    def get_targets(self, **_kwargs):
        return _resources("target", self.targets)

    def get_tasks(self, **_kwargs):
        return _resources("task", self.tasks)

    def create_target(self, name, **_kwargs):
        self.targets[name] = "target-created"
        return ET.Element("create_target_response")

    def create_task(self, name, _config_id, target_id, _scanner_id, **_kwargs):
        if not target_id:
            raise ValueError("create_task requires a target_id argument")
        self.tasks[name] = "task-created"
        return ET.Element("create_task_response")

    def modify_target(self, *_args, **_kwargs):
        return ET.Element("modify_target_response")

    def modify_task(self, *_args, **_kwargs):
        return ET.Element("modify_task_response")

    def delete_task(self, task_id):
        self.deleted_tasks.append(task_id)
        return ET.Element("delete_task_response")


class GreenboneSynchronizationTests(unittest.TestCase):
    def test_sync_recovers_created_ids_and_retires_removed_assets(self) -> None:
        fake = _FakeGmp()
        assets = [
            {
                "asset_id": "asset-current",
                "hostname": "current",
                "ip": "10.20.30.10",
                "criticality": "high",
                "environment": "prod",
                "vuln_enabled": True,
                "vuln_profile": "network-basic",
                "tags": [],
            }
        ]
        bindings = {
            "asset-retired": {
                "asset_id": "asset-retired",
                "target_ref": "192.168.1.10",
                "target_id": "target-old",
                "target_name": "old target",
                "task_id": "task-old",
                "task_name": "old task",
                "profile": "network-basic",
                "environment": "prod",
                "sync_status": "synced",
            }
        }

        with patch.object(vuln_greenbone, "_with_gmp", side_effect=lambda function: function(fake)):
            result = vuln_greenbone.sync_assets(assets, bindings)

        current = next(item for item in result["items"] if item["asset_id"] == "asset-current")
        retired = next(item for item in result["items"] if item["asset_id"] == "asset-retired")
        self.assertEqual("target-created", current["target_id"])
        self.assertEqual("task-created", current["task_id"])
        self.assertEqual("retired", retired["sync_status"])
        self.assertEqual("", retired["task_id"])
        self.assertEqual(["task-old"], fake.deleted_tasks)
        self.assertEqual(1, result["synced"])
        self.assertEqual(1, result["retired"])
        self.assertEqual(0, result["failed"])

    def test_empty_reports_are_recorded_and_count_toward_limit(self) -> None:
        class _ReportGmp:
            def __init__(self) -> None:
                self.requested: list[str] = []

            def get_reports(self, **_kwargs):
                root = ET.Element("get_reports_response")
                ET.SubElement(root, "report", {"id": "report-empty-1"})
                ET.SubElement(root, "report", {"id": "report-empty-2"})
                return root

            def get_report(self, report_id, **_kwargs):
                self.requested.append(report_id)
                response = ET.Element("get_reports_response")
                wrapper = ET.SubElement(response, "report", {"id": report_id})
                report = ET.SubElement(wrapper, "report", {"id": report_id})
                task = ET.SubElement(report, "task", {"id": "task-1"})
                ET.SubElement(task, "name").text = "Task 1"
                target = ET.SubElement(task, "target", {"id": "target-1"})
                ET.SubElement(target, "name").text = "10.20.30.10"
                ET.SubElement(report, "scan_start").text = "2026-07-26T03:00:00Z"
                ET.SubElement(report, "scan_end").text = "2026-07-26T03:05:00Z"
                return response

        fake = _ReportGmp()
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch.object(vuln_greenbone, "_with_gmp", side_effect=lambda function: function(fake)):
                with patch.object(
                    vuln_greenbone,
                    "_artifact_path",
                    side_effect=lambda report_id: Path(temp_dir) / f"{report_id}.xml",
                ):
                    result = vuln_greenbone.fetch_completed_reports(
                        imported_report_ids=set(),
                        bindings_by_task={},
                        bindings_by_target={},
                        asset_by_target={},
                        limit=1,
                    )

        self.assertEqual(1, result["imported"])
        self.assertEqual(["report-empty-1"], fake.requested)
        self.assertEqual([], result["imported_runs"][0]["findings"])
        self.assertEqual(0, result["imported_runs"][0]["scan_run"]["finding_count"])


if __name__ == "__main__":
    unittest.main()
