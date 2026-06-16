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


connector_ops = importlib.import_module("app.control_plane_connector_ops")
content_ops = importlib.import_module("app.control_plane_content_ops")


class ConnectorMaturityTests(unittest.TestCase):
    def test_connector_overview_ignores_smoke_connectors_for_release_metrics(self) -> None:
        connectors = [
            {
                "id": "endpoint-edr-stream",
                "title": "Endpoint EDR stream",
                "enabled": True,
                "status": "healthy",
                "group": "edr",
                "family": "source",
                "telemetry": {
                    "coverage_score": 92,
                    "parsing_coverage_pct": 95.0,
                    "telemetry_quality_pct": 94.0,
                    "actor_ip_ready": True,
                    "host_telemetry_ready": True,
                    "realtime": True,
                    "evidence_fields": ["src_ip"],
                    "investigation_pivots": ["host", "user"],
                },
                "operations": {
                    "bundle_id": "bundle-edr",
                    "playbooks": ["isolate-host"],
                    "compliance_controls": ["SOC2-CC7"],
                    "runbook_id": "runbook-edr",
                    "onboarding_template": "edr-onboarding",
                },
                "release_gate": {"ready_for_live": True},
            },
            {
                "id": "smoke-webhook-source-1",
                "title": "Smoke webhook source 1",
                "enabled": True,
                "status": "planned",
                "group": "smoke",
                "family": "source",
                "telemetry": {
                    "coverage_score": 0,
                    "parsing_coverage_pct": 0.0,
                    "telemetry_quality_pct": 0.0,
                    "actor_ip_ready": False,
                    "host_telemetry_ready": False,
                    "realtime": False,
                    "evidence_fields": [],
                    "investigation_pivots": [],
                },
                "operations": {},
                "release_gate": {"ready_for_live": False},
            },
        ]
        with patch.object(connector_ops, "list_connector_definitions", return_value=connectors):
            with patch.object(connector_ops, "list_connector_runs", return_value=[]):
                with patch.object(connector_ops, "_list_response_actions", return_value=[]):
                    with patch.object(content_ops, "list_content_bundles", return_value=[]):
                        overview = connector_ops.get_connectors_overview()

        self.assertEqual(1, overview["metrics"]["total"])
        self.assertEqual(2, overview["metrics"]["catalog_total"])
        self.assertEqual(1, overview["metrics"]["ignored_nonprod"])
        self.assertEqual(1, overview["metrics"]["release_gate_ready"])
        self.assertEqual(100.0, overview["posture"]["release_gate_ready_pct"])


if __name__ == "__main__":
    unittest.main()
