from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import correlation_pack_runtime as runtime


class CorrelationPackRuntimeTests(unittest.TestCase):
    def test_validate_pack_reports_missing_sigma(self) -> None:
        payload = {
            "pack_id": "test-pack",
            "title": "Test pack",
            "stream_rules": [
                {
                    "id": 1,
                    "title": "Broken rule",
                    "severity": "medium",
                    "window_s": 300,
                    "threshold": 1,
                    "entity_field": "host.name",
                    "suppression_key": "host.name + service.name",
                    "status": "draft",
                    "operator_action": "Inspect it",
                    "sigma_yaml": "",
                }
            ],
        }
        result = runtime.validate_correlation_pack(payload=payload)
        self.assertFalse(result["valid"])
        self.assertTrue(any("sigma_yaml or expr is required" in item for item in result["errors"]))

    def test_validate_pack_accepts_direct_stream_expr(self) -> None:
        payload = {
            "pack_id": "test-pack",
            "title": "Test pack",
            "stream_rules": [
                {
                    "id": 1,
                    "title": "Direct rule",
                    "severity": "medium",
                    "window_s": 300,
                    "threshold": 1,
                    "entity_field": "host.name",
                    "suppression_key": "host.name + service.name",
                    "status": "active",
                    "operator_action": "Inspect it",
                    "expr": "event.type == 'unit_test'",
                }
            ],
        }

        result = runtime.validate_correlation_pack(payload=payload)

        self.assertTrue(result["valid"])

    def test_save_and_list_pack_roundtrip(self) -> None:
        payload = {
            "pack_id": "test-pack",
            "title": "Test pack",
            "stream_rules": [
                {
                    "id": 1,
                    "title": "Working rule",
                    "severity": "medium",
                    "window_s": 300,
                    "threshold": 1,
                    "entity_field": "host.name",
                    "suppression_key": "host.name + service.name",
                    "status": "active",
                    "operator_action": "Inspect it",
                    "sigma_yaml": "title: Working rule\nid: sigma-working-rule\nstatus: experimental\nlogsource:\n  product: custom\n  service: runtime\ndetection:\n  selection:\n    event.provider: custom.runtime\n  condition: selection\nlevel: medium\n",
                }
            ],
            "batch_rules": [],
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch.object(runtime, "PACK_DIR", Path(temp_dir)):
                saved = runtime.save_correlation_pack(payload, actor="tester")
                listed = runtime.list_correlation_packs()
        self.assertEqual("test-pack", saved["pack_id"])
        self.assertEqual(1, len(listed))
        self.assertEqual("test-pack", listed[0]["pack_id"])


if __name__ == "__main__":
    unittest.main()
