import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PACK_PATH = ROOT / "correlation_rule_packs" / "host_runtime_observability_v1.json"


class HostRuntimeRulePackTests(unittest.TestCase):
    def test_rule_pack_exists_and_has_expected_shape(self) -> None:
        payload = json.loads(PACK_PATH.read_text(encoding="utf-8"))

        self.assertEqual(payload["pack_id"], "host-runtime-observability-v1")
        self.assertEqual(payload["status"], "active")
        self.assertGreaterEqual(len(payload["stream_rules"]), 10)
        self.assertGreaterEqual(len(payload["batch_rules"]), 4)

    def test_stream_rules_target_host_metrics_event_family(self) -> None:
        payload = json.loads(PACK_PATH.read_text(encoding="utf-8"))
        stream_rules = payload["stream_rules"]
        ids = {int(rule["id"]) for rule in stream_rules}

        self.assertEqual(len(ids), len(stream_rules))
        for rule in stream_rules:
            self.assertEqual(rule["entity_field"], "host.name")
            self.assertIn("event.provider: host.metrics", rule["sigma_yaml"])
            self.assertIn("event.type: host_", rule["sigma_yaml"])


if __name__ == "__main__":
    unittest.main()
