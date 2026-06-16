import json
import unittest

from host_runtime_pipeline import build_snapshot_event
from services.filter.worker import FilterWorker
from services.normalizer.normalizer_core import apply_rules
from services.normalizer.worker import _transport_field_value
from writer_worker import WriterSettings, WriterWorker


class HostRuntimeEventRoundtripTests(unittest.TestCase):
    def test_host_runtime_metrics_survive_normalizer_and_writer_roundtrip(self) -> None:
        snapshot = {
            "generated_ts": "2026-03-27T10:00:00Z",
            "host_name": "siem-web",
            "host_role": "control-plane",
            "primary_ip": "192.168.1.39",
            "metrics": {
                "cpu_pct": 12.4,
                "memory_used_pct": 19.3,
                "disk_used_pct": 41.8,
                "load_ratio": 0.22,
            },
            "services": [{"name": "siem-web", "status": "active"}],
        }

        raw_event = build_snapshot_event(snapshot)
        raw_event["details"] = {"heartbeat": True, "source": "unit-test"}
        uem = apply_rules([], raw_event)

        self.assertIsNotNone(uem)
        assert uem is not None
        self.assertEqual(19.3, uem["metrics"]["memory_used_pct"])
        self.assertEqual("control-plane", uem["host.role"])
        self.assertEqual("192.168.1.39", uem["host.ip"])

        transport_fields = {key: _transport_field_value(value) for key, value in uem.items()}
        worker = WriterWorker(WriterSettings())
        payload = json.loads(worker._build_normalized_json(transport_fields))

        self.assertEqual("host.metrics", payload["provider"])
        self.assertEqual("control-plane", payload["host.role"])
        self.assertEqual("192.168.1.39", payload["host.ip"])
        self.assertEqual(19.3, payload["metrics"]["memory_used_pct"])
        self.assertEqual("siem-web", payload["services"][0]["name"])
        self.assertTrue(payload["details"]["heartbeat"])

    def test_host_runtime_metrics_survive_filter_transport_step(self) -> None:
        snapshot = {
            "generated_ts": "2026-03-27T10:00:00Z",
            "host_name": "siem-web",
            "host_role": "control-plane",
            "primary_ip": "192.168.1.39",
            "metrics": {
                "cpu_pct": 12.4,
                "memory_used_pct": 19.3,
                "disk_used_pct": 41.8,
                "load_ratio": 0.22,
            },
            "services": [{"name": "siem-web", "status": "active"}],
        }

        raw_event = build_snapshot_event(snapshot)
        raw_event["details"] = {"heartbeat": True, "source": "unit-test"}
        normalized = apply_rules([], raw_event)

        self.assertIsNotNone(normalized)
        assert normalized is not None

        filter_worker = FilterWorker.__new__(FilterWorker)
        filter_worker._rules = []
        _, filtered = FilterWorker.apply_rules(filter_worker, {key: _transport_field_value(value) for key, value in normalized.items()})
        worker = WriterWorker(WriterSettings())
        payload = json.loads(worker._build_normalized_json({key: _transport_field_value(value) for key, value in filtered.items()}))

        self.assertEqual(19.3, payload["metrics"]["memory_used_pct"])
        self.assertEqual("siem-web", payload["services"][0]["name"])
        self.assertTrue(payload["details"]["heartbeat"])


if __name__ == "__main__":
    unittest.main()
