import unittest
from datetime import datetime, timezone
from unittest.mock import patch
import json

from host_runtime_runtime import fetch_host_runtime_last_seen_map, fetch_host_runtime_overview, host_runtime_targets_from_env


class _FakeQueryResult:
    def __init__(self, rows):
        self._rows = rows

    def named_results(self):
        return list(self._rows)


class _FakeClient:
    def __init__(self, rows):
        self._rows = rows
        self.last_query = ""

    def query(self, query_text):  # noqa: ARG002
        self.last_query = str(query_text)
        return _FakeQueryResult(self._rows)


class HostRuntimeRuntimeTests(unittest.TestCase):
    def test_host_runtime_targets_from_env_merges_proxmox_fleet_monitoring_targets(self) -> None:
        fleet_payload = {
            "items": [
                {"source_name": "navidrome-01", "role": "media-node", "ip": "10.20.20.121", "state": "onboardable", "host_runtime_enabled": True},
                {"source_name": "openclaw-gateway", "role": "openclaw-gateway", "ip": "10.20.30.126", "state": "connected", "host_runtime_enabled": True},
                {"source_name": "opnsense-edge-01", "role": "edge-router", "ip": "192.168.1.102", "state": "connected", "host_runtime_enabled": True, "monitoring_supported": False},
                {"source_name": "win-rtx-test", "role": "workstation", "ip": "192.168.1.42", "state": "scan-only", "host_runtime_enabled": False},
                {"source_name": "offline-host", "role": "linux", "ip": "192.168.1.99", "state": "offline", "host_runtime_enabled": True},
            ]
        }
        with patch("host_runtime_runtime.list_proxmox_fleet_inventory", return_value=fleet_payload):
            targets = host_runtime_targets_from_env({})

        host_names = {item["host_name"] for item in targets}
        self.assertIn("siem-ingest", host_names)
        self.assertIn("navidrome-01", host_names)
        self.assertNotIn("openclaw-gateway", host_names)
        self.assertNotIn("opnsense-edge-01", host_names)
        self.assertNotIn("win-rtx-test", host_names)
        self.assertNotIn("offline-host", host_names)

    def test_host_runtime_targets_from_env_keeps_env_targets_and_adds_fleet_targets(self) -> None:
        env = {
            "SIEM_HOST_RUNTIME_TARGETS_JSON": json.dumps(
                [
                    {"host_name": "siem-ingest", "host_role": "ingest", "host_ip": "192.168.1.35"},
                    {"host_name": "siem-processing", "host_role": "processing", "host_ip": "192.168.1.37"},
                ]
            )
        }
        fleet_payload = {
            "items": [
                {"source_name": "nextcloud-siem", "role": "business-app", "ip": "10.20.20.120", "state": "onboardable", "host_runtime_enabled": True},
                {"source_name": "navidrome-01", "role": "media-node", "ip": "10.20.20.121", "state": "onboardable", "host_runtime_enabled": True},
            ]
        }
        with patch("host_runtime_runtime.list_proxmox_fleet_inventory", return_value=fleet_payload):
            targets = host_runtime_targets_from_env(env)

        host_names = {item["host_name"] for item in targets}
        self.assertIn("siem-ingest", host_names)
        self.assertIn("siem-processing", host_names)
        self.assertIn("nextcloud-siem", host_names)
        self.assertIn("navidrome-01", host_names)

    def test_fetch_host_runtime_overview_summarizes_targets(self) -> None:
        rows = [
            {
                "ts": "2026-03-25T10:00:00Z",
                "message": "snapshot",
                "severity": "info",
                "normalized_json": json.dumps(
                    {
                        "provider": "host.metrics",
                        "event": {"type": "host_runtime_snapshot"},
                        "host": {"name": "siem-ingest", "role": "ingest", "ip": "192.168.1.35"},
                        "metrics": {
                            "cpu_pct": 12.0,
                            "memory_used_pct": 41.0,
                            "disk_used_pct": 62.0,
                            "load_ratio": 0.2,
                            "swap_used_pct": 0.0,
                            "inode_used_pct": 12.0,
                            "stale_age_seconds": 0,
                        },
                        "services": [{"name": "siem-ingest", "status": "active"}],
                    }
                ),
            },
            {
                "ts": "2026-03-25T10:01:00Z",
                "message": "memory pressure",
                "severity": "high",
                "normalized_json": json.dumps(
                    {
                        "provider": "host.metrics",
                        "event": {"type": "host_memory_pressure"},
                        "host": {"name": "siem-storage", "role": "storage", "ip": "192.168.1.38"},
                        "metrics": {"memory_used_pct": 91.0},
                    }
                ),
            },
        ]
        with patch("host_runtime_runtime.get_clickhouse_client", return_value=_FakeClient(rows)):
            with patch(
                "host_runtime_runtime.host_runtime_targets_from_env",
                return_value=[{"host_name": "siem-ingest", "host_role": "ingest", "host_ip": "192.168.1.35"}],
            ):
                with patch(
                    "host_runtime_runtime._utc_now",
                    return_value=datetime(2026, 3, 25, 10, 2, 0, tzinfo=timezone.utc),
                ):
                    payload = fetch_host_runtime_overview(hours=6, limit=10)

        self.assertEqual(1, payload["metrics"]["snapshot_events"])
        self.assertEqual(1, payload["metrics"]["alert_events"])
        self.assertEqual("siem-ingest", payload["targets"][0]["host_name"])
        self.assertFalse(payload["targets"][0]["stale"])
        self.assertTrue(payload["healthy"])
        self.assertEqual("healthy", payload["status"])
        self.assertEqual(0, payload["stale_targets"])
        self.assertEqual(1, payload["targets_total"])
        self.assertEqual("2026-03-25T10:00:00Z", payload["latest_snapshot_ts"])

    def test_fetch_host_runtime_overview_marks_old_snapshot_stale(self) -> None:
        rows = [
            {
                "ts": "2026-03-25T10:00:00Z",
                "message": "snapshot",
                "severity": "info",
                "normalized_json": json.dumps(
                    {
                        "provider": "host.metrics",
                        "event": {"type": "host_runtime_snapshot"},
                        "host": {"name": "siem-ingest", "role": "ingest", "ip": "192.168.1.35"},
                        "metrics": {"cpu_pct": 12.0, "memory_used_pct": 41.0, "disk_used_pct": 62.0, "load_ratio": 0.2, "inode_used_pct": 12.0},
                    }
                ),
            }
        ]
        with patch("host_runtime_runtime.get_clickhouse_client", return_value=_FakeClient(rows)):
            with patch(
                "host_runtime_runtime.host_runtime_targets_from_env",
                return_value=[{"host_name": "siem-ingest", "host_role": "ingest", "host_ip": "192.168.1.35"}],
            ):
                with patch(
                    "host_runtime_runtime._utc_now",
                    return_value=datetime(2026, 3, 25, 10, 20, 0, tzinfo=timezone.utc),
                ):
                    with patch.dict("os.environ", {"SIEM_HOST_RUNTIME_STALE_AFTER_SECONDS": "300"}, clear=False):
                        payload = fetch_host_runtime_overview(hours=6, limit=10)

        self.assertTrue(payload["targets"][0]["stale"])
        self.assertGreater(payload["targets"][0]["stale_age_seconds"], 300)
        self.assertEqual(1, payload["metrics"]["stale_targets"])
        self.assertFalse(payload["healthy"])
        self.assertEqual("degraded", payload["status"])
        self.assertEqual(1, payload["stale_targets"])
        self.assertEqual(["1 host runtime targets are stale"], payload["issues"])

    def test_fetch_host_runtime_last_seen_map_returns_latest_snapshots(self) -> None:
        rows = [
            {"ts": "2026-03-25T10:00:00Z", "message": "", "severity": "", "normalized_json": json.dumps({"provider": "host.metrics", "event": {"type": "host_runtime_snapshot"}, "host": {"name": "siem-ingest", "role": "ingest"}})},
            {"ts": "2026-03-25T09:55:00Z", "message": "", "severity": "", "normalized_json": json.dumps({"provider": "host.metrics", "event": {"type": "host_runtime_snapshot"}, "host": {"name": "siem-processing", "role": "processing"}})},
        ]
        with patch("host_runtime_runtime.get_clickhouse_client", return_value=_FakeClient(rows)):
            payload = fetch_host_runtime_last_seen_map(hours=6)

        self.assertEqual("2026-03-25T10:00:00Z", payload["siem-ingest"])
        self.assertEqual("2026-03-25T09:55:00Z", payload["siem-processing"])

    def test_host_runtime_query_supports_live_provider_and_host_fields(self) -> None:
        client = _FakeClient(
            [
                {
                    "ts": "2026-03-25T10:00:00Z",
                    "message": "Host runtime snapshot collected for siem-web",
                    "severity": "info",
                    "normalized_json": json.dumps(
                        {
                            "provider": "host.metrics",
                            "event": {"type": "host_runtime_snapshot"},
                            "host": {"name": "siem-web", "ip": "192.168.1.39"},
                            "metrics": {},
                        }
                    ),
                }
            ]
        )
        with patch("host_runtime_runtime.get_clickhouse_client", return_value=client):
            payload = fetch_host_runtime_last_seen_map(hours=6)

        self.assertEqual("2026-03-25T10:00:00Z", payload["siem-web"])
        self.assertIn('"provider":"host.metrics"', client.last_query)
        self.assertIn("normalized_json", client.last_query)

    def test_fetch_host_runtime_overview_backfills_empty_latest_snapshot(self) -> None:
        rows = [
            {
                "ts": "2026-03-25T10:05:00Z",
                "message": "snapshot",
                "severity": "info",
                "normalized_json": json.dumps(
                    {
                        "provider": "host.metrics",
                        "event": {"type": "host_runtime_snapshot"},
                        "host": {"name": "siem-web", "role": "control-plane", "ip": "192.168.1.39"},
                        "metrics": {},
                        "services": [],
                    }
                ),
            },
            {
                "ts": "2026-03-25T10:02:00Z",
                "message": "snapshot",
                "severity": "info",
                "normalized_json": json.dumps(
                    {
                        "provider": "host.metrics",
                        "event": {"type": "host_runtime_snapshot"},
                        "host": {"name": "siem-web", "role": "control-plane", "ip": "192.168.1.39"},
                        "metrics": {"memory_used_pct": 73.0, "cpu_pct": 14.0},
                        "services": [{"name": "siem-web", "status": "active"}],
                    }
                ),
            },
        ]
        with patch("host_runtime_runtime.get_clickhouse_client", return_value=_FakeClient(rows)):
            with patch(
                "host_runtime_runtime.host_runtime_targets_from_env",
                return_value=[{"host_name": "siem-web", "host_role": "control-plane", "host_ip": "192.168.1.39"}],
            ):
                payload = fetch_host_runtime_overview(hours=6, limit=10)

        self.assertEqual("siem-web", payload["targets"][0]["host_name"])
        self.assertEqual(73.0, payload["targets"][0]["snapshot"]["memory_used_pct"])
        self.assertEqual(1, len(payload["targets"][0]["snapshot"]["services"]))

    def test_fetch_host_runtime_overview_uses_target_ip_when_snapshot_host_ip_is_invalid(self) -> None:
        rows = [
            {
                "ts": "2026-03-25T10:05:00Z",
                "message": "snapshot",
                "severity": "info",
                "normalized_json": json.dumps(
                    {
                        "provider": "host.metrics",
                        "event": {"type": "host_runtime_snapshot"},
                        "host.name": "siem-processing",
                        "host.role": "processing",
                        "host.ip": "siem-processing",
                        "metrics": {"cpu_pct": 9.0},
                    }
                ),
            }
        ]
        with patch("host_runtime_runtime.get_clickhouse_client", return_value=_FakeClient(rows)):
            with patch(
                "host_runtime_runtime.host_runtime_targets_from_env",
                return_value=[{"host_name": "siem-processing", "host_role": "processing", "host_ip": "192.168.1.37"}],
            ):
                payload = fetch_host_runtime_overview(hours=6, limit=10)

        self.assertEqual("192.168.1.37", payload["targets"][0]["snapshot"]["host_ip"])

    def test_fetch_host_runtime_overview_exposes_memory_truth_without_false_pressure(self) -> None:
        rows = [
            {
                "ts": "2026-03-25T10:05:00Z",
                "message": "snapshot",
                "severity": "info",
                "normalized_json": json.dumps(
                    {
                        "provider": "host.metrics",
                        "event": {"type": "host_runtime_snapshot"},
                        "host": {"name": "siem-storage", "role": "storage", "ip": "192.168.1.38"},
                        "metrics": {
                            "memory_used_pct": 86.0,
                            "memory_available_pct": 74.0,
                            "memory_cache_pct": 48.0,
                            "memory_pressure_status": "normal",
                            "swap_used_pct": 0.0,
                        },
                    }
                ),
            }
        ]
        with patch("host_runtime_runtime.get_clickhouse_client", return_value=_FakeClient(rows)):
            with patch(
                "host_runtime_runtime.host_runtime_targets_from_env",
                return_value=[{"host_name": "siem-storage", "host_role": "storage", "host_ip": "192.168.1.38"}],
            ):
                with patch(
                    "host_runtime_runtime._utc_now",
                    return_value=datetime(2026, 3, 25, 10, 6, 0, tzinfo=timezone.utc),
                ):
                    payload = fetch_host_runtime_overview(hours=6, limit=10)

        self.assertEqual(1, payload["metrics"]["cache_heavy_targets"])
        self.assertEqual(0, payload["metrics"]["pressure_targets"])
        self.assertEqual(74.0, payload["metrics"]["avg_memory_available_pct"])
        self.assertEqual(48.0, payload["metrics"]["avg_memory_cache_pct"])
        self.assertIn("Cache-heavy Linux memory usage is expected", payload["memory_truth"]["summary"])
        self.assertEqual([], payload["issues"])


if __name__ == "__main__":
    unittest.main()
