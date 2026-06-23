import importlib
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


class QueryOperationalFilterTests(unittest.TestCase):
    def test_shared_marker_policy_catches_extended_test_runtime_residue(self) -> None:
        filters = importlib.import_module("operational_filters")

        self.assertTrue(filters.is_non_operational_record({"source": "vm1-smoke"}))
        self.assertTrue(filters.is_non_operational_record({"source": "collector-bench-syslog-app-siem-vm1-w1"}))
        self.assertTrue(filters.is_non_operational_record({"source": "e2e-correlation-assignment-full-batch-e2e-20260515"}))
        self.assertTrue(filters.is_non_operational_record({"entity_key": "openclaw-gateway-e2e-assignment-full-batch-e2e"}))
        self.assertTrue(filters.is_non_operational_record({"title": "pve validation"}))
        self.assertTrue(filters.is_non_operational_record({"indicator": "203.0.113.44", "tags": ["lab"]}))
        self.assertTrue(filters.is_non_operational_record({"connector_id": "demo-router"}))
        self.assertFalse(filters.is_non_operational_record({"source": "siem-web", "message": "production audit event"}))

    def test_sources_filters_non_operational_records_and_sanitizes_collectors(self) -> None:
        sources_module = importlib.import_module("query.sources")
        sources_module._CACHE.clear()

        class FakeDeps:
            @staticmethod
            def fetch_source_inventory(*, limit: int, hours: int):
                return [
                    {"source_name": "linux-prod-01", "events": 24},
                    {"source_name": "vm1-smoke", "events": 3},
                    {"source_name": "collector-bench-syslog-linux-auth-siem-vm1-w1", "events": 10},
                    {"source_name": "siem-storage-e2e-assignment-full-batch-e2e", "events": 3},
                    {"source_name": "kafka-cutover-smoke", "events": 2},
                    {"source_name": "generic-http-refresh", "events": 2},
                    {"source_name": "127.0.0.1", "events": 1},
                ]

            @staticmethod
            def fetch_collector_inventory(*, hours: int):
                return [
                    {"collector_id": "linux", "covered_sources": ["linux-prod-01", "vm1-smoke"], "active_sources": 2},
                    {"collector_id": "smoke", "covered_sources": ["vm1-smoke"], "active_sources": 1},
                    {"collector_id": "generic-http", "covered_sources": ["generic-http-refresh"], "active_sources": 1},
                ]

            @staticmethod
            def fetch_top_sources(*, limit: int, hours: int, from_ts: str = "", to_ts: str = ""):
                return [
                    {"source_name": "linux-prod-01", "events": 24},
                    {"source_name": "vm1-smoke", "events": 3},
                    {"source_name": "127.0.0.1", "events": 1},
                ]

        with patch("query.sources.deps_module", return_value=FakeDeps):
            source_rows = sources_module.fetch_source_inventory(limit=20, hours=24)
            collector_rows = sources_module.fetch_collector_inventory(hours=24)
            top_rows = sources_module.fetch_top_sources(limit=20, hours=24)

        self.assertEqual(["linux-prod-01"], [row["source_name"] for row in source_rows])
        self.assertEqual(["linux-prod-01"], list(collector_rows[0]["covered_sources"]))
        self.assertEqual(1, collector_rows[0]["active_sources"])
        self.assertEqual(["linux-prod-01"], [row["source_name"] for row in top_rows])

    def test_inventory_filter_does_not_hide_real_sources_because_of_event_message_noise(self) -> None:
        shared_module = importlib.import_module("query.shared")

        self.assertFalse(
            shared_module.is_non_operational_inventory_record(
                {
                    "source_name": "siem-web",
                    "message": "operator ran pytest from /opt/siem/siem-solution/deploy/",
                }
            )
        )
        self.assertTrue(shared_module.is_non_operational_inventory_record({"source_name": "vm4-smoke"}))
        self.assertTrue(shared_module.is_non_operational_inventory_record({"source_name": "pve-validation"}))
        self.assertTrue(shared_module.is_non_operational_inventory_record({"source_name": "e2e-host-assignment-full"}))
        self.assertTrue(shared_module.is_non_operational_inventory_record({"source_name": "generic-http-refresh"}))
        self.assertTrue(shared_module.is_non_operational_inventory_record({"source_name": "127.0.0.1"}))

    def test_sources_fallback_to_ingest_runtime_when_clickhouse_inventory_is_empty(self) -> None:
        sources_module = importlib.import_module("query.sources")
        sources_module._CACHE.clear()

        class EmptyDeps:
            @staticmethod
            def fetch_source_inventory(*, limit: int, hours: int):
                return []

            @staticmethod
            def fetch_collector_inventory(*, hours: int):
                return []

        def fake_ingest_sources(*, limit: int):
            return {
                "items": [
                    {
                        "id": "runtime-linux-01",
                        "source_alias": "linux-prod-01",
                        "collector_profile": "linux-auth",
                        "status": "healthy",
                        "events_total": 42,
                        "last_seen_ts": "2026-05-11T08:00:00Z",
                    }
                ]
            }

        def fake_ingest_collectors(*, limit: int):
            return {
                "items": [
                    {
                        "collector_profile": "linux-auth",
                        "status": "healthy",
                        "events_total": 42,
                        "sources_count": 1,
                    }
                ]
            }

        with (
            patch("query.sources.deps_module", return_value=EmptyDeps),
            patch("query.sources.list_ingest_sources", side_effect=fake_ingest_sources),
            patch("query.sources.list_ingest_collectors", side_effect=fake_ingest_collectors),
        ):
            source_rows = sources_module.fetch_source_inventory(limit=20, hours=24)
            collector_rows = sources_module.fetch_collector_inventory(hours=24)

        self.assertEqual("linux-prod-01", source_rows[0]["source_name"])
        self.assertEqual("ingest-health-fallback", source_rows[0]["inventory_source"])
        self.assertEqual("linux-auth", collector_rows[0]["collector_id"])
        self.assertEqual("ingest-health-fallback", collector_rows[0]["inventory_source"])

    def test_assets_filter_non_operational_rows(self) -> None:
        assets_module = importlib.import_module("query.assets")

        class FakeDeps:
            @staticmethod
            def fetch_assets(*, limit: int, hours: int):
                return [
                    {"asset": "siem-web", "events": 120},
                    {"asset": "vm1-kafka-cutover", "events": 12},
                    {"asset": "vm1-smoke", "events": 3},
                    {"asset": "collector-bench-syslog-network-siem-vm4-w2", "events": 10},
                    {"asset": "pilot-db-01-validation", "events": 3},
                    {"asset": "scanner-01", "aliases": ["synthetic-benchmark"], "events": 9},
                    {"asset": "127.0.0.1", "events": 1},
                    {"asset": "generic-http-refresh", "events": 2},
                ]

        with patch("query.assets.deps_module", return_value=FakeDeps):
            rows = assets_module.fetch_assets(limit=20, hours=24)

        self.assertEqual(["siem-web"], [row["asset"] for row in rows])

    def test_cmdb_assets_filter_non_operational_rows(self) -> None:
        assets_module = importlib.import_module("query.assets")

        class FakeDeps:
            @staticmethod
            def fetch_cmdb_assets(*, limit: int):
                return [
                    {"asset_id": "asset-siem-web", "hostname": "siem-web", "ip": "192.168.1.39"},
                    {"asset_id": "asset-127-0-0-1", "hostname": "127.0.0.1", "ip": "127.0.0.1"},
                    {"asset_id": "asset-loopback-alias", "hostname": "vm15611031.example.com", "ip": "127.0.0.1"},
                    {"asset_id": "asset-generic-http", "hostname": "generic-http-refresh"},
                ]

        with patch("query.assets.deps_module", return_value=FakeDeps):
            rows = assets_module.fetch_cmdb_assets(limit=20)

        self.assertEqual(["asset-siem-web"], [row["asset_id"] for row in rows])

    def test_cmdb_autocreate_has_ip_only_guard(self) -> None:
        deps_text = (ROOT / "services" / "web" / "app" / "deps.py").read_text(encoding="utf-8")

        self.assertIn("_is_observed_cmdb_autocreate_candidate", deps_text)
        self.assertIn("_is_ip_literal(identity)", deps_text)
        self.assertIn("is_non_operational_record", deps_text)
        self.assertIn("sync_observed_assets_to_cmdb", deps_text)


if __name__ == "__main__":
    unittest.main()
