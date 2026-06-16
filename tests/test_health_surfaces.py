import unittest
from unittest.mock import patch

from health_surfaces import build_backup_health_payload, build_storage_health_payload, build_transport_health_payload


class HealthSurfacesTests(unittest.TestCase):
    def test_transport_payload_prefers_live_kafka_sqlite_runtime(self) -> None:
        ingest_transport = {
            "backend": "kafka",
            "cutover_stage": "kafka_only",
            "kafka_configured": True,
            "kafka_bootstrap_servers": ["vm1:9093", "vm2:9093", "vm5:9093"],
            "configured_topics": {"raw": "siem.raw"},
            "kafka_auth_mode": "scram_tls",
        }
        platform_status = {
            "last_event_ts": "2026-03-24T00:00:00Z",
            "transport_backend": "kafka",
            "stream_state_backend": "sqlite",
            "content_store_backend": "mongo",
            "content_store_healthy": True,
            "stream_correlation": {"state_backend": "sqlite", "shadow_compare": True},
            "transport_shadow_status": {"status": "healthy", "healthy": True},
        }
        with patch("health_surfaces.local_transport_health_snapshot", return_value={"backend": "redis", "cutover_stage": "redis_only", "kafka_expected_brokers": 3}):
            with patch("health_surfaces.local_stream_state_runtime_status", return_value={"backend": "redis", "healthy": True, "sqlite_exists": False}):
                payload = build_transport_health_payload(ingest_transport=ingest_transport, platform_status=platform_status)

        self.assertEqual("kafka", payload["transport_backend"])
        self.assertEqual("kafka_only", payload["transport_cutover_stage"])
        self.assertEqual("sqlite", payload["stream_state_backend"])
        self.assertEqual("mongo", payload["content_store_backend"])
        self.assertEqual("kafka", payload["desired_transport"]["backend"])
        self.assertEqual("sqlite", payload["stream_state"]["backend"])
        self.assertTrue(payload["healthy"])

    def test_storage_and_backup_payloads_include_storage_ha(self) -> None:
        platform_status = {
            "last_event_ts": "2026-03-24T00:00:00Z",
            "clickhouse_ok": True,
            "events_5m": 120,
            "alerts_24h": 9,
            "storage_memory": {"pressure": "healthy"},
            "content_store_status": {"backend": "mongo"},
        }
        fake_storage_ha = {"clickhouse": {"healthy": True}, "postgres": {"healthy": True}, "mongo": {"healthy": True}}
        with patch("health_surfaces.build_storage_ha_status", return_value=fake_storage_ha):
            storage_payload = build_storage_health_payload(platform_status)
            backup_payload = build_backup_health_payload(
                control_plane_status={"backend": "postgres"},
                content_status={"backend": "mongo"},
                platform_status=platform_status,
                env={"SIEM_STREAM_STATE_BACKEND": "sqlite"},
            )

        self.assertEqual(fake_storage_ha, storage_payload["storage_ha"])
        self.assertEqual(fake_storage_ha, backup_payload["storage_ha"])

    def test_storage_payload_prefers_clickhouse_runtime_when_legacy_flag_is_false(self) -> None:
        platform_status = {
            "last_event_ts": "2026-03-24T00:00:00Z",
            "clickhouse_ok": False,
            "clickhouse_runtime": {"healthy": True, "active_endpoint": {"host": "vm3", "port": 8123}},
            "events_5m": 12,
            "alerts_24h": 3,
            "storage_memory": {"pressure": "healthy"},
        }
        with patch("health_surfaces.build_storage_ha_status", return_value={"clickhouse": {"healthy": True}}):
            payload = build_storage_health_payload(platform_status)

        self.assertTrue(payload["clickhouse_ok"])
        self.assertEqual("vm3", payload["clickhouse_runtime"]["active_endpoint"]["host"])

    def test_transport_payload_is_unhealthy_when_shadow_pipeline_is_missing(self) -> None:
        ingest_transport = {"backend": "kafka", "kafka_configured": True}
        platform_status = {
            "transport_backend": "kafka",
            "stream_state_backend": "sqlite",
            "content_store_backend": "mongo",
            "content_store_healthy": True,
            "stream_correlation": {"state_backend": "sqlite", "shadow_compare": True},
            "transport_shadow_status": {"status": "missing", "healthy": False, "issues": ["Kafka shadow table is missing"]},
        }
        with patch("health_surfaces.local_transport_health_snapshot", return_value={"backend": "kafka", "kafka_configured": True, "kafka_expected_brokers": 3}):
            with patch("health_surfaces.local_stream_state_runtime_status", return_value={"backend": "sqlite", "healthy": True, "sqlite_exists": True}):
                payload = build_transport_health_payload(ingest_transport=ingest_transport, platform_status=platform_status)

        self.assertFalse(payload["healthy"])
        self.assertIn("Kafka shadow table is missing", payload["issues"])


if __name__ == "__main__":
    unittest.main()
