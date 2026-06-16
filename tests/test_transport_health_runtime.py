import unittest
from datetime import datetime, timezone

from transport_health_runtime import build_shadow_transport_status, transport_health_snapshot


class TransportHealthRuntimeTests(unittest.TestCase):
    def test_kafka_cutover_snapshot_uses_topics(self) -> None:
        payload = transport_health_snapshot(
            {
                "SIEM_TRANSPORT_BACKEND": "kafka",
                "SIEM_TRANSPORT_CONSUMER_BACKEND": "kafka",
                "SIEM_KAFKA_BOOTSTRAP_SERVERS": "vm1:9093,vm2:9093,vm5:9093",
                "SIEM_KAFKA_SECURITY_PROTOCOL": "SASL_SSL",
                "SIEM_KAFKA_SASL_USERNAME": "siem",
                "SIEM_KAFKA_SASL_PASSWORD": "secret",
                "SIEM_KAFKA_TOPIC_RAW": "siem.raw",
            }
        )

        self.assertEqual("kafka", payload["backend"])
        self.assertEqual("kafka_only", payload["cutover_stage"])
        self.assertEqual("scram_tls", payload["kafka_auth_mode"])
        self.assertEqual("siem.raw", payload["raw_target"])
        self.assertFalse(payload["redis_streams_active"])

    def test_dual_cutover_retains_redis_targets(self) -> None:
        payload = transport_health_snapshot(
            {
                "SIEM_TRANSPORT_BACKEND": "dual",
                "SIEM_REDIS_STREAM_RAW": "siem:raw",
            }
        )

        self.assertEqual("dual_write", payload["cutover_stage"])
        self.assertTrue(payload["redis_streams_active"])
        self.assertEqual("siem.raw", payload["configured_topics"]["raw"])
        self.assertEqual("siem.raw", payload["raw_target"])

    def test_build_shadow_transport_status_marks_recent_shadow_flow_healthy(self) -> None:
        payload = build_shadow_transport_status(
            shadow_table_exists=True,
            main_events_5m=120,
            main_events_15m=480,
            shadow_events_5m=55,
            shadow_events_15m=210,
            shadow_last_event_ts="2026-03-23T01:00:00Z",
            freshness_window_sec=900,
            now=datetime(2026, 3, 23, 1, 5, 0, tzinfo=timezone.utc),
        )

        self.assertTrue(payload["healthy"])
        self.assertEqual("healthy", payload["status"])
        self.assertEqual(0.4583, payload["shadow_to_main_ratio_5m"])
        self.assertEqual(300, payload["shadow_last_event_age_sec"])

    def test_build_shadow_transport_status_marks_stale_shadow_flow(self) -> None:
        payload = build_shadow_transport_status(
            shadow_table_exists=True,
            main_events_5m=80,
            main_events_15m=240,
            shadow_events_5m=0,
            shadow_events_15m=12,
            shadow_last_event_ts="2026-03-23T00:30:00Z",
            freshness_window_sec=900,
            now=datetime(2026, 3, 23, 1, 5, 0, tzinfo=timezone.utc),
        )

        self.assertFalse(payload["healthy"])
        self.assertEqual("stale", payload["status"])
        self.assertGreater(payload["shadow_last_event_age_sec"], 900)
        self.assertIn("Kafka shadow pipeline is stale", payload["issues"][0])

    def test_build_shadow_transport_status_marks_missing_table(self) -> None:
        payload = build_shadow_transport_status(
            shadow_table_exists=False,
            main_events_5m=10,
            main_events_15m=40,
            shadow_events_5m=0,
            shadow_events_15m=0,
            shadow_last_event_ts="",
        )

        self.assertFalse(payload["healthy"])
        self.assertEqual("missing", payload["status"])
        self.assertIn("Kafka shadow table is missing", payload["issues"][0])


if __name__ == "__main__":
    unittest.main()
