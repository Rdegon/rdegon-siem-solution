from __future__ import annotations

from datetime import datetime, timezone
import unittest
from uuid import UUID

from services.web.app.security_services_runtime import get_security_service, list_security_services


class _Result:
    def __init__(self, rows):
        self._rows = rows

    def named_results(self):
        return iter(self._rows)


class _Client:
    def query(self, query: str, settings=None):
        if "GROUP BY service_host" in query:
            return _Result(
                [
                    {
                        "service_host": "soc-ndr-01",
                        "events_15m": 25,
                        "events_1h": 100,
                        "events_24h": 1000,
                        "latest_event": datetime(2026, 7, 27, tzinfo=timezone.utc),
                        "products": ["zeek", "host.metrics"],
                        "signal_types": ["zeek_conn"],
                    }
                ]
            )
        if "GROUP BY device_product" in query:
            return _Result(
                [
                    {
                        "device_product": "zeek",
                        "category": "network",
                        "subcategory": "zeek_conn",
                        "severity": "info",
                        "event_count": 1000,
                        "latest_event": datetime(2026, 7, 27, tzinfo=timezone.utc),
                    }
                ]
            )
        if "FROM siem.events" in query:
            return _Result(
                [
                    {
                        "ts": datetime(2026, 7, 27, tzinfo=timezone.utc),
                        "event_id": "event-1",
                        "message": "token=top-secret",
                    }
                ]
            )
        if "FROM siem.alerts_raw" in query:
            return _Result(
                [
                    {
                        "ts_last": datetime(2026, 7, 27, tzinfo=timezone.utc),
                        "alert_id": UUID("12345678-1234-5678-1234-567812345678"),
                    }
                ]
            )
        raise AssertionError(query)


class SecurityServicesRuntimeTests(unittest.TestCase):
    def test_catalog_reports_stale_and_healthy_sources(self) -> None:
        payload = list_security_services(client=_Client())
        by_id = {item["service_id"]: item for item in payload["items"]}

        self.assertEqual(payload["total"], 10)
        self.assertEqual(payload["healthy"], 1)
        self.assertEqual(by_id["ndr"]["telemetry_state"], "healthy")
        self.assertEqual(by_id["dfir"]["telemetry_state"], "stale")
        self.assertEqual(by_id["evidence"]["address"], "10.20.10.133")
        self.assertEqual(by_id["ngfw"]["address"], "192.168.3.103")
        self.assertEqual(by_id["ngfw"]["host_name"], "opnsense-edge-01")
        self.assertIn("arkime", by_id["ndr"]["expected_products"])

    def test_detail_redacts_event_secrets(self) -> None:
        payload = get_security_service("ndr", client=_Client())

        self.assertEqual(payload["telemetry"]["state"], "healthy")
        self.assertEqual(payload["signal_breakdown"][0]["subcategory"], "zeek_conn")
        self.assertEqual(payload["recent_events"][0]["message"], "token=[REDACTED]")
        self.assertEqual(payload["recent_alerts"][0]["alert_id"], "12345678-1234-5678-1234-567812345678")

    def test_detail_rejects_unknown_service(self) -> None:
        with self.assertRaises(KeyError):
            get_security_service("does-not-exist", client=_Client())
