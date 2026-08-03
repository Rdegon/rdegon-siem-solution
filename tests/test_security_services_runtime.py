from __future__ import annotations

from datetime import datetime, timezone
import unittest
from unittest.mock import patch
from uuid import UUID

from services.web.app import security_services_runtime
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


class _EmptyClient:
    def query(self, query: str, settings=None):
        return _Result([])


class _FailedClient:
    def query(self, query: str, settings=None):
        raise RuntimeError("password=do-not-expose transport unavailable")


class SecurityServicesRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.adapter_inventory = patch(
            "services.web.app.security_services_runtime._adapter_inventory",
            return_value={},
        )
        self.adapter_inventory_mock = self.adapter_inventory.start()

    def tearDown(self) -> None:
        self.adapter_inventory.stop()

    def test_catalog_reports_stale_and_healthy_sources(self) -> None:
        payload = list_security_services(client=_Client())
        by_id = {item["service_id"]: item for item in payload["items"]}

        self.assertEqual(payload["total"], 11)
        self.assertEqual(payload["healthy"], 1)
        self.assertEqual(by_id["ndr"]["telemetry_state"], "healthy")
        self.assertEqual(by_id["dfir"]["telemetry_state"], "stale")
        self.assertEqual(by_id["ndr"]["host_telemetry_state"], "healthy")
        self.assertEqual(by_id["ndr"]["matched_products"], ["zeek"])
        self.assertEqual(by_id["ndr"]["missing_products"], ["arkime"])
        self.assertEqual(by_id["evidence"]["address"], "10.20.10.133")
        self.assertEqual(by_id["ngfw"]["address"], "192.168.3.103")
        self.assertEqual(by_id["ngfw"]["host_name"], "opnsense-edge-01")
        self.assertEqual(by_id["vpn"]["product"], "WireGuard on OPNsense")
        self.assertTrue(any(item["href"].endswith("q=wireguard") for item in by_id["vpn"]["workspaces"]))
        self.assertIn("arkime", by_id["ndr"]["expected_products"])
        self.assertEqual(payload["data_state"], "fresh")
        self.assertEqual(by_id["ndr"]["metrics_state"], "fresh")
        self.assertEqual(by_id["dfir"]["metrics_state"], "stale")
        self.assertEqual(by_id["ndr"]["control_state"], "read-only")
        self.assertEqual(by_id["ngfw"]["control_state"], "unavailable")

    def test_detail_redacts_event_secrets(self) -> None:
        payload = get_security_service("ndr", client=_Client())

        self.assertEqual(payload["telemetry"]["state"], "healthy")
        self.assertEqual(payload["telemetry"]["product_coverage"], 0.5)
        self.assertEqual(payload["signal_breakdown"][0]["subcategory"], "zeek_conn")
        self.assertEqual(payload["recent_events"][0]["message"], "token=[REDACTED]")
        self.assertEqual(payload["recent_alerts"][0]["alert_id"], "12345678-1234-5678-1234-567812345678")

    def test_detail_rejects_unknown_service(self) -> None:
        with self.assertRaises(KeyError):
            get_security_service("does-not-exist", client=_Client())

    def test_host_metrics_do_not_mask_missing_product_integration(self) -> None:
        class HostMetricsOnlyClient(_Client):
            def query(self, query: str, settings=None):
                if "GROUP BY service_host" in query:
                    return _Result(
                        [
                            {
                                "service_host": "soc-analysis-01",
                                "events_15m": 20,
                                "events_1h": 80,
                                "events_24h": 1200,
                                "latest_event": datetime(2026, 7, 27, tzinfo=timezone.utc),
                                "products": ["host.metrics"],
                                "signal_types": ["host_metrics"],
                            }
                        ]
                    )
                return super().query(query, settings=settings)

        payload = list_security_services(client=HostMetricsOnlyClient())
        analysis = next(item for item in payload["items"] if item["service_id"] == "analysis")

        self.assertEqual(analysis["integration_state"], "degraded")
        self.assertEqual(analysis["host_telemetry_state"], "healthy")
        self.assertEqual(analysis["matched_products"], [])
        self.assertEqual(
            analysis["missing_products"],
            ["malware-analysis", "clamav", "yara"],
        )

    def test_product_health_is_not_truncated_by_busy_host_processes(self) -> None:
        class BusyRuntimeClient(_Client):
            def query(self, query: str, settings=None):
                if "GROUP BY service_host" in query:
                    products = [
                        "host.metrics",
                        *[f"linux.process-{index}" for index in range(20)],
                        "falco",
                    ]
                    if "groupUniqArray(16)" in query:
                        products = products[:16]
                    return _Result(
                        [
                            {
                                "service_host": "gamepanel-01",
                                "events_15m": 300,
                                "events_1h": 1200,
                                "events_24h": 28000,
                                "latest_event": datetime(2026, 7, 30, tzinfo=timezone.utc),
                                "products": products,
                                "signal_types": ["security_integration_heartbeat"],
                            }
                        ]
                    )
                return super().query(query, settings=settings)

        payload = list_security_services(client=BusyRuntimeClient())
        runtime = next(item for item in payload["items"] if item["service_id"] == "runtime")

        self.assertEqual(runtime["integration_state"], "healthy")
        self.assertEqual(runtime["matched_products"], ["falco"])
        self.assertEqual(runtime["missing_products"], [])

    def test_managed_actions_are_backed_by_concrete_adapters(self) -> None:
        inventory = {
            "ngfw": {
                "adapter": "services.web.app.opnsense_control_runtime",
                "state": "managed",
                "reason": "configured",
            },
            "ips": {
                "adapter": "services.web.app.opnsense_control_runtime",
                "state": "managed",
                "reason": "configured",
            },
            "vpn": {
                "adapter": "services.web.app.remote_access_runtime",
                "state": "managed",
                "reason": "configured",
                "providers": {
                    "openvpn": {"configured": True, "local_controller": True},
                    "vless": {"configured": False, "local_controller": False},
                },
            },
        }
        self.adapter_inventory_mock.return_value = inventory
        payload = list_security_services(client=_EmptyClient())
        by_id = {item["service_id"]: item for item in payload["items"]}

        self.assertEqual(by_id["ngfw"]["control_state"], "managed")
        self.assertEqual(by_id["ips"]["control_state"], "managed")
        self.assertEqual(by_id["vpn"]["control_state"], "managed")
        self.assertEqual(by_id["vulnerability"]["control_state"], "read-only")
        self.assertEqual(by_id["vulnerability"]["integration_mode"], "telemetry_and_pivot")
        managed_ngfw = [action for action in by_id["ngfw"]["actions"] if action["state"] == "managed"]
        self.assertEqual({action["operation"] for action in managed_ngfw}, {"create", "update", "toggle", "delete"})
        self.assertTrue(all(action["adapter"].endswith("opnsense_control_runtime") for action in managed_ngfw))
        vpn_actions = {action["id"]: action for action in by_id["vpn"]["actions"]}
        self.assertEqual(vpn_actions["vpn.openvpn.create"]["state"], "managed")
        self.assertEqual(vpn_actions["vpn.openvpn.revoke"]["state"], "managed")
        self.assertEqual(vpn_actions["vpn.vless.create"]["state"], "unavailable")
        self.assertFalse(vpn_actions["vpn.vless.create"]["available"])

    def test_catalog_reports_clickhouse_failure_without_fake_metrics(self) -> None:
        payload = list_security_services(client=_FailedClient())

        self.assertEqual(payload["data_state"], "error")
        self.assertEqual(payload["error"], payload["total"])
        self.assertNotIn("do-not-expose", payload["data_error"])
        for item in payload["items"]:
            self.assertEqual(item["telemetry_state"], "error")
            self.assertEqual(item["metrics_state"], "error")
            self.assertEqual(item["events_24h"], 0)
            self.assertFalse(item["metrics"]["observed"])
            telemetry_actions = [
                action
                for action in item["actions"]
                if action["id"] in {"telemetry.view", "incidents.view"}
            ]
            self.assertEqual(len(telemetry_actions), 2)
            self.assertTrue(all(action["state"] == "unavailable" for action in telemetry_actions))

    def test_catalog_reports_successful_empty_runtime_as_stale(self) -> None:
        payload = list_security_services(client=_EmptyClient())

        self.assertEqual(payload["data_state"], "stale")
        self.assertEqual(payload["error"], 0)
        self.assertEqual(payload["stale"], payload["total"])
        self.assertTrue(all(item["metrics_state"] == "stale" for item in payload["items"]))

    def test_detail_keeps_healthy_datasets_when_alert_query_fails(self) -> None:
        class AlertsFailedClient(_Client):
            def query(self, query: str, settings=None):
                if "FROM siem.alerts_raw" in query:
                    raise RuntimeError("alerts backend unavailable")
                return super().query(query, settings=settings)

        payload = get_security_service("ndr", client=AlertsFailedClient())

        self.assertEqual(payload["data_state"], "error")
        self.assertEqual(payload["datasets"]["recent_alerts"]["state"], "error")
        self.assertEqual(payload["datasets"]["signal_breakdown"]["state"], "fresh")
        self.assertEqual(payload["telemetry"]["metrics_state"], "fresh")
        self.assertEqual(len(payload["recent_events"]), 1)
        self.assertEqual(payload["recent_alerts"], [])
        incident_action = next(
            action for action in payload["service"]["actions"] if action["id"] == "incidents.view"
        )
        self.assertEqual(incident_action["state"], "unavailable")

    def test_detail_default_client_path_uses_cache_without_unbound_payload(self) -> None:
        security_services_runtime.clear_security_services_cache()
        with (
            patch(
                "services.web.app.security_services_runtime.get_clickhouse_client",
                return_value=_Client(),
            ) as client_factory,
            patch(
                "services.web.app.security_services_runtime._adapter_inventory",
                return_value={},
            ),
        ):
            first = get_security_service("ndr")
            second = get_security_service("ndr")

        self.assertEqual(first, second)
        client_factory.assert_called_once_with()
