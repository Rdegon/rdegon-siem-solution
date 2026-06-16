import importlib.util
import os
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]


def _load_deps_module():
    package_name = "testrepo_geo"
    if package_name not in sys.modules:
        package = types.ModuleType(package_name)
        package.__path__ = [str(ROOT)]  # type: ignore[attr-defined]
        sys.modules[package_name] = package
    module_name = f"{package_name}.deps"
    for stale in (
        module_name,
        f"{package_name}.config",
        f"{package_name}.clickhouse_runtime",
        f"{package_name}.content_store",
        f"{package_name}.inventory_catalog",
        f"{package_name}.transport_health_runtime",
        f"{package_name}.stream_state_runtime",
        f"{package_name}.proxmox_fleet_runtime",
        f"{package_name}.runtime_humanization",
        f"{package_name}.secret_runtime",
    ):
        sys.modules.pop(stale, None)
    spec = importlib.util.spec_from_file_location(module_name, ROOT / "deps.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


class GeoDashboardRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        env_overrides = {
            "SIEM_ENV": "dev",
            "SIEM_CH_HOST": "127.0.0.1",
            "SIEM_CH_PORT": "8123",
            "SIEM_CH_USER": "siem_admin",
            "SIEM_CH_PASSWORD": "secret",
            "SIEM_CH_DB": "siem",
            "SIEM_JWT_SECRET": "test-secret",
            "SIEM_ADMIN_DEFAULT_PASSWORD_HASH": "pbkdf2_sha256$390000$test$hash",
            "SIEM_HOT_RETENTION_HOURS": "168",
            "SIEM_COLD_RETENTION_DAYS": "365",
        }
        self.original = {key: os.environ.get(key) for key in env_overrides}
        os.environ.update(env_overrides)
        self.addCleanup(
            lambda: [
                os.environ.pop(key, None) if value is None else os.environ.__setitem__(key, value)
                for key, value in self.original.items()
            ]
        )
        self.deps = _load_deps_module()

    def test_extract_vpn_destination_host_supports_current_xray_format(self) -> None:
        host = self.deps._extract_vpn_destination_host(
            "<30>1 2026-04-06T14:28:30Z openclaw-gateway xray - - - from 10.20.30.124:42896 accepted //api.telegram.org:443 [http-in -> proxy]"
        )
        self.assertEqual("api.telegram.org", host)

    def test_fetch_top_vpn_sites_aggregates_current_log_format(self) -> None:
        class FakeQuery:
            def named_results(self):
                return [
                    {"ts": 3, "message": "accepted //api.telegram.org:443 [http-in -> proxy]", "client_ip": "10.20.30.124", "client_id": ""},
                    {"ts": 2, "message": "accepted tcp:api.telegram.org:443", "client_ip": "10.20.30.125", "client_id": "friend10"},
                    {"ts": 1, "message": "accepted //api.ipify.org:443 [http-in -> proxy]", "client_ip": "10.20.30.124", "client_id": ""},
                ]

        class FakeClient:
            def query(self, _sql):
                return FakeQuery()

        with patch.object(self.deps, "get_ch_client", return_value=FakeClient()):
            rows = self.deps.fetch_top_vpn_sites(limit=10, hours=24)

        self.assertEqual("api.telegram.org", rows[0]["domain"])
        self.assertEqual(2, rows[0]["visits"])
        self.assertEqual(2, rows[0]["unique_clients"])
        self.assertEqual("friend10", rows[0]["client_id"])

    def test_fetch_geo_source_activity_falls_back_to_last_non_empty_window(self) -> None:
        empty_payload = {"items": [], "countries": [], "summary": {"countries": 0, "ips": 0, "events": 0}}
        fallback_payload = {
            "items": [{"ip": "45.67.229.222", "country": "Moldova", "events": 688}],
            "countries": [{"country": "Moldova", "events": 688, "ips": 1}],
            "summary": {"countries": 1, "ips": 1, "events": 688},
        }

        def fake_fetch(*, hours, limit, from_ts="", to_ts="", allow_network=True):
            if hours < 168:
                return dict(empty_payload)
            return dict(fallback_payload)

        with patch.object(self.deps, "_fetch_geo_source_activity_window", side_effect=fake_fetch):
            payload = self.deps.fetch_geo_source_activity(hours=24, limit=10)

        self.assertTrue(payload["summary"]["fallback_applied"])
        self.assertEqual(24, payload["summary"]["requested_window_hours"])
        self.assertEqual(168, payload["summary"]["observed_window_hours"])
        self.assertEqual(1, len(payload["items"]))

    def test_dashboard_geo_payload_hydrates_when_cached_items_have_no_coordinates(self) -> None:
        calls = []
        cached_payload = {
            "items": [{"ip": "8.8.8.8", "country": "Unknown", "country_code": "", "lat": None, "lon": None}],
            "countries": [{"country": "Unknown", "events": 4, "ips": 1}],
            "summary": {"countries": 1, "ips": 1, "events": 4},
        }
        hydrated_payload = {
            "items": [{"ip": "8.8.8.8", "country": "United States", "country_code": "US", "lat": 37.386, "lon": -122.084}],
            "countries": [{"country": "United States", "events": 4, "ips": 1}],
            "summary": {"countries": 1, "ips": 1, "events": 4},
        }

        def fake_fetch(*, hours, limit, from_ts="", to_ts="", allow_network=True):
            calls.append(
                {
                    "hours": hours,
                    "limit": limit,
                    "from_ts": from_ts,
                    "to_ts": to_ts,
                    "allow_network": allow_network,
                }
            )
            return dict(hydrated_payload if allow_network else cached_payload)

        payload = self.deps._dashboard_geo_payload(fake_fetch, hours=24, limit=16)

        self.assertEqual(hydrated_payload, payload)
        self.assertEqual([False, True], [call["allow_network"] for call in calls])

    def test_dashboard_geo_payload_hydrates_when_some_cached_items_are_missing_coordinates(self) -> None:
        calls = []
        cached_payload = {
            "items": [
                {"ip": "8.8.8.8", "country": "United States", "country_code": "US", "lat": 37.386, "lon": -122.084},
                {"ip": "69.5.169.67", "country": "Unknown", "country_code": "", "lat": None, "lon": None},
            ],
            "countries": [{"country": "United States", "events": 4, "ips": 1}],
            "summary": {"countries": 1, "ips": 2, "events": 6},
        }
        hydrated_payload = {
            "items": [
                {"ip": "8.8.8.8", "country": "United States", "country_code": "US", "lat": 37.386, "lon": -122.084},
                {"ip": "69.5.169.67", "country": "Germany", "country_code": "DE", "lat": 50.1109, "lon": 8.6821},
            ],
            "countries": [{"country": "United States", "events": 4, "ips": 1}, {"country": "Germany", "events": 2, "ips": 1}],
            "summary": {"countries": 2, "ips": 2, "events": 6},
        }

        def fake_fetch(*, hours, limit, from_ts="", to_ts="", allow_network=True):
            calls.append(allow_network)
            return dict(hydrated_payload if allow_network else cached_payload)

        payload = self.deps._dashboard_geo_payload(fake_fetch, hours=24, limit=16)

        self.assertEqual(hydrated_payload, payload)
        self.assertEqual([False, True], calls)

    def test_threat_intel_overview_filters_nonproduction_iocs_and_surfaces_protected_target_activity(self) -> None:
        class FakeQuery:
            def named_results(self):
                return []

        class FakeClient:
            def query(self, _sql):
                return FakeQuery()

        entries = [
            {"indicator_type": "ip", "indicator": "203.0.113.44", "provider": "lab", "severity": "high", "tags": ["smoke-test"]},
            {"indicator_type": "ip", "indicator": "79.124.62.122", "provider": "Rdegon Lab TI", "severity": "high", "tags": ["internet-scan"]},
        ]
        geo_payload = {
            "items": [
                {
                    "ip": "80.66.66.61",
                    "country": "Germany",
                    "events": 2,
                    "target_ips": "176.108.250.215",
                    "target_ports": "6022,6023",
                    "reputation": "unknown",
                    "reputation_sources": [],
                }
            ],
            "countries": [],
            "summary": {},
        }

        with patch.object(self.deps, "fetch_threat_intel_entries", return_value=entries), patch.object(
            self.deps, "fetch_geo_source_activity", return_value=geo_payload
        ), patch.object(self.deps, "get_ch_client", return_value=FakeClient()):
            payload = self.deps.fetch_threat_intel_overview(limit=10, hours=24)

        self.assertEqual(1, payload["summary"]["indicators"])
        self.assertEqual(1, payload["summary"]["ignored_nonprod_indicators"])
        self.assertEqual(1, payload["summary"]["protected_target_sources"])
        self.assertEqual("protected-target-activity", payload["malicious_sources"][0]["reputation"])

    def test_resolve_hostname_ip_retries_when_cache_contains_empty_value(self) -> None:
        saved = {}

        with patch.object(self.deps, "_load_dns_cache", return_value={"api.telegram.org": ""}), patch.object(
            self.deps, "_save_dns_cache", side_effect=lambda payload: saved.update(payload)
        ), patch.object(
            self.deps.socket,
            "getaddrinfo",
            return_value=[(None, None, None, None, ("149.154.167.220", 443))],
        ):
            resolved = self.deps._resolve_hostname_ip("api.telegram.org")

        self.assertEqual("149.154.167.220", resolved)
        self.assertEqual("149.154.167.220", saved.get("api.telegram.org"))

    def test_geo_lookup_skips_external_lookup_when_network_disabled(self) -> None:
        with patch.object(self.deps, "_load_geoip_cache", return_value={}), patch.object(
            self.deps, "_save_geoip_cache"
        ) as save_cache, patch.object(self.deps, "urlopen") as urlopen_mock:
            payload = self.deps._geo_lookup("8.8.8.8", allow_network=False)

        self.assertEqual("Unknown", payload["country"])
        self.assertEqual("", payload["country_code"])
        urlopen_mock.assert_not_called()
        save_cache.assert_not_called()

    def test_resolve_hostname_ip_skips_dns_when_network_disabled(self) -> None:
        with patch.object(self.deps, "_load_dns_cache", return_value={}), patch.object(
            self.deps, "_save_dns_cache"
        ) as save_cache, patch.object(self.deps.socket, "getaddrinfo") as getaddrinfo_mock:
            resolved = self.deps._resolve_hostname_ip("api.telegram.org", allow_network=False)

        self.assertEqual("", resolved)
        getaddrinfo_mock.assert_not_called()
        save_cache.assert_not_called()


if __name__ == "__main__":
    unittest.main()
