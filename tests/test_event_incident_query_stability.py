import importlib.util
import os
import sys
import types
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
APP_ROOT = ROOT / "services" / "web" / "app"


def _load_deps_module():
    for key, value in {
        "SIEM_CH_HOST": "127.0.0.1",
        "SIEM_CH_USER": "default",
        "SIEM_CH_PASSWORD": "test-password",
        "SIEM_ADMIN_DEFAULT_PASSWORD": "test-admin-password",
        "SIEM_JWT_SECRET": "test-jwt-secret",
    }.items():
        os.environ.setdefault(key, value)
    package_name = "query_stability_app"
    for name in list(sys.modules):
        if name == package_name or name.startswith(f"{package_name}."):
            sys.modules.pop(name, None)
    package = types.ModuleType(package_name)
    package.__path__ = [str(APP_ROOT)]  # type: ignore[attr-defined]
    sys.modules[package_name] = package
    spec = importlib.util.spec_from_file_location(f"{package_name}.deps", APP_ROOT / "deps.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    module.__package__ = package_name
    sys.modules[f"{package_name}.deps"] = module
    spec.loader.exec_module(module)
    return module


class EventIncidentQueryStabilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.deps = _load_deps_module()

    def test_incident_event_projection_contains_filter_columns(self) -> None:
        slim_sql = self.deps._incident_event_select_sql()
        command_sql = self.deps._incident_event_select_sql(include_normalized_json=True)

        self.assertIn("'' AS normalized_json", slim_sql)
        self.assertIn("asset_service", slim_sql)
        self.assertIn("normalized_json", command_sql)
        self.assertIn("asset_service", command_sql)

    def test_materialized_incident_key_ignores_volatile_storage_uuid(self) -> None:
        first = {
            "agg_id": "5c60de3f-2295-4ad1-b6a7-aee0a58d83b7",
            "entity_key": "DESKTOP-5JMJVBH",
            "rule_id": 2604,
            "rule_name": "Windows WMI Activity Burst",
            "severity_agg": "high",
        }
        second = dict(first)
        second["agg_id"] = "f07b2e6f-f651-45a3-b3d7-ef13ee0ead59"

        first_key = self.deps._stable_materialized_incident_key(first, {"entity_key": "DESKTOP-5JMJVBH"})
        second_key = self.deps._stable_materialized_incident_key(second, {"entity_key": "DESKTOP-5JMJVBH"})

        self.assertEqual(first_key, second_key)
        self.assertTrue(first_key.startswith("agg:"))

    def test_materialized_incident_alert_matching_uses_entity_and_rule(self) -> None:
        captured: list[str] = []

        class Result:
            def named_results(self):
                return [{"alert_id": "raw-1"}, {"alert_id": "raw-2"}]

        class Client:
            def query(self, sql):
                captured.append(sql)
                return Result()

        original_client = self.deps.get_ch_client
        try:
            self.deps.get_ch_client = lambda: Client()
            alert_ids = self.deps._match_alert_ids_for_materialized_incident(
                {
                    "entity_key": "DESKTOP-5JMJVBH",
                    "rule_id": 2604,
                    "rule_name": "Windows WMI Activity Burst",
                    "ts_first": "2026-05-11 17:00:00",
                    "ts_last": "2026-05-11 17:11:17",
                },
                limit=50,
            )
        finally:
            self.deps.get_ch_client = original_client

        self.assertEqual(["raw-1", "raw-2"], alert_ids)
        self.assertIn("toString(entity_key) = 'DESKTOP-5JMJVBH'", captured[0])
        self.assertIn("toInt64(rule_id) = 2604", captured[0])

    def test_incident_scope_matching_keeps_raw_scan_bounded(self) -> None:
        captured: list[str] = []

        class Result:
            def named_results(self):
                return []

        class Client:
            def query(self, sql):
                captured.append(sql)
                return Result()

        original_client = self.deps.get_ch_client
        try:
            self.deps.get_ch_client = lambda: Client()
            self.deps._match_alert_ids_for_incident_scope("agg:test", window="30d", limit=50)
        finally:
            self.deps.get_ch_client = original_client

        self.assertIn("LIMIT 1000", captured[0])
        self.assertNotIn("LIMIT 30000", captured[0])

    def test_event_view_sql_does_not_fail_on_schema_ensure_timeout(self) -> None:
        original_ensure = self.deps.ensure_event_enrichment_support
        try:
            self.deps.ensure_event_enrichment_support = lambda: (_ for _ in ()).throw(TimeoutError("ddl timeout"))
            sql = self.deps._event_view_sql("hot")
        finally:
            self.deps.ensure_event_enrichment_support = original_ensure

        self.assertIn("FROM siem.events", sql)

    def test_event_rows_do_not_execute_facets_by_default(self) -> None:
        calls: list[str] = []
        original_build = self.deps._build_events_base_sql
        original_paginate = self.deps._paginate_sql
        original_scalar = self.deps._scalar
        original_rows = self.deps._rows_from_query
        original_histogram = self.deps._histogram_query
        original_severity = self.deps._severity_stats_query
        original_source = self.deps._source_stats_query
        original_host = self.deps._host_stats_query
        try:
            self.deps._build_events_base_sql = lambda **_: "SELECT * FROM events_view"
            self.deps._paginate_sql = lambda sql, limit, offset: f"{sql} LIMIT {limit} OFFSET {offset}"
            self.deps._scalar = lambda _query: calls.append("count") or 1
            self.deps._rows_from_query = lambda _query: {"columns": ["ts"], "rows": [{"ts": "2026-05-11 00:00:00"}]}

            def facet_call(name):
                def _inner(*_args, **_kwargs):
                    calls.append(name)
                    return []

                return _inner

            self.deps._histogram_query = facet_call("histogram")
            self.deps._severity_stats_query = facet_call("severity")
            self.deps._source_stats_query = facet_call("source")
            self.deps._host_stats_query = facet_call("host")

            rows_payload = self.deps.execute_event_query(query_text="", window="24h")
            self.assertEqual(1, rows_payload["row_count"])
            self.assertTrue(rows_payload["total_count_is_estimate"])
            self.assertNotIn("histogram", rows_payload)
            self.assertEqual([], calls)

            counted_payload = self.deps.execute_event_query(query_text="", window="24h", include_count=True)
            self.assertFalse(counted_payload["total_count_is_estimate"])
            self.assertIn("count", calls)
            calls.clear()

            facets_payload = self.deps.execute_event_facets_query(query_text="", window="24h")
            self.assertIn("histogram", facets_payload)
            self.assertEqual(["histogram", "severity", "source", "host"], calls)
        finally:
            self.deps._build_events_base_sql = original_build
            self.deps._paginate_sql = original_paginate
            self.deps._scalar = original_scalar
            self.deps._rows_from_query = original_rows
            self.deps._histogram_query = original_histogram
            self.deps._severity_stats_query = original_severity
            self.deps._source_stats_query = original_source
            self.deps._host_stats_query = original_host


if __name__ == "__main__":
    unittest.main()
