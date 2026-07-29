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

    def test_aggregate_alert_filter_uses_only_aggregate_table_columns(self) -> None:
        filter_sql = self.deps._alert_agg_operational_filter_sql()

        self.assertNotIn("toString(source)", filter_sql)
        self.assertIn("toString(group_key_json)", filter_sql)
        self.assertIn("toString(samples_json)", filter_sql)

    def test_short_incident_uses_one_contiguous_evidence_window(self) -> None:
        clause = self.deps._incident_evidence_time_clause(
            "2026-07-25 16:00:00",
            "2026-07-25 16:30:00",
        )

        self.assertNotIn(" OR ", clause)
        self.assertIn("2026-07-25 16:00:00", clause)
        self.assertIn("2026-07-25 16:30:00", clause)

    def test_long_incident_bounds_evidence_to_first_and_last_activity(self) -> None:
        clause = self.deps._incident_evidence_time_clause(
            "2026-07-25 01:00:00",
            "2026-07-25 19:00:00",
        )

        self.assertIn(" OR ", clause)
        self.assertEqual(4, clause.count("INTERVAL 45 MINUTE"))
        self.assertNotIn(
            "ts >= parseDateTimeBestEffort('2026-07-25 01:00:00') - INTERVAL 45 MINUTE "
            "AND ts <= parseDateTimeBestEffort('2026-07-25 19:00:00') + INTERVAL 45 MINUTE",
            clause,
        )

    def test_command_incident_uses_one_priority_query(self) -> None:
        captured: list[str] = []

        original_rows = self.deps._rows_from_query
        original_filter = self.deps._event_operational_filter_sql
        try:
            self.deps._rows_from_query = lambda sql, **_: captured.append(sql) or {"columns": [], "rows": []}
            self.deps._event_operational_filter_sql = lambda: "1"
            self.deps._incident_related_events(
                {
                    "rule_name": "PowerShell execution",
                    "entity_key": "test-host",
                    "ts_first": "2026-07-25 16:00:00",
                    "ts_last": "2026-07-25 16:05:00",
                },
                [],
                limit=50,
            )
        finally:
            self.deps._rows_from_query = original_rows
            self.deps._event_operational_filter_sql = original_filter

        self.assertEqual(1, len(captured))
        self.assertIn("positionCaseInsensitiveUTF8", captured[0])
        self.assertIn("DESC, ts DESC", captured[0])

    def test_incident_history_read_does_not_run_schema_ddl(self) -> None:
        class Result:
            def named_results(self):
                return []

        class Client:
            def query(self, _sql):
                return Result()

        original_client = self.deps.get_ch_client
        original_ensure = self.deps.ensure_incident_workflow_support
        try:
            self.deps._ALERT_HISTORY_CACHE.clear()
            self.deps.get_ch_client = lambda: Client()
            self.deps.ensure_incident_workflow_support = lambda: (_ for _ in ()).throw(
                AssertionError("read path must not execute schema DDL")
            )

            self.assertEqual([], self.deps.fetch_alert_history("agg", "agg:test"))
        finally:
            self.deps.get_ch_client = original_client
            self.deps.ensure_incident_workflow_support = original_ensure

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
        self.assertNotIn("benchmark_run_id", captured[0])

    def test_materialized_incident_alert_matching_prefers_explicit_alert_ids(self) -> None:
        captured: list[str] = []

        class Result:
            def named_results(self):
                return [{"alert_id": "raw-1"}]

        class Client:
            def query(self, sql):
                captured.append(sql)
                return Result()

        original_client = self.deps.get_ch_client
        try:
            self.deps.get_ch_client = lambda: Client()
            alert_ids = self.deps._match_alert_ids_for_materialized_incident(
                {
                    "entity_key": "endpoint-01",
                    "rule_id": 2703,
                    "alert_ids": ["raw-1", "raw-expired"],
                },
                limit=50,
            )
        finally:
            self.deps.get_ch_client = original_client

        self.assertEqual(["raw-1"], alert_ids)
        self.assertIn("toString(alert_id) IN", captured[0])
        self.assertIn("'raw-expired'", captured[0])
        self.assertNotIn("toString(entity_key)", captured[0])

    def test_materialized_incident_alert_matching_falls_back_when_explicit_ids_are_stale(self) -> None:
        captured: list[str] = []

        class Result:
            def __init__(self, rows):
                self.rows = rows

            def named_results(self):
                return self.rows

        class Client:
            def query(self, sql):
                captured.append(sql)
                return Result([] if len(captured) == 1 else [{"alert_id": "raw-current"}])

        original_client = self.deps.get_ch_client
        try:
            self.deps.get_ch_client = lambda: Client()
            alert_ids = self.deps._match_alert_ids_for_materialized_incident(
                {
                    "entity_key": "rdegon",
                    "rule_id": 2703,
                    "alert_ids": ["raw-expired"],
                    "ts_first": "2026-07-29 14:00:00",
                    "ts_last": "2026-07-29 15:00:00",
                },
                limit=50,
            )
        finally:
            self.deps.get_ch_client = original_client

        self.assertEqual(["raw-current"], alert_ids)
        self.assertEqual(2, len(captured))
        self.assertIn("toString(alert_id) IN", captured[0])
        self.assertIn("toString(entity_key) = 'rdegon'", captured[1])
        self.assertIn("toInt64(rule_id) = 2703", captured[1])

    def test_incident_detail_resolves_id_from_raw_scan_fallback(self) -> None:
        original_fetch = self.deps.fetch_alerts_agg
        original_fallback = self.deps._fetch_alerts_agg_from_raw_scan
        try:
            self.deps.fetch_alerts_agg = lambda **_: []
            self.deps._fetch_alerts_agg_from_raw_scan = lambda **_: [
                {
                    "agg_id": "agg:fallback",
                    "record_id": "agg:fallback",
                    "storage_agg_id": "",
                    "entity_key": "endpoint-01",
                    "group_key": {},
                }
            ]
            selected = self.deps._incident_selected_record("agg", "agg:fallback", window="24h")
        finally:
            self.deps.fetch_alerts_agg = original_fetch
            self.deps._fetch_alerts_agg_from_raw_scan = original_fallback

        self.assertIsNotNone(selected)
        self.assertEqual("endpoint-01", selected["entity_key"])

    def test_incident_detail_accepts_storage_aggregate_id(self) -> None:
        original_fetch = self.deps.fetch_alerts_agg
        try:
            self.deps.fetch_alerts_agg = lambda **_: [
                {
                    "agg_id": "agg:stable",
                    "record_id": "agg:stable",
                    "storage_agg_id": "storage-uuid",
                    "entity_key": "endpoint-01",
                    "group_key": {},
                }
            ]
            selected = self.deps._incident_selected_record("agg", "storage-uuid", window="24h")
        finally:
            self.deps.fetch_alerts_agg = original_fetch

        self.assertIsNotNone(selected)
        self.assertEqual("agg:stable", selected["agg_id"])

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
