from __future__ import annotations

import json
import importlib
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

os.environ.setdefault("SIEM_CH_HOST", "127.0.0.1")
os.environ.setdefault("SIEM_CH_USER", "default")
os.environ.setdefault("SIEM_CH_PASSWORD", "test-password")
os.environ.setdefault("SIEM_ADMIN_DEFAULT_PASSWORD", "test-password")
os.environ.setdefault("SIEM_JWT_SECRET", "test-jwt-secret")

if "repo_testpkg" not in sys.modules:
    package = importlib.util.module_from_spec(importlib.machinery.ModuleSpec("repo_testpkg", loader=None))
    package.__path__ = [str(ROOT)]
    sys.modules["repo_testpkg"] = package

deps = importlib.import_module("repo_testpkg.deps")


class _FakeQueryResult:
    def __init__(self, rows):
        self._rows = rows

    def named_results(self):
        return iter(self._rows)

    @property
    def result_rows(self):
        if self._rows and isinstance(self._rows[0], dict):
            return []
        return self._rows


class _FakeClient:
    def __init__(self, rows=None, verification_count=0):
        self.rows = rows or []
        self.verification_count = verification_count
        self.commands = []
        self.inserts = []

    def query(self, query):
        if "SELECT count()" in query:
            return _FakeQueryResult([[self.verification_count]])
        return _FakeQueryResult(self.rows)

    def command(self, query):
        self.commands.append(query)

    def insert(self, *args, **kwargs):
        self.inserts.append((args, kwargs))


class IncidentAssignmentTests(unittest.TestCase):
    def test_fetch_alerts_agg_populates_attacker_ips_from_entity_key_and_context(self) -> None:
        rows = [
            {
                "ts": "2026-03-29 12:00:00",
                "alert_id": "ssh-1",
                "rule_id": 1001,
                "rule_name": "Linux SSH Brute Force Burst",
                "severity": "high",
                "ts_first": "2026-03-29 11:50:00",
                "ts_last": "2026-03-29 12:00:00",
                "window_s": 300,
                "entity_key": "192.168.1.102|siem-web",
                "hits": 12,
                "context_json": json.dumps({"asset_id": "siem-web", "event_type": "ssh_auth_failure", "destination": {"host": {"name": "siem-web"}}}),
                "source": "siem-web",
                "status": "open",
                "assignee": "",
                "updated_ts": "2026-03-29 12:00:00",
            },
            {
                "ts": "2026-03-29 12:01:00",
                "alert_id": "ssh-2",
                "rule_id": 1001,
                "rule_name": "Linux SSH Brute Force Burst",
                "severity": "high",
                "ts_first": "2026-03-29 11:55:00",
                "ts_last": "2026-03-29 12:01:00",
                "window_s": 300,
                "entity_key": "siem-web",
                "hits": 8,
                "context_json": json.dumps({"asset_id": "siem-web", "event_type": "ssh_auth_failure", "src_ip": "192.168.1.102"}),
                "source": "siem-web",
                "status": "open",
                "assignee": "",
                "updated_ts": "2026-03-29 12:01:00",
            },
        ]
        with (
            patch.object(deps, "ensure_incident_workflow_support", return_value=None),
            patch.object(deps, "get_ch_client", return_value=_FakeClient(rows)),
        ):
            incidents = deps.fetch_alerts_agg(limit=20)

        self.assertEqual(1, len(incidents))
        incident = incidents[0]
        self.assertEqual(["192.168.1.102"], incident["cluster"]["actors"])
        self.assertEqual("192.168.1.102", incident["source_summary"])

    def test_fetch_alerts_agg_prefers_materialized_incident_table(self) -> None:
        rows = [
            {
                "ts": "2026-05-11 00:40:00",
                "agg_id": "agg-1",
                "rule_id": 4201,
                "rule_name": "Host Service Flapping",
                "severity_agg": "medium",
                "ts_first": "2026-05-11 00:35:00",
                "ts_last": "2026-05-11 00:40:00",
                "count_alerts": 4,
                "unique_entities": 1,
                "entity_key": "siem-web",
                "group_key_json": json.dumps(
                    {
                        "incident_key": "agg-1",
                        "sources": ["siem-web"],
                        "actors": ["siem-web"],
                        "rule_names": ["Host Service Flapping"],
                        "total_hits": 12,
                    }
                ),
                "samples_json": json.dumps([{"asset_id": "siem-web"}]),
                "status": "open",
                "assignee": "",
                "updated_ts": "2026-05-11 00:40:00",
            }
        ]
        client = _FakeClient(rows)
        with patch.object(deps, "get_ch_client", return_value=client):
            incidents = deps.fetch_alerts_agg(limit=20)

        self.assertEqual(1, len(incidents))
        self.assertEqual("agg-1", incidents[0]["agg_id"])
        self.assertEqual(12, incidents[0]["raw_hits_total"])
        self.assertEqual("siem-web", incidents[0]["source_summary"])

    def test_match_alert_ids_for_incident_scope_uses_python_scope_key(self) -> None:
        rows = [
            {
                "ts": "2026-03-29 12:00:00",
                "alert_id": "uuid-1",
                "rule_id": 4105,
                "rule_name": "OpenClaw DNS Query Burst",
                "severity": "medium",
                "ts_first": "2026-03-29 11:50:00",
                "ts_last": "2026-03-29 12:00:00",
                "window_s": 300,
                "entity_key": "",
                "hits": 12,
                "context_json": json.dumps({"asset_id": "openclaw-gateway", "event_type": "linux_dns_query"}),
                "source": "openclaw-gateway",
                "status": "open",
                "assignee": "",
                "updated_ts": "2026-03-29 12:00:00",
            },
            {
                "ts": "2026-03-29 12:00:00",
                "alert_id": "uuid-2",
                "rule_id": 4105,
                "rule_name": "OpenClaw DNS Query Burst",
                "severity": "medium",
                "ts_first": "2026-03-29 11:50:00",
                "ts_last": "2026-03-29 12:00:00",
                "window_s": 300,
                "entity_key": "",
                "hits": 5,
                "context_json": json.dumps({"asset_id": "nextcloud-siem", "event_type": "linux_dns_query"}),
                "source": "nextcloud-siem",
                "status": "open",
                "assignee": "",
                "updated_ts": "2026-03-29 12:00:00",
            },
        ]
        client = _FakeClient(rows)
        with patch.object(deps, "get_ch_client", return_value=client):
            matched = deps._match_alert_ids_for_incident_scope("asset:openclaw-gateway|campaign:linux_dns_query")
        self.assertEqual(["uuid-1"], matched)

    def test_update_alert_assignment_for_agg_targets_matched_alert_ids(self) -> None:
        client = _FakeClient(verification_count=2)
        incidents = [
            {
                "agg_id": "agg:hashed-ui-id",
                "record_id": "agg:hashed-ui-id",
                "rule_id": 4105,
                "rule_name": "OpenClaw DNS Query Burst",
                "entity_key": "openclaw-gateway",
                "ts_first": "2026-03-29 11:50:00",
                "ts_last": "2026-03-29 12:00:00",
                "status": "open",
                "assignee": "",
            }
        ]
        with (
            patch.object(deps, "ensure_incident_workflow_support", return_value=None),
            patch.object(deps, "fetch_alerts_agg", return_value=incidents),
            patch.object(deps, "_match_alert_ids_for_materialized_incident", return_value=["uuid-1", "uuid-2"]),
            patch.object(deps, "_match_alert_ids_for_incident_scope") as scope_matcher,
            patch.object(deps, "get_ch_client", return_value=client),
        ):
            deps.update_alert_assignment(
                "agg",
                "agg:hashed-ui-id",
                status="false_positive",
                assignee="system-fp-remediation",
                changed_by="tester",
                note="false positive",
            )
        self.assertTrue(client.commands)
        self.assertIn("toString(alert_id) IN ('uuid-1', 'uuid-2')", client.commands[0])
        self.assertEqual(1, len(client.inserts))
        scope_matcher.assert_not_called()

    def test_update_alert_assignment_rejects_zero_raw_matches(self) -> None:
        incidents = [
            {
                "agg_id": "agg:missing",
                "record_id": "agg:missing",
                "rule_id": 4105,
                "rule_name": "OpenClaw DNS Query Burst",
                "entity_key": "openclaw-gateway",
                "ts_first": "2026-03-29 11:50:00",
                "ts_last": "2026-03-29 12:00:00",
                "status": "open",
                "assignee": "",
            }
        ]
        with (
            patch.object(deps, "ensure_incident_workflow_support", return_value=None),
            patch.object(deps, "fetch_alerts_agg", return_value=incidents),
            patch.object(deps, "_match_alert_ids_for_materialized_incident", return_value=[]),
            patch.object(deps, "_match_alert_ids_for_incident_scope", return_value=[]),
            patch.object(deps, "get_ch_client", return_value=_FakeClient()),
        ):
            with self.assertRaisesRegex(ValueError, "No raw alerts matched"):
                deps.update_alert_assignment(
                    "agg",
                    "agg:missing",
                    status="false_positive",
                    assignee="system-fp-remediation",
                    changed_by="tester",
                    note="false positive",
                )


if __name__ == "__main__":
    unittest.main()
