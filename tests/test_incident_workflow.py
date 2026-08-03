from __future__ import annotations

import os
import re
from pathlib import Path
from unittest.mock import patch

import pytest


ROOT = Path(__file__).resolve().parents[1]
for key, value in {
    "SIEM_CH_HOST": "127.0.0.1",
    "SIEM_CH_USER": "default",
    "SIEM_CH_PASSWORD": "test-password",
    "SIEM_ADMIN_DEFAULT_PASSWORD": "test-password",
    "SIEM_JWT_SECRET": "test-jwt-secret",
}.items():
    os.environ.setdefault(key, value)

from services.web.app.routes import alerts  # noqa: E402


RAW_ROWS = {
    "raw-1": {
        "alert_id": "raw-1",
        "rule_id": 1001,
        "rule_name": "SSH brute force",
        "severity": "high",
        "ts": "2026-08-03 10:00:00",
        "ts_first": "2026-08-03 09:59:00",
        "ts_last": "2026-08-03 10:00:00",
        "entity_key": "host-1",
        "source": "linux-01",
        "hits": 7,
        "context": {},
    },
    "raw-2": {
        "alert_id": "raw-2",
        "rule_id": 1002,
        "rule_name": "Suspicious process",
        "severity": "critical",
        "ts": "2026-08-03 10:02:00",
        "ts_first": "2026-08-03 10:01:00",
        "ts_last": "2026-08-03 10:02:00",
        "entity_key": "host-2",
        "source": "windows-01",
        "hits": 2,
        "context": {},
    },
}


def raw_by_ids(alert_ids: list[str]) -> list[dict]:
    return [dict(RAW_ROWS[alert_id]) for alert_id in alert_ids if alert_id in RAW_ROWS]


def test_workflow_state_preserves_link_unlink_and_merge_history() -> None:
    events = [
        {"event_id": "e1", "operation": "create", "incident_id": "manual:one", "alert_ids": ["raw-1"], "title": "Manual", "severity": "high"},
        {"event_id": "e2", "operation": "link", "incident_id": "manual:one", "alert_id": "raw-2"},
        {"event_id": "e3", "operation": "unlink", "incident_id": "manual:one", "alert_id": "raw-1"},
        {"event_id": "e4", "operation": "merge", "incident_id": "manual:one", "target_incident_id": "agg:target", "alert_ids": ["raw-2"]},
    ]

    states = alerts._build_incident_workflow_states(events)

    assert alerts._effective_alert_ids(states["manual:one"]) == ["raw-2"]
    assert states["manual:one"]["merged_into"] == "agg:target"
    assert states["agg:target"]["linked_alert_ids"] == ["raw-2"]
    assert len(states["manual:one"]["operations"]) == 4
    assert states["manual:one"]["revision"] != "0"


def test_workflow_events_are_ordered_inside_same_clickhouse_second() -> None:
    class Result:
        def named_results(self):
            return iter([
                {
                    "changed_ts": "2026-08-03 10:00:00",
                    "record_id": "agg:one",
                    "rule_id": 1001,
                    "changed_by": "analyst",
                    "note": alerts.INCIDENT_WORKFLOW_NOTE_PREFIX + alerts._workflow_json(
                        {"event_id": "later", "sequence_ns": 20, "operation": "unlink", "incident_id": "agg:one", "alert_id": "raw-1"}
                    ),
                },
                {
                    "changed_ts": "2026-08-03 10:00:00",
                    "record_id": "agg:one",
                    "rule_id": 1001,
                    "changed_by": "analyst",
                    "note": alerts.INCIDENT_WORKFLOW_NOTE_PREFIX + alerts._workflow_json(
                        {"event_id": "earlier", "sequence_ns": 10, "operation": "link", "incident_id": "agg:one", "alert_id": "raw-1"}
                    ),
                },
            ])

    class Client:
        def query(self, _query: str) -> Result:
            return Result()

    with patch.object(alerts.deps_module, "get_ch_client", return_value=Client()):
        events = alerts._load_incident_workflow_events()

    assert [event["event_id"] for event in events] == ["earlier", "later"]
    state = alerts._build_incident_workflow_states(events)["agg:one"]
    assert alerts._effective_alert_ids(state) == []


def test_manual_incident_requires_real_alerts_and_is_idempotent() -> None:
    events: list[dict] = []

    def append(event: dict, **_: object) -> None:
        events.append(dict(event))

    payload = {
        "alert_ids": ["raw-1", "raw-2"],
        "title": "Confirmed attack chain",
        "severity": "critical",
        "idempotency_key": "create-attack-chain",
    }
    with (
        patch.object(alerts, "_load_incident_workflow_events", side_effect=lambda: [dict(event) for event in events]),
        patch.object(alerts, "_raw_alerts_by_ids", side_effect=raw_by_ids),
        patch.object(alerts, "_append_workflow_event", side_effect=append),
    ):
        created = alerts._create_manual_incident(payload, actor="analyst")
        replayed = alerts._create_manual_incident(payload, actor="analyst")

        assert created["incident_id"].startswith("manual:")
        assert created["item"]["raw_alerts_total"] == 2
        assert replayed["idempotent"] is True
        assert len(events) == 1

        with pytest.raises(alerts.IncidentWorkflowConflict, match="different operation"):
            alerts._create_manual_incident({**payload, "alert_ids": ["raw-1"]}, actor="analyst")

        with pytest.raises(ValueError, match="Raw alerts not found"):
            alerts._create_manual_incident(
                {"alert_ids": ["missing"], "idempotency_key": "missing-alert"},
                actor="analyst",
            )


def test_severity_update_rejects_stale_revision() -> None:
    incident = {"agg_id": "agg:one", "rule_id": 1001, "severity_agg": "high"}
    with (
        patch.object(alerts, "_load_incident_workflow_events", return_value=[]),
        patch.object(alerts, "_find_aggregate_incident", return_value=incident),
    ):
        with pytest.raises(alerts.IncidentWorkflowConflict, match="changed concurrently"):
            alerts._change_incident_severity(
                "agg:one",
                {"severity": "critical", "expected_revision": "stale", "idempotency_key": "severity-1"},
                actor="analyst",
            )


def test_link_unlink_and_merge_are_append_only() -> None:
    events: list[dict] = []
    incidents = {
        "agg:source": {"agg_id": "agg:source", "rule_id": 1001, "severity_agg": "high"},
        "agg:target": {"agg_id": "agg:target", "rule_id": 1002, "severity_agg": "critical"},
    }

    def append(event: dict, **_: object) -> None:
        events.append(dict(event))

    with (
        patch.object(alerts, "_load_incident_workflow_events", side_effect=lambda: [dict(event) for event in events]),
        patch.object(alerts, "_find_aggregate_incident", side_effect=lambda incident_id: incidents.get(incident_id)),
        patch.object(alerts, "_base_incident_alert_ids", side_effect=lambda incident: ["raw-1"] if incident and incident["agg_id"] == "agg:source" else []),
        patch.object(alerts, "_raw_alerts_by_ids", side_effect=raw_by_ids),
        patch.object(alerts, "_append_workflow_event", side_effect=append),
    ):
        linked = alerts._change_incident_alert_link(
            "agg:target",
            {"alert_id": "raw-2", "expected_revision": "0", "idempotency_key": "link-1"},
            actor="analyst",
            operation="link",
        )
        unlinked = alerts._change_incident_alert_link(
            "agg:target",
            {"alert_id": "raw-2", "expected_revision": linked["revision"], "idempotency_key": "unlink-1"},
            actor="analyst",
            operation="unlink",
        )
        merged = alerts._merge_incidents(
            "agg:source",
            {"target_incident_id": "agg:target", "expected_revision": "0", "idempotency_key": "merge-1"},
            actor="analyst",
        )

    assert [event["operation"] for event in events] == ["link", "unlink", "merge"]
    assert unlinked["revision"] != linked["revision"]
    assert merged["merged_alerts"] == 1
    assert events[-1]["alert_ids"] == ["raw-1"]


def test_every_incident_workflow_write_requires_response_run() -> None:
    source = (ROOT / "services" / "web" / "app" / "routes" / "alerts.py").read_text(encoding="utf-8")
    functions = (
        "create_manual_incident_api",
        "change_incident_severity_api",
        "link_raw_alert_api",
        "unlink_raw_alert_api",
        "merge_incidents_api",
    )
    for function in functions:
        match = re.search(rf"async def {function}\([\s\S]+?\) -> JSONResponse:", source)
        assert match, function
        assert "require_permissions('response:run')" in match.group(0), function
