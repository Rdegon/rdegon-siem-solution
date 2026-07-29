from __future__ import annotations

from unittest.mock import patch

from services.web.app.incident_delivery_runtime import (
    enrich_incidents_with_delivery,
    record_incident_delivery,
)


def test_record_delivery_persists_and_deduplicates_unchanged_state() -> None:
    stored: list[dict] = []

    def load(_: str) -> list[dict]:
        return [dict(row) for row in stored]

    def save(_: str, rows: list[dict]) -> None:
        stored[:] = [dict(row) for row in rows]

    payload = {
        "incident_key": "INC-42",
        "incident_view": "agg",
        "channel": "telegram",
        "delivery_status": "sent",
        "incident_status": "new",
        "message_id": 123,
        "delivery_count": 1,
        "updated_at": "2026-07-29T12:00:00Z",
    }
    with (
        patch(
            "services.web.app.incident_delivery_runtime.load_control_plane_rows",
            side_effect=load,
        ),
        patch(
            "services.web.app.incident_delivery_runtime.save_control_plane_rows",
            side_effect=save,
        ) as save_mock,
    ):
        first = record_incident_delivery(payload, actor="incident-bot")
        duplicate = record_incident_delivery(
            {**payload, "updated_at": "2026-07-29T12:01:00Z"},
            actor="incident-bot",
        )

    assert first == duplicate
    assert save_mock.call_count == 1


def test_enrich_incidents_reports_telegram_queue_state() -> None:
    deliveries = [
        {
            "incident_key": "INC-1",
            "incident_view": "agg",
            "channel": "telegram",
            "delivery_status": "sent",
            "message_id": 10,
            "updated_at": "2026-07-29T12:00:00Z",
        },
        {
            "incident_key": "INC-2",
            "incident_view": "agg",
            "channel": "telegram",
            "delivery_status": "failed",
            "message_id": 0,
            "updated_at": "2026-07-29T12:01:00Z",
        },
    ]
    with patch(
        "services.web.app.incident_delivery_runtime.load_control_plane_rows",
        return_value=deliveries,
    ):
        items, summary = enrich_incidents_with_delivery(
            [
                {"agg_id": "INC-1"},
                {"agg_id": "INC-2"},
                {"agg_id": "INC-3"},
            ],
            view="agg",
        )

    assert items[0]["notification_delivery"]["delivery_status"] == "sent"
    assert items[2]["notification_delivery"]["delivery_status"] == "pending"
    assert summary == {
        "channel": "telegram",
        "queue_count": 3,
        "delivered": 1,
        "pending": 1,
        "failed": 1,
        "synchronized": False,
        "updated_at": "2026-07-29T12:01:00Z",
    }
