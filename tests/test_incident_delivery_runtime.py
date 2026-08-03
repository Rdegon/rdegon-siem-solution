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


def test_record_delivery_accepts_card_lifecycle_states() -> None:
    stored: list[dict] = []

    with (
        patch(
            "services.web.app.incident_delivery_runtime.load_control_plane_rows",
            side_effect=lambda _: [dict(row) for row in stored],
        ),
        patch(
            "services.web.app.incident_delivery_runtime.save_control_plane_rows",
            side_effect=lambda _, rows: stored.__setitem__(slice(None), [dict(row) for row in rows]),
        ),
    ):
        for status in ("deleted", "expired", "delete_failed"):
            result = record_incident_delivery(
                {
                    "incident_key": f"INC-{status}",
                    "incident_view": "agg",
                    "channel": "telegram",
                    "delivery_status": status,
                    "incident_status": "expired",
                },
                actor="incident-bot",
            )
            assert result["delivery_status"] == status


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
        "active_cards": 1,
        "retracted": 0,
        "synchronized": False,
        "updated_at": "2026-07-29T12:01:00Z",
    }


def test_delivery_key_replaces_obsolete_incident_alias() -> None:
    stored: list[dict] = []

    with (
        patch(
            "services.web.app.incident_delivery_runtime.load_control_plane_rows",
            side_effect=lambda _: [dict(row) for row in stored],
        ),
        patch(
            "services.web.app.incident_delivery_runtime.save_control_plane_rows",
            side_effect=lambda _, rows: stored.__setitem__(slice(None), [dict(row) for row in rows]),
        ),
    ):
        record_incident_delivery(
            {
                "incident_key": "old-web-id",
                "delivery_key": "asset:web|campaign:ssh",
                "incident_view": "agg",
                "delivery_status": "sent",
                "incident_status": "open",
                "message_id": 41,
                "delivery_count": 1,
                "active": True,
            },
            actor="incident-bot",
        )
        record_incident_delivery(
            {
                "incident_key": "new-web-id",
                "delivery_key": "asset:web|campaign:ssh",
                "incident_view": "agg",
                "delivery_status": "edited",
                "incident_status": "open",
                "message_id": 41,
                "active": True,
            },
            actor="incident-bot",
        )

    assert len(stored) == 1
    assert stored[0]["incident_key"] == "new-web-id"
    assert stored[0]["message_id"] == 41
    assert stored[0]["delivery_count"] == 1


def test_terminal_delivery_is_not_counted_as_an_active_card() -> None:
    with patch(
        "services.web.app.incident_delivery_runtime.load_control_plane_rows",
        return_value=[
            {
                "incident_key": "INC-closed",
                "incident_view": "agg",
                "channel": "telegram",
                "delivery_status": "deleted",
                "incident_status": "closed",
                "message_id": 0,
                "active": False,
                "updated_at": "2026-07-29T12:02:00Z",
            }
        ],
    ):
        _, summary = enrich_incidents_with_delivery([{"agg_id": "INC-closed"}], view="agg")

    assert summary["active_cards"] == 0
    assert summary["retracted"] == 1


def test_raw_alert_view_never_reports_independent_notification_fanout() -> None:
    with patch(
        "services.web.app.incident_delivery_runtime.load_control_plane_rows"
    ) as load_mock:
        items, summary = enrich_incidents_with_delivery(
            [{"alert_id": "raw-1"}, {"alert_id": "raw-2"}],
            view="raw",
        )

    load_mock.assert_not_called()
    assert summary["mode"] == "aggregated_incidents_only"
    assert summary["queue_count"] == 0
    assert summary["pending"] == 0
    assert items[0]["notification_delivery"]["delivery_status"] == "not_applicable"
