from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .enterprise_control_plane import load_control_plane_rows, save_control_plane_rows


COLLECTION_NAME = "incident_notification_delivery"
MAX_DELIVERY_ROWS = 2500


def _now_iso() -> str:
    return datetime.now(tz=timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _text(value: Any, *, limit: int = 500) -> str:
    return str(value or "").strip()[:limit]


def incident_record_key(row: dict[str, Any], view: str) -> str:
    normalized_view = "raw" if str(view or "").strip().lower() == "raw" else "agg"
    value = (
        row.get("record_id")
        or (row.get("alert_id") if normalized_view == "raw" else row.get("agg_id"))
        or row.get("agg_id")
        or row.get("alert_id")
        or row.get("id")
    )
    return _text(value, limit=800)


def record_incident_delivery(payload: dict[str, Any], *, actor: str) -> dict[str, Any]:
    incident_key = _text(payload.get("incident_key"), limit=800)
    if not incident_key:
        raise ValueError("incident_key is required")
    incident_view = "raw" if _text(payload.get("incident_view")).lower() == "raw" else "agg"
    channel = _text(payload.get("channel") or "telegram", limit=40).lower()
    if channel != "telegram":
        raise ValueError(f"Unsupported incident notification channel: {channel}")
    delivery_status = _text(payload.get("delivery_status") or "unknown", limit=80).lower()
    if delivery_status not in {
        "sent",
        "edited",
        "unchanged",
        "skipped",
        "telegram_disabled",
        "edit_failed",
        "failed",
        "unknown",
    }:
        raise ValueError(f"Unsupported delivery status: {delivery_status}")
    row = {
        "key": f"{incident_view}:{incident_key}:{channel}",
        "incident_key": incident_key,
        "incident_view": incident_view,
        "channel": channel,
        "delivery_status": delivery_status,
        "incident_status": _text(payload.get("incident_status"), limit=80).lower(),
        "message_id": int(payload.get("message_id") or 0),
        "delivery_count": max(0, int(payload.get("delivery_count") or 0)),
        "reason": _text(payload.get("reason"), limit=300),
        "actor": _text(actor, limit=120) or "service",
        "updated_at": _text(payload.get("updated_at"), limit=80) or _now_iso(),
    }
    rows = load_control_plane_rows(COLLECTION_NAME)
    rows_by_key = {
        _text(item.get("key"), limit=1200): dict(item)
        for item in rows
        if isinstance(item, dict) and _text(item.get("key"), limit=1200)
    }
    previous = rows_by_key.get(row["key"])
    if previous and all(
        previous.get(field) == row.get(field)
        for field in (
            "incident_key",
            "incident_view",
            "channel",
            "delivery_status",
            "incident_status",
            "message_id",
            "delivery_count",
            "reason",
            "actor",
        )
    ):
        return dict(previous)
    rows_by_key[row["key"]] = row
    ordered = sorted(
        rows_by_key.values(),
        key=lambda item: _text(item.get("updated_at")),
        reverse=True,
    )[:MAX_DELIVERY_ROWS]
    save_control_plane_rows(COLLECTION_NAME, ordered)
    return dict(row)


def enrich_incidents_with_delivery(
    items: list[dict[str, Any]],
    *,
    view: str,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    rows = load_control_plane_rows(COLLECTION_NAME)
    normalized_view = "raw" if str(view or "").strip().lower() == "raw" else "agg"
    delivery_by_incident = {
        _text(row.get("incident_key"), limit=800): dict(row)
        for row in rows
        if isinstance(row, dict)
        and _text(row.get("incident_view")).lower() == normalized_view
        and _text(row.get("channel")).lower() == "telegram"
    }
    enriched: list[dict[str, Any]] = []
    delivered = 0
    pending = 0
    failed = 0
    for source in items:
        row = dict(source)
        incident_key = incident_record_key(row, normalized_view)
        delivery = delivery_by_incident.get(incident_key)
        if delivery:
            row["notification_delivery"] = delivery
            status = _text(delivery.get("delivery_status")).lower()
            if status in {"sent", "edited", "unchanged"}:
                delivered += 1
            elif status in {"edit_failed", "failed"}:
                failed += 1
            else:
                pending += 1
        else:
            row["notification_delivery"] = {
                "channel": "telegram",
                "delivery_status": "pending",
                "incident_key": incident_key,
            }
            pending += 1
        enriched.append(row)
    return enriched, {
        "channel": "telegram",
        "queue_count": len(enriched),
        "delivered": delivered,
        "pending": pending,
        "failed": failed,
        "synchronized": pending == 0 and failed == 0,
        "updated_at": max(
            (_text(item.get("updated_at")) for item in delivery_by_incident.values()),
            default="",
        ),
    }
