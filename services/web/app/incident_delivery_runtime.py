from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from .enterprise_control_plane import load_control_plane_rows, save_control_plane_rows


COLLECTION_NAME = "incident_notification_delivery"
MAX_DELIVERY_ROWS = 2500
TERMINAL_INCIDENT_STATUSES = {
    "closed",
    "expired",
    "false_positive",
    "merged",
    "resolved",
    "suppressed",
    "suppressed_by_tuning",
}


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


def incident_delivery_key(row: dict[str, Any], view: str) -> str:
    normalized_view = "raw" if str(view or "").strip().lower() == "raw" else "agg"
    if normalized_view == "raw":
        return incident_record_key(row, normalized_view)

    group = row.get("group_key")
    if not isinstance(group, dict):
        raw_group = row.get("group_key_json")
        try:
            parsed_group = json.loads(raw_group) if isinstance(raw_group, str) and raw_group.strip() else {}
        except (TypeError, ValueError):
            parsed_group = {}
        group = parsed_group if isinstance(parsed_group, dict) else {}
    value = (
        group.get("incident_key")
        or group.get("agg_id")
        or row.get("aggregation_key")
        or incident_record_key(row, normalized_view)
    )
    return _text(value, limit=800)


def _aggregation_fingerprint(delivery_key: str) -> str:
    if not delivery_key:
        return ""
    return hashlib.sha256(f"agg|{delivery_key}".encode("utf-8")).hexdigest()


def _delivery_is_active(delivery: dict[str, Any]) -> bool:
    if "active" in delivery:
        return bool(delivery.get("active"))
    delivery_status = _text(delivery.get("delivery_status")).lower()
    incident_status = _text(delivery.get("incident_status")).lower()
    return (
        delivery_status not in {"deleted", "expired", "skipped", "telegram_disabled"}
        and incident_status not in TERMINAL_INCIDENT_STATUSES
    )


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
        "pending",
        "retrying",
        "uncertain",
        "sent",
        "edited",
        "unchanged",
        "skipped",
        "telegram_disabled",
        "edit_failed",
        "deleted",
        "expired",
        "delete_failed",
        "failed",
        "unknown",
    }:
        raise ValueError(f"Unsupported delivery status: {delivery_status}")
    incident_status = _text(payload.get("incident_status"), limit=80).lower()
    delivery_key = _text(payload.get("delivery_key") or incident_key, limit=800)
    active_default = (
        delivery_status not in {"deleted", "expired", "skipped", "telegram_disabled"}
        and incident_status not in TERMINAL_INCIDENT_STATUSES
    )
    row = {
        "key": f"{incident_view}:{incident_key}:{channel}",
        "incident_key": incident_key,
        "delivery_key": delivery_key,
        "aggregation_fingerprint": _text(payload.get("aggregation_fingerprint"), limit=160),
        "incident_view": incident_view,
        "channel": channel,
        "delivery_status": delivery_status,
        "incident_status": incident_status,
        "message_id": int(payload.get("message_id") or 0),
        "delivery_count": max(0, int(payload.get("delivery_count") or 0)),
        "active": bool(payload.get("active", active_default)),
        "operation": _text(payload.get("operation"), limit=80).lower(),
        "attempt_key": _text(payload.get("attempt_key"), limit=160),
        "reason": _text(payload.get("reason"), limit=300),
        "actor": _text(actor, limit=120) or "service",
        "updated_at": _text(payload.get("updated_at"), limit=80) or _now_iso(),
    }
    rows = load_control_plane_rows(COLLECTION_NAME)
    previous_scope = next(
        (
            dict(item)
            for item in rows
            if isinstance(item, dict)
            and _text(item.get("incident_view")).lower() == incident_view
            and _text(item.get("channel")).lower() == channel
            and _text(item.get("delivery_key") or item.get("incident_key"), limit=800) == delivery_key
        ),
        None,
    )
    if previous_scope:
        prior_count = max(0, int(previous_scope.get("delivery_count") or 0))
        same_attempt = (
            bool(row["attempt_key"])
            and row["attempt_key"] == _text(previous_scope.get("attempt_key"), limit=160)
        ) or (
            not row["attempt_key"]
            and not _text(previous_scope.get("attempt_key"), limit=160)
            and row["delivery_status"] == _text(previous_scope.get("delivery_status")).lower()
            and row["message_id"] == int(previous_scope.get("message_id") or 0)
        )
        row["delivery_count"] = prior_count if same_attempt else prior_count + row["delivery_count"]
    # A Web incident id can change while the aggregation scope remains the same
    # (for example after materialization or merge). Keep only one delivery row for
    # that stable scope so metrics and cards cannot fan out by an obsolete alias.
    rows = [
        item
        for item in rows
        if not (
            isinstance(item, dict)
            and _text(item.get("incident_view")).lower() == incident_view
            and _text(item.get("channel")).lower() == channel
            and _text(item.get("delivery_key") or item.get("incident_key"), limit=800) == delivery_key
            and _text(item.get("key"), limit=1200) != row["key"]
        )
    ]
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
            "delivery_key",
            "aggregation_fingerprint",
            "incident_view",
            "channel",
            "delivery_status",
            "incident_status",
            "message_id",
            "delivery_count",
            "active",
            "operation",
            "attempt_key",
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
    normalized_view = "raw" if str(view or "").strip().lower() == "raw" else "agg"
    if normalized_view == "raw":
        enriched = []
        for source in items:
            row = dict(source)
            row["notification_delivery"] = {
                "channel": "telegram",
                "delivery_status": "not_applicable",
                "incident_key": incident_record_key(row, normalized_view),
                "reason": "notifications_follow_aggregated_incidents",
            }
            enriched.append(row)
        return enriched, {
            "channel": "telegram",
            "mode": "aggregated_incidents_only",
            "queue_count": 0,
            "delivered": 0,
            "pending": 0,
            "failed": 0,
            "active_cards": 0,
            "retracted": 0,
            "synchronized": True,
            "updated_at": "",
        }
    rows = sorted(
        (
            dict(row)
            for row in load_control_plane_rows(COLLECTION_NAME)
            if isinstance(row, dict)
            and _text(row.get("incident_view")).lower() == normalized_view
            and _text(row.get("channel")).lower() == "telegram"
        ),
        key=lambda row: _text(row.get("updated_at")),
        reverse=True,
    )
    delivery_by_incident: dict[str, dict[str, Any]] = {}
    delivery_by_scope: dict[str, dict[str, Any]] = {}
    delivery_by_fingerprint: dict[str, dict[str, Any]] = {}
    for delivery in rows:
        incident_key = _text(delivery.get("incident_key"), limit=800)
        delivery_key = _text(delivery.get("delivery_key") or incident_key, limit=800)
        aggregation_fingerprint = _text(delivery.get("aggregation_fingerprint"), limit=160)
        if incident_key:
            delivery_by_incident.setdefault(incident_key, delivery)
        if delivery_key:
            delivery_by_scope.setdefault(delivery_key, delivery)
        if aggregation_fingerprint:
            delivery_by_fingerprint.setdefault(aggregation_fingerprint, delivery)
    enriched: list[dict[str, Any]] = []
    delivered = 0
    pending = 0
    failed = 0
    untracked = 0
    queue_count = 0
    active_message_ids: set[int] = set()
    retracted = 0
    matched_updates: list[str] = []
    for source in items:
        row = dict(source)
        incident_key = incident_record_key(row, normalized_view)
        delivery_key = incident_delivery_key(row, normalized_view)
        aggregation_fingerprint = _aggregation_fingerprint(delivery_key)
        delivery = (
            delivery_by_incident.get(incident_key)
            or delivery_by_scope.get(delivery_key)
            or delivery_by_fingerprint.get(aggregation_fingerprint)
        )
        incident_status = _text(row.get("status") or "new").lower()
        is_terminal_incident = incident_status in TERMINAL_INCIDENT_STATUSES
        if not is_terminal_incident:
            queue_count += 1
        if delivery:
            row["notification_delivery"] = delivery
            status = _text(delivery.get("delivery_status")).lower()
            is_active = _delivery_is_active(delivery)
            matched_updates.append(_text(delivery.get("updated_at")))
            if is_active and int(delivery.get("message_id") or 0) > 0:
                active_message_ids.add(int(delivery.get("message_id") or 0))
            if status in {"sent", "edited", "unchanged"} and is_active:
                delivered += 1
            elif status in {"edit_failed", "failed", "delete_failed", "uncertain"}:
                failed += 1
            elif not is_active:
                retracted += 1
            else:
                pending += 1
        elif is_terminal_incident:
            row["notification_delivery"] = {
                "channel": "telegram",
                "delivery_status": "not_recorded",
                "incident_key": incident_key,
                "delivery_key": delivery_key,
                "reason": "terminal_incident_has_no_recorded_delivery",
            }
            untracked += 1
        else:
            row["notification_delivery"] = {
                "channel": "telegram",
                "delivery_status": "pending",
                "incident_key": incident_key,
                "delivery_key": delivery_key,
            }
            pending += 1
        enriched.append(row)
    return enriched, {
        "channel": "telegram",
        "queue_count": queue_count,
        "record_count": len(enriched),
        "delivered": delivered,
        "pending": pending,
        "failed": failed,
        "untracked": untracked,
        "active_cards": len(active_message_ids),
        "retracted": retracted,
        "synchronized": pending == 0 and failed == 0,
        "updated_at": max(matched_updates, default=""),
    }
