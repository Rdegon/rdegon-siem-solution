from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

try:
    from . import enterprise_control_plane as core
except ImportError:  # pragma: no cover - local test fallback
    import enterprise_control_plane as core  # type: ignore[no-redef]


CONTROL_PLANE_SCHEMA_VERSION = core.CONTROL_PLANE_SCHEMA_VERSION
_collection = core._collection
_find_by_id = core._find_by_id
_json_clone = core._json_clone
_new_id = core._new_id
_now_iso = core._now_iso
_safe_slug = core._safe_slug
_save_collection = core._save_collection
append_audit_event = core.append_audit_event


def _default_source_policies() -> list[dict[str, Any]]:
    return []


def _normalize_policy(payload: dict[str, Any], existing: dict[str, Any] | None = None) -> dict[str, Any]:
    current = dict(existing or {})
    name = str(payload.get("name") or current.get("name") or "").strip()
    if not name:
        raise ValueError("Source policy name is required")
    source_pattern = str(
        payload.get("source_pattern")
        if "source_pattern" in payload
        else current.get("source_pattern") or ""
    ).strip()
    if not source_pattern:
        raise ValueError("Source pattern is required")
    policy_id = _safe_slug(
        str(payload.get("id") or current.get("id") or name),
        default=_new_id("source-policy"),
    )
    min_events = max(0, int(payload.get("min_events") if "min_events" in payload else current.get("min_events") or 0))
    max_events = max(0, int(payload.get("max_events") if "max_events" in payload else current.get("max_events") or 0))
    if max_events and max_events < min_events:
        raise ValueError("max_events must be greater than or equal to min_events")
    return {
        "id": policy_id,
        "type": "source_monitoring_policy",
        "schema_version": CONTROL_PLANE_SCHEMA_VERSION,
        "name": name,
        "description": str(payload.get("description") if "description" in payload else current.get("description") or "").strip(),
        "enabled": bool(payload.get("enabled", current.get("enabled", True))),
        "source_pattern": source_pattern,
        "window_hours": max(1, min(int(payload.get("window_hours") or current.get("window_hours") or 24), 720)),
        "min_events": min_events,
        "max_events": max_events,
        "stale_after_minutes": max(
            1,
            min(int(payload.get("stale_after_minutes") or current.get("stale_after_minutes") or 30), 43200),
        ),
        "severity": str(payload.get("severity") or current.get("severity") or "high").strip().lower(),
        "notifications": [
            str(item).strip()
            for item in (
                payload.get("notifications")
                if isinstance(payload.get("notifications"), list)
                else current.get("notifications") or []
            )
            if str(item).strip()
        ],
        "owner": str(payload.get("owner") or current.get("owner") or "siem-engineering").strip(),
        "created_ts": str(current.get("created_ts") or _now_iso()),
        "updated_ts": _now_iso(),
    }


def list_source_policies() -> list[dict[str, Any]]:
    rows = _collection("source_monitoring_policies", _default_source_policies)
    normalized = [_normalize_policy(item, item) for item in rows]
    if normalized != rows:
        _save_collection("source_monitoring_policies", normalized)
    normalized.sort(key=lambda item: str(item.get("name") or item.get("id") or "").lower())
    return _json_clone(normalized)


def save_source_policy(payload: dict[str, Any], *, actor: str = "system") -> dict[str, Any]:
    rows = list_source_policies()
    requested_id = str(payload.get("id") or "").strip()
    existing = _find_by_id(rows, requested_id) if requested_id else None
    item = _normalize_policy(payload, existing)
    rows = [row for row in rows if str(row.get("id") or "") != item["id"]]
    rows.append(item)
    _save_collection("source_monitoring_policies", rows)
    append_audit_event(
        actor=actor,
        action="source_policy.saved",
        object_type="source_monitoring_policy",
        object_id=item["id"],
        summary=item["name"],
        details={
            "source_pattern": item["source_pattern"],
            "window_hours": item["window_hours"],
            "min_events": item["min_events"],
            "max_events": item["max_events"],
        },
    )
    return _json_clone(item)


def delete_source_policy(policy_id: str, *, actor: str = "system") -> dict[str, Any]:
    rows = list_source_policies()
    existing = _find_by_id(rows, policy_id)
    if existing is None:
        raise ValueError(f"Source policy not found: {policy_id}")
    _save_collection(
        "source_monitoring_policies",
        [row for row in rows if str(row.get("id") or "") != policy_id],
    )
    append_audit_event(
        actor=actor,
        action="source_policy.deleted",
        object_type="source_monitoring_policy",
        object_id=policy_id,
        summary=str(existing.get("name") or policy_id),
        details={},
    )
    return {"deleted": True, "id": policy_id}


def _parse_ts(value: Any) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.replace(tzinfo=parsed.tzinfo or timezone.utc).astimezone(timezone.utc)


def evaluate_source_policies(
    sources: list[dict[str, Any]],
    *,
    policies: list[dict[str, Any]] | None = None,
    now: datetime | None = None,
) -> list[dict[str, Any]]:
    evaluated_ts = now or datetime.now(timezone.utc)
    results: list[dict[str, Any]] = []
    for policy in policies if policies is not None else list_source_policies():
        pattern = str(policy.get("source_pattern") or "").strip().lower()
        matches: list[dict[str, Any]] = []
        for source in sources:
            haystack = " ".join(
                [
                    str(source.get("source_name") or ""),
                    str(source.get("source_type") or ""),
                    str(source.get("collector_name") or source.get("collector_id") or ""),
                    " ".join(str(item) for item in list(source.get("products") or [])),
                    " ".join(str(item) for item in list(source.get("aliases") or [])),
                ]
            ).lower()
            if pattern in haystack:
                matches.append(source)

        violations: list[dict[str, Any]] = []
        if bool(policy.get("enabled", True)):
            for source in matches:
                events = int(source.get("events") or 0)
                reasons: list[str] = []
                min_events = int(policy.get("min_events") or 0)
                max_events = int(policy.get("max_events") or 0)
                if min_events and events < min_events:
                    reasons.append("below_min_events")
                if max_events and events > max_events:
                    reasons.append("above_max_events")
                last_seen = _parse_ts(source.get("last_seen"))
                stale_seconds = int(policy.get("stale_after_minutes") or 30) * 60
                if last_seen is None or (evaluated_ts - last_seen).total_seconds() > stale_seconds:
                    reasons.append("stale")
                if reasons:
                    violations.append(
                        {
                            "source_name": str(source.get("source_name") or ""),
                            "events": events,
                            "last_seen": str(source.get("last_seen") or ""),
                            "reasons": reasons,
                        }
                    )
        result = {
            **policy,
            "matched_sources": len(matches),
            "violation_count": len(violations),
            "violations": violations,
            "evaluation_status": (
                "disabled"
                if not bool(policy.get("enabled", True))
                else "unmatched"
                if not matches
                else "breached"
                if violations
                else "healthy"
            ),
            "evaluated_ts": evaluated_ts.isoformat(),
        }
        results.append(result)
    return _json_clone(results)
