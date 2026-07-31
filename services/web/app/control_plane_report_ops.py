from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timedelta, timezone
from typing import Any, Callable
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

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

REPORT_SECTION_IDS = (
    "executive_summary",
    "incidents",
    "sources",
    "assets",
    "vulnerabilities",
    "platform",
)
REPORT_FORMATS = ("json", "csv")
_PERIOD_HOURS = {
    "12h": 12,
    "24h": 24,
    "7d": 24 * 7,
    "30d": 24 * 30,
}


def _default_report_templates() -> list[dict[str, Any]]:
    return [
        {
            "id": "soc-shift-summary",
            "name": "SOC shift summary",
            "description": "Incidents, source health and platform status for the current SOC shift.",
            "owner": "soc-ops",
            "tenant_scope": ["all"],
            "period": "12h",
            "retention_days": 90,
            "sections": ["executive_summary", "incidents", "sources", "platform"],
            "formats": ["json", "csv"],
            "schedule": {
                "enabled": False,
                "frequency": "shift",
                "time": "08:00",
                "timezone": "Europe/Moscow",
                "recipients": [],
            },
        },
        {
            "id": "source-health-daily",
            "name": "Source health daily",
            "description": "Observed source coverage, delivery state and asset visibility.",
            "owner": "siem-engineering",
            "tenant_scope": ["all"],
            "period": "24h",
            "retention_days": 90,
            "sections": ["executive_summary", "sources", "assets", "platform"],
            "formats": ["json", "csv"],
            "schedule": {
                "enabled": False,
                "frequency": "daily",
                "time": "08:00",
                "timezone": "Europe/Moscow",
                "recipients": [],
            },
        },
        {
            "id": "exposure-weekly",
            "name": "Exposure management weekly",
            "description": "Vulnerability findings and exposed asset coverage for the last seven days.",
            "owner": "exposure-management",
            "tenant_scope": ["all"],
            "period": "7d",
            "retention_days": 365,
            "sections": ["executive_summary", "assets", "vulnerabilities"],
            "formats": ["json", "csv"],
            "schedule": {
                "enabled": False,
                "frequency": "weekly",
                "time": "09:00",
                "timezone": "Europe/Moscow",
                "recipients": [],
            },
        },
    ]


def _string_list(value: Any, *, allowed: tuple[str, ...] | None = None) -> list[str]:
    if isinstance(value, str):
        values = [part.strip() for part in value.split(",")]
    else:
        values = [str(item).strip() for item in (value or [])]
    normalized = list(dict.fromkeys(item for item in values if item))
    if allowed is not None:
        normalized = [item for item in normalized if item in allowed]
    return normalized


def _normalize_template(payload: dict[str, Any], existing: dict[str, Any] | None = None) -> dict[str, Any]:
    current = dict(existing or {})
    name = str(payload.get("name") or payload.get("title") or current.get("name") or "").strip()
    if not name:
        raise ValueError("Report template name is required")
    template_id = _safe_slug(
        str(payload.get("id") or current.get("id") or name),
        default=_new_id("report-template"),
    )
    period = str(payload.get("period") or current.get("period") or "24h").strip().lower()
    if period not in _PERIOD_HOURS:
        raise ValueError(f"Unsupported report period: {period}")
    sections = _string_list(
        payload.get("sections") if "sections" in payload else current.get("sections"),
        allowed=REPORT_SECTION_IDS,
    )
    if not sections:
        raise ValueError("At least one report section is required")
    formats = _string_list(
        payload.get("formats") if "formats" in payload else current.get("formats"),
        allowed=REPORT_FORMATS,
    )
    if not formats:
        formats = ["json"]
    schedule_payload = dict(payload.get("schedule") or current.get("schedule") or {})
    schedule = {
        "enabled": bool(schedule_payload.get("enabled", False)),
        "frequency": str(schedule_payload.get("frequency") or "daily").strip().lower(),
        "time": str(schedule_payload.get("time") or "08:00").strip(),
        "timezone": str(schedule_payload.get("timezone") or "Europe/Moscow").strip(),
        "recipients": _string_list(schedule_payload.get("recipients")),
    }
    return {
        "id": template_id,
        "type": "report_template",
        "schema_version": CONTROL_PLANE_SCHEMA_VERSION,
        "name": name,
        "description": str(payload.get("description") if "description" in payload else current.get("description") or "").strip(),
        "owner": str(payload.get("owner") or current.get("owner") or "soc-ops").strip(),
        "tenant_scope": _string_list(
            payload.get("tenant_scope") if "tenant_scope" in payload else current.get("tenant_scope")
        )
        or ["all"],
        "period": period,
        "retention_days": max(
            1,
            min(int(payload.get("retention_days") or current.get("retention_days") or 90), 3650),
        ),
        "sections": sections,
        "formats": formats,
        "schedule": schedule,
        "created_ts": str(current.get("created_ts") or _now_iso()),
        "updated_ts": _now_iso(),
    }


def list_report_templates() -> list[dict[str, Any]]:
    rows = _collection("report_templates", _default_report_templates)
    normalized = [_normalize_template(item, item) for item in rows]
    if normalized != rows:
        _save_collection("report_templates", normalized)
    normalized.sort(key=lambda item: str(item.get("name") or item.get("id") or "").lower())
    return _json_clone(normalized)


def get_report_template(template_id: str) -> dict[str, Any] | None:
    return _json_clone(_find_by_id(list_report_templates(), template_id))


def save_report_template(payload: dict[str, Any], *, actor: str = "system") -> dict[str, Any]:
    rows = list_report_templates()
    requested_id = str(payload.get("id") or "").strip()
    existing = _find_by_id(rows, requested_id) if requested_id else None
    item = _normalize_template(payload, existing)
    rows = [row for row in rows if str(row.get("id") or "") != item["id"]]
    rows.append(item)
    _save_collection("report_templates", rows)
    append_audit_event(
        actor=actor,
        action="report_template.saved",
        object_type="report_template",
        object_id=item["id"],
        summary=item["name"],
        details={
            "period": item["period"],
            "sections": item["sections"],
            "schedule_enabled": item["schedule"]["enabled"],
        },
    )
    return _json_clone(item)


def delete_report_template(template_id: str, *, actor: str = "system") -> dict[str, Any]:
    rows = list_report_templates()
    existing = _find_by_id(rows, template_id)
    if existing is None:
        raise ValueError(f"Report template not found: {template_id}")
    _save_collection(
        "report_templates",
        [row for row in rows if str(row.get("id") or "") != template_id],
    )
    append_audit_event(
        actor=actor,
        action="report_template.deleted",
        object_type="report_template",
        object_id=template_id,
        summary=str(existing.get("name") or template_id),
        details={},
    )
    return {"deleted": True, "id": template_id}


def _default_report_runs() -> list[dict[str, Any]]:
    return []


def list_report_runs(*, limit: int = 100) -> list[dict[str, Any]]:
    safe_limit = max(1, min(int(limit or 100), 500))
    rows = _collection("report_runs", _default_report_runs)
    rows.sort(
        key=lambda item: str(item.get("created_ts") or item.get("id") or ""),
        reverse=True,
    )
    summaries = []
    for row in rows[:safe_limit]:
        summary = {key: value for key, value in row.items() if key != "snapshot"}
        summaries.append(summary)
    return _json_clone(summaries)


def get_report_run(run_id: str) -> dict[str, Any] | None:
    return _json_clone(_find_by_id(_collection("report_runs", _default_report_runs), run_id))


def _hours_for_period(period: str) -> int:
    return _PERIOD_HOURS.get(str(period or "24h").lower(), 24)


def _default_section_loaders(hours: int) -> dict[str, Callable[[], Any]]:
    from .query.alerts import fetch_alerts_agg
    from .query.assets import fetch_assets
    from .query.dashboard import fetch_dashboard_snapshot, fetch_platform_status
    from .query.sources import fetch_source_inventory
    from .vulnerability_query_runtime import fetch_vulnerability_reports

    window = next(
        (name for name, value in _PERIOD_HOURS.items() if value == hours),
        "24h",
    )
    return {
        "executive_summary": lambda: fetch_dashboard_snapshot(
            window=window,
            bucket_minutes=max(15, min(720, hours * 60 // 24)),
            recent_limit=20,
        ),
        "incidents": lambda: fetch_alerts_agg(limit=200, window=window),
        "sources": lambda: fetch_source_inventory(limit=300, hours=min(hours, 720)),
        "assets": lambda: fetch_assets(limit=500, hours=min(hours, 720)),
        "vulnerabilities": lambda: fetch_vulnerability_reports(
            limit=200,
            days=max(1, min(90, (hours + 23) // 24)),
        ),
        "platform": fetch_platform_status,
    }


def _count_records(value: Any) -> int:
    if isinstance(value, list):
        return len(value)
    if isinstance(value, dict):
        for key in ("items", "rows", "incidents", "alerts", "sources", "assets"):
            nested = value.get(key)
            if isinstance(nested, list):
                return len(nested)
        return 1
    return 0


def generate_report_run(
    template_id: str,
    *,
    actor: str = "system",
    tenant_scope: list[str] | None = None,
    loaders: dict[str, Callable[[], Any]] | None = None,
) -> dict[str, Any]:
    template = get_report_template(template_id)
    if template is None:
        raise ValueError(f"Report template not found: {template_id}")
    created = datetime.now(timezone.utc)
    hours = _hours_for_period(str(template.get("period") or "24h"))
    selected_sections = list(template.get("sections") or [])
    section_loaders = dict(loaders or _default_section_loaders(hours))
    snapshot: dict[str, Any] = {}
    errors: list[dict[str, str]] = []
    record_count = 0
    for section_id in selected_sections:
        loader = section_loaders.get(section_id)
        if loader is None:
            errors.append({"section": section_id, "error": "section loader is unavailable"})
            continue
        try:
            value = loader()
            snapshot[section_id] = value
            record_count += _count_records(value)
        except Exception as exc:  # noqa: BLE001
            errors.append({"section": section_id, "error": str(exc)})

    completed = datetime.now(timezone.utc)
    if snapshot and errors:
        status = "completed_with_warnings"
    elif snapshot:
        status = "completed"
    else:
        status = "failed"
    run_id = _new_id("report-run")
    run = {
        "id": run_id,
        "type": "report_run",
        "schema_version": CONTROL_PLANE_SCHEMA_VERSION,
        "template_id": template["id"],
        "name": template["name"],
        "description": template.get("description") or "",
        "status": status,
        "owner": actor,
        "tenant_scope": list(tenant_scope or template.get("tenant_scope") or ["all"]),
        "period": {
            "window": template["period"],
            "from_ts": (created - timedelta(hours=hours)).isoformat(),
            "to_ts": created.isoformat(),
        },
        "formats": list(template.get("formats") or ["json"]),
        "sections": selected_sections,
        "section_count": len(snapshot),
        "record_count": record_count,
        "errors": errors,
        "snapshot": snapshot,
        "created_ts": created.isoformat(),
        "completed_ts": completed.isoformat(),
        "duration_ms": max(0, int((completed - created).total_seconds() * 1000)),
    }
    rows = _collection("report_runs", _default_report_runs)
    rows.append(run)
    retention_days = int(template.get("retention_days") or 90)
    cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
    retained: list[dict[str, Any]] = []
    for row in rows:
        try:
            row_ts = datetime.fromisoformat(str(row.get("created_ts") or "").replace("Z", "+00:00"))
        except ValueError:
            row_ts = completed
        if row_ts >= cutoff or str(row.get("template_id") or "") != template_id:
            retained.append(row)
    _save_collection("report_runs", retained[-500:])
    append_audit_event(
        actor=actor,
        action="report.generated",
        object_type="report_run",
        object_id=run_id,
        summary=template["name"],
        details={
            "template_id": template["id"],
            "status": status,
            "record_count": record_count,
            "duration_ms": run["duration_ms"],
        },
    )
    return _json_clone(run)


def _parse_datetime(value: Any) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.replace(tzinfo=parsed.tzinfo or timezone.utc).astimezone(timezone.utc)


def _scheduled_slot(template: dict[str, Any], now: datetime) -> datetime | None:
    schedule = dict(template.get("schedule") or {})
    if not bool(schedule.get("enabled")):
        return None
    try:
        schedule_zone = ZoneInfo(str(schedule.get("timezone") or "UTC"))
    except ZoneInfoNotFoundError:
        schedule_zone = timezone.utc
    local_now = now.astimezone(schedule_zone)
    try:
        hour_text, minute_text = str(schedule.get("time") or "08:00").split(":", 1)
        hour = max(0, min(int(hour_text), 23))
        minute = max(0, min(int(minute_text), 59))
    except (TypeError, ValueError):
        hour, minute = 8, 0
    frequency = str(schedule.get("frequency") or "daily").strip().lower()
    base = local_now.replace(hour=hour, minute=minute, second=0, microsecond=0)
    if frequency == "shift":
        slots = (base, base + timedelta(hours=12))
        due_slots = [slot for slot in slots if slot <= local_now]
        return max(due_slots).astimezone(timezone.utc) if due_slots else None
    if frequency == "weekly":
        slot = base - timedelta(days=base.weekday())
    elif frequency == "monthly":
        slot = base.replace(day=1)
    else:
        slot = base
    if slot > local_now:
        return None
    return slot.astimezone(timezone.utc)


def run_due_report_templates(
    *,
    actor: str = "report-scheduler",
    now: datetime | None = None,
    loaders: dict[str, Callable[[], Any]] | None = None,
) -> dict[str, Any]:
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    runs = _collection("report_runs", _default_report_runs)
    generated: list[dict[str, Any]] = []
    skipped: list[dict[str, str]] = []
    for template in list_report_templates():
        slot = _scheduled_slot(template, current)
        if slot is None:
            skipped.append({"template_id": template["id"], "reason": "not_due"})
            continue
        latest = max(
            (
                parsed
                for parsed in (
                    _parse_datetime(row.get("created_ts"))
                    for row in runs
                    if str(row.get("template_id") or "") == template["id"]
                )
                if parsed is not None
            ),
            default=None,
        )
        if latest is not None and latest >= slot:
            skipped.append({"template_id": template["id"], "reason": "slot_already_generated"})
            continue
        generated.append(
            generate_report_run(
                template["id"],
                actor=actor,
                tenant_scope=list(template.get("tenant_scope") or ["all"]),
                loaders=loaders,
            )
        )
    return {
        "generated_ts": current.isoformat(),
        "generated": generated,
        "skipped": skipped,
    }


def report_run_json(run: dict[str, Any]) -> str:
    return json.dumps(run, ensure_ascii=False, indent=2, default=str)


def report_run_csv(run: dict[str, Any]) -> str:
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(("report_id", run.get("id") or ""))
    writer.writerow(("template_id", run.get("template_id") or ""))
    writer.writerow(("name", run.get("name") or ""))
    writer.writerow(("status", run.get("status") or ""))
    writer.writerow(("created_ts", run.get("created_ts") or ""))
    writer.writerow(("period_from", dict(run.get("period") or {}).get("from_ts") or ""))
    writer.writerow(("period_to", dict(run.get("period") or {}).get("to_ts") or ""))
    writer.writerow(())
    writer.writerow(("section", "record", "payload"))
    for section_id, value in dict(run.get("snapshot") or {}).items():
        if isinstance(value, list):
            rows = value
        elif isinstance(value, dict) and isinstance(value.get("items"), list):
            rows = value["items"]
        else:
            rows = [value]
        for index, item in enumerate(rows, start=1):
            writer.writerow(
                (
                    section_id,
                    index,
                    json.dumps(item, ensure_ascii=False, separators=(",", ":"), default=str),
                )
            )
    return output.getvalue()
