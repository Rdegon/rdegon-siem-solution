from __future__ import annotations

import csv
import hashlib
import io
import json
import logging
import re
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable
from xml.sax.saxutils import escape
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
REPORT_FORMATS = ("json", "csv", "pdf")
REPORT_FREQUENCIES = ("shift", "daily", "weekly", "monthly")
REPORT_TENANTS = ("main",)
TERMINAL_RUN_STATUSES = {"completed", "completed_with_warnings", "failed"}
ACTIVE_RUN_STATUSES = {"queued", "running"}
_RUN_LOCK = core._LOCK
_ACTIVE_LOCK = threading.Lock()
_ACTIVE_RUNS: set[str] = set()
_SAFE_IDEMPOTENCY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:+-]{7,159}$")
logger = logging.getLogger("siem_web.reporting")
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
            "tenant_scope": ["main"],
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
            "tenant_scope": ["main"],
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
            "tenant_scope": ["main"],
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


def _normalize_tenant_scope(value: Any) -> list[str]:
    requested = _string_list(value)
    if not requested or requested == ["all"]:
        return ["main"]
    invalid = sorted(set(requested) - set(REPORT_TENANTS))
    if invalid:
        raise ValueError(f"Tenant scope is not available: {', '.join(invalid)}")
    return [tenant for tenant in REPORT_TENANTS if tenant in requested]


def _normalize_schedule(value: Any) -> dict[str, Any]:
    schedule_payload = dict(value or {})
    frequency = str(schedule_payload.get("frequency") or "daily").strip().lower()
    if frequency not in REPORT_FREQUENCIES:
        raise ValueError(f"Unsupported report frequency: {frequency}")
    schedule_time = str(schedule_payload.get("time") or "08:00").strip()
    if not re.fullmatch(r"(?:[01]\d|2[0-3]):[0-5]\d", schedule_time):
        raise ValueError("Report schedule time must use HH:MM")
    timezone_name = str(schedule_payload.get("timezone") or "Europe/Moscow").strip()
    try:
        ZoneInfo(timezone_name)
    except ZoneInfoNotFoundError as exc:
        raise ValueError(f"Unknown report schedule timezone: {timezone_name}") from exc
    return {
        "enabled": bool(schedule_payload.get("enabled", False)),
        "frequency": frequency,
        "time": schedule_time,
        "timezone": timezone_name,
        "recipients": _string_list(schedule_payload.get("recipients"))[:50],
    }


def _normalize_template(
    payload: dict[str, Any],
    existing: dict[str, Any] | None = None,
    *,
    touch: bool = True,
) -> dict[str, Any]:
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
    schedule = _normalize_schedule(payload.get("schedule") or current.get("schedule") or {})
    return {
        "id": template_id,
        "type": "report_template",
        "schema_version": CONTROL_PLANE_SCHEMA_VERSION,
        "name": name,
        "description": str(payload.get("description") if "description" in payload else current.get("description") or "").strip(),
        "owner": str(payload.get("owner") or current.get("owner") or "soc-ops").strip(),
        "tenant_scope": _normalize_tenant_scope(
            payload.get("tenant_scope") if "tenant_scope" in payload else current.get("tenant_scope")
        ),
        "period": period,
        "retention_days": max(
            1,
            min(int(payload.get("retention_days") or current.get("retention_days") or 90), 3650),
        ),
        "sections": sections,
        "formats": formats,
        "schedule": schedule,
        "created_ts": str(current.get("created_ts") or _now_iso()),
        "updated_ts": _now_iso() if touch else str(current.get("updated_ts") or _now_iso()),
    }


def list_report_templates() -> list[dict[str, Any]]:
    rows = _collection("report_templates", _default_report_templates)
    normalized = [_normalize_template(item, item, touch=False) for item in rows]
    if normalized != rows:
        _save_collection("report_templates", normalized)
    normalized.sort(key=lambda item: str(item.get("name") or item.get("id") or "").lower())
    runs = _collection("report_runs", _default_report_runs)
    return _json_clone([_with_schedule_state(item, runs=runs) for item in normalized])


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


def _safe_error(exc: Exception) -> str:
    message = str(exc)[:1000]
    message = re.sub(r"(?i)(password|passwd|token|secret|authorization)\s*[=:]\s*[^\s,;]+", r"\1=[redacted]", message)
    message = re.sub(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]+", "Bearer [redacted]", message)
    return message


def _prune_report_runs(template_id: str, retention_days: int) -> None:
    cutoff = datetime.now(timezone.utc) - timedelta(days=max(1, min(retention_days, 3650)))
    with _RUN_LOCK:
        rows = _collection("report_runs", _default_report_runs)
        retained: list[dict[str, Any]] = []
        for row in rows:
            if str(row.get("template_id") or "") != template_id or str(row.get("status") or "") in ACTIVE_RUN_STATUSES:
                retained.append(row)
                continue
            row_ts = _parse_datetime(row.get("created_ts")) or datetime.now(timezone.utc)
            if row_ts >= cutoff:
                retained.append(row)
        _save_collection("report_runs", retained[-500:])


def _request_hash(value: dict[str, Any]) -> str:
    canonical = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _idempotent_run_id(idempotency_key: str) -> str:
    safe_key = str(idempotency_key or "").strip()
    if not _SAFE_IDEMPOTENCY_RE.fullmatch(safe_key):
        raise ValueError("A valid 8-160 character idempotency key is required")
    return f"report-run-{hashlib.sha256(safe_key.encode('utf-8')).hexdigest()[:24]}"


def _replace_report_run(run_id: str, updater: Callable[[dict[str, Any]], None]) -> dict[str, Any]:
    with _RUN_LOCK:
        rows = _collection("report_runs", _default_report_runs)
        item = _find_by_id(rows, run_id)
        if item is None:
            raise ValueError(f"Generated report not found: {run_id}")
        updater(item)
        _save_collection("report_runs", rows[-500:])
        return _json_clone(item)


def create_report_run(
    template_id: str,
    *,
    actor: str = "system",
    tenant_scope: list[str] | None = None,
    idempotency_key: str,
    source: str = "manual",
    scheduled_slot: datetime | None = None,
) -> tuple[dict[str, Any], bool]:
    template = get_report_template(template_id)
    if template is None:
        raise ValueError(f"Report template not found: {template_id}")
    selected_tenants = _normalize_tenant_scope(tenant_scope or template.get("tenant_scope"))
    allowed_tenants = set(_normalize_tenant_scope(template.get("tenant_scope")))
    if not set(selected_tenants).issubset(allowed_tenants):
        raise ValueError("Requested tenant scope exceeds the template scope")
    created = datetime.now(timezone.utc)
    hours = _hours_for_period(str(template.get("period") or "24h"))
    run_id = _idempotent_run_id(idempotency_key)
    request = {
        "template_id": template["id"],
        "template_updated_ts": template.get("updated_ts") or "",
        "tenant_scope": selected_tenants,
        "period": template["period"],
        "sections": list(template.get("sections") or []),
        "formats": list(template.get("formats") or ["json"]),
        "source": str(source or "manual"),
        "scheduled_slot": scheduled_slot.isoformat() if scheduled_slot else "",
    }
    fingerprint = _request_hash(request)
    with _RUN_LOCK:
        rows = _collection("report_runs", _default_report_runs)
        existing = _find_by_id(rows, run_id)
        if existing is not None:
            if str(existing.get("request_hash") or "") != fingerprint:
                raise ValueError("Idempotency key was already used for a different report request")
            replay = _json_clone(existing)
            replay["idempotent_replay"] = True
            return replay, False
        selected_sections = list(template.get("sections") or [])
        run = {
            "id": run_id,
            "type": "report_run",
            "schema_version": CONTROL_PLANE_SCHEMA_VERSION,
            "template_id": template["id"],
            "name": template["name"],
            "description": template.get("description") or "",
            "status": "queued",
            "owner": actor,
            "source": str(source or "manual"),
            "tenant_scope": selected_tenants,
            "period": {
                "window": template["period"],
                "from_ts": (created - timedelta(hours=hours)).isoformat(),
                "to_ts": created.isoformat(),
            },
            "formats": list(template.get("formats") or ["json"]),
            "sections": selected_sections,
            "section_count": 0,
            "record_count": 0,
            "errors": [],
            "snapshot": {},
            "progress": {
                "phase": "queued",
                "percent": 0,
                "sections_total": len(selected_sections),
                "sections_completed": 0,
                "current_section": "",
            },
            "request_hash": fingerprint,
            "idempotency_hash": hashlib.sha256(idempotency_key.encode("utf-8")).hexdigest()[:16],
            "scheduled_slot": request["scheduled_slot"],
            "created_ts": created.isoformat(),
            "started_ts": "",
            "heartbeat_ts": created.isoformat(),
            "completed_ts": "",
            "duration_ms": 0,
        }
        rows.append(run)
        _save_collection("report_runs", rows[-500:])
    append_audit_event(
        actor=actor,
        action="report.queued",
        object_type="report_run",
        object_id=run_id,
        summary=template["name"],
        details={"template_id": template["id"], "source": source, "tenant_scope": selected_tenants},
    )
    return _json_clone(run), True


def _run_is_stale(run: dict[str, Any], *, now: datetime) -> bool:
    heartbeat = _parse_datetime(run.get("heartbeat_ts") or run.get("started_ts") or run.get("created_ts"))
    return heartbeat is None or (now - heartbeat).total_seconds() > 900


def execute_report_run(
    run_id: str,
    *,
    loaders: dict[str, Callable[[], Any]] | None = None,
) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    with _ACTIVE_LOCK:
        if run_id in _ACTIVE_RUNS:
            return get_report_run(run_id) or {}
        _ACTIVE_RUNS.add(run_id)
    try:
        current = get_report_run(run_id)
        if current is None:
            raise ValueError(f"Generated report not found: {run_id}")
        if str(current.get("status") or "") in TERMINAL_RUN_STATUSES:
            return current
        if str(current.get("status") or "") == "running" and not _run_is_stale(current, now=now):
            return current
        hours = _hours_for_period(str(dict(current.get("period") or {}).get("window") or "24h"))
        section_loaders = dict(loaders or _default_section_loaders(hours))
        selected_sections = list(current.get("sections") or [])
        started = datetime.now(timezone.utc)

        def mark_running(item: dict[str, Any]) -> None:
            item["status"] = "running"
            item["started_ts"] = item.get("started_ts") or started.isoformat()
            item["heartbeat_ts"] = started.isoformat()
            item["snapshot"] = {}
            item["errors"] = []
            item["section_count"] = 0
            item["record_count"] = 0
            item["progress"] = {
                "phase": "running",
                "percent": 0,
                "sections_total": len(selected_sections),
                "sections_completed": 0,
                "current_section": selected_sections[0] if selected_sections else "",
            }

        _replace_report_run(run_id, mark_running)
        snapshot: dict[str, Any] = {}
        errors: list[dict[str, str]] = []
        record_count = 0
        for index, section_id in enumerate(selected_sections, start=1):
            loader = section_loaders.get(section_id)
            if loader is None:
                errors.append({"section": section_id, "error": "section loader is unavailable"})
            else:
                try:
                    value = loader()
                    snapshot[section_id] = value
                    record_count += _count_records(value)
                except Exception as exc:  # noqa: BLE001
                    logger.exception("Report section %s failed for run %s", section_id, run_id)
                    errors.append({"section": section_id, "error": _safe_error(exc)})

            def update_progress(item: dict[str, Any]) -> None:
                item["snapshot"] = _json_clone(snapshot)
                item["errors"] = list(errors)
                item["section_count"] = len(snapshot)
                item["record_count"] = record_count
                item["heartbeat_ts"] = datetime.now(timezone.utc).isoformat()
                item["progress"] = {
                    "phase": "running",
                    "percent": int(index * 100 / max(1, len(selected_sections))),
                    "sections_total": len(selected_sections),
                    "sections_completed": index,
                    "current_section": selected_sections[index] if index < len(selected_sections) else "",
                }

            _replace_report_run(run_id, update_progress)

        completed = datetime.now(timezone.utc)
        status = "completed_with_warnings" if snapshot and errors else "completed" if snapshot else "failed"

        def mark_completed(item: dict[str, Any]) -> None:
            item["status"] = status
            item["snapshot"] = _json_clone(snapshot)
            item["errors"] = list(errors)
            item["section_count"] = len(snapshot)
            item["record_count"] = record_count
            item["heartbeat_ts"] = completed.isoformat()
            item["completed_ts"] = completed.isoformat()
            item["duration_ms"] = max(0, int((completed - started).total_seconds() * 1000))
            item["progress"] = {
                "phase": status,
                "percent": 100,
                "sections_total": len(selected_sections),
                "sections_completed": len(selected_sections),
                "current_section": "",
            }

        result = _replace_report_run(run_id, mark_completed)
        append_audit_event(
            actor=str(result.get("owner") or "system"),
            action="report.generated",
            object_type="report_run",
            object_id=run_id,
            summary=str(result.get("name") or run_id),
            details={
                "template_id": result.get("template_id"),
                "status": status,
                "record_count": record_count,
                "duration_ms": result["duration_ms"],
            },
        )
        template = get_report_template(str(result.get("template_id") or "")) or {}
        _prune_report_runs(str(result.get("template_id") or ""), int(template.get("retention_days") or 90))
        return result
    except Exception as exc:  # noqa: BLE001
        logger.exception("Report executor failed for run %s", run_id)
        completed = datetime.now(timezone.utc)

        def mark_failed(item: dict[str, Any]) -> None:
            item["status"] = "failed"
            item["heartbeat_ts"] = completed.isoformat()
            item["completed_ts"] = completed.isoformat()
            item["errors"] = [*list(item.get("errors") or []), {"section": "runtime", "error": _safe_error(exc)}]
            started_ts = _parse_datetime(item.get("started_ts") or item.get("created_ts")) or completed
            item["duration_ms"] = max(0, int((completed - started_ts).total_seconds() * 1000))
            item["progress"] = {**dict(item.get("progress") or {}), "phase": "failed"}

        try:
            result = _replace_report_run(run_id, mark_failed)
        except Exception:  # pragma: no cover - storage failure prevents durable status
            raise exc
        append_audit_event(
            actor=str(result.get("owner") or "system"),
            action="report.failed",
            object_type="report_run",
            object_id=run_id,
            summary=str(result.get("name") or run_id),
            details={"error": _safe_error(exc)},
        )
        return result
    finally:
        with _ACTIVE_LOCK:
            _ACTIVE_RUNS.discard(run_id)


def generate_report_run(
    template_id: str,
    *,
    actor: str = "system",
    tenant_scope: list[str] | None = None,
    loaders: dict[str, Callable[[], Any]] | None = None,
) -> dict[str, Any]:
    item, _ = create_report_run(
        template_id,
        actor=actor,
        tenant_scope=tenant_scope,
        idempotency_key=f"compat:{template_id}:{uuid.uuid4().hex}",
    )
    return execute_report_run(item["id"], loaders=loaders)


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
        slots = (base - timedelta(hours=12), base, base + timedelta(hours=12))
        return max(slot for slot in slots if slot <= local_now).astimezone(timezone.utc)
    if frequency == "weekly":
        slot = base - timedelta(days=base.weekday())
        if slot > local_now:
            slot -= timedelta(days=7)
    elif frequency == "monthly":
        slot = base.replace(day=1)
        if slot > local_now:
            previous_month_end = slot - timedelta(days=1)
            slot = slot.replace(year=previous_month_end.year, month=previous_month_end.month, day=1)
    else:
        slot = base
        if slot > local_now:
            slot -= timedelta(days=1)
    return slot.astimezone(timezone.utc)


def _next_scheduled_slot(template: dict[str, Any], now: datetime) -> datetime | None:
    schedule = dict(template.get("schedule") or {})
    if not bool(schedule.get("enabled")):
        return None
    schedule_zone = ZoneInfo(str(schedule.get("timezone") or "UTC"))
    local_now = now.astimezone(schedule_zone)
    hour_text, minute_text = str(schedule.get("time") or "08:00").split(":", 1)
    base = local_now.replace(hour=int(hour_text), minute=int(minute_text), second=0, microsecond=0)
    frequency = str(schedule.get("frequency") or "daily")
    if frequency == "shift":
        candidates = [base, base + timedelta(hours=12), base + timedelta(days=1)]
        return min(item for item in candidates if item > local_now).astimezone(timezone.utc)
    if frequency == "weekly":
        candidate = base - timedelta(days=base.weekday())
        if candidate <= local_now:
            candidate += timedelta(days=7)
    elif frequency == "monthly":
        candidate = base.replace(day=1)
        if candidate <= local_now:
            candidate = (
                candidate.replace(year=candidate.year + 1, month=1)
                if candidate.month == 12
                else candidate.replace(month=candidate.month + 1)
            )
    else:
        candidate = base if base > local_now else base + timedelta(days=1)
    return candidate.astimezone(timezone.utc)


def _with_schedule_state(template: dict[str, Any], *, runs: list[dict[str, Any]]) -> dict[str, Any]:
    item = _json_clone(template)
    relevant = [row for row in runs if str(row.get("template_id") or "") == str(template.get("id") or "")]
    relevant.sort(key=lambda row: str(row.get("created_ts") or ""), reverse=True)
    latest = relevant[0] if relevant else {}
    now = datetime.now(timezone.utc)
    schedule = dict(item.get("schedule") or {})
    next_slot = _next_scheduled_slot(item, now)
    schedule["next_run_ts"] = next_slot.isoformat() if next_slot else ""
    schedule["last_run_ts"] = str(latest.get("completed_ts") or latest.get("created_ts") or "")
    schedule["last_run_status"] = str(latest.get("status") or "never")
    item["schedule"] = schedule
    return item


def reporting_capabilities() -> dict[str, Any]:
    try:
        import reportlab  # noqa: F401

        pdf_available = True
        pdf_reason = ""
    except ImportError:
        pdf_available = False
        pdf_reason = "ReportLab is not installed in the web runtime"
    return {
        "formats": ["json", "csv"] + (["pdf"] if pdf_available else []),
        "pdf_available": pdf_available,
        "pdf_unavailable_reason": pdf_reason,
        "periods": list(_PERIOD_HOURS),
        "max_range_hours": max(_PERIOD_HOURS.values()),
        "tenants": list(REPORT_TENANTS),
        "frequencies": list(REPORT_FREQUENCIES),
    }


def run_due_report_templates(
    *,
    actor: str = "report-scheduler",
    now: datetime | None = None,
    loaders: dict[str, Callable[[], Any]] | None = None,
) -> dict[str, Any]:
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    generated: list[dict[str, Any]] = []
    skipped: list[dict[str, str]] = []
    for template in list_report_templates():
        slot = _scheduled_slot(template, current)
        if slot is None:
            skipped.append({"template_id": template["id"], "reason": "not_due"})
            continue
        idempotency_key = f"schedule:{template['id']}:{slot.isoformat()}"
        existing = get_report_run(_idempotent_run_id(idempotency_key))
        if existing is not None:
            item, created = existing, False
        else:
            item, created = create_report_run(
                template["id"],
                actor=actor,
                tenant_scope=list(template.get("tenant_scope") or ["main"]),
                idempotency_key=idempotency_key,
                source="schedule",
                scheduled_slot=slot,
            )
        if not created and str(item.get("status") or "") in TERMINAL_RUN_STATUSES:
            skipped.append({"template_id": template["id"], "reason": "slot_already_generated"})
            continue
        result = execute_report_run(item["id"], loaders=loaders)
        if str(result.get("status") or "") in ACTIVE_RUN_STATUSES:
            skipped.append({"template_id": template["id"], "reason": "slot_in_progress"})
        else:
            generated.append(result)
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


def report_run_pdf(run: dict[str, Any]) -> bytes:
    if not reporting_capabilities()["pdf_available"]:
        raise RuntimeError(str(reporting_capabilities()["pdf_unavailable_reason"]))
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    output = io.BytesIO()
    font_name = "Helvetica"
    for font_path in (
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "C:/Windows/Fonts/arial.ttf",
    ):
        if not Path(font_path).is_file():
            continue
        try:
            pdfmetrics.registerFont(TTFont("SentinelUnicode", font_path))
            font_name = "SentinelUnicode"
            break
        except Exception:  # noqa: BLE001 - font backends use library-specific exceptions
            continue
    styles = getSampleStyleSheet()
    body = ParagraphStyle("SentinelBody", parent=styles["BodyText"], fontName=font_name, fontSize=8, leading=11, alignment=TA_LEFT)
    heading = ParagraphStyle("SentinelHeading", parent=styles["Heading2"], fontName=font_name, fontSize=13, leading=16, spaceAfter=5 * mm)
    title = ParagraphStyle("SentinelTitle", parent=styles["Title"], fontName=font_name, fontSize=18, leading=22)
    document = SimpleDocTemplate(
        output,
        pagesize=A4,
        rightMargin=14 * mm,
        leftMargin=14 * mm,
        topMargin=14 * mm,
        bottomMargin=14 * mm,
        title=str(run.get("name") or run.get("id") or "SIEM report"),
        author="Rdegon Sentinel",
    )
    pdf_text = lambda value: escape(str(value or ""))  # noqa: E731
    story: list[Any] = [Paragraph(pdf_text(run.get("name") or "SIEM report"), title), Spacer(1, 4 * mm)]
    period = dict(run.get("period") or {})
    summary_rows = [
        ["Report ID", str(run.get("id") or "")],
        ["Status", str(run.get("status") or "")],
        ["Tenant", ", ".join(str(item) for item in run.get("tenant_scope") or [])],
        ["Period", f"{period.get('from_ts', '')} - {period.get('to_ts', '')}"],
        ["Records", str(run.get("record_count") or 0)],
        ["Created", str(run.get("created_ts") or "")],
    ]
    summary = Table([[Paragraph(pdf_text(cell), body) for cell in row] for row in summary_rows], colWidths=[38 * mm, 130 * mm])
    summary.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#aab4c0")), ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#e8edf2")), ("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 5), ("RIGHTPADDING", (0, 0), (-1, -1), 5)]))
    story.extend([summary, Spacer(1, 7 * mm)])
    errors = list(run.get("errors") or [])
    if errors:
        story.append(Paragraph("Execution errors", heading))
        error_rows = [["Section", "Error"], *[[str(item.get("section") or ""), str(item.get("error") or "")] for item in errors]]
        table = Table([[Paragraph(pdf_text(cell), body) for cell in row] for row in error_rows], colWidths=[42 * mm, 126 * mm], repeatRows=1)
        table.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#b8c1cc")), ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f2dede")), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
        story.extend([table, PageBreak()])
    for section_id, value in dict(run.get("snapshot") or {}).items():
        story.append(Paragraph(pdf_text(str(section_id).replace("_", " ").title()), heading))
        if isinstance(value, list):
            records = value[:100]
        elif isinstance(value, dict) and isinstance(value.get("items"), list):
            records = list(value["items"])[:100]
        else:
            records = [value]
        rows = [["#", "Record"]]
        for index, record in enumerate(records, start=1):
            payload = json.dumps(record, ensure_ascii=False, separators=(", ", ": "), default=str)
            rows.append([str(index), payload[:4000]])
        table = Table([[Paragraph(pdf_text(cell), body) for cell in row] for row in rows], colWidths=[12 * mm, 156 * mm], repeatRows=1)
        table.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#b8c1cc")), ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#dce9ee")), ("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4)]))
        story.extend([table, PageBreak()])
    document.build(story)
    return output.getvalue()
