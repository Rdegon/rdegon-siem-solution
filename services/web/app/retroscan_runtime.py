from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import threading
import uuid
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Any, Callable, Iterable

from .filter_expression_runtime import eval_expr, parse_expr

try:
    from . import enterprise_control_plane as core
except ImportError:  # pragma: no cover - local test fallback
    import enterprise_control_plane as core  # type: ignore[no-redef]


logger = logging.getLogger("siem_web.retroscan")

RETROSCAN_COLLECTION = "retroscan_runs"
RETROSCAN_SCHEMA_VERSION = "v1"
TERMINAL_STATUSES = {"completed", "completed_with_warnings", "cancelled", "failed"}
ACTIVE_STATUSES = {"queued", "running", "cancelling"}
_RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_RULE_INDEX_FIELDS = {
    "event.provider",
    "event.dataset",
    "event.category",
    "event.type",
    "event.action",
    "event.outcome",
    "event.code",
    "host.name",
    "log_source",
    "source_type",
    "collector_profile",
    "ingest_profile",
}
_STORE_LOCK = core._LOCK
_ACTIVE_LOCK = threading.Lock()
_ACTIVE_RUNS: set[str] = set()
_WORKER_SLOTS = threading.BoundedSemaphore(max(1, int(os.getenv("SIEM_RETROSCAN_CONCURRENCY", "1") or "1")))


class RetroscanError(ValueError):
    code = "retroscan_error"


class RetroscanValidationError(RetroscanError):
    code = "validation_error"


class RetroscanConflictError(RetroscanError):
    code = "idempotency_conflict"


class RetroscanNotFoundError(RetroscanError):
    code = "not_found"


class RetroscanCommitUnavailableError(RetroscanError):
    code = "commit_unavailable"


def retroscan_capabilities() -> dict[str, Any]:
    return {
        "dry_run": True,
        "commit": False,
        "commit_reason": "No reusable alert service path exists; the live stream worker owns alert persistence.",
        "engines": ["stream_threshold"],
        "event_table": "siem.events",
        "rule_table": "siem.correlation_rules_stream",
        "max_range_hours": _max_range_hours(),
        "max_rows": _max_rows_limit(),
        "preview_limit": _preview_limit(),
    }


def _max_range_hours() -> int:
    return max(1, min(int(os.getenv("SIEM_RETROSCAN_MAX_RANGE_HOURS", "720") or "720"), 24 * 365))


def _max_rows_limit() -> int:
    return max(100, min(int(os.getenv("SIEM_RETROSCAN_MAX_ROWS", "50000") or "50000"), 1_000_000))


def _preview_limit() -> int:
    return max(1, min(int(os.getenv("SIEM_RETROSCAN_PREVIEW_LIMIT", "100") or "100"), 1000))


def _cooldown_floor_seconds() -> int:
    return max(0, int(os.getenv("SIEM_STREAM_CORR_MIN_ALERT_COOLDOWN_SEC", "3600") or "3600"))


def _stale_after_seconds() -> int:
    return max(300, int(os.getenv("SIEM_RETROSCAN_STALE_AFTER_SECONDS", "1800") or "1800"))


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _parse_time(value: Any, *, field: str) -> datetime:
    text = str(value or "").strip()
    if not text:
        raise RetroscanValidationError(f"{field} is required")
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise RetroscanValidationError(f"{field} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _default_runs() -> list[dict[str, Any]]:
    return []


def _load_runs() -> list[dict[str, Any]]:
    return core._collection(RETROSCAN_COLLECTION, _default_runs)


def _save_runs(rows: list[dict[str, Any]]) -> None:
    core._save_collection(RETROSCAN_COLLECTION, rows[-500:])


def _clone(value: Any) -> Any:
    return core._json_clone(value)


def _find_run(rows: Iterable[dict[str, Any]], run_id: str) -> dict[str, Any] | None:
    return next((row for row in rows if str(row.get("id") or "") == run_id), None)


def _replace_run(run_id: str, updater: Callable[[dict[str, Any]], None]) -> dict[str, Any]:
    with _STORE_LOCK:
        rows = _load_runs()
        item = _find_run(rows, run_id)
        if item is None:
            raise RetroscanNotFoundError(f"Retroscan run not found: {run_id}")
        updater(item)
        _save_runs(rows)
        return _clone(item)


def _reconcile_stale_runs() -> None:
    now = _now()
    changed = False
    with _STORE_LOCK:
        rows = _load_runs()
        with _ACTIVE_LOCK:
            active_here = set(_ACTIVE_RUNS)
        for item in rows:
            status = str(item.get("status") or "")
            run_id = str(item.get("id") or "")
            if status not in ACTIVE_STATUSES or run_id in active_here:
                continue
            heartbeat_raw = item.get("heartbeat_ts") or item.get("started_ts") or item.get("created_ts")
            try:
                heartbeat = _parse_time(heartbeat_raw, field="heartbeat_ts")
            except RetroscanValidationError:
                heartbeat = datetime.min.replace(tzinfo=timezone.utc)
            if (now - heartbeat).total_seconds() <= _stale_after_seconds():
                continue
            item["status"] = "failed"
            item["completed_ts"] = _iso(now)
            item["heartbeat_ts"] = item["completed_ts"]
            item["error"] = {
                "code": "worker_lost",
                "message": "Retroscan worker heartbeat expired before the task reached a terminal state.",
            }
            item["progress"] = {**dict(item.get("progress") or {}), "phase": "failed"}
            changed = True
        if changed:
            _save_runs(rows)


def _request_hash(request: dict[str, Any]) -> str:
    canonical = json.dumps(request, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _normalize_request(payload: dict[str, Any]) -> dict[str, Any]:
    if bool(payload.get("commit", False)) or payload.get("dry_run") is False:
        raise RetroscanCommitUnavailableError(str(retroscan_capabilities()["commit_reason"]))
    from_ts = _parse_time(payload.get("from_ts"), field="from_ts")
    to_ts = _parse_time(payload.get("to_ts"), field="to_ts")
    if to_ts <= from_ts:
        raise RetroscanValidationError("to_ts must be later than from_ts")
    range_hours = (to_ts - from_ts).total_seconds() / 3600
    if range_hours > _max_range_hours():
        raise RetroscanValidationError(f"Time range exceeds {_max_range_hours()} hours")
    try:
        max_rows = int(payload.get("max_rows") or min(10_000, _max_rows_limit()))
    except (TypeError, ValueError) as exc:
        raise RetroscanValidationError("max_rows must be an integer") from exc
    if max_rows < 1 or max_rows > _max_rows_limit():
        raise RetroscanValidationError(f"max_rows must be between 1 and {_max_rows_limit()}")
    raw_rule_ids = payload.get("rule_ids") or []
    if not isinstance(raw_rule_ids, list):
        raise RetroscanValidationError("rule_ids must be an array")
    try:
        rule_ids = sorted({int(value) for value in raw_rule_ids if int(value) > 0})
    except (TypeError, ValueError) as exc:
        raise RetroscanValidationError("rule_ids must contain positive integers") from exc
    if len(rule_ids) > 500:
        raise RetroscanValidationError("No more than 500 rule_ids may be requested")
    return {
        "from_ts": _iso(from_ts),
        "to_ts": _iso(to_ts),
        "max_rows": max_rows,
        "rule_ids": rule_ids,
        "dry_run": True,
        "commit": False,
    }


def _normalize_run_id(value: Any) -> str:
    run_id = str(value or "").strip() or f"retroscan-{uuid.uuid4().hex}"
    if not _RUN_ID_RE.fullmatch(run_id):
        raise RetroscanValidationError("run_id must be 1-128 safe identifier characters")
    return run_id


def create_retroscan(
    payload: dict[str, Any],
    *,
    actor: str,
    idempotency_key: str = "",
) -> tuple[dict[str, Any], bool]:
    request = _normalize_request(dict(payload or {}))
    run_id = _normalize_run_id(payload.get("run_id") or idempotency_key)
    fingerprint = _request_hash(request)
    created_ts = _iso(_now())
    with _STORE_LOCK:
        rows = _load_runs()
        existing = _find_run(rows, run_id)
        if existing is not None:
            if str(existing.get("request_hash") or "") != fingerprint:
                raise RetroscanConflictError(f"run_id {run_id} already exists with a different request")
            replay = _clone(existing)
            replay["idempotent_replay"] = True
            return replay, False
        run = {
            "id": run_id,
            "run_id": run_id,
            "type": "retroscan_run",
            "schema_version": RETROSCAN_SCHEMA_VERSION,
            "status": "queued",
            "owner": str(actor or "web"),
            "mode": "dry_run",
            "request": request,
            "request_hash": fingerprint,
            "capabilities": retroscan_capabilities(),
            "progress": {
                "phase": "queued",
                "percent": 0,
                "events_available": 0,
                "events_scanned": 0,
                "matched_events": 0,
                "candidate_alerts": 0,
            },
            "result": None,
            "error": None,
            "cancel_requested": False,
            "created_ts": created_ts,
            "started_ts": "",
            "heartbeat_ts": created_ts,
            "completed_ts": "",
            "duration_ms": 0,
        }
        rows.append(run)
        _save_runs(rows)
    _audit("retroscan.created", run_id, actor, {"request": request})
    return _clone(run), True


def list_retroscans(*, limit: int = 100, status: str = "") -> list[dict[str, Any]]:
    _reconcile_stale_runs()
    safe_limit = max(1, min(int(limit or 100), 500))
    status_filter = str(status or "").strip().lower()
    rows = _load_runs()
    if status_filter:
        rows = [row for row in rows if str(row.get("status") or "").lower() == status_filter]
    rows.sort(key=lambda row: str(row.get("created_ts") or row.get("id") or ""), reverse=True)
    return _clone(rows[:safe_limit])


def get_retroscan(run_id: str) -> dict[str, Any]:
    _reconcile_stale_runs()
    item = _find_run(_load_runs(), str(run_id or "").strip())
    if item is None:
        raise RetroscanNotFoundError(f"Retroscan run not found: {run_id}")
    return _clone(item)


def cancel_retroscan(run_id: str, *, actor: str) -> dict[str, Any]:
    def update(item: dict[str, Any]) -> None:
        status = str(item.get("status") or "")
        if status in TERMINAL_STATUSES:
            return
        item["cancel_requested"] = True
        item["status"] = "cancelling" if status == "running" else "cancelled"
        item["heartbeat_ts"] = _iso(_now())
        if item["status"] == "cancelled":
            item["completed_ts"] = item["heartbeat_ts"]
            item["progress"] = {**dict(item.get("progress") or {}), "phase": "cancelled"}

    item = _replace_run(str(run_id or "").strip(), update)
    _audit("retroscan.cancel_requested", run_id, actor, {"status": item.get("status")})
    return item


def _audit(action: str, run_id: str, actor: str, details: dict[str, Any]) -> None:
    try:
        core.append_audit_event(
            actor=str(actor or "system"),
            action=action,
            object_type="retroscan_run",
            object_id=str(run_id),
            summary=str(run_id),
            details=details,
        )
    except Exception:  # pragma: no cover - audit failure must not corrupt the task
        logger.exception("Unable to append retroscan audit event")


def _get_clickhouse_client():
    from .deps import get_ch_client

    return get_ch_client()


def _format_ch_time(value: str) -> str:
    parsed = _parse_time(value, field="timestamp")
    return parsed.strftime("%Y-%m-%d %H:%M:%S")


def _query_named(client: Any, sql: str) -> list[dict[str, Any]]:
    result = client.query(sql)
    return [dict(row) for row in result.named_results()]


def _load_active_rules(client: Any, requested_rule_ids: list[int]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    id_filter = ""
    if requested_rule_ids:
        id_filter = f" AND id IN ({', '.join(str(value) for value in requested_rule_ids)})"
    rows = _query_named(
        client,
        f"""
        SELECT id, name, description, severity, pattern, window_s, threshold, expr, entity_field, updated_ts
        FROM siem.correlation_rules_stream
        WHERE enabled = 1{id_filter}
        ORDER BY id
        """,
    )
    rules: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    found_ids = {int(row.get("id") or 0) for row in rows}
    for missing_id in sorted(set(requested_rule_ids) - found_ids):
        skipped.append({"rule_id": missing_id, "reason": "not_published_or_inactive"})
    for row in rows:
        rule_id = int(row.get("id") or 0)
        if str(row.get("pattern") or "") != "threshold":
            skipped.append({"rule_id": rule_id, "reason": "unsupported_pattern", "pattern": str(row.get("pattern") or "")})
            continue
        try:
            ast = parse_expr(str(row.get("expr") or ""))
        except Exception as exc:  # noqa: BLE001
            skipped.append({"rule_id": rule_id, "reason": "invalid_expression", "error": type(exc).__name__})
            continue
        threshold = max(1, int(row.get("threshold") or 1))
        window_s = max(1, int(row.get("window_s") or 1))
        rules.append({**row, "id": rule_id, "threshold": threshold, "window_s": window_s, "ast": ast})
    return rules, skipped


def _load_events(client: Any, request: dict[str, Any]) -> tuple[int, list[dict[str, Any]]]:
    from_sql = _format_ch_time(str(request["from_ts"]))
    to_sql = _format_ch_time(str(request["to_ts"]))
    predicate = f"ts >= toDateTime('{from_sql}', 'UTC') AND ts < toDateTime('{to_sql}', 'UTC')"
    count_rows = _query_named(client, f"SELECT count() AS total FROM siem.events WHERE {predicate}")
    total = int(count_rows[0].get("total") or 0) if count_rows else 0
    max_rows = int(request["max_rows"])
    rows = _query_named(
        client,
        f"""
        SELECT
            ts, event_id, event_code, category, subcategory, event_action, event_outcome,
            if(src_ip = 0, '', IPv4NumToString(src_ip)) AS src_ip,
            if(dst_ip = 0, '', IPv4NumToString(dst_ip)) AS dst_ip,
            src_port, dst_port, device_vendor, device_product, log_source, host_name,
            user_name, target_user, process_name, process_executable, process_command,
            severity, message, normalized_json, tags
        FROM siem.events
        WHERE {predicate}
        ORDER BY ts ASC, event_id ASC
        LIMIT {max_rows}
        """,
    )
    return total, rows


def _flatten_json(value: Any, *, prefix: str = "") -> dict[str, Any]:
    flattened: dict[str, Any] = {}
    if not isinstance(value, dict):
        return flattened
    for key, nested in value.items():
        path = f"{prefix}.{key}" if prefix else str(key)
        if isinstance(nested, dict):
            flattened.update(_flatten_json(nested, prefix=path))
        else:
            flattened[path] = nested
    return flattened


def _runtime_event(row: dict[str, Any]) -> dict[str, Any]:
    event = dict(row)
    normalized_raw = row.get("normalized_json")
    normalized: dict[str, Any] = {}
    if isinstance(normalized_raw, dict):
        normalized = normalized_raw
    elif str(normalized_raw or "").strip():
        try:
            parsed = json.loads(str(normalized_raw))
            normalized = parsed if isinstance(parsed, dict) else {}
        except json.JSONDecodeError:
            normalized = {}
    flattened = _flatten_json(normalized)
    for key, value in flattened.items():
        if value not in (None, ""):
            event[key] = value
    aliases = {
        "@timestamp": row.get("ts"),
        "event.id": row.get("event_id"),
        "event.code": row.get("event_code"),
        "event.category": row.get("category"),
        "event.type": row.get("subcategory"),
        "event.action": row.get("event_action"),
        "event.outcome": row.get("event_outcome"),
        "event.severity": row.get("severity"),
        "source.ip": row.get("src_ip"),
        "destination.ip": row.get("dst_ip"),
        "source.port": row.get("src_port"),
        "destination.port": row.get("dst_port"),
        "device.vendor": row.get("device_vendor"),
        "device.product": row.get("device_product"),
        "host.name": row.get("host_name"),
        "user.name": row.get("user_name"),
        "user.target.name": row.get("target_user"),
        "process.name": row.get("process_name"),
        "process.executable": row.get("process_executable"),
        "process.command_line": row.get("process_command"),
        "event.original": row.get("message"),
    }
    for key, value in aliases.items():
        event.setdefault(key, value)
    event.setdefault("event.provider", normalized.get("provider") or row.get("device_product") or "")
    event.setdefault("log_source", row.get("log_source") or row.get("host_name") or "")
    event.setdefault("tags", row.get("tags") or "")
    return event


def _event_epoch(value: Any) -> float:
    if isinstance(value, datetime):
        parsed = value.replace(tzinfo=value.tzinfo or timezone.utc)
        return parsed.astimezone(timezone.utc).timestamp()
    if isinstance(value, (int, float)):
        return float(value)
    return _parse_time(value, field="event.ts").timestamp()


def _event_tags(event: dict[str, Any]) -> set[str]:
    raw = event.get("tags", event.get("event.tags", ""))
    if isinstance(raw, (list, tuple, set)):
        return {str(item).strip().lower() for item in raw if str(item).strip()}
    text = str(raw or "").strip()
    if text.startswith("["):
        try:
            parsed = json.loads(text)
            if isinstance(parsed, list):
                return {str(item).strip().lower() for item in parsed if str(item).strip()}
        except json.JSONDecodeError:
            pass
    return {part.strip().lower() for part in re.split(r"[,;\s]+", text) if part.strip()}


def _skip_event(event: dict[str, Any]) -> bool:
    category = str(event.get("event.category") or event.get("category") or "").strip().lower()
    dataset = str(event.get("event.dataset") or event.get("dataset") or "").strip().lower()
    tags = _event_tags(event)
    return category == "benchmark" or dataset == "benchmark" or "allowlist:benchmark" in tags or "suppress:correlation" in tags


def _entity_key(event: dict[str, Any], field_spec: Any) -> str:
    fields = [field.strip() for field in str(field_spec or "").split("+") if field.strip()]
    values = [str(event.get(field) or "").strip() for field in fields]
    return "|".join(value for value in values if value)


def _index_key(field: str, value: Any) -> str:
    return f"{field}\x00{str(value or '').strip().lower()}"


def _ast_index_keys(ast: tuple[Any, ...]) -> tuple[set[str], bool]:
    node_type = ast[0]
    if node_type == "cmp":
        _, field, operator, value = ast
        if operator == "==" and field in _RULE_INDEX_FIELDS and str(value).strip():
            return {_index_key(str(field), value)}, True
        return set(), False
    if node_type == "not":
        return set(), False
    left_keys, left_guaranteed = _ast_index_keys(ast[1])
    right_keys, right_guaranteed = _ast_index_keys(ast[2])
    if node_type == "and":
        if left_guaranteed and right_guaranteed:
            return left_keys | right_keys, True
        if left_guaranteed:
            return left_keys, True
        if right_guaranteed:
            return right_keys, True
        return set(), False
    if node_type == "or" and left_guaranteed and right_guaranteed:
        return left_keys | right_keys, True
    return set(), False


def _build_rule_index(rules: list[dict[str, Any]]) -> tuple[dict[str, list[dict[str, Any]]], list[dict[str, Any]]]:
    index: dict[str, list[dict[str, Any]]] = defaultdict(list)
    fallback: list[dict[str, Any]] = []
    for rule in rules:
        keys, guaranteed = _ast_index_keys(rule["ast"])
        if not guaranteed or not keys:
            fallback.append(rule)
            continue
        for key in keys:
            index[key].append(rule)
    return dict(index), fallback


def _candidate_rules(
    event: dict[str, Any],
    index: dict[str, list[dict[str, Any]]],
    fallback: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    candidates = list(fallback)
    seen = {int(rule["id"]) for rule in candidates}
    for field in _RULE_INDEX_FIELDS:
        value = event.get(field)
        if value in (None, ""):
            continue
        for rule in index.get(_index_key(field, value), []):
            if int(rule["id"]) in seen:
                continue
            seen.add(int(rule["id"]))
            candidates.append(rule)
    return candidates


def _cancel_requested(run_id: str) -> bool:
    try:
        return bool(get_retroscan(run_id).get("cancel_requested"))
    except RetroscanNotFoundError:
        return True


def _progress(run_id: str, **values: Any) -> None:
    def update(item: dict[str, Any]) -> None:
        item["progress"] = {**dict(item.get("progress") or {}), **values}
        item["heartbeat_ts"] = _iso(_now())

    _replace_run(run_id, update)


def _finish(
    run_id: str,
    *,
    status: str,
    result: dict[str, Any] | None,
    error: dict[str, str] | None = None,
) -> dict[str, Any]:
    completed = _now()

    def update(item: dict[str, Any]) -> None:
        started = _parse_time(item.get("started_ts") or item.get("created_ts"), field="started_ts")
        item["status"] = status
        item["result"] = result
        item["error"] = error
        item["completed_ts"] = _iso(completed)
        item["heartbeat_ts"] = item["completed_ts"]
        item["duration_ms"] = max(0, int((completed - started).total_seconds() * 1000))
        item["progress"] = {
            **dict(item.get("progress") or {}),
            "phase": status,
            "percent": 100 if status in {"completed", "completed_with_warnings"} else dict(item.get("progress") or {}).get("percent", 0),
        }

    return _replace_run(run_id, update)


def _safe_failure(exc: Exception) -> dict[str, str]:
    debug_id = uuid.uuid4().hex[:12]
    message = str(exc) if isinstance(exc, RetroscanError) else f"Retroscan execution failed ({type(exc).__name__})."
    return {"code": "execution_failed", "message": message[:500], "debug_id": debug_id}


def _candidate_id(run_id: str, rule_id: int, entity_key: str, event_epoch: float) -> str:
    raw = f"{run_id}\n{rule_id}\n{entity_key}\n{event_epoch:.6f}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]


def _evaluate(
    run_id: str,
    rules: list[dict[str, Any]],
    events: list[dict[str, Any]],
    *,
    events_available: int,
    skipped_rules: list[dict[str, Any]],
) -> dict[str, Any]:
    rule_index, fallback_rules = _build_rule_index(rules)
    windows: dict[tuple[int, str], deque[tuple[float, str]]] = defaultdict(deque)
    seen_ids: dict[tuple[int, str], set[str]] = defaultdict(set)
    last_alert: dict[tuple[int, str], float] = {}
    stats = {
        int(rule["id"]): {
            "rule_id": int(rule["id"]),
            "rule_name": str(rule.get("name") or rule["id"]),
            "matched_events": 0,
            "candidate_alerts": 0,
            "entities": set(),
        }
        for rule in rules
    }
    preview: list[dict[str, Any]] = []
    matched_events = 0
    candidate_alerts = 0
    scanned = 0
    scan_total = max(1, len(events))
    progress_interval = max(50, min(500, scan_total // 100 or 50))
    for row in events:
        scanned += 1
        event = _runtime_event(row)
        if _skip_event(event):
            if scanned % progress_interval == 0 or scanned == len(events):
                if _cancel_requested(run_id):
                    return {
                        "cancelled": True,
                        "events_available": events_available,
                        "events_scanned": scanned,
                        "matched_events": matched_events,
                        "candidate_alerts": candidate_alerts,
                        "preview": preview,
                    }
                _progress(
                    run_id,
                    phase="evaluating",
                    percent=min(99, 15 + int((scanned / scan_total) * 84)),
                    events_available=events_available,
                    events_scanned=scanned,
                    matched_events=matched_events,
                    candidate_alerts=candidate_alerts,
                )
            continue
        event_epoch = _event_epoch(row.get("ts"))
        message_id = str(row.get("event_id") or f"row-{scanned}")
        for rule in _candidate_rules(event, rule_index, fallback_rules):
            if not bool(eval_expr(rule["ast"], event)):
                continue
            entity = _entity_key(event, rule.get("entity_field"))
            if not entity:
                continue
            key = (int(rule["id"]), entity)
            if message_id in seen_ids[key]:
                continue
            seen_ids[key].add(message_id)
            matched_events += 1
            stats[int(rule["id"])]["matched_events"] += 1
            stats[int(rule["id"])]["entities"].add(entity)
            queue = windows[key]
            queue.append((event_epoch, message_id))
            window_start = event_epoch - int(rule["window_s"])
            while queue and queue[0][0] < window_start:
                expired_epoch, expired_id = queue.popleft()
                if not any(item_id == expired_id for _, item_id in queue):
                    seen_ids[key].discard(expired_id)
            hits = len(queue)
            if hits < int(rule["threshold"]):
                continue
            cooldown = max(int(rule["window_s"]), _cooldown_floor_seconds())
            previous_alert = last_alert.get(key, 0.0)
            if previous_alert and abs(event_epoch - previous_alert) < cooldown:
                continue
            last_alert[key] = event_epoch
            candidate_alerts += 1
            stats[int(rule["id"])]["candidate_alerts"] += 1
            if len(preview) < _preview_limit():
                preview.append(
                    {
                        "candidate_id": _candidate_id(run_id, int(rule["id"]), entity, event_epoch),
                        "would_create_alert": True,
                        "rule_id": int(rule["id"]),
                        "rule_name": str(rule.get("name") or rule["id"]),
                        "severity": str(rule.get("severity") or "info").lower(),
                        "entity_key": entity,
                        "hits": hits,
                        "window_s": int(rule["window_s"]),
                        "ts_first": _iso(datetime.fromtimestamp(max(window_start, queue[0][0]), tz=timezone.utc)),
                        "ts_last": _iso(datetime.fromtimestamp(event_epoch, tz=timezone.utc)),
                        "source": str(event.get("log_source") or event.get("host.name") or event.get("source.ip") or "stream"),
                    }
                )
        if scanned % progress_interval == 0 or scanned == len(events):
            if _cancel_requested(run_id):
                return {
                    "cancelled": True,
                    "events_available": events_available,
                    "events_scanned": scanned,
                    "matched_events": matched_events,
                    "candidate_alerts": candidate_alerts,
                    "preview": preview,
                }
            _progress(
                run_id,
                phase="evaluating",
                percent=min(99, 15 + int((scanned / scan_total) * 84)),
                events_available=events_available,
                events_scanned=scanned,
                matched_events=matched_events,
                candidate_alerts=candidate_alerts,
            )
    rule_stats = []
    for rule_id in sorted(stats):
        item = dict(stats[rule_id])
        item["entities"] = len(item["entities"])
        rule_stats.append(item)
    return {
        "cancelled": False,
        "dry_run": True,
        "commit": False,
        "alerts_created": 0,
        "events_available": events_available,
        "events_scanned": scanned,
        "truncated": events_available > len(events),
        "matched_events": matched_events,
        "candidate_alerts": candidate_alerts,
        "preview_count": len(preview),
        "preview": preview,
        "rules_requested": len(rules) + len(skipped_rules),
        "rules_evaluated": len(rules),
        "rules_skipped": skipped_rules,
        "rule_stats": rule_stats,
    }


def run_retroscan_task(run_id: str, *, client_factory: Callable[[], Any] | None = None) -> dict[str, Any]:
    safe_run_id = str(run_id or "").strip()
    with _ACTIVE_LOCK:
        if safe_run_id in _ACTIVE_RUNS:
            return get_retroscan(safe_run_id)
        _ACTIVE_RUNS.add(safe_run_id)
    try:
        with _WORKER_SLOTS:
            current = get_retroscan(safe_run_id)
            if str(current.get("status") or "") in TERMINAL_STATUSES:
                return current
            if bool(current.get("cancel_requested")):
                return _finish(safe_run_id, status="cancelled", result={"cancelled": True, "alerts_created": 0})
            started = _now()

            def mark_running(item: dict[str, Any]) -> None:
                item["status"] = "running"
                item["started_ts"] = item.get("started_ts") or _iso(started)
                item["heartbeat_ts"] = _iso(started)
                item["progress"] = {**dict(item.get("progress") or {}), "phase": "loading_rules", "percent": 2}

            current = _replace_run(safe_run_id, mark_running)
            request = dict(current.get("request") or {})
            client = (client_factory or _get_clickhouse_client)()
            rules, skipped = _load_active_rules(client, list(request.get("rule_ids") or []))
            if not rules:
                result = {
                    "dry_run": True,
                    "commit": False,
                    "alerts_created": 0,
                    "events_available": 0,
                    "events_scanned": 0,
                    "matched_events": 0,
                    "candidate_alerts": 0,
                    "preview": [],
                    "rules_evaluated": 0,
                    "rules_skipped": skipped,
                }
                return _finish(safe_run_id, status="completed_with_warnings", result=result)
            _progress(safe_run_id, phase="loading_events", percent=8)
            events_available, events = _load_events(client, request)
            if _cancel_requested(safe_run_id):
                return _finish(
                    safe_run_id,
                    status="cancelled",
                    result={"cancelled": True, "alerts_created": 0, "events_available": events_available, "events_scanned": 0},
                )
            _progress(safe_run_id, phase="evaluating", percent=15, events_available=events_available)
            result = _evaluate(
                safe_run_id,
                rules,
                events,
                events_available=events_available,
                skipped_rules=skipped,
            )
            if bool(result.get("cancelled")):
                return _finish(safe_run_id, status="cancelled", result=result)
            status = "completed_with_warnings" if skipped else "completed"
            finished = _finish(safe_run_id, status=status, result=result)
            _audit(
                "retroscan.completed",
                safe_run_id,
                str(current.get("owner") or "system"),
                {
                    "status": status,
                    "events_scanned": result.get("events_scanned"),
                    "candidate_alerts": result.get("candidate_alerts"),
                    "commit": False,
                },
            )
            return finished
    except Exception as exc:  # noqa: BLE001
        logger.exception("Retroscan run failed: %s", safe_run_id)
        failure = _safe_failure(exc)
        try:
            return _finish(safe_run_id, status="failed", result=None, error=failure)
        except RetroscanNotFoundError:
            raise exc
    finally:
        with _ACTIVE_LOCK:
            _ACTIVE_RUNS.discard(safe_run_id)
