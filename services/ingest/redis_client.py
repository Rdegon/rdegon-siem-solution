"""
Redis helpers for the ingest service.
"""

from __future__ import annotations

import json
import logging
import os
import time
from collections import Counter
from datetime import datetime, timezone
from typing import Any

try:
    from redis.asyncio import Redis
except ModuleNotFoundError:  # pragma: no cover - local test fallback
    Redis = Any  # type: ignore[assignment,misc]

from .config import IngestSettings
from .runtime_state import SQLiteIngestStateStore
from services.redis_runtime import connection_settings_from_object, create_resilient_async_redis_client
from services.transport_runtime import transport_cutover_stage, transport_health_snapshot, transport_settings_from_object

logger = logging.getLogger(__name__)
_LAST_DRAINING_WARNING_TS = 0.0

RAW_STREAM_KEY = "siem:raw"
DLQ_STREAM_KEY = "siem:raw:dlq"
INGEST_METRICS_HASH_KEY = "siem:ingest:metrics"
SOURCE_HEALTH_HASH_KEY = "siem:ingest:sources"
COLLECTOR_HEALTH_HASH_KEY = "siem:ingest:collectors"
DLQ_REPLAY_HASH_KEY = "siem:ingest:dlq:replays"

MAX_STREAM_LEN = 1_000_000
DEFAULT_RAW_STREAM_SOFT_LIMIT = 900_000
DEFAULT_RAW_STREAM_HARD_LIMIT = 980_000
DRAINING_WARNING_INTERVAL_SECONDS = 60
HEALTH_DELAY_SECONDS = 300
HEALTH_STALE_SECONDS = 1_800
HEALTH_GATING_WINDOW_SECONDS = 86_400
INGEST_STALE_ALERT_THRESHOLD = 2
INGEST_DLQ_ALERT_THRESHOLD = 5
DLQ_SCAN_CHUNK_SIZE = 2_000
DLQ_SCAN_MAX_ROWS = 500_000
DLQ_LIST_SCAN_MULTIPLIER = 40
DLQ_LIST_SCAN_MAX_ROWS = 2_000
DLQ_REPLAY_SCAN_MULTIPLIER = 100
DLQ_REPLAY_SCAN_MAX_ROWS = 10_000
SOURCE_ALIAS_OVERRIDES = {
    "192.168.3.81": "DESKTOP-5JMJVBH",
    "192.168.3.101": "pve",
    "192.168.3.102": "lab-edge-01",
    "192.168.1.102": "lab-edge-01",
    "192.168.1.35": "siem-ingest",
    "192.168.1.37": "siem-processing",
    "192.168.1.38": "siem-storage",
    "192.168.1.39": "siem-web",
    "192.168.1.101": "pve",
    "192.168.1.120": "nextcloud-siem",
    "192.168.1.121": "vuln-siem",
    "10.20.10.1": "lab-edge-01",
    "10.20.10.104": "siem-ingest",
    "10.20.10.105": "siem-processing",
    "10.20.10.106": "siem-storage",
    "10.20.10.107": "siem-web",
    "10.20.10.108": "siem-transport",
    "10.20.20.1": "lab-edge-01",
    "10.20.20.100": "minecraft-01",
    "10.20.20.120": "nextcloud-siem",
    "10.20.20.121": "navidrome-01",
    "10.20.20.130": "gamepanel-01",
    "10.20.30.1": "lab-edge-01",
    "10.20.30.122": "vuln-mgr-01",
    "10.20.30.123": "pilot-web-01",
    "10.20.30.124": "pilot-db-01",
    "10.20.30.125": "pilot-cache-01",
    "10.20.30.126": "openclaw-gateway",
}
SOURCE_TYPE_THRESHOLDS = {
    "default": (HEALTH_DELAY_SECONDS, HEALTH_STALE_SECONDS),
    "Platform": (1_800, 7_200),
    "Network": (3_600, 21_600),
    "Vulnerability scanner": (3_600, 21_600),
    "Synthetic": (HEALTH_STALE_SECONDS, HEALTH_STALE_SECONDS),
}
SYNTHETIC_SOURCE_TOKENS = ("smoke", "synthetic")
NON_OPERATIONAL_HEALTH_TOKENS = (
    "eps-bench",
    "benchmark",
    "generic-http",
    "kafka-cutover",
    "-probe",
    "vm1-debug",
    "manual",
)
LEGACY_OPTIONAL_COLLECTOR_PROFILES = {
    "network",
    "vpn",
    "vulnscanner-http",
}
TERMINAL_REPLAY_FAILURE_REASONS = {"payload_not_object", "dlq_item_not_found"}
NON_OPERATIONAL_DLQ_TOKENS = (
    "ci-test",
    "codex-smoke",
    "cleanup-smoke",
)
NON_OPERATIONAL_REPLAY_STATUSES = {"success", "ignored"}
RSYSLOG_OMFWD_NOISE_MARKERS = (
    "rsyslogd: action 'action-8-builtin:omfwd' suspended",
    "rsyslogd: action 'action-8-builtin:omfwd' resumed",
    "rsyslogd: omfwd: remote server at 127.0.0.1:5517 seems to have closed connection",
)
OPENCLAW_EXPECTED_DLQ_TOKENS = (
    "openclaw-gateway systemd-resolved",
    "openclaw-gateway auditd",
    "key=\"openclaw_config\"",
    "key=\"openclaw_connect\"",
    "key=\"openclaw_send\"",
    "/home/openclaw/.openclaw/",
    "proctitle=\"openclaw-agent\"",
    "comm=\"openclaw-agent\"",
    "comm=\"libuv-worker\"",
)


class IngestBackpressureError(RuntimeError):
    def __init__(self, *, dlq_id: str, stream_length: int, hard_limit: int) -> None:
        super().__init__("raw_stream_backpressure")
        self.dlq_id = dlq_id
        self.stream_length = stream_length
        self.hard_limit = hard_limit


def create_redis_client(settings: IngestSettings) -> Redis:
    if str(getattr(settings, "runtime_state_backend", "redis") or "redis").strip().lower() == "sqlite":
        return SQLiteIngestStateStore(str(getattr(settings, "runtime_state_sqlite_path", "") or ""))  # type: ignore[return-value]
    return create_resilient_async_redis_client(connection_settings_from_object(settings))


def _now() -> datetime:
    return datetime.now(tz=timezone.utc)


def _now_iso() -> str:
    return _now().replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _parse_ts(value: Any) -> datetime:
    text = str(value or "").strip()
    if not text:
        return datetime.min.replace(tzinfo=timezone.utc)
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return datetime.min.replace(tzinfo=timezone.utc)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _safe_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _json_dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def _safe_json_loads(value: Any, *, default: Any) -> Any:
    text = str(value or "").strip()
    if not text:
        return default
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return default


def _stringify_fields(payload: dict[str, Any]) -> dict[str, str]:
    fields: dict[str, str] = {}
    for key, value in payload.items():
        if isinstance(value, (dict, list)):
            fields[str(key)] = _json_dumps(value)
        else:
            fields[str(key)] = "" if value is None else str(value)
    return fields


def _stream_id_before(stream_id: Any) -> str:
    text = str(stream_id or "").strip()
    if not text or text == "-":
        return "-"
    try:
        millis_text, sequence_text = text.split("-", 1)
        millis = int(millis_text)
        sequence = int(sequence_text)
    except (TypeError, ValueError):
        return text
    if sequence > 0:
        return f"{millis}-{sequence - 1}"
    if millis <= 0:
        return "-"
    return f"{millis - 1}-18446744073709551615"


async def _scan_stream_reverse(
    redis: Redis,
    key: str,
    *,
    max_scan: int,
    chunk_size: int = DLQ_SCAN_CHUNK_SIZE,
) -> list[tuple[Any, dict[str, Any]]]:
    items: list[tuple[Any, dict[str, Any]]] = []
    cursor = "+"
    remaining = max(1, min(DLQ_SCAN_MAX_ROWS, int(max_scan)))
    while remaining > 0:
        batch_size = min(max(1, int(chunk_size)), remaining)
        rows = await redis.xrevrange(key, max=cursor, min="-", count=batch_size)
        if not rows:
            break
        items.extend(rows)
        remaining -= len(rows)
        if len(rows) < batch_size:
            break
        cursor = _stream_id_before(rows[-1][0])
        if cursor == "-":
            break
    return items


def _stream_limits(settings: IngestSettings | None = None) -> dict[str, int]:
    max_len = int(
        getattr(settings, "raw_stream_max_len", MAX_STREAM_LEN)
        if settings is not None
        else os.getenv("SIEM_INGEST_RAW_STREAM_MAX_LEN", str(MAX_STREAM_LEN))
    )
    soft_limit = int(
        getattr(settings, "raw_stream_soft_limit", DEFAULT_RAW_STREAM_SOFT_LIMIT)
        if settings is not None
        else os.getenv("SIEM_INGEST_RAW_STREAM_SOFT_LIMIT", str(DEFAULT_RAW_STREAM_SOFT_LIMIT))
    )
    hard_limit = int(
        getattr(settings, "raw_stream_hard_limit", DEFAULT_RAW_STREAM_HARD_LIMIT)
        if settings is not None
        else os.getenv("SIEM_INGEST_RAW_STREAM_HARD_LIMIT", str(DEFAULT_RAW_STREAM_HARD_LIMIT))
    )
    soft_limit = max(1, min(soft_limit, max_len))
    hard_limit = max(soft_limit, min(hard_limit, max_len))
    return {
        "max_len": max_len,
        "soft_limit": soft_limit,
        "hard_limit": hard_limit,
    }


async def _stream_length(redis: Redis, key: str) -> int:
    if hasattr(redis, "xlen"):
        try:
            return _safe_int(await redis.xlen(key))
        except Exception:  # noqa: BLE001
            logger.debug("xlen failed for %s", key, exc_info=True)
    try:
        rows = await redis.xrevrange(key, max="+", min="-", count=MAX_STREAM_LEN)
    except Exception:  # noqa: BLE001
        logger.debug("xrevrange fallback failed for %s", key, exc_info=True)
        return 0
    return len(rows)


async def _stream_group_pending(redis: Redis, key: str, group: str) -> int:
    if hasattr(redis, "xinfo_groups"):
        try:
            groups = await redis.xinfo_groups(key)
        except Exception:  # noqa: BLE001
            logger.debug("xinfo_groups failed for %s", key, exc_info=True)
        else:
            for item in groups or []:
                if not isinstance(item, dict):
                    continue
                if str(item.get("name") or "").strip() != group:
                    continue
                return _safe_int(item.get("pending"))
    return -1


def _source_identity(event: dict[str, Any]) -> str:
    for key in ("source_id", "source.name", "source", "host.name", "host", "device.name", "device"):
        value = str(event.get(key) or "").strip()
        if value:
            return value
    return "unknown-source"


def _collector_identity(event: dict[str, Any]) -> str:
    for key in ("collector_profile", "collector", "observer.profile", "ingest_profile", "observer.collector"):
        value = str(event.get(key) or "").strip()
        if value:
            return value
    return "unknown-collector"


def _event_timestamp(event: dict[str, Any]) -> str:
    for key in ("ts", "@timestamp", "event.created", "ingest_ts"):
        value = str(event.get(key) or "").strip()
        if value:
            return value
    return _now_iso()


def _source_alias(source_key: str) -> str:
    return SOURCE_ALIAS_OVERRIDES.get(str(source_key or "").strip(), str(source_key or "").strip())


def _canonicalize_source_health_row(row: dict[str, Any]) -> dict[str, Any]:
    payload = dict(row or {})
    canonical = _source_alias(str(payload.get("id") or payload.get("source") or ""))
    if canonical:
        payload["id"] = canonical
        payload["source"] = _source_alias(str(payload.get("source") or canonical))
        payload["source_alias"] = canonical
    return payload


def _merge_canonical_source_health_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {}
    counter_fields = (
        "events_total",
        "accepted_total",
        "rejected_total",
        "replayed_total",
        "synthetic_total",
    )
    for raw_row in rows:
        row = _canonicalize_source_health_row(raw_row)
        canonical = str(row.get("id") or row.get("source") or "").strip()
        if not canonical:
            continue
        existing = merged.get(canonical)
        if existing is None:
            merged[canonical] = row
            continue

        latest = max(
            (existing, row),
            key=lambda item: _parse_ts(item.get("last_seen_ts")),
        )
        combined = dict(latest)
        for field in counter_fields:
            combined[field] = _safe_int(existing.get(field)) + _safe_int(row.get(field))
        first_seen = min(
            (
                value
                for value in (str(existing.get("first_seen_ts") or ""), str(row.get("first_seen_ts") or ""))
                if value
            ),
            key=_parse_ts,
            default="",
        )
        if first_seen:
            combined["first_seen_ts"] = first_seen
        combined["id"] = canonical
        combined["source"] = canonical
        combined["source_alias"] = canonical
        merged[canonical] = combined
    return list(merged.values())


def _guess_runtime_source_type(source_key: str, current_type: str) -> str:
    explicit_type = str(current_type or "").strip()
    if explicit_type and explicit_type not in {"unknown", "http_json", "syslog"}:
        return explicit_type
    alias = _source_alias(source_key).lower()
    if alias.startswith("siem-"):
        return "Platform"
    if alias in {"vuln-siem"} or "vuln" in alias or "scanner" in alias:
        return "Vulnerability scanner"
    return explicit_type or "unknown"


def _is_synthetic_event(event: dict[str, Any], source_key: str) -> bool:
    if str(event.get("source_type") or "").strip().lower() == "synthetic":
        return True
    for value in (
        source_key,
        event.get("source"),
        event.get("source_id"),
        event.get("collector_profile"),
        event.get("ingest_profile"),
        event.get("event.dataset"),
    ):
        text = str(value or "").strip().lower()
        if text and any(token in text for token in SYNTHETIC_SOURCE_TOKENS):
            return True
    tags = event.get("tags") or []
    if isinstance(tags, list):
        return any(str(tag or "").strip().lower() in SYNTHETIC_SOURCE_TOKENS for tag in tags)
    return False


def _health_status(last_seen_ts: str, *, source_type: str = "", synthetic: bool = False) -> tuple[str, int]:
    parsed = _parse_ts(last_seen_ts)
    if parsed == datetime.min.replace(tzinfo=timezone.utc):
        return "unknown", -1
    age_seconds = max(0, int((_now() - parsed).total_seconds()))
    if synthetic:
        return "synthetic", age_seconds
    delay_seconds, stale_seconds = SOURCE_TYPE_THRESHOLDS.get(source_type or "default", SOURCE_TYPE_THRESHOLDS["default"])
    if age_seconds >= stale_seconds:
        return "stale", age_seconds
    if age_seconds >= delay_seconds:
        return "delayed", age_seconds
    return "healthy", age_seconds


def _runtime_source_type(row: dict[str, Any]) -> str:
    explicit = _guess_runtime_source_type(str(row.get("id") or row.get("source") or ""), str(row.get("source_type") or ""))
    if explicit not in {"unknown", "http_json", "syslog"}:
        return explicit
    inferred_tokens = " ".join(
        [
            str(row.get("collector_profile") or ""),
            str(row.get("collector") or ""),
            str(row.get("ingest_profile") or ""),
            str(row.get("last_dataset") or ""),
        ]
    ).lower()
    if "vuln" in inferred_tokens or "scanner" in inferred_tokens:
        return "Vulnerability scanner"
    if "network" in inferred_tokens or "syslog_tcp" in inferred_tokens:
        return "Network"
    if "siem-" in inferred_tokens or "linux-auth" in inferred_tokens or "linux-audit" in inferred_tokens:
        return "Platform"
    return explicit


async def _load_hash_record(redis: Redis, key: str, field: str) -> dict[str, Any]:
    raw = await redis.hget(key, field)
    if not raw:
        return {}
    value = _safe_json_loads(raw, default={})
    return value if isinstance(value, dict) else {}


async def _save_hash_record(redis: Redis, key: str, field: str, payload: dict[str, Any]) -> None:
    await redis.hset(key, field, _json_dumps(payload))


async def _increment_metric(redis: Redis, field: str, amount: int = 1) -> int:
    return int(await redis.hincrby(INGEST_METRICS_HASH_KEY, field, amount))


async def _touch_metrics(
    redis: Redis,
    *,
    event_ts: str,
    source_key: str,
    collector_key: str,
    stream_id: str,
    raw_stream_length: int | None = None,
) -> None:
    mapping = {
        "last_event_ts": event_ts,
        "last_source": source_key,
        "last_collector": collector_key,
        "last_stream_id": stream_id,
    }
    if raw_stream_length is not None:
        mapping["raw_stream_length"] = raw_stream_length
    await redis.hset(INGEST_METRICS_HASH_KEY, mapping=mapping)


def build_transport_overview(settings: IngestSettings | None = None) -> dict[str, Any]:
    transport = transport_health_snapshot(settings)
    transport["cutover_stage"] = transport_cutover_stage(settings)
    transport["security_protocol"] = str(transport.get("kafka_security_protocol") or "PLAINTEXT")
    return transport


async def _update_source_health(
    redis: Redis,
    event: dict[str, Any],
    *,
    stream_id: str,
    accepted: bool,
    rejected: bool,
    replayed: bool,
    error: str = "",
) -> None:
    source_key = _source_identity(event)
    collector_key = _collector_identity(event)
    existing = await _load_hash_record(redis, SOURCE_HEALTH_HASH_KEY, source_key)
    now_iso = _now_iso()
    event_ts = _event_timestamp(event)
    total_increment = 1 if accepted or rejected else 0
    source_type = _guess_runtime_source_type(source_key, str(event.get("source_type") or existing.get("source_type") or "unknown"))
    synthetic = _is_synthetic_event(event, source_key)

    row = {
        "id": source_key,
        "source": _source_alias(str(event.get("source") or source_key)),
        "source_alias": _source_alias(source_key),
        "source_type": source_type,
        "collector_profile": str(event.get("collector_profile") or collector_key),
        "collector": str(event.get("collector") or collector_key),
        "ingest_profile": str(event.get("ingest_profile") or existing.get("ingest_profile") or ""),
        "last_dataset": str(event.get("event.dataset") or existing.get("last_dataset") or ""),
        "first_seen_ts": str(existing.get("first_seen_ts") or now_iso),
        "last_seen_ts": now_iso,
        "last_event_ts": event_ts,
        "last_stream_id": stream_id,
        "events_total": _safe_int(existing.get("events_total")) + total_increment,
        "accepted_total": _safe_int(existing.get("accepted_total")) + (1 if accepted else 0),
        "rejected_total": _safe_int(existing.get("rejected_total")) + (1 if rejected else 0),
        "replayed_total": _safe_int(existing.get("replayed_total")) + (1 if replayed else 0),
        "synthetic_total": _safe_int(existing.get("synthetic_total")) + (1 if synthetic and total_increment else 0),
        "last_error": error or str(existing.get("last_error") or ""),
    }
    await _save_hash_record(redis, SOURCE_HEALTH_HASH_KEY, source_key, row)


async def _update_collector_health(
    redis: Redis,
    event: dict[str, Any],
    *,
    stream_id: str,
    accepted: bool,
    rejected: bool,
    replayed: bool,
    error: str = "",
) -> None:
    collector_key = _collector_identity(event)
    existing = await _load_hash_record(redis, COLLECTOR_HEALTH_HASH_KEY, collector_key)
    now_iso = _now_iso()
    event_ts = _event_timestamp(event)
    total_increment = 1 if accepted or rejected else 0
    synthetic = _is_synthetic_event(event, str(event.get("source") or ""))

    row = {
        "id": collector_key,
        "collector": str(event.get("collector") or collector_key),
        "collector_profile": str(event.get("collector_profile") or collector_key),
        "ingest_profile": str(event.get("ingest_profile") or existing.get("ingest_profile") or ""),
        "first_seen_ts": str(existing.get("first_seen_ts") or now_iso),
        "last_seen_ts": now_iso,
        "last_event_ts": event_ts,
        "last_stream_id": stream_id,
        "events_total": _safe_int(existing.get("events_total")) + total_increment,
        "accepted_total": _safe_int(existing.get("accepted_total")) + (1 if accepted else 0),
        "rejected_total": _safe_int(existing.get("rejected_total")) + (1 if rejected else 0),
        "replayed_total": _safe_int(existing.get("replayed_total")) + (1 if replayed else 0),
        "synthetic_total": _safe_int(existing.get("synthetic_total")) + (1 if synthetic and total_increment else 0),
        "last_error": error or str(existing.get("last_error") or ""),
    }
    await _save_hash_record(redis, COLLECTOR_HEALTH_HASH_KEY, collector_key, row)


async def _update_source_health_batch(
    redis: Redis,
    accepted_events: list[dict[str, Any]],
) -> None:
    grouped: dict[str, dict[str, Any]] = {}
    for item in accepted_events:
        event = dict(item.get("event") or {})
        if not event:
            continue
        source_key = _source_identity(event)
        group = grouped.setdefault(
            source_key,
            {
                "event": event,
                "stream_id": str(item.get("stream_id") or ""),
                "accepted_total": 0,
                "replayed_total": 0,
                "synthetic_total": 0,
            },
        )
        group["event"] = event
        group["stream_id"] = str(item.get("stream_id") or "")
        group["accepted_total"] += 1
        if bool(item.get("replayed")):
            group["replayed_total"] += 1
        if _is_synthetic_event(event, source_key):
            group["synthetic_total"] += 1

    for source_key, group in grouped.items():
        event = dict(group.get("event") or {})
        collector_key = _collector_identity(event)
        existing = await _load_hash_record(redis, SOURCE_HEALTH_HASH_KEY, source_key)
        now_iso = _now_iso()
        source_type = _guess_runtime_source_type(source_key, str(event.get("source_type") or existing.get("source_type") or "unknown"))
        accepted_total = _safe_int(group.get("accepted_total"))
        row = {
            "id": source_key,
            "source": _source_alias(str(event.get("source") or source_key)),
            "source_alias": _source_alias(source_key),
            "source_type": source_type,
            "collector_profile": str(event.get("collector_profile") or collector_key),
            "collector": str(event.get("collector") or collector_key),
            "ingest_profile": str(event.get("ingest_profile") or existing.get("ingest_profile") or ""),
            "last_dataset": str(event.get("event.dataset") or existing.get("last_dataset") or ""),
            "first_seen_ts": str(existing.get("first_seen_ts") or now_iso),
            "last_seen_ts": now_iso,
            "last_event_ts": _event_timestamp(event),
            "last_stream_id": str(group.get("stream_id") or ""),
            "events_total": _safe_int(existing.get("events_total")) + accepted_total,
            "accepted_total": _safe_int(existing.get("accepted_total")) + accepted_total,
            "rejected_total": _safe_int(existing.get("rejected_total")),
            "replayed_total": _safe_int(existing.get("replayed_total")) + _safe_int(group.get("replayed_total")),
            "synthetic_total": _safe_int(existing.get("synthetic_total")) + _safe_int(group.get("synthetic_total")),
            "last_error": str(existing.get("last_error") or ""),
        }
        await _save_hash_record(redis, SOURCE_HEALTH_HASH_KEY, source_key, row)


async def _update_collector_health_batch(
    redis: Redis,
    accepted_events: list[dict[str, Any]],
) -> None:
    grouped: dict[str, dict[str, Any]] = {}
    for item in accepted_events:
        event = dict(item.get("event") or {})
        if not event:
            continue
        collector_key = _collector_identity(event)
        group = grouped.setdefault(
            collector_key,
            {
                "event": event,
                "stream_id": str(item.get("stream_id") or ""),
                "accepted_total": 0,
                "replayed_total": 0,
                "synthetic_total": 0,
            },
        )
        group["event"] = event
        group["stream_id"] = str(item.get("stream_id") or "")
        group["accepted_total"] += 1
        if bool(item.get("replayed")):
            group["replayed_total"] += 1
        if _is_synthetic_event(event, str(event.get("source") or "")):
            group["synthetic_total"] += 1

    for collector_key, group in grouped.items():
        event = dict(group.get("event") or {})
        existing = await _load_hash_record(redis, COLLECTOR_HEALTH_HASH_KEY, collector_key)
        now_iso = _now_iso()
        accepted_total = _safe_int(group.get("accepted_total"))
        row = {
            "id": collector_key,
            "collector": str(event.get("collector") or collector_key),
            "collector_profile": str(event.get("collector_profile") or collector_key),
            "ingest_profile": str(event.get("ingest_profile") or existing.get("ingest_profile") or ""),
            "first_seen_ts": str(existing.get("first_seen_ts") or now_iso),
            "last_seen_ts": now_iso,
            "last_event_ts": _event_timestamp(event),
            "last_stream_id": str(group.get("stream_id") or ""),
            "events_total": _safe_int(existing.get("events_total")) + accepted_total,
            "accepted_total": _safe_int(existing.get("accepted_total")) + accepted_total,
            "rejected_total": _safe_int(existing.get("rejected_total")),
            "replayed_total": _safe_int(existing.get("replayed_total")) + _safe_int(group.get("replayed_total")),
            "synthetic_total": _safe_int(existing.get("synthetic_total")) + _safe_int(group.get("synthetic_total")),
            "last_error": str(existing.get("last_error") or ""),
        }
        await _save_hash_record(redis, COLLECTOR_HEALTH_HASH_KEY, collector_key, row)


def _health_row_with_runtime(row: dict[str, Any]) -> dict[str, Any]:
    item = dict(row)
    item["source_type"] = _runtime_source_type(item)
    total_events = max(0, _safe_int(item.get("events_total")))
    synthetic = str(item.get("source_type") or "").strip().lower() == "synthetic" or (
        total_events > 0 and _safe_int(item.get("synthetic_total")) >= total_events
    )
    status, age_seconds = _health_status(
        str(item.get("last_seen_ts") or ""),
        source_type=str(item.get("source_type") or ""),
        synthetic=synthetic,
    )
    item["status"] = status
    item["is_synthetic"] = synthetic
    item["seconds_since_last_seen"] = age_seconds
    event_lag_seconds = -1
    if str(item.get("last_event_ts") or "").strip():
        event_lag_seconds = max(0, int((_now() - _parse_ts(item.get("last_event_ts"))).total_seconds()))
    item["event_lag_seconds"] = event_lag_seconds
    return item


def _joined_health_tokens(row: dict[str, Any]) -> str:
    return " ".join(
        str(
            row.get(field) or ""
        ).strip().lower()
        for field in ("id", "source", "source_alias", "collector", "collector_profile", "ingest_profile", "last_dataset")
        if str(row.get(field) or "").strip()
    )


def _exclude_from_health_gating(row: dict[str, Any]) -> bool:
    if bool(row.get("is_synthetic")):
        return True
    if any(
        str(row.get(field) or "").strip().lower() in {"127.0.0.1", "::1", "localhost"}
        for field in ("id", "source", "source_alias")
    ):
        return True
    if any(
        str(row.get(field) or "").strip().lower().startswith("generic-http")
        for field in ("id", "source", "source_alias", "collector_profile", "ingest_profile", "last_dataset")
    ):
        return True
    joined = _joined_health_tokens(row)
    if joined.startswith("{'ip':"):
        return True
    if any(token in joined for token in NON_OPERATIONAL_HEALTH_TOKENS):
        return True
    age_seconds = max(0, _safe_int(row.get("seconds_since_last_seen")))
    if age_seconds > HEALTH_GATING_WINDOW_SECONDS and str(row.get("source_type") or "").strip() != "Platform":
        return True
    return False


def _health_profile(row: dict[str, Any]) -> str:
    for field in ("collector_profile", "ingest_profile", "collector", "last_dataset", "id"):
        value = str(row.get(field) or "").strip().lower()
        if value:
            return value
    return ""


def _annotate_health_gating(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    annotated: list[dict[str, Any]] = []
    for row in rows:
        item = dict(row)
        excluded = _exclude_from_health_gating(item)
        item["health_gating_excluded"] = excluded
        item["health_gating_reason"] = "non_operational" if excluded else ""
        annotated.append(item)
    return annotated


def _annotate_collector_gating(
    rows: list[dict[str, Any]],
    *,
    source_rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    annotated = _annotate_health_gating(rows)
    active_source_profiles = {
        _health_profile(source)
        for source in _annotate_health_gating(source_rows)
        if not bool(source.get("health_gating_excluded"))
    }
    active_source_profiles.discard("")
    for item in annotated:
        if bool(item.get("health_gating_excluded")):
            continue
        profile = _health_profile(item)
        status = str(item.get("status") or "").strip().lower()
        if (
            profile in LEGACY_OPTIONAL_COLLECTOR_PROFILES
            and status in {"stale", "delayed", "missing", "unknown"}
            and profile not in active_source_profiles
        ):
            item["health_gating_excluded"] = True
            item["health_gating_reason"] = "orphaned_legacy_collector"
    return annotated


def _replay_record_is_resolved(row: dict[str, Any]) -> bool:
    status = str(row.get("status") or "").strip().lower()
    if status in NON_OPERATIONAL_REPLAY_STATUSES:
        return True
    if status == "failed" and str(row.get("reason") or "").strip() in TERMINAL_REPLAY_FAILURE_REASONS:
        return True
    return False


def _dlq_payload_message(payload: Any) -> str:
    if isinstance(payload, dict):
        return str(payload.get("message") or payload.get("raw") or payload.get("payload") or "").strip()
    return str(payload or "").strip()


def _looks_like_rsyslog_omfwd_noise(*, reason: str, message: str) -> bool:
    if str(reason or "").strip().lower() != "syslog_push_failed":
        return False
    lowered = str(message or "").strip().lower()
    return bool(lowered) and any(marker in lowered for marker in RSYSLOG_OMFWD_NOISE_MARKERS)


def _looks_like_openclaw_expected_dlq_noise(*, source_ip: str, message: str) -> bool:
    if str(source_ip or "").strip() not in {"10.20.30.126", "127.0.0.1"}:
        return False
    lowered = str(message or "").strip().lower()
    return bool(lowered) and any(token in lowered for token in OPENCLAW_EXPECTED_DLQ_TOKENS)


def _dlq_entry_is_non_operational(
    *,
    reason: str,
    source_ip: str,
    collector: str,
    collector_profile: str,
    ingest_path: str,
    payload: Any,
    metadata: dict[str, Any],
    replay: dict[str, Any],
) -> bool:
    if str(metadata.get("operator_visibility") or replay.get("operator_visibility") or "").strip().lower() == "hidden":
        return True
    message = _dlq_payload_message(payload)
    if _looks_like_rsyslog_omfwd_noise(reason=reason, message=message):
        return True
    if _looks_like_openclaw_expected_dlq_noise(source_ip=source_ip, message=message):
        return True
    haystack = json.dumps(
        {
            "reason": reason,
            "source_ip": source_ip,
            "collector": collector,
            "collector_profile": collector_profile,
            "ingest_path": ingest_path,
            "payload": payload,
            "metadata": metadata,
            "replay": replay,
        },
        ensure_ascii=False,
        sort_keys=True,
    ).lower()
    return any(token in haystack for token in NON_OPERATIONAL_DLQ_TOKENS)


def prepare_raw_event_payload(event: dict[str, Any], *, replayed_from: str = "") -> dict[str, Any]:
    payload = dict(event)
    payload.setdefault("ingest_ts", _now_iso())
    payload.setdefault("pipeline", "redis-stream")
    if replayed_from:
        payload["replayed_from_dlq"] = replayed_from
    return payload


async def push_raw_event(
    redis: Redis,
    event: dict[str, Any],
    *,
    replayed_from: str = "",
    settings: IngestSettings | None = None,
    producer: Any | None = None,
    record_runtime_bookkeeping: bool = True,
) -> str:
    payload = prepare_raw_event_payload(event, replayed_from=replayed_from)
    limits = _stream_limits(settings)
    transport = transport_settings_from_object(settings)
    current_length = 0
    raw_pending = -1
    if transport.backend in {"redis", "dual"}:
        current_length = await _stream_length(redis, RAW_STREAM_KEY)
        raw_pending = await _stream_group_pending(redis, RAW_STREAM_KEY, "normalizer")
    source_key = _source_identity(payload)
    collector_key = _collector_identity(payload)
    if transport.backend in {"redis", "dual"} and current_length >= limits["hard_limit"] and (raw_pending < 0 or raw_pending >= limits["hard_limit"]):
        dlq_id = await push_dead_letter_event(
            redis,
            payload,
            reason="raw_stream_backpressure",
            source_ip=str(payload.get("source") or source_key),
            collector=str(payload.get("collector") or collector_key),
            collector_profile=str(payload.get("collector_profile") or collector_key),
            ingest_path=str(payload.get("ingest_path") or "/ingest"),
            metadata={
                "source_type": str(payload.get("source_type") or "backpressure_rejected"),
                "collector": str(payload.get("collector") or collector_key),
                "collector_profile": str(payload.get("collector_profile") or collector_key),
                "ingest_profile": str(payload.get("ingest_profile") or ""),
                "event.dataset": str(payload.get("event.dataset") or ""),
                "backpressure": {
                    "stream_key": RAW_STREAM_KEY,
                    "current_length": current_length,
                    "group_pending": raw_pending,
                    "soft_limit": limits["soft_limit"],
                    "hard_limit": limits["hard_limit"],
                    "max_len": limits["max_len"],
                },
            },
            count_parser_error=False,
        )
        await _increment_metric(redis, "backpressure_total")
        await redis.hset(
            INGEST_METRICS_HASH_KEY,
            mapping={
                "last_backpressure_ts": _now_iso(),
                "last_backpressure_stream_length": current_length,
                "last_backpressure_group_pending": raw_pending,
                "last_backpressure_reason": "raw_stream_hard_limit",
                "raw_stream_length": current_length,
            },
        )
        raise IngestBackpressureError(dlq_id=dlq_id, stream_length=current_length, hard_limit=limits["hard_limit"])
    if transport.backend in {"redis", "dual"} and current_length >= limits["hard_limit"]:
        global _LAST_DRAINING_WARNING_TS
        now_ts = time.monotonic()
        if now_ts - _LAST_DRAINING_WARNING_TS >= DRAINING_WARNING_INTERVAL_SECONDS:
            logger.warning(
                "Raw stream is at hard limit but consumer group is draining; allowing event through",
                extra={
                    "extra": {
                        "stream": RAW_STREAM_KEY,
                        "length": current_length,
                        "pending": raw_pending,
                        "hard_limit": limits["hard_limit"],
                    }
                },
            )
            _LAST_DRAINING_WARNING_TS = now_ts

    if transport.backend == "redis" or producer is None:
        stream_id = await redis.xadd(
            RAW_STREAM_KEY,
            _stringify_fields(payload),
            maxlen=limits["max_len"],
            approximate=True,
        )
    else:
        stream_id = await producer.publish(
            "raw",
            payload,
            maxlen=limits["max_len"],
            approximate=True,
        )

    if not record_runtime_bookkeeping:
        return str(stream_id)

    await _increment_metric(redis, "received_total")
    await _increment_metric(redis, "accepted_total")
    if replayed_from:
        await _increment_metric(redis, "replayed_total")
    await _touch_metrics(
        redis,
        event_ts=_event_timestamp(payload),
        source_key=source_key,
        collector_key=collector_key,
        stream_id=stream_id,
        raw_stream_length=(current_length + 1) if transport.backend in {"redis", "dual"} else None,
    )
    await redis.hset(
        INGEST_METRICS_HASH_KEY,
        mapping={
            "transport_backend": transport.backend,
            "transport_cutover_stage": transport_cutover_stage(settings),
            "transport_raw_target": transport.alias_target("raw"),
        },
    )
    await _update_source_health(redis, payload, stream_id=stream_id, accepted=True, rejected=False, replayed=bool(replayed_from))
    await _update_collector_health(redis, payload, stream_id=stream_id, accepted=True, rejected=False, replayed=bool(replayed_from))

    logger.debug(
        "Pushed event to Redis stream",
        extra={"extra": {"stream": RAW_STREAM_KEY, "id": stream_id, "collector": collector_key}},
    )
    return stream_id


async def push_raw_events_batch(
    redis: Redis,
    events: list[dict[str, Any]],
    *,
    settings: IngestSettings | None = None,
    producer: Any | None = None,
) -> list[dict[str, Any]]:
    if not events:
        return []
    transport = transport_settings_from_object(settings)
    if transport.backend != "kafka" or producer is None or not hasattr(producer, "publish_many"):
        accepted: list[dict[str, Any]] = []
        for event in events:
            stream_id = await push_raw_event(
                redis,
                event,
                settings=settings,
                producer=producer,
                record_runtime_bookkeeping=False,
            )
            accepted.append({"event": event, "stream_id": stream_id, "replayed": False})
        return accepted

    limits = _stream_limits(settings)
    payloads = [prepare_raw_event_payload(event) for event in events]
    stream_ids = await producer.publish_many(
        "raw",
        payloads,
        maxlen=limits["max_len"],
        approximate=True,
    )
    return [
        {"event": payload, "stream_id": stream_id, "replayed": False}
        for payload, stream_id in zip(payloads, stream_ids)
    ]


async def record_ingest_acceptance_batch(
    redis: Redis,
    accepted_events: list[dict[str, Any]],
    *,
    settings: IngestSettings | None = None,
) -> None:
    if not accepted_events:
        return
    transport = transport_settings_from_object(settings)
    accepted_total = len(accepted_events)
    replayed_total = sum(1 for item in accepted_events if bool(item.get("replayed")))
    latest = accepted_events[-1]
    latest_event = dict(latest.get("event") or {})
    mapping = {
        "last_event_ts": _event_timestamp(latest_event),
        "last_source": _source_identity(latest_event),
        "last_collector": _collector_identity(latest_event),
        "last_stream_id": str(latest.get("stream_id") or ""),
        "transport_backend": transport.backend,
        "transport_cutover_stage": transport_cutover_stage(settings),
        "transport_raw_target": transport.alias_target("raw"),
    }
    if transport.backend in {"redis", "dual"}:
        mapping["raw_stream_length"] = await _stream_length(redis, RAW_STREAM_KEY)
    await _increment_metric(redis, "received_total", accepted_total)
    await _increment_metric(redis, "accepted_total", accepted_total)
    if replayed_total:
        await _increment_metric(redis, "replayed_total", replayed_total)
    await redis.hset(INGEST_METRICS_HASH_KEY, mapping=mapping)
    await _update_source_health_batch(redis, accepted_events)
    await _update_collector_health_batch(redis, accepted_events)


async def push_dead_letter_event(
    redis: Redis,
    payload: Any,
    *,
    reason: str,
    source_ip: str = "",
    collector: str = "",
    collector_profile: str = "",
    ingest_path: str = "",
    metadata: dict[str, Any] | None = None,
    count_parser_error: bool = True,
) -> str:
    now_iso = _now_iso()
    event = {
        "reason": reason,
        "source_ip": source_ip,
        "collector": collector,
        "collector_profile": collector_profile,
        "ingest_path": ingest_path,
        "ingest_ts": now_iso,
        "raw_payload": _json_dumps(payload),
        "metadata": metadata or {},
    }
    dlq_id = await redis.xadd(
        DLQ_STREAM_KEY,
        _stringify_fields(event),
        maxlen=MAX_STREAM_LEN,
        approximate=True,
    )

    health_event = {
        "source": source_ip or str((metadata or {}).get("source") or ""),
        "source_type": str((metadata or {}).get("source_type") or "invalid_payload"),
        "collector": collector or str((metadata or {}).get("collector") or "unknown-collector"),
        "collector_profile": collector_profile or str((metadata or {}).get("collector_profile") or "unknown-collector"),
        "ingest_profile": str((metadata or {}).get("ingest_profile") or ""),
        "event.dataset": str((metadata or {}).get("event.dataset") or ""),
        "ts": now_iso,
    }

    await _increment_metric(redis, "received_total")
    await _increment_metric(redis, "dlq_total")
    if count_parser_error:
        await _increment_metric(redis, "parser_errors_total")
    await redis.hset(
        INGEST_METRICS_HASH_KEY,
        mapping={
            "last_dlq_ts": now_iso,
            "last_dlq_id": dlq_id,
            "last_error_reason": reason,
        },
    )
    await _update_source_health(redis, health_event, stream_id=dlq_id, accepted=False, rejected=True, replayed=False, error=reason)
    await _update_collector_health(redis, health_event, stream_id=dlq_id, accepted=False, rejected=True, replayed=False, error=reason)
    return dlq_id


async def _load_replay_records(redis: Redis) -> dict[str, dict[str, Any]]:
    raw = await redis.hgetall(DLQ_REPLAY_HASH_KEY)
    items: dict[str, dict[str, Any]] = {}
    for key, value in (raw or {}).items():
        parsed = _safe_json_loads(value, default={})
        if isinstance(parsed, dict):
            items[str(key)] = parsed
    return items


async def list_source_health(redis: Redis, *, limit: int = 200, include_excluded: bool = False) -> dict[str, Any]:
    rows = [
        _safe_json_loads(value, default={})
        for value in await redis.hvals(SOURCE_HEALTH_HASH_KEY)
    ]
    rows = [row for row in rows if row]
    rows = [_health_row_with_runtime(row) for row in _merge_canonical_source_health_rows(rows)]
    rows.sort(key=lambda item: str(item.get("last_seen_ts") or ""), reverse=True)
    rows = _annotate_health_gating(rows)
    operational_rows = [row for row in rows if not bool(row.get("health_gating_excluded"))]
    visible_rows = rows if include_excluded else operational_rows
    breakdown = Counter(str(item.get("status") or "unknown") for item in operational_rows)
    synthetic_count = sum(1 for item in rows if bool(item.get("is_synthetic")))
    excluded_count = sum(1 for item in rows if bool(item.get("health_gating_excluded")))
    return {
        "items": visible_rows[: max(1, min(500, limit))],
        "metrics": {
            "total": len(operational_rows),
            "healthy": breakdown.get("healthy", 0),
            "delayed": breakdown.get("delayed", 0),
            "stale": breakdown.get("stale", 0),
            "synthetic": synthetic_count,
            "excluded": excluded_count,
            "events_total": sum(_safe_int(item.get("events_total")) for item in operational_rows),
        },
        "breakdown": [
            {"label": label, "count": count}
            for label, count in (
                ([("synthetic", synthetic_count)] if synthetic_count else [])
                + ([("excluded", excluded_count)] if excluded_count else [])
                + list(breakdown.most_common())
            )
        ],
    }


async def list_collector_health(redis: Redis, *, limit: int = 200, include_excluded: bool = False) -> dict[str, Any]:
    rows = [_health_row_with_runtime(_safe_json_loads(value, default={})) for value in await redis.hvals(COLLECTOR_HEALTH_HASH_KEY)]
    rows = [row for row in rows if row]
    rows.sort(key=lambda item: str(item.get("last_seen_ts") or ""), reverse=True)
    source_rows = [
        _safe_json_loads(value, default={})
        for value in await redis.hvals(SOURCE_HEALTH_HASH_KEY)
    ]
    source_rows = [row for row in source_rows if row]
    source_rows = [_health_row_with_runtime(row) for row in _merge_canonical_source_health_rows(source_rows)]
    rows = _annotate_collector_gating(rows, source_rows=source_rows)
    operational_rows = [row for row in rows if not bool(row.get("health_gating_excluded"))]
    visible_rows = rows if include_excluded else operational_rows
    breakdown = Counter(str(item.get("status") or "unknown") for item in operational_rows)
    synthetic_count = sum(1 for item in rows if bool(item.get("is_synthetic")))
    excluded_count = sum(1 for item in rows if bool(item.get("health_gating_excluded")))
    return {
        "items": visible_rows[: max(1, min(500, limit))],
        "metrics": {
            "total": len(operational_rows),
            "healthy": breakdown.get("healthy", 0),
            "delayed": breakdown.get("delayed", 0),
            "stale": breakdown.get("stale", 0),
            "synthetic": synthetic_count,
            "excluded": excluded_count,
            "events_total": sum(_safe_int(item.get("events_total")) for item in operational_rows),
        },
        "breakdown": [
            {"label": label, "count": count}
            for label, count in (
                ([("synthetic", synthetic_count)] if synthetic_count else [])
                + ([("excluded", excluded_count)] if excluded_count else [])
                + list(breakdown.most_common())
            )
        ],
    }


async def list_dlq_events(redis: Redis, *, count: int = 200) -> dict[str, Any]:
    replay_rows = await _load_replay_records(redis)
    requested_count = max(1, min(500, count))
    total = _safe_int((await redis.hget(INGEST_METRICS_HASH_KEY, "dlq_total")) or 0)
    replayed_success = sum(1 for item in replay_rows.values() if _replay_record_is_resolved(item))
    outstanding = max(0, total - replayed_success)
    # Keep DLQ listing responsive even when the stream contains hundreds of
    # thousands of historical entries. The UI only needs a recent visible slice,
    # so scanning the full outstanding backlog here is pathological.
    scan_count = max(requested_count * DLQ_LIST_SCAN_MULTIPLIER, requested_count)
    max_scan = min(DLQ_LIST_SCAN_MAX_ROWS, scan_count)
    entries = await _scan_stream_reverse(redis, DLQ_STREAM_KEY, max_scan=max_scan)
    items: list[dict[str, Any]] = []
    hidden_non_operational = 0
    hidden_resolved = 0
    for stream_id, fields in entries:
        metadata = _safe_json_loads(fields.get("metadata"), default={})
        payload = _safe_json_loads(fields.get("raw_payload"), default=fields.get("raw_payload") or "")
        replay = replay_rows.get(str(stream_id), {})
        reason = str(fields.get("reason") or "")
        source_ip = str(fields.get("source_ip") or "")
        collector = str(fields.get("collector") or "")
        collector_profile = str(fields.get("collector_profile") or "")
        ingest_path = str(fields.get("ingest_path") or "")
        if _replay_record_is_resolved(replay):
            hidden_resolved += 1
            continue
        if _dlq_entry_is_non_operational(
            reason=reason,
            source_ip=source_ip,
            collector=collector,
            collector_profile=collector_profile,
            ingest_path=ingest_path,
            payload=payload,
            metadata=metadata if isinstance(metadata, dict) else {},
            replay=replay if isinstance(replay, dict) else {},
        ):
            hidden_non_operational += 1
            continue
        items.append(
            {
                "id": str(stream_id),
                "reason": reason,
                "source_ip": source_ip,
                "collector": collector,
                "collector_profile": collector_profile,
                "ingest_path": ingest_path,
                "ingest_ts": str(fields.get("ingest_ts") or ""),
                "payload": payload,
                "metadata": metadata if isinstance(metadata, dict) else {},
                "replay": replay,
            }
        )
        if len(items) >= requested_count:
            break

    return {
        "items": items,
        "metrics": {
            "visible": len(items),
            "replayed": replayed_success,
            "total": total,
            "outstanding": outstanding,
            "hidden_resolved": hidden_resolved,
            "hidden_non_operational": hidden_non_operational,
        },
    }


async def replay_dlq_events(
    redis: Redis,
    *,
    ids: list[str] | None = None,
    limit: int = 20,
    actor: str = "system",
    settings: IngestSettings | None = None,
    producer: Any | None = None,
) -> dict[str, Any]:
    replay_rows = await _load_replay_records(redis)
    requested_ids = [str(item).strip() for item in (ids or []) if str(item).strip()]
    if not requested_ids:
        requested_limit = max(1, min(200, int(limit)))
        total = _safe_int((await redis.hget(INGEST_METRICS_HASH_KEY, "dlq_total")) or 0)
        replayed_success = sum(1 for item in replay_rows.values() if _replay_record_is_resolved(item))
        outstanding = max(0, total - replayed_success)
        if outstanding <= 0:
            return {
                "status": "ok",
                "requested": 0,
                "replayed": 0,
                "skipped": 0,
                "failed": 0,
                "items": [],
            }
        resolved_window = sum(1 for item in replay_rows.values() if _replay_record_is_resolved(item))
        max_scan = min(
            DLQ_REPLAY_SCAN_MAX_ROWS,
            max(requested_limit * DLQ_REPLAY_SCAN_MULTIPLIER, resolved_window + (requested_limit * 10)),
        )
        visible_entries = await _scan_stream_reverse(redis, DLQ_STREAM_KEY, max_scan=max_scan)
        requested_ids = [
            str(stream_id)
            for stream_id, fields in visible_entries
            if str(stream_id)
            and not _replay_record_is_resolved(dict(replay_rows.get(str(stream_id), {}) or {}))
            and isinstance(_safe_json_loads(fields.get("raw_payload"), default=None), dict)
            and not _dlq_entry_is_non_operational(
                reason=str(fields.get("reason") or ""),
                source_ip=str(fields.get("source_ip") or ""),
                collector=str(fields.get("collector") or ""),
                collector_profile=str(fields.get("collector_profile") or ""),
                ingest_path=str(fields.get("ingest_path") or ""),
                payload=_safe_json_loads(fields.get("raw_payload"), default=fields.get("raw_payload") or ""),
                metadata=_safe_json_loads(fields.get("metadata"), default={}),
                replay=dict(replay_rows.get(str(stream_id), {}) or {}),
            )
        ][: requested_limit]

    replayed = 0
    skipped = 0
    failed = 0
    results: list[dict[str, Any]] = []

    for dlq_id in requested_ids:
        existing_replay = replay_rows.get(dlq_id, {})
        if str(existing_replay.get("status") or "") == "success":
            skipped += 1
            results.append({"id": dlq_id, "status": "skipped", "reason": "already_replayed"})
            continue

        rows = await redis.xrange(DLQ_STREAM_KEY, min=dlq_id, max=dlq_id, count=1)
        if not rows:
            failed += 1
            result = {"id": dlq_id, "status": "failed", "reason": "dlq_item_not_found", "actor": actor, "ts": _now_iso()}
            await _save_hash_record(redis, DLQ_REPLAY_HASH_KEY, dlq_id, result)
            results.append(result)
            continue

        _, fields = rows[0]
        payload = _safe_json_loads(fields.get("raw_payload"), default=None)
        if not isinstance(payload, dict):
            failed += 1
            result = {"id": dlq_id, "status": "failed", "reason": "payload_not_object", "actor": actor, "ts": _now_iso()}
            await _save_hash_record(redis, DLQ_REPLAY_HASH_KEY, dlq_id, result)
            results.append(result)
            continue

        metadata = _safe_json_loads(fields.get("metadata"), default={})
        payload.setdefault("source", str(fields.get("source_ip") or ""))
        payload.setdefault("collector", str(fields.get("collector") or "dlq_replay"))
        payload.setdefault("collector_profile", str(fields.get("collector_profile") or "dlq-replay"))
        payload.setdefault("ingest_path", str(fields.get("ingest_path") or "/dlq/replay"))
        if isinstance(metadata, dict):
            payload.setdefault("event.dataset", str(metadata.get("event.dataset") or "dlq-replay"))
            payload.setdefault("source_type", str(metadata.get("source_type") or "dlq-replay"))
        try:
            raw_stream_id = await push_raw_event(
                redis,
                payload,
                replayed_from=dlq_id,
                settings=settings,
                producer=producer,
            )
        except IngestBackpressureError as exc:
            failed += 1
            result = {
                "id": dlq_id,
                "status": "failed",
                "reason": "raw_stream_backpressure",
                "actor": actor,
                "ts": _now_iso(),
                "backpressure_dlq_id": exc.dlq_id,
                "stream_length": exc.stream_length,
                "hard_limit": exc.hard_limit,
            }
            await _save_hash_record(redis, DLQ_REPLAY_HASH_KEY, dlq_id, result)
            results.append(result)
            continue

        replayed += 1
        result = {
            "id": dlq_id,
            "status": "success",
            "actor": actor,
            "ts": _now_iso(),
            "raw_stream_id": raw_stream_id,
        }
        await _save_hash_record(redis, DLQ_REPLAY_HASH_KEY, dlq_id, result)
        results.append(result)

    return {
        "status": "ok",
        "requested": len(requested_ids),
        "replayed": replayed,
        "skipped": skipped,
        "failed": failed,
        "items": results,
    }


async def suppress_non_operational_dlq_events(
    redis: Redis,
    *,
    actor: str = "system",
    limit: int = 100_000,
) -> dict[str, Any]:
    replay_rows = await _load_replay_records(redis)
    rows = await _scan_stream_reverse(redis, DLQ_STREAM_KEY, max_scan=max(1, min(DLQ_SCAN_MAX_ROWS, int(limit))))
    suppressed = 0
    skipped = 0
    for stream_id, fields in rows:
        dlq_id = str(stream_id)
        existing_replay = dict(replay_rows.get(dlq_id) or {})
        if _replay_record_is_resolved(existing_replay):
            skipped += 1
            continue
        payload = _safe_json_loads(fields.get("raw_payload"), default=fields.get("raw_payload") or "")
        metadata = _safe_json_loads(fields.get("metadata"), default={})
        if not _dlq_entry_is_non_operational(
            reason=str(fields.get("reason") or ""),
            source_ip=str(fields.get("source_ip") or ""),
            collector=str(fields.get("collector") or ""),
            collector_profile=str(fields.get("collector_profile") or ""),
            ingest_path=str(fields.get("ingest_path") or ""),
            payload=payload,
            metadata=metadata if isinstance(metadata, dict) else {},
            replay=existing_replay,
        ):
            continue
        record = {
            "id": dlq_id,
            "status": "ignored",
            "reason": "non_operational_runtime_noise",
            "actor": actor,
            "ts": _now_iso(),
            "operator_visibility": "hidden",
        }
        await _save_hash_record(redis, DLQ_REPLAY_HASH_KEY, dlq_id, record)
        replay_rows[dlq_id] = record
        suppressed += 1
    return {
        "status": "ok",
        "suppressed": suppressed,
        "skipped": skipped,
        "scanned": len(rows),
    }


async def build_ingest_overview(redis: Redis, settings: IngestSettings | None = None) -> dict[str, Any]:
    source_health = await list_source_health(redis, limit=500)
    collector_health = await list_collector_health(redis, limit=500)
    replay_rows = await _load_replay_records(redis)
    raw_metrics = await redis.hgetall(INGEST_METRICS_HASH_KEY)
    transport = build_transport_overview(settings)
    limits = _stream_limits(settings)
    raw_stream_length = await _stream_length(redis, RAW_STREAM_KEY) if transport["redis_streams_active"] else 0
    dlq_stream_length = await _stream_length(redis, DLQ_STREAM_KEY)
    pressure_state = "healthy"
    if transport["redis_streams_active"] and raw_stream_length >= limits["hard_limit"]:
        pressure_state = "backpressure"
    elif transport["redis_streams_active"] and raw_stream_length >= limits["soft_limit"]:
        pressure_state = "warning"
    metrics = {
        "received_total": _safe_int(raw_metrics.get("received_total")),
        "accepted_total": _safe_int(raw_metrics.get("accepted_total")),
        "dlq_total": _safe_int(raw_metrics.get("dlq_total")),
        "replayed_total": _safe_int(raw_metrics.get("replayed_total")),
        "parser_errors_total": _safe_int(raw_metrics.get("parser_errors_total")),
        "backpressure_total": _safe_int(raw_metrics.get("backpressure_total")),
        "active_sources": source_health["metrics"]["healthy"] + source_health["metrics"]["delayed"],
        "active_collectors": collector_health["metrics"]["healthy"] + collector_health["metrics"]["delayed"],
        "last_event_ts": str(raw_metrics.get("last_event_ts") or ""),
        "last_source": str(raw_metrics.get("last_source") or ""),
        "last_collector": str(raw_metrics.get("last_collector") or ""),
        "last_stream_id": str(raw_metrics.get("last_stream_id") or ""),
        "last_dlq_ts": str(raw_metrics.get("last_dlq_ts") or ""),
        "last_backpressure_ts": str(raw_metrics.get("last_backpressure_ts") or ""),
        "raw_stream_length": raw_stream_length,
        "dlq_stream_length": dlq_stream_length,
        "raw_stream_max_len": limits["max_len"],
        "raw_stream_soft_limit": limits["soft_limit"],
        "raw_stream_hard_limit": limits["hard_limit"],
        "raw_stream_pressure_state": pressure_state,
    }
    replayed_success = sum(1 for item in replay_rows.values() if _replay_record_is_resolved(item))
    outstanding_dlq = max(0, metrics["dlq_total"] - replayed_success)
    issues: list[str] = []
    if source_health["metrics"]["stale"] >= INGEST_STALE_ALERT_THRESHOLD:
        issues.append(f"Stale sources detected: {source_health['metrics']['stale']}")
    if collector_health["metrics"]["stale"] >= INGEST_STALE_ALERT_THRESHOLD:
        issues.append(f"Stale collectors detected: {collector_health['metrics']['stale']}")
    if outstanding_dlq >= INGEST_DLQ_ALERT_THRESHOLD:
        issues.append(f"Outstanding DLQ events: {outstanding_dlq}")
    if metrics["parser_errors_total"] and outstanding_dlq >= INGEST_DLQ_ALERT_THRESHOLD:
        issues.append(f"Parser errors recorded: {metrics['parser_errors_total']}")
    if raw_stream_length >= limits["soft_limit"]:
        issues.append(f"Raw ingest stream near capacity: {raw_stream_length}/{limits['max_len']}")
    if metrics["backpressure_total"]:
        issues.append(f"Backpressure rejections recorded: {metrics['backpressure_total']}")

    return {
        "generated_ts": _now_iso(),
        "env": settings.env if settings else "",
        "instance": settings.instance_name if settings else "",
        "syslog_profiles": settings.syslog_profiles() if settings else {},
        "metrics": metrics,
        "sources": source_health,
        "collectors": collector_health,
        "dlq": {
            "total": metrics["dlq_total"],
            "outstanding": outstanding_dlq,
            "replayed": replayed_success,
            "last_dlq_ts": metrics["last_dlq_ts"],
        },
        "streams": {
            "raw": {
                "key": RAW_STREAM_KEY,
                "length": raw_stream_length,
                "max_len": limits["max_len"],
                "soft_limit": limits["soft_limit"],
                "hard_limit": limits["hard_limit"],
                "pressure_state": pressure_state,
            },
            "dlq": {
                "key": DLQ_STREAM_KEY,
                "length": dlq_stream_length,
            },
        },
        "transport": transport,
        "issues": issues,
    }
