from __future__ import annotations

from time import time
from typing import Any

from .shared import deps_module, is_non_operational_inventory_record

try:
    from ..ingest_runtime import list_ingest_collectors, list_ingest_sources
except ImportError:  # pragma: no cover - local test fallback
    from ingest_runtime import list_ingest_collectors, list_ingest_sources  # type: ignore[no-redef]


INVENTORY_CACHE_TTL_SECONDS = 45
_CACHE: dict[tuple[str, int, int], tuple[float, list[dict[str, object]]]] = {}


def _clone(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    return [dict(row) for row in rows]


def _cache_get(key: tuple[str, int, int]) -> list[dict[str, object]] | None:
    cached = _CACHE.get(key)
    if not cached:
        return None
    if time() - cached[0] > INVENTORY_CACHE_TTL_SECONDS:
        _CACHE.pop(key, None)
        return None
    return _clone(cached[1])


def _cache_put(key: tuple[str, int, int], rows: list[dict[str, object]]) -> list[dict[str, object]]:
    _CACHE[key] = (time(), _clone(rows))
    if len(_CACHE) > 32:
        oldest_key = min(_CACHE, key=lambda item: _CACHE[item][0])
        _CACHE.pop(oldest_key, None)
    return _clone(rows)


def _runtime_source_name(item: dict[str, Any]) -> str:
    for key in ("source_alias", "source", "host_name", "hostname", "id", "source_ip"):
        value = str(item.get(key) or "").strip()
        if value:
            return value
    return ""


def _ip_text(value: object) -> str:
    text = str(value or "").strip()
    parts = text.split(".")
    if len(parts) != 4:
        return ""
    try:
        if all(0 <= int(part) <= 255 for part in parts):
            return text
    except ValueError:
        return ""
    return ""


def _fallback_source_inventory(limit: int) -> list[dict[str, object]]:
    try:
        payload = list_ingest_sources(limit=limit)
    except Exception:  # noqa: BLE001
        return []
    rows: list[dict[str, object]] = []
    for item in list(payload.get("items") or []):
        if not isinstance(item, dict):
            continue
        source_name = _runtime_source_name(item)
        if not source_name:
            continue
        collector_id = str(item.get("collector_profile") or item.get("collector") or "runtime-health")
        source_ip = _ip_text(source_name)
        rows.append(
            {
                "source_name": source_name,
                "source_ips": [source_ip] if source_ip else [],
                "observed_ips": [source_ip] if source_ip else [],
                "cmdb_ip": "",
                "source_type": str(item.get("source_type") or item.get("kind") or "Runtime heartbeat"),
                "collector_id": collector_id,
                "collector_name": collector_id,
                "events": int(item.get("events_total") or item.get("events") or 0),
                "last_seen": str(item.get("last_seen_ts") or item.get("last_seen") or item.get("last_event_ts") or ""),
                "status": str(item.get("status") or "observed"),
                "categories": [],
                "products": [],
                "services": [],
                "aliases": [str(item.get("id") or "")] if str(item.get("id") or "") and str(item.get("id") or "") != source_name else [],
                "inventory_source": "ingest-health-fallback",
            }
        )
    return rows[:limit]


def _fallback_collector_inventory(hours: int) -> list[dict[str, object]]:
    try:
        payload = list_ingest_collectors(limit=200)
    except Exception:  # noqa: BLE001
        payload = {"items": []}
    rows: list[dict[str, object]] = []
    for item in list(payload.get("items") or []):
        if not isinstance(item, dict):
            continue
        collector_id = str(item.get("collector_profile") or item.get("collector") or item.get("id") or "").strip()
        if not collector_id:
            continue
        rows.append(
            {
                "collector_id": collector_id,
                "name": collector_id,
                "node": str(item.get("node") or item.get("host") or ""),
                "role": str(item.get("role") or item.get("source_type") or "runtime collector"),
                "protocols": list(item.get("protocols") or []),
                "source_types": [str(item.get("source_type") or "")] if str(item.get("source_type") or "") else [],
                "sources_count": int(item.get("sources_count") or item.get("active_sources") or 0),
                "events": int(item.get("events_total") or item.get("events") or 0),
                "last_seen": str(item.get("last_seen_ts") or item.get("last_seen") or item.get("last_event_ts") or ""),
                "status": str(item.get("status") or "observed"),
                "covered_sources": list(item.get("covered_sources") or []),
                "inventory_source": "ingest-health-fallback",
            }
        )
    if rows:
        return rows

    grouped: dict[str, dict[str, object]] = {}
    for source in _fallback_source_inventory(500):
        collector_id = str(source.get("collector_id") or "runtime-health")
        current = grouped.setdefault(
            collector_id,
            {
                "collector_id": collector_id,
                "name": collector_id,
                "node": "",
                "role": "runtime collector",
                "protocols": [],
                "source_types": [],
                "sources_count": 0,
                "events": 0,
                "last_seen": "",
                "status": "observed",
                "covered_sources": [],
                "inventory_source": "ingest-health-fallback",
            },
        )
        current["sources_count"] = int(current.get("sources_count") or 0) + 1
        current["events"] = int(current.get("events") or 0) + int(source.get("events") or 0)
        current["covered_sources"] = [*list(current.get("covered_sources") or []), str(source.get("source_name") or "")]
        if str(source.get("last_seen") or "") > str(current.get("last_seen") or ""):
            current["last_seen"] = str(source.get("last_seen") or "")
    return list(grouped.values())


def fetch_source_inventory(limit: int = 200, hours: int = 24) -> list[dict[str, object]]:
    safe_limit = max(1, min(int(limit or 200), 1000))
    safe_hours = max(1, min(int(hours or 24), 720))
    cache_key = ("sources", safe_limit, safe_hours)
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached
    try:
        rows = list(deps_module().fetch_source_inventory(limit=safe_limit, hours=safe_hours))
    except Exception:  # noqa: BLE001
        rows = []
    sanitized = [row for row in rows if not is_non_operational_inventory_record(row)]
    if not sanitized:
        sanitized = [row for row in _fallback_source_inventory(safe_limit) if not is_non_operational_inventory_record(row)]
    return _cache_put(cache_key, sanitized[:safe_limit])


def fetch_collector_inventory(hours: int = 24) -> list[dict[str, object]]:
    safe_hours = max(1, min(int(hours or 24), 720))
    cache_key = ("collectors", 200, safe_hours)
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached
    try:
        rows = list(deps_module().fetch_collector_inventory(hours=safe_hours))
    except Exception:  # noqa: BLE001
        rows = []
    sanitized: list[dict[str, object]] = []
    for row in rows:
        current = dict(row)
        covered_sources = [item for item in list(current.get("covered_sources") or []) if not is_non_operational_inventory_record(item)]
        if "covered_sources" in current:
            current["covered_sources"] = covered_sources
        if "active_sources" in current:
            current["active_sources"] = len(covered_sources)
        if not covered_sources and is_non_operational_inventory_record(current):
            continue
        sanitized.append(current)
    if not sanitized or not any(
        int(row.get("sources_count") or 0)
        or int(row.get("active_sources") or 0)
        or int(row.get("events") or 0)
        or len(list(row.get("covered_sources") or []))
        for row in sanitized
    ):
        sanitized = [row for row in _fallback_collector_inventory(safe_hours) if not is_non_operational_inventory_record(row)]
    return _cache_put(cache_key, sanitized)


def fetch_top_sources(limit: int = 20, hours: int = 24, *, from_ts: str = "", to_ts: str = "") -> list[dict[str, object]]:
    rows = list(deps_module().fetch_top_sources(limit=limit, hours=hours, from_ts=from_ts, to_ts=to_ts))
    return [row for row in rows if not is_non_operational_inventory_record(row)]
