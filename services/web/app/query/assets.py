from __future__ import annotations

import os
from pathlib import Path
from time import time
from typing import Any

from .shared import deps_module, is_non_operational_inventory_record
from .stale_cache import load_snapshot, refresh_in_background, save_snapshot


INVENTORY_CACHE_TTL_SECONDS = max(
    30,
    int(os.getenv("SIEM_INVENTORY_CACHE_TTL_SECONDS", "300") or "300"),
)
INVENTORY_CACHE_MAX_STALE_SECONDS = max(
    INVENTORY_CACHE_TTL_SECONDS,
    int(os.getenv("SIEM_INVENTORY_CACHE_MAX_STALE_SECONDS", "86400") or "86400"),
)
INVENTORY_CACHE_FILE = Path(
    os.getenv(
        "SIEM_ASSET_QUERY_CACHE_FILE",
        "/opt/siem/runtime-docs/asset_query_cache.json",
    )
)
_CACHE: dict[int, tuple[float, list[dict[str, Any]]]] = {}


def fetch_active_list_items(limit: int = 200) -> list[dict[str, Any]]:
    return list(deps_module().fetch_active_list_items(limit=limit))


def save_active_list_item(*, list_name: str, list_kind: str, item_type: str, item_value: str, item_label: str, tags: str) -> dict[str, Any]:
    return dict(
        deps_module().save_active_list_item(
            list_name=list_name,
            list_kind=list_kind,
            item_type=item_type,
            item_value=item_value,
            item_label=item_label,
            tags=tags,
        )
    )


def fetch_asset_categories() -> list[dict[str, Any]]:
    return list(deps_module().fetch_asset_categories())


def _clone(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [dict(row) for row in rows]


def refresh_assets(hours: int = 24) -> list[dict[str, Any]]:
    safe_hours = max(1, min(int(hours or 24), 720))
    rows = list(deps_module().fetch_assets(limit=500, hours=safe_hours))
    sanitized = [row for row in rows if not is_non_operational_inventory_record(row)]
    _CACHE[safe_hours] = (time(), _clone(sanitized))
    save_snapshot(INVENTORY_CACHE_FILE, str(safe_hours), sanitized)
    return _clone(sanitized)


def fetch_assets(limit: int = 50, hours: int = 24) -> list[dict[str, Any]]:
    safe_limit = max(1, min(int(limit or 50), 500))
    safe_hours = max(1, min(int(hours or 24), 720))
    cached = _CACHE.get(safe_hours)
    if cached and time() - cached[0] <= INVENTORY_CACHE_TTL_SECONDS:
        return _clone(cached[1][:safe_limit])

    snapshot = load_snapshot(
        INVENTORY_CACHE_FILE,
        str(safe_hours),
        max_stale_seconds=INVENTORY_CACHE_MAX_STALE_SECONDS,
    )
    if snapshot is not None:
        updated_ts, rows = snapshot
        _CACHE[safe_hours] = (updated_ts, _clone(rows))
        if time() - updated_ts > INVENTORY_CACHE_TTL_SECONDS:
            refresh_in_background(
                INVENTORY_CACHE_FILE,
                str(safe_hours),
                lambda: refresh_assets(safe_hours),
            )
        return _clone(rows[:safe_limit])

    return refresh_assets(safe_hours)[:safe_limit]


def fetch_cmdb_assets(limit: int = 200) -> list[dict[str, Any]]:
    rows = list(deps_module().fetch_cmdb_assets(limit=limit))
    return [row for row in rows if not is_non_operational_inventory_record(row)]


def save_cmdb_asset(**payload: Any) -> dict[str, Any]:
    return dict(deps_module().save_cmdb_asset(**payload))


def import_cmdb_assets(payload: str) -> dict[str, Any]:
    return dict(deps_module().import_cmdb_assets(payload))


def sync_observed_assets_to_cmdb(hours: int = 72, limit: int = 200) -> dict[str, Any]:
    return dict(deps_module().sync_observed_assets_to_cmdb(hours=hours, limit=limit))


def fetch_resource_overview() -> dict[str, Any]:
    return dict(deps_module().fetch_resource_overview())
