from __future__ import annotations

from typing import Any


def _deps():
    try:
        from . import deps as deps_module
    except ImportError:  # pragma: no cover - local test fallback
        import deps as deps_module  # type: ignore[no-redef]

    return deps_module


def fetch_source_inventory(limit: int = 200, hours: int = 24) -> list[dict[str, Any]]:
    return list(_deps()._fetch_source_inventory_raw(limit=limit, hours=hours))


def fetch_collector_inventory(hours: int = 24) -> list[dict[str, Any]]:
    return list(_deps()._fetch_collector_inventory_raw(hours=hours))


def fetch_resource_overview() -> dict[str, Any]:
    return dict(_deps()._fetch_resource_overview_raw())


def fetch_platform_status() -> dict[str, Any]:
    return dict(_deps()._fetch_platform_status_raw())


def fetch_transport_shadow_status() -> dict[str, Any]:
    return dict(_deps()._fetch_transport_shadow_status_raw())
