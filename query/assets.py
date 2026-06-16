from __future__ import annotations

from typing import Any

from .shared import deps_module, is_non_operational_inventory_record


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


def fetch_assets(limit: int = 50, hours: int = 24) -> list[dict[str, Any]]:
    rows = list(deps_module().fetch_assets(limit=limit, hours=hours))
    return [row for row in rows if not is_non_operational_inventory_record(row)]


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
