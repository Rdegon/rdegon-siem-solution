from __future__ import annotations

import csv
import io
import json
import re
from typing import Any

from . import deps
from .control_plane_governance_runtime import append_audit_event


_ALLOWED_KINDS = {"watch", "allow", "deny"}
_ALLOWED_TYPES = {"ip", "domain", "hash", "user", "host", "process", "string", "raw"}
_LIST_NAME_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
_MAX_IMPORT_ROWS = 5_000


def _normalize_item(payload: dict[str, Any]) -> dict[str, Any]:
    list_name = str(payload.get("list_name") or payload.get("name") or "").strip()
    list_kind = str(payload.get("list_kind") or payload.get("kind") or "watch").strip().lower()
    item_type = str(payload.get("item_type") or payload.get("indicator_type") or payload.get("type") or "string").strip().lower()
    item_value = str(payload.get("item_value") or payload.get("indicator") or payload.get("value") or "").strip()
    item_label = str(payload.get("item_label") or payload.get("description") or payload.get("label") or "").strip()[:500]
    raw_tags = payload.get("tags") or []
    tags = [str(item).strip() for item in (raw_tags if isinstance(raw_tags, list) else str(raw_tags).split(",")) if str(item).strip()]
    if not _LIST_NAME_RE.fullmatch(list_name):
        raise ValueError("Active list name must contain only letters, numbers, dot, colon, underscore or dash")
    if list_kind not in _ALLOWED_KINDS:
        raise ValueError("Active list kind must be watch, allow or deny")
    if item_type not in _ALLOWED_TYPES:
        raise ValueError("Unsupported active list item type")
    if not item_value or len(item_value) > 2_048 or any(character in item_value for character in "\r\n\x00"):
        raise ValueError("Active list value is missing or invalid")
    return {
        "list_name": list_name,
        "list_kind": list_kind,
        "item_type": item_type,
        "item_value": item_value,
        "item_label": item_label,
        "tags": tags[:64],
        "enabled": bool(payload.get("enabled", True)),
    }


def _where(item: dict[str, Any]) -> str:
    quote = deps._sql_quote
    return (
        f"list_name = {quote(item['list_name'])} "
        f"AND list_kind = {quote(item['list_kind'])} "
        f"AND value_type = {quote(item['item_type'])} "
        f"AND value = {quote(item['item_value'])}"
    )


def _set_enabled(item: dict[str, Any], enabled: bool) -> None:
    deps.ensure_active_list_support()
    deps.get_ch_client().command(
        f"ALTER TABLE {deps.ACTIVE_LIST_TABLE} UPDATE enabled = {1 if enabled else 0} WHERE {_where(item)}",
        settings={"mutations_sync": 1},
    )


def list_active_items(*, list_name: str = "", limit: int = 1_000) -> list[dict[str, Any]]:
    safe_limit = max(1, min(int(limit or 1_000), 5_000))
    items = [dict(item) for item in deps.fetch_active_list_items(limit=5_000)]
    if list_name:
        items = [item for item in items if str(item.get("list_name") or "") == list_name]
    return items[:safe_limit]


def save_active_item(payload: dict[str, Any], *, actor: str) -> dict[str, Any]:
    item = _normalize_item(payload)
    saved = deps.save_active_list_item(
        list_name=item["list_name"],
        list_kind=item["list_kind"],
        item_type=item["item_type"],
        item_value=item["item_value"],
        item_label=item["item_label"],
        tags=",".join(item["tags"]),
    )
    if not item["enabled"]:
        _set_enabled(item, False)
    append_audit_event(
        actor=actor,
        action="active_list.item.saved",
        object_type="active_list_item",
        object_id=f"{item['list_name']}:{item['item_type']}:{item['item_value']}",
        summary=f"Saved item in active list {item['list_name']}",
        details={"list_kind": item["list_kind"], "item_type": item["item_type"], "enabled": item["enabled"]},
    )
    return {**dict(saved), "enabled": item["enabled"]}


def delete_active_item(payload: dict[str, Any], *, actor: str) -> dict[str, Any]:
    item = _normalize_item(payload)
    deps.ensure_active_list_support()
    deps.get_ch_client().command(
        f"ALTER TABLE {deps.ACTIVE_LIST_TABLE} DELETE WHERE {_where(item)}",
        settings={"mutations_sync": 1},
    )
    append_audit_event(
        actor=actor,
        action="active_list.item.deleted",
        object_type="active_list_item",
        object_id=f"{item['list_name']}:{item['item_type']}:{item['item_value']}",
        summary=f"Deleted item from active list {item['list_name']}",
        details={"list_kind": item["list_kind"], "item_type": item["item_type"]},
    )
    return {"status": "deleted", **item}


def set_active_item_enabled(payload: dict[str, Any], *, enabled: bool, actor: str) -> dict[str, Any]:
    item = _normalize_item(payload)
    _set_enabled(item, enabled)
    append_audit_event(
        actor=actor,
        action="active_list.item.enabled" if enabled else "active_list.item.disabled",
        object_type="active_list_item",
        object_id=f"{item['list_name']}:{item['item_type']}:{item['item_value']}",
        summary=f"{'Enabled' if enabled else 'Disabled'} item in active list {item['list_name']}",
        details={"list_kind": item["list_kind"], "item_type": item["item_type"]},
    )
    return {"status": "enabled" if enabled else "disabled", **item, "enabled": enabled}


def import_active_items(payload: dict[str, Any], *, actor: str) -> dict[str, Any]:
    raw_items = payload.get("items") or []
    if not isinstance(raw_items, list):
        raise ValueError("items must be an array")
    if not raw_items or len(raw_items) > _MAX_IMPORT_ROWS:
        raise ValueError(f"Active list import requires 1-{_MAX_IMPORT_ROWS} rows")
    normalized = [_normalize_item(dict(item or {})) for item in raw_items if isinstance(item, dict)]
    if len(normalized) != len(raw_items):
        raise ValueError("Every active list import row must be an object")
    unique: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for item in normalized:
        unique[(item["list_name"], item["list_kind"], item["item_type"], item["item_value"])] = item
    dry_run = bool(payload.get("dry_run", True))
    if dry_run:
        return {"status": "validated", "dry_run": True, "rows": len(unique), "duplicates_removed": len(normalized) - len(unique)}
    for item in unique.values():
        deps.save_active_list_item(
            list_name=item["list_name"],
            list_kind=item["list_kind"],
            item_type=item["item_type"],
            item_value=item["item_value"],
            item_label=item["item_label"],
            tags=",".join(item["tags"]),
        )
        if not item["enabled"]:
            _set_enabled(item, False)
    append_audit_event(
        actor=actor,
        action="active_list.imported",
        object_type="active_list",
        object_id="bulk-import",
        summary=f"Imported {len(unique)} active list items",
        details={"rows": len(unique), "duplicates_removed": len(normalized) - len(unique)},
    )
    return {"status": "imported", "dry_run": False, "rows": len(unique), "duplicates_removed": len(normalized) - len(unique)}


def export_active_items(*, list_name: str = "", output_format: str = "json") -> tuple[bytes, str, str]:
    items = list_active_items(list_name=list_name, limit=5_000)
    if output_format == "json":
        return json.dumps({"items": items}, ensure_ascii=False, indent=2).encode("utf-8"), "application/json", "active-lists.json"
    if output_format != "csv":
        raise ValueError("format must be json or csv")
    stream = io.StringIO(newline="")
    fieldnames = ["list_name", "list_kind", "item_type", "item_value", "item_label", "tags", "enabled", "updated_ts"]
    writer = csv.DictWriter(stream, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    for item in items:
        writer.writerow({**item, "tags": ",".join(item.get("tags") or [])})
    return stream.getvalue().encode("utf-8-sig"), "text/csv; charset=utf-8", "active-lists.csv"
