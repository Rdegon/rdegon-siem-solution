from __future__ import annotations

from typing import Any

try:
    from . import enterprise_control_plane as core
except ImportError:  # pragma: no cover - local test fallback
    import enterprise_control_plane as core  # type: ignore[no-redef]

try:
    from .control_plane_governance_runtime import append_audit_event
except ImportError:  # pragma: no cover - local test fallback
    from control_plane_governance_runtime import append_audit_event  # type: ignore[no-redef]


BINDING_OVERRIDES_COLLECTION = "asset_binding_overrides"
_collection = core._collection
_find_by_id = core._find_by_id
_json_clone = core._json_clone
_new_id = core._new_id
_now_iso = core._now_iso
_save_collection = core._save_collection


def _default_binding_overrides() -> list[dict[str, Any]]:
    return []


def _string(value: Any) -> str:
    return str(value or "").strip()


def _string_list(value: Any) -> list[str]:
    if isinstance(value, str):
        raw = value.split(",")
    elif isinstance(value, (list, tuple, set)):
        raw = list(value)
    else:
        raw = []
    items: list[str] = []
    seen: set[str] = set()
    for item in raw:
        text = _string(item)
        if not text:
            continue
        key = text.lower()
        if key in seen:
            continue
        seen.add(key)
        items.append(text)
    return items


def _normalize_override(payload: dict[str, Any], *, existing: dict[str, Any] | None = None, actor: str) -> dict[str, Any]:
    current = dict(existing or {})
    override_id = _string(payload.get("id") or current.get("id") or _new_id("bind"))
    aliases = _string_list(payload.get("aliases") if "aliases" in payload else current.get("aliases"))
    enabled = bool(payload.get("enabled")) if "enabled" in payload else bool(current.get("enabled", True))
    target = _string(payload.get("target") if "target" in payload else current.get("target"))
    if not target and aliases:
        target = aliases[0]
    asset_id = _string(payload.get("asset_id") if "asset_id" in payload else current.get("asset_id"))
    hostname = _string(payload.get("hostname") if "hostname" in payload else current.get("hostname"))
    ip_value = _string(payload.get("ip") if "ip" in payload else current.get("ip"))
    scope = _string(payload.get("scope") if "scope" in payload else current.get("scope") or "all").lower() or "all"
    note = _string(payload.get("note") if "note" in payload else current.get("note"))
    if not any((target, asset_id, hostname, ip_value, aliases)):
        raise ValueError("binding override requires target, aliases, asset_id, hostname, or ip")
    row = {
        **current,
        "id": override_id,
        "target": target,
        "aliases": aliases,
        "asset_id": asset_id,
        "hostname": hostname,
        "ip": ip_value,
        "scope": scope,
        "note": note,
        "enabled": enabled,
        "updated_ts": _now_iso(),
        "updated_by": actor,
    }
    if not current:
        row["created_ts"] = row["updated_ts"]
        row["created_by"] = actor
    return row


def list_binding_overrides(*, scope: str = "", include_disabled: bool = True, limit: int = 500) -> list[dict[str, Any]]:
    rows = _collection(BINDING_OVERRIDES_COLLECTION, _default_binding_overrides)
    safe_scope = _string(scope).lower()
    filtered: list[dict[str, Any]] = []
    for item in rows:
        item_scope = _string(item.get("scope") or "all").lower() or "all"
        if safe_scope and item_scope not in {"all", safe_scope}:
            continue
        if not include_disabled and not bool(item.get("enabled", True)):
            continue
        filtered.append(_json_clone(item))
    filtered.sort(key=lambda item: (_string(item.get("target") or item.get("asset_id")).lower(), _string(item.get("updated_ts"))))
    return filtered[: max(1, min(limit, 2000))]


def get_binding_override(override_id: str) -> dict[str, Any] | None:
    return _find_by_id(_collection(BINDING_OVERRIDES_COLLECTION, _default_binding_overrides), override_id)


def save_binding_override(payload: dict[str, Any], *, actor: str = "system") -> dict[str, Any]:
    rows = _collection(BINDING_OVERRIDES_COLLECTION, _default_binding_overrides)
    existing = get_binding_override(_string(payload.get("id")))
    row = _normalize_override(dict(payload or {}), existing=existing, actor=actor)
    if existing:
        rows = [row if _string(item.get("id")) == row["id"] else item for item in rows]
        action = "asset_binding_override.updated"
        summary = f"Updated binding override {row['id']}"
    else:
        rows.insert(0, row)
        action = "asset_binding_override.created"
        summary = f"Created binding override {row['id']}"
    _save_collection(BINDING_OVERRIDES_COLLECTION, rows)
    append_audit_event(
        actor=actor,
        action=action,
        object_type="asset_binding_override",
        object_id=row["id"],
        summary=summary,
        details={"target": row.get("target"), "asset_id": row.get("asset_id"), "scope": row.get("scope"), "enabled": row.get("enabled")},
    )
    return _json_clone(row)


def update_binding_override(override_id: str, payload: dict[str, Any], *, actor: str = "system") -> dict[str, Any]:
    merged = dict(payload or {})
    merged["id"] = override_id
    return save_binding_override(merged, actor=actor)


def delete_binding_override(override_id: str, *, actor: str = "system") -> dict[str, Any]:
    rows = _collection(BINDING_OVERRIDES_COLLECTION, _default_binding_overrides)
    item = _find_by_id(rows, override_id)
    if item is None:
        raise ValueError(f"Binding override not found: {override_id}")
    rows = [row for row in rows if _string(row.get("id")) != _string(override_id)]
    _save_collection(BINDING_OVERRIDES_COLLECTION, rows)
    append_audit_event(
        actor=actor,
        action="asset_binding_override.deleted",
        object_type="asset_binding_override",
        object_id=_string(override_id),
        summary=f"Deleted binding override {override_id}",
        details={"target": item.get("target"), "asset_id": item.get("asset_id"), "scope": item.get("scope")},
    )
    return _json_clone(item)
