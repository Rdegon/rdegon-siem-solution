from __future__ import annotations

import json
import math
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .content_store import (
    content_store_backend,
    get_content_document,
    upsert_content_document,
)
from .control_plane_governance_runtime import append_audit_event


COLLECTION_NAME = "topology_layouts"
ALLOWED_SEGMENTS = {
    "external",
    "mgmt",
    "sec",
    "servers-games",
    "lab",
    "users",
    "legacy",
    "unassigned",
}


def _now_iso() -> str:
    return (
        datetime.now(tz=timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _workspace_id(value: Any) -> str:
    workspace = str(value or "network").strip().lower()
    if not workspace or len(workspace) > 80:
        raise ValueError("A valid topology workspace id is required")
    if not all(character.isalnum() or character in {"-", "_"} for character in workspace):
        raise ValueError("Topology workspace id contains unsupported characters")
    return workspace


def _layout_path(workspace: str) -> Path:
    root = Path(
        os.getenv(
            "SIEM_TOPOLOGY_LAYOUT_DIR",
            "/var/lib/siem-web/topology-layouts",
        )
    )
    return root / f"{workspace}.json"


def _sanitize_positions(value: Any) -> dict[str, dict[str, Any]]:
    rows = value if isinstance(value, dict) else {}
    if len(rows) > 600:
        raise ValueError("Topology layout cannot contain more than 600 nodes")
    result: dict[str, dict[str, Any]] = {}
    for raw_node_id, raw_position in rows.items():
        node_id = str(raw_node_id or "").strip()
        if not node_id or len(node_id) > 240 or not isinstance(raw_position, dict):
            continue
        try:
            x = float(raw_position.get("x"))
            y = float(raw_position.get("y"))
        except (TypeError, ValueError):
            continue
        if not math.isfinite(x) or not math.isfinite(y):
            continue
        if abs(x) > 100_000 or abs(y) > 100_000:
            continue
        segment = str(raw_position.get("segment") or "unassigned").strip().lower()
        if segment not in ALLOWED_SEGMENTS:
            segment = "unassigned"
        result[node_id] = {
            "x": round(x, 2),
            "y": round(y, 2),
            "segment": segment,
        }
    return result


def _read_file(workspace: str) -> dict[str, Any] | None:
    path = _layout_path(workspace)
    if not path.is_file():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return None
    return dict(payload) if isinstance(payload, dict) else None


def get_topology_layout(workspace: str = "network") -> dict[str, Any]:
    safe_workspace = _workspace_id(workspace)
    payload = get_content_document(COLLECTION_NAME, safe_workspace)
    if not isinstance(payload, dict):
        payload = _read_file(safe_workspace) or {}
    return {
        "workspace": safe_workspace,
        "version": int(payload.get("version") or 1),
        "positions": _sanitize_positions(payload.get("positions")),
        "updated_at": str(payload.get("updated_at") or ""),
        "updated_by": str(payload.get("updated_by") or ""),
        "storage_backend": content_store_backend(),
    }


def save_topology_layout(
    payload: dict[str, Any],
    *,
    actor: str,
) -> dict[str, Any]:
    workspace = _workspace_id(payload.get("workspace"))
    positions = _sanitize_positions(payload.get("positions"))
    document = {
        "workspace": workspace,
        "version": 1,
        "positions": positions,
        "updated_at": _now_iso(),
        "updated_by": str(actor or "web")[:120],
    }
    stored_in_content = upsert_content_document(
        COLLECTION_NAME,
        workspace,
        document,
    )
    file_error = ""
    try:
        path = _layout_path(workspace)
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(".json.tmp")
        temporary.write_text(
            json.dumps(document, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        temporary.replace(path)
    except Exception as exc:  # noqa: BLE001
        file_error = f"{type(exc).__name__}: {exc}"
    if not stored_in_content and file_error:
        raise RuntimeError(
            f"Topology layout storage is unavailable: {file_error[:300]}"
        )
    result = {
        **document,
        "node_count": len(positions),
        "storage_backend": (
            content_store_backend() if stored_in_content else "filesystem"
        ),
    }
    append_audit_event(
        actor=str(actor or "web"),
        action="topology.layout.saved",
        object_type="topology_layout",
        object_id=workspace,
        summary=f"Saved topology layout with {len(positions)} nodes",
        details={
            "node_count": len(positions),
            "storage_backend": result["storage_backend"],
        },
    )
    return result
