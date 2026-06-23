from __future__ import annotations

from typing import Any

try:
    from . import enterprise_control_plane as core
except ImportError:  # pragma: no cover - local test fallback
    import enterprise_control_plane as core  # type: ignore[no-redef]


def append_audit_event(*, actor: str, action: str, object_type: str, object_id: str, summary: str, details: dict[str, Any] | None = None) -> dict[str, Any]:
    return dict(
        core.append_audit_event(
            actor=actor,
            action=action,
            object_type=object_type,
            object_id=object_id,
            summary=summary,
            details=details,
        )
    )


def list_audit_events(*, object_type: str = "", actor: str = "", limit: int = 200) -> dict[str, Any]:
    return dict(core.list_audit_events(object_type=object_type, actor=actor, limit=limit))


def get_secret_inventory() -> dict[str, Any]:
    return dict(core.get_secret_inventory())
