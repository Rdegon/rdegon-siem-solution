from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def _utc_now_iso() -> str:
    return datetime.now(tz=timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def build_tenant_scope() -> dict[str, Any]:
    """Return only tenant scopes backed by the current production data model."""
    from . import deps

    issues: list[str] = []
    source_count = 0
    incident_count = 0
    try:
        source_count = len(deps.fetch_source_inventory(limit=1000, hours=24))
    except Exception as exc:  # noqa: BLE001
        issues.append(f"sources:{type(exc).__name__}")
    try:
        incident_count = int(deps.fetch_alert_metrics().get("agg_open") or 0)
    except Exception as exc:  # noqa: BLE001
        issues.append(f"incidents:{type(exc).__name__}")
    return {
        "available": [
            {
                "id": "main",
                "name": "Main",
                "description": "Production SOC data and security services",
                "source_count": source_count,
                "incident_count": incident_count,
            }
        ],
        "default": ["main"],
        "generated_ts": _utc_now_iso(),
        "issues": issues,
    }


def validate_tenant_scope_header(value: str) -> list[str]:
    selected = [item.strip() for item in str(value or "").split(",") if item.strip()]
    if not selected:
        return ["main"]
    invalid = sorted(set(selected) - {"main"})
    if invalid:
        raise ValueError(f"Tenant scope is not available: {', '.join(invalid)}")
    return ["main"]
