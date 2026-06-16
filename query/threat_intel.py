from __future__ import annotations

from typing import Any

from .shared import deps_module


def fetch_threat_intel_overview(limit: int = 20, hours: int = 24, *, from_ts: str = "", to_ts: str = "") -> dict[str, Any]:
    return dict(deps_module().fetch_threat_intel_overview(limit=limit, hours=hours, from_ts=from_ts, to_ts=to_ts))


def fetch_threat_intel_entries(limit: int = 200) -> list[dict[str, Any]]:
    return list(deps_module().fetch_threat_intel_entries(limit=limit))


def save_threat_intel_indicator(*, indicator_type: str, indicator: str, provider: str, severity: str, confidence: int, description: str, tags: str) -> dict[str, Any]:
    return dict(
        deps_module().save_threat_intel_indicator(
            indicator_type=indicator_type,
            indicator=indicator,
            provider=provider,
            severity=severity,
            confidence=confidence,
            description=description,
            tags=tags,
        )
    )


def import_threat_intel_entries(payload: str) -> dict[str, Any]:
    return dict(deps_module().import_threat_intel_entries(payload))
