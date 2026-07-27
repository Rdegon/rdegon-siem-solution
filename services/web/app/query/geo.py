from __future__ import annotations

from typing import Any

from .shared import deps_module


def fetch_geo_ip_detail(ip_text: str, hours: int = 72) -> dict[str, Any]:
    return dict(deps_module().fetch_geo_ip_detail(ip_text=ip_text, hours=hours))


def fetch_geo_source_activity(hours: int = 24, limit: int = 20, *, from_ts: str = "", to_ts: str = "") -> dict[str, Any]:
    return dict(deps_module().fetch_geo_source_activity(hours=hours, limit=limit, from_ts=from_ts, to_ts=to_ts))


def fetch_geo_vpn_destinations(hours: int = 24, limit: int = 20, *, from_ts: str = "", to_ts: str = "") -> dict[str, Any]:
    return dict(deps_module().fetch_geo_vpn_destinations(hours=hours, limit=limit, from_ts=from_ts, to_ts=to_ts))


def fetch_geo_country_detail(country: str, hours: int = 24, limit: int = 60, kind: str = "source") -> dict[str, Any]:
    return dict(deps_module().fetch_geo_country_detail(country=country, hours=hours, limit=limit, kind=kind))
