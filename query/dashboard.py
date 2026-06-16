from __future__ import annotations

from typing import Any

from .shared import deps_module


def fetch_dashboard_snapshot(*, window: str = "24h", from_ts: str = "", to_ts: str = "", bucket_minutes: int = 60, recent_limit: int = 10) -> dict[str, Any]:
    return dict(
        deps_module().fetch_dashboard_snapshot(
            window=window,
            from_ts=from_ts,
            to_ts=to_ts,
            bucket_minutes=bucket_minutes,
            recent_limit=recent_limit,
        )
    )


def fetch_platform_status() -> dict[str, Any]:
    return dict(deps_module().fetch_platform_status())


def list_dashboards() -> list[dict[str, Any]]:
    return list(deps_module().list_dashboards())


def describe_dashboard_widgets() -> list[dict[str, Any]]:
    return list(deps_module().describe_dashboard_widgets())


def save_dashboard_definition(*, dashboard_id: str = "", title: str, description: str = "", widgets: list[str] | None = None, layout: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    return dict(
        deps_module().save_dashboard_definition(
            dashboard_id=dashboard_id,
            title=title,
            description=description,
            widgets=widgets or [],
            layout=layout or [],
        )
    )


def delete_dashboard_definition(dashboard_id: str) -> None:
    deps_module().delete_dashboard_definition(dashboard_id)
