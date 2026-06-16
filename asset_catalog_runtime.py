from __future__ import annotations

from typing import Any


def _parse_hours(window: str) -> int:
    text = str(window or "24h").strip().lower()
    if not text:
        return 24
    multiplier = 1
    if text.endswith("d"):
        multiplier = 24
        text = text[:-1]
    elif text.endswith("h"):
        text = text[:-1]
    try:
        return max(1, int(text) * multiplier)
    except ValueError:
        return 24


def _deps():
    try:
        from .query import assets as assets_queries
        from .query import geo as geo_queries
        from .query import sources as source_queries
        from .query import threat_intel as threat_intel_queries
        from .query import vuln as vuln_queries
    except ImportError:  # pragma: no cover - local test fallback
        from query import assets as assets_queries  # type: ignore[no-redef]
        from query import geo as geo_queries  # type: ignore[no-redef]
        from query import sources as source_queries  # type: ignore[no-redef]
        from query import threat_intel as threat_intel_queries  # type: ignore[no-redef]
        from query import vuln as vuln_queries  # type: ignore[no-redef]

    class DepsFacade:
        fetch_active_list_items = staticmethod(assets_queries.fetch_active_list_items)
        fetch_asset_categories = staticmethod(assets_queries.fetch_asset_categories)
        fetch_assets = staticmethod(assets_queries.fetch_assets)
        fetch_cmdb_assets = staticmethod(assets_queries.fetch_cmdb_assets)
        fetch_collector_inventory = staticmethod(source_queries.fetch_collector_inventory)
        fetch_detection_rules = staticmethod(vuln_queries.fetch_detection_rules)
        fetch_geo_country_detail = staticmethod(geo_queries.fetch_geo_country_detail)
        fetch_geo_ip_detail = staticmethod(geo_queries.fetch_geo_ip_detail)
        fetch_geo_source_activity = staticmethod(geo_queries.fetch_geo_source_activity)
        fetch_geo_vpn_destinations = staticmethod(geo_queries.fetch_geo_vpn_destinations)
        fetch_normalizer_rules = staticmethod(vuln_queries.fetch_normalizer_rules)
        fetch_resource_overview = staticmethod(assets_queries.fetch_resource_overview)
        fetch_source_inventory = staticmethod(source_queries.fetch_source_inventory)
        fetch_threat_intel_entries = staticmethod(threat_intel_queries.fetch_threat_intel_entries)
        fetch_threat_intel_overview = staticmethod(threat_intel_queries.fetch_threat_intel_overview)
        fetch_top_sources = staticmethod(source_queries.fetch_top_sources)
        import_cmdb_assets = staticmethod(assets_queries.import_cmdb_assets)
        import_threat_intel_entries = staticmethod(threat_intel_queries.import_threat_intel_entries)
        save_active_list_item = staticmethod(assets_queries.save_active_list_item)
        save_cmdb_asset = staticmethod(assets_queries.save_cmdb_asset)
        save_normalizer_rule = staticmethod(vuln_queries.save_normalizer_rule)
        save_sigma_rule = staticmethod(vuln_queries.save_sigma_rule)
        save_threat_intel_indicator = staticmethod(threat_intel_queries.save_threat_intel_indicator)
        sync_observed_assets_to_cmdb = staticmethod(assets_queries.sync_observed_assets_to_cmdb)
        test_detection_rule = staticmethod(vuln_queries.test_detection_rule)
        archive_events_to_cold = staticmethod(lambda older_than_hours: __import__(__name__.replace("asset_catalog_runtime", "deps"), fromlist=["archive_events_to_cold"]).archive_events_to_cold(older_than_hours))

    return DepsFacade


def _runtime_docs():
    try:
        from . import deps_runtime_docs_ops as runtime_docs_module
    except ImportError:  # pragma: no cover - local test fallback
        import deps_runtime_docs_ops as runtime_docs_module  # type: ignore[no-redef]

    return runtime_docs_module


def fetch_active_list_items(limit: int = 200) -> list[dict[str, Any]]:
    return list(_deps().fetch_active_list_items(limit=limit))


def fetch_asset_categories() -> list[dict[str, Any]]:
    return list(_deps().fetch_asset_categories())


def fetch_assets(limit: int = 50, hours: int = 24) -> list[dict[str, Any]]:
    return list(_deps().fetch_assets(limit=limit, hours=hours))


def fetch_cmdb_assets(limit: int = 200) -> list[dict[str, Any]]:
    return list(_deps().fetch_cmdb_assets(limit=limit))


def fetch_collector_inventory(hours: int = 24) -> list[dict[str, Any]]:
    return list(_deps().fetch_collector_inventory(hours=hours))


def fetch_detection_rules(limit: int = 100) -> list[dict[str, Any]]:
    return list(_deps().fetch_detection_rules(limit=limit))


def fetch_geo_country_detail(country: str, hours: int = 24, limit: int = 60, kind: str = "source") -> dict[str, Any]:
    return dict(_deps().fetch_geo_country_detail(country=country, hours=hours, limit=limit, kind=kind))


def fetch_geo_ip_detail(ip_text: str, hours: int = 72) -> dict[str, Any]:
    return dict(_deps().fetch_geo_ip_detail(ip_text=ip_text, hours=hours))


def fetch_geo_source_activity(hours: int = 24, limit: int = 20, *, from_ts: str = "", to_ts: str = "") -> dict[str, Any]:
    return dict(_deps().fetch_geo_source_activity(hours=hours, limit=limit, from_ts=from_ts, to_ts=to_ts))


def fetch_geo_vpn_destinations(hours: int = 24, limit: int = 20, *, from_ts: str = "", to_ts: str = "") -> dict[str, Any]:
    return dict(_deps().fetch_geo_vpn_destinations(hours=hours, limit=limit, from_ts=from_ts, to_ts=to_ts))


def fetch_normalizer_rules(limit: int = 100) -> list[dict[str, Any]]:
    return list(_deps().fetch_normalizer_rules(limit=limit))


def fetch_resource_overview() -> dict[str, Any]:
    return dict(_deps().fetch_resource_overview())


def fetch_source_inventory(limit: int = 200, hours: int = 24) -> list[dict[str, Any]]:
    return list(_deps().fetch_source_inventory(limit=limit, hours=hours))


def fetch_threat_intel_entries(limit: int = 200) -> list[dict[str, Any]]:
    return list(_deps().fetch_threat_intel_entries(limit=limit))


def fetch_threat_intel_overview(limit: int = 20, hours: int = 24, *, from_ts: str = "", to_ts: str = "") -> dict[str, Any]:
    return dict(_deps().fetch_threat_intel_overview(limit=limit, hours=hours, from_ts=from_ts, to_ts=to_ts))


def fetch_top_sources(
    limit: int = 20,
    window: str = "24h",
    *,
    hours: int | None = None,
    from_ts: str = "",
    to_ts: str = "",
) -> list[dict[str, Any]]:
    effective_hours = max(1, int(hours)) if hours is not None else _parse_hours(window)
    return list(_deps().fetch_top_sources(limit=limit, hours=effective_hours, from_ts=from_ts, to_ts=to_ts))


def import_cmdb_assets(payload: str) -> dict[str, Any]:
    return dict(_deps().import_cmdb_assets(payload))


def import_threat_intel_entries(payload: str) -> dict[str, Any]:
    return dict(_deps().import_threat_intel_entries(payload))


def list_builder_drafts() -> list[dict[str, Any]]:
    return list(_runtime_docs().list_builder_drafts())


def publish_builder_draft(draft_id: str) -> dict[str, Any]:
    return dict(_runtime_docs().publish_builder_draft(draft_id))


def save_active_list_item(
    *,
    list_name: str,
    list_kind: str,
    item_type: str,
    item_value: str,
    item_label: str,
    tags: str,
) -> dict[str, Any]:
    return dict(
        _deps().save_active_list_item(
            list_name=list_name,
            list_kind=list_kind,
            item_type=item_type,
            item_value=item_value,
            item_label=item_label,
            tags=tags,
        )
    )


def save_builder_draft(
    title: str,
    description: str,
    kind: str,
    blocks: list[dict[str, Any]],
    draft_id: str = "",
    status: str = "draft",
) -> dict[str, Any]:
    return dict(
        _runtime_docs().save_builder_draft(
            title=title,
            description=description,
            kind=kind,
            blocks=blocks,
            draft_id=draft_id,
            status=status,
        )
    )


def save_cmdb_asset(**payload: Any) -> dict[str, Any]:
    return dict(_deps().save_cmdb_asset(**payload))


def save_normalizer_rule(
    *,
    rule_id: int | None,
    priority: int,
    source_type: str,
    event_matcher: str,
    uem_mapping: dict[str, Any],
    enabled: bool,
) -> dict[str, Any]:
    return dict(
        _deps().save_normalizer_rule(
            rule_id=rule_id,
            priority=priority,
            source_type=source_type,
            event_matcher=event_matcher,
            uem_mapping=uem_mapping,
            enabled=enabled,
        )
    )


def save_sigma_rule(
    sigma_yaml: str,
    *,
    threshold: int,
    window_s: int,
    entity_field: str,
    author: str = "web",
) -> dict[str, Any]:
    return dict(
        _deps().save_sigma_rule(
            sigma_yaml,
            threshold=threshold,
            window_s=window_s,
            entity_field=entity_field,
            author=author,
        )
    )


def save_threat_intel_indicator(
    *,
    indicator_type: str,
    indicator: str,
    provider: str,
    severity: str,
    confidence: int,
    description: str,
    tags: str,
) -> dict[str, Any]:
    return dict(
        _deps().save_threat_intel_indicator(
            indicator_type=indicator_type,
            indicator=indicator,
            provider=provider,
            severity=severity,
            confidence=confidence,
            description=description,
            tags=tags,
        )
    )


def sync_observed_assets_to_cmdb(hours: int = 72, limit: int = 200) -> dict[str, Any]:
    return dict(_deps().sync_observed_assets_to_cmdb(hours=hours, limit=limit))


def test_builder_draft_payload(title: str, description: str, kind: str, blocks: list[dict[str, Any]]) -> dict[str, Any]:
    return dict(_runtime_docs().test_builder_draft_payload(title, description, kind, blocks))


def test_detection_rule(rule_id: int) -> dict[str, Any]:
    return dict(_deps().test_detection_rule(rule_id))


def validate_builder_draft_payload(title: str, description: str, kind: str, blocks: list[dict[str, Any]]) -> dict[str, Any]:
    return dict(_runtime_docs().validate_builder_draft_payload(title, description, kind, blocks))


def archive_events_to_cold(older_than_hours: int) -> dict[str, Any]:
    return dict(_deps().archive_events_to_cold(older_than_hours))
