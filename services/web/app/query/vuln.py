from __future__ import annotations

from typing import Any

from .shared import deps_module


def fetch_vulnerability_reports(limit: int = 100, days: int = 14) -> list[dict[str, Any]]:
    return list(deps_module().fetch_vulnerability_reports(limit=limit, days=days))


def fetch_vulnerability_inventory(days: int = 30, limit: int = 25) -> dict[str, Any]:
    return dict(deps_module().fetch_vulnerability_inventory(days=days, limit=limit))


def fetch_vulnerability_findings(*args: Any, **kwargs: Any) -> Any:
    return deps_module().fetch_vulnerability_findings(*args, **kwargs)


def fetch_detection_rules(limit: int = 100) -> list[dict[str, Any]]:
    return list(deps_module().fetch_detection_rules(limit=limit))


def save_sigma_rule(sigma_yaml: str, *, threshold: int, window_s: int, entity_field: str, author: str = "web") -> dict[str, Any]:
    return dict(
        deps_module().save_sigma_rule(
            sigma_yaml,
            threshold=threshold,
            window_s=window_s,
            entity_field=entity_field,
            author=author,
        )
    )


def test_detection_rule(rule_id: int) -> dict[str, Any]:
    return dict(deps_module().test_detection_rule(rule_id))


def fetch_normalizer_rules(limit: int = 100) -> list[dict[str, Any]]:
    return list(deps_module().fetch_normalizer_rules(limit=limit))


def save_normalizer_rule(*, rule_id: int | None, priority: int, source_type: str, event_matcher: str, uem_mapping: dict[str, Any], enabled: bool) -> dict[str, Any]:
    return dict(
        deps_module().save_normalizer_rule(
            rule_id=rule_id,
            priority=priority,
            source_type=source_type,
            event_matcher=event_matcher,
            uem_mapping=uem_mapping,
            enabled=enabled,
        )
    )
