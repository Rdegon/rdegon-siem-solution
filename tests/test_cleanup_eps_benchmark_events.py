from __future__ import annotations

from datetime import datetime, timezone

from deploy import cleanup_eps_benchmark_events as cleanup


def test_event_cleanup_keeps_run_id_time_scope() -> None:
    scope = cleanup.CleanupScope(
        run_ids=["collector-eps-test"],
        started_at=datetime(2026, 6, 17, 10, 0, tzinfo=timezone.utc),
        finished_at=datetime(2026, 6, 17, 11, 0, tzinfo=timezone.utc),
    )

    where, uses_time_scope, uses_all_time_alert_scope = cleanup._build_cleanup_where(
        {"ts", "message", "tags"},
        search_columns=cleanup.EVENT_SEARCH_COLUMNS,
        scope=scope,
        include_eps_bench_alerts=False,
        table="siem.events",
    )

    assert uses_time_scope is True
    assert uses_all_time_alert_scope is False
    assert "collector-eps-test" in where
    assert "toDateTime('2026-06-17 10:00:00')" in where


def test_alert_cleanup_uses_all_time_scope_for_explicit_benchmark_alerts() -> None:
    scope = cleanup.CleanupScope(
        run_ids=[],
        started_at=datetime(2026, 6, 17, 10, 0, tzinfo=timezone.utc),
        finished_at=datetime(2026, 6, 17, 11, 0, tzinfo=timezone.utc),
    )

    where, uses_time_scope, uses_all_time_alert_scope = cleanup._build_cleanup_where(
        {"ts", "entity_key", "group_key_json", "samples_json"},
        search_columns=cleanup.ALERT_SEARCH_COLUMNS,
        scope=scope,
        include_eps_bench_alerts=True,
        table="siem.alerts_agg",
    )

    assert uses_time_scope is False
    assert uses_all_time_alert_scope is True
    assert "eps-bench" in where
    assert "allowlist:benchmark" in where
    assert "toDateTime(" not in where
