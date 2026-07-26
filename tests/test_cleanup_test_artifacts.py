from deploy.cleanup_test_artifacts import alert_test_predicate, asset_test_predicate, event_test_predicate


def test_event_cleanup_uses_explicit_markers_and_preserves_real_test_named_assets() -> None:
    predicate = event_test_predicate(["SIEM-E2E-"])

    assert "SIEM-E2E-" in predicate
    assert "eps-bench" in predicate
    assert "INTERVAL 7 DAY" in predicate
    assert "win-test" not in predicate
    assert "win-rtx-test" not in predicate


def test_asset_cleanup_does_not_use_generic_test_substring() -> None:
    predicate = asset_test_predicate(["SIEM-E2E-"])

    assert "SIEM-E2E-" in predicate
    assert "%test%" not in predicate
    assert "win-test" not in predicate


def test_alert_cleanup_scopes_runtime_fixtures_by_rule_entity_and_time() -> None:
    predicate = alert_test_predicate(
        ["SIEM-E2E-"],
        rule_ids=[8102, 8107],
        entities=["lab-edge-01", "9.9.9.9"],
        recent_hours=2,
    )

    assert "rule_id IN (8102,8107)" in predicate
    assert "'9.9.9.9','lab-edge-01'" in predicate
    assert "INTERVAL 2 HOUR" in predicate


def test_alert_cleanup_supports_aggregate_table_columns() -> None:
    predicate = alert_test_predicate(
        ["SIEM-E2E-"],
        rule_ids=[],
        entities=[],
        recent_hours=2,
        text_fields=("rule_name", "entity_key", "group_key_json", "samples_json"),
    )

    assert "group_key_json" in predicate
    assert "samples_json" in predicate
    assert "context_json" not in predicate
    assert "toString(source)" not in predicate
