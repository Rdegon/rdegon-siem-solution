from __future__ import annotations

from tools.full_rule_audit import build_audit, render_markdown


def test_full_rule_audit_assigns_decision_to_every_pack_rule() -> None:
    audit = build_audit(30, live=False)

    assert audit["summary"]["total_rules"] > 250
    assert audit["summary"]["all_rules_have_decision"] is True
    assert len(audit["rules"]) == audit["summary"]["total_rules"]
    assert {item["decision"] for item in audit["rules"]}
    assert audit["runtime_inventory"] == {}
    assert audit["source_coverage"] == []


def test_full_rule_audit_marks_known_noisy_families_for_calibration() -> None:
    audit = build_audit(30, live=False)
    by_id = {int(item["rule_id"]): item for item in audit["rules"]}

    assert by_id[2618]["decision"] in {"tune_threshold", "tune_window", "add_allowlist", "deduplicate"}
    assert by_id[2701]["decision"] in {"tune_threshold", "tune_window", "add_allowlist", "deduplicate"}
    assert by_id[2708]["decision"] in {"tune_threshold", "tune_window", "add_allowlist", "deduplicate"}


def test_full_rule_audit_markdown_contains_summary_and_rule_rows() -> None:
    audit = build_audit(30, live=False)
    markdown = render_markdown(audit)

    assert "# Full Rule Audit" in markdown
    assert "All rules have decision: True" in markdown
    assert "| rule_id | source_id | layer | severity | cost | alerts | fp | open | decision | title |" in markdown
