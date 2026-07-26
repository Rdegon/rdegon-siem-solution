from __future__ import annotations

from deploy.validate_assignment_batch_rules import validate_batch_rules


class _Client:
    def __init__(self) -> None:
        self.queries: list[str] = []

    def command(self, query: str) -> None:
        self.queries.append(query)
        if "BROKEN QUERY" in query:
            raise RuntimeError("syntax error")


def test_validate_batch_rules_renders_window_and_reports_rule_identity() -> None:
    client = _Client()
    failures = validate_batch_rules(
        client,
        {
            "batch_rules": [
                {
                    "id": 8001,
                    "source_id": "HB-001",
                    "window_s": 900,
                    "sql_template": "INSERT INTO t SELECT {WINDOW_S}",
                },
                {
                    "id": 8002,
                    "source_id": "HB-002",
                    "window_s": 300,
                    "sql_template": "BROKEN QUERY {WINDOW_S}",
                },
            ]
        },
    )

    assert "EXPLAIN SYNTAX INSERT INTO t SELECT 900" in client.queries
    assert failures[0]["rule_id"] == 8002
    assert failures[0]["source_id"] == "HB-002"
