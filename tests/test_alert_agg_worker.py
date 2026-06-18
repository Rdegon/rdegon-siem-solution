from __future__ import annotations

from services.alert_agg.worker import AGG_INSERT_SQL, AlertAggWorker


def test_alert_aggregation_only_materializes_open_raw_alerts() -> None:
    assert "FROM siem.alerts_raw AS raw_alert" in AGG_INSERT_SQL
    assert "WHERE lower(raw_alert.status) = 'open'" in AGG_INSERT_SQL
    assert "WHERE lower(status) = 'open'" not in AGG_INSERT_SQL
    assert "if(max(status) = 'open', 'open', 'closed')" not in AGG_INSERT_SQL


def test_alert_aggregation_uses_sync_truncate_before_rebuild() -> None:
    class FakeClient:
        def __init__(self) -> None:
            self.queries: list[str] = []

        def execute(self, query: str):
            self.queries.append(query)
            if query == "SELECT count() FROM siem.alerts_agg":
                return [(0,)]
            return []

    worker = AlertAggWorker.__new__(AlertAggWorker)
    worker._client = FakeClient()

    assert worker._run_aggregation() == 0
    assert worker._client.queries[0] == "TRUNCATE TABLE siem.alerts_agg SYNC"
