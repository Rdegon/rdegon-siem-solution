from __future__ import annotations

import inspect
import os
from datetime import datetime, timezone

import pytest

os.environ.setdefault("SIEM_CH_HOST", "127.0.0.1")
os.environ.setdefault("SIEM_CH_USER", "test")
os.environ.setdefault("SIEM_CH_PASSWORD", "test")
os.environ.setdefault("SIEM_ADMIN_DEFAULT_PASSWORD", "test-password")
os.environ.setdefault("SIEM_JWT_SECRET", "test-jwt-secret")

from services.web.app import event_hunting_runtime as runtime
from services.web.app.routes import console_event_hunting_routes as routes
from services.web.app.routes import console_router_registry


class _Result:
    def __init__(self, rows):
        self.rows = rows

    def named_results(self):
        return iter(self.rows)


class _FakeClickHouse:
    def __init__(self, event_rows=None):
        self.event_rows = list(event_rows or [])
        self.queries: list[tuple[str, dict]] = []
        self.commands: list[str] = []
        self.saved: dict[tuple[str, str, str], dict] = {}

    def command(self, sql: str, **_kwargs):
        self.commands.append(sql)

    def query(self, sql: str, parameters=None, **_kwargs):
        params = dict(parameters or {})
        self.queries.append((sql, params))
        if "FROM system.tables" in sql:
            return _Result([{"database": "siem", "name": "events"}])
        if runtime.SAVED_SEARCH_TABLE in sql:
            tenant = params.get("tenant_id")
            owner = params.get("owner")
            rows = [
                value
                for (row_tenant, row_owner, _), value in self.saved.items()
                if row_tenant == tenant and row_owner == owner and not value["deleted"]
            ]
            return _Result(rows)
        if "count() AS total" in sql:
            return _Result([{"total": len(self.event_rows)}])
        if "ARRAY JOIN" in sql:
            return _Result([{"facet_name": facet, "value": "linux", "count": 4} for facet in runtime._FACETS])
        if "FROM siem.events" in sql:
            return _Result(self.event_rows)
        raise AssertionError(sql)

    def insert(self, table: str, rows, column_names):
        assert table == runtime.SAVED_SEARCH_TABLE
        record = dict(zip(column_names, rows[0], strict=True))
        key = (record["tenant_id"], record["owner"], record["search_id"])
        self.saved[key] = {
            "search_id": record["search_id"],
            "name": record["name"],
            "description": record["description"],
            "specification_json": record["specification_json"],
            "deleted": record["deleted"],
            "revision": record["revision"],
            "updated_at": record["updated_at"],
        }


def _event(index: int) -> dict:
    return {
        "ts": datetime(2026, 8, 3, 12, 0, index, tzinfo=timezone.utc),
        "stable_id": f"event-{index}",
        "event_id": f"event-{index}",
        "source_type": "linux",
        "source": "pilot-web-01",
        "log_source": "pilot-web-01",
        "collector_profile": "linux-rsyslog",
        "category": "authentication",
        "severity": "high",
        "host": "pilot-web-01",
        "message": "Failed SSH login",
    }


def _payload(**overrides):
    return {
        "source": "hot",
        "from_ts": "2026-08-02T00:00:00Z",
        "to_ts": "2026-08-02T23:59:00Z",
        "limit": 2,
        **overrides,
    }


def test_structured_and_expert_queries_are_parameterized() -> None:
    client = _FakeClickHouse([_event(1)])
    attack = "x' OR 1=1 --"
    result = runtime.query_events(
        _payload(
            filters=[{"field": "severity", "operator": "in", "values": ["high", "critical"]}],
            expert_query=f'message:"{attack}" AND source:pilot-web-01',
        ),
        tenant_id="main",
        client=client,
    )

    sql, parameters = next((sql, params) for sql, params in client.queries if "ORDER BY ts DESC" in sql)
    assert attack not in sql
    assert attack in parameters.values()
    assert "siem.events" in sql
    assert result["rows"][0]["event_id"] == "event-1"


def test_cursor_is_stable_and_offset_cannot_be_mixed() -> None:
    client = _FakeClickHouse([_event(3), _event(2), _event(1)])
    first = runtime.query_events(_payload(), tenant_id="main", client=client)
    assert first["has_more"] is True
    assert first["next_cursor"]

    second = runtime.query_events(
        _payload(cursor=first["next_cursor"], pagination="cursor"),
        tenant_id="main",
        client=client,
    )
    page_sql = [sql for sql, _ in client.queries if "ORDER BY ts DESC" in sql][-1]
    assert "stable_id DESC" in page_sql
    assert "ts <" in page_sql
    assert second["pagination"] == "cursor"

    with pytest.raises(runtime.HuntingValidationError):
        runtime.query_events(_payload(cursor=first["next_cursor"], offset=10), tenant_id="main", client=client)


def test_time_range_and_fields_are_bounded() -> None:
    client = _FakeClickHouse()
    with pytest.raises(runtime.HuntingValidationError):
        runtime.query_events(
            _payload(from_ts="2026-01-01T00:00:00Z", to_ts="2026-08-03T00:00:00Z"),
            tenant_id="main",
            client=client,
        )
    with pytest.raises(runtime.HuntingValidationError):
        runtime.query_events(
            _payload(filters=[{"field": "not_a_column", "operator": "eq", "value": "x"}]),
            tenant_id="main",
            client=client,
        )
    with pytest.raises(runtime.HuntingValidationError):
        runtime.query_events(_payload(expert_query="SELECT * FROM siem.events"), tenant_id="main", client=client)


def test_facets_cover_operator_dimensions() -> None:
    client = _FakeClickHouse()
    result = runtime.query_facets(_payload(), tenant_id="main", client=client)
    assert set(result["facets"]) == {"source_type", "source", "collector_profile", "category", "severity", "host"}
    assert result["facets"]["source_type"] == [{"value": "linux", "count": 4}]
    facet_queries = [sql for sql, _ in client.queries if "ARRAY JOIN" in sql]
    assert len(facet_queries) == 1


def test_event_detail_is_time_bounded_and_does_not_return_raw_json() -> None:
    row = _event(1)
    row["normalized_json"] = '{"event.kind":"event","secret":"must-not-leak"}'
    client = _FakeClickHouse([row])
    result = runtime.event_detail(
        "event-1",
        event_ts="2026-08-03T12:00:01Z",
        source="hot",
        tenant_id="main",
        client=client,
    )
    detail_sql = next(sql for sql, _ in client.queries if "normalized_json" in sql)
    assert "INTERVAL 1 SECOND" in detail_sql
    assert result["raw_json_available"] is False
    assert result["sections"]["normalized"] == {"event.kind": "event"}
    assert "normalized_json" not in result["event"]
    assert "secret" not in result["sections"]["normalized"]


def test_saved_search_crud_is_scoped_to_tenant_and_owner() -> None:
    client = _FakeClickHouse()
    saved = runtime.save_saved_search(
        {
            "name": "SSH failures",
            "specification": _payload(filters=[{"field": "event_outcome", "operator": "eq", "value": "failure"}]),
        },
        tenant_id="main",
        owner="alice",
        client=client,
    )
    assert runtime.list_saved_searches(tenant_id="main", owner="alice", client=client)["items"][0]["id"] == saved["id"]
    assert runtime.list_saved_searches(tenant_id="main", owner="bob", client=client)["items"] == []

    deleted = runtime.delete_saved_search(saved["id"], tenant_id="main", owner="alice", client=client)
    assert deleted["status"] == "deleted"
    assert runtime.list_saved_searches(tenant_id="main", owner="alice", client=client)["items"] == []


def test_routes_have_rbac_and_full_operator_contract() -> None:
    source = inspect.getsource(routes)
    assert source.count('require_permissions("events:query")') == 4
    assert source.count('require_permissions("search:write")') == 2
    assert 'require_permissions("events:view")' in source
    paths = {(route.path, next(iter(route.methods or []), "")) for route in routes.router.routes}
    assert ("/api/hunting/events/query", "POST") in paths
    assert ("/api/hunting/events/facets", "POST") in paths
    assert ("/api/hunting/events/{event_id}", "GET") in paths
    assert ("/api/hunting/saved-searches", "GET") in paths
    assert ("/api/hunting/saved-searches", "POST") in paths
    assert ("/api/hunting/saved-searches/{search_id}", "DELETE") in paths
    registered_paths = {route.path for route in console_router_registry.build_console_router().routes}
    assert "/api/hunting/events/query" in registered_paths
    assert "/api/hunting/saved-searches/{search_id}" in registered_paths
