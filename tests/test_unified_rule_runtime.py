from __future__ import annotations

import json
import os
import asyncio
from pathlib import Path
from types import SimpleNamespace

import pytest

os.environ.setdefault("SIEM_CH_HOST", "127.0.0.1")
os.environ.setdefault("SIEM_CH_USER", "test")
os.environ.setdefault("SIEM_CH_PASSWORD", "test")
os.environ.setdefault("SIEM_ADMIN_DEFAULT_PASSWORD", "test-password")
os.environ.setdefault("SIEM_JWT_SECRET", "test-jwt-secret")

from services.web.app import correlation_pack_runtime, unified_rule_runtime as runtime
from services.web.app.routes import console_rule_inventory_routes as rule_routes
from services.web.app.routes.console_rule_inventory_routes import router as rule_inventory_router


class _Result:
    def __init__(self, rows):
        self._rows = rows

    def named_results(self):
        return iter(self._rows)


class _FakeClickHouse:
    def __init__(self, *, stream=None, batch=None, catalog=None, noise=None):
        self.stream = list(stream or [])
        self.batch = list(batch or [])
        self.catalog = list(catalog or [])
        self.noise = list(noise or [])
        self.queries: list[str] = []

    def query(self, sql: str):
        self.queries.append(sql)
        if "FROM siem.correlation_rules_stream" in sql:
            return _Result(self.stream)
        if "FROM siem.correlation_rules_batch" in sql:
            return _Result(self.batch)
        if "FROM siem.detection_rule_catalog" in sql:
            return _Result(self.catalog)
        if "FROM siem.alerts_raw" in sql:
            return _Result(self.noise)
        if "FROM siem.normalizer_rules" in sql:
            return _Result([{"total": 4, "enabled": 3}])
        if "FROM siem.filter_rules" in sql:
            return _Result([{"total": 16, "enabled": 16}])
        raise AssertionError(sql)


def _stream(rule_id: int, *, enabled: int = 1, updated: str = "2026-08-03T10:00:00Z", name: str = "") -> dict:
    return {
        "id": rule_id,
        "name": name or f"Stream {rule_id}",
        "description": "stream definition",
        "enabled": enabled,
        "severity": "high",
        "pattern": "threshold",
        "window_s": 300,
        "threshold": 2,
        "expr": "event.type == 'failure'",
        "entity_field": "host.name",
        "created_ts": updated,
        "updated_ts": updated,
    }


def _batch(rule_id: int, *, enabled: int = 1) -> dict:
    return {
        "id": rule_id,
        "name": f"Batch {rule_id}",
        "description": "batch definition",
        "enabled": enabled,
        "severity": "medium",
        "window_s": 900,
        "sql_template": "SELECT 1",
        "created_ts": "2026-08-03T09:00:00Z",
        "updated_ts": "2026-08-03T09:00:00Z",
    }


def _catalog(rule_id: int, *, enabled: int = 1, author: str = "") -> dict:
    return {
        "id": rule_id,
        "title": f"Catalog {rule_id}",
        "sigma_id": f"sigma-{rule_id}",
        "status": "stable",
        "level": "medium",
        "source_format": "sigma",
        "logsource_product": "linux",
        "logsource_service": "sshd",
        "logsource_category": "authentication",
        "expr": "",
        "entity_field": "host.name",
        "window_s": 300,
        "threshold": 1,
        "tags": "attack.initial_access",
        "description": "catalog definition",
        "enabled": enabled,
        "author": author,
        "created_ts": "2026-08-03T08:00:00Z",
        "updated_ts": "2026-08-03T08:00:00Z",
    }


def _write_pack(path: Path, rules: list[dict], *, pack_id: str = "test-pack") -> None:
    path.write_text(
        json.dumps(
            {
                "pack_id": pack_id,
                "title": "Test pack",
                "version": "2.1.0",
                "status": "active",
                "owner": "tests",
                "stream_rules": rules,
                "batch_rules": [],
            }
        ),
        encoding="utf-8",
    )


def test_reconciles_catalog_stream_batch_and_duplicate_rows(tmp_path: Path) -> None:
    _write_pack(
        tmp_path / "test_pack.json",
        [
            {"id": 1, "title": "One", "status": "active", "severity": "high"},
            {"id": 4, "title": "Four", "status": "active", "severity": "low"},
            {
                "id": 5,
                "title": "Retired",
                "status": "retired",
                "severity": "low",
                "replacement_rule_id": 1,
                "replacement_reason": "covered by rule 1",
            },
        ],
    )
    client = _FakeClickHouse(
        stream=[
            _stream(1, updated="2026-08-03T09:00:00Z", name="old duplicate"),
            _stream(1, updated="2026-08-03T10:00:00Z", name="latest stream"),
            _stream(2, enabled=0),
        ],
        batch=[_batch(1), _batch(3)],
        catalog=[_catalog(1, author="operational-pack:test-pack"), _catalog(2), _catalog(3), _catalog(4)],
        noise=[
            {
                "rule_id": 1,
                "alert_count": 12,
                "hit_count": 30,
                "unique_alerts": 12,
                "unique_entities": 3,
                "false_positive_count": 2,
                "suppressed_count": 1,
                "last_alert_ts": "2026-08-03T11:00:00Z",
            }
        ],
    )

    result = runtime.list_unified_rules(client=client, pack_dir=tmp_path)
    items = {item["rule_id"]: item for item in result["items"]}

    assert result["summary"]["rule_count"] == 5
    assert result["summary"]["enabled_rule_count"] == 2
    assert result["summary"]["stream_count"] == 4
    assert result["summary"]["batch_count"] == 2
    assert result["diagnostics"]["duplicate_rows_collapsed"]["stream"] == 1
    assert items[1]["kind"] == "hybrid"
    assert items[1]["title"] == "latest stream"
    assert items[1]["noise"]["false_positive_count"] == 2
    assert items[1]["noise"]["false_positive_ratio"] == pytest.approx(2 / 12, abs=0.0001)
    assert items[2]["status"] == "drift"
    assert items[4]["status"] == "unpublished"
    assert items[5]["status"] == "retired"
    assert items[5]["replacement"]["replacement_identity"] == "rule:1"
    assert all(link["counted_as_detection_rules"] is False for link in result["summary"]["linked_processing"])


def test_search_and_identity_never_enter_clickhouse_sql(tmp_path: Path) -> None:
    attack = "x' OR 1=1; DROP TABLE siem.events --"
    client = _FakeClickHouse(stream=[_stream(7)], catalog=[_catalog(7)])

    result = runtime.list_unified_rules(search=attack, pack_id=attack, client=client, pack_dir=tmp_path)

    assert result["total"] == 0
    assert all(attack not in query for query in client.queries)
    with pytest.raises(runtime.RuleInventoryError):
        runtime.get_unified_rule("rule:7 OR 1=1", client=client, pack_dir=tmp_path)


def test_publish_delegates_to_existing_pack_publisher_and_audits(tmp_path: Path, monkeypatch) -> None:
    _write_pack(tmp_path / "test_pack.json", [{"id": 10, "title": "Ten", "status": "active", "severity": "high"}])
    client = _FakeClickHouse(stream=[_stream(10)], catalog=[_catalog(10, author="operational-pack:test-pack")])
    published: list[str] = []
    audited: list[tuple] = []
    monkeypatch.setattr(runtime, "_audit", lambda *args: audited.append(args))

    result = runtime.publish_unified_rule(
        "rule:10",
        actor="alice",
        client=client,
        pack_dir=tmp_path,
        publisher=lambda pack_id: published.append(pack_id) or {"status": "published"},
    )

    assert result["status"] == "published"
    assert published == ["test-pack"]
    assert audited and audited[0][0] == "alice"


def test_disable_requires_active_replacement_and_preserves_metadata(tmp_path: Path, monkeypatch) -> None:
    _write_pack(
        tmp_path / "test_pack.json",
        [
            {"id": 10, "title": "Old", "status": "active", "severity": "high", "expr": "a == 1"},
            {"id": 11, "title": "New", "status": "active", "severity": "high", "expr": "a == 1 and b == 2"},
        ],
    )
    client = _FakeClickHouse(
        stream=[_stream(10), _stream(11)],
        catalog=[_catalog(10, author="operational-pack:test-pack"), _catalog(11, author="operational-pack:test-pack")],
    )
    saves: list[dict] = []
    publishes: list[str] = []
    monkeypatch.setattr(runtime, "_audit", lambda *_args: None)

    result = runtime.set_unified_rule_enabled(
        10,
        enabled=False,
        actor="alice",
        reason="Rule 11 provides narrower equivalent coverage",
        replacement_identity="rule:11",
        client=client,
        pack_dir=tmp_path,
        saver=lambda payload, **_kwargs: saves.append(json.loads(json.dumps(payload))) or {},
        publisher=lambda pack_id: publishes.append(pack_id) or {"status": "published"},
    )

    old = next(row for row in saves[0]["stream_rules"] if row["id"] == 10)
    assert result["status"] == "retired_with_replacement"
    assert old["status"] == "retired"
    assert old["replacement_rule_id"] == 11
    assert old["replacement_reason"].startswith("Rule 11")
    assert publishes == ["test-pack"]

    with pytest.raises(runtime.RuleInventoryError):
        runtime.set_unified_rule_enabled(
            10,
            enabled=False,
            actor="alice",
            reason="too short",
            client=client,
            pack_dir=tmp_path,
            saver=lambda *_args, **_kwargs: {},
            publisher=lambda *_args: {},
        )


def test_failed_publish_restores_authored_pack(tmp_path: Path, monkeypatch) -> None:
    _write_pack(tmp_path / "test_pack.json", [{"id": 20, "title": "Twenty", "status": "retired", "severity": "high", "expr": "x == 1"}])
    client = _FakeClickHouse(stream=[_stream(20, enabled=0)], catalog=[_catalog(20, enabled=0, author="operational-pack:test-pack")])
    saves: list[dict] = []
    monkeypatch.setattr(runtime, "_audit", lambda *_args: None)

    def fail(_pack_id: str):
        raise RuntimeError("publisher failed")

    with pytest.raises(RuntimeError, match="publisher failed"):
        runtime.set_unified_rule_enabled(
            20,
            enabled=True,
            actor="alice",
            client=client,
            pack_dir=tmp_path,
            saver=lambda payload, **_kwargs: saves.append(json.loads(json.dumps(payload))) or {},
            publisher=fail,
        )

    assert saves[0]["stream_rules"][0]["status"] == "active"
    assert saves[1]["stream_rules"][0]["status"] == "retired"


def test_batch_only_rule_has_no_fake_write_capability(tmp_path: Path) -> None:
    client = _FakeClickHouse(batch=[_batch(30)], catalog=[_catalog(30)])
    item = runtime.get_unified_rule("rule:30", client=client, pack_dir=tmp_path)
    assert item["capabilities"] == {"publish": False, "enable": False, "disable": False, "batch_write": False}
    with pytest.raises(runtime.RuleConflictError):
        runtime.publish_unified_rule("rule:30", actor="alice", client=client, pack_dir=tmp_path, publisher=lambda _: {})


def test_pack_normalization_preserves_replacement_audit_metadata() -> None:
    normalized = correlation_pack_runtime._rule_view(  # noqa: SLF001
        {
            "id": 40,
            "title": "Retired rule",
            "description": "Original description",
            "pattern": "threshold",
            "status": "retired",
            "replacement_rule_id": 41,
            "replacement_reason": "Narrower replacement covers the same source",
            "expr": "x == 1",
        }
    )
    assert normalized["description"] == "Original description"
    assert normalized["replacement_rule_id"] == 41
    assert normalized["replacement_reason"].startswith("Narrower replacement")


def test_unified_rule_router_is_registered_without_replacing_other_routers() -> None:
    paths = {route.path for route in rule_inventory_router.routes}
    assert "/api/rules/unified" in paths
    assert "/api/rules/unified/{rule_identity}/publish" in paths
    registry = (Path(__file__).parents[1] / "services/web/app/routes/console_router_registry.py").read_text(encoding="utf-8")
    assert "rule_inventory_router," in registry
    assert "retroscan_router," in registry
    assert "service_lifecycle_router," in registry


def test_unified_rule_list_route_uses_query_parameters_without_mutation_payload(monkeypatch) -> None:
    calls: list[dict] = []

    def fake_list(**kwargs):
        calls.append(kwargs)
        return {"items": [], "total": 0, "summary": {}}

    monkeypatch.setattr(rule_routes, "list_unified_rules", fake_list)
    response = asyncio.run(
        rule_routes.unified_rules_api(
            search="ssh",
            status="active",
            engine="stream",
            pack_id="linux",
            limit=50,
            offset=10,
            noise_days=30,
            user=SimpleNamespace(username="analyst"),
        )
    )

    assert response.status_code == 200
    assert calls == [
        {
            "search": "ssh",
            "status": "active",
            "engine": "stream",
            "pack_id": "linux",
            "limit": 50,
            "offset": 10,
            "noise_days": 30,
        }
    ]
