from __future__ import annotations

import copy
import inspect
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

os.environ.setdefault("SIEM_CH_HOST", "127.0.0.1")
os.environ.setdefault("SIEM_CH_USER", "test")
os.environ.setdefault("SIEM_CH_PASSWORD", "test")
os.environ.setdefault("SIEM_ADMIN_DEFAULT_PASSWORD", "test-password")
os.environ.setdefault("SIEM_JWT_SECRET", "test-jwt-secret")

from services.web.app import retroscan_runtime
from services.web.app.routes import console_retroscan_routes


def test_retroscan_imports_filter_parser_with_web_app_dir_only(tmp_path: Path) -> None:
    web_root = Path(__file__).parents[1] / "services" / "web"
    environment = {
        **os.environ,
        "PYTHONPATH": str(web_root),
        "SIEM_CH_HOST": "127.0.0.1",
        "SIEM_CH_USER": "test",
        "SIEM_CH_PASSWORD": "test",
        "SIEM_ADMIN_DEFAULT_PASSWORD": "test-password",
        "SIEM_JWT_SECRET": "test-jwt-secret",
    }
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "from app.retroscan_runtime import parse_expr; print(bool(parse_expr(\"event.type == 'x'\")))",
        ],
        cwd=tmp_path,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )
    assert result.stdout.strip() == "True"


@pytest.mark.parametrize(
    ("expression", "event"),
    [
        ("event.type == 'failure'", {"event.type": "failure"}),
        ("event.original icontains 'ssh'", {"event.original": "SSHD rejected login"}),
        ("event.type != 'success' and host.name startswith 'pve'", {"event.type": "failure", "host.name": "pve-01"}),
        ("not event.outcome == 'success' or event.action endswith 'deny'", {"event.outcome": "failure", "event.action": "firewall-deny"}),
    ],
)
def test_web_filter_expression_matches_processing_engine(expression: str, event: dict) -> None:
    from services.filter.filter_core import eval_expr as processing_eval
    from services.filter.filter_core import parse_expr as processing_parse
    from services.web.app.filter_expression_runtime import eval_expr as web_eval
    from services.web.app.filter_expression_runtime import parse_expr as web_parse

    assert web_parse(expression) == processing_parse(expression)
    assert web_eval(web_parse(expression), event) == processing_eval(processing_parse(expression), event)


class _QueryResult:
    def __init__(self, rows: list[dict]) -> None:
        self._rows = rows

    def named_results(self):
        return iter(self._rows)


class _FakeClickHouse:
    def __init__(self, events: list[dict]) -> None:
        self.events = events
        self.queries: list[str] = []

    def query(self, sql: str) -> _QueryResult:
        self.queries.append(sql)
        if "correlation_rules_stream" in sql:
            return _QueryResult(
                [
                    {
                        "id": 1002,
                        "name": "SSH failure burst",
                        "description": "Repeated SSH failures",
                        "severity": "high",
                        "pattern": "threshold",
                        "window_s": 300,
                        "threshold": 2,
                        "expr": "event.category == 'authentication' and event.outcome == 'failure'",
                        "entity_field": "source.ip",
                        "updated_ts": "2026-08-03T00:00:00Z",
                    }
                ]
            )
        if "count() AS total" in sql:
            return _QueryResult([{"total": len(self.events)}])
        if "FROM siem.events" in sql:
            return _QueryResult(self.events)
        raise AssertionError(f"Unexpected query: {sql}")


@pytest.fixture()
def task_store(monkeypatch):
    rows: list[dict] = []

    def load(_name, _factory):
        return copy.deepcopy(rows)

    def save(_name, value):
        rows[:] = copy.deepcopy(value)

    monkeypatch.setattr(retroscan_runtime.core, "_collection", load)
    monkeypatch.setattr(retroscan_runtime.core, "_save_collection", save)
    monkeypatch.setattr(retroscan_runtime.core, "append_audit_event", lambda **_kwargs: None)
    return rows


def _request(**overrides):
    return {
        "run_id": "retroscan-contract-1",
        "from_ts": "2026-08-03T00:00:00Z",
        "to_ts": "2026-08-03T01:00:00Z",
        "max_rows": 1000,
        **overrides,
    }


def _event(event_id: str, minute: int) -> dict:
    return {
        "ts": datetime(2026, 8, 3, 0, minute, tzinfo=timezone.utc),
        "event_id": event_id,
        "event_code": "sshd",
        "category": "authentication",
        "subcategory": "start",
        "event_action": "ssh_login",
        "event_outcome": "failure",
        "src_ip": "198.51.100.40",
        "dst_ip": "192.168.3.120",
        "src_port": 45123,
        "dst_port": 22,
        "device_vendor": "linux",
        "device_product": "sshd",
        "log_source": "pilot-web-01",
        "host_name": "pilot-web-01",
        "user_name": "root",
        "target_user": "root",
        "process_name": "sshd",
        "process_executable": "/usr/sbin/sshd",
        "process_command": "sshd: root [priv]",
        "severity": "medium",
        "message": "Failed password for root",
        "normalized_json": "{}",
        "tags": "",
    }


def test_capability_refuses_commit_without_alert_service(task_store) -> None:
    assert retroscan_runtime.retroscan_capabilities()["commit"] is False
    with pytest.raises(retroscan_runtime.RetroscanCommitUnavailableError):
        retroscan_runtime.create_retroscan(_request(commit=True), actor="analyst")
    assert task_store == []


def test_request_is_bounded_and_idempotent(task_store, monkeypatch) -> None:
    monkeypatch.setenv("SIEM_RETROSCAN_MAX_RANGE_HOURS", "24")
    first, created = retroscan_runtime.create_retroscan(_request(), actor="analyst")
    replay, replay_created = retroscan_runtime.create_retroscan(_request(), actor="analyst")
    assert created is True
    assert replay_created is False
    assert replay["id"] == first["id"]
    assert replay["idempotent_replay"] is True

    with pytest.raises(retroscan_runtime.RetroscanConflictError):
        retroscan_runtime.create_retroscan(_request(max_rows=999), actor="analyst")
    with pytest.raises(retroscan_runtime.RetroscanValidationError):
        retroscan_runtime.create_retroscan(
            _request(run_id="retroscan-too-wide", to_ts="2026-08-05T00:00:00Z"),
            actor="analyst",
        )
    with pytest.raises(retroscan_runtime.RetroscanValidationError):
        retroscan_runtime.create_retroscan(
            _request(run_id="retroscan-too-many", max_rows=retroscan_runtime._max_rows_limit() + 1),
            actor="analyst",
        )


def test_dry_run_uses_active_rule_engine_and_never_writes_alerts(task_store) -> None:
    run, created = retroscan_runtime.create_retroscan(_request(), actor="analyst")
    assert created is True
    client = _FakeClickHouse([_event("evt-1", 0), _event("evt-2", 1)])

    completed = retroscan_runtime.run_retroscan_task(run["id"], client_factory=lambda: client)

    assert completed["status"] == "completed"
    assert completed["result"]["events_scanned"] == 2
    assert completed["result"]["matched_events"] == 2
    assert completed["result"]["candidate_alerts"] == 1
    assert completed["result"]["alerts_created"] == 0
    assert completed["result"]["preview"][0]["would_create_alert"] is True
    assert completed["result"]["preview"][0]["entity_key"] == "198.51.100.40"
    assert all(statement.lstrip().upper().startswith("SELECT") for statement in client.queries)
    assert not any("INSERT INTO" in statement.upper() for statement in client.queries)


def test_cancelled_queued_run_stays_cancelled(task_store) -> None:
    run, _ = retroscan_runtime.create_retroscan(_request(), actor="analyst")
    cancelled = retroscan_runtime.cancel_retroscan(run["id"], actor="analyst")
    assert cancelled["status"] == "cancelled"

    result = retroscan_runtime.run_retroscan_task(
        run["id"],
        client_factory=lambda: pytest.fail("cancelled run must not open ClickHouse"),
    )
    assert result["status"] == "cancelled"


def test_stale_worker_is_reconciled_to_failed(task_store, monkeypatch) -> None:
    monkeypatch.setenv("SIEM_RETROSCAN_STALE_AFTER_SECONDS", "300")
    run, _ = retroscan_runtime.create_retroscan(_request(), actor="analyst")
    task_store[0]["status"] = "running"
    task_store[0]["heartbeat_ts"] = "2020-01-01T00:00:00Z"

    item = retroscan_runtime.get_retroscan(run["id"])

    assert item["status"] == "failed"
    assert item["error"]["code"] == "worker_lost"


def test_routes_enforce_required_rbac_and_expose_full_lifecycle() -> None:
    source = inspect.getsource(console_retroscan_routes)
    assert 'require_permissions("health:view")' in source
    assert source.count('require_permissions("response:run")') == 2
    paths = [(route.path, set(route.methods or [])) for route in console_retroscan_routes.router.routes]
    assert ("/api/retroscan/runs", {"POST"}) in paths
    assert any(route.path == "/api/retroscan/runs" and route.methods == {"GET"} for route in console_retroscan_routes.router.routes)
    assert ("/api/retroscan/runs/{run_id}", {"GET"}) in paths
    assert ("/api/retroscan/runs/{run_id}/cancel", {"POST"}) in paths
