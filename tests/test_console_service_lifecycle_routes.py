from __future__ import annotations

import os

from fastapi import FastAPI
from fastapi.testclient import TestClient

os.environ.setdefault("SIEM_CH_HOST", "127.0.0.1")
os.environ.setdefault("SIEM_CH_USER", "test")
os.environ.setdefault("SIEM_CH_PASSWORD", "test")
os.environ.setdefault("SIEM_ADMIN_DEFAULT_PASSWORD", "test-password")
os.environ.setdefault("SIEM_JWT_SECRET", "test-jwt-secret")

from services.web.app import security
from services.web.app.routes import console_service_lifecycle_routes as routes


def _app(user: security.User) -> FastAPI:
    app = FastAPI()
    app.include_router(routes.router)
    app.dependency_overrides[security.get_current_user] = lambda: user
    return app


def test_health_viewer_can_read_registry(monkeypatch) -> None:
    captured = {}

    def list_instances(**kwargs):
        captured.update(kwargs)
        return {"items": [], "metrics": {}, "adapter": {}}

    monkeypatch.setattr(routes, "list_service_instances", list_instances)
    client = TestClient(_app(security.User("viewer", "viewer")))
    response = client.get("/api/service-lifecycle")
    assert response.status_code == 200
    assert response.json()["items"] == []
    assert captured["refresh_live"] is False


def test_viewer_cannot_execute_lifecycle_action(monkeypatch) -> None:
    monkeypatch.setattr(routes, "execute_service_action", lambda *_, **__: {"status": "completed"})
    client = TestClient(_app(security.User("viewer", "viewer")))
    response = client.post(
        "/api/service-lifecycle/writer-primary/actions/restart",
        json={"idempotency_key": "route:test:restart:0001"},
    )
    assert response.status_code == 403


def test_analyst_with_response_run_can_execute(monkeypatch) -> None:
    captured = {}

    def execute(instance_id, action, **kwargs):
        captured.update({"instance_id": instance_id, "action": action, **kwargs})
        return {"instance_id": instance_id, "action": action, "status": "completed", "verified": True}

    monkeypatch.setattr(routes, "execute_service_action", execute)
    client = TestClient(_app(security.User("analyst", "analyst")))
    response = client.post(
        "/api/service-lifecycle/writer-primary/actions/restart",
        headers={"Idempotency-Key": "route:test:restart:0002"},
        json={},
    )
    assert response.status_code == 200
    assert captured["actor"] == "analyst"
    assert captured["idempotency_key"] == "route:test:restart:0002"


def test_route_rejects_non_allowlisted_action_before_runtime(monkeypatch) -> None:
    called = False

    def execute(*_, **__):
        nonlocal called
        called = True
        return {}

    monkeypatch.setattr(routes, "execute_service_action", execute)
    client = TestClient(_app(security.User("admin", "admin")))
    response = client.post(
        "/api/service-lifecycle/writer-primary/actions/run-arbitrary-command",
        json={"idempotency_key": "route:test:invalid:0001"},
    )
    assert response.status_code == 400
    assert called is False
