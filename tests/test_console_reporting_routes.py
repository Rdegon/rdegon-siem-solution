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
from services.web.app.routes import console_reporting_routes as routes


def _app(user: security.User) -> FastAPI:
    app = FastAPI()
    app.include_router(routes.router)
    app.dependency_overrides[security.get_current_user] = lambda: user
    return app


def test_viewer_can_read_reporting_capabilities(monkeypatch) -> None:
    monkeypatch.setattr(routes, "reporting_capabilities", lambda: {"pdf_available": True, "formats": ["json", "csv", "pdf"]})
    response = TestClient(_app(security.User("viewer", "viewer"))).get("/api/reporting/capabilities")
    assert response.status_code == 200
    assert response.json()["pdf_available"] is True


def test_viewer_cannot_create_template(monkeypatch) -> None:
    monkeypatch.setattr(routes, "save_report_template", lambda *_, **__: {"id": "not-created"})
    response = TestClient(_app(security.User("viewer", "viewer"))).post(
        "/api/reporting/templates", json={"name": "Forbidden"}
    )
    assert response.status_code == 403


def test_admin_run_queues_background_job_with_main_tenant(monkeypatch) -> None:
    captured: dict = {}

    def create(template_id, **kwargs):
        captured.update({"template_id": template_id, **kwargs})
        return {"id": "report-run-1", "status": "queued"}, True

    monkeypatch.setattr(routes, "create_report_run", create)
    monkeypatch.setattr(routes, "execute_report_run", lambda run_id: captured.update({"executed": run_id}))
    response = TestClient(_app(security.User("admin", "admin"))).post(
        "/api/reporting/templates/daily/run",
        headers={"Idempotency-Key": "manual:daily:0001", "X-SIEM-Tenant-Scope": "main"},
        json={},
    )
    assert response.status_code == 202
    assert captured["tenant_scope"] == ["main"]
    assert captured["idempotency_key"] == "manual:daily:0001"
    assert captured["executed"] == "report-run-1"


def test_run_rejects_unknown_tenant_before_queue(monkeypatch) -> None:
    called = False

    def create(*_, **__):
        nonlocal called
        called = True
        return {}, True

    monkeypatch.setattr(routes, "create_report_run", create)
    response = TestClient(_app(security.User("admin", "admin"))).post(
        "/api/reporting/templates/daily/run",
        headers={"Idempotency-Key": "manual:daily:0002", "X-SIEM-Tenant-Scope": "other"},
        json={},
    )
    assert response.status_code == 400
    assert called is False
