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
from services.web.app.routes import console_assets_routes as routes


def _app(user: security.User) -> FastAPI:
    app = FastAPI()
    app.include_router(routes.router)
    app.dependency_overrides[security.get_current_user] = lambda: user
    return app


def test_viewer_can_read_discovery_inventory(monkeypatch) -> None:
    monkeypatch.setattr(routes, "list_source_discovery_candidates", lambda **_: {"items": [], "jobs": [], "metrics": {}})
    response = TestClient(_app(security.User("viewer", "viewer"))).get("/api/sources/discovery")
    assert response.status_code == 200
    assert response.json()["items"] == []


def test_viewer_cannot_verify_onboarding(monkeypatch) -> None:
    called = False

    def verify(*_, **__):
        nonlocal called
        called = True
        return {}

    monkeypatch.setattr(routes, "verify_source_onboarding", verify)
    response = TestClient(_app(security.User("viewer", "viewer"))).post("/api/sources/discovery/jobs/job-1/verify")
    assert response.status_code == 403
    assert called is False


def test_analyst_can_verify_real_event_state(monkeypatch) -> None:
    captured = {}

    def verify(job_id: str, *, actor: str):
        captured.update({"job_id": job_id, "actor": actor})
        return {"verified": False, "connected": True, "status": "connected"}

    monkeypatch.setattr(routes, "verify_source_onboarding", verify)
    response = TestClient(_app(security.User("analyst", "analyst"))).post("/api/sources/discovery/jobs/job-1/verify")
    assert response.status_code == 200
    assert response.json()["status"] == "connected"
    assert captured == {"job_id": "job-1", "actor": "analyst"}


def test_scan_accepts_network_array_from_ui(monkeypatch) -> None:
    captured = {}

    def scan(cidr: str, **kwargs):
        captured.update({"cidr": cidr, **kwargs})
        return {"items": [], "jobs": [], "metrics": {}}

    monkeypatch.setattr(routes, "scan_source_candidates", scan)
    response = TestClient(_app(security.User("analyst", "analyst"))).post(
        "/api/sources/discovery/scan",
        json={"networks": ["10.20.10.0/24", "10.20.20.0/24"]},
    )
    assert response.status_code == 200
    assert captured["cidr"] == "10.20.10.0/24,10.20.20.0/24"
