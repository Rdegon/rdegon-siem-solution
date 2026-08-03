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
from services.web.app.routes import console_resource_lifecycle_routes as routes


def _app(user: security.User) -> FastAPI:
    app = FastAPI()
    app.include_router(routes.router)
    app.dependency_overrides[security.get_current_user] = lambda: user
    return app


def test_viewer_can_list_versions_but_cannot_duplicate(monkeypatch) -> None:
    monkeypatch.setattr(
        routes,
        "list_resource_versions",
        lambda resource_id, **_: {"resource_id": resource_id, "items": [], "total": 0},
    )
    monkeypatch.setattr(routes, "duplicate_resource", lambda *_, **__: {"status": "created"})
    client = TestClient(_app(security.User("viewer", "viewer")))

    assert client.get("/api/resources/catalog/example/versions").status_code == 200
    assert client.post(
        "/api/resources/catalog/example/duplicate",
        headers={"Idempotency-Key": "resource:duplicate:route"},
        json={},
    ).status_code == 403


def test_admin_duplicate_passes_tenant_actor_and_idempotency(monkeypatch) -> None:
    captured = {}

    def duplicate(resource_id, **kwargs):
        captured.update({"resource_id": resource_id, **kwargs})
        return {"status": "created", "resource": {"id": "managed-copy"}, "idempotent_replay": False}

    monkeypatch.setattr(routes, "duplicate_resource", duplicate)
    client = TestClient(_app(security.User("admin", "admin")))
    response = client.post(
        "/api/resources/catalog/runtime-source/duplicate",
        headers={"Idempotency-Key": "resource:duplicate:route", "X-Tenant-Scope": "main"},
        json={"name": "Managed copy"},
    )

    assert response.status_code == 201
    assert captured == {
        "resource_id": "runtime-source",
        "actor": "admin",
        "idempotency_key": "resource:duplicate:route",
        "tenant_id": "main",
        "name": "Managed copy",
    }


def test_delete_requires_resource_write_permission(monkeypatch) -> None:
    monkeypatch.setattr(routes, "delete_unpublished_draft", lambda *_, **__: {"status": "deleted"})
    client = TestClient(_app(security.User("analyst", "analyst")))

    response = client.request(
        "DELETE",
        "/api/resources/catalog/draft-1",
        headers={"Idempotency-Key": "resource:delete:route"},
        json={"expected_revision": 1},
    )

    assert response.status_code == 403


def test_router_maps_lifecycle_conflicts(monkeypatch) -> None:
    def rollback(*_, **__):
        raise routes.ResourceLifecycleError("stale", code="revision_conflict", status_code=409)

    monkeypatch.setattr(routes, "rollback_resource", rollback)
    client = TestClient(_app(security.User("admin", "admin")))
    response = client.post(
        "/api/resources/catalog/resource-1/rollback",
        headers={"Idempotency-Key": "resource:rollback:route"},
        json={"target_version": 1, "expected_revision": 2},
    )

    assert response.status_code == 409
    assert response.json()["code"] == "revision_conflict"


def test_route_rejects_missing_revision_before_runtime(monkeypatch) -> None:
    called = False

    def delete(*_, **__):
        nonlocal called
        called = True
        return {}

    monkeypatch.setattr(routes, "delete_unpublished_draft", delete)
    client = TestClient(_app(security.User("admin", "admin")))
    response = client.request(
        "DELETE",
        "/api/resources/catalog/draft-1",
        headers={"Idempotency-Key": "resource:delete:missing-revision"},
        json={},
    )

    assert response.status_code == 400
    assert response.json()["code"] == "invalid_request"
    assert called is False
