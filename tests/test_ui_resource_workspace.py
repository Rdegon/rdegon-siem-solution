from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest

os.environ.setdefault("SIEM_CH_HOST", "127.0.0.1")
os.environ.setdefault("SIEM_CH_USER", "default")
os.environ.setdefault("SIEM_CH_PASSWORD", "test")
os.environ.setdefault("SIEM_JWT_SECRET", "test-jwt-secret")
os.environ.setdefault("SIEM_ADMIN_DEFAULT_PASSWORD", "test-admin-password")

from app import kuma_integration_runtime, resource_catalog_runtime, tenant_scope_runtime

ROOT = Path(__file__).resolve().parents[1]


def test_tenant_scope_uses_production_inventory(monkeypatch: pytest.MonkeyPatch) -> None:
    from app import deps

    monkeypatch.setattr(deps, "fetch_source_inventory", lambda **_: [{"id": "a"}, {"id": "b"}])
    monkeypatch.setattr(deps, "fetch_alert_metrics", lambda: {"agg_open": 7})

    result = tenant_scope_runtime.build_tenant_scope()

    assert result["default"] == ["main"]
    assert result["available"] == [
        {
            "id": "main",
            "name": "Main",
            "description": "Production SOC data and security services",
            "source_count": 2,
            "incident_count": 7,
        }
    ]
    assert result["issues"] == []
    assert tenant_scope_runtime.validate_tenant_scope_header("") == ["main"]
    with pytest.raises(ValueError, match="not available"):
        tenant_scope_runtime.validate_tenant_scope_header("demo")


def test_managed_resource_is_versioned_validated_and_published(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stored: list[dict[str, Any]] = []
    monkeypatch.setattr(resource_catalog_runtime, "_stored_resources", lambda: [dict(item) for item in stored])
    monkeypatch.setattr(
        resource_catalog_runtime,
        "_save_resources",
        lambda rows: stored.__setitem__(slice(None), [dict(item) for item in rows]),
    )
    monkeypatch.setattr(resource_catalog_runtime, "_runtime_resources", lambda: ([], []))

    payload = {
        "name": "Production HTTP intake",
        "kind": "collector",
        "description": "Managed intake contract",
        "config": {
            "collector_profile": "production-http",
            "transport": "http",
            "source_type": "generic_json",
        },
        "bindings": {},
    }
    first = resource_catalog_runtime.save_resource(payload, actor="tester")
    second = resource_catalog_runtime.save_resource({**payload, "id": first["id"]}, actor="tester")

    assert first["version"] == 1
    assert second["version"] == 2
    assert resource_catalog_runtime.validate_resource(second["id"])["valid"] is True

    published = resource_catalog_runtime.publish_resource(second["id"], actor="tester")

    assert published["status"] == "published"
    assert published["resource"]["status"] == "active"
    assert published["activation"]["collector_profile"] == "production-http"
    assert published["activation"]["ingest_contract"]["http_endpoint"] == "/ingest/http"


def test_kuma_package_workflows_follow_supported_api_sequence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, str, dict[str, Any]]] = []

    def fake_request(method: str, path: str, **kwargs: Any) -> Any:
        calls.append((method, path, kwargs))
        if path == "/api/v1/resources/export":
            return {"fileID": "export-1"}
        if path == "/api/v1/resources/download/export-1":
            return b"package"
        if path == "/api/v1/resources/upload":
            return {"id": "upload-1"}
        if path == "/api/v1/resources/import":
            return {"accepted": True}
        raise AssertionError(path)

    monkeypatch.setattr(kuma_integration_runtime, "_request", fake_request)

    exported = kuma_integration_runtime.export_kuma_resources(
        ["rule-1"],
        password="package-password",
        tenant_id="tenant-1",
    )
    imported = kuma_integration_runtime.import_kuma_package(
        b"package",
        password="package-password",
        tenant_id="tenant-1",
        actions={"rule-1": 1},
    )

    assert exported["content"] == b"package"
    assert imported["status"] == "imported"
    assert [(method, path) for method, path, _ in calls] == [
        ("POST", "/api/v1/resources/export"),
        ("GET", "/api/v1/resources/download/export-1"),
        ("POST", "/api/v1/resources/upload"),
        ("POST", "/api/v1/resources/import"),
    ]
    assert calls[0][2]["json_body"]["TenantID"] == "tenant-1"
    assert calls[3][2]["json_body"]["actions"] == {"rule-1": 1}


def test_kuma_deployment_uses_vault_reference_and_trusted_ca() -> None:
    deploy_source = (ROOT / "deploy" / "vm4_enterprise_foundation_deploy.py").read_text(encoding="utf-8")
    identity_source = (ROOT / "deploy" / "vm4_identity_governance_bootstrap.py").read_text(encoding="utf-8")
    ca_text = (ROOT / "deploy" / "certs" / "kuma-rest-api-ca.pem").read_text(encoding="utf-8")

    assert "SIEM_KUMA_API_TOKEN_FILE" in deploy_source
    assert '"SIEM_KUMA_VERIFY_TLS": "1"' in deploy_source
    assert "kuma-rest-api-ca.pem" in deploy_source
    assert "kv/siem/kuma-api" in identity_source
    assert "SIEM_KUMA_API_TOKEN_REF" in identity_source
    assert "BEGIN CERTIFICATE" in ca_text
    assert "PRIVATE KEY" not in ca_text


@pytest.mark.parametrize(
    ("kind", "config", "expected_error"),
    [
        ("collector", {"transport": "file", "collector_profile": "bad"}, "collector transport"),
        (
            "correlationRule",
            {"rule_id": 7, "expr": "", "threshold": 1, "window_s": 300},
            "expr or sigma_yaml",
        ),
        ("filter", {"expr": "true", "action": "delete"}, "filter action"),
    ],
)
def test_resource_validation_rejects_non_publishable_configs(
    kind: str,
    config: dict[str, Any],
    expected_error: str,
) -> None:
    result = resource_catalog_runtime.validate_resource_payload(
        {"name": "Invalid", "kind": kind, "config": config, "bindings": {}}
    )

    assert result["valid"] is False
    assert any(expected_error in item for item in result["errors"])
