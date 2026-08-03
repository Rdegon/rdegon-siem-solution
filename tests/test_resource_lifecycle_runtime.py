from __future__ import annotations

import json
import os
from typing import Any

import pytest

os.environ.setdefault("SIEM_CH_HOST", "127.0.0.1")
os.environ.setdefault("SIEM_CH_USER", "test")
os.environ.setdefault("SIEM_CH_PASSWORD", "test")
os.environ.setdefault("SIEM_ADMIN_DEFAULT_PASSWORD", "test-password")
os.environ.setdefault("SIEM_JWT_SECRET", "test-jwt-secret")

from app import resource_catalog_runtime as catalog
from app import resource_lifecycle_runtime as lifecycle


@pytest.fixture
def resource_state(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    state: dict[str, Any] = {
        "resources": [],
        "runtime": [],
        "snapshots": [],
        "idempotency": [],
        "audit": [],
    }
    monkeypatch.setattr(catalog, "_stored_resources", lambda: [dict(item) for item in state["resources"]])
    monkeypatch.setattr(
        catalog,
        "_save_resources",
        lambda rows: state["resources"].__setitem__(slice(None), [dict(item) for item in rows]),
    )
    monkeypatch.setattr(catalog, "_runtime_resources", lambda: ([dict(item) for item in state["runtime"]], []))
    monkeypatch.setattr(lifecycle, "_load_snapshots", lambda: [dict(item) for item in state["snapshots"]])
    monkeypatch.setattr(
        lifecycle,
        "_save_snapshots",
        lambda rows: state["snapshots"].__setitem__(slice(None), [dict(item) for item in rows]),
    )
    monkeypatch.setattr(lifecycle, "_load_idempotency", lambda: [dict(item) for item in state["idempotency"]])
    monkeypatch.setattr(
        lifecycle,
        "_save_idempotency",
        lambda rows: state["idempotency"].__setitem__(slice(None), [dict(item) for item in rows]),
    )
    monkeypatch.setattr(
        lifecycle,
        "append_audit_event",
        lambda **kwargs: state["audit"].append(dict(kwargs)) or dict(kwargs),
    )
    monkeypatch.setattr(catalog, "append_audit_event", lambda **kwargs: state["audit"].append(dict(kwargs)) or dict(kwargs))
    return state


def _collector(name: str, profile: str) -> dict[str, Any]:
    return {
        "name": name,
        "kind": "collector",
        "description": "Managed collector",
        "tenant_id": "main",
        "config": {"collector_profile": profile, "transport": "http"},
        "bindings": {},
    }


def test_duplicate_runtime_resource_creates_sanitized_managed_draft_and_replays(
    resource_state: dict[str, Any],
) -> None:
    resource_state["runtime"].append(
        {
            "id": "runtime-collector-linux",
            "name": "Linux runtime",
            "kind": "collector",
            "description": "Discovered",
            "status": "active",
            "version": 1,
            "origin": "sentinel-runtime",
            "tenant_id": "main",
            "config": {
                "collector_profile": "linux",
                "transport": "http",
                "access_token": "must-not-copy",
                "nested": {"password": "must-not-copy"},
            },
            "bindings": {},
            "read_only": True,
        }
    )

    first = lifecycle.duplicate_resource(
        "runtime-collector-linux",
        actor="admin",
        idempotency_key="resource:duplicate:0001",
        name="Managed Linux",
    )
    replay = lifecycle.duplicate_resource(
        "runtime-collector-linux",
        actor="admin",
        idempotency_key="resource:duplicate:0001",
        name="Managed Linux",
    )

    created = first["resource"]
    assert created["origin"] == "sentinel-managed"
    assert created["status"] == "draft"
    assert created["read_only"] is False
    assert "access_token" not in created["config"]
    assert "password" not in created["config"]["nested"]
    assert replay["resource"]["id"] == created["id"]
    assert replay["idempotent_replay"] is True
    assert len(resource_state["resources"]) == 1
    assert [item["action"] for item in resource_state["audit"]] == ["resource.saved", "resource.duplicated"]


def test_versions_compare_and_rollback_create_new_immutable_version(resource_state: dict[str, Any]) -> None:
    first = catalog.save_resource(_collector("Production intake", "http-v1"), actor="admin")
    second = catalog.save_resource(
        {**_collector("Production intake", "http-v2"), "id": first["id"]},
        actor="admin",
    )

    versions = lifecycle.list_resource_versions(first["id"])
    comparison = lifecycle.compare_resource_versions(
        first["id"],
        from_version=1,
        to_version=2,
    )
    rolled_back = lifecycle.rollback_resource(
        first["id"],
        target_version=1,
        expected_revision=second["revision"],
        actor="admin",
        idempotency_key="resource:rollback:0001",
    )

    assert [item["version"] for item in versions["items"]] == [2, 1]
    assert comparison["identical"] is False
    assert any(item["path"] == "/config/collector_profile" for item in comparison["changes"])
    assert rolled_back["resource"]["version"] == 3
    assert rolled_back["resource"]["revision"] == 3
    assert rolled_back["resource"]["config"]["collector_profile"] == "http-v1"
    assert [item["version"] for item in lifecycle.list_resource_versions(first["id"])["items"]] == [3, 2, 1]
    assert resource_state["snapshots"][0]["definition"]["config"]["collector_profile"] == "http-v1"
    assert resource_state["audit"][-1]["action"] == "resource.rolled_back"


def test_rollback_rejects_stale_revision(resource_state: dict[str, Any]) -> None:
    first = catalog.save_resource(_collector("Intake", "v1"), actor="admin")
    catalog.save_resource({**_collector("Intake", "v2"), "id": first["id"]}, actor="admin")

    with pytest.raises(lifecycle.ResourceLifecycleError, match="changed concurrently") as exc_info:
        lifecycle.rollback_resource(
            first["id"],
            target_version=1,
            expected_revision=1,
            actor="admin",
            idempotency_key="resource:rollback:stale",
        )

    assert exc_info.value.status_code == 409
    assert exc_info.value.code == "revision_conflict"


def test_delete_is_limited_to_never_published_managed_drafts_and_is_idempotent(
    resource_state: dict[str, Any],
) -> None:
    draft = catalog.save_resource(_collector("Temporary draft", "temp"), actor="admin")

    deleted = lifecycle.delete_unpublished_draft(
        draft["id"],
        expected_revision=draft["revision"],
        actor="admin",
        idempotency_key="resource:delete:0001",
    )
    replay = lifecycle.delete_unpublished_draft(
        draft["id"],
        expected_revision=draft["revision"],
        actor="admin",
        idempotency_key="resource:delete:0001",
    )

    assert deleted["status"] == "deleted"
    assert deleted["version_history_retained"] is True
    assert replay["idempotent_replay"] is True
    assert resource_state["resources"] == []
    assert len(resource_state["snapshots"]) == 1
    retained = lifecycle.list_resource_versions(draft["id"])
    assert retained["deleted"] is True
    assert retained["current_version"] is None
    assert retained["items"][0]["version"] == 1

    published = catalog.save_resource(_collector("Published", "published"), actor="admin")
    catalog.publish_resource(published["id"], actor="admin")
    edited = catalog.save_resource({**_collector("Published", "edited"), "id": published["id"]}, actor="admin")
    with pytest.raises(lifecycle.ResourceLifecycleError, match="never been published"):
        lifecycle.delete_unpublished_draft(
            edited["id"],
            expected_revision=edited["revision"],
            actor="admin",
            idempotency_key="resource:delete:published",
        )


def test_export_import_package_is_bounded_validated_secret_free_and_draft_only(
    resource_state: dict[str, Any],
) -> None:
    resource = catalog.save_resource(_collector("Portable intake", "portable"), actor="admin")
    exported = lifecycle.export_resource_package([resource["id"]], actor="auditor")
    package = json.loads(exported["content"])

    imported = lifecycle.import_resource_package(
        exported["content"],
        actor="admin",
        idempotency_key="resource:import:0001",
    )
    replay = lifecycle.import_resource_package(
        exported["content"],
        actor="admin",
        idempotency_key="resource:import:0001",
    )

    assert package["schema"] == lifecycle.PACKAGE_SCHEMA
    assert set(package["resources"][0]["definition"]) == set(lifecycle._DEFINITION_FIELDS)
    assert imported["items"][0]["resource_id"] != resource["id"]
    assert imported["items"][0]["status"] == "draft"
    assert replay["idempotent_replay"] is True
    assert {item["action"] for item in resource_state["audit"]} >= {
        "resource.package_exported",
        "resource.package_imported",
    }

    unsafe = {
        "schema": lifecycle.PACKAGE_SCHEMA,
        "tenant_id": "main",
        "exported_ts": "2026-08-03T00:00:00Z",
        "resources": [
            {
                "source_id": "connector-unsafe",
                "source_version": 1,
                "definition": {
                    "name": "Unsafe",
                    "kind": "connector",
                    "description": "",
                    "tenant_id": "main",
                    "config": {
                        "block_type": "webhook",
                        "endpoint": "https://example.invalid",
                        "token": "secret",
                    },
                    "bindings": {},
                },
            }
        ],
    }
    with pytest.raises(lifecycle.ResourceLifecycleError) as exc_info:
        lifecycle.import_resource_package(
            unsafe,
            actor="admin",
            idempotency_key="resource:import:unsafe",
        )
    assert exc_info.value.code == "secret_gate_failed"


def test_package_rejects_secret_resources_artifacts_and_cross_tenant_access(
    resource_state: dict[str, Any],
) -> None:
    secret = catalog.save_resource(
        {
            "name": "Vault reference",
            "kind": "secret",
            "tenant_id": "main",
            "config": {"secret_ref": "kv/siem/example"},
            "bindings": {},
        },
        actor="admin",
    )
    with pytest.raises(lifecycle.ResourceLifecycleError) as secret_error:
        lifecycle.export_resource_package([secret["id"]], actor="admin")
    assert secret_error.value.code == "secret_resource_forbidden"

    artifact_package = {
        "schema": lifecycle.PACKAGE_SCHEMA,
        "tenant_id": "main",
        "exported_ts": "2026-08-03T00:00:00Z",
        "resources": [
            {
                "source_id": "collector-artifact",
                "source_version": 1,
                "definition": {
                    **_collector("Artifact", "artifact"),
                    "config": {
                        "collector_profile": "artifact",
                        "transport": "http",
                        "blob": "embedded-output",
                    },
                },
            }
        ],
    }
    with pytest.raises(lifecycle.ResourceLifecycleError) as artifact_error:
        lifecycle.import_resource_package(
            artifact_package,
            actor="admin",
            idempotency_key="resource:import:artifact",
        )
    assert artifact_error.value.code == "artifact_gate_failed"

    with pytest.raises(lifecycle.ResourceLifecycleError, match="not available"):
        lifecycle.list_resource_versions(secret["id"], tenant_id="another")


def test_record_resource_version_refuses_history_rewrite(resource_state: dict[str, Any]) -> None:
    resource = catalog.save_resource(_collector("Immutable", "first"), actor="admin")
    tampered = {**resource, "config": {"collector_profile": "tampered", "transport": "http"}}

    with pytest.raises(lifecycle.ResourceLifecycleError) as exc_info:
        lifecycle.record_resource_version(tampered, actor="attacker")

    assert exc_info.value.code == "immutable_version_conflict"


def test_runtime_resource_has_to_be_duplicated_before_version_operations(resource_state: dict[str, Any]) -> None:
    resource_state["runtime"].append(
        {
            "id": "runtime-collector-only",
            "name": "Runtime only",
            "kind": "collector",
            "status": "active",
            "version": 1,
            "origin": "sentinel-runtime",
            "tenant_id": "main",
            "config": {"collector_profile": "runtime", "transport": "http"},
            "bindings": {},
            "read_only": True,
        }
    )

    with pytest.raises(lifecycle.ResourceLifecycleError) as exc_info:
        lifecycle.list_resource_versions("runtime-collector-only")

    assert exc_info.value.code == "not_managed"


def test_managed_snapshot_gate_rejects_credentials_hidden_in_url(resource_state: dict[str, Any]) -> None:
    with pytest.raises(lifecycle.ResourceLifecycleError) as exc_info:
        catalog.save_resource(
            {
                "name": "Unsafe storage",
                "kind": "storage",
                "tenant_id": "main",
                "config": {"engine": "s3", "endpoint": "https://user:password@example.invalid/archive"},
                "bindings": {},
            },
            actor="admin",
        )

    assert exc_info.value.code == "secret_gate_failed"
    assert resource_state["resources"] == []
