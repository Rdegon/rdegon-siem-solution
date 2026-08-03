from __future__ import annotations

import os
from types import SimpleNamespace

import pytest

os.environ.setdefault("SIEM_CH_HOST", "127.0.0.1")
os.environ.setdefault("SIEM_CH_USER", "default")
os.environ.setdefault("SIEM_CH_PASSWORD", "test")
os.environ.setdefault("SIEM_JWT_SECRET", "test-jwt-secret")
os.environ.setdefault("SIEM_ADMIN_DEFAULT_PASSWORD", "test-admin-password")

from app import active_list_runtime


def item(**overrides):
    return {
        "list_name": "vip_admins",
        "list_kind": "watch",
        "item_type": "user",
        "item_value": "operator",
        "item_label": "SOC operator",
        "tags": ["vip"],
        **overrides,
    }


def test_import_is_dry_run_by_default_and_deduplicates(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(active_list_runtime.deps, "save_active_list_item", lambda **_: pytest.fail("dry-run wrote data"))
    result = active_list_runtime.import_active_items({"items": [item(), item()]}, actor="tester")
    assert result == {"status": "validated", "dry_run": True, "rows": 1, "duplicates_removed": 1}


def test_save_validates_names_and_audits(monkeypatch: pytest.MonkeyPatch) -> None:
    saved = []
    audits = []
    monkeypatch.setattr(active_list_runtime.deps, "save_active_list_item", lambda **kwargs: saved.append(kwargs) or kwargs)
    monkeypatch.setattr(active_list_runtime, "append_audit_event", lambda **kwargs: audits.append(kwargs) or kwargs)
    result = active_list_runtime.save_active_item(item(), actor="tester")
    assert result["enabled"] is True
    assert saved[0]["list_name"] == "vip_admins"
    assert audits[0]["action"] == "active_list.item.saved"
    with pytest.raises(ValueError, match="name"):
        active_list_runtime.save_active_item(item(list_name="bad list"), actor="tester")


def test_delete_uses_quoted_composite_key(monkeypatch: pytest.MonkeyPatch) -> None:
    commands = []
    audits = []
    client = SimpleNamespace(command=lambda query, **kwargs: commands.append((query, kwargs)))
    monkeypatch.setattr(active_list_runtime.deps, "ensure_active_list_support", lambda: None)
    monkeypatch.setattr(active_list_runtime.deps, "get_ch_client", lambda: client)
    monkeypatch.setattr(active_list_runtime, "append_audit_event", lambda **kwargs: audits.append(kwargs) or kwargs)
    result = active_list_runtime.delete_active_item(item(item_value="o'reilly"), actor="tester")
    assert result["status"] == "deleted"
    assert "o''reilly" in commands[0][0]
    assert commands[0][1]["settings"]["mutations_sync"] == 1
    assert audits[0]["action"] == "active_list.item.deleted"


def test_csv_export_has_no_json_payload(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(active_list_runtime, "list_active_items", lambda **_: [item(updated_ts="2026-08-03T00:00:00Z", enabled=True)])
    content, media_type, filename = active_list_runtime.export_active_items(output_format="csv")
    assert filename == "active-lists.csv"
    assert media_type.startswith("text/csv")
    assert b"vip_admins" in content


def test_committed_import_preserves_disabled_state(monkeypatch: pytest.MonkeyPatch) -> None:
    saved = []
    enabled = []
    audits = []
    monkeypatch.setattr(active_list_runtime.deps, "save_active_list_item", lambda **kwargs: saved.append(kwargs) or kwargs)
    monkeypatch.setattr(active_list_runtime, "_set_enabled", lambda value, state: enabled.append((value, state)))
    monkeypatch.setattr(active_list_runtime, "append_audit_event", lambda **kwargs: audits.append(kwargs) or kwargs)

    result = active_list_runtime.import_active_items(
        {"items": [item(enabled=False)], "dry_run": False},
        actor="tester",
    )

    assert result["status"] == "imported"
    assert len(saved) == 1
    assert enabled[0][1] is False
    assert audits[0]["action"] == "active_list.imported"
