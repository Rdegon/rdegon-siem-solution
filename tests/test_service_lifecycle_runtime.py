from __future__ import annotations

from unittest.mock import patch

import pytest

from services.web.app import service_lifecycle_runtime as runtime


def _live_status(*, active: str = "active", can_reload: bool = False) -> dict:
    return {
        "load_state": "loaded",
        "active_state": active,
        "sub_state": "running" if active == "active" else "dead",
        "result": "success",
        "unit_file_state": "enabled",
        "can_reload": can_reload,
        "restarts": 0,
        "version": "2026.08",
        "source": "systemd_live",
    }


def _fleet() -> dict[int, dict]:
    return {
        vmid: {"vmid": str(vmid), "running": True, "state": "connected", "guest_type": "qemu", "ip": f"10.20.10.{vmid}"}
        for vmid in {104, 105, 106, 107, 108}
    }


def test_registry_merges_live_systemd_runtime_metrics_and_fleet() -> None:
    targets = {
        "siem-storage": {
            "host_name": "siem-storage",
            "host_ip": "10.20.10.106",
            "last_seen_ts": "2026-08-03T10:00:00Z",
            "stale": False,
            "snapshot": {"metrics": {"output_eps": 812.5, "consumer_lag": 7}},
        }
    }
    statuses = {"writer-primary": _live_status(can_reload=True)}
    with (
        patch.object(runtime, "_runtime_targets", return_value=targets),
        patch.object(runtime, "_fleet_items", return_value=_fleet()),
        patch.object(runtime, "_live_statuses", return_value=(statuses, {})),
        patch.object(runtime, "proxmox_guest_exec_configured", return_value=True),
    ):
        payload = runtime.list_service_instances(refresh_live=True)
    writer = next(item for item in payload["items"] if item["instance_id"] == "writer-primary")
    assert writer["active_state"] == "active"
    assert writer["status_source"] == "systemd_live"
    assert writer["node_ip"] == "10.20.10.106"
    assert writer["eps"] == 812.5
    assert writer["lag"] == 7
    assert writer["version"] == "2026.08"
    assert writer["capabilities"] == ["stop", "restart", "reload"]


def test_unavailable_adapter_is_strictly_read_only() -> None:
    with (
        patch.object(runtime, "_runtime_targets", return_value={}),
        patch.object(runtime, "_fleet_items", return_value=_fleet()),
        patch.object(runtime, "proxmox_guest_exec_configured", return_value=False),
    ):
        payload = runtime.list_service_instances(refresh_live=False)
    assert payload["items"]
    assert all(item["management_state"] == "read_only" for item in payload["items"])
    assert all(item["capabilities"] == [] for item in payload["items"])


def test_systemd_parser_does_not_invent_version_or_capabilities() -> None:
    parsed = runtime._parse_systemd_show(
        "Id=siem-writer.service\nLoadState=loaded\nActiveState=active\nSubState=running\n"
        "Result=success\nUnitFileState=enabled\nDescription=Writer\nCanReload=no\nNRestarts=2\nEnvironment=FOO=bar\n"
    )
    assert parsed["siem-writer.service"]["version"] == ""
    assert parsed["siem-writer.service"]["can_reload"] is False
    assert parsed["siem-writer.service"]["restarts"] == 2


def test_action_uses_allowlisted_unit_verifies_and_is_idempotent() -> None:
    rows: list[dict] = []

    def load_rows() -> list[dict]:
        return [dict(item) for item in rows]

    def save_rows(next_rows: list[dict]) -> None:
        rows[:] = [dict(item) for item in next_rows]

    statuses = [_live_status(), _live_status()]
    with (
        patch.object(runtime, "_load_idempotency_rows", side_effect=load_rows),
        patch.object(runtime, "_save_idempotency_rows", side_effect=save_rows),
        patch.object(runtime, "proxmox_guest_exec_configured", return_value=True),
        patch.object(runtime, "_fleet_items", return_value=_fleet()),
        patch.object(runtime, "_single_live_status", side_effect=statuses),
        patch.object(runtime, "guest_exec", return_value="") as guest_exec,
        patch.object(runtime, "append_audit_event") as audit,
    ):
        first = runtime.execute_service_action(
            "writer-primary",
            "restart",
            actor="operator",
            idempotency_key="test:writer:restart:0001",
        )
        second = runtime.execute_service_action(
            "writer-primary",
            "restart",
            actor="operator",
            idempotency_key="test:writer:restart:0001",
        )
    assert first["verified"] is True
    assert second["idempotent_replay"] is True
    guest_exec.assert_called_once_with(106, "qemu", "systemctl restart -- siem-writer.service", timeout=20)
    assert [call.kwargs["action"] for call in audit.call_args_list] == [
        "siem_service.restart.requested",
        "siem_service.restart",
    ]


def test_action_rejects_unknown_instance_before_adapter_execution() -> None:
    with patch.object(runtime, "guest_exec") as guest_exec:
        with pytest.raises(runtime.ServiceLifecycleError) as error:
            runtime.execute_service_action(
                "user-controlled-unit",
                "restart",
                actor="operator",
                idempotency_key="test:unknown:restart:0001",
            )
    assert error.value.code == "instance_not_found"
    guest_exec.assert_not_called()


def test_pending_idempotency_key_never_reexecutes_an_uncertain_action() -> None:
    fingerprint = runtime._idempotency_fingerprint("writer-primary", "restart")
    rows = [{
        "key": "test:writer:pending:0001",
        "fingerprint": fingerprint,
        "instance_id": "writer-primary",
        "action": "restart",
        "status": "pending",
        "created_ts": "2020-01-01T00:00:00Z",
    }]
    with (
        patch.object(runtime, "_load_idempotency_rows", return_value=rows),
        patch.object(runtime, "_save_idempotency_rows"),
        patch.object(runtime, "guest_exec") as guest_exec,
    ):
        with pytest.raises(runtime.ServiceLifecycleError) as error:
            runtime.execute_service_action(
                "writer-primary",
                "restart",
                actor="operator",
                idempotency_key="test:writer:pending:0001",
            )
    assert error.value.code == "action_in_progress"
    guest_exec.assert_not_called()


def test_reload_is_rejected_when_systemd_reports_no_reload_support() -> None:
    rows: list[dict] = []
    with (
        patch.object(runtime, "_load_idempotency_rows", side_effect=lambda: [dict(item) for item in rows]),
        patch.object(runtime, "_save_idempotency_rows", side_effect=lambda value: rows.__setitem__(slice(None), [dict(item) for item in value])),
        patch.object(runtime, "proxmox_guest_exec_configured", return_value=True),
        patch.object(runtime, "_fleet_items", return_value=_fleet()),
        patch.object(runtime, "_single_live_status", return_value=_live_status(can_reload=False)),
        patch.object(runtime, "guest_exec") as guest_exec,
        patch.object(runtime, "append_audit_event"),
    ):
        with pytest.raises(runtime.ServiceLifecycleError) as error:
            runtime.execute_service_action(
                "writer-primary",
                "reload",
                actor="operator",
                idempotency_key="test:writer:reload:0001",
            )
    assert error.value.code == "action_unavailable"
    guest_exec.assert_not_called()
