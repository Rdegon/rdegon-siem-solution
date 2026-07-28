from pathlib import Path
import sys
import types
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

if "paramiko" not in sys.modules:
    sys.modules["paramiko"] = types.SimpleNamespace(SSHClient=object, AutoAddPolicy=object)

from deploy.homelab_watchdog import (
    _collect_critical_ingest_state,
    _default_vm2_dns_runner_state,
    _ensure_service_bundle,
    _ensure_vm2_available,
    _parse_info_section,
    _processing_stalled,
    _query_vm2_dns_runner_state,
    _runner_status_or_api_error,
    _restart_vm2_processing_bundle,
    _vm5_service_units_clause,
    _vm2_service_units_clause,
    parse_bool_flag,
    parse_qm_status,
    parse_runner_status,
    parse_systemctl_states,
    service_state_is_inactive,
)


class HomelabWatchdogTests(unittest.TestCase):
    def test_parse_qm_status_from_standard_output(self) -> None:
        self.assertEqual(parse_qm_status("status: running\n"), "running")

    def test_parse_qm_status_from_single_token_output(self) -> None:
        self.assertEqual(parse_qm_status("stopped\n"), "stopped")

    def test_parse_systemctl_states_keeps_only_nonempty_lines(self) -> None:
        self.assertEqual(parse_systemctl_states("active\n\nactive\r\nfailed\n"), ["active", "active", "failed"])

    def test_service_bundle_restarts_only_unhealthy_units(self) -> None:
        module = sys.modules["deploy.homelab_watchdog"]
        original_run = module._run_command
        original_sleep = module.time.sleep
        commands: list[str] = []
        responses = iter(
            (
                (3, "active\ninactive\nactive\n", ""),
                (1, "", ""),
                (0, "", ""),
                (0, "active\nactive\nactive\n", ""),
            )
        )

        def fake_run(_client: object, command: str, **_kwargs: object) -> tuple[int, str, str]:
            commands.append(command)
            return next(responses)

        try:
            module._run_command = fake_run
            module.time.sleep = lambda _seconds: None
            states = _ensure_service_bundle(
                object(),
                ["clickhouse-server", "siem-writer", "siem-stream-corr"],
                sudo_password="secret",
                restart_bundle="systemctl restart clickhouse-server siem-writer siem-stream-corr",
            )
        finally:
            module._run_command = original_run
            module.time.sleep = original_sleep

        self.assertEqual(states, ["active", "active", "active"])
        self.assertEqual(commands[2], "systemctl restart siem-writer")

    def test_service_bundle_respects_maintenance_marker(self) -> None:
        module = sys.modules["deploy.homelab_watchdog"]
        original_run = module._run_command
        commands: list[str] = []
        responses = iter(
            (
                (3, "active\ninactive\n", ""),
                (0, "", ""),
            )
        )

        def fake_run(_client: object, command: str, **_kwargs: object) -> tuple[int, str, str]:
            commands.append(command)
            return next(responses)

        try:
            module._run_command = fake_run
            states = _ensure_service_bundle(
                object(),
                ["clickhouse-server", "siem-writer"],
                sudo_password="secret",
                restart_bundle="systemctl restart clickhouse-server siem-writer",
            )
        finally:
            module._run_command = original_run

        self.assertEqual(states, ["active", "inactive"])
        self.assertEqual(commands[-1], "test -e /run/siem-maintenance")

    def test_service_state_is_inactive_accepts_non_running_states(self) -> None:
        self.assertTrue(service_state_is_inactive("inactive"))
        self.assertTrue(service_state_is_inactive("unknown"))
        self.assertFalse(service_state_is_inactive("active"))

    def test_parse_bool_flag_accepts_trueish_values(self) -> None:
        self.assertTrue(parse_bool_flag("PONG"))
        self.assertTrue(parse_bool_flag("true"))
        self.assertFalse(parse_bool_flag("no"))

    def test_parse_info_section_ignores_comments(self) -> None:
        payload = _parse_info_section("# Persistence\nloading:0\naof_enabled:1\n")
        self.assertEqual(payload["loading"], "0")
        self.assertEqual(payload["aof_enabled"], "1")

    def test_parse_runner_status_returns_online_and_busy(self) -> None:
        status, busy = parse_runner_status(
            {
                "runners": [
                    {"name": "siem-vm1", "status": "online", "busy": False},
                    {"name": "siem-vm2", "status": "online", "busy": True},
                ]
            },
            "siem-vm2",
        )
        self.assertEqual(status, "online")
        self.assertTrue(busy)

    def test_parse_runner_status_returns_missing_for_unknown_runner(self) -> None:
        status, busy = parse_runner_status({"runners": [{"name": "siem-vm1", "status": "online", "busy": False}]}, "siem-vm2")
        self.assertEqual(status, "missing")
        self.assertFalse(busy)

    def test_processing_stalled_when_transport_is_not_kafka(self) -> None:
        self.assertTrue(
            _processing_stalled(
                {"transport_backend": "redis", "consumer_backend": "redis", "kafka_bootstrap_servers": [], "kafka_expected_brokers": 3},
                minimum_events_5m=1,
                events_5m=10,
            )
        )

    def test_processing_stalled_when_flow_is_zero(self) -> None:
        self.assertTrue(
            _processing_stalled(
                {
                    "transport_backend": "kafka",
                    "consumer_backend": "kafka",
                    "kafka_bootstrap_servers": ["192.168.1.35:9092", "192.168.1.37:9092", "192.168.1.40:9092"],
                    "kafka_expected_brokers": 3,
                },
                minimum_events_5m=1,
                events_5m=0,
            )
        )

    def test_processing_not_stalled_when_flow_is_present(self) -> None:
        self.assertFalse(
            _processing_stalled(
                {
                    "transport_backend": "kafka",
                    "consumer_backend": "kafka",
                    "kafka_bootstrap_servers": ["192.168.1.35:9092", "192.168.1.37:9092", "192.168.1.40:9092"],
                    "kafka_expected_brokers": 3,
                },
                minimum_events_5m=1,
                events_5m=5,
            )
        )

    def test_collect_critical_ingest_state_accepts_edge_source_as_vpn_path(self) -> None:
        state = _collect_critical_ingest_state(
            sources={
                "items": [
                    {"collector_profile": "app", "source_alias": "pve", "status": "healthy"},
                    {"collector_profile": "linux-auth", "source_alias": "opnsense-edge-01", "id": "192.168.1.102", "status": "healthy"},
                ]
            },
            collectors={
                "items": [
                    {"collector_profile": "app", "status": "healthy"},
                    {"collector_profile": "linux-auth", "status": "healthy"},
                    {"collector_profile": "linux-audit", "status": "healthy"},
                ]
            },
        )
        self.assertTrue(state["healthy"])
        self.assertEqual([], state["problems"])
        self.assertEqual("healthy", state["edge_status"])

    def test_collect_critical_ingest_state_accepts_pve_linux_auth_after_relocation(self) -> None:
        state = _collect_critical_ingest_state(
            sources={
                "items": [
                    {"collector_profile": "linux-auth", "source_alias": "pve", "status": "healthy"},
                    {"collector_profile": "linux-auth", "source_alias": "opnsense-edge-01", "status": "healthy"},
                ]
            },
            collectors={
                "items": [
                    {"collector_profile": "app", "status": "healthy"},
                    {"collector_profile": "linux-auth", "status": "healthy"},
                    {"collector_profile": "linux-audit", "status": "healthy"},
                ]
            },
        )

        self.assertTrue(state["healthy"])
        self.assertEqual("healthy", state["pve_source_status"])
        self.assertEqual([], state["problems"])

    def test_collect_critical_ingest_state_prefers_healthy_relocated_sources(self) -> None:
        state = _collect_critical_ingest_state(
            sources={
                "items": [
                    {
                        "collector_profile": "app",
                        "source_alias": "pve",
                        "id": "192.168.1.101",
                        "status": "stale",
                        "seconds_since_last_seen": 3600,
                    },
                    {
                        "collector_profile": "app",
                        "source_alias": "192.168.3.101",
                        "id": "192.168.3.101",
                        "status": "healthy",
                        "seconds_since_last_seen": 3,
                    },
                    {
                        "collector_profile": "linux-auth",
                        "source_alias": "192.168.3.102",
                        "id": "192.168.1.102",
                        "status": "stale",
                        "seconds_since_last_seen": 3600,
                    },
                    {
                        "collector_profile": "linux-auth",
                        "source_alias": "lab-edge-01",
                        "id": "192.168.3.102",
                        "status": "healthy",
                        "seconds_since_last_seen": 2,
                    },
                ]
            },
            collectors={
                "items": [
                    {"collector_profile": "app", "status": "healthy"},
                    {"collector_profile": "linux-auth", "status": "healthy"},
                    {"collector_profile": "linux-audit", "status": "healthy"},
                ]
            },
        )
        self.assertTrue(state["healthy"])
        self.assertEqual("healthy", state["pve_app_status"])
        self.assertEqual("healthy", state["edge_status"])

    def test_collect_critical_ingest_state_flags_missing_vpn_path(self) -> None:
        state = _collect_critical_ingest_state(
            sources={"items": [{"collector_profile": "app", "source_alias": "pve", "status": "healthy"}]},
            collectors={
                "items": [
                    {"collector_profile": "app", "status": "healthy"},
                    {"collector_profile": "linux-auth", "status": "healthy"},
                    {"collector_profile": "linux-audit", "status": "healthy"},
                ]
            },
        )
        self.assertFalse(state["healthy"])
        self.assertIn("source:vpn-path:vpn=missing edge=missing", state["problems"])

    def test_default_vm2_dns_runner_state_marks_hosts_unhealthy(self) -> None:
        state = _default_vm2_dns_runner_state(query_error="probe failed")
        self.assertFalse(state["runner_active"])
        self.assertEqual(state["query_error"], "probe failed")
        self.assertTrue(all(not state[f"resolve::{host}"] for host in (
            "github.com",
            "broker.actions.githubusercontent.com",
            "pipelinesghubeus9.actions.githubusercontent.com",
        )))

    def test_vm2_service_units_clause_excludes_redis_and_sentinel(self) -> None:
        clause = _vm2_service_units_clause()
        self.assertNotIn("redis-server", clause)
        self.assertNotIn("siem-redis-sentinel", clause)

    def test_vm5_service_units_clause_can_include_kafka(self) -> None:
        clause = _vm5_service_units_clause(include_kafka=True)
        self.assertIn("siem-kafka", clause)
        self.assertIn("siem-vm5.service", clause)

    def test_runner_status_or_api_error_returns_degraded_state(self) -> None:
        module = sys.modules["deploy.homelab_watchdog"]
        original_wait = module._wait_for_runner_online

        def fake_wait(*_args: object, **_kwargs: object) -> tuple[str, bool]:
            raise RuntimeError("HTTP Error 403: Forbidden")

        try:
            module._wait_for_runner_online = fake_wait
            status, busy, error = _runner_status_or_api_error("repo/name", "token", "siem-vm5")
        finally:
            module._wait_for_runner_online = original_wait

        self.assertEqual(status, "unknown")
        self.assertFalse(busy)
        self.assertIn("403", error)

    def test_query_vm2_dns_runner_state_retries_and_returns_fallback(self) -> None:
        module = sys.modules["deploy.homelab_watchdog"]
        original_exec = module._qm_guest_exec_text
        original_sleep = module.time.sleep
        calls: list[str] = []

        def fake_exec(_proxmox: object, _vmid: str, _command: str) -> str:
            calls.append("x")
            return ""

        try:
            module._qm_guest_exec_text = fake_exec
            module.time.sleep = lambda _seconds: None
            state = _query_vm2_dns_runner_state(object(), "105")
        finally:
            module._qm_guest_exec_text = original_exec
            module.time.sleep = original_sleep

        self.assertEqual(len(calls), 3)
        self.assertFalse(state["runner_active"])
        self.assertIn("query_error", state)

    def test_ensure_vm2_available_accepts_live_guest_agent_even_without_service_listing(self) -> None:
        module = sys.modules["deploy.homelab_watchdog"]
        original_qm_status = module._qm_status
        original_guest_exec = module._qm_guest_exec_json
        original_sleep = module.time.sleep

        def fake_status(_proxmox: object, _vmid: str) -> str:
            return "running"

        def fake_guest_exec(_proxmox: object, _vmid: str, _command: str) -> dict[str, object]:
            return {"exitcode": 0, "out-data": ""}

        try:
            module._qm_status = fake_status
            module._qm_guest_exec_json = fake_guest_exec
            module.time.sleep = lambda _seconds: None
            payload = _ensure_vm2_available(object(), "105")
        finally:
            module._qm_status = original_qm_status
            module._qm_guest_exec_json = original_guest_exec
            module.time.sleep = original_sleep

        self.assertEqual(payload["exitcode"], 0)

    def test_restart_vm2_processing_bundle_retries_until_services_turn_active(self) -> None:
        module = sys.modules["deploy.homelab_watchdog"]
        original_exec_json = module._qm_guest_exec_json
        original_exec_text = module._qm_guest_exec_text
        original_sleep = module.time.sleep
        probe_calls: list[int] = []

        def fake_exec_json(_proxmox: object, _vmid: str, _command: str) -> dict[str, object]:
            return {"exitcode": 0}

        def fake_exec_text(_proxmox: object, _vmid: str, _command: str) -> str:
            probe_calls.append(1)
            if len(probe_calls) == 1:
                return "activating\nactive\nactivating\nactive\nactive\nactive\n"
            return "active\nactive\nactive\nactive\nactive\nactive\n"

        try:
            module._qm_guest_exec_json = fake_exec_json
            module._qm_guest_exec_text = fake_exec_text
            module.time.sleep = lambda _seconds: None
            payload = _restart_vm2_processing_bundle(object(), "105")
        finally:
            module._qm_guest_exec_json = original_exec_json
            module._qm_guest_exec_text = original_exec_text
            module.time.sleep = original_sleep

        self.assertEqual(payload["attempts"], 2)
        self.assertEqual(len(probe_calls), 2)
        self.assertNotIn("redis-server", payload["unit_clause"])


if __name__ == "__main__":
    unittest.main()
