import unittest

from host_runtime_pipeline import (
    _memory_pressure_status,
    build_snapshot_event,
    build_stale_events,
    evaluate_snapshot,
)


class HostRuntimePipelineTests(unittest.TestCase):
    def test_build_snapshot_event_includes_nested_host_payload(self) -> None:
        event = build_snapshot_event(
            {
                "generated_ts": "2026-03-25T00:00:00Z",
                "host_name": "siem-web",
                "host_role": "control-plane",
                "primary_ip": "192.168.1.39",
                "metrics": {},
                "services": [],
            }
        )

        self.assertEqual("siem-web", event["host.name"])
        self.assertEqual("192.168.1.39", event["host.ip"])
        self.assertEqual({"name": "siem-web", "role": "control-plane", "ip": "192.168.1.39"}, event["host"])

    def test_evaluate_snapshot_emits_pressure_and_service_flapping_events(self) -> None:
        snapshot = {
            "generated_ts": "2026-03-25T00:00:00Z",
            "host_name": "siem-storage",
            "host_role": "storage",
            "primary_ip": "192.168.1.38",
            "metrics": {
                "cpu_pct": 95.0,
                "memory_used_pct": 91.0,
                "disk_used_pct": 92.0,
                "load_ratio": 1.8,
                "swap_used_pct": 25.0,
                "inode_used_pct": 91.0,
            },
            "services": [{"name": "clickhouse-server", "status": "failed"}],
        }
        state = {
            "hosts": {},
            "services": {
                "siem-storage": {
                    "clickhouse-server": {
                        "status": "active",
                        "change_epochs": [100.0, 200.0],
                    }
                }
            },
            "stale": {},
        }

        events, next_state = evaluate_snapshot(snapshot, state, now_epoch=300.0)
        event_types = {item["event.type"] for item in events}

        self.assertIn("host_cpu_pressure", event_types)
        self.assertIn("host_memory_pressure", event_types)
        self.assertIn("host_disk_pressure", event_types)
        self.assertIn("host_load_pressure", event_types)
        self.assertIn("host_swap_pressure", event_types)
        self.assertIn("host_inode_pressure", event_types)
        self.assertIn("host_storage_pressure", event_types)
        self.assertIn("host_service_flapping", event_types)
        self.assertIn("siem-storage", next_state["hosts"])

    def test_build_stale_events_deduplicates_until_recovered(self) -> None:
        expected_hosts = [{"host_name": "siem-web", "host_role": "control-plane", "host_ip": "192.168.1.39"}]
        events, state = build_stale_events(expected_hosts=expected_hosts, last_seen={}, state=None, stale_after_seconds=120, now_epoch=300.0)

        self.assertEqual(1, len(events))
        self.assertEqual("host_telemetry_stale", events[0]["event.type"])

        duplicate_events, state = build_stale_events(expected_hosts=expected_hosts, last_seen={}, state=state, stale_after_seconds=120, now_epoch=360.0)
        self.assertEqual([], duplicate_events)

        recovered_events, state = build_stale_events(
            expected_hosts=expected_hosts,
            last_seen={"siem-web": "2026-03-25T00:10:00Z"},
            state=state,
            stale_after_seconds=120,
            now_epoch=620.0,
        )
        self.assertEqual([], recovered_events)
        self.assertFalse(state["stale"])

    def test_policy_suppresses_duplicate_events_inside_window(self) -> None:
        snapshot = {
            "generated_ts": "2026-03-25T00:00:00Z",
            "host_name": "siem-storage",
            "host_role": "storage",
            "primary_ip": "192.168.1.38",
            "metrics": {"memory_used_pct": 95.0},
            "services": [],
        }
        policy = {"event_overrides": {"host_memory_pressure": {"suppression_seconds": 600, "escalate_after": 2, "severity": "high"}}}

        events_first, state = evaluate_snapshot(snapshot, {}, policy=policy, now_epoch=100.0)
        events_second, _ = evaluate_snapshot(snapshot, state, policy=policy, now_epoch=200.0)

        first_types = [item["event.type"] for item in events_first]
        second_types = [item["event.type"] for item in events_second]

        self.assertIn("host_memory_pressure", first_types)
        self.assertNotIn("host_memory_pressure", second_types)

    def test_policy_escalates_after_repeat_threshold(self) -> None:
        snapshot = {
            "generated_ts": "2026-03-25T00:00:00Z",
            "host_name": "siem-web",
            "host_role": "control-plane",
            "primary_ip": "192.168.1.39",
            "metrics": {"load_ratio": 2.0},
            "services": [],
        }
        policy = {"event_overrides": {"host_load_pressure": {"suppression_seconds": 0, "escalate_after": 2, "severity": "medium"}}}

        first, state = evaluate_snapshot(snapshot, {}, policy=policy, now_epoch=100.0)
        second, _ = evaluate_snapshot(snapshot, state, policy=policy, now_epoch=200.0)

        self.assertEqual("medium", first[0]["severity"])
        self.assertEqual("high", second[0]["severity"])
        self.assertTrue(second[0]["details"]["escalated"])

    def test_cache_heavy_snapshot_does_not_raise_memory_pressure_without_low_available_or_swap(self) -> None:
        snapshot = {
            "generated_ts": "2026-03-25T00:00:00Z",
            "host_name": "siem-storage",
            "host_role": "storage",
            "primary_ip": "192.168.1.38",
            "metrics": {
                "memory_used_pct": 93.0,
                "memory_available_pct": 21.0,
                "memory_cache_pct": 48.0,
                "swap_used_pct": 0.0,
            },
            "services": [],
        }

        events, _ = evaluate_snapshot(snapshot, {}, now_epoch=300.0)
        event_types = {item["event.type"] for item in events}

        self.assertNotIn("host_memory_pressure", event_types)
        self.assertNotIn("host_storage_pressure", event_types)

    def test_generic_load_spike_without_resource_pressure_or_service_failure_is_suppressed(self) -> None:
        snapshot = {
            "generated_ts": "2026-03-25T00:00:00Z",
            "host_name": "navidrome-01",
            "host_role": "media-node",
            "primary_ip": "192.168.1.121",
            "metrics": {
                "cpu_pct": 28.0,
                "memory_used_pct": 61.0,
                "memory_available_pct": 26.0,
                "load_ratio": 1.9,
                "swap_used_pct": 0.0,
                "failed_services_total": 0,
            },
            "services": [],
        }

        events, _ = evaluate_snapshot(snapshot, {}, now_epoch=300.0)
        event_types = {item["event.type"] for item in events}

        self.assertNotIn("host_load_pressure", event_types)

    def test_swap_usage_with_plenty_of_available_memory_is_not_treated_as_pressure(self) -> None:
        status = _memory_pressure_status(
            {
                "memory_used_pct": 19.8,
                "memory_available_pct": 80.2,
                "swap_used_pct": 9.7,
                "memory_available_bytes": 11420320 * 1024,
            },
            "transport",
        )

        self.assertEqual("healthy", status)

    def test_clean_active_inactive_restart_does_not_count_as_service_flapping(self) -> None:
        snapshot = {
            "generated_ts": "2026-03-25T00:00:00Z",
            "host_name": "siem-ingest",
            "host_role": "ingest",
            "primary_ip": "192.168.1.35",
            "metrics": {},
            "services": [{"name": "nginx", "status": "inactive"}],
        }
        state = {
            "hosts": {},
            "services": {
                "siem-ingest": {
                    "nginx": {
                        "status": "active",
                        "change_epochs": [100.0, 200.0],
                    }
                }
            },
            "stale": {},
        }

        events, next_state = evaluate_snapshot(snapshot, state, now_epoch=300.0)

        self.assertNotIn("host_service_flapping", {item["event.type"] for item in events})
        self.assertEqual([100.0, 200.0], next_state["services"]["siem-ingest"]["nginx"]["change_epochs"])


if __name__ == "__main__":
    unittest.main()
