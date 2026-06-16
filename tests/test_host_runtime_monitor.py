import json
import unittest
from unittest.mock import patch

import deploy.host_runtime_monitor as monitor


class HostRuntimeMonitorTests(unittest.TestCase):
    def test_fallback_target_items_refreshes_hosts_before_they_turn_stale(self) -> None:
        fleet_index = {
            "nextcloud-siem": {
                "vmid": 120,
                "guest_type": "lxc",
                "role": "business-app",
                "ip": "10.20.20.120",
                "state": "onboardable",
                "monitoring_enabled": True,
            }
        }
        targets = [{"host_name": "nextcloud-siem", "host_role": "business-app", "host_ip": "10.20.20.120"}]
        last_seen = {"nextcloud-siem": "2026-04-10T06:00:00Z"}

        with (
            patch.object(monitor, "proxmox_guest_exec_configured", return_value=True),
            patch.object(monitor, "_fleet_guest_index", return_value=fleet_index),
            patch.object(monitor, "time", autospec=True) as fake_time,
        ):
            fake_time.time.return_value = 1_775_801_100  # 2026-04-10T06:05:00Z
            items = monitor._fallback_target_items(targets, last_seen, stale_after_seconds=420)

        self.assertEqual(1, len(items))
        self.assertEqual("nextcloud-siem", items[0]["host_name"])
        self.assertEqual(120, items[0]["vmid"])

    def test_main_collects_fallback_snapshot_before_stale_detection(self) -> None:
        snapshot = {
            "generated_ts": "2026-04-07T11:30:00Z",
            "host_name": "nextcloud-siem",
            "host_role": "business-app",
            "primary_ip": "10.20.20.120",
            "metrics": {"cpu_pct": 12.0},
            "services": [],
        }
        posted: list[list[dict]] = []

        with (
            patch.object(monitor, "host_runtime_targets_from_env", return_value=[{"host_name": "nextcloud-siem", "host_role": "business-app", "host_ip": "10.20.20.120"}]),
            patch.object(monitor, "fetch_host_runtime_last_seen_map", return_value={}),
            patch.object(monitor, "load_state", return_value={"hosts": {}, "services": {}, "stale": {}}),
            patch.object(monitor, "_fallback_target_items", return_value=[{"host_name": "nextcloud-siem", "host_role": "business-app", "host_ip": "10.20.20.120", "vmid": 120, "guest_type": "lxc"}]),
            patch.object(monitor, "_collect_guest_snapshot", return_value=snapshot),
            patch.object(monitor, "evaluate_snapshot", return_value=([], {"hosts": {}, "services": {}, "stale": {}})),
            patch.object(monitor, "build_snapshot_event", side_effect=lambda current: {"event.type": "host_runtime_snapshot", "host.name": current["host_name"]}),
            patch.object(monitor, "build_stale_events", return_value=([], {"hosts": {}, "services": {}, "stale": {}})),
            patch.object(monitor, "save_state"),
            patch.object(monitor, "_post_events", side_effect=lambda events: posted.append(events) or {"status": "ok", "ingested": len(events)}),
        ):
            result = monitor.main()

        self.assertEqual(0, result)
        self.assertEqual(1, len(posted))
        self.assertEqual("host_runtime_snapshot", posted[0][0]["event.type"])


if __name__ == "__main__":
    unittest.main()
