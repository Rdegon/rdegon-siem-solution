import unittest
from unittest.mock import patch

import proxmox_fleet_runtime as runtime
import vuln_store


class ProxmoxFleetRuntimeTests(unittest.TestCase):
    def test_sync_inventory_builds_states_and_metrics(self) -> None:
        saved_rows: dict[str, list[dict[str, object]]] = {}
        resources = {
            "data": [
                {"type": "qemu", "vmid": "123", "name": "pilot-web-01", "node": "pve", "status": "running", "cpu": 0.2, "mem": 256, "maxmem": 1024},
                {"type": "qemu", "vmid": "126", "name": "openclaw-gateway", "node": "pve", "status": "running", "cpu": 0.5, "mem": 512, "maxmem": 2048},
                {"type": "lxc", "vmid": "125", "name": "pilot-cache-01", "node": "pve", "status": "stopped", "cpu": 0.0, "mem": 0, "maxmem": 1024},
            ]
        }

        with patch("proxmox_fleet_runtime.proxmox_is_configured", return_value=True):
            with patch("proxmox_fleet_runtime._proxmox_request", return_value=resources):
                with patch("proxmox_fleet_runtime._resolve_qemu_ips", side_effect=lambda _node, vmid: ["10.20.30.126"] if vmid == "126" else ["10.20.30.123"]):
                    with patch("proxmox_fleet_runtime._last_seen_map", return_value={"openclaw-gateway": "2026-03-28T10:00:00Z"}):
                        with patch("proxmox_fleet_runtime._cmdb_index", return_value={}):
                            with patch("proxmox_fleet_runtime._save_rows", side_effect=lambda name, rows: saved_rows.__setitem__(name, rows)):
                                payload = runtime.sync_proxmox_fleet_inventory(
                                    actor="tester",
                                    connected_sources=[{"source_name": "openclaw-gateway"}],
                                )

        items = list(payload["items"])
        self.assertEqual(3, len(items))
        openclaw = next(item for item in items if item["name"] == "openclaw-gateway")
        pilot = next(item for item in items if item["name"] == "pilot-web-01")
        cache = next(item for item in items if item["name"] == "pilot-cache-01")
        self.assertEqual("connected", openclaw["state"])
        self.assertEqual("onboardable", pilot["state"])
        self.assertEqual("offline", cache["state"])
        self.assertFalse(bool(openclaw["host_runtime_enabled"]))
        self.assertEqual(1, int(payload["metrics"]["connected"]))
        self.assertEqual(1, int(payload["metrics"]["onboardable"]))
        self.assertEqual(1, int(payload["metrics"]["offline"]))
        self.assertIn(runtime.PROXMOX_FLEET_COLLECTION, saved_rows)

    def test_sync_to_cmdb_upserts_scannable_assets(self) -> None:
        saved_assets: list[dict[str, object]] = []
        fleet_payload = {
            "items": [
                {
                    "asset_id": "",
                    "name": "pilot-web-01",
                    "hostname": "pilot-web-01",
                    "ip": "10.20.30.123",
                    "guest_type": "lxc",
                    "criticality": "medium",
                    "business_service": "Pilot collaboration web service",
                    "os_family": "linux",
                    "vuln_scannable": True,
                    "tags": ["proxmox-fleet", "pilot"],
                    "state": "connected",
                }
            ]
        }

        with patch("proxmox_fleet_runtime.list_proxmox_fleet_inventory", return_value=fleet_payload):
            with patch("proxmox_fleet_runtime._save_rows"):
                with patch("vuln_store.fetch_cmdb_assets", return_value=[]):
                    with patch(
                        "vuln_store.save_cmdb_assets",
                        side_effect=lambda items: saved_assets.extend(items) or items,
                    ):
                        result = runtime.sync_proxmox_fleet_to_cmdb(actor="tester")

        self.assertEqual("ok", result["status"])
        self.assertEqual(1, result["created"])
        self.assertEqual(1, len(saved_assets))
        self.assertEqual("pilot-web-01", saved_assets[0]["hostname"])
        self.assertTrue(bool(saved_assets[0]["vuln_enabled"]))

    def test_sync_to_cmdb_refreshes_existing_ip_and_hostname(self) -> None:
        saved_assets: list[dict[str, object]] = []
        fleet_payload = {
            "items": [
                {
                    "asset_id": "asset-pilot-db-01",
                    "name": "pilot-db-01",
                    "hostname": "pilot-db-01",
                    "ip": "10.20.30.124",
                    "guest_type": "qemu",
                    "criticality": "medium",
                    "business_service": "Pilot data service",
                    "os_family": "linux",
                    "vuln_scannable": True,
                    "tags": ["proxmox-fleet", "pilot"],
                    "state": "connected",
                }
            ]
        }
        existing_assets = [
            {
                "asset_id": "asset-pilot-db-01",
                "hostname": "pilot-db-01",
                "ip": "192.168.1.232",
                "asset_type": "server",
                "owner": "soc-fleet",
                "criticality": "medium",
                "environment": "lab",
                "business_service": "Pilot data service",
                "os_family": "linux",
                "tags": ["pilot"],
                "notes": "Managed by Proxmox fleet sync.",
            }
        ]

        with patch("proxmox_fleet_runtime.list_proxmox_fleet_inventory", return_value=fleet_payload):
            with patch("proxmox_fleet_runtime._save_rows"):
                with patch("vuln_store.fetch_cmdb_assets", return_value=existing_assets):
                    with patch(
                        "vuln_store.save_cmdb_assets",
                        side_effect=lambda items: saved_assets.extend(items) or items,
                    ):
                        result = runtime.sync_proxmox_fleet_to_cmdb(actor="tester")

        self.assertEqual("ok", result["status"])
        self.assertEqual(1, result["updated"])
        self.assertEqual(1, len(saved_assets))
        self.assertEqual("pilot-db-01", saved_assets[0]["hostname"])
        self.assertEqual("10.20.30.124", saved_assets[0]["ip"])
        self.assertTrue(bool(saved_assets[0]["vuln_enabled"]))

    def test_build_vuln_coverage_uses_ts_last_and_targets(self) -> None:
        fleet_payload = {
            "items": [
                {"asset_id": "asset-openclaw", "name": "openclaw-gateway", "hostname": "openclaw-gateway", "ip": "10.20.30.126", "reachable": True, "vuln_scannable": True, "state": "connected"},
                {"asset_id": "asset-gitea", "name": "pilot-web-01", "hostname": "pilot-web-01", "ip": "10.20.30.123", "reachable": True, "vuln_scannable": True, "state": "onboardable"},
                {"asset_id": "", "name": "pilot-db-01", "hostname": "pilot-db-01", "ip": "", "reachable": False, "vuln_scannable": False, "state": "inventory-only"},
                {"asset_id": "asset-cache", "name": "pilot-cache-01", "hostname": "pilot-cache-01", "ip": "10.20.30.125", "reachable": False, "vuln_scannable": False, "state": "offline"},
            ]
        }
        reports = [
            {"report_id": "r1", "ts_last": "2026-03-28T09:00:00Z", "targets": ["openclaw-gateway", "10.20.30.123"]},
        ]

        with patch("proxmox_fleet_runtime.list_proxmox_fleet_inventory", return_value=fleet_payload):
            with patch("vuln_store.fetch_vulnerability_reports", return_value=reports):
                payload = runtime.build_proxmox_fleet_vuln_coverage(days=30)

        self.assertEqual(4, payload["total_guests"])
        self.assertEqual(2, payload["reachable_guests"])
        self.assertEqual(2, payload["scannable_guests"])
        self.assertEqual(2, payload["recently_scanned_guests"])
        self.assertEqual(1, payload["offline_guests"])
        self.assertEqual(1, payload["unresolved_guests"])
        self.assertEqual("2026-03-28T09:00:00Z", payload["last_successful_import"])

    def test_host_runtime_targets_from_fleet_excludes_unsupported_monitoring_rows(self) -> None:
        fleet_payload = {
            "items": [
                {"source_name": "nextcloud-siem", "name": "nextcloud-siem", "role": "business-app", "ip": "10.20.20.120", "state": "connected", "host_runtime_enabled": True, "monitoring_supported": True},
                {"source_name": "opnsense-edge-01", "name": "opnsense-edge-01", "role": "edge-router", "ip": "192.168.1.102", "state": "connected", "host_runtime_enabled": True, "monitoring_supported": False},
            ]
        }

        with patch("proxmox_fleet_runtime.list_proxmox_fleet_inventory", return_value=fleet_payload):
            targets = runtime.host_runtime_targets_from_fleet()

        self.assertEqual([{"host_name": "nextcloud-siem", "host_role": "business-app", "host_ip": "10.20.20.120"}], targets)


if __name__ == "__main__":
    unittest.main()
