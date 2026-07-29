import importlib
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
MODULE_DIR = str(ROOT)

if MODULE_DIR not in sys.path:
    sys.path.insert(0, MODULE_DIR)

if "app" not in sys.modules:
    app_module = types.ModuleType("app")
    app_module.__path__ = [MODULE_DIR]  # type: ignore[attr-defined]
    app_module.__file__ = str(ROOT / "__init__.py")
    sys.modules["app"] = app_module

topology_runtime = importlib.import_module("app.topology_runtime")


class TopologyRuntimeTests(unittest.TestCase):
    def test_build_network_topology_links_external_ip_to_protected_target(self) -> None:
        with patch.object(
            topology_runtime,
            "_load_sources",
            return_value=[
                {
                    "source_name": "vpn-host-khanov",
                    "collector_id": "linux-syslog",
                    "status": "active",
                    "events": 1200,
                    "source_type": "linux",
                },
                {
                    "source_name": "siem-web",
                    "collector_id": "linux-syslog",
                    "status": "active",
                    "events": 400,
                    "source_type": "linux",
                }
            ],
        ), patch.object(
            topology_runtime,
            "_load_collectors",
            return_value=[
                {
                    "collector_id": "linux-syslog",
                    "name": "Linux syslog",
                    "status": "active",
                    "events": 1200,
                    "sources_count": 1,
                }
            ],
        ), patch.object(
            topology_runtime,
            "_load_geo_sources",
            return_value=[
                {
                    "ip": "80.66.66.61",
                    "country": "Germany",
                    "events": 2,
                    "target_ips": "176.108.250.215",
                    "target_ports": "6022,6023",
                    "reputation": "protected-target-activity",
                }
            ],
        ), patch.object(
            topology_runtime,
            "_load_discovery",
            return_value={"items": [{"id": "candidate-192-168-1-55", "ip": "192.168.1.55", "connected": False}], "jobs": [], "metrics": {}},
        ), patch.object(
            topology_runtime,
            "_load_fleet",
            return_value={
                "items": [
                    {
                        "id": "vm-101",
                        "name": "siem-web",
                        "source_name": "siem-web",
                        "ip": "192.168.1.39",
                        "role": "control-plane",
                        "connected": True,
                        "reachable": True,
                    },
                    {
                        "id": "vm-102",
                        "name": "opnsense-edge-01",
                        "source_name": "opnsense-edge-01",
                        "ip": "192.168.1.102",
                        "role": "edge-router",
                        "connected": False,
                        "reachable": True,
                    },
                ],
                "metrics": {},
            },
        ), patch.object(
            topology_runtime,
            "_load_host_access_profiles",
            return_value=[
                {
                    "profile_id": "host-access-siem-web",
                    "host_id": "fleet:vm-101",
                    "host_label": "siem-web",
                    "ip": "192.168.1.39",
                    "protocol": "ssh",
                    "port": 22,
                    "username": "rdegon",
                    "secret_status": "reference",
                }
            ],
        ):
            payload = topology_runtime.build_network_topology(hours=24, limit=100)

        self.assertGreaterEqual(payload["metrics"]["nodes"], 1)
        self.assertEqual(1, payload["metrics"]["protected_target_hits"])
        self.assertEqual(1, payload["metrics"]["unmanaged_candidates"])
        self.assertEqual(1, payload["metrics"]["host_access_profiles"])
        self.assertEqual(1, payload["metrics"]["hosts_with_access_profiles"])
        self.assertTrue(any(edge["type"] == "attack_observation" for edge in payload["edges"]))
        protected_node = next(node for node in payload["nodes"] if node["type"] == "protected_public_ip" and node["ip"] == "176.108.250.215")
        self.assertEqual("vpn-host-khanov", protected_node["hostname"])
        self.assertEqual("vpn_host", protected_node["source_kind"])
        external_node = next(node for node in payload["nodes"] if node["type"] == "external_ip" and node["ip"] == "80.66.66.61")
        self.assertEqual("external-80-66-66-61", external_node["hostname"])
        source_node = next(node for node in payload["nodes"] if node["id"] == "source:siem-web")
        self.assertEqual("siem-web", source_node["hostname"])
        self.assertEqual("192.168.1.39", source_node["ip"])
        self.assertEqual("siem_core", source_node["source_kind"])
        router_node = next(node for node in payload["nodes"] if node["id"] == "fleet:vm-102")
        self.assertEqual("virtual_router", router_node["source_kind"])
        self.assertEqual("NGFW / router", router_node["source_type_label"])
        self.assertEqual("opnsense-edge-01", router_node["hostname"])
        self.assertEqual("192.168.3.103", router_node["ip"])
        fleet_node = next(node for node in payload["nodes"] if node["id"] == "fleet:vm-101")
        self.assertEqual(1, fleet_node["access_profile_count"])
        self.assertEqual("configured", fleet_node["access_status"])
        self.assertEqual("host-access-siem-web", payload["host_access_profiles"][0]["profile_id"])
        self.assertGreaterEqual(len(payload["packet_flows"]), 7)
        self.assertEqual("packet-flow-external-edge", payload["packet_flows"][0]["id"])
        self.assertIn("tcp", payload["packet_flows"][0]["protocols"])
        self.assertIn("6022", payload["packet_flows"][0]["ports"])
        self.assertTrue(any(flow["id"] == "packet-flow-discovery" and flow["nodes"] == 1 for flow in payload["packet_flows"]))
        attention_item = next(item for item in payload["attention"] if item["kind"] == "discovery")
        self.assertIn("/app/assets?view=unconnected", attention_item["href"])
        self.assertEqual("legacy", fleet_node["network_segment"])
        self.assertEqual("ip", fleet_node["segment_source"])
        self.assertEqual("mgmt", router_node["network_segment"])
        self.assertEqual("external", external_node["network_segment"])

    def test_all_sources_are_returned_and_auto_segmented(self) -> None:
        sources = [
            {
                "source_name": f"source-{index}",
                "collector_id": "collector-main",
                "status": "active",
                "events": index,
                "ip": f"10.20.20.{index + 1}",
            }
            for index in range(40)
        ]
        sources.append(
            {
                "source_name": "new-game-source",
                "collector_id": "collector-main",
                "status": "active",
                "events": 1,
                "ip": "10.20.20.222",
            }
        )
        with patch.object(
            topology_runtime,
            "_load_sources",
            return_value=sources,
        ), patch.object(
            topology_runtime,
            "_load_collectors",
            return_value=[
                {
                    "collector_id": "collector-main",
                    "name": "Main collector",
                    "status": "active",
                }
            ],
        ), patch.object(
            topology_runtime,
            "_load_geo_sources",
            return_value=[],
        ), patch.object(
            topology_runtime,
            "_load_discovery",
            return_value={"items": [], "jobs": [], "metrics": {}},
        ), patch.object(
            topology_runtime,
            "_load_fleet",
            return_value={"items": [], "metrics": {}},
        ), patch.object(
            topology_runtime,
            "_load_host_access_profiles",
            return_value=[],
        ):
            payload = topology_runtime.build_network_topology(hours=24, limit=300)

        returned_sources = [
            node for node in payload["nodes"] if node["type"] == "source"
        ]
        self.assertEqual(41, len(returned_sources))
        new_source = next(
            node for node in returned_sources if node["id"] == "source:new-game-source"
        )
        self.assertEqual("servers-games", new_source["network_segment"])
        self.assertEqual("10.20.20.0/24", new_source["segment_cidr"])
        self.assertEqual("ip", new_source["segment_source"])
        self.assertEqual(41, payload["metrics"]["monitored_sources"])

    def test_explicit_segment_overrides_ip_classification(self) -> None:
        classified = topology_runtime._network_segment(
            {
                "ip": "10.20.20.45",
                "network_segment": "lab",
                "asset_group": "game",
            }
        )
        self.assertEqual("lab", classified["network_segment"])
        self.assertEqual("explicit", classified["segment_source"])


if __name__ == "__main__":
    unittest.main()
