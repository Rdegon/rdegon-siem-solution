import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "deploy" / "security" / "suricata" / "configure_lab_edge_ids.py"
SPEC = importlib.util.spec_from_file_location("configure_lab_edge_ids", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class SuricataSegmentConfigTests(unittest.TestCase):
    def test_rewrite_adds_every_segment_and_capture_interface(self) -> None:
        source = """vars:
  address-groups:
    HOME_NET: "[10.20.30.0/24]"
af-packet:
  - interface: eth1
    cluster-id: 99
af-xdp:
  - interface: default
outputs:
  - eve-log:
      types:
        - alert
        - flow
# threshold-file: /etc/suricata/threshold.config
"""

        rewritten = MODULE.rewrite_config(source)

        for network in MODULE.HOME_NETWORKS:
            self.assertIn(network, rewritten)
        for interface in MODULE.DEFAULT_INTERFACES:
            self.assertIn(f"- interface: {interface}", rewritten)
        self.assertNotIn("cluster-id: 99", rewritten)
        self.assertEqual(5, rewritten.count("threads: 1"))
        self.assertEqual(5, rewritten.count("checksum-checks: no"))
        self.assertIn("threshold-file: /etc/suricata/threshold.config", rewritten)
        self.assertNotIn("\n        - flow\n", rewritten)
        self.assertIn("Disabled: retain packet inspection", rewritten)

    def test_rewrite_requires_home_net_and_af_packet_boundaries(self) -> None:
        with self.assertRaises(ValueError):
            MODULE.rewrite_config("af-packet:\naf-xdp:\n")

    def test_threshold_rewrite_manages_only_infrastructure_noise(self) -> None:
        rewritten = MODULE.rewrite_threshold_config("# existing policy\n")

        self.assertIn("# existing policy", rewritten)
        for sid in MODULE.INFRASTRUCTURE_NOISE_SIDS:
            self.assertIn(f"suppress gen_id 1, sig_id {sid}", rewritten)
        for sid, source_ip in MODULE.EXPECTED_SERVICE_SUPPRESSIONS:
            self.assertIn(
                f"suppress gen_id 1, sig_id {sid}, track by_src, ip {source_ip}",
                rewritten,
            )
        self.assertEqual(1, rewritten.count(MODULE.THRESHOLD_BLOCK_START))


if __name__ == "__main__":
    unittest.main()
