import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TUNNEL_SCRIPT = ROOT / "deploy" / "vm4" / "siem-jump-tunnels.sh"


class JumpTunnelNetworkRelocationTests(unittest.TestCase):
    def test_reverse_tunnels_use_current_segment_addresses(self) -> None:
        script = TUNNEL_SCRIPT.read_text(encoding="utf-8")

        self.assertNotIn("192.168.1.", script)
        for address in (
            "10.20.10.104",
            "10.20.10.105",
            "10.20.10.106",
            "10.20.10.107",
            "10.20.10.108",
            "192.168.3.102",
        ):
            self.assertIn(address, script)


if __name__ == "__main__":
    unittest.main()
