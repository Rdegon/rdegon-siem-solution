import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "deploy" / "network_relocation" / "migrate_mongo_internal_addresses.py"
SPEC = importlib.util.spec_from_file_location("migrate_mongo_internal_addresses", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class MongoNetworkRelocationTests(unittest.TestCase):
    def test_rewrite_mongo_uri_replaces_only_cluster_members(self) -> None:
        current = (
            "mongodb://user:secret@192.168.1.39:27017,192.168.1.35:27017,"
            "192.168.1.40:27017/siem_content?replicaSet=siem-rs"
        )

        rewritten = MODULE.rewrite_mongo_uri(current)

        self.assertIn("10.20.10.107:27017", rewritten)
        self.assertIn("10.20.10.104:27017", rewritten)
        self.assertIn("10.20.10.108:27017", rewritten)
        self.assertNotIn("192.168.1.", rewritten)


if __name__ == "__main__":
    unittest.main()
