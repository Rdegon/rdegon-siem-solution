import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "services" / "web" / "app" / "inventory_catalog.py"
SPEC = importlib.util.spec_from_file_location("inventory_catalog", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class InventoryCatalogAddressTests(unittest.TestCase):
    def test_legacy_siem_core_ip_is_presented_as_current_sec_ip(self) -> None:
        self.assertEqual(MODULE.canonicalize_core_ip("192.168.1.38"), "10.20.10.106")

    def test_non_core_ip_is_not_changed(self) -> None:
        self.assertEqual(MODULE.canonicalize_core_ip("203.0.113.8"), "203.0.113.8")


if __name__ == "__main__":
    unittest.main()
