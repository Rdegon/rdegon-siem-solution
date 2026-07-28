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

    def test_opnsense_staging_alias_is_merged_into_production_asset(self) -> None:
        self.assertEqual(
            MODULE.SOURCE_ALIAS_OVERRIDES["opnsense-staging"],
            "opnsense-edge-01",
        )
        self.assertEqual(
            MODULE.SOURCE_ALIAS_OVERRIDES["172.31.255.2"],
            "opnsense-edge-01",
        )
        self.assertEqual(
            MODULE.SOURCE_ALIAS_OVERRIDES["192.168.3.103"],
            "opnsense-edge-01",
        )
        self.assertNotIn("opnsense-edge-01", MODULE.SOURCE_ALIAS_OVERRIDES)
        frontend = (
            ROOT / "frontend-react" / "src" / "shell" / "humanize.ts"
        ).read_text(encoding="utf-8")
        self.assertIn('"opnsense-staging": "opnsense-edge-01"', frontend)
        self.assertIn('"192.168.3.103": "opnsense-edge-01"', frontend)
        self.assertIn('"opnsense-edge-01": { en: "OPNsense NGFW"', frontend)
        self.assertNotIn('"opnsense-edge-01": "lab-edge-01"', frontend)


if __name__ == "__main__":
    unittest.main()
