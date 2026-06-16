from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from deploy import homelab_watchdog
from deploy import vm2_processing_resilience_deploy as deploy_vm2


class ProcessingScaleoutTests(unittest.TestCase):
    def test_processing_service_units_include_scaleout_instances(self) -> None:
        self.assertIn("siem-normalizer@2", deploy_vm2.PROCESSING_SERVICE_UNITS)
        self.assertIn("siem-filter@2", deploy_vm2.PROCESSING_SERVICE_UNITS)
        self.assertIn("siem-normalizer", deploy_vm2.PROCESSING_SERVICE_UNITS)
        self.assertIn("siem-filter", deploy_vm2.PROCESSING_SERVICE_UNITS)

    def test_service_status_command_renders_all_units(self) -> None:
        command = deploy_vm2._service_status_command("redis-server", *deploy_vm2.PROCESSING_SERVICE_UNITS)
        self.assertIn("redis-server", command)
        self.assertIn("siem-normalizer@2", command)
        self.assertIn("siem-filter@2", command)

    def test_watchdog_vm2_service_clause_tracks_scaleout_units(self) -> None:
        clause = homelab_watchdog._vm2_service_units_clause()
        self.assertNotIn("siem-redis-sentinel", clause)
        self.assertIn("siem-normalizer@2", clause)
        self.assertIn("siem-filter@2", clause)
        self.assertIn("actions.runner.Rdegon-siem-solution.siem-vm2.service", clause)


if __name__ == "__main__":
    unittest.main()
