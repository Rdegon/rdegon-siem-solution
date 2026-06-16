from __future__ import annotations

import sys
import types
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

if "paramiko" not in sys.modules:
    sys.modules["paramiko"] = types.SimpleNamespace(SSHClient=object, SFTPClient=object, AutoAddPolicy=object)

from deploy.redis_ha_resilience_deploy import VM3_FILE_MAPPINGS, _render_sentinel_unit


class RedisHaResilienceDeployTests(unittest.TestCase):
    def test_render_sentinel_unit_uses_systemd_notify_profile(self) -> None:
        unit = _render_sentinel_unit()
        self.assertIn("Type=notify", unit)
        self.assertIn("RuntimeDirectory=redis", unit)
        self.assertIn("RuntimeDirectoryMode=2755", unit)
        self.assertIn("TimeoutStopSec=0", unit)
        self.assertIn("ExecStart=/usr/bin/redis-server /etc/redis/siem-sentinel.conf --sentinel", unit)

    def test_vm3_writer_mapping_targets_live_service_path(self) -> None:
        mapping = {item.local_rel: item.remote_rel for item in VM3_FILE_MAPPINGS}
        self.assertEqual(mapping["writer_worker.py"], "services/writer/worker.py")


if __name__ == "__main__":
    unittest.main()
