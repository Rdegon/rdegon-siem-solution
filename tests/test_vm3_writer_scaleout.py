from pathlib import Path
import sys
import types
import unittest


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

if "paramiko" not in sys.modules:
    sys.modules["paramiko"] = types.SimpleNamespace(SSHClient=object, SFTPClient=object, AutoAddPolicy=object)

from deploy.vm3_stream_corr_event_time_deploy import (
    FILE_MAPPINGS,
    SYSTEMD_WRITER_TEMPLATE,
    WRITER_SCALEOUT_UNITS,
    WRITER_TEMPLATE_LOCAL,
)


class Vm3WriterScaleoutTests(unittest.TestCase):
    def test_writer_mapping_targets_live_service_path(self) -> None:
        mapping = {item.local_rel: item.remote_rel for item in FILE_MAPPINGS}
        self.assertEqual(mapping["writer_worker.py"], "services/writer/worker.py")

    def test_writer_scaleout_template_metadata_is_stable(self) -> None:
        self.assertEqual(SYSTEMD_WRITER_TEMPLATE, "/etc/systemd/system/siem-writer@.service")
        self.assertEqual(WRITER_SCALEOUT_UNITS, ("siem-writer@2",))
        self.assertTrue(WRITER_TEMPLATE_LOCAL.exists())

    def test_writer_scaleout_template_sets_consumer_override(self) -> None:
        payload = WRITER_TEMPLATE_LOCAL.read_text(encoding="utf-8")
        self.assertIn("Environment=SIEM_WRITER_CONSUMER=writer-%i", payload)
        self.assertIn("ExecStart=/opt/siem/venv-storage/bin/python /opt/siem/siem-solution/services/writer/worker.py", payload)


if __name__ == "__main__":
    unittest.main()
