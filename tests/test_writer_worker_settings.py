import importlib
import os
import sys
import unittest


class WriterWorkerSettingsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.original_port = os.environ.get("SIEM_CH_PORT")
        os.environ.pop("SIEM_CH_PORT", None)
        sys.modules.pop("services.writer.worker", None)

    def tearDown(self) -> None:
        if self.original_port is None:
            os.environ.pop("SIEM_CH_PORT", None)
        else:
            os.environ["SIEM_CH_PORT"] = self.original_port
        sys.modules.pop("services.writer.worker", None)

    def test_writer_defaults_to_clickhouse_native_port(self) -> None:
        writer_worker = importlib.import_module("services.writer.worker")

        self.assertEqual(writer_worker.WriterSettings().ch_port, 9000)


if __name__ == "__main__":
    unittest.main()
