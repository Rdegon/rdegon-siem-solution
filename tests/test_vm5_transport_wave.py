import unittest

from deploy import vm5_transport_wave_deploy as vm5_wave


class VM5TransportWaveTests(unittest.TestCase):
    def test_file_mappings_include_processing_and_kafka_assets(self) -> None:
        local_files = {mapping.local_rel for mapping in vm5_wave.FILE_MAPPINGS}

        self.assertIn("services/transport_runtime.py", local_files)
        self.assertIn("deploy/kafka_wave_prepare.py", local_files)
        self.assertIn("deploy/kafka_wave_smoke.py", local_files)
        self.assertIn("deploy/vm5_processing_prepare.py", local_files)
        self.assertIn("deploy/vm5_processing_smoke.py", local_files)
        self.assertIn("deploy/vm5/siem-kafka.service", local_files)
        self.assertIn("deploy/vm5/systemd-networkd-wait-online.override.conf", local_files)

    def test_remote_path_uses_posix_layout(self) -> None:
        payload = vm5_wave._remote_path("/opt/siem/siem-solution", r"deploy\vm5\siem-kafka.service")

        self.assertEqual(payload, "/opt/siem/siem-solution/deploy/vm5/siem-kafka.service")

    def test_strip_sudo_echo_removes_password_line_only(self) -> None:
        payload = vm5_wave._strip_sudo_echo("secret\nok\n", "secret")

        self.assertEqual(payload, "ok\n")


if __name__ == "__main__":
    unittest.main()
