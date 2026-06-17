import unittest

from deploy import vm2_processing_remote_deploy as vm2_deploy


class VM2ProcessingRemoteDeployTests(unittest.TestCase):
    def test_file_mappings_include_transport_and_processing_workers(self) -> None:
        local_files = {mapping.local_rel for mapping in vm2_deploy.FILE_MAPPINGS}

        self.assertIn("services/transport_runtime.py", local_files)
        self.assertIn("services/normalizer/worker.py", local_files)
        self.assertIn("services/filter/worker.py", local_files)

    def test_remote_path_uses_remote_root_for_relative_paths(self) -> None:
        path = vm2_deploy._remote_path("/opt/siem/siem-solution", "services/transport_runtime.py")

        self.assertEqual(path, "/opt/siem/siem-solution/services/transport_runtime.py")

    def test_remote_path_preserves_absolute_paths(self) -> None:
        path = vm2_deploy._remote_path("/opt/siem/siem-solution", "/etc/systemd/system/siem-filter@.service")

        self.assertEqual(path, "/etc/systemd/system/siem-filter@.service")


if __name__ == "__main__":
    unittest.main()
