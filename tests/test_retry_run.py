import sys
import unittest

from deploy import retry_run


class RetryRunTests(unittest.TestCase):
    def test_normalize_command_rewrites_python_to_current_interpreter(self) -> None:
        command = retry_run.normalize_command(["python", "deploy/storage_ha_wave_deploy.py"])

        self.assertEqual(sys.executable, command[0])
        self.assertEqual(["deploy/storage_ha_wave_deploy.py"], command[1:])

    def test_normalize_command_rewrites_python3_to_current_interpreter(self) -> None:
        command = retry_run.normalize_command(["python3", "deploy/storage_ha_wave_deploy.py"])

        self.assertEqual(sys.executable, command[0])

    def test_normalize_command_leaves_non_python_commands_untouched(self) -> None:
        command = retry_run.normalize_command(["bash", "-lc", "hostname"])

        self.assertEqual(["bash", "-lc", "hostname"], command)


if __name__ == "__main__":
    unittest.main()
