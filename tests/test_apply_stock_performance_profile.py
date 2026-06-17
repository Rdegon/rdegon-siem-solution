import types
import unittest
from unittest import mock

from deploy import apply_stock_performance_profile as profile


class StockPerformanceProfileTests(unittest.TestCase):
    def test_render_dropin_quotes_environment_values(self) -> None:
        rendered = profile.render_dropin({"SIEM_KAFKA_PRODUCER_COMPRESSION_TYPE": "lz4", "SIEM_WRITER_BATCH_SIZE": "1000"})

        self.assertIn('[Service]', rendered)
        self.assertIn('Environment="SIEM_KAFKA_PRODUCER_COMPRESSION_TYPE=lz4"', rendered)
        self.assertIn('Environment="SIEM_WRITER_BATCH_SIZE=1000"', rendered)

    def test_aggressive_profile_overrides_balanced_batches(self) -> None:
        items = {item.name: item for item in profile.profile_items("aggressive")}

        self.assertEqual(items["SIEM_VM1"].env["SIEM_INGEST_HTTP_PUBLISH_BATCH_SIZE"], "1000")
        self.assertNotIn("SIEM_KAFKA_PRODUCER_COMPRESSION_TYPE", items["SIEM_VM1"].env)
        self.assertEqual(items["SIEM_VM2"].env["SIEM_NORMALIZER_BATCH_SIZE"], "1000")
        self.assertEqual(items["SIEM_VM3"].env["SIEM_WRITER_BATCH_SIZE"], "2000")

    def test_dry_run_outputs_sudo_n_commands_and_restart_units(self) -> None:
        args = types.SimpleNamespace(
            profile="balanced",
            execute=False,
            restart=True,
            ssh_key="unused",
            user="rdegon",
            sudo_password_env="",
            command_timeout_sec=1.0,
            output="",
        )

        payload = profile.apply_profile(args)

        self.assertEqual(payload["mode"], "dry-run")
        vm1 = next(item for item in payload["hosts"] if item["name"] == "SIEM_VM1")
        self.assertIn("siem-ingest.service", vm1["restart_units"])
        self.assertTrue(any("sudo -n install" in command for command in vm1["commands"]))
        self.assertTrue(any("sudo -n systemctl daemon-reload" in command for command in vm1["commands"]))

    def test_dry_run_uses_password_sudo_mode_without_rendering_secret(self) -> None:
        args = types.SimpleNamespace(
            profile="balanced",
            execute=False,
            restart=True,
            ssh_key="unused",
            user="rdegon",
            sudo_password_env="SIEM_NODE_PASSWORD",
            command_timeout_sec=1.0,
            output="",
        )

        with mock.patch.dict("os.environ", {"SIEM_VM1_PASSWORD": "super-secret"}, clear=False):
            payload = profile.apply_profile(args)

        vm1 = next(item for item in payload["hosts"] if item["name"] == "SIEM_VM1")
        rendered = "\n".join(vm1["commands"])
        self.assertEqual(vm1["sudo_mode"], "password")
        self.assertIn("sudo -S -p '' install", rendered)
        self.assertNotIn("super-secret", rendered)

    def test_strip_sudo_echo_removes_password_lines(self) -> None:
        cleaned = profile._strip_sudo_echo("secret\r\nok\r\nsecret\r\n", "secret")

        self.assertEqual(cleaned, "ok\n")


if __name__ == "__main__":
    unittest.main()
