from __future__ import annotations

import io
import json
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

import deploy.vm3_firewall_sanitize as sanitize


class Vm3FirewallSanitizeTests(unittest.TestCase):
    def test_matching_rules_filters_retired_redis_ports(self) -> None:
        with patch.object(
            sanitize,
            "_list_rules",
            return_value=[
                "-A ufw-user-input -s 192.168.1.35/32 -p tcp -m tcp --dport 6379 -j ACCEPT",
                "-A ufw-user-input -s 192.168.1.37/32 -p tcp -m tcp --dport 26379 -j ACCEPT",
                "-A ufw-user-input -s 192.168.1.40/32 -p tcp -m tcp --dport 8123 -j ACCEPT",
            ],
        ):
            self.assertEqual(
                sanitize._matching_rules(),
                [
                    ["-D", "ufw-user-input", "-s", "192.168.1.35/32", "-p", "tcp", "-m", "tcp", "--dport", "6379", "-j", "ACCEPT"],
                    ["-D", "ufw-user-input", "-s", "192.168.1.37/32", "-p", "tcp", "-m", "tcp", "--dport", "26379", "-j", "ACCEPT"],
                ],
            )

    def test_main_reports_removed_and_remaining_rules(self) -> None:
        calls: list[list[str]] = []

        def fake_matching_rules() -> list[list[str]]:
            if not calls:
                return [["-D", "ufw-user-input", "-s", "192.168.1.35/32", "-p", "tcp", "-m", "tcp", "--dport", "6379", "-j", "ACCEPT"]]
            return []

        def fake_run(command: list[str]):
            calls.append(command)

            class Result:
                returncode = 0
                stdout = ""
                stderr = ""

            return Result()

        with patch.object(sanitize, "_matching_rules", side_effect=fake_matching_rules), patch.object(sanitize, "_run", side_effect=fake_run):
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(sanitize.main(), 0)
        payload = json.loads(output.getvalue())
        self.assertEqual(len(payload["removed"]), 1)
        self.assertEqual(payload["remaining"], [])
        self.assertEqual(calls[0][0], "iptables")


if __name__ == "__main__":
    unittest.main()
