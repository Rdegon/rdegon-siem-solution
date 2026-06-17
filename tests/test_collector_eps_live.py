import unittest

from deploy import collector_eps_ladder_live, collector_eps_worker


class CollectorEpsLiveTests(unittest.TestCase):
    def test_default_targets_cover_http_ports_and_syslog_profiles(self) -> None:
        names = {item["name"] for item in collector_eps_ladder_live.DEFAULT_COLLECTOR_TARGETS}

        self.assertIn("windows-security-http", names)
        self.assertIn("app-json-http", names)
        self.assertIn("vulnscanner-http", names)
        self.assertIn("vpn-http", names)
        self.assertIn("syslog-linux-auth", names)
        self.assertIn("syslog-linux-audit", names)
        self.assertIn("syslog-network", names)
        self.assertIn("syslog-vpn", names)
        self.assertIn("syslog-app", names)
        self.assertEqual(13, len(names))

    def test_worker_events_keep_cleanup_marker_in_message(self) -> None:
        event = collector_eps_worker.build_http_event(
            run_id="collector-eps-test",
            stage_id=4500,
            target_name="windows-security-http",
            worker_id="w1",
            sequence=7,
        )
        line = collector_eps_worker.build_syslog_line(
            run_id="collector-eps-test",
            stage_id=4500,
            target_name="syslog-linux-auth",
            worker_id="w1",
            sequence=7,
        )

        self.assertIn("collector-eps-test:4500:windows-security-http:w1:7", event["message"])
        self.assertIn("collector-eps-test:4500:syslog-linux-auth:w1:7", line)
        self.assertIn("allowlist:benchmark", event["tags"])

    def test_worker_accepts_past_start_barrier_without_sleeping(self) -> None:
        event = collector_eps_worker.build_http_event(
            run_id="collector-eps-test",
            stage_id=1,
            target_name="app-json-http",
            worker_id="w1",
            sequence=1,
        )

        self.assertEqual(event["message"], "collector-eps-test:1:app-json-http:w1:1")


if __name__ == "__main__":
    unittest.main()
