import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import certification_runtime as runtime
import deploy.production_certification as production_certification
from deploy.production_certification import validate_profile


class CertificationRuntimeTests(unittest.TestCase):
    def test_connect_client_with_retry_recovers_from_transient_probe_failure(self) -> None:
        class DummyClient:
            def close(self) -> None:
                return None

        attempts: list[str] = []

        def flaky_connect(host: str, user: str, password: str):
            attempts.append(host)
            if len(attempts) == 1:
                raise RuntimeError("temporary vm2 probe failure")
            return DummyClient()

        with patch("deploy.production_certification._connect_client", side_effect=flaky_connect):
            client = production_certification._connect_client_with_retry(
                "192.168.1.37",
                "rdegon",
                "314159King.",
                attempts=2,
                delay_seconds=0.0,
            )

        self.assertIsInstance(client, DummyClient)
        self.assertEqual(2, len(attempts))

    def test_evaluate_benchmark_flags_budget_regressions(self) -> None:
        profile = {
            "stage_ladder_eps": [1000, 2500],
            "delivery_ratio_min": 0.995,
            "ingest_p95_latency_ms_max": 1500,
            "kafka_lag_max": 5000,
        }
        summary = {
            "best_sustained_eps": 2500,
            "best_delivery_ratio": 0.992,
            "max_observed_consumer_lag": 6000,
            "stages": [{"p95_latency_ms": 1700}],
        }

        result = runtime.evaluate_benchmark(summary, profile)

        self.assertFalse(result["healthy"])
        self.assertIn("delivery_ratio<0.995", result["issues"])
        self.assertIn("ingest_p95_latency_ms>1500", result["issues"])
        self.assertIn("kafka_lag>5000", result["issues"])

    def test_validate_profile_rejects_unsorted_stage_ladder(self) -> None:
        result = validate_profile(
            {
                "stage_ladder_eps": [2500, 1000],
                "latency_budget_skip_initial_stages": 1,
                "delivery_ratio_min": 0.995,
                "ingest_p95_latency_ms_max": 1500,
                "kafka_lag_max": 5000,
            }
        )

        self.assertFalse(result["healthy"])
        self.assertIn("stage_ladder_eps_not_sorted", result["issues"])

    def test_evaluate_benchmark_skips_warmup_stage_for_latency_budget(self) -> None:
        profile = {
            "stage_ladder_eps": [100, 250, 500],
            "latency_budget_skip_initial_stages": 1,
            "delivery_ratio_min": 0.995,
            "ingest_p95_latency_ms_max": 18000,
            "kafka_lag_max": 5000,
        }
        summary = {
            "best_sustained_eps": 72,
            "best_delivery_ratio": 1.0,
            "max_observed_consumer_lag": 0,
            "stages": [
                {"eps_target_total": 100, "achieved_eps": 48.43, "delivery_ratio": 1.0, "status": "success", "latency": {"p95_ms": 18726.0}},
                {"eps_target_total": 250, "achieved_eps": 57.68, "delivery_ratio": 1.0, "status": "success", "latency": {"p95_ms": 17942.0}},
                {"eps_target_total": 500, "achieved_eps": 72.25, "delivery_ratio": 1.0, "status": "success", "latency": {"p95_ms": 17191.1}},
            ],
        }

        result = runtime.evaluate_benchmark(summary, profile)

        self.assertTrue(result["healthy"])
        self.assertEqual(1, result["latency_budget_skip_initial_stages"])
        self.assertEqual(17191.1, result["observed_ingest_p95_latency_ms"])
        self.assertEqual([500], result["certified_window_stage_targets"])

    def test_evaluate_benchmark_ignores_failed_stages_beyond_certified_ceiling(self) -> None:
        profile = {
            "stage_ladder_eps": [100, 250, 500],
            "latency_budget_skip_initial_stages": 1,
            "delivery_ratio_min": 0.995,
            "ingest_p95_latency_ms_max": 18000,
            "kafka_lag_max": 5000,
        }
        summary = {
            "best_sustained_eps": 91,
            "best_delivery_ratio": 1.0,
            "max_observed_consumer_lag": 0,
            "stages": [
                {"eps_target_total": 100, "achieved_eps": 91.22, "delivery_ratio": 1.0, "status": "success", "latency": {"p95_ms": 12283.9}},
                {
                    "eps_target_total": 250,
                    "achieved_eps": 67.92,
                    "delivery_ratio": 1.0,
                    "status": "failed",
                    "errors": ["worker timeout"],
                    "latency": {"p95_ms": 20769.1},
                },
                {"eps_target_total": 500, "achieved_eps": 68.33, "delivery_ratio": 1.0, "status": "success", "latency": {"p95_ms": 14723.9}},
            ],
        }

        result = runtime.evaluate_benchmark(summary, profile)

        self.assertTrue(result["healthy"])
        self.assertEqual(14723.9, result["observed_ingest_p95_latency_ms"])
        self.assertEqual([500], result["certified_window_stage_targets"])

    def test_runtime_status_uses_saved_payload(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            status_path = Path(temp_dir) / "production_certification_status.json"
            payload = {
                "benchmark": {
                    "best_sustained_eps": 2500,
                    "best_delivery_ratio": 0.999,
                    "max_observed_consumer_lag": 120,
                    "stages": [{"p95_latency_ms": 250}],
                },
                "drill": {"healthy": True, "items": []},
                "post_benchmark_health": {"healthy": True, "issues": []},
                "last_updated_ts": "2026-03-26T12:00:00Z",
            }
            status_path.write_text(json.dumps(payload), encoding="utf-8")
            original = os.environ.get("SIEM_CERTIFICATION_STATUS_PATH")
            os.environ["SIEM_CERTIFICATION_STATUS_PATH"] = str(status_path)
            try:
                status = runtime.certification_runtime_status()
            finally:
                if original is None:
                    os.environ.pop("SIEM_CERTIFICATION_STATUS_PATH", None)
                else:
                    os.environ["SIEM_CERTIFICATION_STATUS_PATH"] = original

        self.assertTrue(status["healthy"])
        self.assertEqual(2500, status["latest_certified_ceiling_eps"])
        self.assertEqual("2026-03-26T12:00:00Z", status["last_updated_ts"])

    def test_collect_post_benchmark_health_tolerates_low_signal_ingest_residuals(self) -> None:
        class FakeWebClient:
            def __init__(self, _base_url: str) -> None:
                return None

            def request(self, path: str, *, method: str = "GET", payload=None):  # noqa: ANN001, ARG002
                if path == "/auth/login":
                    return 200, ""
                if path == "/api/health/overview":
                    body = json.dumps(
                        {
                            "issues": ["Delayed sources detected: 4"],
                            "platform": {
                                "transport_backend": "kafka",
                                "content_store_status": {"backend": "mongo"},
                            },
                        }
                    )
                    return 200, body
                raise AssertionError(f"unexpected path {path}")

        env = {
            "SIEM_WEB_BASE_URL": "https://192.168.1.39",
            "SIEM_WEB_ADMIN_USER": "admin",
            "SIEM_WEB_ADMIN_PASSWORD": "secret",
        }
        previous = {key: os.environ.get(key) for key in env}
        os.environ.update(env)
        try:
            with patch("deploy.production_certification.WebClient", FakeWebClient), patch(
                "deploy.production_certification.stabilize_ingest_health",
                return_value={"healthy": True, "issues": []},
            ):
                status = production_certification.collect_post_benchmark_health()
        finally:
            for key, value in previous.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value

        self.assertTrue(status["healthy"])
        self.assertEqual([], status["issues"])
        self.assertEqual(["Delayed sources detected: 4"], status["summary"]["tolerated_issues"])
        self.assertEqual(1, status["summary"]["tolerated_issue_count"])
        self.assertEqual("", status["last_failure_reason"])


if __name__ == "__main__":
    unittest.main()
