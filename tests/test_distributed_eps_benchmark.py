import unittest

from deploy import distributed_eps_benchmark as benchmark


class DistributedEpsBenchmarkTests(unittest.TestCase):
    def test_split_stage_target_balances_remainder(self) -> None:
        self.assertEqual([3, 3, 2, 2], benchmark.split_stage_target(10, 4))

    def test_parse_stages_uses_defaults(self) -> None:
        self.assertEqual((1000, 2500, 5000), benchmark.parse_stages(""))

    def test_summarize_results_prefers_successful_highest_stage(self) -> None:
        summary = benchmark.summarize_results(
            [
                {"eps_target_total": 1000, "delivery_ratio": 1.0, "largest_consumer_lag": 1, "status": "success"},
                {"eps_target_total": 2500, "delivery_ratio": 0.998, "largest_consumer_lag": 9},
                {"eps_target_total": 5000, "delivery_ratio": 0.999, "largest_consumer_lag": 30, "status": "failed"},
            ]
        )

        self.assertEqual(2500, summary["best_sustained_eps"])
        self.assertEqual(30, summary["max_observed_consumer_lag"])


if __name__ == "__main__":
    unittest.main()
