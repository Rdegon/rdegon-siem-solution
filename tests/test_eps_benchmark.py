import unittest

from deploy import eps_benchmark


class EpsBenchmarkTests(unittest.TestCase):
    def test_parse_eps_stages_uses_defaults_for_empty_value(self) -> None:
        self.assertEqual((500, 1000, 2000, 4000), eps_benchmark.parse_eps_stages(""))

    def test_parse_eps_stages_parses_csv(self) -> None:
        self.assertEqual((250, 750, 1250), eps_benchmark.parse_eps_stages("250,750,1250"))

    def test_summarize_eps_results_prefers_best_successful_stage(self) -> None:
        summary = eps_benchmark.summarize_eps_results(
            [
                {"eps_target": 500, "delivery_ratio": 0.999},
                {"eps_target": 1000, "delivery_ratio": 0.996},
                {"eps_target": 2000, "delivery_ratio": 0.88},
            ]
        )

        self.assertEqual(1000, summary["best_sustained_eps"])
        self.assertEqual(0.996, summary["best_delivery_ratio"])


if __name__ == "__main__":
    unittest.main()
