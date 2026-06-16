import unittest

from deploy.kafka_wave_smoke import require_quorum_check


class KafkaWaveSmokeTests(unittest.TestCase):
    def test_quorum_check_defaults_to_false(self) -> None:
        self.assertFalse(require_quorum_check(None))
        self.assertFalse(require_quorum_check(""))
        self.assertFalse(require_quorum_check("0"))
        self.assertFalse(require_quorum_check("false"))

    def test_quorum_check_accepts_truthy_values(self) -> None:
        self.assertTrue(require_quorum_check("1"))
        self.assertTrue(require_quorum_check("true"))
        self.assertTrue(require_quorum_check("YES"))


if __name__ == "__main__":
    unittest.main()
