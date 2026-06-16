import unittest

from deploy.kafka_topic_bootstrap import topic_retention_configs


class KafkaTopicBootstrapTests(unittest.TestCase):
    def test_topic_retention_configs_cover_core_topics(self) -> None:
        configs = topic_retention_configs()

        self.assertIn("siem.raw", configs)
        self.assertIn("siem.normalized", configs)
        self.assertIn("siem.filtered", configs)
        self.assertEqual(configs["siem.raw"]["retention.ms"], 172800000)
        self.assertEqual(configs["siem.raw"]["retention.bytes"], 268435456)
        self.assertEqual(configs["siem.raw"]["segment.ms"], 3600000)
        self.assertEqual(configs["siem.transport.audit"]["retention.bytes"], 134217728)
        self.assertEqual(configs["siem.dlq"]["cleanup.policy"], "delete")


if __name__ == "__main__":
    unittest.main()
