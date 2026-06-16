import unittest

from deploy import vm5_processing_prepare as vm5_prepare


class VM5ProcessingPrepareTests(unittest.TestCase):
    def test_render_processing_env_adds_kafka_only_shadow_defaults(self) -> None:
        payload = vm5_prepare.render_processing_env("")

        self.assertIn("SIEM_TRANSPORT_BACKEND=kafka", payload)
        self.assertIn("SIEM_TRANSPORT_CONSUMER_BACKEND=kafka", payload)
        self.assertIn("SIEM_KAFKA_BOOTSTRAP_SERVERS=192.168.1.35:9092,192.168.1.37:9092,192.168.1.40:9092", payload)
        self.assertIn("SIEM_KAFKA_MIN_INSYNC_REPLICAS=2", payload)

    def test_render_processing_env_updates_existing_values_in_place(self) -> None:
        existing = "\n".join(
            [
                "SIEM_ENV=prod",
                "SIEM_TRANSPORT_BACKEND=redis",
                "SIEM_TRANSPORT_CONSUMER_BACKEND=redis",
                "SIEM_KAFKA_BOOTSTRAP_SERVERS=127.0.0.1:9092",
                "CUSTOM=value",
                "",
            ]
        )

        payload = vm5_prepare.render_processing_env(existing)

        self.assertIn("SIEM_TRANSPORT_BACKEND=kafka", payload)
        self.assertIn("SIEM_TRANSPORT_CONSUMER_BACKEND=kafka", payload)
        self.assertIn("SIEM_KAFKA_BOOTSTRAP_SERVERS=192.168.1.35:9092,192.168.1.37:9092,192.168.1.40:9092", payload)
        self.assertIn("CUSTOM=value", payload)
        self.assertNotIn("SIEM_TRANSPORT_BACKEND=redis", payload)

    def test_render_redis_retirement_command_disables_and_purges_redis(self) -> None:
        payload = vm5_prepare.render_redis_retirement_command()

        self.assertIn("systemctl disable --now redis-server", payload)
        self.assertIn("apt-get purge -y redis-server redis-tools", payload)

    def test_scaleout_template_mappings_include_wait_online_override(self) -> None:
        self.assertIn(
            vm5_prepare.Path("deploy/vm5/systemd-networkd-wait-online.override.conf"),
            vm5_prepare.SCALEOUT_TEMPLATE_MAPPINGS,
        )


if __name__ == "__main__":
    unittest.main()
