import unittest

from deploy.kafka_cluster_layout import (
    bootstrap_servers,
    build_env_exports,
    build_server_properties,
    build_systemd_unit,
    controller_quorum_voters,
    default_lab_kafka_layout,
    normalize_security_protocol,
)


class KafkaClusterLayoutTests(unittest.TestCase):
    def test_default_lab_layout_uses_three_nodes(self) -> None:
        layout = default_lab_kafka_layout()

        self.assertEqual(len(layout.nodes), 3)
        self.assertEqual(layout.replication_factor, 3)
        self.assertEqual(layout.min_insync_replicas, 2)
        self.assertEqual(bootstrap_servers(layout), "192.168.1.35:9092,192.168.1.37:9092,192.168.1.40:9092")

    def test_server_properties_include_kraft_and_security_defaults(self) -> None:
        layout = default_lab_kafka_layout()
        properties = build_server_properties(layout, layout.nodes[0])

        self.assertIn("process.roles=broker,controller", properties)
        self.assertIn("controller.quorum.voters=1@192.168.1.35:9093,2@192.168.1.37:9093,3@192.168.1.40:9093", properties)
        self.assertIn("listener.security.protocol.map=INTERNAL:PLAINTEXT,CONTROLLER:PLAINTEXT", properties)
        self.assertIn("default.replication.factor=3", properties)
        self.assertIn("log.retention.hours=48", properties)
        self.assertIn("log.retention.bytes=536870912", properties)
        self.assertIn("log.segment.bytes=134217728", properties)
        self.assertIn("log.roll.ms=3600000", properties)
        self.assertIn("log.retention.check.interval.ms=300000", properties)

    def test_env_exports_include_transport_wave_defaults(self) -> None:
        layout = default_lab_kafka_layout()
        exports = build_env_exports(layout)

        self.assertIn("SIEM_TRANSPORT_BACKEND=dual", exports)
        self.assertIn("SIEM_KAFKA_EXPECTED_BROKERS=3", exports)
        self.assertIn("SIEM_KAFKA_MIN_INSYNC_REPLICAS=2", exports)
        self.assertIn("SIEM_KAFKA_SECURITY_PROTOCOL=PLAINTEXT", exports)
        self.assertIn("LOG_DIR=/var/log/siem-kafka", exports)
        self.assertIn("KAFKA_HEAP_OPTS=-Xms256m -Xmx512m", exports)
        self.assertIn("KAFKA_JVM_PERFORMANCE_OPTS=", exports)

    def test_ssl_protocol_can_be_rendered_explicitly(self) -> None:
        layout = default_lab_kafka_layout()
        properties = build_server_properties(layout, layout.nodes[1], security_protocol="ssl")
        exports = build_env_exports(layout, security_protocol="ssl")

        self.assertIn("listener.security.protocol.map=INTERNAL:SSL,CONTROLLER:SSL", properties)
        self.assertIn("inter.broker.listener.name=INTERNAL", properties)
        self.assertIn("ssl.client.auth=required", properties)
        self.assertIn("SIEM_KAFKA_SECURITY_PROTOCOL=SSL", exports)

    def test_security_protocol_normalization_defaults_to_plaintext(self) -> None:
        self.assertEqual(normalize_security_protocol("SSL"), "SSL")
        self.assertEqual(normalize_security_protocol("plaintext"), "PLAINTEXT")
        self.assertEqual(normalize_security_protocol("unknown"), "PLAINTEXT")

    def test_systemd_unit_is_service_ready(self) -> None:
        unit = build_systemd_unit()

        self.assertIn("ExecStart=/opt/kafka/bin/kafka-server-start.sh /etc/siem/kafka/server.properties", unit)
        self.assertIn("WorkingDirectory=/opt/kafka", unit)
        self.assertIn("Restart=always", unit)
        self.assertIn("WantedBy=multi-user.target", unit)


if __name__ == "__main__":
    unittest.main()
