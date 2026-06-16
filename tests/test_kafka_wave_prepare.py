import base64
import unittest

from deploy.kafka_wave_prepare import (
    deterministic_cluster_id,
    render_client_properties,
    render_firewall_prepare_command,
    render_kafka_prepare_payload,
    resolve_layout_node,
)


class KafkaWavePrepareTests(unittest.TestCase):
    def test_resolve_layout_node_returns_vm5_transport_node(self) -> None:
        node = resolve_layout_node(3)

        self.assertEqual(node.role_name, "vm5-transport")
        self.assertEqual(node.host, "192.168.1.40")

    def test_render_payload_contains_server_properties_env_and_unit(self) -> None:
        payload = render_kafka_prepare_payload(2, cluster_id="test-cluster-id")

        self.assertIn("node.id=2", payload["server_properties"])
        self.assertIn("controller.quorum.voters=1@192.168.1.35:9093,2@192.168.1.37:9093,3@192.168.1.40:9093", payload["server_properties"])
        self.assertIn("SIEM_KAFKA_BOOTSTRAP_SERVERS=192.168.1.35:9092,192.168.1.37:9092,192.168.1.40:9092", payload["kafka_env"])
        self.assertIn("SIEM_KAFKA_CLUSTER_ID=test-cluster-id", payload["kafka_env"])
        self.assertIn("LOG_DIR=/var/log/siem-kafka", payload["kafka_env"])
        self.assertIn("ExecStart=/opt/kafka/bin/kafka-server-start.sh /etc/siem/kafka/server.properties", payload["systemd_unit"])
        self.assertIn("WorkingDirectory=/opt/kafka", payload["systemd_unit"])
        self.assertEqual(payload["node_role_name"], "vm2-processing")
        self.assertEqual(payload["cluster_id"], "test-cluster-id")

    def test_render_payload_supports_ssl_security_protocol(self) -> None:
        payload = render_kafka_prepare_payload(1, security_protocol="ssl", cluster_id="cluster-1")

        self.assertIn("listener.security.protocol.map=INTERNAL:SSL,CONTROLLER:SSL", payload["server_properties"])
        self.assertIn("SIEM_KAFKA_SECURITY_PROTOCOL=SSL", payload["kafka_env"])
        self.assertEqual(payload["security_protocol"], "SSL")

    def test_client_properties_render_protocol(self) -> None:
        self.assertIn("security.protocol=PLAINTEXT", render_client_properties(security_protocol="plaintext"))
        self.assertIn("security.protocol=SSL", render_client_properties(security_protocol="ssl"))

    def test_deterministic_cluster_id_is_stable_and_base64(self) -> None:
        first = deterministic_cluster_id("siem-kraft")
        second = deterministic_cluster_id("siem-kraft")

        self.assertEqual(first, second)
        self.assertNotEqual(first, deterministic_cluster_id("other-cluster"))
        padded = first + "=" * ((4 - len(first) % 4) % 4)
        decoded = base64.urlsafe_b64decode(padded.encode("ascii"))
        self.assertEqual(len(decoded), 16)

    def test_firewall_prepare_command_opens_broker_and_controller_ports_for_all_nodes(self) -> None:
        command = render_firewall_prepare_command()

        self.assertIn("ufw status | head -n 1 | grep -qi active", command)
        self.assertIn("ufw allow from 192.168.1.35 to any port 9092 proto tcp", command)
        self.assertIn("ufw allow from 192.168.1.37 to any port 9093 proto tcp", command)
        self.assertIn("ufw allow from 192.168.1.40 to any port 9092 proto tcp", command)
        self.assertIn("ufw allow from 192.168.1.38 to any port 9092 proto tcp", command)
        self.assertIn("ufw allow from 192.168.1.39 to any port 9092 proto tcp", command)


if __name__ == "__main__":
    unittest.main()
