import unittest
from pathlib import Path

from deploy.vm1_kafka_shadow_prepare import render_ingest_env, render_ingest_sync_commands
from deploy.vm3_kafka_shadow_writer_prepare import (
    render_shadow_dependency_install_command,
    render_shadow_env,
    render_vm3_storage_access_command,
)


class KafkaShadowWaveTests(unittest.TestCase):
    def test_vm1_ingest_env_enables_dual_write(self) -> None:
        rendered = render_ingest_env("SIEM_TRANSPORT_BACKEND=redis\n")

        self.assertIn("SIEM_TRANSPORT_BACKEND=dual", rendered)
        self.assertIn("SIEM_KAFKA_BOOTSTRAP_SERVERS=192.168.1.35:9092,192.168.1.37:9092,192.168.1.40:9092", rendered)
        self.assertIn("SIEM_KAFKA_TOPIC_RAW=siem.raw", rendered)

    def test_vm1_ingest_env_can_render_kafka_only_cutover(self) -> None:
        rendered = render_ingest_env("SIEM_TRANSPORT_BACKEND=dual\n", transport_backend="kafka")

        self.assertIn("SIEM_TRANSPORT_BACKEND=kafka", rendered)
        self.assertNotIn("SIEM_TRANSPORT_BACKEND=dual", rendered)

    def test_vm1_ingest_sync_commands_use_install_for_root_owned_targets(self) -> None:
        rendered = render_ingest_sync_commands(Path("/workspace"), Path("/opt/siem/siem-solution"), require_existing=False).replace("\\", "/")

        self.assertIn("install -m 0644", rendered)
        self.assertIn("/workspace/services/ingest/app.py", rendered)
        self.assertIn("/opt/siem/siem-solution/services/ingest/app.py", rendered)
        self.assertIn("/workspace/services/ingest/syslog_server.py", rendered)
        self.assertIn("/opt/siem/siem-solution/services/ingest/syslog_server.py", rendered)
        self.assertNotIn("copytree", rendered)

    def test_vm3_shadow_env_targets_shadow_table(self) -> None:
        rendered = render_shadow_env("")

        self.assertIn("SIEM_TRANSPORT_BACKEND=kafka", rendered)
        self.assertIn("SIEM_TRANSPORT_CONSUMER_BACKEND=kafka", rendered)
        self.assertIn("SIEM_EVENTS_TABLE=siem.events_shadow", rendered)
        self.assertIn("SIEM_WRITER_GROUP=writer-shadow", rendered)

    def test_vm3_shadow_dependency_install_command_uses_retryable_aiokafka_install(self) -> None:
        rendered = render_shadow_dependency_install_command()

        self.assertIn("aiokafka==0.10.0", rendered)
        self.assertIn("--retries 10", rendered)
        self.assertIn("--default-timeout 120", rendered)

    def test_vm3_storage_access_command_opens_clickhouse_for_vm5_wave(self) -> None:
        rendered = render_vm3_storage_access_command()

        self.assertIn("ufw allow from 192.168.1.40 to any port 9000 proto tcp", rendered)
        self.assertIn("ufw allow from 192.168.1.40 to any port 8123 proto tcp", rendered)


if __name__ == "__main__":
    unittest.main()
