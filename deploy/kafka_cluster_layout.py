from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class KafkaNodeLayout:
    node_id: int
    role_name: str
    host: str
    broker_port: int = 9092
    controller_port: int = 9093
    data_dir: str = "/var/lib/siem-kafka"
    log_dir: str = "/var/log/siem-kafka"


@dataclass(frozen=True)
class KafkaClusterLayout:
    cluster_name: str
    replication_factor: int
    min_insync_replicas: int
    default_security_protocol: str
    topic_partitions: int
    broker_log_retention_hours: int
    broker_log_retention_bytes: int
    broker_log_segment_bytes: int
    broker_log_roll_ms: int
    broker_log_retention_check_interval_ms: int
    broker_log_segment_delete_delay_ms: int
    nodes: tuple[KafkaNodeLayout, ...]


def default_lab_kafka_layout() -> KafkaClusterLayout:
    return KafkaClusterLayout(
        cluster_name="siem-kraft",
        replication_factor=3,
        min_insync_replicas=2,
        default_security_protocol="PLAINTEXT",
        topic_partitions=6,
        broker_log_retention_hours=48,
        broker_log_retention_bytes=512 * 1024 * 1024,
        broker_log_segment_bytes=128 * 1024 * 1024,
        broker_log_roll_ms=60 * 60 * 1000,
        broker_log_retention_check_interval_ms=5 * 60 * 1000,
        broker_log_segment_delete_delay_ms=60 * 1000,
        nodes=(
            KafkaNodeLayout(node_id=1, role_name="vm1-ingest", host="192.168.1.35"),
            KafkaNodeLayout(node_id=2, role_name="vm2-processing", host="192.168.1.37"),
            KafkaNodeLayout(node_id=3, role_name="vm5-transport", host="192.168.1.40"),
        ),
    )


def bootstrap_servers(layout: KafkaClusterLayout) -> str:
    return ",".join(f"{node.host}:{node.broker_port}" for node in layout.nodes)


def controller_quorum_voters(layout: KafkaClusterLayout) -> str:
    return ",".join(f"{node.node_id}@{node.host}:{node.controller_port}" for node in layout.nodes)


def normalize_security_protocol(value: str | None) -> str:
    rendered = str(value or "").strip().upper()
    if rendered in {"PLAINTEXT", "SSL"}:
        return rendered
    return "PLAINTEXT"


def build_server_properties(
    layout: KafkaClusterLayout,
    node: KafkaNodeLayout,
    *,
    security_protocol: str | None = None,
) -> str:
    protocol = normalize_security_protocol(security_protocol or layout.default_security_protocol)
    protocol_map = f"INTERNAL:{protocol},CONTROLLER:{protocol}"
    properties = [
        f"node.id={node.node_id}",
        "process.roles=broker,controller",
        f"controller.quorum.voters={controller_quorum_voters(layout)}",
        "controller.listener.names=CONTROLLER",
        "inter.broker.listener.name=INTERNAL",
        "listeners=INTERNAL://0.0.0.0:{broker},CONTROLLER://0.0.0.0:{controller}".format(
            broker=node.broker_port,
            controller=node.controller_port,
        ),
        "advertised.listeners=INTERNAL://{host}:{broker}".format(
            host=node.host,
            broker=node.broker_port,
        ),
        f"listener.security.protocol.map={protocol_map}",
        f"log.dirs={node.data_dir}",
        f"default.replication.factor={layout.replication_factor}",
        f"offsets.topic.replication.factor={layout.replication_factor}",
        f"transaction.state.log.replication.factor={layout.replication_factor}",
        f"transaction.state.log.min.isr={layout.min_insync_replicas}",
        f"min.insync.replicas={layout.min_insync_replicas}",
        f"num.partitions={layout.topic_partitions}",
        f"log.retention.hours={layout.broker_log_retention_hours}",
        f"log.retention.bytes={layout.broker_log_retention_bytes}",
        f"log.segment.bytes={layout.broker_log_segment_bytes}",
        f"log.roll.ms={layout.broker_log_roll_ms}",
        f"log.retention.check.interval.ms={layout.broker_log_retention_check_interval_ms}",
        f"log.segment.delete.delay.ms={layout.broker_log_segment_delete_delay_ms}",
        "auto.create.topics.enable=false",
    ]
    if protocol == "SSL":
        properties.extend(
            [
                "ssl.client.auth=required",
                "ssl.enabled.protocols=TLSv1.2,TLSv1.3",
            ]
        )
    return "\n".join(properties) + "\n"


def build_env_exports(layout: KafkaClusterLayout, *, security_protocol: str | None = None) -> str:
    protocol = normalize_security_protocol(security_protocol or layout.default_security_protocol)
    return "\n".join(
        [
            f"SIEM_KAFKA_BOOTSTRAP_SERVERS={bootstrap_servers(layout)}",
            f"SIEM_KAFKA_SECURITY_PROTOCOL={protocol}",
            f"SIEM_KAFKA_EXPECTED_BROKERS={len(layout.nodes)}",
            f"SIEM_KAFKA_EXPECTED_CONTROLLERS={len(layout.nodes)}",
            f"SIEM_KAFKA_DEFAULT_REPLICATION_FACTOR={layout.replication_factor}",
            f"SIEM_KAFKA_MIN_INSYNC_REPLICAS={layout.min_insync_replicas}",
            "KAFKA_HEAP_OPTS=-Xms256m -Xmx512m",
            "KAFKA_JVM_PERFORMANCE_OPTS=-server -XX:+UseG1GC -XX:MaxGCPauseMillis=200 -XX:+UseStringDeduplication",
            "LOG_DIR=/var/log/siem-kafka",
            "SIEM_TRANSPORT_BACKEND=dual",
        ]
    ) + "\n"


def build_systemd_unit() -> str:
    return "\n".join(
        [
            "[Unit]",
            "Description=SIEM Kafka KRaft broker",
            "After=network-online.target",
            "Wants=network-online.target",
            "",
            "[Service]",
            "Type=simple",
            "User=siem",
            "Group=siem",
            "EnvironmentFile=/etc/siem/kafka/kafka.env",
            "WorkingDirectory=/opt/kafka",
            "ExecStart=/opt/kafka/bin/kafka-server-start.sh /etc/siem/kafka/server.properties",
            "ExecStop=/opt/kafka/bin/kafka-server-stop.sh",
            "Restart=always",
            "RestartSec=5",
            "LimitNOFILE=65536",
            "",
            "[Install]",
            "WantedBy=multi-user.target",
        ]
    ) + "\n"
