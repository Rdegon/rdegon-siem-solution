from __future__ import annotations

import os
import shlex
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from deploy.kafka_cluster_layout import build_env_exports, default_lab_kafka_layout  # noqa: E402
from deploy.kafka_wave_prepare import KAFKA_CLIENT_PROPERTIES, KAFKA_HOME  # noqa: E402


def topic_retention_configs() -> dict[str, dict[str, int | str]]:
    day_ms = 24 * 60 * 60 * 1000
    gib = 1024 * 1024 * 1024
    return {
        "siem.raw": {
            "retention.ms": 2 * day_ms,
            "retention.bytes": 256 * 1024 * 1024,
            "segment.bytes": 128 * 1024 * 1024,
            "segment.ms": 60 * 60 * 1000,
            "cleanup.policy": "delete",
        },
        "siem.normalized": {
            "retention.ms": 2 * day_ms,
            "retention.bytes": 384 * 1024 * 1024,
            "segment.bytes": 128 * 1024 * 1024,
            "segment.ms": 60 * 60 * 1000,
            "cleanup.policy": "delete",
        },
        "siem.filtered": {
            "retention.ms": 2 * day_ms,
            "retention.bytes": 384 * 1024 * 1024,
            "segment.bytes": 128 * 1024 * 1024,
            "segment.ms": 60 * 60 * 1000,
            "cleanup.policy": "delete",
        },
        "siem.dlq": {
            "retention.ms": 7 * day_ms,
            "retention.bytes": 256 * 1024 * 1024,
            "segment.bytes": 128 * 1024 * 1024,
            "segment.ms": 60 * 60 * 1000,
            "cleanup.policy": "delete",
        },
        "siem.replay": {
            "retention.ms": 7 * day_ms,
            "retention.bytes": 256 * 1024 * 1024,
            "segment.bytes": 128 * 1024 * 1024,
            "segment.ms": 60 * 60 * 1000,
            "cleanup.policy": "delete",
        },
        "siem.transport.audit": {
            "retention.ms": 7 * day_ms,
            "retention.bytes": 128 * 1024 * 1024,
            "segment.bytes": 128 * 1024 * 1024,
            "segment.ms": 60 * 60 * 1000,
            "cleanup.policy": "delete",
        },
    }


def _required_env(name: str, *, default: str | None = None) -> str:
    value = str(os.getenv(name, default or "") or "").strip()
    if value:
        return value
    raise SystemExit(f"Missing required environment variable: {name}")


def _run(command: str, *, sudo_password: str = "", use_sudo: bool = False, timeout: int = 180) -> tuple[int, str, str]:
    wrapped = f"sudo -S -p '' bash -lc {shlex.quote(command)}" if use_sudo else command
    proc = subprocess.run(
        ["bash", "-lc", wrapped],
        input=f"{sudo_password}\n" if use_sudo else None,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return proc.returncode, proc.stdout, proc.stderr


def _strip_sudo_echo(text: str, sudo_password: str) -> str:
    if not sudo_password:
        return text
    cleaned: list[str] = []
    for raw_line in str(text or "").replace("\r", "\n").split("\n"):
        if raw_line.strip() == sudo_password:
            continue
        cleaned.append(raw_line)
    return "\n".join(cleaned)


def _command_config_fragment(security_protocol: str) -> str:
    if security_protocol.upper() == "PLAINTEXT":
        return ""
    return f" --command-config {shlex.quote(str(KAFKA_CLIENT_PROPERTIES))}"


def main() -> int:
    sudo_password = _required_env("SIEM_NODE_PASSWORD")
    expected_host = _required_env("SIEM_KAFKA_EXPECT_HOST")
    security_protocol = str(os.getenv("SIEM_KAFKA_SECURITY_PROTOCOL", default_lab_kafka_layout().default_security_protocol) or default_lab_kafka_layout().default_security_protocol).strip().upper()

    code, out, err = _run("hostname")
    hostname = out.strip()
    if code != 0 or not hostname:
        raise SystemExit(f"Unable to read local hostname: {err.strip()}")
    if hostname != expected_host:
        raise SystemExit(f"This topic bootstrap script must run on {expected_host}, got {hostname}")

    env_exports = build_env_exports(default_lab_kafka_layout(), security_protocol=security_protocol)
    env_map: dict[str, str] = {}
    for line in env_exports.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        env_map[key.strip()] = value.strip()
    bootstrap = env_map["SIEM_KAFKA_BOOTSTRAP_SERVERS"]
    replication_factor = env_map["SIEM_KAFKA_DEFAULT_REPLICATION_FACTOR"]

    topics = [
        (env_map.get("SIEM_KAFKA_TOPIC_RAW", "siem.raw"), 12),
        (env_map.get("SIEM_KAFKA_TOPIC_NORMALIZED", "siem.normalized"), 12),
        (env_map.get("SIEM_KAFKA_TOPIC_FILTERED", "siem.filtered"), 12),
        (env_map.get("SIEM_KAFKA_TOPIC_DLQ", "siem.dlq"), 6),
        (env_map.get("SIEM_KAFKA_TOPIC_REPLAY", "siem.replay"), 6),
        (env_map.get("SIEM_KAFKA_TOPIC_TRANSPORT_AUDIT", "siem.transport.audit"), 3),
    ]
    retention_by_topic = topic_retention_configs()
    command_config = _command_config_fragment(security_protocol)
    for topic_name, partitions in topics:
        create_cmd = (
            f"{shlex.quote(str(KAFKA_HOME / 'bin/kafka-topics.sh'))}"
            f" --bootstrap-server {shlex.quote(bootstrap)}"
            f"{command_config}"
            f" --create --if-not-exists --topic {shlex.quote(topic_name)}"
            f" --partitions {partitions} --replication-factor {replication_factor}"
        )
        code, out, err = _run(create_cmd, sudo_password=sudo_password, use_sudo=True, timeout=180)
        cleaned = _strip_sudo_echo(out, sudo_password)
        if cleaned.strip():
            print(cleaned, end="")
        if code != 0 and "Topic" not in cleaned and "already exists" not in cleaned:
            raise SystemExit(f"Failed to create topic {topic_name}: stdout={cleaned.strip()} stderr={err.strip()}")
        config_map = retention_by_topic.get(topic_name)
        if config_map:
            config_value = ",".join(f"{key}={value}" for key, value in config_map.items())
            alter_cmd = (
                f"{shlex.quote(str(KAFKA_HOME / 'bin/kafka-configs.sh'))}"
                f" --bootstrap-server {shlex.quote(bootstrap)}"
                f"{command_config}"
                f" --entity-type topics --entity-name {shlex.quote(topic_name)}"
                f" --alter --add-config {shlex.quote(config_value)}"
            )
            code, out, err = _run(alter_cmd, sudo_password=sudo_password, use_sudo=True, timeout=180)
            cleaned = _strip_sudo_echo(out, sudo_password)
            if cleaned.strip():
                print(cleaned, end="")
            if code != 0:
                raise SystemExit(
                    f"Failed to apply Kafka topic retention to {topic_name}: stdout={cleaned.strip()} stderr={err.strip()}"
                )
        print(f"topic={topic_name} partitions={partitions} replication_factor={replication_factor}")

    list_cmd = f"{shlex.quote(str(KAFKA_HOME / 'bin/kafka-topics.sh'))} --bootstrap-server {shlex.quote(bootstrap)}{command_config} --list"
    code, out, err = _run(list_cmd, sudo_password=sudo_password, use_sudo=True, timeout=120)
    cleaned = _strip_sudo_echo(out, sudo_password)
    if code != 0:
        raise SystemExit(f"Failed to list Kafka topics: stdout={cleaned.strip()} stderr={err.strip()}")
    listed = {line.strip() for line in cleaned.splitlines() if line.strip()}
    missing = [topic for topic, _ in topics if topic not in listed]
    if missing:
        raise SystemExit(f"Kafka topic bootstrap incomplete, missing={missing}")
    print("topic_bootstrap=success")
    return 0


if __name__ == "__main__":
    sys.exit(main())
