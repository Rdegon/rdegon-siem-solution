from __future__ import annotations

import base64
import os
import shlex
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from deploy.kafka_cluster_layout import (  # noqa: E402
    KafkaNodeLayout,
    build_env_exports,
    build_server_properties,
    build_systemd_unit,
    default_lab_kafka_layout,
    normalize_security_protocol,
)


KAFKA_ETC_DIR = Path("/etc/siem/kafka")
KAFKA_SERVER_PROPERTIES = KAFKA_ETC_DIR / "server.properties"
KAFKA_ENV_FILE = KAFKA_ETC_DIR / "kafka.env"
KAFKA_CLIENT_PROPERTIES = KAFKA_ETC_DIR / "client.properties"
KAFKA_CLUSTER_ID_FILE = KAFKA_ETC_DIR / "cluster.id"
KAFKA_SYSTEMD_UNIT = Path("/etc/systemd/system/siem-kafka.service")
KAFKA_INSTALL_ROOT = Path("/opt/siem")
KAFKA_HOME = Path("/opt/kafka")
KAFKA_BINARY = KAFKA_HOME / "bin/kafka-server-start.sh"
KAFKA_STORAGE_TOOL = KAFKA_HOME / "bin/kafka-storage.sh"
DEFAULT_KAFKA_VERSION = "3.7.1"
DEFAULT_SCALA_VERSION = "2.13"


def _required_env(name: str, *, default: str | None = None) -> str:
    value = str(os.getenv(name, default or "") or "").strip()
    if value:
        return value
    raise SystemExit(f"Missing required environment variable: {name}")


def _run(command: str, *, sudo_password: str = "", use_sudo: bool = False, timeout: int = 240) -> tuple[int, str, str]:
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


def _random_cluster_id() -> str:
    return base64.urlsafe_b64encode(uuid.uuid4().bytes).decode("ascii").rstrip("=")


def deterministic_cluster_id(cluster_name: str) -> str:
    seed = uuid.uuid5(uuid.NAMESPACE_DNS, f"rdegon-siem-kraft:{cluster_name}")
    return base64.urlsafe_b64encode(seed.bytes).decode("ascii").rstrip("=")


def resolve_layout_node(node_id: int) -> KafkaNodeLayout:
    layout = default_lab_kafka_layout()
    for node in layout.nodes:
        if int(node.node_id) == int(node_id):
            return node
    raise SystemExit(f"Unknown Kafka node id for lab layout: {node_id}")


def render_client_properties(*, security_protocol: str) -> str:
    protocol = normalize_security_protocol(security_protocol)
    return "\n".join(
        [
            f"security.protocol={protocol}",
            "request.timeout.ms=15000",
        ]
    ) + "\n"


def render_firewall_prepare_command() -> str:
    layout = default_lab_kafka_layout()
    allow_rules: list[str] = []
    broker_client_hosts = sorted(
        {
            *(node.host for node in layout.nodes),
            "192.168.1.38",  # VM3 storage/shadow writer
            "192.168.1.39",  # VM4 web health/runtime checks
        }
    )
    controller_hosts = [node.host for node in layout.nodes]
    for host in broker_client_hosts:
        allow_rules.append(f"ufw allow from {host} to any port 9092 proto tcp >/dev/null 2>&1 || true")
    for host in controller_hosts:
        allow_rules.append(f"ufw allow from {host} to any port 9093 proto tcp >/dev/null 2>&1 || true")
    return (
        "if command -v ufw >/dev/null 2>&1 && ufw status | head -n 1 | grep -qi active; then "
        + " && ".join(allow_rules)
        + "; fi"
    )


def render_kafka_prepare_payload(
    node_id: int,
    *,
    security_protocol: str | None = None,
    cluster_id: str,
    kafka_version: str = DEFAULT_KAFKA_VERSION,
    scala_version: str = DEFAULT_SCALA_VERSION,
) -> dict[str, str]:
    layout = default_lab_kafka_layout()
    node = resolve_layout_node(node_id)
    protocol = normalize_security_protocol(security_protocol or layout.default_security_protocol)
    env_exports = build_env_exports(layout, security_protocol=protocol) + "\n".join(
        [
            f"SIEM_KAFKA_NODE_ID={node.node_id}",
            f"SIEM_KAFKA_CLUSTER_ID={cluster_id}",
            f"SIEM_KAFKA_VERSION={kafka_version}",
            f"SIEM_KAFKA_SCALA_VERSION={scala_version}",
        ]
    ) + "\n"
    return {
        "server_properties": build_server_properties(layout, node, security_protocol=protocol),
        "kafka_env": env_exports,
        "systemd_unit": build_systemd_unit(),
        "client_properties": render_client_properties(security_protocol=protocol),
        "node_host": node.host,
        "node_role_name": node.role_name,
        "cluster_id": cluster_id,
        "security_protocol": protocol,
        "kafka_version": kafka_version,
        "scala_version": scala_version,
    }


def _read_existing_cluster_id(sudo_password: str) -> str:
    code, out, err = _run(
        f"test -f {shlex.quote(str(KAFKA_CLUSTER_ID_FILE))} && cat {shlex.quote(str(KAFKA_CLUSTER_ID_FILE))} || true",
        sudo_password=sudo_password,
        use_sudo=True,
    )
    current = _strip_sudo_echo(out, sudo_password).strip()
    if code == 0 and current:
        return current
    return ""


def _resolve_cluster_id(sudo_password: str, requested_cluster_id: str) -> str:
    if requested_cluster_id:
        return requested_cluster_id
    return deterministic_cluster_id(default_lab_kafka_layout().cluster_name)


def main() -> int:
    sudo_password = _required_env("SIEM_NODE_PASSWORD")
    node_id = int(_required_env("SIEM_KAFKA_NODE_ID"))
    expected_host = str(os.getenv("SIEM_KAFKA_EXPECT_HOST", "") or "").strip()
    requested_cluster_id = str(os.getenv("SIEM_KAFKA_CLUSTER_ID", "") or "").strip()
    kafka_version = str(os.getenv("SIEM_KAFKA_VERSION", DEFAULT_KAFKA_VERSION) or DEFAULT_KAFKA_VERSION).strip()
    scala_version = str(os.getenv("SIEM_KAFKA_SCALA_VERSION", DEFAULT_SCALA_VERSION) or DEFAULT_SCALA_VERSION).strip()
    security_protocol = normalize_security_protocol(os.getenv("SIEM_KAFKA_SECURITY_PROTOCOL", default_lab_kafka_layout().default_security_protocol))

    code, out, err = _run("hostname")
    hostname = out.strip()
    if code != 0 or not hostname:
        raise SystemExit(f"Unable to read local hostname: {err.strip()}")
    if expected_host and hostname != expected_host:
        raise SystemExit(f"This prepare script must run on {expected_host}, got {hostname}")

    existing_cluster_id = _read_existing_cluster_id(sudo_password)
    cluster_id = _resolve_cluster_id(sudo_password, requested_cluster_id)
    cluster_reset_required = bool(existing_cluster_id and existing_cluster_id != cluster_id)
    node = resolve_layout_node(node_id)
    firewall_prepare_cmd = render_firewall_prepare_command()
    payload = render_kafka_prepare_payload(
        node_id,
        security_protocol=security_protocol,
        cluster_id=cluster_id,
        kafka_version=kafka_version,
        scala_version=scala_version,
    )
    temp_root = Path.cwd() / ".tmp"
    temp_root.mkdir(parents=True, exist_ok=True)
    temp_properties = temp_root / "siem-kafka-server.properties"
    temp_env = temp_root / "siem-kafka.env"
    temp_unit = temp_root / "siem-kafka.service"
    temp_client = temp_root / "siem-kafka-client.properties"
    temp_cluster_id = temp_root / "siem-kafka.cluster.id"
    temp_properties.write_text(payload["server_properties"], encoding="utf-8")
    temp_env.write_text(payload["kafka_env"], encoding="utf-8")
    temp_unit.write_text(payload["systemd_unit"], encoding="utf-8")
    temp_client.write_text(payload["client_properties"], encoding="utf-8")
    temp_cluster_id.write_text(cluster_id + "\n", encoding="utf-8")

    backup_root = f"/tmp/siem-kafka-prepare-backup-{datetime.now(tz=timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
    backup_cmd = (
        f"mkdir -p {shlex.quote(backup_root)} && "
        f"if [ -f {shlex.quote(str(KAFKA_SERVER_PROPERTIES))} ]; then cp {shlex.quote(str(KAFKA_SERVER_PROPERTIES))} {shlex.quote(backup_root + '/server.properties')}; fi && "
        f"if [ -f {shlex.quote(str(KAFKA_ENV_FILE))} ]; then cp {shlex.quote(str(KAFKA_ENV_FILE))} {shlex.quote(backup_root + '/kafka.env')}; fi && "
        f"if [ -f {shlex.quote(str(KAFKA_SYSTEMD_UNIT))} ]; then cp {shlex.quote(str(KAFKA_SYSTEMD_UNIT))} {shlex.quote(backup_root + '/siem-kafka.service')}; fi && "
        f"if [ -f {shlex.quote(str(KAFKA_CLUSTER_ID_FILE))} ]; then cp {shlex.quote(str(KAFKA_CLUSTER_ID_FILE))} {shlex.quote(backup_root + '/cluster.id')}; fi && "
        f"if [ -f {shlex.quote(str(KAFKA_CLIENT_PROPERTIES))} ]; then cp {shlex.quote(str(KAFKA_CLIENT_PROPERTIES))} {shlex.quote(backup_root + '/client.properties')}; fi"
    )
    code, out, err = _run(backup_cmd, sudo_password=sudo_password, use_sudo=True)
    if code != 0:
        raise SystemExit(f"Unable to back up Kafka config files: {err.strip()}")

    release_name = f"kafka_{scala_version}-{kafka_version}"
    archive_name = f"{release_name}.tgz"
    release_dir = KAFKA_INSTALL_ROOT / release_name
    archive_url = f"https://archive.apache.org/dist/kafka/{kafka_version}/{archive_name}"
    install_cmd = (
        "export DEBIAN_FRONTEND=noninteractive && "
        "apt-get update -y && "
        "apt-get install -y openjdk-17-jre-headless curl ca-certificates tar && "
        f"install -d -m 0755 {shlex.quote(str(KAFKA_INSTALL_ROOT))} {shlex.quote(str(KAFKA_ETC_DIR))} "
        f"{shlex.quote(node.data_dir)} {shlex.quote(node.log_dir)} && "
        f"chown -R siem:siem {shlex.quote(node.data_dir)} {shlex.quote(node.log_dir)} && "
        f"if [ ! -x {shlex.quote(str(release_dir / 'bin/kafka-server-start.sh'))} ]; then "
        f"cd {shlex.quote(str(KAFKA_INSTALL_ROOT))} && "
        f"rm -f {shlex.quote(str(KAFKA_INSTALL_ROOT / archive_name))} && "
        f"curl -fsSL {shlex.quote(archive_url)} -o {shlex.quote(str(KAFKA_INSTALL_ROOT / archive_name))} && "
        f"tar -xzf {shlex.quote(str(KAFKA_INSTALL_ROOT / archive_name))}; "
        "fi && "
        f"install -d -m 0755 {shlex.quote(str(release_dir / 'logs'))} && "
        f"chown -R siem:siem {shlex.quote(str(release_dir / 'logs'))} && "
        f"ln -sfn {shlex.quote(str(release_dir))} {shlex.quote(str(KAFKA_HOME))}"
    )
    code, out, err = _run(install_cmd, sudo_password=sudo_password, use_sudo=True, timeout=900)
    cleaned = _strip_sudo_echo(out, sudo_password)
    if cleaned.strip():
        print(cleaned, end="")
    if code != 0:
        raise SystemExit(f"Unable to install Kafka runtime: {err.strip()}")

    install_config_cmd = (
        f"install -m 0644 {shlex.quote(str(temp_properties))} {shlex.quote(str(KAFKA_SERVER_PROPERTIES))} && "
        f"install -m 0600 {shlex.quote(str(temp_env))} {shlex.quote(str(KAFKA_ENV_FILE))} && "
        f"install -m 0600 {shlex.quote(str(temp_client))} {shlex.quote(str(KAFKA_CLIENT_PROPERTIES))} && "
        f"install -m 0600 {shlex.quote(str(temp_cluster_id))} {shlex.quote(str(KAFKA_CLUSTER_ID_FILE))} && "
        f"install -m 0644 {shlex.quote(str(temp_unit))} {shlex.quote(str(KAFKA_SYSTEMD_UNIT))} && "
        "systemctl daemon-reload"
    )
    code, out, err = _run(install_config_cmd, sudo_password=sudo_password, use_sudo=True)
    cleaned = _strip_sudo_echo(out, sudo_password)
    if cleaned.strip():
        print(cleaned, end="")
    if code != 0:
        raise SystemExit(f"Unable to install Kafka wave files: {err.strip()}")

    code, out, err = _run(firewall_prepare_cmd, sudo_password=sudo_password, use_sudo=True, timeout=180)
    cleaned = _strip_sudo_echo(out, sudo_password)
    if cleaned.strip():
        print(cleaned, end="")
    if code != 0:
        raise SystemExit(f"Unable to configure Kafka firewall rules: {err.strip()}")

    if cluster_reset_required:
        reset_cmd = (
            "systemctl stop siem-kafka || true && "
            f"rm -rf {shlex.quote(node.data_dir)}/*"
        )
        code, out, err = _run(reset_cmd, sudo_password=sudo_password, use_sudo=True, timeout=180)
        cleaned = _strip_sudo_echo(out, sudo_password)
        if cleaned.strip():
            print(cleaned, end="")
        if code != 0:
            raise SystemExit(f"Unable to reset Kafka data dir for cluster id change: {err.strip()}")
        print(f"kafka_cluster_id_reset=from:{existing_cluster_id}->to:{cluster_id}")

    format_cmd = (
        f"runuser -u siem -- {shlex.quote(str(KAFKA_STORAGE_TOOL))} "
        f"format --cluster-id $(cat {shlex.quote(str(KAFKA_CLUSTER_ID_FILE))}) "
        f"--config {shlex.quote(str(KAFKA_SERVER_PROPERTIES))} --ignore-formatted"
    )
    code, out, err = _run(format_cmd, sudo_password=sudo_password, use_sudo=True, timeout=300)
    cleaned = _strip_sudo_echo(out, sudo_password)
    if cleaned.strip():
        print(cleaned, end="")
    if code != 0:
        raise SystemExit(f"Kafka storage format failed: stdout={cleaned.strip()} stderr={err.strip()}")

    start_cmd = "systemctl enable --now siem-kafka && systemctl is-active siem-kafka"
    code, out, err = _run(start_cmd, sudo_password=sudo_password, use_sudo=True, timeout=180)
    cleaned = _strip_sudo_echo(out, sudo_password)
    if cleaned.strip():
        print(cleaned, end="")
    if code != 0 or "active" not in cleaned:
        raise SystemExit(f"Kafka service did not become active: stdout={cleaned.strip()} stderr={err.strip()}")

    verify_cmd = (
        "python3 - <<'PY'\n"
        "from pathlib import Path\n"
        f"props = Path({str(KAFKA_SERVER_PROPERTIES)!r}).read_text(encoding='utf-8')\n"
        f"env = Path({str(KAFKA_ENV_FILE)!r}).read_text(encoding='utf-8')\n"
        f"cluster_id = Path({str(KAFKA_CLUSTER_ID_FILE)!r}).read_text(encoding='utf-8').strip()\n"
        f"required_props = ['node.id={node_id}', 'process.roles=broker,controller', 'min.insync.replicas=2']\n"
        "for needle in required_props:\n"
        "    if needle not in props:\n"
        "        raise SystemExit(f'missing server.properties setting: {needle}')\n"
        "for needle in ['SIEM_KAFKA_BOOTSTRAP_SERVERS=', 'SIEM_KAFKA_CLUSTER_ID=', 'SIEM_KAFKA_SECURITY_PROTOCOL=']:\n"
        "    if needle not in env:\n"
        "        raise SystemExit(f'missing kafka.env setting: {needle}')\n"
        "if 'LOG_DIR=/var/log/siem-kafka' not in env:\n"
        "    raise SystemExit('missing kafka.env setting: LOG_DIR')\n"
        "if not cluster_id:\n"
        "    raise SystemExit('missing cluster.id value')\n"
        "print('kafka_prepare=ok')\n"
        "PY"
    )
    code, out, err = _run(verify_cmd, sudo_password=sudo_password, use_sudo=True)
    cleaned = _strip_sudo_echo(out, sudo_password)
    if cleaned.strip():
        print(cleaned, end="")
    if code != 0:
        raise SystemExit(f"Kafka prepare verification failed: stdout={cleaned.strip()} stderr={err.strip()}")

    print(f"node_id={node_id}")
    print(f"node_role_name={payload['node_role_name']}")
    print(f"node_host={payload['node_host']}")
    print(f"cluster_id={cluster_id}")
    print(f"security_protocol={payload['security_protocol']}")
    print("service_mode=active")
    print(f"kafka_release={release_name}")
    print(f"backup_root={backup_root}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
