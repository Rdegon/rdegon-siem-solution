from __future__ import annotations

import base64
import json
import os
import shlex
from pathlib import Path

try:
    from deploy.soc_foundation_provision import Proxmox
except ModuleNotFoundError:
    from soc_foundation_provision import Proxmox


ROOT = Path(__file__).resolve().parents[1]


def _write_vm(pve: Proxmox, vmid: int, path: str, content: bytes, mode: int) -> None:
    encoded = base64.b64encode(content).decode("ascii")
    parent = str(Path(path).parent).replace("\\", "/")
    temp = f"/tmp/soc-integration-{os.getpid()}-{Path(path).name}.b64"
    pve.guest_exec(vmid, f"install -d -m 0755 {shlex.quote(parent)}; : > {shlex.quote(temp)}")
    try:
        for offset in range(0, len(encoded), 24_000):
            pve.guest_exec(
                vmid,
                f"printf %s {shlex.quote(encoded[offset:offset + 24_000])} "
                f">> {shlex.quote(temp)}",
            )
        pve.guest_exec(
            vmid,
            f"base64 -d {shlex.quote(temp)} > {shlex.quote(path)} && "
            f"chmod {mode:o} {shlex.quote(path)}",
        )
    finally:
        pve.guest_exec(vmid, f"rm -f {shlex.quote(temp)}")


def _write_ct(pve: Proxmox, vmid: int, path: str, content: bytes, mode: int) -> None:
    encoded = base64.b64encode(content).decode("ascii")
    parent = str(Path(path).parent).replace("\\", "/")
    temp = f"/tmp/soc-integration-{os.getpid()}-{Path(path).name}.b64"
    pve.ct(vmid, f"install -d -m 0755 {shlex.quote(parent)}; : > {shlex.quote(temp)}")
    try:
        for offset in range(0, len(encoded), 24_000):
            pve.ct(
                vmid,
                f"printf %s {shlex.quote(encoded[offset:offset + 24_000])} "
                f">> {shlex.quote(temp)}",
            )
        pve.ct(
            vmid,
            f"base64 -d {shlex.quote(temp)} > {shlex.quote(path)} && "
            f"chmod {mode:o} {shlex.quote(path)}",
        )
    finally:
        pve.ct(vmid, f"rm -f {shlex.quote(temp)}")


def _deploy_misp(pve: Proxmox, ingest_certificate: str) -> dict[str, str]:
    files = (
        (
            ROOT / "deploy/misp_event_exporter.py",
            "/opt/siem/deploy/misp_event_exporter.py",
            0o755,
        ),
        (
            ROOT / "deploy/misp_feed_cache.py",
            "/opt/siem/deploy/misp_feed_cache.py",
            0o755,
        ),
        (
            ROOT / "deploy/security_sensor_forwarder.py",
            "/opt/siem/deploy/security_sensor_forwarder.py",
            0o755,
        ),
        (
            ROOT / "deploy/systemd/siem-misp-exporter.service",
            "/etc/systemd/system/siem-misp-exporter.service",
            0o644,
        ),
        (
            ROOT / "deploy/systemd/siem-misp-exporter.timer",
            "/etc/systemd/system/siem-misp-exporter.timer",
            0o644,
        ),
        (
            ROOT / "deploy/systemd/siem-misp-feed-cache.service",
            "/etc/systemd/system/siem-misp-feed-cache.service",
            0o644,
        ),
        (
            ROOT / "deploy/systemd/siem-misp-feed-cache.timer",
            "/etc/systemd/system/siem-misp-feed-cache.timer",
            0o644,
        ),
        (
            ROOT / "deploy/systemd/siem-security-sensor-forwarder@.service",
            "/etc/systemd/system/siem-security-sensor-forwarder@.service",
            0o644,
        ),
    )
    for source, destination, mode in files:
        _write_vm(pve, 131, destination, source.read_bytes(), mode)
    _write_vm(
        pve,
        131,
        "/etc/siem/pki/ingest-ca.crt",
        ingest_certificate.encode("ascii"),
        0o644,
    )
    pve.guest_exec(
        131,
        """
set -euo pipefail
install -d -m 0750 /var/lib/siem-misp-exporter /var/lib/siem-security-forwarder /var/log/siem /etc/siem/pki
touch /var/log/siem/misp-events.jsonl
chmod 0640 /var/log/siem/misp-events.jsonl
cat >/etc/siem/security-sensor-misp.env <<'EOF'
SIEM_SENSOR_KIND=misp
SIEM_SENSOR_FORMAT=jsonl
SIEM_SENSOR_PATHS=/var/log/siem/misp-events.jsonl
SIEM_SENSOR_HOSTNAME=soc-ti-01
SIEM_SENSOR_INGEST_URL=https://10.20.10.104/ingest/json
SIEM_SENSOR_TLS_VERIFY=required
SIEM_SENSOR_CA_FILE=/etc/siem/pki/ingest-ca.crt
SIEM_SENSOR_START_POSITION=beginning
SIEM_SENSOR_BATCH_SIZE=250
SIEM_SENSOR_READ_LIMIT=2000
SIEM_SENSOR_SPOOL_MAX_BYTES=536870912
SIEM_SENSOR_INTERVAL_SECONDS=2
EOF
chmod 0640 /etc/siem/security-sensor-misp.env
/usr/bin/python3 -m py_compile \
  /opt/siem/deploy/misp_event_exporter.py \
  /opt/siem/deploy/security_sensor_forwarder.py
systemctl daemon-reload
systemctl enable --now siem-misp-exporter.timer
systemctl start siem-misp-exporter.service
systemctl enable --now siem-misp-feed-cache.timer
systemctl start siem-misp-feed-cache.service
systemctl enable --now siem-security-sensor-forwarder@misp.service
systemctl restart siem-security-sensor-forwarder@misp.service
systemctl is-active --quiet siem-misp-exporter.timer
systemctl is-active --quiet siem-misp-feed-cache.timer
systemctl is-active --quiet siem-security-sensor-forwarder@misp.service
""",
        timeout=300,
    )
    return {
        "exporter_timer": "active",
        "forwarder": "active",
        "api_key": "managed-locally",
    }


def _deploy_velociraptor(pve: Proxmox, ingest_certificate: str) -> dict[str, str]:
    files = (
        (
            ROOT / "deploy/velociraptor_flow_exporter.py",
            "/opt/siem/deploy/velociraptor_flow_exporter.py",
            0o755,
        ),
        (
            ROOT / "deploy/security_sensor_forwarder.py",
            "/opt/siem/deploy/security_sensor_forwarder.py",
            0o755,
        ),
        (
            ROOT / "deploy/systemd/siem-security-sensor-forwarder@.service",
            "/etc/systemd/system/siem-security-sensor-forwarder@.service",
            0o644,
        ),
        (
            ROOT / "deploy/systemd/siem-velociraptor-flow-exporter.service",
            "/etc/systemd/system/siem-velociraptor-flow-exporter.service",
            0o644,
        ),
        (
            ROOT / "deploy/systemd/siem-velociraptor-flow-exporter.timer",
            "/etc/systemd/system/siem-velociraptor-flow-exporter.timer",
            0o644,
        ),
    )
    for source, destination, mode in files:
        _write_ct(pve, 128, destination, source.read_bytes(), mode)
    _write_ct(
        pve,
        128,
        "/etc/siem/pki/ingest-ca.crt",
        ingest_certificate.encode("ascii"),
        0o644,
    )
    pve.ct(
        128,
        """
set -euo pipefail
install -d -m 0750 /var/lib/siem-security-forwarder /etc/siem/pki
install -d -o velociraptor -g velociraptor -m 0750 \
  /var/lib/siem-velociraptor-exporter /var/log/siem
touch /var/log/siem/velociraptor-client-flows.jsonl
chown velociraptor:velociraptor /var/log/siem/velociraptor-client-flows.jsonl
chmod 0640 /var/log/siem/velociraptor-client-flows.jsonl
cat >/etc/siem/security-sensor-velociraptor.env <<'EOF'
SIEM_SENSOR_KIND=velociraptor
SIEM_SENSOR_FORMAT=jsonl
SIEM_SENSOR_PATHS=/var/lib/velociraptor/server_artifacts/*/*/*.json;/var/log/siem/velociraptor-client-flows.jsonl
SIEM_SENSOR_HOSTNAME=soc-dfir-01
SIEM_SENSOR_INGEST_URL=https://10.20.10.104/ingest/json
SIEM_SENSOR_TLS_VERIFY=required
SIEM_SENSOR_CA_FILE=/etc/siem/pki/ingest-ca.crt
SIEM_SENSOR_START_POSITION=beginning
SIEM_SENSOR_BATCH_SIZE=250
SIEM_SENSOR_READ_LIMIT=2000
SIEM_SENSOR_SPOOL_MAX_BYTES=536870912
SIEM_SENSOR_INTERVAL_SECONDS=5
EOF
chmod 0640 /etc/siem/security-sensor-velociraptor.env
/usr/bin/python3 -m py_compile \
  /opt/siem/deploy/security_sensor_forwarder.py \
  /opt/siem/deploy/velociraptor_flow_exporter.py
systemctl daemon-reload
systemctl enable --now siem-velociraptor-flow-exporter.timer
systemctl start siem-velociraptor-flow-exporter.service
systemctl enable --now siem-security-sensor-forwarder@velociraptor.service
systemctl restart siem-security-sensor-forwarder@velociraptor.service
systemctl is-active --quiet velociraptor.service
systemctl is-active --quiet siem-velociraptor-flow-exporter.timer
systemctl is-active --quiet siem-security-sensor-forwarder@velociraptor.service
""",
        timeout=300,
    )
    return {"server": "active", "flow_exporter_timer": "active", "forwarder": "active"}


def main() -> int:
    with Proxmox() as pve:
        ingest_certificate = pve.guest_exec(104, "cat /etc/siem/tls/ingest.crt")
        if "BEGIN CERTIFICATE" not in ingest_certificate:
            raise RuntimeError("VM104 did not return the ingest certificate")
        result = {
            "misp": _deploy_misp(pve, ingest_certificate),
            "velociraptor": _deploy_velociraptor(pve, ingest_certificate),
        }
        print(json.dumps(result, indent=2, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
