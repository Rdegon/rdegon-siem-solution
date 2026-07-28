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
            ROOT / "deploy/misp_curated_feed_sync.py",
            "/opt/siem/deploy/misp_curated_feed_sync.py",
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
  /opt/siem/deploy/misp_curated_feed_sync.py \
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


def _deploy_misp_enrichment(pve: Proxmox) -> dict[str, str]:
    files = (
        (
            ROOT / "deploy/misp_ioc_sync.sh",
            "/usr/local/sbin/siem-misp-ioc-sync",
            0o755,
        ),
        (
            ROOT / "deploy/systemd/siem-misp-ioc-sync.service",
            "/etc/systemd/system/siem-misp-ioc-sync.service",
            0o644,
        ),
        (
            ROOT / "deploy/systemd/siem-misp-ioc-sync.timer",
            "/etc/systemd/system/siem-misp-ioc-sync.timer",
            0o644,
        ),
    )
    for source, destination, mode in files:
        _write_vm(pve, 106, destination, source.read_bytes(), mode)
    output = pve.guest_exec(
        106,
        """
set -euo pipefail
systemctl daemon-reload
systemctl enable --now siem-misp-ioc-sync.timer
systemctl start siem-misp-ioc-sync.service
systemctl is-active --quiet siem-misp-ioc-sync.timer
journalctl -u siem-misp-ioc-sync.service -n 1 --no-pager -o cat
""",
        timeout=600,
    ).strip()
    return {"timer": "active", "sync": output or "completed"}


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


def _deploy_step_ca(pve: Proxmox, ingest_certificate: str) -> dict[str, str]:
    files = (
        (
            ROOT / "deploy/journal_event_exporter.py",
            "/opt/siem/deploy/journal_event_exporter.py",
            0o755,
        ),
        (
            ROOT / "deploy/security_sensor_forwarder.py",
            "/opt/siem/deploy/security_sensor_forwarder.py",
            0o755,
        ),
        (
            ROOT / "deploy/systemd/siem-journal-event-exporter@.service",
            "/etc/systemd/system/siem-journal-event-exporter@.service",
            0o644,
        ),
        (
            ROOT / "deploy/systemd/siem-journal-event-exporter@.timer",
            "/etc/systemd/system/siem-journal-event-exporter@.timer",
            0o644,
        ),
        (
            ROOT / "deploy/systemd/siem-security-sensor-forwarder@.service",
            "/etc/systemd/system/siem-security-sensor-forwarder@.service",
            0o644,
        ),
    )
    for source, destination, mode in files:
        _write_ct(pve, 132, destination, source.read_bytes(), mode)
    _write_ct(
        pve,
        132,
        "/etc/siem/pki/ingest-ca.crt",
        ingest_certificate.encode("ascii"),
        0o644,
    )
    pve.ct(
        132,
        """
set -euo pipefail
install -d -m 0750 \
  /var/lib/siem-journal-exporter \
  /var/lib/siem-security-forwarder \
  /var/log/siem \
  /etc/siem/pki
touch /var/log/siem/step-ca-audit.jsonl
chmod 0640 /var/log/siem/step-ca-audit.jsonl
cat >/etc/siem/journal-exporter-step-ca.env <<'EOF'
SIEM_JOURNAL_UNIT=step-ca.service
SIEM_JOURNAL_PROVIDER=step-ca
SIEM_JOURNAL_HOST=soc-pki-01
SIEM_JOURNAL_STATE=/var/lib/siem-journal-exporter/step-ca.json
SIEM_JOURNAL_OUTPUT=/var/log/siem/step-ca-audit.jsonl
EOF
cat >/etc/siem/security-sensor-step-ca.env <<'EOF'
SIEM_SENSOR_KIND=step-ca
SIEM_SENSOR_FORMAT=jsonl
SIEM_SENSOR_PATHS=/var/log/siem/step-ca-audit.jsonl
SIEM_SENSOR_HOSTNAME=soc-pki-01
SIEM_SENSOR_INGEST_URL=https://10.20.10.104/ingest/json
SIEM_SENSOR_TLS_VERIFY=required
SIEM_SENSOR_CA_FILE=/etc/siem/pki/ingest-ca.crt
SIEM_SENSOR_START_POSITION=beginning
SIEM_SENSOR_BATCH_SIZE=250
SIEM_SENSOR_READ_LIMIT=2000
SIEM_SENSOR_SPOOL_MAX_BYTES=268435456
SIEM_SENSOR_INTERVAL_SECONDS=2
EOF
chmod 0640 /etc/siem/journal-exporter-step-ca.env /etc/siem/security-sensor-step-ca.env
/usr/bin/python3 -m py_compile \
  /opt/siem/deploy/journal_event_exporter.py \
  /opt/siem/deploy/security_sensor_forwarder.py
systemctl daemon-reload
systemctl start siem-journal-event-exporter@step-ca.service
systemctl enable --now siem-journal-event-exporter@step-ca.timer
systemctl enable --now siem-security-sensor-forwarder@step-ca.service
systemctl restart siem-security-sensor-forwarder@step-ca.service
systemctl is-active --quiet step-ca.service
systemctl is-active --quiet siem-journal-event-exporter@step-ca.timer
systemctl is-active --quiet siem-security-sensor-forwarder@step-ca.service
""",
        timeout=300,
    )
    return {"ca": "active", "audit_exporter": "active", "forwarder": "active"}


def _deploy_minio(pve: Proxmox, ingest_certificate: str) -> dict[str, str]:
    files = (
        (
            ROOT / "deploy/minio_audit_receiver.py",
            "/opt/siem/deploy/minio_audit_receiver.py",
            0o755,
        ),
        (
            ROOT / "deploy/security_sensor_forwarder.py",
            "/opt/siem/deploy/security_sensor_forwarder.py",
            0o755,
        ),
        (
            ROOT / "deploy/systemd/siem-minio-audit-receiver.service",
            "/etc/systemd/system/siem-minio-audit-receiver.service",
            0o644,
        ),
        (
            ROOT / "deploy/minio_certificate_renew.sh",
            "/usr/local/sbin/siem-minio-certificate-renew",
            0o755,
        ),
        (
            ROOT / "deploy/systemd/siem-minio-certificate-renew.service",
            "/etc/systemd/system/siem-minio-certificate-renew.service",
            0o644,
        ),
        (
            ROOT / "deploy/systemd/siem-minio-certificate-renew.timer",
            "/etc/systemd/system/siem-minio-certificate-renew.timer",
            0o644,
        ),
        (
            ROOT / "deploy/systemd/siem-security-sensor-forwarder@.service",
            "/etc/systemd/system/siem-security-sensor-forwarder@.service",
            0o644,
        ),
    )
    for source, destination, mode in files:
        _write_ct(pve, 133, destination, source.read_bytes(), mode)
    _write_ct(
        pve,
        133,
        "/etc/siem/pki/ingest-ca.crt",
        ingest_certificate.encode("ascii"),
        0o644,
    )
    pve.ct(
        133,
        """
set -euo pipefail
install -d -m 0750 /var/lib/siem-security-forwarder /var/log/siem /etc/siem/pki
install -d -o minio-user -g minio-user -m 0750 /var/lib/minio/audit-queue
touch /var/log/siem/minio-audit.jsonl
chmod 0640 /var/log/siem/minio-audit.jsonl
if [ ! -s /etc/siem/minio-audit.env ]; then
  umask 077
  printf 'MINIO_AUDIT_RECEIVER_TOKEN=siem-%s\\n' "$(openssl rand -hex 32)" \
    >/etc/siem/minio-audit.env
fi
. /etc/siem/minio-audit.env
set_env() {
  key="$1"
  value="$2"
  sed -i "/^${key}=/d" /etc/siem/evidence.env
  printf '%s=%s\\n' "$key" "$value" >>/etc/siem/evidence.env
}
set_env MINIO_AUDIT_WEBHOOK_ENABLE_SIEM on
set_env MINIO_AUDIT_WEBHOOK_ENDPOINT_SIEM http://127.0.0.1:9191/audit
set_env MINIO_AUDIT_WEBHOOK_AUTH_TOKEN_SIEM "$MINIO_AUDIT_RECEIVER_TOKEN"
set_env MINIO_AUDIT_WEBHOOK_QUEUE_DIR_SIEM /var/lib/minio/audit-queue
set_env MINIO_AUDIT_WEBHOOK_QUEUE_LIMIT_SIEM 100000
chown root:minio-user /etc/siem/evidence.env
chmod 0640 /etc/siem/evidence.env /etc/siem/minio-audit.env
install -d -m 0755 /etc/systemd/system/minio.service.d
cat >/etc/systemd/system/minio.service.d/20-audit-receiver.conf <<'EOF'
[Unit]
After=siem-minio-audit-receiver.service
Wants=siem-minio-audit-receiver.service
EOF
cat >/etc/siem/security-sensor-minio.env <<'EOF'
SIEM_SENSOR_KIND=minio
SIEM_SENSOR_FORMAT=jsonl
SIEM_SENSOR_PATHS=/var/log/siem/minio-audit.jsonl
SIEM_SENSOR_HOSTNAME=soc-evidence-01
SIEM_SENSOR_INGEST_URL=https://10.20.10.104/ingest/json
SIEM_SENSOR_TLS_VERIFY=required
SIEM_SENSOR_CA_FILE=/etc/siem/pki/ingest-ca.crt
SIEM_SENSOR_START_POSITION=beginning
SIEM_SENSOR_BATCH_SIZE=500
SIEM_SENSOR_READ_LIMIT=4000
SIEM_SENSOR_SPOOL_MAX_BYTES=536870912
SIEM_SENSOR_INTERVAL_SECONDS=1
EOF
chmod 0640 /etc/siem/security-sensor-minio.env
/usr/bin/python3 -m py_compile \
  /opt/siem/deploy/minio_audit_receiver.py \
  /opt/siem/deploy/security_sensor_forwarder.py
systemctl daemon-reload
systemctl enable --now siem-minio-audit-receiver.service
systemctl restart minio.service
for attempt in $(seq 1 60); do
  curl -fsS http://127.0.0.1:9191/health >/dev/null \
    && curl -kfsS https://127.0.0.1:9000/minio/health/ready >/dev/null \
    && break
  sleep 2
done
systemctl enable --now siem-minio-certificate-renew.timer
systemctl enable --now siem-security-sensor-forwarder@minio.service
systemctl restart siem-security-sensor-forwarder@minio.service
systemctl is-active --quiet minio.service
systemctl is-active --quiet siem-minio-audit-receiver.service
systemctl is-active --quiet siem-minio-certificate-renew.timer
systemctl is-active --quiet siem-security-sensor-forwarder@minio.service
""",
        timeout=420,
    )
    return {"store": "active", "audit_receiver": "active", "forwarder": "active"}


def _deploy_arkime(pve: Proxmox, ingest_certificate: str) -> dict[str, str]:
    files = (
        (
            ROOT / "deploy/arkime_metrics_exporter.py",
            "/opt/siem/deploy/arkime_metrics_exporter.py",
            0o755,
        ),
        (
            ROOT / "deploy/security_sensor_forwarder.py",
            "/opt/siem/deploy/security_sensor_forwarder.py",
            0o755,
        ),
        (
            ROOT / "deploy/systemd/siem-arkime-metrics-exporter.service",
            "/etc/systemd/system/siem-arkime-metrics-exporter.service",
            0o644,
        ),
        (
            ROOT / "deploy/systemd/siem-arkime-metrics-exporter.timer",
            "/etc/systemd/system/siem-arkime-metrics-exporter.timer",
            0o644,
        ),
        (
            ROOT / "deploy/systemd/siem-security-sensor-forwarder@.service",
            "/etc/systemd/system/siem-security-sensor-forwarder@.service",
            0o644,
        ),
    )
    for source, destination, mode in files:
        _write_vm(pve, 127, destination, source.read_bytes(), mode)
    _write_vm(
        pve,
        127,
        "/etc/siem/pki/ingest-ca.crt",
        ingest_certificate.encode("ascii"),
        0o644,
    )
    pve.guest_exec(
        127,
        """
set -euo pipefail
install -d -m 0750 /var/lib/siem-security-forwarder /var/log/siem /etc/siem/pki
touch /var/log/siem/arkime-health.jsonl
chmod 0640 /var/log/siem/arkime-health.jsonl
cat >/etc/siem/security-sensor-arkime.env <<'EOF'
SIEM_SENSOR_KIND=arkime
SIEM_SENSOR_FORMAT=jsonl
SIEM_SENSOR_PATHS=/var/log/siem/arkime-health.jsonl
SIEM_SENSOR_HOSTNAME=soc-ndr-01
SIEM_SENSOR_INGEST_URL=https://10.20.10.104/ingest/json
SIEM_SENSOR_TLS_VERIFY=required
SIEM_SENSOR_CA_FILE=/etc/siem/pki/ingest-ca.crt
SIEM_SENSOR_START_POSITION=beginning
SIEM_SENSOR_BATCH_SIZE=100
SIEM_SENSOR_READ_LIMIT=1000
SIEM_SENSOR_SPOOL_MAX_BYTES=134217728
SIEM_SENSOR_INTERVAL_SECONDS=2
EOF
chmod 0640 /etc/siem/security-sensor-arkime.env
/usr/bin/python3 -m py_compile \
  /opt/siem/deploy/arkime_metrics_exporter.py \
  /opt/siem/deploy/security_sensor_forwarder.py
systemctl daemon-reload
systemctl start siem-arkime-metrics-exporter.service
systemctl enable --now siem-arkime-metrics-exporter.timer
systemctl enable --now siem-security-sensor-forwarder@arkime.service
systemctl restart siem-security-sensor-forwarder@arkime.service
systemctl is-active --quiet arkimecapture.service
systemctl is-active --quiet arkimeviewer.service
systemctl is-active --quiet siem-arkime-metrics-exporter.timer
systemctl is-active --quiet siem-security-sensor-forwarder@arkime.service
""",
        timeout=300,
    )
    return {"capture": "active", "metrics_exporter": "active", "forwarder": "active"}


def main() -> int:
    with Proxmox() as pve:
        ingest_certificate = pve.guest_exec(104, "cat /etc/siem/tls/ingest.crt")
        if "BEGIN CERTIFICATE" not in ingest_certificate:
            raise RuntimeError("VM104 did not return the ingest certificate")
        result = {
            "misp": _deploy_misp(pve, ingest_certificate),
            "velociraptor": _deploy_velociraptor(pve, ingest_certificate),
            "step_ca": _deploy_step_ca(pve, ingest_certificate),
            "minio": _deploy_minio(pve, ingest_certificate),
            "arkime": _deploy_arkime(pve, ingest_certificate),
            "misp_enrichment": _deploy_misp_enrichment(pve),
        }
        print(json.dumps(result, indent=2, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
