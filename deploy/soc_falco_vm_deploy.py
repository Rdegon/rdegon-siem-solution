from __future__ import annotations

import base64
import os
import shlex
from pathlib import Path

try:
    from deploy.soc_foundation_provision import Proxmox
except ModuleNotFoundError:
    from soc_foundation_provision import Proxmox


ROOT = Path(__file__).resolve().parents[1]
TARGETS = {
    130: "gamepanel-01",
}
RETIRED_TARGETS = {
    104: "siem-ingest",
    105: "siem-processing",
    106: "siem-storage",
    107: "siem-web",
    108: "siem-transport",
}
FALCO_PACKAGE = "/var/lib/vz/snippets/falco-0.44.1-x86_64.deb"
FALCO_SHA256 = "c5394345af92f4c40a6b9535621c42faa1059cab7bb9f30e2be776b9dca0b6a4"


def _guest_write(
    pve: Proxmox,
    vmid: int,
    path: str,
    content: bytes,
    mode: int,
) -> None:
    encoded = base64.b64encode(content).decode("ascii")
    parent = str(Path(path).parent).replace("\\", "/")
    if not parent.startswith("/"):
        parent = "/" + parent.lstrip("/")
    temp = f"/tmp/soc-falco-{os.getpid()}-{Path(path).name}.b64"
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


def _install_falco(pve: Proxmox, vmid: int) -> str:
    return pve.guest_exec(
        vmid,
        """
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
if ! dpkg-query -W -f='${Status} ${Version}' falco 2>/dev/null | grep -q 'install ok installed 0.44.1'; then
  curl -fsSLo /tmp/falco-0.44.1.deb \
    http://192.168.3.101:18765/falco-0.44.1-x86_64.deb
  echo 'c5394345af92f4c40a6b9535621c42faa1059cab7bb9f30e2be776b9dca0b6a4  /tmp/falco-0.44.1.deb' \
    | sha256sum -c -
  FALCO_FRONTEND=noninteractive FALCO_DRIVER_CHOICE=modern_ebpf \
    dpkg --install /tmp/falco-0.44.1.deb
fi
install -d -m 0750 /etc/falco/config.d /var/log/falco /var/lib/siem-security-forwarder /etc/siem/pki
touch /var/log/falco/events.jsonl
chmod 0640 /var/log/falco/events.jsonl
cat >/etc/falco/config.d/90-siem-output.yaml <<'EOF'
json_output: true
json_include_output_property: true
json_include_tags_property: true
stdout_output:
  enabled: false
file_output:
  enabled: true
  keep_alive: true
  filename: /var/log/falco/events.jsonl
EOF
systemctl daemon-reload
if systemctl list-unit-files falco-modern-bpf.service --no-legend 2>/dev/null | grep -q falco-modern-bpf; then
  falco_unit=falco-modern-bpf.service
elif systemctl list-unit-files falco.service --no-legend 2>/dev/null | grep -q falco.service; then
  falco_unit=falco.service
else
  echo 'Falco systemd unit not found' >&2
  exit 1
fi
systemctl enable --now "$falco_unit"
for attempt in $(seq 1 30); do
  systemctl is-active --quiet "$falco_unit" && break
  sleep 2
done
systemctl is-active --quiet "$falco_unit"
printf '%s|' "$falco_unit"
/usr/bin/falco --version | head -1
""",
        timeout=1800,
    ).strip()


def _install_forwarder(
    pve: Proxmox,
    vmid: int,
    hostname: str,
    ingest_certificate: str,
) -> None:
    files = (
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
    )
    for source, destination, mode in files:
        _guest_write(pve, vmid, destination, source.read_bytes(), mode)
    _guest_write(
        pve,
        vmid,
        "/etc/siem/pki/ingest-ca.crt",
        ingest_certificate.encode("ascii"),
        0o644,
    )
    pve.guest_exec(
        vmid,
        f"""
set -euo pipefail
cat >/etc/siem/security-sensor-falco.env <<'EOF'
SIEM_SENSOR_KIND=falco
SIEM_SENSOR_FORMAT=jsonl
SIEM_SENSOR_PATHS=/var/log/falco/events.jsonl
SIEM_SENSOR_HOSTNAME={hostname}
SIEM_SENSOR_INGEST_URL=https://10.20.10.104/ingest/json
SIEM_SENSOR_TLS_VERIFY=required
SIEM_SENSOR_CA_FILE=/etc/siem/pki/ingest-ca.crt
SIEM_SENSOR_START_POSITION=beginning
SIEM_SENSOR_BATCH_SIZE=250
SIEM_SENSOR_READ_LIMIT=2000
SIEM_SENSOR_SPOOL_MAX_BYTES=536870912
SIEM_SENSOR_INTERVAL_SECONDS=2
EOF
chmod 0640 /etc/siem/security-sensor-falco.env
/usr/bin/python3 -m py_compile /opt/siem/deploy/security_sensor_forwarder.py
systemctl daemon-reload
systemctl enable --now siem-security-sensor-forwarder@falco.service
systemctl restart siem-security-sensor-forwarder@falco.service
systemctl is-active --quiet siem-security-sensor-forwarder@falco.service
""",
        timeout=300,
    )


def _retire_non_container_sensor(pve: Proxmox, vmid: int) -> dict[str, object]:
    output = pve.guest_exec(
        vmid,
        """
set -euo pipefail
systemctl disable --now siem-security-sensor-forwarder@falco.service 2>/dev/null || true
for unit in falco-modern-bpf.service falco-bpf.service falco-kmod.service falco.service; do
  systemctl disable --now "$unit" 2>/dev/null || true
done
printf 'falco_active='
systemctl is-active falco-modern-bpf.service falco-bpf.service falco-kmod.service falco.service \
  2>/dev/null | grep -c '^active$' || true
printf 'forwarder='
systemctl is-active siem-security-sensor-forwarder@falco.service 2>/dev/null || true
""",
        timeout=180,
    )
    return {
        "vmid": vmid,
        "hostname": RETIRED_TARGETS[vmid],
        "status": output.strip().splitlines(),
    }


def main() -> int:
    with Proxmox() as pve:
        ingest_certificate = pve.guest_exec(104, "cat /etc/siem/tls/ingest.crt")
        if "BEGIN CERTIFICATE" not in ingest_certificate:
            raise RuntimeError("VM104 did not return the ingest certificate")
        pve.run(
            "set -e; "
            f"echo '{FALCO_SHA256}  {FALCO_PACKAGE}' | sha256sum -c; "
            "systemctl stop soc-package-cache.service 2>/dev/null || true; "
            "systemd-run --unit=soc-package-cache --property=Restart=on-failure "
            "/usr/bin/python3 -m http.server 18765 --bind 192.168.3.101 "
            "--directory /var/lib/vz/snippets"
        )
        results: list[dict[str, object]] = []
        try:
            for vmid, hostname in TARGETS.items():
                falco = _install_falco(pve, vmid)
                _install_forwarder(pve, vmid, hostname, ingest_certificate)
                results.append(
                    {
                        "vmid": vmid,
                        "hostname": hostname,
                        "falco": falco,
                        "forwarder": "active",
                    }
                )
            retired = [
                _retire_non_container_sensor(pve, vmid)
                for vmid in RETIRED_TARGETS
            ]
        finally:
            pve.run("systemctl stop soc-package-cache.service 2>/dev/null || true")
        import json

        print(
            json.dumps(
                {"active_container_sensors": results, "retired_non_container_sensors": retired},
                indent=2,
                ensure_ascii=True,
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
