from __future__ import annotations

import base64
import json
import os
import shlex
import time
from pathlib import Path

try:
    from deploy.soc_foundation_provision import Proxmox
except ModuleNotFoundError:
    from soc_foundation_provision import Proxmox


ROOT = Path(__file__).resolve().parents[1]
VMID = 127
HOSTNAME = "soc-ndr-01"
ADDRESS = "10.20.10.127"


CLOUD_CONFIG = """#cloud-config
hostname: soc-ndr-01
fqdn: soc-ndr-01.lab.home.arpa
manage_etc_hosts: true
timezone: Europe/Moscow
package_update: true
package_upgrade: false
packages:
  - qemu-guest-agent
  - ca-certificates
  - curl
  - gnupg
  - jq
  - chrony
users:
  - default
  - name: socadmin
    groups: [adm, sudo]
    shell: /bin/bash
    lock_passwd: true
    sudo: ALL=(ALL) NOPASSWD:ALL
runcmd:
  - [systemctl, enable, --now, qemu-guest-agent]
  - [systemctl, enable, --now, chrony]
  - [install, -d, -m, "0750", /etc/siem, /var/log/siem]
final_message: "soc-ndr-01 cloud-init complete"
"""


def _host_write(pve: Proxmox, path: str, content: bytes, mode: int) -> None:
    encoded = base64.b64encode(content).decode("ascii")
    temp = f"{path}.b64"
    pve.run(f"install -d -m 0755 {shlex.quote(path.rsplit('/', 1)[0])}; : > {shlex.quote(temp)}")
    try:
        for offset in range(0, len(encoded), 32_000):
            pve.run(
                f"printf %s {shlex.quote(encoded[offset:offset + 32_000])} "
                f">> {shlex.quote(temp)}"
            )
        pve.run(
            f"base64 -d {shlex.quote(temp)} > {shlex.quote(path)} && "
            f"chmod {mode:o} {shlex.quote(path)}"
        )
    finally:
        pve.run(f"rm -f {shlex.quote(temp)}")


def _guest_write(pve: Proxmox, path: str, content: bytes, mode: int) -> None:
    encoded = base64.b64encode(content).decode("ascii")
    remote = f"/tmp/soc-ndr-{os.getpid()}-{Path(path).name}.b64"
    pve.guest_exec(
        VMID,
        f"install -d -m 0755 {shlex.quote(str(Path(path).parent).replace(chr(92), '/'))}; "
        f": > {shlex.quote(remote)}",
    )
    try:
        for offset in range(0, len(encoded), 24_000):
            pve.guest_exec(
                VMID,
                f"printf %s {shlex.quote(encoded[offset:offset + 24_000])} "
                f">> {shlex.quote(remote)}",
            )
        pve.guest_exec(
            VMID,
            f"base64 -d {shlex.quote(remote)} > {shlex.quote(path)} && "
            f"chmod {mode:o} {shlex.quote(path)}",
        )
    finally:
        pve.guest_exec(VMID, f"rm -f {shlex.quote(remote)}")


def _ensure_vm(pve: Proxmox) -> None:
    exists = pve.run(
        f"test -f /etc/pve/qemu-server/{VMID}.conf && echo yes || echo no"
    ).strip()
    if exists == "yes":
        config = pve.run(f"qm config {VMID}")
        if f"name: {HOSTNAME}" not in config:
            raise RuntimeError(f"VMID {VMID} belongs to another workload")
        return

    storage = json.loads(pve.run("pvesh get /storage/local --output-format json"))
    content = {item.strip() for item in str(storage.get("content") or "").split(",")}
    if "snippets" not in content:
        content.add("snippets")
        pve.run(f"pvesm set local --content {','.join(sorted(content))}")
    _host_write(
        pve,
        f"/var/lib/vz/snippets/{HOSTNAME}-user.yaml",
        CLOUD_CONFIG.encode("utf-8"),
        0o600,
    )
    pve.run(
        " ".join(
            (
                "qm create",
                str(VMID),
                f"--name {HOSTNAME}",
                "--ostype l26",
                "--machine q35",
                "--cpu host",
                "--cores 4",
                "--memory 6144",
                "--balloon 4096",
                "--scsihw virtio-scsi-single",
                "--net0 virtio,bridge=vmbr2,firewall=1",
                "--net1 virtio,bridge=vmbr0,firewall=0",
                "--net2 virtio,bridge=vmbr2,firewall=0",
                "--net3 virtio,bridge=vmbr3,firewall=0",
                "--net4 virtio,bridge=vmbr1,firewall=0",
                "--net5 virtio,bridge=vmbr4,firewall=0",
                "--agent enabled=1,freeze-fs-on-backup=1",
                "--onboot 1",
                "--startup order=49,up=45,down=45",
                "--serial0 socket",
                "--vga serial0",
            )
        )
    )
    image = pve.run("pvesm path local:iso/noble-server-cloudimg-amd64.img").strip()
    pve.run(
        f"qm disk import {VMID} {shlex.quote(image)} kingston256gig "
        "--format qcow2 --target-disk scsi0",
        timeout=1200,
    )
    config = pve.run(f"qm config {VMID}")
    if "scsi0:" not in config:
        unused = next(
            (
                line.split(":", 1)[1].strip()
                for line in config.splitlines()
                if line.startswith("unused0:")
            ),
            "",
        )
        if not unused:
            raise RuntimeError("Imported Zeek system disk was not attached")
        pve.run(f"qm set {VMID} --scsi0 {shlex.quote(unused)},discard=on,ssd=1")
    pve.run(f"qm disk resize {VMID} scsi0 40G")
    pve.run(f"qm set {VMID} --ide2 kingston256gig:cloudinit")
    pve.run(
        f"qm set {VMID} --ipconfig0 ip={ADDRESS}/24,gw=10.20.10.1 "
        "--nameserver 10.20.10.1 --searchdomain lab.home.arpa "
        f"--cicustom user=local:snippets/{HOSTNAME}-user.yaml "
        "--boot order=scsi0"
    )


def _wait_for_guest(pve: Proxmox) -> None:
    if not pve.run(f"qm status {VMID}").strip().endswith("running"):
        pve.run(f"qm start {VMID}", timeout=300)
    for _ in range(180):
        try:
            pve.guest_exec(VMID, "true", timeout=15)
            break
        except (RuntimeError, ValueError, json.JSONDecodeError):
            time.sleep(5)
    else:
        raise RuntimeError("Zeek VM did not expose QEMU guest agent")
    pve.guest_exec(VMID, "cloud-init status --wait", timeout=1800)


def _install_zeek(pve: Proxmox) -> None:
    pve.guest_exec(
        VMID,
        """
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
if [ ! -s /usr/share/keyrings/zeek-observatory.gpg ]; then
  curl -fsSL https://download.opensuse.org/repositories/security:/zeek/xUbuntu_24.04/Release.key \
    | gpg --dearmor -o /usr/share/keyrings/zeek-observatory.gpg
fi
echo 'deb [signed-by=/usr/share/keyrings/zeek-observatory.gpg] http://download.opensuse.org/repositories/security:/zeek/xUbuntu_24.04/ /' \
  >/etc/apt/sources.list.d/zeek.list
apt-get update -qq
apt-get install -y -qq zeek
install -d -m 0750 /opt/zeek/logs /var/lib/zeek /var/lib/siem-security-forwarder /etc/siem/pki
for interface in enp6s19 enp6s20 enp6s21 enp6s22 enp6s23; do
  install -d -m 0750 "/opt/zeek/logs/$interface"
done
cat >/opt/zeek/share/zeek/site/local.zeek <<'EOF'
@load policy/tuning/json-logs
@load policy/protocols/conn/community-id-logging
redef Log::default_rotation_interval = 1hr;
redef LogAscii::use_json = T;
EOF
""",
        timeout=1800,
    )
    ingest_certificate = pve.guest_exec(104, "cat /etc/siem/tls/ingest.crt")
    if "BEGIN CERTIFICATE" not in ingest_certificate:
        raise RuntimeError("VM104 did not return the ingest certificate")
    guest_files = (
        (
            ROOT / "deploy/network/siem_prepare_monitor_interfaces.sh",
            "/usr/local/sbin/siem-prepare-monitor-interfaces",
            0o755,
        ),
        (
            ROOT / "deploy/systemd/siem-monitor-interfaces.service",
            "/etc/systemd/system/siem-monitor-interfaces.service",
            0o644,
        ),
        (
            ROOT / "deploy/systemd/siem-zeek@.service",
            "/etc/systemd/system/siem-zeek@.service",
            0o644,
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
    )
    for source, destination, mode in guest_files:
        _guest_write(pve, destination, source.read_bytes(), mode)
    _guest_write(
        pve,
        "/etc/siem/pki/ingest-ca.crt",
        ingest_certificate.encode("ascii"),
        0o644,
    )
    pve.guest_exec(
        VMID,
        """
set -euo pipefail
cat >/etc/siem/security-sensor-zeek.env <<'EOF'
SIEM_SENSOR_KIND=zeek
SIEM_SENSOR_FORMAT=jsonl
SIEM_SENSOR_PATHS=/opt/zeek/logs/*/*.log
SIEM_SENSOR_HOSTNAME=soc-ndr-01
SIEM_SENSOR_INGEST_URL=https://10.20.10.104/ingest/json
SIEM_SENSOR_TLS_VERIFY=required
SIEM_SENSOR_CA_FILE=/etc/siem/pki/ingest-ca.crt
SIEM_SENSOR_START_POSITION=beginning
SIEM_SENSOR_BATCH_SIZE=1000
SIEM_SENSOR_DELIVERY_BATCHES=16
SIEM_SENSOR_READ_LIMIT=5000
SIEM_SENSOR_SPOOL_MAX_BYTES=1073741824
SIEM_SENSOR_INTERVAL_SECONDS=1
EOF
chmod 0640 /etc/siem/security-sensor-zeek.env
/usr/bin/python3 -m py_compile /opt/siem/deploy/security_sensor_forwarder.py
systemctl daemon-reload
systemctl enable --now siem-monitor-interfaces.service
systemctl restart siem-monitor-interfaces.service
for interface in ens19 ens20 ens21 ens22 ens23; do
  systemctl disable --now "siem-zeek@$interface.service" 2>/dev/null || true
done
for interface in enp6s19 enp6s20 enp6s21 enp6s22 enp6s23; do
  systemctl enable --now "siem-zeek@$interface.service"
done
systemctl enable --now siem-security-sensor-forwarder@zeek.service
""",
        timeout=300,
    )


def _install_mirror(pve: Proxmox) -> None:
    files = (
        (
            ROOT / "deploy/network/siem_zeek_mirror.sh",
            "/usr/local/sbin/siem-zeek-mirror",
            0o755,
        ),
        (
            ROOT / "deploy/systemd/soc-ndr-mirror.service",
            "/etc/systemd/system/soc-ndr-mirror.service",
            0o644,
        ),
        (
            ROOT / "deploy/systemd/soc-ndr-mirror.timer",
            "/etc/systemd/system/soc-ndr-mirror.timer",
            0o644,
        ),
    )
    for source, destination, mode in files:
        _host_write(pve, destination, source.read_bytes(), mode)
    pve.run(
        "systemctl daemon-reload && "
        "systemctl enable --now soc-ndr-mirror.timer && "
        "systemctl restart soc-ndr-mirror.service"
    )


def main() -> int:
    with Proxmox() as pve:
        _ensure_vm(pve)
        _wait_for_guest(pve)
        _install_zeek(pve)
        _install_mirror(pve)
        print(
            pve.guest_exec(
                VMID,
                "hostname; hostname -I; /opt/zeek/bin/zeek --version; "
                "for interface in enp6s19 enp6s20 enp6s21 enp6s22 enp6s23; do "
                "printf '%s=' \"$interface\"; systemctl is-active \"siem-zeek@$interface\"; done; "
                "printf 'forwarder='; systemctl is-active siem-security-sensor-forwarder@zeek",
            )
        )
        print(
            pve.run(
                "systemctl is-active soc-ndr-mirror.timer; "
                "/usr/local/sbin/siem-zeek-mirror; "
                "for dev in fwpr102p0 fwpr104p2 veth100i0; do "
                "test -e /sys/class/net/$dev || continue; "
                "printf '%s=' \"$dev\"; "
                "tc filter show dev \"$dev\" ingress pref 49127 | grep -c mirred || true; "
                "done"
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
