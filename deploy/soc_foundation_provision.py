from __future__ import annotations

import argparse
import base64
import json
import os
import shlex
import time
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

import paramiko


PVE_TEMPLATE = "local:vztmpl/ubuntu-24.04-standard_24.04-2_amd64.tar.zst"
PVE_ROOT_STORAGE = "kingston256gig"
PVE_DATA_STORAGE = "toshiba500gig"
ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class ContainerSpec:
    vmid: int
    hostname: str
    address: str
    gateway: str
    bridge: str
    cores: int
    memory_mb: int
    swap_mb: int
    root_gb: int
    startup_order: int
    nesting: bool = False
    data_gb: int = 0
    data_mount: str = ""


CONTAINERS = {
    "pki": ContainerSpec(
        vmid=132,
        hostname="soc-pki-01",
        address="10.20.10.132/24",
        gateway="10.20.10.1",
        bridge="vmbr2",
        cores=1,
        memory_mb=1024,
        swap_mb=512,
        root_gb=12,
        startup_order=40,
    ),
    "evidence": ContainerSpec(
        vmid=133,
        hostname="soc-evidence-01",
        address="10.20.10.133/24",
        gateway="10.20.10.1",
        bridge="vmbr2",
        cores=2,
        memory_mb=2048,
        swap_mb=1024,
        root_gb=16,
        startup_order=41,
        data_gb=200,
        data_mount="/srv/evidence",
    ),
    "dfir": ContainerSpec(
        vmid=128,
        hostname="soc-dfir-01",
        address="10.20.10.128/24",
        gateway="10.20.10.1",
        bridge="vmbr2",
        cores=4,
        memory_mb=4096,
        swap_mb=2048,
        root_gb=40,
        startup_order=50,
    ),
    "analysis": ContainerSpec(
        vmid=129,
        hostname="soc-analysis-01",
        address="10.20.30.129/24",
        gateway="10.20.30.1",
        bridge="vmbr1",
        cores=4,
        memory_mb=4096,
        swap_mb=2048,
        root_gb=60,
        startup_order=51,
    ),
    "ti": ContainerSpec(
        vmid=131,
        hostname="soc-ti-01",
        address="10.20.10.131/24",
        gateway="10.20.10.1",
        bridge="vmbr2",
        cores=4,
        memory_mb=6144,
        swap_mb=2048,
        root_gb=80,
        startup_order=52,
        nesting=True,
    ),
}


def required_env(name: str, default: str = "") -> str:
    value = str(os.getenv(name, default) or "").strip()
    if not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value


class Proxmox:
    def __init__(self) -> None:
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    def __enter__(self) -> "Proxmox":
        self.client.connect(
            required_env("SIEM_PROXMOX_HOST", "192.168.3.101"),
            username=required_env("SIEM_PROXMOX_USER", "root"),
            password=required_env("SIEM_PROXMOX_PASSWORD"),
            timeout=30,
            banner_timeout=30,
            auth_timeout=30,
            look_for_keys=False,
            allow_agent=False,
        )
        return self

    def __exit__(self, *_: object) -> None:
        self.client.close()

    def run(self, command: str, timeout: int = 600) -> str:
        _, stdout, stderr = self.client.exec_command(command, timeout=timeout)
        output = stdout.read().decode("utf-8", errors="replace")
        error = stderr.read().decode("utf-8", errors="replace")
        exit_code = stdout.channel.recv_exit_status()
        if exit_code:
            raise RuntimeError(
                f"Proxmox command failed ({exit_code}): {error.strip() or output.strip()}"
            )
        return output

    def ct(self, vmid: int, script: str, timeout: int = 1200) -> str:
        command = f"pct exec {vmid} -- /bin/bash -lc {shlex.quote(script)}"
        return self.run(command, timeout=timeout)

    def guest_exec(self, vmid: int, script: str, timeout: int = 120) -> str:
        command = (
            f"qm guest exec {vmid} --timeout {timeout} -- /bin/bash -lc "
            + shlex.quote(script)
        )
        payload = json.loads(self.run(command, timeout=timeout + 30) or "{}")
        exit_code = int(payload.get("exitcode") or 0)
        output = str(payload.get("out-data") or "")
        error = str(payload.get("err-data") or "")
        if exit_code:
            raise RuntimeError(
                f"Guest command failed on VM{vmid} ({exit_code}): {error.strip() or output.strip()}"
            )
        return output

    def push_bytes(self, vmid: int, content: bytes, destination: str, mode: int = 0o644) -> None:
        encoded = base64.b64encode(content).decode("ascii")
        remote_path = PurePosixPath(destination)
        temp_path = f"/tmp/soc-deploy-{vmid}-{os.getpid()}-{remote_path.name}.b64"
        self.ct(
            vmid,
            f"install -d -m 0755 {shlex.quote(str(remote_path.parent))}",
        )
        self.run(f": > {shlex.quote(temp_path)}")
        try:
            for offset in range(0, len(encoded), 32_000):
                chunk = encoded[offset : offset + 32_000]
                self.run(
                    f"printf %s {shlex.quote(chunk)} >> {shlex.quote(temp_path)}"
                )
            decoded_path = temp_path.removesuffix(".b64")
            self.run(
                f"base64 -d {shlex.quote(temp_path)} > {shlex.quote(decoded_path)} && "
                f"pct push {vmid} {shlex.quote(decoded_path)} {shlex.quote(destination)} "
                f"--perms {mode:o}"
            )
            self.ct(
                vmid,
                f"test -f {shlex.quote(destination)} && "
                f"chmod {mode:o} {shlex.quote(destination)}",
            )
        finally:
            self.run(
                f"rm -f {shlex.quote(temp_path)} {shlex.quote(temp_path.removesuffix('.b64'))}"
            )

    def push_file(self, vmid: int, source: Path, destination: str, mode: int = 0o644) -> None:
        self.push_bytes(vmid, source.read_bytes(), destination, mode)


def ensure_container(pve: Proxmox, spec: ContainerSpec) -> None:
    exists = pve.run(f"test -f /etc/pve/lxc/{spec.vmid}.conf && echo yes || echo no").strip()
    if exists == "yes":
        config = pve.run(f"pct config {spec.vmid}")
        if f"hostname: {spec.hostname}" not in config:
            raise RuntimeError(
                f"VMID {spec.vmid} already belongs to another workload; expected {spec.hostname}"
            )
    else:
        options = [
            "pct",
            "create",
            str(spec.vmid),
            PVE_TEMPLATE,
            "--hostname",
            spec.hostname,
            "--ostype",
            "ubuntu",
            "--unprivileged",
            "1",
            "--cores",
            str(spec.cores),
            "--memory",
            str(spec.memory_mb),
            "--swap",
            str(spec.swap_mb),
            "--rootfs",
            f"{PVE_ROOT_STORAGE}:{spec.root_gb}",
            "--net0",
            (
                f"name=eth0,bridge={spec.bridge},ip={spec.address},gw={spec.gateway},"
                "firewall=1,type=veth"
            ),
            "--nameserver",
            spec.gateway,
            "--searchdomain",
            "lab.home.arpa",
            "--onboot",
            "1",
            "--startup",
            f"order={spec.startup_order},up=20,down=30",
        ]
        if spec.nesting:
            options.extend(["--features", "nesting=1,keyctl=1"])
        pve.run(" ".join(shlex.quote(item) for item in options), timeout=1200)
        if spec.data_gb:
            pve.run(
                f"pct set {spec.vmid} --mp0 "
                + shlex.quote(
                    f"{PVE_DATA_STORAGE}:{spec.data_gb},mp={spec.data_mount},backup=0"
                )
            )

    pve.run(
        f"pct set {spec.vmid} --onboot 1 --startup "
        + shlex.quote(f"order={spec.startup_order},up=20,down=30")
    )
    restart_required = False
    if spec.nesting:
        marker = pve.run(
            f"config=/etc/pve/lxc/{spec.vmid}.conf; changed=0; "
            f"grep -qxF 'lxc.apparmor.profile: unconfined' \"$config\" "
            f"|| {{ printf '\\nlxc.apparmor.profile: unconfined\\n' >> \"$config\"; changed=1; }}; "
            f"grep -qxF 'lxc.mount.entry: /sys/kernel/security sys/kernel/security none bind,optional,ro,create=dir' \"$config\" "
            f"|| {{ printf 'lxc.mount.entry: /sys/kernel/security sys/kernel/security none bind,optional,ro,create=dir\\n' "
            f">> \"$config\"; changed=1; }}; "
            f"test \"$changed\" = 0 || echo changed"
        ).strip()
        restart_required = marker == "changed"
    status = pve.run(f"pct status {spec.vmid}").strip()
    if restart_required and status.endswith("running"):
        pve.run(f"pct reboot {spec.vmid}", timeout=300)
        status = "status: running"
    if not status.endswith("running"):
        pve.run(f"pct start {spec.vmid}", timeout=300)

    for _ in range(30):
        try:
            pve.ct(spec.vmid, "systemctl is-system-running || true", timeout=60)
            break
        except RuntimeError:
            time.sleep(2)
    else:
        raise RuntimeError(f"Container {spec.vmid} did not become ready")


def bootstrap_container(pve: Proxmox, spec: ContainerSpec) -> None:
    pve.ct(
        spec.vmid,
        """
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
for attempt in $(seq 1 120); do
  if ! pgrep -x apt-get >/dev/null && ! pgrep -x dpkg >/dev/null; then
    break
  fi
  sleep 2
done
dpkg --configure -a
apt-get update -qq
apt-get install -y -qq ca-certificates curl jq openssl chrony unattended-upgrades
timedatectl set-timezone Europe/Moscow
systemctl enable --now chrony
install -d -m 0750 /etc/siem /var/lib/siem /var/log/siem
cat >/etc/sysctl.d/90-soc-service.conf <<'EOF'
net.ipv4.tcp_syncookies=1
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
EOF
sysctl --system >/dev/null
""",
    )


def install_step_ca(pve: Proxmox, spec: ContainerSpec) -> None:
    pve.ct(
        spec.vmid,
        """
set -euo pipefail
STEP_CA_VERSION="${STEP_CA_VERSION:-0.30.2}"
STEP_CLI_VERSION="${STEP_CLI_VERSION:-0.30.2}"
if ! command -v step >/dev/null 2>&1; then
  curl -fsSLo /tmp/step-cli.deb \
    "https://github.com/smallstep/cli/releases/download/v${STEP_CLI_VERSION}/step-cli_${STEP_CLI_VERSION}-1_amd64.deb"
  echo "9aee0346ffd154ed643063953ef42ff86a9880ed82810789e0fe1a103fc31613  /tmp/step-cli.deb" \
    | sha256sum -c -
  apt-get install -y -qq /tmp/step-cli.deb
fi
if ! command -v step-ca >/dev/null 2>&1; then
  curl -fsSLo /tmp/step-ca.deb \
    "https://github.com/smallstep/certificates/releases/download/v${STEP_CA_VERSION}/step-ca_${STEP_CA_VERSION}-1_amd64.deb"
  echo "f8e43f0f2ba1e37121b75623993ea0bece5cc3a02b73eefc16e414d41c9fec71  /tmp/step-ca.deb" \
    | sha256sum -c -
  apt-get install -y -qq /tmp/step-ca.deb
fi
id step-ca >/dev/null 2>&1 || useradd --system --home /etc/step-ca --shell /usr/sbin/nologin step-ca
install -d -o step-ca -g step-ca -m 0750 /etc/step-ca /etc/step-ca/secrets
if [ -s /etc/step-ca/.step/config/ca.json ] && [ ! -s /etc/step-ca/config/ca.json ]; then
  cp -a /etc/step-ca/.step/config /etc/step-ca/
  cp -a /etc/step-ca/.step/certs /etc/step-ca/
  cp -a /etc/step-ca/.step/db /etc/step-ca/
  cp -a /etc/step-ca/.step/secrets/root_ca_key /etc/step-ca/secrets/
  cp -a /etc/step-ca/.step/secrets/intermediate_ca_key /etc/step-ca/secrets/
fi
if [ ! -s /etc/step-ca/config/ca.json ]; then
  umask 077
  openssl rand -base64 48 >/etc/step-ca/secrets/ca_password
  openssl rand -base64 48 >/etc/step-ca/secrets/provisioner_password
  STEPPATH=/etc/step-ca step ca init \
    --deployment-type standalone \
    --name "Rdegon SOC Internal CA" \
    --dns soc-pki-01 \
    --dns soc-pki-01.lab.home.arpa \
    --dns 10.20.10.132 \
    --address :9000 \
    --provisioner soc-admin \
    --password-file /etc/step-ca/secrets/ca_password \
    --provisioner-password-file /etc/step-ca/secrets/provisioner_password
  chown -R step-ca:step-ca /etc/step-ca
fi
cat >/etc/systemd/system/step-ca.service <<'EOF'
[Unit]
Description=Rdegon SOC internal certificate authority
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=step-ca
Group=step-ca
Environment=HOME=/etc/step-ca
ExecStart=/usr/bin/step-ca /etc/step-ca/config/ca.json --password-file /etc/step-ca/secrets/ca_password
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/etc/step-ca

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now step-ca
for attempt in $(seq 1 30); do
  if curl --fail --silent --show-error --cacert /etc/step-ca/certs/root_ca.crt \
    https://10.20.10.132:9000/health >/dev/null; then
    exit 0
  fi
  sleep 2
done
exit 1
""",
    )


def install_minio(pve: Proxmox, spec: ContainerSpec) -> None:
    pve.ct(
        spec.vmid,
        """
set -euo pipefail
id minio-user >/dev/null 2>&1 || useradd --system --home /var/lib/minio --shell /usr/sbin/nologin minio-user
install -d -o minio-user -g minio-user -m 0750 /srv/evidence /var/lib/minio /etc/minio/certs
if [ ! -x /usr/local/bin/minio ]; then
  curl -fsSLo /usr/local/bin/minio \
    https://dl.min.io/server/minio/release/linux-amd64/minio
  chmod 0755 /usr/local/bin/minio
fi
if [ ! -x /usr/local/bin/mc ]; then
  curl -fsSLo /usr/local/bin/mc \
    https://dl.min.io/client/mc/release/linux-amd64/mc
  chmod 0755 /usr/local/bin/mc
fi
if [ ! -s /etc/siem/evidence.env ]; then
  umask 077
  {
    printf 'MINIO_ROOT_USER=socadmin\\n'
    printf 'MINIO_ROOT_PASSWORD=%s\\n' "$(openssl rand -base64 36 | tr -d '\\n')"
  } >/etc/siem/evidence.env
fi
chown root:minio-user /etc/siem/evidence.env
chmod 0640 /etc/siem/evidence.env
cat >/etc/systemd/system/minio.service <<'EOF'
[Unit]
Description=SOC evidence object store
After=network-online.target
Wants=network-online.target

[Service]
User=minio-user
Group=minio-user
EnvironmentFile=/etc/siem/evidence.env
ExecStart=/usr/local/bin/minio server --certs-dir /etc/minio/certs --address :9000 --console-address :9001 /srv/evidence
Restart=always
RestartSec=5
LimitNOFILE=1048576
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/srv/evidence /var/lib/minio

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
""",
    )


def issue_evidence_certificate(pve: Proxmox) -> None:
    pve.run("rm -f /tmp/soc-root-ca.crt")
    pve.run("pct pull 132 /etc/step-ca/certs/root_ca.crt /tmp/soc-root-ca.crt")
    pve.run("pct push 133 /tmp/soc-root-ca.crt /usr/local/share/ca-certificates/soc-root-ca.crt")
    pve.ct(133, "update-ca-certificates >/dev/null")
    token = pve.ct(
        132,
        """
HOME=/etc/step-ca step ca token soc-evidence-01 \
  --san soc-evidence-01.lab.home.arpa \
  --san 10.20.10.133 \
  --ca-url https://10.20.10.132:9000 \
  --root /etc/step-ca/certs/root_ca.crt \
  --password-file /etc/step-ca/secrets/provisioner_password
""",
    ).strip()
    if not token:
        raise RuntimeError("step-ca did not return a certificate token")
    pve.ct(
        133,
        f"""
set -euo pipefail
if ! command -v step >/dev/null 2>&1; then
  STEP_CLI_VERSION="${{STEP_CLI_VERSION:-0.30.2}}"
  curl -fsSLo /tmp/step-cli.deb \
    "https://github.com/smallstep/cli/releases/download/v${{STEP_CLI_VERSION}}/step-cli_${{STEP_CLI_VERSION}}-1_amd64.deb"
  echo "9aee0346ffd154ed643063953ef42ff86a9880ed82810789e0fe1a103fc31613  /tmp/step-cli.deb" \
    | sha256sum -c -
  apt-get install -y -qq /tmp/step-cli.deb
fi
install -d -o minio-user -g minio-user -m 0750 /etc/minio/certs
rm -f /etc/minio/certs/public.crt /etc/minio/certs/private.key
step ca certificate soc-evidence-01 \
  /etc/minio/certs/public.crt /etc/minio/certs/private.key \
  --token {shlex.quote(token)} \
  --ca-url https://10.20.10.132:9000 \
  --root /usr/local/share/ca-certificates/soc-root-ca.crt
chown minio-user:minio-user /etc/minio/certs/public.crt /etc/minio/certs/private.key
chmod 0644 /etc/minio/certs/public.crt
chmod 0600 /etc/minio/certs/private.key
systemctl enable --now minio
for attempt in $(seq 1 30); do
  curl -fsS https://10.20.10.133:9000/minio/health/ready >/dev/null && break
  sleep 2
done
. /etc/siem/evidence.env
/usr/local/bin/mc alias set local https://10.20.10.133:9000 "$MINIO_ROOT_USER" "$MINIO_ROOT_PASSWORD" >/dev/null
/usr/local/bin/mc mb --ignore-existing --with-lock local/soc-evidence >/dev/null
/usr/local/bin/mc version enable local/soc-evidence >/dev/null
/usr/local/bin/mc retention set --default GOVERNANCE 365d local/soc-evidence >/dev/null
""",
    )
    pve.run("rm -f /tmp/soc-root-ca.crt")


def install_analysis_tools(pve: Proxmox, spec: ContainerSpec) -> None:
    pve.ct(
        spec.vmid,
        """
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get install -y -qq clamav clamav-daemon yara python3 python3-venv python3-pip gnupg
install -d -m 0750 /srv/analysis/inbox /srv/analysis/results /srv/analysis/quarantine
install -d -o clamav -g clamav -m 0755 /var/lib/clamav
cat >/var/lib/clamav/siem-local.hdb <<'EOF'
44d88612fea8a8f36de82e1278abb02f:68:Eicar-Test-Signature
EOF
chown clamav:clamav /var/lib/clamav/siem-local.hdb
chmod 0644 /var/lib/clamav/siem-local.hdb
install -d -m 0755 /etc/systemd/system/clamav-daemon.service.d
cat >/etc/systemd/system/clamav-daemon.service.d/siem-local-signatures.conf <<'EOF'
[Unit]
ConditionPathExistsGlob=
ConditionPathExists=/var/lib/clamav/siem-local.hdb
EOF
if ! command -v trivy >/dev/null 2>&1; then
  curl -fsSL https://aquasecurity.github.io/trivy-repo/deb/public.key \
    | gpg --dearmor -o /usr/share/keyrings/trivy.gpg
  echo 'deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main' \
    >/etc/apt/sources.list.d/trivy.list
  apt-get update -qq
  apt-get install -y -qq trivy
fi
systemctl daemon-reload
systemctl enable clamav-freshclam clamav-daemon
systemctl restart clamav-freshclam || true
systemctl restart clamav-daemon
""",
        timeout=1800,
    )


def install_analysis_runtime(pve: Proxmox, spec: ContainerSpec) -> None:
    ingest_certificate = pve.guest_exec(104, "cat /etc/siem/tls/ingest.crt")
    if "BEGIN CERTIFICATE" not in ingest_certificate:
        raise RuntimeError("VM104 did not return its ingest certificate")
    files = (
        (
            ROOT / "services/security_analysis/static_worker.py",
            "/opt/siem/services/security_analysis/static_worker.py",
            0o644,
        ),
        (
            ROOT / "services/security_analysis/__init__.py",
            "/opt/siem/services/security_analysis/__init__.py",
            0o644,
        ),
        (
            ROOT / "deploy/security_sensor_forwarder.py",
            "/opt/siem/deploy/security_sensor_forwarder.py",
            0o755,
        ),
        (
            ROOT / "deploy/systemd/siem-static-analysis.service",
            "/etc/systemd/system/siem-static-analysis.service",
            0o644,
        ),
        (
            ROOT / "deploy/systemd/siem-security-sensor-forwarder@.service",
            "/etc/systemd/system/siem-security-sensor-forwarder@.service",
            0o644,
        ),
        (
            ROOT / "deploy/security_analysis_rules/eicar.yar",
            "/etc/siem/yara/eicar.yar",
            0o644,
        ),
    )
    for source, destination, mode in files:
        pve.push_file(spec.vmid, source, destination, mode)
    pve.push_bytes(
        spec.vmid,
        ingest_certificate.encode("ascii"),
        "/etc/siem/pki/ingest-ca.crt",
        0o644,
    )
    pve.ct(
        spec.vmid,
        """
set -euo pipefail
install -d -m 0750 /var/lib/siem-security-forwarder /var/log/siem
touch /var/log/siem/security-analysis.jsonl
chmod 0640 /var/log/siem/security-analysis.jsonl
cat >/etc/siem/security-sensor-static-analysis.env <<'EOF'
SIEM_SENSOR_KIND=malware
SIEM_SENSOR_FORMAT=jsonl
SIEM_SENSOR_PATHS=/var/log/siem/security-analysis.jsonl
SIEM_SENSOR_HOSTNAME=soc-analysis-01
SIEM_SENSOR_INGEST_URL=https://10.20.10.104/ingest/json
SIEM_SENSOR_TLS_VERIFY=required
SIEM_SENSOR_CA_FILE=/etc/siem/pki/ingest-ca.crt
SIEM_SENSOR_START_POSITION=beginning
SIEM_SENSOR_BATCH_SIZE=250
SIEM_SENSOR_READ_LIMIT=2000
SIEM_SENSOR_SPOOL_MAX_BYTES=536870912
SIEM_SENSOR_INTERVAL_SECONDS=2
EOF
chmod 0640 /etc/siem/security-sensor-static-analysis.env
/usr/bin/python3 -m py_compile \
  /opt/siem/services/security_analysis/static_worker.py \
  /opt/siem/deploy/security_sensor_forwarder.py
systemctl daemon-reload
systemctl enable --now siem-static-analysis.service
systemctl enable --now siem-security-sensor-forwarder@static-analysis.service
systemctl is-active --quiet siem-static-analysis.service
systemctl is-active --quiet siem-security-sensor-forwarder@static-analysis.service
""",
    )


def install_velociraptor_binary(pve: Proxmox, spec: ContainerSpec) -> None:
    pve.ct(
        spec.vmid,
        """
set -euo pipefail
VERSION=0.77.1
EXPECTED_SHA256=6636020f3ce03ea4eff5d5b96d635c400e51d2636c823a8f0bd458ddc7c4d28a
URL="https://github.com/Velocidex/velociraptor/releases/download/v${VERSION}/velociraptor-v${VERSION}-linux-amd64"
if [ ! -x /usr/local/bin/velociraptor ] || \
   [ "$(/usr/local/bin/velociraptor version 2>/dev/null | sed -n 's/.*version: //p' | head -1)" != "$VERSION" ]; then
  curl -fsSLo /tmp/velociraptor "$URL"
  echo "$EXPECTED_SHA256  /tmp/velociraptor" | sha256sum -c -
  install -m 0755 /tmp/velociraptor /usr/local/bin/velociraptor
fi
id velociraptor >/dev/null 2>&1 || \
  useradd --system --home /var/lib/velociraptor --shell /usr/sbin/nologin velociraptor
install -d -o velociraptor -g velociraptor -m 0750 \
  /etc/velociraptor /var/lib/velociraptor /var/log/velociraptor
if [ ! -s /etc/velociraptor/server.config.yaml ]; then
  /usr/local/bin/velociraptor config generate \
    --merge '{"Client":{"server_urls":["https://10.20.10.128:8000/"],"writeback_linux":"/var/lib/velociraptor/client.writeback.yaml"},"API":{"bind_address":"127.0.0.1"},"GUI":{"bind_address":"0.0.0.0","bind_port":8889,"public_url":"https://10.20.10.128:8889/app/index.html"},"Frontend":{"hostname":"10.20.10.128","bind_address":"0.0.0.0","bind_port":8000},"Datastore":{"location":"/var/lib/velociraptor","filestore_directory":"/var/lib/velociraptor"}}' \
    >/etc/velociraptor/server.config.yaml
  /usr/local/bin/velociraptor \
    --config /etc/velociraptor/server.config.yaml config client \
    >/etc/velociraptor/client.config.yaml
  chown -R velociraptor:velociraptor /etc/velociraptor /var/lib/velociraptor
  chmod 0640 /etc/velociraptor/server.config.yaml /etc/velociraptor/client.config.yaml
fi
sed -i \
  's#public_url: https://10\\.20\\.10\\.128:8889/$#public_url: https://10.20.10.128:8889/app/index.html#' \
  /etc/velociraptor/server.config.yaml
if [ ! -s /etc/siem/velociraptor-admin.env ]; then
  umask 077
  printf 'VELOCIRAPTOR_ADMIN_PASSWORD=%s\\n' "$(openssl rand -base64 36 | tr -d '\\n')" \
    >/etc/siem/velociraptor-admin.env
  password="$(cut -d= -f2- /etc/siem/velociraptor-admin.env)"
  runuser -u velociraptor -- /usr/local/bin/velociraptor \
    --config /etc/velociraptor/server.config.yaml \
    user add --role administrator socadmin "$password"
fi
cat >/etc/systemd/system/velociraptor.service <<'EOF'
[Unit]
Description=Velociraptor DFIR server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=velociraptor
Group=velociraptor
Environment=HOME=/var/lib/velociraptor
ExecStart=/usr/local/bin/velociraptor --config /etc/velociraptor/server.config.yaml frontend
Restart=always
RestartSec=5
LimitNOFILE=1048576
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/velociraptor /var/log/velociraptor

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now velociraptor
for attempt in $(seq 1 60); do
  if curl -kfsS https://127.0.0.1:8889/ >/dev/null; then
    break
  fi
  sleep 2
done
systemctl is-active --quiet velociraptor
/usr/local/bin/velociraptor version
""",
        timeout=1200,
    )


def install_misp(pve: Proxmox, spec: ContainerSpec) -> None:
    pve.ct(
        spec.vmid,
        """
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get install -y -qq docker.io docker-compose-v2 git uuid-runtime
systemctl enable --now docker
if [ ! -d /opt/misp-docker/.git ]; then
  git clone https://github.com/MISP/misp-docker.git /opt/misp-docker
fi
cd /opt/misp-docker
git fetch --depth 1 origin 223b675c4480730832f928e113b6f2e5260b450d
git checkout --detach 223b675c4480730832f928e113b6f2e5260b450d
if [ ! -s .env ]; then
  umask 077
  admin_password="$(openssl rand -base64 36 | tr -d '\\n')"
  admin_key="$(openssl rand -hex 20)"
  mysql_password="$(openssl rand -base64 36 | tr -d '\\n')"
  mysql_root_password="$(openssl rand -base64 36 | tr -d '\\n')"
  redis_password="$(openssl rand -base64 36 | tr -d '\\n')"
  gpg_password="$(openssl rand -base64 36 | tr -d '\\n')"
  encryption_key="$(openssl rand -hex 32)"
  salt="$(openssl rand -hex 32)"
  instance_uuid="$(uuidgen)"
  cat >.env <<EOF
CORE_TAG=v2.5.44
MODULES_TAG=v3.0.9
GUARD_TAG=v1.2
CORE_RUNNING_TAG=v2.5.44
MODULES_RUNNING_TAG=v3.0.9
ADMIN_EMAIL=socadmin@lab.home.arpa
ADMIN_ORG=Rdegon-SOC
ADMIN_PASSWORD=$admin_password
ADMIN_KEY=$admin_key
DISABLE_PRINTING_PLAINTEXT_CREDENTIALS=true
GPG_PASSPHRASE=$gpg_password
BASE_URL=https://10.20.10.131
ENABLE_DB_SETTINGS=true
ENCRYPTION_KEY=$encryption_key
SALT=$salt
UUID=$instance_uuid
AUTOGEN_ADMIN_KEY=false
DISABLE_IPV6=true
TZ=Europe/Moscow
MYSQL_PASSWORD=$mysql_password
MYSQL_ROOT_PASSWORD=$mysql_root_password
REDIS_PASSWORD=$redis_password
ENABLE_REDIS_EMPTY_PASSWORD=false
INNODB_BUFFER_POOL_SIZE=1024M
PHP_MEMORY_LIMIT=1024M
PHP_FCGI_CHILDREN=4
PHP_FCGI_START_SERVERS=2
PHP_FCGI_SPARE_SERVERS=1
EOF
  chmod 0600 .env
fi
grep -q '^CORE_TAG=' .env || printf 'CORE_TAG=v2.5.44\\n' >>.env
grep -q '^MODULES_TAG=' .env || printf 'MODULES_TAG=v3.0.9\\n' >>.env
grep -q '^GUARD_TAG=' .env || printf 'GUARD_TAG=v1.2\\n' >>.env
cat >docker-compose.override.yml <<'EOF'
services:
  mail:
    security_opt:
      - apparmor=unconfined
  misp-modules:
    security_opt:
      - apparmor=unconfined
  redis:
    security_opt:
      - apparmor=unconfined
  db:
    security_opt:
      - apparmor=unconfined
  misp-core:
    security_opt:
      - apparmor=unconfined
EOF
docker compose pull
docker compose up -d
for attempt in $(seq 1 120); do
  if curl -kfsS https://127.0.0.1/users/login >/dev/null; then
    break
  fi
  sleep 5
done
curl -kfsS https://127.0.0.1/users/login >/dev/null
docker compose ps --format json
""",
        timeout=3600,
    )


def collect_status(pve: Proxmox, names: list[str]) -> list[dict[str, object]]:
    status: list[dict[str, object]] = []
    for name in names:
        spec = CONTAINERS[name]
        service_check = {
            "pki": "systemctl is-active step-ca",
            "evidence": "systemctl is-active minio",
            "dfir": (
                "systemctl is-active velociraptor; "
                "/usr/local/bin/velociraptor version | head -1"
            ),
            "analysis": "trivy --version | head -1; yara --version; clamscan --version | head -1",
            "ti": (
                "cd /opt/misp-docker 2>/dev/null && "
                "docker compose ps --status running --format '{{.Service}}' | sort || "
                "systemctl is-system-running || true"
            ),
        }[name]
        output = pve.ct(
            spec.vmid,
            f"hostname; hostname -I; {service_check}; systemctl is-enabled chrony",
        )
        status.append(
            {
                "component": name,
                "vmid": spec.vmid,
                "hostname": spec.hostname,
                "status": output.strip().splitlines(),
            }
        )
    return status


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Provision the first SOC platform services on Proxmox")
    parser.add_argument(
        "--components",
        nargs="+",
        choices=tuple(CONTAINERS),
        default=["pki", "evidence", "dfir", "analysis"],
    )
    parser.add_argument("--status-only", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    names = list(dict.fromkeys(args.components))
    with Proxmox() as pve:
        if not args.status_only:
            for name in names:
                spec = CONTAINERS[name]
                ensure_container(pve, spec)
                bootstrap_container(pve, spec)
                if name == "pki":
                    install_step_ca(pve, spec)
                elif name == "evidence":
                    install_minio(pve, spec)
                elif name == "dfir":
                    install_velociraptor_binary(pve, spec)
                elif name == "analysis":
                    install_analysis_tools(pve, spec)
                    install_analysis_runtime(pve, spec)
                elif name == "ti":
                    install_misp(pve, spec)
            if "pki" in names and "evidence" in names:
                issue_evidence_certificate(pve)

        print(json.dumps(collect_status(pve, names), indent=2, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
