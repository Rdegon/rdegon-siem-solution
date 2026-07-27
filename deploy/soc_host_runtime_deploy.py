from __future__ import annotations

import argparse
import base64
import os
import shlex
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from deploy.soc_foundation_provision import Proxmox  # noqa: E402


REMOTE_ROOT = "/opt/siem/siem-solution"
INGEST_CA_PATH = "/etc/siem/pki/ingest-ca.crt"


@dataclass(frozen=True)
class RuntimeTarget:
    vmid: int
    guest_type: str
    host_name: str
    role: str
    services: tuple[str, ...]


TARGETS: tuple[RuntimeTarget, ...] = (
    RuntimeTarget(100, "lxc", "minecraft-01", "game-server", ("minecraft", "minecraft-admin-console", "nftables", "rsyslog")),
    RuntimeTarget(102, "qemu", "lab-edge-01", "edge-router", ("suricata", "unbound", "nftables", "auditd", "rsyslog")),
    RuntimeTarget(104, "qemu", "siem-ingest", "ingest", ("siem-ingest", "nginx")),
    RuntimeTarget(105, "qemu", "siem-processing", "processing", ("siem-normalizer", "siem-normalizer@2", "siem-filter", "siem-filter@2")),
    RuntimeTarget(106, "qemu", "siem-storage", "storage", ("clickhouse-server", "siem-writer", "siem-writer@2", "siem-stream-corr", "siem-batch-corr", "siem-alert-agg")),
    RuntimeTarget(107, "qemu", "siem-web", "control-plane", ("siem-web", "nginx", "keycloak", "vault")),
    RuntimeTarget(108, "qemu", "siem-transport", "transport", ("siem-kafka", "siem-normalizer@1", "siem-filter@1")),
    RuntimeTarget(120, "lxc", "nextcloud-siem", "business-app", ("apache2", "mariadb", "redis-server", "fail2ban", "ssh", "rsyslog")),
    RuntimeTarget(121, "lxc", "navidrome-01", "media-node", ("navidrome", "ssh", "rsyslog")),
    RuntimeTarget(122, "qemu", "vuln-mgr-01", "vulnerability-manager", ("docker", "rdegon-vuln-scan.timer", "auditd", "ssh", "rsyslog")),
    RuntimeTarget(123, "qemu", "pilot-web-01", "pilot-web", ("docker", "pilot-gitea", "auditd", "ssh", "rsyslog")),
    RuntimeTarget(124, "qemu", "pilot-db-01", "pilot-db", ("postgresql@14-main", "auditd", "ssh", "rsyslog")),
    RuntimeTarget(125, "qemu", "pilot-cache-01", "pilot-cache", ("docker", "pilot-valkey", "auditd", "ssh", "rsyslog")),
    RuntimeTarget(127, "qemu", "soc-ndr-01", "ndr", ("siem-monitor-interfaces", "siem-security-sensor-forwarder@zeek")),
    RuntimeTarget(128, "lxc", "soc-dfir-01", "dfir", ("velociraptor", "siem-security-sensor-forwarder@velociraptor")),
    RuntimeTarget(129, "lxc", "soc-analysis-01", "malware-analysis", ("clamav-daemon", "siem-clamav-update.timer", "siem-static-analysis", "siem-security-sensor-forwarder@static-analysis")),
    RuntimeTarget(130, "qemu", "gamepanel-01", "game-panel", ("docker", "wings", "nginx", "auditd", "rsyslog")),
    RuntimeTarget(131, "qemu", "soc-ti-01", "threat-intel", ("docker", "siem-misp-exporter.timer", "siem-security-sensor-forwarder@misp")),
    RuntimeTarget(132, "lxc", "soc-pki-01", "pki", ("step-ca",)),
    RuntimeTarget(133, "lxc", "soc-evidence-01", "evidence-storage", ("minio",)),
)

RUNTIME_FILES: tuple[tuple[str, str, int], ...] = (
    ("services/web/app/host_runtime_pipeline.py", f"{REMOTE_ROOT}/host_runtime_pipeline.py", 0o644),
    ("deploy/host_runtime_agent.py", f"{REMOTE_ROOT}/deploy/host_runtime_agent.py", 0o755),
    ("correlation_rule_packs/host_runtime_policy_v1.json", f"{REMOTE_ROOT}/correlation_rule_packs/host_runtime_policy_v1.json", 0o644),
    ("deploy/common/siem-host-runtime-agent.service", "/etc/systemd/system/siem-host-runtime-agent.service", 0o644),
    ("deploy/common/siem-host-runtime-agent.timer", "/etc/systemd/system/siem-host-runtime-agent.timer", 0o644),
)


def _selected_targets(raw_vmids: str) -> tuple[RuntimeTarget, ...]:
    requested = {int(item.strip()) for item in str(raw_vmids or "").split(",") if item.strip()}
    if not requested:
        return TARGETS
    selected = tuple(target for target in TARGETS if target.vmid in requested)
    missing = requested - {target.vmid for target in selected}
    if missing:
        raise ValueError(f"Unknown runtime target VMIDs: {sorted(missing)}")
    return selected


def _exec(pve: Proxmox, target: RuntimeTarget, command: str, timeout: int = 300) -> str:
    if target.guest_type == "lxc":
        return pve.ct(target.vmid, command, timeout=timeout)
    return pve.guest_exec(target.vmid, command, timeout=timeout)


def _write(pve: Proxmox, target: RuntimeTarget, content: bytes, destination: str, mode: int) -> None:
    if target.guest_type == "lxc":
        pve.push_bytes(target.vmid, content, destination, mode)
        return
    encoded = base64.b64encode(content).decode("ascii")
    temp_path = f"/tmp/siem-host-runtime-{target.vmid}-{Path(destination).name}.b64"
    _exec(
        pve,
        target,
        f"install -d -m 0755 {shlex.quote(str(Path(destination).parent))} && : > {shlex.quote(temp_path)}",
    )
    for offset in range(0, len(encoded), 32_000):
        chunk = encoded[offset : offset + 32_000]
        _exec(pve, target, f"printf %s {shlex.quote(chunk)} >> {shlex.quote(temp_path)}")
    _exec(
        pve,
        target,
        f"base64 -d {shlex.quote(temp_path)} > {shlex.quote(destination)} && "
        f"chmod {mode:o} {shlex.quote(destination)} && rm -f {shlex.quote(temp_path)}",
    )


def render_environment(target: RuntimeTarget) -> str:
    return (
        f"SIEM_HOST_RUNTIME_HOSTNAME={target.host_name}\n"
        f"SIEM_HOST_RUNTIME_ROLE={target.role}\n"
        f"SIEM_HOST_RUNTIME_SERVICES={','.join(target.services)}\n"
        "SIEM_HOST_RUNTIME_INGEST_URL=https://10.20.10.104/ingest/json\n"
        "SIEM_HOST_RUNTIME_INGEST_TLS_VERIFY=required\n"
        f"SIEM_HOST_RUNTIME_INGEST_CA_FILE={INGEST_CA_PATH}\n"
        "SIEM_HOST_RUNTIME_TIMEOUT_SECONDS=20\n"
        "SIEM_HOST_RUNTIME_DELIVERY_ATTEMPTS=4\n"
        "SIEM_HOST_RUNTIME_STATE_PATH=/var/lib/siem-host-runtime/state.json\n"
        f"SIEM_HOST_RUNTIME_POLICY_PATH={REMOTE_ROOT}/correlation_rule_packs/host_runtime_policy_v1.json\n"
    )


def deploy_target(pve: Proxmox, target: RuntimeTarget, ingest_certificate: bytes) -> str:
    _exec(
        pve,
        target,
        f"install -d -m 0755 /etc/siem/pki /var/lib/siem-host-runtime "
        f"{shlex.quote(REMOTE_ROOT)} {shlex.quote(REMOTE_ROOT + '/deploy')} "
        f"{shlex.quote(REMOTE_ROOT + '/correlation_rule_packs')}",
    )
    for source, destination, mode in RUNTIME_FILES:
        _write(pve, target, (ROOT / source).read_bytes(), destination, mode)
    _write(pve, target, ingest_certificate, INGEST_CA_PATH, 0o644)
    _write(pve, target, render_environment(target).encode("utf-8"), "/etc/siem/host-runtime.env", 0o600)
    return _exec(
        pve,
        target,
        "systemctl daemon-reload && "
        "systemctl enable siem-host-runtime-agent.timer >/dev/null && "
        "systemctl restart siem-host-runtime-agent.timer && "
        "systemctl start siem-host-runtime-agent.service && "
        "systemctl is-active siem-host-runtime-agent.timer && "
        "systemctl show siem-host-runtime-agent.service -p Result --value",
        timeout=180,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Deploy strict-TLS host runtime telemetry to the SOC fleet.")
    parser.add_argument("--vmids", default=os.getenv("SIEM_RUNTIME_TARGET_VMIDS", ""))
    args = parser.parse_args()
    targets = _selected_targets(args.vmids)
    with Proxmox() as pve:
        certificate = pve.guest_exec(104, "cat /etc/siem/tls/ingest.crt", timeout=60).encode("utf-8")
        if b"BEGIN CERTIFICATE" not in certificate:
            raise RuntimeError("VM104 did not return a valid ingest certificate")
        for target in targets:
            result = deploy_target(pve, target, certificate)
            print(f"{target.vmid} {target.host_name}: {result.strip().replace(chr(10), ' ')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
