from __future__ import annotations

import base64
import json
import shlex
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from deploy.soc_foundation_provision import Proxmox


REMOTE_ROOT = "/opt/siem/siem-solution"
FORWARDER_SOURCE = ROOT / "deploy" / "security_sensor_forwarder.py"
FORWARDER_DESTINATION = "/opt/siem/deploy/security_sensor_forwarder.py"
NORMALIZER_SOURCE = ROOT / "services" / "normalizer" / "security_tool_normalizers.py"
NORMALIZER_DESTINATION = (
    f"{REMOTE_ROOT}/services/normalizer/security_tool_normalizers.py"
)
STREAM_SOURCE = ROOT / "services" / "stream_corr" / "worker.py"
STREAM_DESTINATION = f"{REMOTE_ROOT}/services/stream_corr/worker.py"


@dataclass(frozen=True)
class SensorTarget:
    vmid: int
    guest_type: str


SENSOR_TARGETS = (
    SensorTarget(102, "qemu"),
    SensorTarget(122, "qemu"),
    SensorTarget(127, "qemu"),
    SensorTarget(130, "qemu"),
    SensorTarget(131, "qemu"),
    SensorTarget(128, "lxc"),
    SensorTarget(129, "lxc"),
    SensorTarget(132, "lxc"),
    SensorTarget(133, "lxc"),
)


def _guest_run(
    pve: Proxmox,
    target: SensorTarget,
    command: str,
    *,
    timeout: int = 180,
) -> str:
    if target.guest_type == "lxc":
        return pve.ct(target.vmid, command, timeout=timeout)
    return pve.guest_exec(target.vmid, command, timeout=timeout)


def _push_qemu(
    pve: Proxmox,
    vmid: int,
    source: Path,
    destination: str,
    *,
    mode: int,
    backup_root: str,
) -> None:
    encoded = base64.b64encode(source.read_bytes()).decode("ascii")
    temporary = f"/tmp/siem-heartbeat-release-{source.name}.b64"
    backup = str(
        PurePosixPath(backup_root)
        / destination.removeprefix("/").replace("/", "__")
    )
    pve.guest_exec(
        vmid,
        f"install -d -m 0750 {shlex.quote(backup_root)}; "
        f"install -d -m 0755 {shlex.quote(str(PurePosixPath(destination).parent))}; "
        f"if [ -f {shlex.quote(destination)} ]; then "
        f"cp -a {shlex.quote(destination)} {shlex.quote(backup)}; fi; "
        f": > {shlex.quote(temporary)}",
    )
    for offset in range(0, len(encoded), 32_000):
        pve.guest_exec(
            vmid,
            f"printf %s {shlex.quote(encoded[offset:offset + 32_000])} "
            f">> {shlex.quote(temporary)}",
        )
    pve.guest_exec(
        vmid,
        f"base64 -d {shlex.quote(temporary)} > {shlex.quote(destination)}; "
        f"rm -f {shlex.quote(temporary)}; "
        f"chmod {mode:o} {shlex.quote(destination)}",
    )


def _push_lxc(
    pve: Proxmox,
    vmid: int,
    source: Path,
    destination: str,
    *,
    mode: int,
    backup_root: str,
) -> None:
    backup = str(
        PurePosixPath(backup_root)
        / destination.removeprefix("/").replace("/", "__")
    )
    pve.ct(
        vmid,
        f"install -d -m 0750 {shlex.quote(backup_root)}; "
        f"if [ -f {shlex.quote(destination)} ]; then "
        f"cp -a {shlex.quote(destination)} {shlex.quote(backup)}; fi",
    )
    pve.push_bytes(vmid, source.read_bytes(), destination, mode)


def _push(
    pve: Proxmox,
    target: SensorTarget,
    source: Path,
    destination: str,
    *,
    mode: int,
    backup_root: str,
) -> None:
    if target.guest_type == "lxc":
        _push_lxc(
            pve,
            target.vmid,
            source,
            destination,
            mode=mode,
            backup_root=backup_root,
        )
        return
    _push_qemu(
        pve,
        target.vmid,
        source,
        destination,
        mode=mode,
        backup_root=backup_root,
    )


def _release_sensor(
    pve: Proxmox,
    target: SensorTarget,
    *,
    backup_root: str,
) -> dict[str, object]:
    probe = _guest_run(
        pve,
        target,
        "if [ -d /etc/siem ]; then "
        "find /etc/siem -maxdepth 1 -type f -name 'security-sensor-*.env' "
        "-printf '%f\\n' | sort; fi",
    )
    environment_files = [line.strip() for line in probe.splitlines() if line.strip()]
    if not environment_files:
        return {"status": "not_installed", "instances": []}
    _push(
        pve,
        target,
        FORWARDER_SOURCE,
        FORWARDER_DESTINATION,
        mode=0o755,
        backup_root=backup_root,
    )
    output = _guest_run(
        pve,
        target,
        "set -euo pipefail; "
        f"python3 -m py_compile {shlex.quote(FORWARDER_DESTINATION)}; "
        "instances=''; "
        "for env_file in /etc/siem/security-sensor-*.env; do "
        "  [ -f \"$env_file\" ] || continue; "
        "  instance=\"${env_file##*/security-sensor-}\"; "
        "  instance=\"${instance%.env}\"; "
        "  unit=\"siem-security-sensor-forwarder@${instance}.service\"; "
        "  if systemctl is-enabled --quiet \"$unit\" "
        "     || systemctl is-active --quiet \"$unit\"; then "
        "    systemctl restart \"$unit\"; "
        "    systemctl is-active --quiet \"$unit\"; "
        "    instances=\"${instances}${instances:+,}${instance}\"; "
        "  fi; "
        "done; "
        "printf '%s\\n' \"$instances\"",
        timeout=300,
    )
    instances = [
        value for value in output.strip().split(",") if value
    ]
    return {"status": "active", "instances": instances}


def main() -> int:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup_root = f"/var/backups/siem/security-heartbeat-{stamp}"
    results: dict[str, object] = {
        "backup": backup_root,
        "processing": {},
        "sensors": {},
    }
    with Proxmox() as pve:
        stream_target = SensorTarget(106, "qemu")
        _push(
            pve,
            stream_target,
            STREAM_SOURCE,
            STREAM_DESTINATION,
            mode=0o644,
            backup_root=backup_root,
        )
        stream_output = pve.guest_exec(
            106,
            f"python3 -m py_compile {shlex.quote(STREAM_DESTINATION)}; "
            "systemctl restart siem-stream-corr.service; "
            "systemctl is-active siem-stream-corr.service",
            timeout=240,
        )
        results["processing"]["stream_corr"] = stream_output.strip()

        for vmid in (105, 108):
            target = SensorTarget(vmid, "qemu")
            _push(
                pve,
                target,
                NORMALIZER_SOURCE,
                NORMALIZER_DESTINATION,
                mode=0o644,
                backup_root=backup_root,
            )
            normalizer_output = pve.guest_exec(
                vmid,
                f"python3 -m py_compile {shlex.quote(NORMALIZER_DESTINATION)}; "
                "systemctl restart siem-normalizer.service "
                "siem-normalizer@1.service siem-normalizer@2.service; "
                "systemctl is-active siem-normalizer.service "
                "siem-normalizer@1.service siem-normalizer@2.service",
                timeout=300,
            )
            states = [
                line for line in normalizer_output.splitlines() if line.strip()
            ]
            if states != ["active", "active", "active"]:
                raise RuntimeError(
                    f"Normalizer release failed on VM{vmid}: {states}"
                )
            results["processing"][f"normalizer_{vmid}"] = states

        for target in SENSOR_TARGETS:
            results["sensors"][str(target.vmid)] = _release_sensor(
                pve,
                target,
                backup_root=backup_root,
            )
    print(json.dumps(results, ensure_ascii=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
