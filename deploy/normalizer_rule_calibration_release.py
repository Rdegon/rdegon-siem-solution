from __future__ import annotations

import base64
import json
import shlex
import sys
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

try:
    from deploy.soc_foundation_provision import Proxmox
except ModuleNotFoundError:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from soc_foundation_provision import Proxmox


ROOT = Path(__file__).resolve().parents[1]
REMOTE_ROOT = "/opt/siem/siem-solution"
TARGET_VMIDS = (105, 108)
RELEASE_FILES = (
    "services/normalizer/normalizer_core.py",
    "services/normalizer/linux_service_normalizers.py",
    "services/normalizer/security_tool_normalizers.py",
)
NORMALIZER_UNITS = (
    "siem-normalizer.service",
    "siem-normalizer@1.service",
    "siem-normalizer@2.service",
)


def _push_file(
    pve: Proxmox,
    vmid: int,
    relative: str,
    *,
    backup_root: str,
) -> None:
    source = ROOT / relative
    destination = str(PurePosixPath(REMOTE_ROOT) / relative)
    backup = str(
        PurePosixPath(backup_root)
        / destination.removeprefix("/").replace("/", "__")
    )
    temp = f"/tmp/siem-normalizer-calibration-{source.name}.b64"
    encoded = base64.b64encode(source.read_bytes()).decode("ascii")
    pve.guest_exec(
        vmid,
        f"install -d -m 0750 {shlex.quote(backup_root)} "
        f"{shlex.quote(str(PurePosixPath(destination).parent))}; "
        f"if [ -f {shlex.quote(destination)} ]; then "
        f"cp -a {shlex.quote(destination)} {shlex.quote(backup)}; fi; "
        f": > {shlex.quote(temp)}",
    )
    for offset in range(0, len(encoded), 32_000):
        pve.guest_exec(
            vmid,
            f"printf %s {shlex.quote(encoded[offset:offset + 32_000])} "
            f">> {shlex.quote(temp)}",
        )
    pve.guest_exec(
        vmid,
        f"base64 -d {shlex.quote(temp)} > {shlex.quote(destination)}; "
        f"rm -f {shlex.quote(temp)}; "
        f"chmod 0755 {shlex.quote(str(PurePosixPath(destination).parent))}; "
        f"chmod 0644 {shlex.quote(destination)}",
    )


def main() -> int:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    results: dict[str, object] = {"backup_stamp": stamp, "targets": {}}
    unit_args = " ".join(shlex.quote(unit) for unit in NORMALIZER_UNITS)
    with Proxmox() as pve:
        for vmid in TARGET_VMIDS:
            backup_root = f"/var/backups/siem/normalizer-calibration-{stamp}"
            for relative in RELEASE_FILES:
                _push_file(pve, vmid, relative, backup_root=backup_root)
            output = pve.guest_exec(
                vmid,
                f"python3 -m py_compile "
                + " ".join(
                    shlex.quote(str(PurePosixPath(REMOTE_ROOT) / relative))
                    for relative in RELEASE_FILES
                )
                + f"; systemctl restart {unit_args}; "
                "for attempt in $(seq 1 30); do "
                f"states=$(systemctl is-active {unit_args} 2>/dev/null || true); "
                "test \"$(printf '%s\\n' \"$states\" | grep -c '^active$')\" -eq 3 "
                "&& break; "
                "sleep 2; "
                "done; "
                f"states=$(systemctl is-active {unit_args} 2>/dev/null || true); "
                "test \"$(printf '%s\\n' \"$states\" | grep -c '^active$')\" -eq 3; "
                "printf '%s\\n' \"$states\"",
                timeout=240,
            )
            results["targets"][str(vmid)] = {
                "backup": backup_root,
                "services": output.splitlines(),
            }
    print(json.dumps(results, ensure_ascii=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
