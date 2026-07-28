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
WEB_PYTHON = "/opt/siem/venv-web/bin/python"
QEMU_RUNTIME_IDS = (102, 104, 105, 106, 107, 108, 122, 123, 124, 125, 127, 130, 131)
CONTAINER_RUNTIME_IDS = (100, 120, 121, 128, 129, 132, 133)
RULE_FILES = (
    "correlation_rule_packs/siem_detection_pack_v1.json",
    "correlation_rule_packs/siem_detection_pack_v1_report.md",
    "deploy/curated_assignment_rules.py",
    "deploy/publish_assignment_detection_pack.py",
)


def _push_file(
    pve: Proxmox,
    vmid: int,
    source: Path,
    destination: str,
    *,
    backup_root: str,
) -> None:
    encoded = base64.b64encode(source.read_bytes()).decode("ascii")
    temp = f"/tmp/siem-calibration-{vmid}-{source.name}.b64"
    backup = str(
        PurePosixPath(backup_root)
        / destination.removeprefix("/").replace("/", "__")
    )
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
        f"rm -f {shlex.quote(temp)}; chmod 0644 {shlex.quote(destination)}",
    )


def _push_container_file(
    pve: Proxmox,
    vmid: int,
    source: Path,
    destination: str,
    *,
    backup_root: str,
) -> None:
    encoded = base64.b64encode(source.read_bytes()).decode("ascii")
    temp = f"/tmp/siem-calibration-{vmid}-{source.name}.b64"
    backup = str(
        PurePosixPath(backup_root)
        / destination.removeprefix("/").replace("/", "__")
    )
    pve.ct(
        vmid,
        f"install -d -m 0750 {shlex.quote(backup_root)} "
        f"{shlex.quote(str(PurePosixPath(destination).parent))}; "
        f"if [ -f {shlex.quote(destination)} ]; then "
        f"cp -a {shlex.quote(destination)} {shlex.quote(backup)}; fi; "
        f": > {shlex.quote(temp)}",
    )
    for offset in range(0, len(encoded), 32_000):
        pve.ct(
            vmid,
            f"printf %s {shlex.quote(encoded[offset:offset + 32_000])} "
            f">> {shlex.quote(temp)}",
        )
    pve.ct(
        vmid,
        f"base64 -d {shlex.quote(temp)} > {shlex.quote(destination)}; "
        f"rm -f {shlex.quote(temp)}; chmod 0644 {shlex.quote(destination)}",
    )


def _publish_command() -> str:
    return f"""
set -euo pipefail
cd {shlex.quote(REMOTE_ROOT)}
{shlex.quote(WEB_PYTHON)} - <<'PY'
import os
import runpy
from pathlib import Path

for raw_line in Path("/etc/siem/web.env").read_text(encoding="utf-8").splitlines():
    line = raw_line.strip()
    if not line or line.startswith("#") or "=" not in raw_line:
        continue
    key, value = raw_line.split("=", 1)
    if key.strip():
        os.environ.setdefault(key.strip(), value)
runpy.run_path("deploy/publish_assignment_detection_pack.py", run_name="__main__")
PY
"""


def main() -> int:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    results: dict[str, object] = {"backup_stamp": stamp, "runtime": {}}
    runtime_source = ROOT / "services/web/app/host_runtime_pipeline.py"
    with Proxmox() as pve:
        for vmid in QEMU_RUNTIME_IDS:
            backup_root = f"/var/backups/siem/rule-calibration-{stamp}"
            _push_file(
                pve,
                vmid,
                runtime_source,
                f"{REMOTE_ROOT}/host_runtime_pipeline.py",
                backup_root=backup_root,
            )
            if vmid == 107:
                _push_file(
                    pve,
                    vmid,
                    runtime_source,
                    f"{REMOTE_ROOT}/services/web/app/host_runtime_pipeline.py",
                    backup_root=backup_root,
                )
            output = pve.guest_exec(
                vmid,
                f"python3 -m py_compile {shlex.quote(REMOTE_ROOT + '/host_runtime_pipeline.py')}; "
                "systemctl restart siem-host-runtime-agent.timer; "
                "systemctl start siem-host-runtime-agent.service; "
                "systemctl is-active siem-host-runtime-agent.timer",
                timeout=240,
            )
            results["runtime"][str(vmid)] = output.strip()

        for vmid in CONTAINER_RUNTIME_IDS:
            backup_root = f"/var/backups/siem/rule-calibration-{stamp}"
            _push_container_file(
                pve,
                vmid,
                runtime_source,
                f"{REMOTE_ROOT}/host_runtime_pipeline.py",
                backup_root=backup_root,
            )
            output = pve.ct(
                vmid,
                f"python3 -m py_compile {shlex.quote(REMOTE_ROOT + '/host_runtime_pipeline.py')}; "
                "systemctl restart siem-host-runtime-agent.timer; "
                "systemctl start siem-host-runtime-agent.service; "
                "systemctl is-active siem-host-runtime-agent.timer",
                timeout=240,
            )
            results["runtime"][str(vmid)] = output.strip()

        for relative in RULE_FILES:
            _push_file(
                pve,
                107,
                ROOT / relative,
                f"{REMOTE_ROOT}/{relative}",
                backup_root=f"/var/backups/siem/rule-calibration-{stamp}",
            )
        pve.guest_exec(
            107,
            f"{shlex.quote(WEB_PYTHON)} -m py_compile "
            f"{shlex.quote(REMOTE_ROOT + '/deploy/curated_assignment_rules.py')} "
            f"{shlex.quote(REMOTE_ROOT + '/deploy/publish_assignment_detection_pack.py')}",
            timeout=180,
        )
        publish_output = pve.guest_exec(107, _publish_command(), timeout=900)
        results["publish"] = json.loads(publish_output.strip())

    print(json.dumps(results, ensure_ascii=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
