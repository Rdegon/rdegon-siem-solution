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
VMID = 104
REMOTE_ROOT = "/opt/siem/siem-solution"
INGEST_PYTHON = "/opt/siem/venv-ingest/bin/python"
RELEASE_FILES = ("services/ingest/redis_client.py",)


def _push_file(pve: Proxmox, relative: str, *, backup_root: str) -> None:
    source = ROOT / relative
    destination = str(PurePosixPath(REMOTE_ROOT) / relative)
    backup = str(
        PurePosixPath(backup_root)
        / destination.removeprefix("/").replace("/", "__")
    )
    temp = f"/tmp/siem-ingest-health-{source.name}.b64"
    encoded = base64.b64encode(source.read_bytes()).decode("ascii")
    pve.guest_exec(
        VMID,
        f"install -d -m 0750 {shlex.quote(backup_root)} "
        f"{shlex.quote(str(PurePosixPath(destination).parent))}; "
        f"cp -a {shlex.quote(destination)} {shlex.quote(backup)}; "
        f": > {shlex.quote(temp)}",
    )
    for offset in range(0, len(encoded), 32_000):
        pve.guest_exec(
            VMID,
            f"printf %s {shlex.quote(encoded[offset:offset + 32_000])} >> {shlex.quote(temp)}",
        )
    pve.guest_exec(
        VMID,
        f"base64 -d {shlex.quote(temp)} > {shlex.quote(destination)}; "
        f"rm -f {shlex.quote(temp)}; "
        f"chmod --reference={shlex.quote(backup)} {shlex.quote(destination)}; "
        f"chown --reference={shlex.quote(backup)} {shlex.quote(destination)}",
    )


def main() -> int:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup_root = f"/var/backups/siem/ingest-health-qga-{stamp}"
    with Proxmox() as pve:
        for relative in RELEASE_FILES:
            _push_file(pve, relative, backup_root=backup_root)
        compile_output = pve.guest_exec(
            VMID,
            f"{shlex.quote(INGEST_PYTHON)} -m py_compile "
            f"{shlex.quote(str(PurePosixPath(REMOTE_ROOT) / RELEASE_FILES[0]))}",
        )
        state_output = pve.guest_exec(
            VMID,
            "set -euo pipefail; "
            "systemctl restart siem-ingest; "
            "systemctl is-active --quiet siem-ingest nginx; "
            "for attempt in $(seq 1 30); do "
            "curl -kfsS --max-time 5 https://127.0.0.1/health >/dev/null && break; "
            "sleep 1; "
            "done; "
            "curl -kfsS --max-time 5 https://127.0.0.1/health >/dev/null; "
            "systemctl is-active siem-ingest nginx",
            timeout=180,
        )
    print(
        json.dumps(
            {
                "vmid": VMID,
                "files": len(RELEASE_FILES),
                "backup": backup_root,
                "compile": compile_output.strip() or "ok",
                "services": state_output.splitlines(),
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
