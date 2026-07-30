from __future__ import annotations

import base64
import json
import shlex
import sys
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from deploy.soc_foundation_provision import Proxmox


VMID = 107
REMOTE_ROOT = "/opt/siem/siem-solution"
WEB_ROOT = f"{REMOTE_ROOT}/services/web"
WEB_PYTHON = "/opt/siem/venv-web/bin/python"

FILES = (
    "services/web/app/clickhouse_runtime.py",
    "services/web/app/proxmox_fleet_runtime.py",
    "services/web/app/security_services_runtime.py",
    "frontend-react/src/shell/pages/SecurityServicePage.tsx",
    "frontend-react/src/shell/types.ts",
    "frontend-react/src/styles/page-families.css",
)


def _remote_path(relative: str) -> str:
    if relative.startswith("frontend-react/"):
        return str(
            PurePosixPath(WEB_ROOT)
            / "frontend-react"
            / relative.removeprefix("frontend-react/")
        )
    return str(PurePosixPath(REMOTE_ROOT) / relative)


def _push_file(
    pve: Proxmox,
    relative: str,
    *,
    backup_root: str,
) -> None:
    source = ROOT / relative
    destination = _remote_path(relative)
    backup = str(
        PurePosixPath(backup_root)
        / destination.removeprefix("/").replace("/", "__")
    )
    temporary = f"/tmp/siem-security-operations-{source.name}.b64"
    encoded = base64.b64encode(source.read_bytes()).decode("ascii")
    pve.guest_exec(
        VMID,
        f"install -d -m 0750 {shlex.quote(backup_root)}; "
        f"install -d -o rdegon -g rdegon -m 0755 "
        f"{shlex.quote(str(PurePosixPath(destination).parent))}; "
        f"if [ -f {shlex.quote(destination)} ]; then "
        f"cp -a {shlex.quote(destination)} {shlex.quote(backup)}; fi; "
        f": > {shlex.quote(temporary)}",
    )
    for offset in range(0, len(encoded), 32_000):
        pve.guest_exec(
            VMID,
            f"printf %s {shlex.quote(encoded[offset:offset + 32_000])} "
            f">> {shlex.quote(temporary)}",
        )
    pve.guest_exec(
        VMID,
        f"base64 -d {shlex.quote(temporary)} > {shlex.quote(destination)}; "
        f"rm -f {shlex.quote(temporary)}; "
        f"chmod 0644 {shlex.quote(destination)}; "
        f"chown rdegon:rdegon {shlex.quote(destination)}",
    )


def main() -> int:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup_root = f"/var/backups/siem/security-operations-{stamp}"
    with Proxmox() as pve:
        for relative in FILES:
            _push_file(pve, relative, backup_root=backup_root)
        output = pve.guest_exec(
            VMID,
            "set -euo pipefail; "
            f"cd {shlex.quote(WEB_ROOT)}; "
            f"{shlex.quote(WEB_PYTHON)} -m py_compile "
            "app/clickhouse_runtime.py "
            "app/proxmox_fleet_runtime.py "
            "app/security_services_runtime.py; "
            f"cd {shlex.quote(WEB_ROOT + '/frontend-react')}; "
            "runuser -u rdegon -- npm run build >/dev/null; "
            "systemctl restart siem-web; "
            "for attempt in $(seq 1 30); do "
            "curl -kfsS --max-time 3 https://127.0.0.1/healthz >/dev/null && break; "
            "sleep 1; "
            "done; "
            "systemctl is-active --quiet siem-web nginx siem-keycloak; "
            "printf 'services='; "
            "systemctl is-active siem-web nginx siem-keycloak | paste -sd, -; "
            "printf 'health='; "
            "curl -kfsS --max-time 5 https://127.0.0.1/healthz",
            timeout=900,
        )
    print(
        json.dumps(
            {
                "vmid": VMID,
                "files": list(FILES),
                "backup": backup_root,
                "smoke": [line for line in output.splitlines() if line.strip()],
            },
            ensure_ascii=True,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
