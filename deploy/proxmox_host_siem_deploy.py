from __future__ import annotations

import base64
import os
import shlex
from datetime import datetime, timezone
from pathlib import Path

try:
    from deploy.soc_foundation_provision import Proxmox
except ModuleNotFoundError:
    from soc_foundation_provision import Proxmox


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "deploy/common/90-proxmox-siem-forward.conf"
DESTINATION = "/etc/rsyslog.d/90-siem-forward.conf"


def _write_host_file(pve: Proxmox, destination: str, content: bytes) -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup = f"/var/backups/siem/proxmox-rsyslog-{timestamp}"
    encoded = base64.b64encode(content).decode("ascii")
    temporary = f"/tmp/siem-proxmox-rsyslog-{os.getpid()}.b64"
    pve.run(
        f"install -d -m 0750 {shlex.quote(backup)}; "
        f"cp -a {shlex.quote(destination)} {shlex.quote(backup + '/90-siem-forward.conf')} "
        f"2>/dev/null || true; : > {shlex.quote(temporary)}"
    )
    try:
        for offset in range(0, len(encoded), 32_000):
            pve.run(
                f"printf %s {shlex.quote(encoded[offset:offset + 32_000])} "
                f">> {shlex.quote(temporary)}"
            )
        pve.run(
            f"base64 -d {shlex.quote(temporary)} > {shlex.quote(destination)}; "
            f"chmod 0644 {shlex.quote(destination)}"
        )
    finally:
        pve.run(f"rm -f {shlex.quote(temporary)}")
    return backup


def main() -> int:
    with Proxmox() as pve:
        backup = _write_host_file(pve, DESTINATION, SOURCE.read_bytes())
        pve.run(
            "rsyslogd -N1; "
            "systemctl enable rsyslog; "
            "systemctl restart rsyslog; "
            "systemctl is-active rsyslog; "
            "logger -p auth.notice -t siem-pve-forwarder "
            "'SIEM PVE forwarder production transport check'"
        )
        print(f"proxmox_rsyslog=active backup={backup}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
