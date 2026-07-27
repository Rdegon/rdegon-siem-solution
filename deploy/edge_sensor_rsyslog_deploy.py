from __future__ import annotations

import base64
import os
import shlex
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from deploy.soc_foundation_provision import Proxmox  # noqa: E402


VMID = int(os.getenv("SIEM_EDGE_VMID", "102") or "102")
REMOTE_MESSAGE_SIZE = "/etc/rsyslog.d/00-siem-rsyslog-message-size.conf"
REMOTE_FORWARD = "/etc/rsyslog.d/90-siem-forward.conf"
REMOTE_SURICATA = "/etc/rsyslog.d/91-suricata-imfile.conf"
LEGACY_FORWARD = "/etc/rsyslog.d/90-lab-edge-forward.conf"


def _timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _write_guest_file(pve: Proxmox, content: bytes, destination: str, mode: int = 0o644) -> None:
    encoded = base64.b64encode(content).decode("ascii")
    temporary = f"/tmp/siem-edge-rsyslog-{Path(destination).name}.b64"
    pve.guest_exec(
        VMID,
        f"install -d -m 0755 {shlex.quote(str(Path(destination).parent))} && "
        f": > {shlex.quote(temporary)}",
    )
    for offset in range(0, len(encoded), 32_000):
        pve.guest_exec(
            VMID,
            f"printf %s {shlex.quote(encoded[offset:offset + 32_000])} >> {shlex.quote(temporary)}",
        )
    pve.guest_exec(
        VMID,
        f"base64 -d {shlex.quote(temporary)} > {shlex.quote(destination)} && "
        f"chmod {mode:o} {shlex.quote(destination)} && rm -f {shlex.quote(temporary)}",
    )


def main() -> int:
    backup = f"/var/backups/siem/edge-rsyslog-{_timestamp()}"
    with Proxmox() as pve:
        pve.guest_exec(VMID, f"install -d -m 0700 {shlex.quote(backup)}")
        for remote_path in (REMOTE_MESSAGE_SIZE, REMOTE_FORWARD, REMOTE_SURICATA, LEGACY_FORWARD):
            pve.guest_exec(
                VMID,
                f"if [ -f {shlex.quote(remote_path)} ]; then "
                f"cp -a {shlex.quote(remote_path)} {shlex.quote(backup + '/' + Path(remote_path).name)}; fi",
            )
        _write_guest_file(
            pve,
            (ROOT / "deploy/common/00-siem-rsyslog-message-size.conf").read_bytes(),
            REMOTE_MESSAGE_SIZE,
            0o644,
        )
        _write_guest_file(
            pve,
            (ROOT / "deploy/common/90-edge-siem-forward.conf").read_bytes(),
            REMOTE_FORWARD,
            0o644,
        )
        _write_guest_file(
            pve,
            (ROOT / "deploy/common/91-suricata-imfile.conf").read_bytes(),
            REMOTE_SURICATA,
            0o644,
        )
        pve.guest_exec(
            VMID,
            f"if [ -f {shlex.quote(LEGACY_FORWARD)} ]; then "
            f"mv {shlex.quote(LEGACY_FORWARD)} {shlex.quote(backup + '/90-lab-edge-forward.conf.disabled')}; fi && "
            "rsyslogd -N1",
        )
        pve.guest_exec(
            VMID,
            f"systemctl stop rsyslog && "
            "for state in /var/spool/rsyslog/imfile-state:*; do "
            "[ -f \"$state\" ] || continue; "
            "if grep -q 'suricata' \"$state\"; then "
            f"mv \"$state\" {shlex.quote(backup)}/; "
            "fi; "
            "done",
        )
        validation = pve.guest_exec(
            VMID,
            "systemctl start rsyslog && sleep 3 && "
            "systemctl is-active rsyslog suricata && "
            "test \"$(grep -Rh 'port=\"1514\"' /etc/rsyslog.d/*.conf | wc -l)\" -eq 1 && "
            "ss -ntp | grep -q '10.20.10.104:1514'",
            timeout=120,
        )
        print(f"edge_rsyslog=active vmid={VMID} backup={backup} validation={validation.strip()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
