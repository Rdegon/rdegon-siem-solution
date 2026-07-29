from __future__ import annotations

import base64
from pathlib import Path
import shlex
import sys


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from deploy.network.publish_security_console_edge import main as publish_edge
from deploy.soc_foundation_provision import Proxmox


WEB_VMID = 107
SOURCE = ROOT / "deploy" / "network" / "security_console_proxy.conf"
DESTINATION = "/etc/nginx/conf.d/siem-security-consoles.conf"


def _push_proxy() -> None:
    encoded = base64.b64encode(SOURCE.read_bytes()).decode("ascii")
    temporary = "/tmp/siem-security-consoles.conf.b64"
    staged = f"{DESTINATION}.staged"
    with Proxmox() as pve:
        pve.guest_exec(WEB_VMID, f": > {shlex.quote(temporary)}", timeout=60)
        for offset in range(0, len(encoded), 32_000):
            pve.guest_exec(
                WEB_VMID,
                f"printf %s {shlex.quote(encoded[offset:offset + 32_000])} >> {shlex.quote(temporary)}",
                timeout=60,
            )
        print(
            pve.guest_exec(
                WEB_VMID,
                f"base64 -d {shlex.quote(temporary)} > {shlex.quote(staged)}; "
                f"rm -f {shlex.quote(temporary)}; "
                f"chmod 0644 {shlex.quote(staged)}; "
                f"backup={shlex.quote(DESTINATION)}.pre-console-proxy; "
                f"if [ -f {shlex.quote(DESTINATION)} ]; then cp -a {shlex.quote(DESTINATION)} \"$backup\"; fi; "
                f"mv -f {shlex.quote(staged)} {shlex.quote(DESTINATION)}; "
                f"if ! nginx -t; then "
                f"  if [ -f \"$backup\" ]; then mv -f \"$backup\" {shlex.quote(DESTINATION)}; "
                f"  else rm -f {shlex.quote(DESTINATION)}; fi; "
                f"  nginx -t; exit 1; "
                f"fi; "
                "ufw allow from 192.168.3.102 to any port 8444 proto tcp "
                "comment 'siem-edge-misp-proxy' >/dev/null; "
                "ufw allow from 192.168.3.102 to any port 8889 proto tcp "
                "comment 'siem-edge-velociraptor-proxy' >/dev/null; "
                "ufw allow from 192.168.3.102 to any port 9001 proto tcp "
                "comment 'siem-edge-minio-proxy' >/dev/null; "
                f"systemctl reload nginx; "
                "systemctl is-active nginx; "
                "ss -lnt | grep -E ':(8444|8889|9001)'",
                timeout=120,
            )
        )


def main() -> int:
    _push_proxy()
    return publish_edge()


if __name__ == "__main__":
    raise SystemExit(main())
