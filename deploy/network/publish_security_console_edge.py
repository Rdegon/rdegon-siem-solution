from __future__ import annotations

import base64
from pathlib import Path
import shlex
import sys


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from deploy.soc_foundation_provision import Proxmox


VMID = 102
SOURCE = ROOT / "deploy" / "network" / "lab_edge_opnsense_transit.sh"
DESTINATION = "/usr/local/sbin/lab-edge-opnsense-transit"


def main() -> int:
    encoded = base64.b64encode(SOURCE.read_bytes()).decode("ascii")
    temporary = "/tmp/lab-edge-opnsense-transit.b64"
    staged = f"{DESTINATION}.staged"
    with Proxmox() as pve:
        pve.guest_exec(VMID, f": > {shlex.quote(temporary)}", timeout=60)
        for offset in range(0, len(encoded), 32_000):
            pve.guest_exec(
                VMID,
                f"printf %s {shlex.quote(encoded[offset:offset + 32_000])} >> {shlex.quote(temporary)}",
                timeout=60,
            )
        pve.guest_exec(
            VMID,
            f"base64 -d {shlex.quote(temporary)} > {shlex.quote(staged)}; "
            f"rm -f {shlex.quote(temporary)}; "
            f"bash -n {shlex.quote(staged)}; "
            f"install -m 0750 {shlex.quote(staged)} {shlex.quote(DESTINATION)}; "
            f"rm -f {shlex.quote(staged)}; "
            f"{shlex.quote(DESTINATION)} apply",
            timeout=300,
        )
        verification = pve.guest_exec(
            VMID,
            "nft list table ip nat | "
            "grep -E 'dport (8005|8444|8889|9001|9392) dnat' | "
            "sort -u",
            timeout=60,
        )
    print(verification)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
