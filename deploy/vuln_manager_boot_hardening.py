from __future__ import annotations

import argparse

try:
    from deploy.soc_foundation_provision import Proxmox
except ModuleNotFoundError:
    from soc_foundation_provision import Proxmox


VMID = 122
FSTAB_PATCH = r"""
from pathlib import Path

path = Path("/etc/fstab")
text = path.read_text(encoding="utf-8")
rendered = []
for line in text.splitlines():
    fields = line.split()
    if fields and fields[0] == "LABEL=UEFI" and len(fields) >= 4:
        options = [item for item in fields[3].split(",") if item]
        for required in ("nofail", "x-systemd.device-timeout=10s"):
            if required not in options:
                options.append(required)
        fields[3] = ",".join(options)
        line = "\t".join(fields)
    rendered.append(line)
path.write_text("\n".join(rendered).rstrip() + "\n", encoding="utf-8")
"""


def harden(pve: Proxmox) -> str:
    pve.run("qm set 122 --onboot 1 --startup order=63,up=45,down=90", timeout=60)
    script = f"""set -euo pipefail
cp -an /etc/fstab /etc/fstab.siem-base
python3 - <<'PY'
{FSTAB_PATCH}
PY
systemctl daemon-reload
systemctl set-default multi-user.target
systemctl enable qemu-guest-agent.service ssh.service docker.service openvas.service
printf 'vm.overcommit_memory = 1\n' >/etc/sysctl.d/90-greenbone-memory.conf
sysctl -q -p /etc/sysctl.d/90-greenbone-memory.conf
grep '^LABEL=UEFI' /etc/fstab
sysctl -n vm.overcommit_memory
systemctl is-active qemu-guest-agent.service ssh.service docker.service openvas.service
systemctl --failed --no-legend
"""
    return pve.guest_exec(VMID, script, timeout=120)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Make the Greenbone VM resilient to a delayed optional EFI device"
    )
    parser.parse_args()
    with Proxmox() as pve:
        print(harden(pve))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
