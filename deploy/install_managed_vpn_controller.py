from __future__ import annotations

import base64
from datetime import datetime, timezone
import os
from pathlib import Path
import shlex
import sys

try:
    from deploy.soc_foundation_provision import Proxmox
    from deploy.vm4_qga_release_deploy import _push_file
except ModuleNotFoundError:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from deploy.soc_foundation_provision import Proxmox
    from deploy.vm4_qga_release_deploy import _push_file


VMID = 107
REMOTE_CONTROLLER_SOURCE = (
    "/opt/siem/siem-solution/deploy/jump-host/siem_openvpn_ca_controller.py"
)
LOCAL_CONTROLLER_SOURCE = (
    "/opt/siem/siem-solution/deploy/vm4/siem_vpn_profile_controller.py"
)
SSH_KEY_DESTINATION = "/etc/siem/credentials/vpnadmin_ed25519"


def main() -> int:
    key_path = Path(str(os.getenv("SIEM_VPNADMIN_SSH_KEY_PATH") or "")).expanduser()
    if not key_path.is_file():
        raise RuntimeError("SIEM_VPNADMIN_SSH_KEY_PATH must point to the operator SSH key")
    key_b64 = base64.b64encode(key_path.read_bytes()).decode("ascii")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup_root = f"/var/backups/siem/managed-vpn-controller-{stamp}"
    with Proxmox() as pve:
        for relative in (
            "deploy/jump-host/siem_openvpn_ca_controller.py",
            "deploy/vm4/siem_vpn_profile_controller.py",
        ):
            _push_file(pve, relative, backup_root=backup_root)
        command = f"""
set -euo pipefail
install -d -o root -g root -m 0700 /etc/siem/credentials
printf %s {shlex.quote(key_b64)} | base64 -d > {shlex.quote(SSH_KEY_DESTINATION)}
chown root:root {shlex.quote(SSH_KEY_DESTINATION)}
chmod 0600 {shlex.quote(SSH_KEY_DESTINATION)}
install -o root -g root -m 0750 {shlex.quote(LOCAL_CONTROLLER_SOURCE)} /usr/local/sbin/siem-vpn-profile-controller
printf '%s\n' 'rdegon ALL=(root) NOPASSWD: /usr/local/sbin/siem-vpn-profile-controller *' > /etc/sudoers.d/siem-vpn-profile-controller
chmod 0440 /etc/sudoers.d/siem-vpn-profile-controller
visudo -cf /etc/sudoers.d/siem-vpn-profile-controller >/dev/null
scp -q -i {shlex.quote(SSH_KEY_DESTINATION)} -o BatchMode=yes -o ConnectTimeout=7 -o StrictHostKeyChecking=accept-new {shlex.quote(REMOTE_CONTROLLER_SOURCE)} vpnadmin_rdegon@10.66.66.1:/tmp/siem-openvpn-ca-controller
ssh -i {shlex.quote(SSH_KEY_DESTINATION)} -o BatchMode=yes -o ConnectTimeout=7 vpnadmin_rdegon@10.66.66.1 'sudo install -o root -g root -m 0750 /tmp/siem-openvpn-ca-controller /usr/local/sbin/siem-openvpn-ca-controller; rm -f /tmp/siem-openvpn-ca-controller; sudo /usr/local/sbin/siem-openvpn-ca-controller initialize' || true
for attempt in $(seq 1 60); do
  if systemctl is-active --quiet openvpn-client@home-gateway && timeout 3 bash -lc '</dev/tcp/10.66.66.1/22' >/dev/null 2>&1; then break; fi
  sleep 2
done
systemctl is-active --quiet openvpn-client@home-gateway
runuser -u rdegon -- sudo -n /usr/local/sbin/siem-vpn-profile-controller status >/dev/null
"""
        pve.guest_exec(VMID, command, timeout=240)
    print(f"managed OpenVPN controller installed; backup={backup_root}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
