#!/usr/bin/env bash
set -euo pipefail

# Prepare Proxmox for access after moving the host to a segmented site.
#
# Safe default action:
#   install-safe
#     - persists routes from Proxmox to the internal 10.20.* lab zones via lab-edge
#     - persists NAT for WireGuard clients so VMs/LXCs do not need return routes to wg0
#
# Destructive/high-risk action:
#   apply-address --confirm-apply-address
#     - rewrites the vmbr0 address/gateway in /etc/network/interfaces
#     - intended for local console use after the move if the management subnet changes

SIEM_EXTERNAL_BRIDGE="${SIEM_EXTERNAL_BRIDGE:-vmbr0}"
SIEM_LAB_EDGE_IP="${SIEM_LAB_EDGE_IP:-192.168.1.102}"
SIEM_VPN_CIDR="${SIEM_VPN_CIDR:-10.10.10.0/24}"
SIEM_INTERNAL_CIDRS="${SIEM_INTERNAL_CIDRS:-10.20.10.0/24 10.20.20.0/24 10.20.30.0/24}"
SIEM_MGMT_IP="${SIEM_MGMT_IP:-192.168.1.101/24}"
SIEM_MGMT_GW="${SIEM_MGMT_GW:-192.168.1.1}"
SIEM_SECONDARY_IP="${SIEM_SECONDARY_IP:-}"

die() {
  echo "ERROR: $*" >&2
  exit 1
}

require_root() {
  if [ "$(id -u)" != "0" ]; then
    die "run as root on the Proxmox host"
  fi
}

write_env_file() {
  install -d -m 0755 /etc/default
  cat >/etc/default/siem-vpn-access <<EOF
SIEM_EXTERNAL_BRIDGE=${SIEM_EXTERNAL_BRIDGE}
SIEM_LAB_EDGE_IP=${SIEM_LAB_EDGE_IP}
SIEM_VPN_CIDR=${SIEM_VPN_CIDR}
SIEM_INTERNAL_CIDRS="${SIEM_INTERNAL_CIDRS}"
EOF
  chmod 0644 /etc/default/siem-vpn-access
}

write_apply_script() {
  install -d -m 0755 /usr/local/sbin
  cat >/usr/local/sbin/siem-vpn-access-apply <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

if [ -f /etc/default/siem-vpn-access ]; then
  # shellcheck disable=SC1091
  . /etc/default/siem-vpn-access
fi

BRIDGE="${SIEM_EXTERNAL_BRIDGE:-vmbr0}"
LAB_EDGE="${SIEM_LAB_EDGE_IP:-192.168.1.102}"
VPN_CIDR="${SIEM_VPN_CIDR:-10.10.10.0/24}"
INTERNAL_CIDRS="${SIEM_INTERNAL_CIDRS:-10.20.10.0/24 10.20.20.0/24 10.20.30.0/24}"

for cidr in ${INTERNAL_CIDRS}; do
  ip route replace "${cidr}" via "${LAB_EDGE}" dev "${BRIDGE}"
done

nft list table ip siem_vpn_access >/dev/null 2>&1 && nft delete table ip siem_vpn_access || true
nft add table ip siem_vpn_access
nft add chain ip siem_vpn_access postrouting '{ type nat hook postrouting priority srcnat; policy accept; }'
nft add rule ip siem_vpn_access postrouting ip saddr "${VPN_CIDR}" oifname "${BRIDGE}" masquerade
EOF
  chmod 0755 /usr/local/sbin/siem-vpn-access-apply
}

write_systemd_unit() {
  cat >/etc/systemd/system/siem-vpn-access.service <<'EOF'
[Unit]
Description=Rdegon SIEM VPN access routes and NAT
After=network-online.target wg-quick@wg0.service
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
EnvironmentFile=-/etc/default/siem-vpn-access
ExecStart=/usr/local/sbin/siem-vpn-access-apply

[Install]
WantedBy=multi-user.target
EOF
  chmod 0644 /etc/systemd/system/siem-vpn-access.service
}

install_safe() {
  require_root
  write_env_file
  write_apply_script
  write_systemd_unit
  systemctl daemon-reload
  systemctl enable --now siem-vpn-access.service
  /usr/local/sbin/siem-vpn-access-apply
  echo "Installed siem-vpn-access routes/NAT:"
  ip route show | grep -E '10\.20\.(10|20|30)\.0/24' || true
  nft list table ip siem_vpn_access
}

render_interfaces() {
  python3 - "$SIEM_EXTERNAL_BRIDGE" "$SIEM_MGMT_IP" "$SIEM_MGMT_GW" "$SIEM_SECONDARY_IP" <<'PY'
from __future__ import annotations

import sys
from pathlib import Path

bridge, mgmt_ip, gateway, secondary_ip = sys.argv[1:5]
path = Path("/etc/network/interfaces")
text = path.read_text(encoding="utf-8")
lines = text.splitlines()
out: list[str] = []
i = 0
while i < len(lines):
    line = lines[i]
    if line.strip() == f"iface {bridge} inet static":
        out.append(line)
        i += 1
        while i < len(lines) and (lines[i].startswith("\t") or lines[i].startswith(" ") or lines[i].strip() == ""):
            current = lines[i]
            stripped = current.strip()
            if stripped.startswith("address "):
                out.append(f"\taddress {mgmt_ip}")
            elif stripped.startswith("gateway "):
                out.append(f"\tgateway {gateway}")
            elif "siem-secondary-management-ip" in stripped:
                pass
            else:
                out.append(current)
            i += 1
        if secondary_ip:
            out.append(f"\tpost-up ip address replace {secondary_ip} dev {bridge} label {bridge}:siem2 || true")
            out.append(f"\tpost-down ip address del {secondary_ip} dev {bridge} label {bridge}:siem2 2>/dev/null || true")
        continue
    out.append(line)
    i += 1
print("\n".join(out) + "\n")
PY
}

apply_address() {
  require_root
  if [ "${1:-}" != "--confirm-apply-address" ]; then
    die "refusing to rewrite /etc/network/interfaces without --confirm-apply-address"
  fi
  local backup="/etc/network/interfaces.bak.$(date -u +%Y%m%dT%H%M%SZ)"
  cp -a /etc/network/interfaces "${backup}"
  render_interfaces >/tmp/siem-network-interfaces.new
  if command -v ifquery >/dev/null 2>&1; then
    ifquery --check "${SIEM_EXTERNAL_BRIDGE}" >/dev/null 2>&1 || true
  fi
  install -m 0644 /tmp/siem-network-interfaces.new /etc/network/interfaces
  echo "Wrote /etc/network/interfaces; backup: ${backup}"
  echo "Review locally, then run one of:"
  echo "  ifreload -a"
  echo "  systemctl restart networking"
}

show_status() {
  echo "--- addresses"
  ip -br addr show "${SIEM_EXTERNAL_BRIDGE}" || true
  ip -br addr show wg0 || true
  echo "--- routes"
  ip route show
  echo "--- siem VPN NAT"
  nft list table ip siem_vpn_access 2>/dev/null || true
  echo "--- systemd"
  systemctl --no-pager --plain status siem-vpn-access.service 2>/dev/null || true
}

usage() {
  cat <<EOF
Usage: $0 install-safe|apply-address|status [--confirm-apply-address]

Environment:
  SIEM_EXTERNAL_BRIDGE=${SIEM_EXTERNAL_BRIDGE}
  SIEM_LAB_EDGE_IP=${SIEM_LAB_EDGE_IP}
  SIEM_VPN_CIDR=${SIEM_VPN_CIDR}
  SIEM_INTERNAL_CIDRS="${SIEM_INTERNAL_CIDRS}"
  SIEM_MGMT_IP=${SIEM_MGMT_IP}
  SIEM_MGMT_GW=${SIEM_MGMT_GW}
  SIEM_SECONDARY_IP=${SIEM_SECONDARY_IP}
EOF
}

case "${1:-}" in
  install-safe)
    install_safe
    ;;
  apply-address)
    shift
    apply_address "${1:-}"
    ;;
  status)
    show_status
    ;;
  *)
    usage
    exit 2
    ;;
esac
