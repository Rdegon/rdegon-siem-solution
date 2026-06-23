#!/usr/bin/env bash
set -euo pipefail

# Prepare Proxmox for access after moving the host to a segmented site.
#
# Safe actions:
#   install-safe
#     - persists Proxmox routes to the internal 10.20.* lab zones via lab-edge
#     - persists NAT for WireGuard clients so VMs/LXCs do not need wg0 return routes
#   stage-site3
#     - installs, but does not activate, the 192.168.3.0/24 relocation helper
#
# Cutover actions, intended for local Proxmox console after physical relocation:
#   apply-site3 --confirm-site3-cutover
#     - changes Proxmox vmbr0 management to 192.168.3.101/24 by default
#     - keeps 192.168.1.1/24 and 192.168.1.101/24 as legacy guest/service aliases
#     - enables NAT/port-forward helpers for old 192.168.1.x services
#   apply-address --confirm-apply-address
#     - lower-level address rewrite helper

SIEM_EXTERNAL_BRIDGE="${SIEM_EXTERNAL_BRIDGE:-vmbr0}"
SIEM_LAB_EDGE_IP="${SIEM_LAB_EDGE_IP:-192.168.1.102}"
SIEM_VPN_CIDR="${SIEM_VPN_CIDR:-10.10.10.0/24}"
SIEM_INTERNAL_CIDRS="${SIEM_INTERNAL_CIDRS:-10.20.10.0/24 10.20.20.0/24 10.20.30.0/24}"

SIEM_MGMT_IP="${SIEM_MGMT_IP:-192.168.1.101/24}"
SIEM_MGMT_GW="${SIEM_MGMT_GW:-192.168.1.1}"
SIEM_SECONDARY_IP="${SIEM_SECONDARY_IP:-}"
SIEM_SECONDARY_IPS="${SIEM_SECONDARY_IPS:-${SIEM_SECONDARY_IP}}"

SIEM_SITE3_MGMT_IP="${SIEM_SITE3_MGMT_IP:-192.168.3.101/24}"
SIEM_SITE3_GW="${SIEM_SITE3_GW:-192.168.3.1}"
SIEM_SITE3_LAN_CIDR="${SIEM_SITE3_LAN_CIDR:-192.168.3.0/24}"
SIEM_LEGACY_GUEST_CIDR="${SIEM_LEGACY_GUEST_CIDR:-192.168.1.0/24}"
SIEM_LEGACY_GATEWAY_IP="${SIEM_LEGACY_GATEWAY_IP:-192.168.1.1/24}"
SIEM_LEGACY_PROXMOX_IP="${SIEM_LEGACY_PROXMOX_IP:-192.168.1.101/24}"

SIEM_WEB_IP="${SIEM_WEB_IP:-192.168.1.39}"
SIEM_INGEST_IP="${SIEM_INGEST_IP:-192.168.1.35}"
SIEM_MINECRAFT_IP="${SIEM_MINECRAFT_IP:-192.168.1.32}"
SIEM_GAMEPANEL_IP="${SIEM_GAMEPANEL_IP:-192.168.1.30}"
SIEM_NEXTCLOUD_IP="${SIEM_NEXTCLOUD_IP:-10.20.20.120}"
SIEM_NAVIDROME_IP="${SIEM_NAVIDROME_IP:-10.20.20.121}"

die() {
  echo "ERROR: $*" >&2
  exit 1
}

require_root() {
  if [ "$(id -u)" != "0" ]; then
    die "run as root on the Proxmox host"
  fi
}

write_vpn_env_file() {
  install -d -m 0755 /etc/default
  cat >/etc/default/siem-vpn-access <<EOF
SIEM_EXTERNAL_BRIDGE=${SIEM_EXTERNAL_BRIDGE}
SIEM_LAB_EDGE_IP=${SIEM_LAB_EDGE_IP}
SIEM_VPN_CIDR=${SIEM_VPN_CIDR}
SIEM_INTERNAL_CIDRS="${SIEM_INTERNAL_CIDRS}"
EOF
  chmod 0644 /etc/default/siem-vpn-access
}

write_vpn_apply_script() {
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

write_vpn_systemd_unit() {
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
  write_vpn_env_file
  write_vpn_apply_script
  write_vpn_systemd_unit
  systemctl daemon-reload
  systemctl enable --now siem-vpn-access.service
  /usr/local/sbin/siem-vpn-access-apply
  echo "Installed siem-vpn-access routes/NAT:"
  ip route show | grep -E '10\.20\.(10|20|30)\.0/24' || true
  nft list table ip siem_vpn_access
}

write_site3_env_file() {
  install -d -m 0755 /etc/default
  cat >/etc/default/siem-site3-edge <<EOF
SIEM_EXTERNAL_BRIDGE=${SIEM_EXTERNAL_BRIDGE}
SIEM_SITE3_MGMT_IP=${SIEM_SITE3_MGMT_IP}
SIEM_SITE3_LAN_CIDR=${SIEM_SITE3_LAN_CIDR}
SIEM_LEGACY_GUEST_CIDR=${SIEM_LEGACY_GUEST_CIDR}
SIEM_LEGACY_GATEWAY_IP=${SIEM_LEGACY_GATEWAY_IP}
SIEM_LEGACY_PROXMOX_IP=${SIEM_LEGACY_PROXMOX_IP}
SIEM_LAB_EDGE_IP=${SIEM_LAB_EDGE_IP}
SIEM_VPN_CIDR=${SIEM_VPN_CIDR}
SIEM_INTERNAL_CIDRS="${SIEM_INTERNAL_CIDRS}"
SIEM_WEB_IP=${SIEM_WEB_IP}
SIEM_INGEST_IP=${SIEM_INGEST_IP}
SIEM_MINECRAFT_IP=${SIEM_MINECRAFT_IP}
SIEM_GAMEPANEL_IP=${SIEM_GAMEPANEL_IP}
SIEM_NEXTCLOUD_IP=${SIEM_NEXTCLOUD_IP}
SIEM_NAVIDROME_IP=${SIEM_NAVIDROME_IP}
EOF
  chmod 0644 /etc/default/siem-site3-edge
}

write_site3_apply_script() {
  install -d -m 0755 /usr/local/sbin
  cat >/usr/local/sbin/siem-site3-edge-apply <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

if [ -f /etc/default/siem-site3-edge ]; then
  # shellcheck disable=SC1091
  . /etc/default/siem-site3-edge
fi

BRIDGE="${SIEM_EXTERNAL_BRIDGE:-vmbr0}"
SITE3_ADDR="${SIEM_SITE3_MGMT_IP%%/*}"
SITE3_CIDR="${SIEM_SITE3_LAN_CIDR:-192.168.3.0/24}"
LEGACY_CIDR="${SIEM_LEGACY_GUEST_CIDR:-192.168.1.0/24}"
LEGACY_GW="${SIEM_LEGACY_GATEWAY_IP:-192.168.1.1/24}"
LEGACY_PVE="${SIEM_LEGACY_PROXMOX_IP:-192.168.1.101/24}"
LAB_EDGE="${SIEM_LAB_EDGE_IP:-192.168.1.102}"
VPN_CIDR="${SIEM_VPN_CIDR:-10.10.10.0/24}"
INTERNAL_CIDRS="${SIEM_INTERNAL_CIDRS:-10.20.10.0/24 10.20.20.0/24 10.20.30.0/24}"

WEB_IP="${SIEM_WEB_IP:-192.168.1.39}"
INGEST_IP="${SIEM_INGEST_IP:-192.168.1.35}"
MINECRAFT_IP="${SIEM_MINECRAFT_IP:-192.168.1.32}"
GAMEPANEL_IP="${SIEM_GAMEPANEL_IP:-192.168.1.30}"
NEXTCLOUD_IP="${SIEM_NEXTCLOUD_IP:-10.20.20.120}"
NAVIDROME_IP="${SIEM_NAVIDROME_IP:-10.20.20.121}"

sysctl -w net.ipv4.ip_forward=1 >/dev/null
ip address replace "${LEGACY_GW}" dev "${BRIDGE}" label "${BRIDGE}:gw"
ip address replace "${LEGACY_PVE}" dev "${BRIDGE}" label "${BRIDGE}:pveold"

for cidr in ${INTERNAL_CIDRS}; do
  ip route replace "${cidr}" via "${LAB_EDGE}" dev "${BRIDGE}"
done

NFT_RULESET="/run/siem-site3-edge.nft"
cat >"${NFT_RULESET}" <<EOF_NFT
table ip siem_site3_edge {
  chain prerouting {
    type nat hook prerouting priority dstnat; policy accept;
    iifname "${BRIDGE}" ip daddr ${SITE3_ADDR} tcp dport 80 dnat to ${WEB_IP}:80
    iifname "${BRIDGE}" ip daddr ${SITE3_ADDR} tcp dport 443 dnat to ${WEB_IP}:443
    iifname "${BRIDGE}" ip daddr ${SITE3_ADDR} tcp dport 8443 dnat to ${INGEST_IP}:8443
    iifname "${BRIDGE}" ip daddr ${SITE3_ADDR} tcp dport { 1514, 1515, 1516, 1517, 1518 } dnat to ${INGEST_IP}
    iifname "${BRIDGE}" ip daddr ${SITE3_ADDR} udp dport { 1514, 1515, 1516, 1517, 1518 } dnat to ${INGEST_IP}
    iifname "${BRIDGE}" ip daddr ${SITE3_ADDR} tcp dport 25565 dnat to ${MINECRAFT_IP}:25565
    iifname "${BRIDGE}" ip daddr ${SITE3_ADDR} tcp dport 8100 dnat to ${MINECRAFT_IP}:8100
    iifname "${BRIDGE}" ip daddr ${SITE3_ADDR} tcp dport 9443 dnat to ${NEXTCLOUD_IP}:443
    iifname "${BRIDGE}" ip daddr ${SITE3_ADDR} tcp dport 9444 dnat to ${NAVIDROME_IP}:443
    iifname "${BRIDGE}" ip daddr ${SITE3_ADDR} tcp dport 9445 dnat to ${GAMEPANEL_IP}:443
  }

  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    ip saddr { ${LEGACY_CIDR}, ${VPN_CIDR} } oifname "${BRIDGE}" masquerade
    ip saddr ${SITE3_CIDR} ip daddr { ${LEGACY_CIDR}, 10.20.10.0/24, 10.20.20.0/24, 10.20.30.0/24 } oifname "${BRIDGE}" masquerade
    ip saddr { 10.20.10.0/24, 10.20.20.0/24, 10.20.30.0/24 } oifname "${BRIDGE}" masquerade
  }
}
EOF_NFT

nft -c -f "${NFT_RULESET}"
nft list table ip siem_site3_edge >/dev/null 2>&1 && nft delete table ip siem_site3_edge || true
nft -f "${NFT_RULESET}"
EOF
  chmod 0755 /usr/local/sbin/siem-site3-edge-apply
}

write_site3_systemd_unit() {
  cat >/etc/systemd/system/siem-site3-edge.service <<'EOF'
[Unit]
Description=Rdegon SIEM 192.168.3 relocation edge NAT and routes
After=network-online.target siem-vpn-access.service
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
EnvironmentFile=-/etc/default/siem-site3-edge
ExecStart=/usr/local/sbin/siem-site3-edge-apply

[Install]
WantedBy=multi-user.target
EOF
  chmod 0644 /etc/systemd/system/siem-site3-edge.service
}

stage_site3() {
  require_root
  write_site3_env_file
  write_site3_apply_script
  write_site3_systemd_unit
  systemctl daemon-reload
  echo "Staged siem-site3-edge. It is installed but not started."
  echo "After moving to 192.168.3.0/24, run apply-site3 from local console."
}

render_interfaces() {
  python3 - "$SIEM_EXTERNAL_BRIDGE" "$SIEM_MGMT_IP" "$SIEM_MGMT_GW" "$SIEM_SECONDARY_IPS" <<'PY'
from __future__ import annotations

import re
import sys
from pathlib import Path

bridge, mgmt_ip, gateway, secondary_ips_raw = sys.argv[1:5]
secondary_ips = [item for item in re.split(r"[\s,]+", secondary_ips_raw.strip()) if item]
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
            elif "siem-secondary-ip-" in stripped:
                pass
            else:
                out.append(current)
            i += 1
        for index, secondary_ip in enumerate(secondary_ips, start=1):
            label = "gw" if secondary_ip.startswith("192.168.1.1/") else f"s{index}"
            out.append(f"\tpost-up ip address replace {secondary_ip} dev {bridge} label {bridge}:siem-{label} || true")
            out.append(f"\tpost-down ip address del {secondary_ip} dev {bridge} label {bridge}:siem-{label} 2>/dev/null || true")
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
  install -m 0644 /tmp/siem-network-interfaces.new /etc/network/interfaces
  echo "Wrote /etc/network/interfaces; backup: ${backup}"
  echo "Review locally, then run:"
  echo "  ifreload -a"
}

apply_site3() {
  require_root
  if [ "${1:-}" != "--confirm-site3-cutover" ]; then
    die "refusing site3 cutover without --confirm-site3-cutover"
  fi
  stage_site3
  SIEM_MGMT_IP="${SIEM_SITE3_MGMT_IP}"
  SIEM_MGMT_GW="${SIEM_SITE3_GW}"
  SIEM_SECONDARY_IPS="${SIEM_LEGACY_GATEWAY_IP} ${SIEM_LEGACY_PROXMOX_IP}"
  apply_address "--confirm-apply-address"
  systemctl enable siem-site3-edge.service >/dev/null
  echo "Site3 cutover files are ready."
  echo "From local console after the move, run:"
  echo "  ifreload -a"
  echo "  systemctl restart siem-site3-edge.service"
  echo "  /usr/local/sbin/siem-post-move-network status"
}

show_status() {
  echo "--- addresses"
  ip -br addr show "${SIEM_EXTERNAL_BRIDGE}" || true
  ip -br addr show wg0 || true
  echo "--- routes"
  ip route show
  echo "--- siem VPN NAT"
  nft list table ip siem_vpn_access 2>/dev/null || true
  echo "--- siem site3 edge"
  nft list table ip siem_site3_edge 2>/dev/null || true
  echo "--- systemd"
  systemctl --no-pager --plain status siem-vpn-access.service 2>/dev/null || true
  systemctl --no-pager --plain status siem-site3-edge.service 2>/dev/null || true
}

usage() {
  cat <<EOF
Usage: $0 install-safe|stage-site3|apply-site3|apply-address|status [confirmation]

Confirmations:
  apply-site3 --confirm-site3-cutover
  apply-address --confirm-apply-address

Environment:
  SIEM_EXTERNAL_BRIDGE=${SIEM_EXTERNAL_BRIDGE}
  SIEM_SITE3_MGMT_IP=${SIEM_SITE3_MGMT_IP}
  SIEM_SITE3_GW=${SIEM_SITE3_GW}
  SIEM_SITE3_LAN_CIDR=${SIEM_SITE3_LAN_CIDR}
  SIEM_LEGACY_GATEWAY_IP=${SIEM_LEGACY_GATEWAY_IP}
  SIEM_LEGACY_PROXMOX_IP=${SIEM_LEGACY_PROXMOX_IP}
  SIEM_LEGACY_GUEST_CIDR=${SIEM_LEGACY_GUEST_CIDR}
  SIEM_LAB_EDGE_IP=${SIEM_LAB_EDGE_IP}
  SIEM_VPN_CIDR=${SIEM_VPN_CIDR}
  SIEM_INTERNAL_CIDRS="${SIEM_INTERNAL_CIDRS}"
EOF
}

case "${1:-}" in
  install-safe)
    install_safe
    ;;
  stage-site3)
    stage_site3
    ;;
  apply-site3)
    shift
    apply_site3 "${1:-}"
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
