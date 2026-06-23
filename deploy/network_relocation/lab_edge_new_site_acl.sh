#!/usr/bin/env bash
set -euo pipefail

# Update lab-edge-01 routing firewall and DNS ACLs for the new segmented site.
# Safe to run before the move: it adds 192.168.3.0/24 and WireGuard client CIDR
# as allowed operator/client networks without removing the existing 192.168.1.0/24
# or legacy 10.66.66.0/24 access.

SIEM_LAN_CIDRS="${SIEM_LAN_CIDRS:-10.10.10.0/24, 10.66.66.0/24, 192.168.1.0/24, 192.168.3.0/24}"
SIEM_UPSTREAM_DNS="${SIEM_UPSTREAM_DNS:-192.168.1.1}"

require_root() {
  if [ "$(id -u)" != "0" ]; then
    echo "ERROR: run as root on lab-edge-01" >&2
    exit 1
  fi
}

backup_file() {
  local path="$1"
  if [ -f "${path}" ]; then
    cp -a "${path}" "${path}.bak.$(date -u +%Y%m%dT%H%M%SZ)"
  fi
}

write_nftables() {
  backup_file /etc/nftables.conf
  cat >/etc/nftables.conf <<EOF
flush ruleset

table inet filter {
  chain input {
    type filter hook input priority 0;
    policy drop;
    iifname "lo" accept
    ct state established,related accept
    ip protocol icmp accept
    iifname "eth0" ip saddr { ${SIEM_LAN_CIDRS} } tcp dport { 22, 53 } accept
    iifname "eth0" ip saddr { ${SIEM_LAN_CIDRS} } udp dport 53 accept
    iifname "eth1" ip saddr 10.20.30.0/24 tcp dport { 22, 53 } accept
    iifname "eth1" ip saddr 10.20.30.0/24 udp dport 53 accept
    log prefix "nft-input-drop " level notice
    drop
  }

  chain forward {
    type filter hook forward priority 0;
    policy drop;
    ct state established,related accept
    iifname "eth1" oifname "eth0" accept
    iifname "eth3" oifname "eth0" ip saddr 10.20.20.0/24 accept
    iifname "eth0" oifname "eth1" ip saddr { ${SIEM_LAN_CIDRS} } accept
    iifname "eth0" oifname "eth3" ip saddr { ${SIEM_LAN_CIDRS} } accept
    iifname "eth2" oifname "eth1" ip saddr 10.20.10.0/24 accept
    iifname "eth1" oifname "eth2" ip daddr 10.20.10.0/24 accept
    iifname "eth2" oifname "eth3" ip saddr 10.20.10.0/24 ip daddr 10.20.20.0/24 accept
    iifname "eth3" oifname "eth1" ip saddr 10.20.20.0/24 accept
    iifname "eth1" oifname "eth3" ip daddr 10.20.20.0/24 accept
    log prefix "nft-forward-drop " level notice
    drop
  }

  chain output {
    type filter hook output priority 0;
    policy accept;
  }
}

table ip nat {
  chain postrouting {
    type nat hook postrouting priority 100;
    policy accept;
    ip saddr 10.20.30.0/24 oifname "eth0" masquerade
    ip saddr 10.20.20.0/24 oifname "eth0" masquerade
    ip saddr { ${SIEM_LAN_CIDRS} } ip daddr 10.20.30.0/24 oifname "eth1" masquerade
    ip saddr { ${SIEM_LAN_CIDRS} } ip daddr 10.20.20.0/24 oifname "eth3" masquerade
  }
}
EOF
  nft -c -f /etc/nftables.conf
  systemctl enable nftables >/dev/null 2>&1 || true
  systemctl restart nftables
}

write_unbound_acl() {
  local conf="/etc/unbound/unbound.conf.d/lab-home-arpa.conf"
  backup_file "${conf}"
  python3 - "${conf}" "${SIEM_UPSTREAM_DNS}" <<'PY'
from __future__ import annotations

import sys
from pathlib import Path

path = Path(sys.argv[1])
upstream = sys.argv[2]
text = path.read_text(encoding="utf-8")
required = [
    "  access-control: 127.0.0.0/8 allow",
    "  access-control: 192.168.1.0/24 allow",
    "  access-control: 192.168.3.0/24 allow",
    "  access-control: 10.10.10.0/24 allow",
    "  access-control: 10.20.30.0/24 allow",
    "  access-control: 10.66.66.0/24 allow",
]
lines = text.splitlines()
out: list[str] = []
inserted = False
for line in lines:
    if line.strip().startswith("access-control:"):
        if not inserted:
            out.extend(required)
            inserted = True
        continue
    if line.strip().startswith("forward-addr:"):
        out.append(f"  forward-addr: {upstream}")
        continue
    out.append(line)
if not inserted:
    try:
        index = out.index("server:")
    except ValueError:
        index = -1
    out[index + 1:index + 1] = required
path.write_text("\n".join(out) + "\n", encoding="utf-8")
PY
  unbound-checkconf
  systemctl restart unbound
}

show_status() {
  echo "--- nft ACL"
  nft list ruleset | sed -n '1,180p'
  echo "--- unbound ACL"
  grep -R "access-control\\|forward-addr" -n /etc/unbound/unbound.conf.d/lab-home-arpa.conf
  echo "--- routes"
  ip route
}

require_root
case "${1:-apply}" in
  apply)
    write_nftables
    write_unbound_acl
    show_status
    ;;
  status)
    show_status
    ;;
  *)
    echo "Usage: $0 apply|status" >&2
    exit 2
    ;;
esac
