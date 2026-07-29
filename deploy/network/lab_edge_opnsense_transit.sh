#!/usr/bin/env bash
set -euo pipefail

# Keep VM102 as the published-service/VPN edge while OPNsense VM103 owns
# routing, policy enforcement and inline IPS for every internal zone.

backup_file() {
  local path="$1"
  if [ -f "${path}" ]; then
    cp -a "${path}" "${path}.pre-opnsense.$(date -u +%Y%m%dT%H%M%SZ)"
  fi
}

write_netplan() {
  backup_file /etc/netplan/50-cloud-init.yaml
  cat >/etc/netplan/50-cloud-init.yaml <<'EOF'
network:
  version: 2
  renderer: networkd
  ethernets:
    eth0:
      match:
        macaddress: "bc:24:11:f1:29:94"
      set-name: eth0
      addresses: [192.168.3.102/24]
      routes:
        - {to: default, via: 192.168.3.1}
        - {to: 10.20.10.0/24, via: 192.168.3.103}
        - {to: 10.20.20.0/24, via: 192.168.3.103}
        - {to: 10.20.30.0/24, via: 192.168.3.103}
        - {to: 10.20.40.0/24, via: 192.168.3.103}
      nameservers:
        addresses: [192.168.3.1, 1.1.1.1]
        search: [lab.home.arpa]
    eth1:
      match:
        macaddress: "bc:24:11:0b:3d:5b"
      set-name: eth1
      dhcp4: false
      dhcp6: false
      link-local: []
      optional: true
    eth2:
      match:
        macaddress: "bc:24:11:ec:17:13"
      set-name: eth2
      dhcp4: false
      dhcp6: false
      link-local: []
      optional: true
    eth3:
      match:
        macaddress: "bc:24:11:bd:29:b9"
      set-name: eth3
      dhcp4: false
      dhcp6: false
      link-local: []
      optional: true
    eth4:
      match:
        macaddress: "bc:24:11:66:a6:a4"
      set-name: eth4
      dhcp4: false
      dhcp6: false
      link-local: []
      optional: true
EOF
  chmod 0600 /etc/netplan/50-cloud-init.yaml
  netplan generate
  netplan apply || true
}

write_nftables() {
  backup_file /etc/nftables.conf
  cat >/etc/nftables.conf <<'EOF'
flush ruleset

table inet filter {
  chain input {
    type filter hook input priority filter;
    policy drop;
    iifname "lo" accept
    ct state established,related accept
    ip protocol icmp accept
    iifname "eth0" ip saddr { 10.10.10.0/24, 10.66.66.0/24, 192.168.3.0/24 } tcp dport { 22, 53 } accept
    iifname "eth0" ip saddr { 10.10.10.0/24, 10.66.66.0/24, 192.168.3.0/24 } udp dport 53 accept
    log prefix "nft-input-drop " level notice
    drop
  }

  chain forward {
    type filter hook forward priority filter;
    policy drop;
    ct state established,related accept
    iifname "eth0" oifname "eth0" ct status dnat ip daddr 10.20.0.0/16 accept
    log prefix "nft-forward-drop " level notice
    drop
  }

  chain output {
    type filter hook output priority filter;
    policy accept;
  }
}

table ip nat {
  chain prerouting {
    type nat hook prerouting priority dstnat;
    policy accept;
    iifname "eth0" ip daddr 192.168.3.102 tcp dport 80 dnat to 10.20.10.107:80
    iifname "eth0" ip daddr 192.168.3.102 tcp dport 443 dnat to 10.20.10.107:443
    iifname "eth0" ip daddr 192.168.3.102 tcp dport 8443 dnat to 10.20.10.104:443
    iifname "eth0" ip daddr 192.168.3.102 tcp dport 8000 dnat to 10.20.10.128:8000
    iifname "eth0" ip daddr 192.168.3.102 tcp dport 8005 dnat to 10.20.10.127:8005
    iifname "eth0" ip daddr 192.168.3.102 tcp dport 8444 dnat to 10.20.10.107:8444
    iifname "eth0" ip daddr 192.168.3.102 tcp dport 8889 dnat to 10.20.10.107:8889
    iifname "eth0" ip daddr 192.168.3.102 tcp dport 9001 dnat to 10.20.10.107:9001
    iifname "eth0" ip daddr 192.168.3.102 tcp dport 9392 dnat to 10.20.30.122:9392
    iifname "eth0" ip daddr 192.168.3.102 tcp dport 1514-1518 dnat to 10.20.10.104
    iifname "eth0" ip daddr 192.168.3.102 udp dport 1514-1518 dnat to 10.20.10.104
    iifname "eth0" ip daddr 192.168.3.102 tcp dport 9443 dnat to 10.20.20.120:443
    iifname "eth0" ip daddr 192.168.3.102 tcp dport 9444 dnat to 10.20.20.121:80
    iifname "eth0" ip daddr 192.168.3.102 tcp dport 9445 dnat to 10.20.20.130:80
    iifname "eth0" ip daddr 192.168.3.102 tcp dport 2022 dnat to 10.20.20.130:2022
    iifname "eth0" ip daddr 192.168.3.102 tcp dport 8080 dnat to 10.20.20.130:8080
    iifname "eth0" ip daddr 192.168.3.102 tcp dport 25565 dnat to 10.20.20.100:25565
    iifname "eth0" ip daddr 192.168.3.102 udp dport 25565 dnat to 10.20.20.100:25565
    iifname "eth0" ip daddr 192.168.3.102 tcp dport 8100 dnat to 10.20.20.100:8100
    iifname "eth0" ip daddr 192.168.3.102 tcp dport 8111 dnat to 10.20.20.100:8111
  }

  chain postrouting {
    type nat hook postrouting priority srcnat;
    policy accept;
    ct status dnat oifname "eth0" ip daddr 10.20.0.0/16 snat to 192.168.3.102
  }
}
EOF
  nft -c -f /etc/nftables.conf
  systemctl enable nftables >/dev/null 2>&1 || true
  systemctl restart nftables
}

verify() {
  for net in 10.20.10.0/24 10.20.20.0/24 10.20.30.0/24 10.20.40.0/24; do
    ip route show "${net}" | grep 'via 192.168.3.103'
  done
  for dev in eth1 eth2 eth3 eth4; do
    if ip -4 -o address show dev "${dev}" | grep -q .; then
      echo "unexpected IPv4 address on ${dev}" >&2
      exit 1
    fi
  done
  curl -kfsS --connect-timeout 5 --max-time 15 https://10.20.10.104/health >/dev/null
  curl -kfsS --connect-timeout 5 --max-time 15 https://10.20.10.107/ >/dev/null
  for endpoint in \
    10.20.10.127:8005 \
    10.20.10.128:8889 \
    10.20.10.131:443 \
    10.20.10.133:9001 \
    10.20.30.122:9392; do
    timeout 5 bash -c "</dev/tcp/${endpoint/:/\/}" >/dev/null 2>&1
  done
  systemctl is-active --quiet nftables
  systemctl is-active --quiet suricata
}

case "${1:-apply}" in
  apply)
    write_netplan
    write_nftables
    verify
    ;;
  verify)
    verify
    ;;
  *)
    echo "Usage: $0 apply|verify" >&2
    exit 2
    ;;
esac
