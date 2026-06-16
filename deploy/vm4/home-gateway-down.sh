#!/bin/sh
set -eu

LAN_IFACE="$(ip route show default 0.0.0.0/0 | awk '/default/ {print $5; exit}')"
SEG_IFACE="ens20"
SEG_SUBNETS="10.20.10.0/24 10.20.20.0/24 10.20.30.0/24"

iptables -D FORWARD -i "$dev" -o "$LAN_IFACE" -d 192.168.1.0/24 -j ACCEPT || true
iptables -D FORWARD -i "$LAN_IFACE" -o "$dev" -s 192.168.1.0/24 -m state --state RELATED,ESTABLISHED -j ACCEPT || true
iptables -t nat -D POSTROUTING -s 10.66.66.0/24 -d 192.168.1.0/24 -o "$LAN_IFACE" -j MASQUERADE || true

for subnet in $SEG_SUBNETS; do
  iptables -D FORWARD -i "$dev" -o "$SEG_IFACE" -d "$subnet" -j ACCEPT || true
  iptables -D FORWARD -i "$SEG_IFACE" -o "$dev" -s "$subnet" -m state --state RELATED,ESTABLISHED -j ACCEPT || true
  iptables -t nat -D POSTROUTING -s 10.66.66.0/24 -d "$subnet" -o "$SEG_IFACE" -j MASQUERADE || true
done
