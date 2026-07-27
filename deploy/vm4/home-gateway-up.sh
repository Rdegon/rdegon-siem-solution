#!/bin/sh
set -eu

LAN_IFACE="$(ip route show default 0.0.0.0/0 | awk '/default/ {print $5; exit}')"
SEG_IFACE="ens20"
LAN_SUBNETS="192.168.1.0/24 192.168.3.0/24"
SEG_SUBNETS="10.20.10.0/24 10.20.20.0/24 10.20.30.0/24 10.20.40.0/24"

sysctl -w net.ipv4.ip_forward=1
for subnet in $LAN_SUBNETS; do
  iptables -I FORWARD 1 -i "$dev" -o "$LAN_IFACE" -d "$subnet" -j ACCEPT
  iptables -I FORWARD 1 -i "$LAN_IFACE" -o "$dev" -s "$subnet" -m state --state RELATED,ESTABLISHED -j ACCEPT
  iptables -t nat -I POSTROUTING 1 -s 10.66.66.0/24 -d "$subnet" -o "$LAN_IFACE" -j MASQUERADE
done

for subnet in $SEG_SUBNETS; do
  iptables -I FORWARD 1 -i "$dev" -o "$SEG_IFACE" -d "$subnet" -j ACCEPT
  iptables -I FORWARD 1 -i "$SEG_IFACE" -o "$dev" -s "$subnet" -m state --state RELATED,ESTABLISHED -j ACCEPT
  iptables -t nat -I POSTROUTING 1 -s 10.66.66.0/24 -d "$subnet" -o "$SEG_IFACE" -j MASQUERADE
done
