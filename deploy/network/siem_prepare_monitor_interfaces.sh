#!/usr/bin/env bash
set -euo pipefail

for interface in enp6s19 enp6s20 enp6s21 enp6s22 enp6s23; do
  [[ -e "/sys/class/net/$interface" ]] || continue
  ip link set dev "$interface" up
  ip link set dev "$interface" promisc on
  ip address flush dev "$interface"
  ip -6 address flush dev "$interface" || true
done
