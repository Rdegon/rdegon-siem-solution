#!/usr/bin/env bash
set -euo pipefail

readonly PREF=49127
declare -Ar TARGETS=(
  [vmbr0]=tap127i1
  [vmbr2]=tap127i2
  [vmbr3]=tap127i3
  [vmbr1]=tap127i4
  [vmbr4]=tap127i5
)

for bridge in "${!TARGETS[@]}"; do
  target="${TARGETS[$bridge]}"
  [[ -d "/sys/class/net/$bridge/brif" && -e "/sys/class/net/$target" ]] || continue
  ip link set "$target" up
  for source_path in "/sys/class/net/$bridge/brif/"*; do
    [[ -e "$source_path" ]] || continue
    source="${source_path##*/}"
    [[ "$source" == tap127i* ]] && continue
    tc qdisc add dev "$source" clsact 2>/dev/null || true
    tc filter del dev "$source" ingress pref "$PREF" 2>/dev/null || true
    tc filter add dev "$source" ingress pref "$PREF" protocol all \
      matchall action mirred egress mirror dev "$target"
  done
done
