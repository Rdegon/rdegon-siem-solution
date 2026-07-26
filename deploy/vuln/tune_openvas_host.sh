#!/usr/bin/env bash
set -euo pipefail

swap_path="${OPENVAS_SWAP_PATH:-/swapfile}"
swap_size="${OPENVAS_SWAP_SIZE:-4G}"

install -m 0644 /dev/null /etc/sysctl.d/90-openvas-performance.conf
cat > /etc/sysctl.d/90-openvas-performance.conf <<'EOF'
vm.overcommit_memory = 1
vm.swappiness = 10
EOF
sysctl --system >/dev/null

if ! swapon --show=NAME --noheadings | grep -Fxq "$swap_path"; then
  if [[ ! -f "$swap_path" ]]; then
    fallocate -l "$swap_size" "$swap_path"
  fi
  chmod 0600 "$swap_path"
  mkswap "$swap_path" >/dev/null
  swapon "$swap_path"
fi

if ! grep -Eq "^[[:space:]]*${swap_path//\//\\/}[[:space:]]+none[[:space:]]+swap[[:space:]]" /etc/fstab; then
  printf '%s none swap sw 0 0\n' "$swap_path" >> /etc/fstab
fi
