#!/usr/bin/env bash
set -euo pipefail

jump_host="${SIEM_JUMP_TUNNEL_HOST:-10.66.66.1}"
jump_user="${SIEM_JUMP_TUNNEL_USER:-vpnadmin_rdegon}"
ssh_key="${SIEM_JUMP_TUNNEL_KEY:-/home/rdegon/.ssh/jump_vm4_tunnel}"
check_interval="${SIEM_JUMP_TUNNEL_CHECK_INTERVAL_SECONDS:-10}"
connect_timeout="${SIEM_JUMP_TUNNEL_CONNECT_TIMEOUT_SECONDS:-10}"
server_alive_interval="${SIEM_JUMP_TUNNEL_SERVER_ALIVE_INTERVAL_SECONDS:-30}"
server_alive_count="${SIEM_JUMP_TUNNEL_SERVER_ALIVE_COUNT_MAX:-3}"

remote_forwards=(
  "127.0.0.1:10035:192.168.1.35:22"
  "127.0.0.1:10037:192.168.1.37:22"
  "127.0.0.1:10038:192.168.1.38:22"
  "127.0.0.1:10039:192.168.1.39:22"
  "127.0.0.1:10435:192.168.1.35:443"
  "127.0.0.1:10439:192.168.1.39:443"
  "127.0.0.1:5514:192.168.1.35:1514"
  "127.0.0.1:5517:192.168.1.35:1517"
  "127.0.0.1:22102:192.168.1.102:22"
  "127.0.0.1:22104:192.168.1.35:22"
  "127.0.0.1:22105:192.168.1.37:22"
  "127.0.0.1:22106:192.168.1.38:22"
  "127.0.0.1:22107:127.0.0.1:22"
  "127.0.0.1:22108:192.168.1.40:22"
  "127.0.0.1:22120:10.20.20.120:22"
  "127.0.0.1:22121:10.20.20.121:22"
  "127.0.0.1:22122:10.20.30.122:22"
  "127.0.0.1:22123:10.20.30.123:22"
  "127.0.0.1:22124:10.20.30.124:22"
  "127.0.0.1:22125:10.20.30.125:22"
  "127.0.0.1:22126:10.20.30.126:22"
)

wait_for_jump_host() {
  while ! timeout "${connect_timeout}" bash -lc "exec 3<>/dev/tcp/${jump_host}/22" >/dev/null 2>&1; do
    sleep "${check_interval}"
  done
}

while true; do
  wait_for_jump_host
  ssh_args=(
    -NT
    -i "${ssh_key}"
    -o BatchMode=yes
    -o ExitOnForwardFailure=yes
    -o ConnectTimeout="${connect_timeout}"
    -o ConnectionAttempts=1
    -o ServerAliveInterval="${server_alive_interval}"
    -o ServerAliveCountMax="${server_alive_count}"
    -o StrictHostKeyChecking=accept-new
  )
  for forward in "${remote_forwards[@]}"; do
    ssh_args+=(-R "${forward}")
  done
  if /usr/bin/ssh "${ssh_args[@]}" "${jump_user}@${jump_host}"; then
    sleep "${check_interval}"
    continue
  fi
  sleep "${check_interval}"
done
