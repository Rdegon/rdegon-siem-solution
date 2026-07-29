#!/usr/bin/env bash
set -uo pipefail

exec 9>/run/lock/siem-cold-start-reconcile.lock
flock -n 9 || exit 0

readonly CORE_GUESTS=(102 103 106 108 105 104 107)
failures=0

log() {
  printf 'siem-cold-start %s\n' "$*"
}

ensure_running() {
  local vmid="$1"
  local status
  status="$(qm status "$vmid" 2>/dev/null | awk '{print $2}')"
  if [[ "$status" != "running" ]]; then
    log "vm=$vmid action=start previous_status=${status:-unknown}"
    qm start "$vmid"
  fi
}

guest_command_ok() {
  local vmid="$1"
  local command="$2"
  local payload
  payload="$(timeout 45 qm guest exec "$vmid" --timeout 35 -- /bin/bash -lc "$command" 2>/dev/null)" || return 1
  printf '%s' "$payload" | python3 -c \
    'import json, sys; payload=json.load(sys.stdin); raise SystemExit(0 if payload.get("exited") == 1 and payload.get("exitcode") == 0 else 1)'
}

wait_guest_agent() {
  local vmid="$1"
  local attempt
  for attempt in $(seq 1 18); do
    if timeout 8 qm agent "$vmid" ping >/dev/null 2>&1; then
      return 0
    fi
    sleep 5
  done
  return 1
}

wait_opnsense() {
  local attempt
  for attempt in $(seq 1 24); do
    if ping -c 1 -W 2 192.168.3.103 >/dev/null 2>&1; then
      return 0
    fi
    sleep 5
  done
  return 1
}

repair_guest() {
  local vmid="$1"
  case "$vmid" in
    104)
      guest_command_ok "$vmid" \
        "systemctl restart siem-ingest nginx"
      ;;
    105)
      guest_command_ok "$vmid" \
        "systemctl restart siem-kafka siem-normalizer siem-normalizer@1 siem-normalizer@2 siem-filter siem-filter@1 siem-filter@2"
      ;;
    106)
      guest_command_ok "$vmid" \
        "systemctl restart clickhouse-server && sleep 8 && systemctl restart siem-writer siem-writer@2 siem-stream-corr siem-batch-corr siem-alert-agg"
      ;;
    107)
      guest_command_ok "$vmid" \
        "systemctl restart siem-vault && sleep 8 && systemctl restart siem-keycloak siem-web nginx"
      ;;
    108)
      guest_command_ok "$vmid" \
        "systemctl restart siem-kafka siem-normalizer@1 siem-normalizer@2 siem-filter@1 siem-filter@2"
      ;;
    *)
      return 1
      ;;
  esac
}

guest_ready() {
  local vmid="$1"
  case "$vmid" in
    102)
      guest_command_ok "$vmid" "systemctl is-system-running --wait >/dev/null || systemctl is-system-running | grep -Eq 'running|degraded'"
      ;;
    104)
      guest_command_ok "$vmid" \
        "systemctl is-active --quiet siem-ingest nginx"
      ;;
    105)
      guest_command_ok "$vmid" \
        "systemctl is-active --quiet siem-kafka siem-normalizer siem-normalizer@1 siem-normalizer@2 siem-filter siem-filter@1 siem-filter@2"
      ;;
    106)
      guest_command_ok "$vmid" \
        "systemctl is-active --quiet clickhouse-server siem-writer siem-writer@2 siem-stream-corr siem-batch-corr siem-alert-agg && clickhouse-client -q 'SELECT 1' | grep -qx 1"
      ;;
    107)
      guest_command_ok "$vmid" \
        "systemctl is-active --quiet siem-vault siem-keycloak siem-web nginx && curl -kfsS --max-time 5 https://127.0.0.1/healthz >/dev/null"
      ;;
    108)
      guest_command_ok "$vmid" \
        "systemctl is-active --quiet siem-kafka siem-normalizer@1 siem-normalizer@2 siem-filter@1 siem-filter@2"
      ;;
    *)
      return 1
      ;;
  esac
}

for vmid in "${CORE_GUESTS[@]}"; do
  if ! ensure_running "$vmid"; then
    log "vm=$vmid result=start_failed"
    failures=$((failures + 1))
    continue
  fi

  if [[ "$vmid" == "103" ]]; then
    if wait_opnsense; then
      log "vm=$vmid result=ready check=icmp"
    else
      log "vm=$vmid result=not_ready check=icmp"
      failures=$((failures + 1))
    fi
    continue
  fi

  if ! wait_guest_agent "$vmid"; then
    log "vm=$vmid result=not_ready check=qemu_guest_agent"
    failures=$((failures + 1))
    continue
  fi

  if guest_ready "$vmid"; then
    log "vm=$vmid result=ready"
    continue
  fi

  log "vm=$vmid action=repair"
  repair_guest "$vmid" || true
  sleep 10
  if guest_ready "$vmid"; then
    log "vm=$vmid result=repaired"
  else
    log "vm=$vmid result=repair_failed"
    failures=$((failures + 1))
  fi
done

if (( failures > 0 )); then
  log "result=degraded failures=$failures"
  exit 1
fi

log "result=healthy"
