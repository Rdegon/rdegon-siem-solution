#!/usr/bin/env bash
set -uo pipefail

exec 9>/run/lock/siem-cold-start-reconcile.lock
flock -n 9 || exit 0

readonly CORE_QEMU_GUESTS=(102 103 106 108 105 104 107)
readonly PLATFORM_QEMU_GUESTS=(122 123 124 125 127 130 131)
readonly PLATFORM_LXC_GUESTS=(100 120 121 128 129 132 133)
readonly START_ONLY_QEMU_GUESTS=(109 111)
failures=0

log() {
  printf 'siem-cold-start %s\n' "$*"
}

guest_status() {
  local guest_type="$1"
  local vmid="$2"
  if [[ "$guest_type" == "lxc" ]]; then
    pct status "$vmid" 2>/dev/null | awk '{print $2}'
  else
    qm status "$vmid" 2>/dev/null | awk '{print $2}'
  fi
}

ensure_running() {
  local guest_type="$1"
  local vmid="$2"
  local status
  status="$(guest_status "$guest_type" "$vmid")"
  if [[ "$status" == "running" ]]; then
    return 0
  fi
  log "guest_type=$guest_type vm=$vmid action=start previous_status=${status:-unknown}"
  if [[ "$guest_type" == "lxc" ]]; then
    pct start "$vmid"
  else
    qm start "$vmid"
  fi
}

guest_command_ok() {
  local guest_type="$1"
  local vmid="$2"
  local command="$3"
  if [[ "$guest_type" == "lxc" ]]; then
    timeout 50 pct exec "$vmid" -- bash -lc "$command" >/dev/null 2>&1
    return
  fi
  local payload
  payload="$(timeout 50 qm guest exec "$vmid" --timeout 40 -- /bin/bash -lc "$command" 2>/dev/null)" || return 1
  printf '%s' "$payload" | python3 -c \
    'import json, sys; payload=json.load(sys.stdin); raise SystemExit(0 if payload.get("exited") == 1 and payload.get("exitcode") == 0 else 1)'
}

wait_guest_runtime() {
  local guest_type="$1"
  local vmid="$2"
  local attempt
  for attempt in $(seq 1 18); do
    if [[ "$guest_type" == "lxc" ]]; then
      if [[ "$(guest_status "$guest_type" "$vmid")" == "running" ]] \
        && timeout 8 pct exec "$vmid" -- true >/dev/null 2>&1; then
        return 0
      fi
    elif timeout 8 qm agent "$vmid" ping >/dev/null 2>&1; then
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

guest_ready() {
  local guest_type="$1"
  local vmid="$2"
  case "$vmid" in
    100)
      guest_command_ok "$guest_type" "$vmid" \
        "systemctl is-active --quiet minecraft minecraft-admin-console rsyslog siem-host-runtime-agent.timer"
      ;;
    102)
      guest_command_ok "$guest_type" "$vmid" \
        "systemctl is-system-running --wait >/dev/null || systemctl is-system-running | grep -Eq 'running|degraded'"
      ;;
    104)
      guest_command_ok "$guest_type" "$vmid" \
        "systemctl is-active --quiet siem-ingest nginx"
      ;;
    105)
      guest_command_ok "$guest_type" "$vmid" \
        "systemctl is-active --quiet siem-kafka siem-normalizer siem-normalizer@1 siem-normalizer@2 siem-filter siem-filter@1 siem-filter@2"
      ;;
    106)
      guest_command_ok "$guest_type" "$vmid" \
        "systemctl is-active --quiet clickhouse-server siem-writer siem-writer@2 siem-stream-corr siem-batch-corr siem-alert-agg && clickhouse-client -q 'SELECT 1' | grep -qx 1"
      ;;
    107)
      guest_command_ok "$guest_type" "$vmid" \
        "systemctl is-active --quiet siem-vault siem-keycloak siem-web nginx && curl -kfsS --max-time 5 https://127.0.0.1/healthz >/dev/null"
      ;;
    108)
      guest_command_ok "$guest_type" "$vmid" \
        "systemctl is-active --quiet siem-kafka siem-normalizer@1 siem-normalizer@2 siem-filter@1 siem-filter@2"
      ;;
    120)
      guest_command_ok "$guest_type" "$vmid" \
        "systemctl is-active --quiet siem-host-runtime-agent.timer apache2 mariadb redis-server cron rsyslog && curl -kfsS --max-time 8 https://127.0.0.1/status.php | grep -q 'installed'"
      ;;
    121)
      guest_command_ok "$guest_type" "$vmid" \
        "systemctl is-active --quiet siem-host-runtime-agent.timer navidrome rsyslog && curl -fsS --max-time 8 -o /dev/null http://127.0.0.1:4533/"
      ;;
    122)
      guest_command_ok "$guest_type" "$vmid" \
        "systemctl is-active --quiet siem-host-runtime-agent.timer docker auditd rsyslog && docker ps --format '{{.Names}}' | grep -qx openvas"
      ;;
    123)
      guest_command_ok "$guest_type" "$vmid" \
        "systemctl is-active --quiet siem-host-runtime-agent.timer docker pilot-gitea auditd rsyslog && curl -fsS --max-time 8 -o /dev/null http://127.0.0.1:3000/"
      ;;
    124)
      guest_command_ok "$guest_type" "$vmid" \
        "systemctl is-active --quiet siem-host-runtime-agent.timer postgresql@14-main incident-telegram-bot siem-telegram-egress auditd rsyslog"
      ;;
    125)
      guest_command_ok "$guest_type" "$vmid" \
        "systemctl is-active --quiet siem-host-runtime-agent.timer docker pilot-valkey auditd rsyslog && docker exec pilot-valkey sh -lc 'valkey-cli ping | grep -q PONG'"
      ;;
    127)
      guest_command_ok "$guest_type" "$vmid" \
        "systemctl is-active --quiet opensearch arkimecapture.service arkimeviewer.service siem-zeek@enp6s19.service siem-zeek@enp6s20.service siem-zeek@enp6s21.service siem-zeek@enp6s22.service siem-zeek@enp6s23.service siem-security-sensor-forwarder@zeek.service siem-security-sensor-forwarder@arkime.service siem-arkime-metrics-exporter.timer"
      ;;
    128)
      guest_command_ok "$guest_type" "$vmid" \
        "systemctl is-active --quiet velociraptor.service siem-velociraptor-flow-exporter.timer siem-security-sensor-forwarder@velociraptor.service"
      ;;
    129)
      guest_command_ok "$guest_type" "$vmid" \
        "systemctl is-active --quiet clamav-daemon siem-clamav-update.timer siem-static-analysis.service siem-security-sensor-forwarder@static-analysis.service"
      ;;
    130)
      guest_command_ok "$guest_type" "$vmid" \
        "systemctl is-active --quiet docker wings nginx siem-security-sensor-forwarder@falco.service && (systemctl is-active --quiet falco-modern-bpf.service || systemctl is-active --quiet falco-bpf.service || systemctl is-active --quiet falco-kmod.service || systemctl is-active --quiet falco.service)"
      ;;
    131)
      guest_command_ok "$guest_type" "$vmid" \
        "systemctl is-active --quiet docker siem-misp-exporter.timer siem-misp-feed-cache.timer siem-security-sensor-forwarder@misp.service"
      ;;
    132)
      guest_command_ok "$guest_type" "$vmid" \
        "systemctl is-active --quiet step-ca.service siem-journal-event-exporter@step-ca.timer siem-security-sensor-forwarder@step-ca.service"
      ;;
    133)
      guest_command_ok "$guest_type" "$vmid" \
        "systemctl is-active --quiet minio.service siem-minio-audit-receiver.service siem-minio-certificate-renew.timer siem-security-sensor-forwarder@minio.service"
      ;;
    *)
      return 1
      ;;
  esac
}

repair_guest() {
  local guest_type="$1"
  local vmid="$2"
  case "$vmid" in
    100) guest_command_ok "$guest_type" "$vmid" "systemctl restart rsyslog minecraft minecraft-admin-console siem-host-runtime-agent.timer" ;;
    104) guest_command_ok "$guest_type" "$vmid" "systemctl restart siem-ingest nginx" ;;
    105) guest_command_ok "$guest_type" "$vmid" "systemctl restart siem-kafka siem-normalizer siem-normalizer@1 siem-normalizer@2 siem-filter siem-filter@1 siem-filter@2" ;;
    106) guest_command_ok "$guest_type" "$vmid" "systemctl restart clickhouse-server && sleep 8 && systemctl restart siem-writer siem-writer@2 siem-stream-corr siem-batch-corr siem-alert-agg" ;;
    107) guest_command_ok "$guest_type" "$vmid" "systemctl restart siem-vault && sleep 8 && systemctl restart siem-keycloak siem-web nginx" ;;
    108) guest_command_ok "$guest_type" "$vmid" "systemctl restart siem-kafka siem-normalizer@1 siem-normalizer@2 siem-filter@1 siem-filter@2" ;;
    120) guest_command_ok "$guest_type" "$vmid" "systemctl restart mariadb redis-server apache2 cron rsyslog siem-host-runtime-agent.timer" ;;
    121) guest_command_ok "$guest_type" "$vmid" "systemctl restart navidrome rsyslog siem-host-runtime-agent.timer" ;;
    122) guest_command_ok "$guest_type" "$vmid" "systemctl restart docker auditd rsyslog siem-host-runtime-agent.timer" ;;
    123) guest_command_ok "$guest_type" "$vmid" "systemctl restart docker pilot-gitea auditd rsyslog siem-host-runtime-agent.timer" ;;
    124) guest_command_ok "$guest_type" "$vmid" "systemctl restart postgresql@14-main siem-telegram-egress incident-telegram-bot auditd rsyslog siem-host-runtime-agent.timer" ;;
    125) guest_command_ok "$guest_type" "$vmid" "systemctl restart docker pilot-valkey auditd rsyslog siem-host-runtime-agent.timer" ;;
    127) guest_command_ok "$guest_type" "$vmid" "systemctl restart opensearch arkimecapture.service arkimeviewer.service siem-zeek@enp6s19.service siem-zeek@enp6s20.service siem-zeek@enp6s21.service siem-zeek@enp6s22.service siem-zeek@enp6s23.service siem-security-sensor-forwarder@zeek.service siem-security-sensor-forwarder@arkime.service" ;;
    128) guest_command_ok "$guest_type" "$vmid" "systemctl restart velociraptor.service siem-velociraptor-flow-exporter.timer siem-security-sensor-forwarder@velociraptor.service" ;;
    129) guest_command_ok "$guest_type" "$vmid" "systemctl restart clamav-daemon siem-clamav-update.timer siem-static-analysis.service siem-security-sensor-forwarder@static-analysis.service" ;;
    130) guest_command_ok "$guest_type" "$vmid" "systemctl restart docker wings nginx siem-security-sensor-forwarder@falco.service" ;;
    131) guest_command_ok "$guest_type" "$vmid" "systemctl restart docker siem-misp-exporter.timer siem-misp-feed-cache.timer siem-security-sensor-forwarder@misp.service" ;;
    132) guest_command_ok "$guest_type" "$vmid" "systemctl restart step-ca.service siem-journal-event-exporter@step-ca.timer siem-security-sensor-forwarder@step-ca.service" ;;
    133) guest_command_ok "$guest_type" "$vmid" "systemctl restart minio.service siem-minio-audit-receiver.service siem-minio-certificate-renew.timer siem-security-sensor-forwarder@minio.service" ;;
    *) return 1 ;;
  esac
}

reconcile_guest() {
  local guest_type="$1"
  local vmid="$2"
  if ! ensure_running "$guest_type" "$vmid"; then
    log "guest_type=$guest_type vm=$vmid result=start_failed"
    failures=$((failures + 1))
    return
  fi
  if [[ "$vmid" == "103" ]]; then
    if wait_opnsense; then
      log "guest_type=$guest_type vm=$vmid result=ready check=icmp"
    else
      log "guest_type=$guest_type vm=$vmid result=not_ready check=icmp"
      failures=$((failures + 1))
    fi
    return
  fi
  if ! wait_guest_runtime "$guest_type" "$vmid"; then
    log "guest_type=$guest_type vm=$vmid result=not_ready check=guest_runtime"
    failures=$((failures + 1))
    return
  fi
  if guest_ready "$guest_type" "$vmid"; then
    log "guest_type=$guest_type vm=$vmid result=ready"
    return
  fi
  log "guest_type=$guest_type vm=$vmid action=repair"
  repair_guest "$guest_type" "$vmid" || true
  sleep 10
  if guest_ready "$guest_type" "$vmid"; then
    log "guest_type=$guest_type vm=$vmid result=repaired"
  else
    log "guest_type=$guest_type vm=$vmid result=repair_failed"
    failures=$((failures + 1))
  fi
}

for vmid in "${CORE_QEMU_GUESTS[@]}"; do
  reconcile_guest qemu "$vmid"
done
for vmid in "${PLATFORM_QEMU_GUESTS[@]}"; do
  reconcile_guest qemu "$vmid"
done
for vmid in "${PLATFORM_LXC_GUESTS[@]}"; do
  reconcile_guest lxc "$vmid"
done
for vmid in "${START_ONLY_QEMU_GUESTS[@]}"; do
  if ensure_running qemu "$vmid"; then
    log "guest_type=qemu vm=$vmid result=running check=start_only"
  else
    log "guest_type=qemu vm=$vmid result=start_failed check=start_only"
    failures=$((failures + 1))
  fi
done

if (( failures > 0 )); then
  log "result=degraded failures=$failures"
  exit 1
fi

log "result=healthy"
