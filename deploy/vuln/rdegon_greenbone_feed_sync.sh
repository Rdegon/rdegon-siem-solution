#!/usr/bin/env bash
set -euo pipefail

container="${SIEM_GREENBONE_CONTAINER:-openvas}"
state_dir="${SIEM_GREENBONE_FEED_STATE_DIR:-/var/lib/rdegon-greenbone}"
lock_file="/run/lock/rdegon-greenbone-feed-sync.lock"
sync_started=false

stop_container_feed_sync() {
  docker exec "${container}" sh -lc '
    pids="$(pgrep -f "[g]reenbone-feed-sync --type all" || true)"
    if [ -z "$pids" ]; then
      exit 0
    fi
    kill -TERM $pids 2>/dev/null || true
    sleep 5
    pids="$(pgrep -f "[g]reenbone-feed-sync --type all" || true)"
    [ -z "$pids" ] || kill -KILL $pids 2>/dev/null || true
  '
}

cleanup_sync() {
  if [[ "${sync_started}" == "true" ]]; then
    stop_container_feed_sync >/dev/null 2>&1 || true
  fi
}

trap cleanup_sync EXIT HUP INT TERM

mkdir -p "${state_dir}"
exec 9>"${lock_file}"
if ! flock -n 9; then
  logger -t rdegon-greenbone-feed-sync "another feed synchronization is active"
  exit 0
fi

if ! systemctl is-active --quiet docker; then
  echo "docker is not active" >&2
  exit 1
fi
if ! docker inspect -f '{{.State.Running}}' "${container}" 2>/dev/null | grep -qx true; then
  echo "Greenbone container is not running: ${container}" >&2
  exit 1
fi

if docker exec "${container}" sh -lc "pgrep -af '[o]penvas --scan-start|[o]penvas: testing' >/dev/null"; then
  printf '%s\n' "$(date --iso-8601=seconds) skipped: active vulnerability scans" >"${state_dir}/last-skip"
  logger -t rdegon-greenbone-feed-sync "feed sync deferred because scans are active"
  exit 0
fi

started_at="$(date --iso-8601=seconds)"
stop_container_feed_sync
sync_started=true
set +e
docker exec "${container}" timeout --foreground --kill-after=60s 5h greenbone-feed-sync \
  --type all \
  --fail-fast \
  --wait-interval 30 \
  --rsync-timeout 300 \
  --user gvm \
  --group gvm
sync_status=$?
set -e
sync_started=false
if (( sync_status != 0 )); then
  failed_at="$(date --iso-8601=seconds)"
  printf '{"status":"error","started_at":"%s","finished_at":"%s","container":"%s","exit_code":%d}\n' \
    "${started_at}" "${failed_at}" "${container}" "${sync_status}" >"${state_dir}/state.json"
  exit "${sync_status}"
fi
docker exec "${container}" greenbone-feed-sync --selftest --user gvm --group gvm
finished_at="$(date --iso-8601=seconds)"

printf '%s\n' "${finished_at}" >"${state_dir}/last-success"
printf '{"status":"ok","started_at":"%s","finished_at":"%s","container":"%s"}\n' \
  "${started_at}" "${finished_at}" "${container}" >"${state_dir}/state.json"
