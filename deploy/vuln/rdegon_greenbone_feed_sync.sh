#!/usr/bin/env bash
set -euo pipefail

container="${SIEM_GREENBONE_CONTAINER:-openvas}"
state_dir="${SIEM_GREENBONE_FEED_STATE_DIR:-/var/lib/rdegon-greenbone}"
lock_file="/run/lock/rdegon-greenbone-feed-sync.lock"

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
docker exec "${container}" greenbone-feed-sync \
  --type all \
  --fail-fast \
  --no-wait \
  --rsync-timeout 300 \
  --user gvm \
  --group gvm
docker exec "${container}" greenbone-feed-sync --selftest --user gvm --group gvm
finished_at="$(date --iso-8601=seconds)"

printf '%s\n' "${finished_at}" >"${state_dir}/last-success"
printf '{"status":"ok","started_at":"%s","finished_at":"%s","container":"%s"}\n' \
  "${started_at}" "${finished_at}" "${container}" >"${state_dir}/state.json"
