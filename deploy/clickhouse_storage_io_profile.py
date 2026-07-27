from __future__ import annotations

import base64
import json
import os
import shlex

try:
    from deploy.soc_foundation_provision import Proxmox
except ModuleNotFoundError:
    from soc_foundation_provision import Proxmox


TARGETS = (106, 108)
SYSTEM_LOG_TABLES = (
    "text_log",
    "processors_profile_log",
    "query_log",
    "part_log",
    "trace_log",
    "metric_log",
    "asynchronous_metric_log",
    "query_metric_log",
)

SYSTEM_LOG_CONFIG = """<clickhouse>
  <logger>
    <level>information</level>
  </logger>
  <query_log>
    <ttl>event_date + INTERVAL 7 DAY DELETE</ttl>
  </query_log>
  <part_log>
    <ttl>event_date + INTERVAL 7 DAY DELETE</ttl>
  </part_log>
  <text_log>
    <level>warning</level>
    <ttl>event_date + INTERVAL 3 DAY DELETE</ttl>
  </text_log>
  <trace_log>
    <ttl>event_date + INTERVAL 3 DAY DELETE</ttl>
  </trace_log>
  <processors_profile_log>
    <ttl>event_date + INTERVAL 3 DAY DELETE</ttl>
  </processors_profile_log>
  <metric_log>
    <collect_interval_milliseconds>10000</collect_interval_milliseconds>
    <ttl>event_date + INTERVAL 7 DAY DELETE</ttl>
  </metric_log>
  <query_metric_log>
    <collect_interval_milliseconds>10000</collect_interval_milliseconds>
    <ttl>event_date + INTERVAL 3 DAY DELETE</ttl>
  </query_metric_log>
  <asynchronous_metric_log>
    <ttl>event_date + INTERVAL 7 DAY DELETE</ttl>
  </asynchronous_metric_log>
</clickhouse>
"""

QUERY_PROFILING_CONFIG = """<clickhouse>
  <profiles>
    <default>
      <log_processors_profiles>0</log_processors_profiles>
      <query_profiler_real_time_period_ns>0</query_profiler_real_time_period_ns>
      <query_profiler_cpu_time_period_ns>0</query_profiler_cpu_time_period_ns>
    </default>
  </profiles>
</clickhouse>
"""


def _write_file(pve: Proxmox, vmid: int, destination: str, content: str) -> None:
    encoded = base64.b64encode(content.encode("ascii")).decode("ascii")
    temporary = f"/tmp/siem-clickhouse-io-{os.getpid()}.b64"
    pve.guest_exec(
        vmid,
        f"install -d -m 0755 {shlex.quote(os.path.dirname(destination))}; "
        f"printf %s {shlex.quote(encoded)} > {shlex.quote(temporary)}; "
        f"base64 -d {shlex.quote(temporary)} > {shlex.quote(destination)}; "
        f"chmod 0644 {shlex.quote(destination)}; "
        f"rm -f {shlex.quote(temporary)}",
        timeout=120,
    )


def _deploy_target(pve: Proxmox, vmid: int) -> dict[str, object]:
    _write_file(
        pve,
        vmid,
        "/etc/clickhouse-server/config.d/siem-system-log-profile.xml",
        SYSTEM_LOG_CONFIG,
    )
    _write_file(
        pve,
        vmid,
        "/etc/clickhouse-server/users.d/siem-query-profiling.xml",
        QUERY_PROFILING_CONFIG,
    )
    truncate_sql = "; ".join(
        f"TRUNCATE TABLE IF EXISTS system.{table} SYNC"
        for table in SYSTEM_LOG_TABLES
    )
    ttl_sql = "; ".join(
        f"ALTER TABLE system.{table} MODIFY TTL event_date + INTERVAL "
        f"{'3' if table in {'text_log', 'trace_log', 'processors_profile_log', 'query_metric_log'} else '7'} DAY DELETE"
        for table in SYSTEM_LOG_TABLES
    )
    old_system_log_sql = (
        "SET max_table_size_to_drop=0; "
        "TRUNCATE TABLE IF EXISTS system.processors_profile_log SYNC; "
        + "; ".join(
            f"DROP TABLE IF EXISTS system.{table}_{suffix}"
            for table in SYSTEM_LOG_TABLES
            for suffix in range(4)
        )
    )
    script = f"""
set -euo pipefail
clickhouse-client --query "SYSTEM STOP MERGES siem.events" 2>/dev/null || true
clickhouse-client --query "ALTER TABLE siem.events MODIFY SETTING max_bytes_to_merge_at_max_space_in_pool = 536870912, max_bytes_to_merge_at_min_space_in_pool = 33554432" 2>/dev/null || true
clickhouse-client --multiquery --query {shlex.quote(truncate_sql)}
systemctl restart clickhouse-server
for attempt in $(seq 1 90); do
  clickhouse-client --query 'SELECT 1' >/dev/null 2>&1 && break
  sleep 2
done
clickhouse-client --query 'SELECT 1' >/dev/null
clickhouse-client --multiquery --query {shlex.quote(ttl_sql)}
clickhouse-client --multiquery --query {shlex.quote(old_system_log_sql)}
clickhouse-client --query "SYSTEM START MERGES siem.events" 2>/dev/null || true
fstrim /var/lib/clickhouse >/dev/null 2>&1 || true
printf 'service='
systemctl is-active clickhouse-server
printf 'processor_profiles='
clickhouse-client --query "SELECT value FROM system.settings WHERE name='log_processors_profiles'"
printf 'query_profiler_real_time_ns='
clickhouse-client --query "SELECT value FROM system.settings WHERE name='query_profiler_real_time_period_ns'"
printf 'query_profiler_cpu_time_ns='
clickhouse-client --query "SELECT value FROM system.settings WHERE name='query_profiler_cpu_time_period_ns'"
printf 'events_merge_cap='
clickhouse-client --query "SELECT value FROM system.merge_tree_settings WHERE name='max_bytes_to_merge_at_max_space_in_pool'"
"""
    output = pve.guest_exec(vmid, script, timeout=900)
    return {"vmid": vmid, "status": output.strip().splitlines()}


def main() -> int:
    with Proxmox() as pve:
        results = [_deploy_target(pve, vmid) for vmid in TARGETS]
    print(json.dumps(results, indent=2, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
