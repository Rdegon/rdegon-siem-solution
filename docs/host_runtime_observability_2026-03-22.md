# Host Runtime Observability

## Status

This wave is now operationally complete for the Linux stand.

Live coverage:

- `VM1` ingest
- `VM2` processing
- `VM3` storage
- `VM4` control-plane
- `VM5` transport

## Runtime Contract

Every monitored host must emit a fresh `host_runtime_snapshot` event into the platform runtime surface.

Required fields:

- `host_name`
- `host_role`
- `host_ip`
- `event_type=host_runtime_snapshot`
- `ts`
- `cpu_pct`
- `memory_used_pct`
- `disk_used_pct`
- `load_ratio`
- `swap_used_pct`
- `inode_used_pct`
- `stale_age_seconds`

## Green Criteria

`GET /api/health/hosts/runtime` is green only when:

- all expected targets are present
- `stale_targets = 0`
- every target has a non-stale `last_seen_ts`
- the latest snapshot set matches the expected five-node inventory

## Delivery Path

Standard rollout:

```powershell
python .\deploy\host_runtime_wave_deploy.py
python .\deploy\host_runtime_wave_smoke.py
```

Shipped assets:

- `deploy/common/siem-host-runtime-agent.service`
- `deploy/common/siem-host-runtime-agent.timer`
- `deploy/host_runtime_agent.py`
- `deploy/host_runtime_monitor.py`
- `host_runtime_runtime.py`

## Operational Notes

- Staleness is based on the actual target inventory and observed timestamps, not on a best-effort dashboard-only count.
- Deploy now ships both the runtime agent and the policy/rule material required by the health surface.
- The runtime surface is an operator gate, not a passive dashboard metric.

## Operator APIs

- `GET /api/health/hosts/runtime`
- `GET /api/health/overview`

## Troubleshooting Order

1. confirm the timer and service are active on the target host;
2. confirm fresh snapshot events are reaching the platform;
3. rerun `deploy/host_runtime_wave_smoke.py`;
4. only after that treat the node as a host-runtime incident.
