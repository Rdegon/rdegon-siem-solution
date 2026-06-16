# Storage Rebalance And Retention Hardening: 2026-04-05

## Summary

This pass closed the homelab storage-pressure regression that surfaced after the cold stop / start cycle and the subsequent disk migration work.

The live root causes were:

- too many guests concentrated on `kingston1ter` and a stale disk left on `kingston256gig`
- no consistent log-maintenance timer on every core and fleet node
- unbounded Kafka topic growth on `VM104`, `VM105`, and `VM108`
- historical Proxmox proxy log write errors during the period when the stand was under storage pressure

The incident was not caused by RAM exhaustion.

`SIEM-Processing` and `SIEM-Transport` both had ample free memory during the repair window; the real failure mode was disk pressure plus Kafka recovery after an unclean stop.

## Live Root Cause

### Processing / Transport

- `VM105` and `VM108` were healthy again as VMs, but both carried `46G` of Kafka data under `/var/lib/siem-kafka`.
- `VM108` was the critical node because its root filesystem reached `93%` usage.
- Kafka logs showed `CorruptRecordException` on startup after the cold stop, followed by truncation and recovery of affected segments.
- `VM108` was also missing `siem-log-maintenance.timer`, so it had no recurring local cleanup.

### Proxmox

- historical `pveproxy` logs showed `No space left on device` while writing access logs during the pressure window.
- after cleanup and redistribution, Proxmox root returned to a healthy margin and the error stopped reproducing.

## What Changed

### Disk placement

Guests were rebalanced away from the overloaded SSDs:

- `VM122`, `VM123`, `VM124`, `VM125` moved to `toshiba1ter`
- `CT121` moved to `toshiba500gig`
- `VM108` moved from `kingston256gig` to `kingston480gig`
- stale `unused0` disk entries were removed from the old SSD-backed placement

### Automatic cleanup

The common maintenance bundle now provides:

- journal vacuuming by size and time
- `logrotate` execution
- `apt-get clean`
- cleanup of stale compressed / rotated logs
- cleanup of stale GitHub Actions runner diagnostics under `/opt/actions-runners/*/_diag`

The common timer now runs every `6h` instead of every `12h`.

### Kafka retention hardening

The Kafka cluster defaults now enforce bounded broker-side log growth:

- `log.retention.hours=48`
- `log.retention.bytes=536870912`
- `log.segment.bytes=134217728`
- `log.roll.ms=3600000`
- `log.retention.check.interval.ms=300000`
- `log.segment.delete.delay.ms=60000`

Topic-level retention is now also enforced on the live cluster:

- `siem.raw`
- `siem.normalized`
- `siem.filtered`
- `siem.dlq`
- `siem.replay`
- `siem.transport.audit`

These topic configs were tightened to per-partition limits that are appropriate for a transient transport layer rather than a long-term archive.

## Live Result

### Storage

After the live rebalance:

- `kingston1ter` dropped to about `74%`
- `kingston256gig` dropped to about `0.34%`
- `kingston480gig` stayed within safe headroom at about `42%`
- both HDD pools remained mostly empty and now absorb the non-latency-critical guests

### Kafka nodes

After the retention rollout:

- `VM104 / siem-ingest` dropped from roughly `69%` root usage to `55%`
- `VM105 / siem-processing` dropped from roughly `68%` root usage to `54%`
- `VM108 / siem-transport` dropped from roughly `93%` root usage to `79%`
- `/var/lib/siem-kafka` dropped from `46G` to `34G` on all three Kafka nodes during the first cleanup cycle

Kafka logs on `VM108` confirmed active deletion of old segment files immediately after the final retention profile was applied.

### Proxmox

- Proxmox root stabilized around `42%`
- no new `pveproxy` `No space left on device` messages were present in the last-hour journal sample after the cleanup pass

## Operational Decision

No RAM increase was applied to `SIEM-Processing` or `SIEM-Transport`.

The live measurements during the repair showed:

- `VM105` had more than `14G` available memory
- `VM108` had roughly `9G` available memory

The bottleneck was storage pressure and Kafka log growth, not memory.

## Files / Deploy Paths

The runtime hardening in this pass is anchored in:

- `deploy/common/90-siem-memory.conf`
- `deploy/common/siem-log-maintenance.sh`
- `deploy/common/siem-log-maintenance.service`
- `deploy/common/siem-log-maintenance.timer`
- `deploy/kafka_cluster_layout.py`
- `deploy/kafka_topic_bootstrap.py`
- `deploy/host_runtime_wave_deploy.py`
- `deploy/proxmox_fleet_wave_deploy.py`

## Follow-Up

If future pressure appears again, the next escalation step should be:

1. inspect live Kafka topic sizes and root usage on `VM104`, `VM105`, `VM108`
2. verify `siem-log-maintenance.timer` on the affected node
3. inspect recent Kafka recovery / truncation warnings after any abrupt stop
4. only then consider disk growth or service relocation

Memory growth should not be the first response unless live memory pressure actually appears.
