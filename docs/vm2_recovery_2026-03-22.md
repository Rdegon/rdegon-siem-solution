# VM2 Recovery: 2026-03-22

Archive note: this document describes the Redis-era outage and recovery sequence. Current runtime guidance is Kafka-based and lives in the current runbooks.

## Incident Summary

- `VM2` (`192.168.1.37`, `siem-processing`) was found stopped on the Proxmox host as `VM105`.
- That outage cut the Redis-backed processing path between `VM1` ingest and `VM3` storage and detection.
- The visible symptom on the stand was severe: no fresh events and no fresh alerts for roughly the last hour.

## Root Cause Chain

1. `VM105` stopped on the Proxmox side, which removed `redis-server`, `siem-normalizer`, and `siem-filter` from the pipeline.
2. `VM1` kept seeing the raw Redis stream at its configured hard limit.
3. The then-current ingest-edge backpressure logic treated `XLEN >= hard_limit` as a permanent stop condition even after consumers came back.
4. After `VM2` recovered, `VM1` still rejected new raw events because the stream stayed trimmed near the hard cap, which made the stand look dead even though the processing tier was back online.

## Recovery Actions

### Proxmox And Guest Recovery

- verified `qm status 105` and confirmed the guest was stopped
- started the guest with `qm start 105`
- removed stale offline disk mounts that had still been attached through `qemu-nbd`
- revalidated guest reachability from the hypervisor
- installed and enabled `qemu-guest-agent` inside `VM2`
- enabled stable guest control through `qm guest exec 105 -- ...`

### VM2 Service Recovery

Confirmed active after boot:

- `ssh`
- `redis-server`
- `qemu-guest-agent`
- `siem-normalizer`
- `siem-filter`
- `siem-normalizer@2`
- `siem-filter@2`
- `actions.runner.Rdegon-siem-solution.siem-vm2.service`

### Direct SSH Recovery

`VM2` now again supports direct operator SSH, not only Proxmox fallback access.

Applied live:

- added the public half of `D:\University\Project_VPN\vpnadmin_ed25519` to `/home/rdegon/.ssh/authorized_keys`
- created `/etc/ssh/sshd_config.d/60-rdegon-lan.conf`
- kept password auth enabled as fallback, while also making key-based login available

Current direct LAN operator command:

```powershell
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=NUL -i "D:\University\Project_VPN\vpnadmin_ed25519" rdegon@192.168.1.37
```

### Network And Runner Hardening

The first recovery pass brought `VM2` back, but a second pass found the deeper cause of the unstable operator path:

- `/etc/netplan` still contained both `01-siem-net.yaml` and `01-siem.yaml`
- the legacy file kept an extra network definition and the old public DNS pair `1.1.1.1` / `8.8.8.8`
- that left `VM2` with a mixed network state, intermittent runner connectivity to GitHub, and non-deterministic direct SSH behavior during the first connections after restart

The canonical live state is now:

- only `/etc/netplan/01-siem.yaml` remains
- `ens19` is the only active LAN interface in the netplan layer
- LAN DNS is pinned to `192.168.1.1`
- `/etc/systemd/resolved.conf` keeps `192.168.1.1` as primary DNS and public resolvers only as fallback
- `actions.runner.Rdegon-siem-solution.siem-vm2.service` is part of the same hardened recovery path as `ssh`

### Ingest Backpressure Hotfix

`VM1` ingest was patched so that the raw stream hard limit no longer becomes a permanent lockout when the `raw` consumer group is clearly draining.

Current behavior:

- if the raw stream is at the hard limit and the normalizer consumer group is still badly backed up, new events are diverted to the DLQ
- if the raw stream is at the hard limit but the consumer group pending count is low and draining, new events are accepted and the condition is logged as a warning instead of a hard drop

The hotfix lives in:

- [services/ingest/redis_client.py](C:/Users/lolol/Documents/Playground/remote-edit2/services/ingest/redis_client.py)
- [test_ingest_fabric.py](C:/Users/lolol/Documents/Playground/remote-edit2/tests/test_ingest_fabric.py)

## Validation

### VM2

- guest reachable through Proxmox guest agent
- `ssh`, `redis-server`, `qemu-guest-agent`, `siem-normalizer`, `siem-filter`, and `siem-vm2` runner all `active`
- repeated direct LAN SSH attempts from the workstation now succeed for both key-based `ssh` and password-based SSH after the restart settles
- the previously duplicated netplan files were reduced to a single canonical `01-siem.yaml`
- `getent ahostsv4 github.com` now resolves again on `VM2`
- the `siem-vm2` GitHub runner now stays `online` again

### CI/CD

- the four-node runner plane is now complete:
  - `siem-vm1`
  - `siem-vm2`
  - `siem-vm3`
  - `siem-vm4`
- `VM2` is now also a dedicated deploy target through `deploy-vm2`, so processing-node resilience changes no longer depend on a remote SSH hop from another runner
- watchdog now also repairs the `VM2` DNS and runner path, not only Redis and processing services

### Processing Resilience

The post-recovery resilience slice now also adds:

- Redis AOF persistence on `VM2`
- a dedicated `VM2` deploy and smoke path
- watchdog-side repair for `redis-server`, `siem-normalizer`, and `siem-filter`
- runtime synchronization of `services/normalizer` and `services/filter` from `main` into the live VM2 checkout before service restart
- smoke verification that the deployed worker code still exposes the consumer-group path (`xreadgroup` and `xack`)
- template-based secondary `siem-normalizer@2` and `siem-filter@2` units so the transform stage is no longer one singleton consumer per step

### Final Redis-HA Follow-Up

The first Redis HA recovery restored replication and Sentinel, but one last runtime regression still kept the stand dark:

- the new shared Redis wrapper used `name` as its own internal first argument
- Redis methods such as `xgroup_create(name=..., ...)` also pass `name` as a keyword
- that crash-looped the `normalizer` and `filter` services on `VM2`

The final live fix renamed the internal wrapper argument, redeployed the shared runtime to `VM1`, `VM2`, and `VM3`, and restored fresh flow through the full pipeline.

### Event Flow

Fresh ClickHouse checks on `VM3` after recovery showed:

- fresh events inside the last `5` and `60` minutes
- fresh aggregated alerts inside the last `60` minutes
- fresh `max(ts)` and `max(updated_ts)` values moving forward again
- after the final Redis-wrapper fix, Redis HA smoke confirmed `flow_events_5m=10399` and `flow_alerts_5m=1835`

## Recovery Anchors

- VM1 ingest deploy backup: `/tmp/siem-ingest-backup-20260321T223814Z`
- live verification point for restored events: `2026-03-21 22:43:24`
- live verification point for restored alerts: `2026-03-21 22:43:53`

## Operational Takeaways

- `VM2` should be treated as a first-class operational dependency, not a quiet middlebox; when it stops, the whole stand goes dark even if `VM1`, `VM3`, and `VM4` still look superficially healthy.
- `qemu-guest-agent` is now mandatory for `VM2` because it gives a recovery path even when the guest SSH service is unstable.
- `VM2` should keep both access paths:
  - direct LAN SSH for normal operator work
  - Proxmox guest-agent fallback for emergency recovery
- ingest-edge backpressure must look at actual consumer drain state, not only stream length, otherwise Redis `MAXLEN` trimming can create a false permanent outage.
- after Redis failover work, a green `redis-server` plus Sentinel quorum is not enough. If flow is still flat, check `journalctl -u siem-normalizer -u siem-filter` on `VM2` for wrapper or consumer-group regressions before assuming ClickHouse or web failures.

## Remaining Follow-Up

- move from AOF plus watchdog repair to real Redis replica or Sentinel failover so `VM2` is no longer a single-node Redis dependency
- keep monitoring whether direct `SSH` to `VM2` remains stable or still intermittently resets while guest-agent access remains healthy
- keep the canonical `VM2` network state single-sourced through `deploy/vm2_processing_resilience_deploy.py`; do not reintroduce a second netplan file
