# Home SOC rollout and resource closure

Date: 2026-07-27.

## Why the node used so much memory

The previous profile reserved memory for peak 4500 EPS tests rather than the
measured steady working set. The five SIEM VMs had up to 87 GiB assigned,
Gamepanel had 24 GiB, and the unused OpenClaw gateway had 6 GiB. Kafka JVMs,
ClickHouse page cache, QEMU guest cache and the 18 GiB operator workstation
made host usage look like application RSS.

Memory was not the cause of the Web and Storage stalls:

- host and guest memory PSI remained zero;
- primary Storage still had more than 14 GiB available during a stall;
- the mechanical ClickHouse disk reached sustained I/O pressure;
- ClickHouse internal trace/profile tables occupied hundreds of GiB;
- vulnerability binding sync generated per-asset ClickHouse mutations;
- a full DLQ replay-history scan ran on every ingest overview request.

The applied profile reduced SIEM maximum allocation to 62 GiB, Gamepanel to
12 GiB, stopped OpenClaw, and retained the 18 GiB operator workstation. The
host had about 40 GiB available after the new SOC services were running, with
only 9.7 MiB swap used and zero memory PSI.

## Deployed services

| ID | Service | Placement | Runtime state |
| --- | --- | --- | --- |
| VM102 | Production edge, nftables, Unbound, Suricata | edge gateway | Active |
| VM103 | OPNsense and Suricata | staged NGFW | Active in staging; not the production gateway |
| VM122 | Greenbone/OpenVAS | vulnerability management | Active in containers |
| VM127 | Zeek 8.2.1 | five mirrored segment interfaces | Active |
| CT128 | Velociraptor 0.77.1 | DFIR server and SIEM exporter | Active |
| CT129 | ClamAV, YARA, Trivy, capa, FLOSS, oletools, PDFID, pefile, LIEF, Volatility, Chainsaw, Nuclei and testssl | static analysis | Active |
| VM130 | Falco 0.44.1 and Velociraptor client | Docker/Gamepanel host | Active |
| VM131 | MISP and curated feed cache | threat intelligence | Active |
| CT132 | step-ca | online internal PKI | Active |
| CT133 | MinIO | evidence object storage | Active |

Trivy repository scanning is also enabled in GitHub Actions. OpenClaw VM126 is
retained on disk, removed from autostart and stopped because no active SIEM or
application workflow depends on it.

CAPE is intentionally not deployed on this physical host. Dynamic detonation
must run on a separate isolated node without a route to `mgmt` or `sec`.

## SIEM integrations

The security services use the production ingest path, not direct ClickHouse
inserts:

```text
sensor/exporter
  -> local spool
  -> HTTPS ingest
  -> Kafka
  -> normalize/filter
  -> ClickHouse events
  -> correlation and incident aggregation
```

Validated integrations:

- Zeek JSON telemetry from all five monitored segments;
- Suricata and edge gateway telemetry;
- Velociraptor flows for the Windows operator workstation and Gamepanel;
- Falco runtime telemetry from the Docker host;
- static-analysis verdicts including ClamAV and YARA;
- MISP exporter and feed-cache runtime;
- Greenbone findings and host runtime;
- PKI and evidence-store host runtime.

The final dynamic ingest inventory contained 23 operational sources and 32
operational collectors, all healthy. The historical `UDP` pseudo-source
created from a Zeek protocol field was removed; the forwarder now pins
transport identity to the sensor host.

## Performance corrections

The following changes are part of this rollout:

- ingest overview stores `resolved_dlq_total` instead of parsing about 456,000
  replay records per request;
- the first one-time backfill took 8.06 seconds, then overview responses fell
  to about 0.13 seconds and transport responses to 0.10-0.14 seconds;
- vulnerability target bindings use one versioned batch insert and latest-key
  reads instead of per-asset `ALTER DELETE`;
- `vuln_asset_bindings` was migrated to
  `ReplacingMergeTree(last_sync_ts)` with all 14 current keys preserved;
- ClickHouse query/processor profilers are disabled for the default runtime
  profile and structured text logging is reduced from trace to warning;
- ClickHouse system logs receive 3-7 day TTLs;
- `siem.events` background merge size is capped;
- obsolete ClickHouse diagnostic tables are removed without touching SIEM
  events, alerts or incidents;
- `cmdb_assets` was migrated to `ReplacingMergeTree(updated_ts)` and fleet
  synchronization now uses one versioned batch insert instead of per-asset
  mutations;
- the Greenbone synchronization path no longer executes existing ClickHouse
  DDL on every cycle;
- writer workers coalesce short Kafka polls for up to 500 ms and insert up to
  2000 events at a time. During backlog recovery, observed batches reached
  2000 rows while all Kafka consumer groups returned to zero lag.

Primary ClickHouse hot data was moved from the shared mechanical VM disk to a
dedicated 300 GiB virtual disk on the `kingston1ter` NVMe pool. The migration
used two `rsync` passes with the pipeline stopped; the final dry run returned
zero changes. `/var/lib/clickhouse` is mounted by filesystem UUID with
`noatime`, and `clickhouse-server.service` has `RequiresMountsFor` protection.
The old LVM filesystem is retained unmounted as a rollback copy. The
maintenance workflow is captured in
`deploy/clickhouse_hot_storage_guard.py`; it uses the watchdog's
`/run/siem-maintenance` marker so planned work cannot trigger an automatic
restart.

## Power and startup state

Production SIEM VMs, VM102, VM103, VM122, VM127, VM130, VM131 and CT128-133
are configured to start with the Proxmox node. VM101 and retired VM126 remain
stopped intentionally.

VM108 wait-online now targets the production `ens20` interface rather than
the disconnected legacy `ens19`. ClickHouse primary, standby, Kafka,
normalizer, filter, writer, stream correlation, batch correlation, alert
aggregation, Web, nginx and the new security service units are checked after
power recovery.

VM122 no longer enters `emergency.target` when its optional EFI device is
late: the EFI mount has `nofail` and a bounded device timeout. CT129 uses a
guarded ClamAV update timer so an upstream CDN cooldown does not leave the
host in a failed systemd state. Apache/Postfix on CT120 were also recovered.

## Acceptance evidence

- public Web health at `https://192.168.3.102/health` returned HTTP 200;
- break-glass login redirected to `/app/dashboards`;
- ingest overview, source list, collector list, incident list and incident
  detail returned HTTP 200;
- health was about 0.10 seconds, incident list about 0.28 seconds and incident
  detail about 0.40-0.48 seconds after the storage migration;
- source health was 23/23 healthy and collector health was 32/32 healthy;
- Kafka lag was zero for normalizer, filter, primary writer, standby writer
  and stream correlation;
- recent ClickHouse events existed for Windows, Linux, Proxmox, SIEM core,
  edge/Suricata, Zeek, Velociraptor, Greenbone, MISP host runtime, static
  analysis, PKI and evidence storage;
- OPNsense Web returned HTTP 200 at `https://192.168.3.103`, and the public
  Web/ingest edge returned in about 0.03 seconds;
- all running Linux QEMU/LXC guests and the Proxmox host had zero failed
  systemd units; Greenbone sync and the ingest recovery watchdog completed
  successfully after maintenance;
- the operator Windows host at `192.168.3.81` had Sysmon and Velociraptor in
  `Running/Automatic` state and continued to produce current events;
- synthetic static-analysis and Falco canaries were removed from source logs,
  primary ClickHouse and standby ClickHouse after validation.

## Deferred gates

- OPNsense remains staged until a controlled gateway cutover can be performed
  without losing operator access.
- CAPE remains deferred to an isolated physical node.
- Web cold-cache query decomposition and source-specific rule/normalizer
  calibration are the next product phase; they are not claimed as complete by
  this rollout record.
