# Proxmox resource right-sizing

Date: 2026-07-26.

## Measured state

The Proxmox host has 164 GiB RAM. Before right-sizing it had only about 9 GiB
available even though host memory PSI was zero. Most of the difference was
idle guest page cache and fixed QEMU allocation, not active application RSS.

| Guest | Assigned before | Active used inside guest | Applied target |
| --- | ---: | ---: | ---: |
| SIEM Ingest | 14 GiB | 2.2 GiB | 10 GiB max / 8 GiB balloon |
| SIEM Processing | 19 GiB | 2.1 GiB | 12 GiB max / 10 GiB balloon |
| SIEM Storage | 28 GiB max / 24 GiB balloon | 3.0 GiB excluding cache | 20 GiB max / 18 GiB balloon |
| SIEM Web | 14 GiB | 1.9 GiB | 10 GiB max / 8 GiB balloon |
| SIEM Transport | 12 GiB | 2.7 GiB | 10 GiB max / 8 GiB balloon |
| Gamepanel | 24 GiB | 4.5 GiB | 12 GiB |
| OpenClaw | 6 GiB | 1.3 GiB | retired and stopped |

The primary ClickHouse cap is reduced from 16 GiB to 12 GiB. The standby
ClickHouse cap is 6 GiB. A 4 GiB candidate cap was rejected after a production
partition read reached 4.01 GiB and was correctly killed by ClickHouse. The
final caps fit inside the VM profiles and leave
memory for the operating system, Kafka, correlation workers, and file cache.

Immediately after the profile was applied, the host had 67 GiB available and
61 GiB free. After guest page caches warmed again, the host stabilized at
48 GiB available and 41 GiB free. Memory PSI remained zero in both cases. The
SIEM maximum allocation fell from 87 GiB to 62 GiB. Gamepanel released another
12 GiB of maximum allocation and stopping OpenClaw released its 6 GiB runtime
allocation.

## OpenClaw retirement

The retirement gate verified:

- no OpenClaw API key in the active SIEM Web environment;
- no Telegram token or chat ID;
- the Telegram bot service is inactive;
- no active SIEM or Navidrome connection to the OpenClaw proxy;
- the gateway produced repeated failed Telegram requests and high-volume
  telemetry without providing an active function.

VM126 is retained on disk but removed from autostart and stopped. Its CMDB
record is disabled, proxy variables are cleared, and only rules that require
the retired OpenClaw asset are retired. Historical events are preserved.

## Gamepanel

The single Pterodactyl server used about 3.5 GiB, had no connected players,
and was configured with a 16 GiB container limit and a 9 GiB Java heap.
The server allocation is now 10 GiB plus 2 GiB swap, while the VM has 12 GiB.
Docker, Wings, nginx, the Minecraft container, and TCP/25565 were verified
after the VM restart.

## Additional safe limits

LXC limits are applied online:

- Minecraft: 10 GiB to 8 GiB;
- Nextcloud: 8 GiB to 4 GiB;
- Navidrome: 6 GiB to 2 GiB.

These LXC limits do not reserve host memory. They prevent future unbounded
growth and do not reclaim already unused memory.

## Storage recovery finding

The rolling restart exposed an existing storage design problem unrelated to
the new memory limit: the Storage operating system and the 690 GiB ClickHouse
filesystem share an 800 GiB QCOW2 on a mechanical Toshiba disk. The virtual
SATA queue timed out during cold boot and ClickHouse executable and metadata
reads were extremely slow.

The VM keeps the SATA boot layout for compatibility, but the QEMU backend now
uses `aio=threads,cache=none`. This avoids blocking the QEMU event loop while
retaining write-through safety for a host without a UPS. The ClickHouse data
filesystem completed `fsck`; the standby retained the live event stream while
the affected primary partition was restored.

The recovery check also found that the standby writer was one release behind
the primary writer. It used Kafka offsets as fallback event IDs and receive
time for some events that already carried `event.id` and `@timestamp`. The
standby `siem.events` schema and writer are now aligned with the primary.
After alignment, all 545 sampled fresh non-NDR events existed on both nodes
and standby Kafka lag was zero. Historical standby rows retain their original
representation.

A later maintenance window should move the Storage OS and ClickHouse binary to
SSD-backed storage. The large ClickHouse data volume can remain on HDD until a
dedicated data SSD is available. Do not use `cache=writeback` on this host
without power-loss protection.

The recovery also exposed unsafe watchdog behavior: one intentionally stopped
worker caused the watchdog to restart the entire Storage service bundle,
including healthy ClickHouse. The watchdog now:

- skips repair while `/run/siem-maintenance` exists on the target host;
- restarts only the units that are not active;
- does not restart a healthy database because a dependent worker is stopped.

Create the marker before planned Storage maintenance and remove it only after
all workers and health checks are active.

## Verification

- Ingest `/health`, `/health/overview`, `/health/transport`, and
  `/health/sources` returned HTTP 200.
- Web `/health` returned HTTP 200; authenticated API routes correctly returned
  HTTP 401 without a session, and `/app` redirected to SSO.
- Kafka remained in `kafka_only` mode with three configured brokers.
- Source health reported 25 active sources and 31 active collectors after the
  retired OpenClaw source became stale as expected.
- OpenClaw-specific runtime rules were disabled while unrelated gateway rules
  remained available.
- OpenClaw is stopped with autostart disabled; its disks and historical events
  are retained.

## Deferred reductions

The following measurements are working set inside each guest, excluding
reclaimable page cache. They identify the next candidates, but do not replace
a peak workload test.

| Guest | Current limit | Measured working set | Candidate | Maximum saving | Required gate |
| --- | ---: | ---: | ---: | ---: | --- |
| VM102 edge router/Suricata | 6 GiB | 1.25 GiB | 4 GiB | 2 GiB | Full interface capture and IPS replay |
| VM103 OPNsense staging | 8 GiB | unavailable | 4 GiB | 4 GiB | Install/enable guest agent and run NGFW/IPS load |
| VM122 Greenbone | 16 GiB | 1.88 GiB idle | 10 GiB | 6 GiB | Full authenticated vulnerability scan |
| VM124 Pilot PostgreSQL | 4 GiB | 0.27 GiB | 2 GiB | 2 GiB | Pilot application transaction test |
| VM131 MISP | 8 GiB | 2.20 GiB idle | 6 GiB max / 4 GiB balloon | 2 GiB | Feed import and correlation test |

Together these deferred VM reductions can release up to another 16 GiB of
maximum allocation. Greenbone and MISP must be changed only after a full
scan/import workload, not from idle measurements.

A second SIEM profile can reduce another 10 GiB of maximum allocation:

| SIEM guest | Current | Candidate after EPS gate |
| --- | ---: | ---: |
| Ingest | 10 / 8 GiB | 8 / 6 GiB |
| Processing | 12 / 10 GiB | 10 / 8 GiB |
| Storage | 20 / 18 GiB | 18 / 16 GiB |
| Web | 10 / 8 GiB | 8 / 6 GiB |
| Transport | 10 / 8 GiB | 8 / 6 GiB |

Apply this second profile only if the production-transport 4500 EPS test keeps
Kafka lag bounded, ClickHouse inserts below the existing latency target,
correlation current, and Web p95 unchanged. The current conservative profile
preserves headroom for that workload.

Gamepanel can be reduced from 12 GiB to 10 GiB in a second step by lowering the
Pterodactyl allocation from 10 GiB to 8 GiB and the Java heap from 9 GiB to
7 GiB. This saves another 2 GiB but requires a representative player/plugin
load test first.

VM111 is the operator workstation and remains at 18 GiB. Zeek, static
analysis, Velociraptor, PKI, and evidence storage keep their current limits
because their future collection and analysis workloads have not yet been
load-tested at lower limits.
