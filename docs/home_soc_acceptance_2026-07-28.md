# Home SOC production acceptance

Date: 2026-07-28.

This is the current acceptance record. Older dated staging documents remain
historical evidence and do not override this state.

## Production service map

| Capability | Placement | Production state |
| --- | --- | --- |
| Routing, NGFW, DNS and inline IPS | VM103 `opnsense-edge-01` | Active on `sec`, `servers`, `lab`, `users` and transit interfaces |
| Public Web, ingest publication and VPN edge | VM102 `lab-edge-01` plus Proxmox VPN service | Active |
| SIEM ingest, Kafka, processing, storage, correlation and Web | VM104-108 | Active with ClickHouse standby on VM108 |
| NDR and packet evidence | VM127 Zeek and Arkime | Active on five mirrored segments |
| Vulnerability and exposure management | VM122 Greenbone/OpenVAS plus Nmap/Nuclei workflow | Active |
| DFIR and endpoint visibility | CT128 Velociraptor | Active; Linux, Windows and Proxmox endpoints enrolled |
| Static malware analysis | CT129 ClamAV, YARA, capa, FLOSS, oletools, PDFID, pefile, LIEF, Volatility and Chainsaw | Active |
| Runtime container detection | VM130 Falco | Active |
| Threat intelligence | VM131 MISP and curated feed cache | Active |
| Internal PKI | CT132 step-ca | Active |
| Evidence object storage | CT133 MinIO | Active |

OpenClaw VM126 is intentionally retired and excluded from autostart. VM101 is
reserved as a disposable Windows guest and remains stopped.

The final fleet check found every required VM and container running with
autostart enabled and zero failed systemd units. Nextcloud on CT120 also passed
explicit Apache, MariaDB, Redis, cron and local HTTPS checks.

## Event path acceptance

Security integrations publish through the production transport:

```text
source or sensor
  -> durable local forwarder/spool
  -> HTTPS or syslog ingest
  -> Kafka
  -> source-specific normalizer and filter
  -> ClickHouse primary and standby
  -> stream/batch correlation
  -> alerts_raw -> alerts_agg -> incidents -> Web/API
```

Current evidence includes events from:

- Windows Security, Sysmon, PowerShell, WMI, Defender, RDP and WinRM;
- Proxmox, all Linux service guests and SIEM core hosts;
- OPNsense, Suricata, Zeek and Arkime;
- Velociraptor, Falco and static-analysis tools;
- Greenbone/Nmap vulnerability workflows;
- MISP, step-ca and MinIO;
- Minecraft, Pterodactyl/Wings, Nextcloud, Navidrome and pilot services.

The final dynamic inventory reported `23/23` sources and `34/34` collectors
healthy. The ingest overview had no issues, no backpressure and zero outstanding
DLQ records. Two live DLQ rows created during maintenance were replayed before
the resolved history was archived and the SQLite runtime store was compacted
from about 821 MiB to about 31 MiB.

## Detection acceptance

- The assignment catalog contains 487 source rules: 355 stream and 132 batch.
- Runtime publication contains 456 unique stream entries, 452 enabled stream
  rules, and 134 unique and enabled batch rules. Four stream entries are exact
  retired duplicates whose coverage remains active under their documented
  replacements.
- Resource rules require sustained structured metrics and use container-safe
  CPU/load scopes.
- Linux SSH, Windows WMI, multi-host SSH, PVE reboot, JMESPath/process,
  heartbeat and benchmark families have explicit asset scope, thresholds,
  suppression and deduplication.
- The last false-positive pass also corrected generic authentication failure
  matching, Proxmox successful-auth matching, transient iowait, retired Windows
  aliases, auditd fragment classification, alert-SLA keyword matching and
  one-off service restart matching.
- Source rule 2726 now accepts only auditd `EXECVE` reconnaissance and excludes
  the exact lab-edge monitoring commands. Batch rules 8001/8002 exclude the
  retired Windows aliases, 8221 queries only real unassigned critical alerts,
  and 8429 requires repeated restart evidence.
- Historical incidents are changed only when the evidence identifies a
  confirmed false-positive class. A real encoded PowerShell alert remains
  visible instead of being broadly suppressed.
- The final open queue contains only rule 2604, `Windows Encoded PowerShell
  Command`, and rule 4005, `Threat Intel Hit On Critical Asset`. None of the
  confirmed false-positive classes reopened after multiple batch cycles.

Rule tuning reduces the observed false-positive classes; it is not a promise
that future environment changes can never require recalibration. True-positive
fixtures and source coverage remain active.

## Storage and transport acceptance

- Both ClickHouse writers are active and use deterministic insert block tokens.
- A historical maintenance gap of 925 events was reconciled from the standby.
- The final bidirectional comparison for the closed interval from
  `2026-07-27T00:00:00Z` through `2026-07-28T13:02:00Z` reported zero missing
  rows on both VM106 and VM108.
- The July 27 partition had 4,048,055 rows, the same unique-event count, and the
  same hash on both storage nodes.
- Suricata no longer reuses one flow identifier as the event identifier for
  alert, query and answer records. Fresh validation produced 287 rows with 287
  unique deterministic `suricata-*` identifiers while retaining the flow ID as
  separate evidence.
- A normalizer deployment permission fault was corrected. All three normalizer
  units are active on VM105 and VM108, and the release gate now waits for exact
  `active` state.
- Final Kafka snapshots showed zero normalizer and filter lag. A transient
  stream-correlation lag of 166 drained to zero; writer lag remained at 0-1.

## Web acceptance

The authenticated smoke test passed every Web/API surface, including dashboard,
incidents, sources, collectors, rules/content, cases, entities, vulnerability
runtime, response actions, storage HA and service-account token authentication.
The React application and VM107 Web, nginx, Keycloak and Vault services also
passed.

Fresh network probes returned approximately 0.03 seconds for SIEM Web and
ingest health, and 0.05 seconds for OPNsense Web. These are point-in-time
availability probes; page-level latency remains covered by the authenticated
smoke and API cache tests.

## Remote access status

The local VPN services are configured for autostart: Proxmox
`wg-quick@wg0`, VM107 `openvpn-client@home-gateway`, and
`siem-jump-tunnels` are active and enabled. Internal routes cover the SOC
segments.

Internet WireGuard access is not accepted in this record: the local interface
is up, but the configured peer currently reports no successful handshake. The
remote endpoint or upstream peer must become available before external
WireGuard E2E can be certified.

## Residual operational risks

- VM106 still boots from a highly fragmented QCOW image on mechanical storage
  (about 266,350 extents). Its ClickHouse hot data is already on NVMe, but the
  boot image should be moved or rewritten during a maintenance window.
- VM130 disk usage is about 83 percent and needs capacity monitoring before
  enabling additional Gamepanel workloads.

## Operational exclusions

Only CAPE Sandbox and disposable Windows detonation guests are intentionally
not deployed. Dynamic detonation must be placed on an isolated node without a
route to `mgmt` or `sec`.
