# Production Recovery And Rule Calibration - 2026-07-26

## Scope

This record covers the post-power recovery, segmented-network verification,
source-flow validation, full assignment-pack publication, and the final
false-positive remediation performed on 2026-07-26.

## Windows Workstation Shutdown

`WIN-RTX-test` is the operator workstation `DESKTOP-5JMJVBH` at
`192.168.3.81`. Windows event `User32/1074` at `2026-07-26 08:10:05 MSK`
records that `C:\Windows\System32\wlms\wlms.exe` initiated a planned shutdown
because the evaluation license period had expired.

The event was not caused by WHEA, NTFS, disk, dump, or current Kernel-Power
hardware failures. The installed edition is Windows Enterprise LTSC
Evaluation. `slmgr /xpr` reported a time-based activation ending on
`2026-10-24 12:40 MSK`; this is not a permanent repair. Replace the evaluation
installation or activate it with a valid license before that date.

The `RdegonSIEMCollector` scheduled task resumed after boot and continued to
deliver Windows events.

## Network And Service State

- Proxmox management: `192.168.3.101`.
- Operator workstation: `192.168.3.81`.
- Public SIEM demonstration endpoint: `https://192.168.3.102`.
- Internal SIEM Web endpoint: `10.20.10.107`.
- Internal ingest endpoint: `10.20.10.104`.
- Keycloak redirect and Web TLS SANs use `192.168.3.102`; the former
  `192.168.1.39` endpoint is not used for current SSO.
- `lab-edge-01` remains the active router/NGFW/VPN demonstration endpoint.
- OPNsense VM103 is running as a staged router with the segment gateways
  reachable, but it has not replaced `lab-edge-01` in a production cutover.

The five network zones remain `mgmt`, `sec`, `users`, `lab`, and
`servers/games`. Internal SIEM communication uses segmented addresses.

## NDR Recovery

The Zeek forwarder had accumulated a large spool after HTTP `413` responses:
the original 1000-event request exceeded the Nginx 1 MiB request limit.

The forwarder now:

- halves the delivery batch automatically after HTTP `413`;
- persists the accepted delivery batch size;
- keeps durable spool offsets;
- drains up to 16 delivery batches per cycle.

The live Zeek worker adapted to 500 events per request, drained the historical
backlog, and returned to a small steady-state spool without restarts.

## Vulnerability Scanner Placement

The secondary Nmap exporter was incorrectly installed on `navidrome-01` and
still targeted the legacy Web address `192.168.1.39`. Its authorized scan
created Suricata Nmap signatures and four correlated IDS false positives.

The corrected placement is:

- `navidrome-01`: scan timer disabled and removed from expected services;
- `vuln-mgr-01` (`10.20.30.122`): secondary Nmap timer enabled;
- targets: current `10.20.10.0/24`, `10.20.20.0/24`, and
  `10.20.30.0/24` service addresses only;
- recurring profile: service detection on the top 200 ports, two retries,
  and a three-minute host timeout;
- Greenbone/OpenVAS remains the deep vulnerability scanner.

The production E2E rerun scanned 20 reachable hosts in 203 seconds and posted
39 of 39 payloads through the vulnerability ingest endpoint. Suricata alerts
whose source is the dedicated scanner IP are tagged
`allowlist:siem_approved_scanner`; other source IPs are not suppressed.

A final real Nmap HTTP probe from `vuln-mgr-01` produced 20
`ET SCAN Possible Nmap User-Agent Observed` records. All 20 records passed
through rsyslog, ingest, Kafka, normalization, filtering, and ClickHouse. All
20 remained searchable with the scanner allowlist tag, while zero IDS
incidents were created. Filter rule `3016` now drops only approved-scanner
Windows network-logon failures; it no longer removes IDS evidence.

## Rule Changes

The complete 487-rule assignment pack was rebuilt and published:

- 355 active stream rules;
- 132 active batch rules;
- all 132 batch SQL templates validated against production ClickHouse;
- no retired runtime IDs.

Notable final calibrations:

- `PVE-016/8036`: explicit `qmreboot` or `qmreset` task tokens for critical
  VMIDs; ordinary `pvestatd` timings no longer match.
- `WIN-010/2607`: legitimate `SoftLanding` evaluation tasks excluded.
- `MET-002/8419`: five sustained host-runtime samples, 80 percent high
  samples, and average CPU above 90 percent are required.
- `HB-013/8013`: discovery is limited to current managed CIDRs; legacy
  `192.168.1.0/24` targets no longer create incidents.
- `CORR-S-002/8212`: absence of alerts is no longer treated as failure. The
  active rule now requires three unhealthy `siem-stream-corr` service
  snapshots.
- `DNS-005/8121`: segmented resolvers and the approved public resolvers
  `1.1.1.1` and `8.8.8.8` are allowed; an unknown external resolver still
  alerts.
- IDS `8102/8104/8106/8114`: authorized scanner traffic is suppressed by a
  narrow source-IP allowlist while unapproved scans remain detectable.

Historical false positives were marked `false_positive`; real historical
events were not deleted.

## Performance And Cleanup

The development `writer-shadow` consumer wrote only to `siem.events_shadow`
and had accumulated substantial lag while competing with production
ClickHouse writes. It was stopped and disabled, and only its Kafka consumer
group was deleted. Production `writer`, the second writer instance, and
`writer-standby` remain active.

Benchmark and synthetic cleanup is performed with
`deploy/cleanup_test_artifacts.py`. It deletes only explicitly marked test
events, alerts, history records, assets, and requested stream-state pairs.

The final production checks recorded:

- zero lag for normalizer and filter consumer groups;
- 22 events of stream-correlation lag;
- 185 events of writer lag, below one configured writer batch;
- 25 expected event sources fresh within 242 seconds;
- zero open raw alerts and zero open aggregate incidents;
- zero remaining explicitly marked benchmark, synthetic, or E2E artifacts
  in the cleanup dry-run;
- 29 enabled CMDB assets and no loopback, HTTP-update, or benchmark assets.

The complete local test suite passed with 610 tests and 51 subtests.

## Recovery Checklist

1. Confirm Proxmox and all required guests have `onboot` enabled.
2. Check `siem-kafka`, normalizer/filter workers, ClickHouse writers,
   correlators, alert aggregation, Web, Keycloak, and Vault.
3. Check Kafka lag for `normalizer`, `filter`, `writer`,
   `siem_stream_corr`, and `writer-standby`.
4. Check the Zeek forwarder logical pending bytes and recent journal errors.
5. Check source freshness in `siem.events` for every expected host.
6. Confirm Web redirects to `192.168.3.102` and Keycloak accepts the current
   callback.
7. Run the cleanup script in dry-run mode before any execute mode.
8. Re-run the 132-rule batch validator before publishing a rebuilt pack.
