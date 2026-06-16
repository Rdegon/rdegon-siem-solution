# SIEM Demo Video Recording Plan - 2026-05-24

This runbook is for recording a short defense video that proves the SIEM chain works end to end:

`source activity -> ingest -> Kafka/normalization -> ClickHouse events -> correlation -> alerts_raw -> alerts_agg -> Web UI incident`

Use controlled demo activity only. Prefer a unique `run_id` and avoid unmarked noisy tests.

## Short Video For The Presentation

Target duration: 90-120 seconds.

| Time | Screen | Action | Voiceover point |
| --- | --- | --- | --- |
| 0:00-0:12 | `/app/dashboards` or overview | Show counters: events, sources, open incidents, ClickHouse live | The system gives SOC operators a single view of telemetry and incidents. |
| 0:12-0:28 | `/app/sources` | Show Windows/Linux/network sources and freshness | Events come from multiple monitored sources, not from a manually edited database. |
| 0:28-0:48 | PowerShell terminal | Set `$runId` and run one or two benign simulations | Demo events are generated through real source activity and marked by a run id. |
| 0:48-1:08 | PowerShell terminal / watcher output | Run `demo_alert_watch.py` and show raw/aggregated alert records | Backend correlation writes alerts into ClickHouse and aggregation prepares incidents for UI. |
| 1:08-1:35 | `/app/incidents` | Filter/open incident for rule `2604`, `2605`, or `2708` | The operator sees severity, rule, entity, timestamps and context for investigation. |
| 1:35-2:00 | `/app/events` | Search by `demo-`, `EncodedCommand`, `RdegonDemoSvc`, or `siem-demo-invalid` | The source event remains searchable, so the alert can be traced back to evidence. |

If the video must be shorter, record only:

1. Overview dashboard.
2. Run `EncodedPowerShell`.
3. Show watcher output for rule `2604`.
4. Open the corresponding incident and event in the UI.

## Full Live Demo Backup

Target duration: 10-15 minutes.

1. Show the dashboard and explain the chain:
   `sources -> ingest -> Kafka -> normalizer/filter -> ClickHouse -> correlation -> incidents`.
2. Open `/app/sources`, `/app/collectors`, `/app/ingest`.
3. Open `/app/events`, filter a known source, then open one event and show normalized fields.
4. Run one controlled simulation wave.
5. Run the watcher and show `alerts_raw` plus `alerts_agg`.
6. Open `/app/incidents`, show rule id, severity, entity, samples and timestamps.
7. Open `/app/builders`, show active rule packs and stream rule runtime.
8. Refer to `docs/performance_eps_ladder_2026-05-23.md` for performance evidence.

## Commands

From the project root:

```powershell
$runId = "demo-" + (Get-Date -Format "yyyyMMddHHmmss")
```

Windows encoded PowerShell, no elevation required:

```powershell
powershell -ExecutionPolicy Bypass -File repo\tools\demo_attack_windows.ps1 `
  -Scenario EncodedPowerShell `
  -RunId $runId
```

Windows service install, elevated PowerShell required:

```powershell
powershell -ExecutionPolicy Bypass -File repo\tools\demo_attack_windows.ps1 `
  -Scenario ServiceInstall `
  -RunId $runId
```

Linux invalid SSH user burst. Use a monitored Linux source with SSH enabled:

```powershell
powershell -ExecutionPolicy Bypass -File repo\tools\demo_attack_ssh_invalid_user.ps1 `
  -TargetHost 192.168.1.39 `
  -Attempts 8 `
  -RunId $runId
```

Read-only watcher:

```powershell
python repo\tools\demo_alert_watch.py `
  --minutes 120 `
  --rules 2604,2605,2708 `
  --contains $runId `
  --wait-seconds 180 `
  --poll-interval 10 `
  --limit 30 `
  --output repo\runtime-control-plane\demo_alert_watch_$runId.json
```

If the alert context does not carry the run id, run the watcher without `--contains` and filter by the newest timestamps:

```powershell
python repo\tools\demo_alert_watch.py `
  --minutes 120 `
  --rules 2604,2605,2708 `
  --limit 30
```

## ClickHouse Queries

Open ClickHouse on VM3:

```powershell
ssh rdegon@192.168.1.38
clickhouse-client
```

Recent demo-marked events:

```sql
SELECT
    ts,
    event_id,
    device_product,
    log_source,
    host_name,
    event_code,
    event_action,
    user_name,
    process_name,
    left(process_command, 180) AS process_command,
    left(message, 220) AS message
FROM siem.events
WHERE ts >= now() - INTERVAL 2 HOUR
  AND (
      positionCaseInsensitiveUTF8(message, 'demo-') > 0
      OR positionCaseInsensitiveUTF8(normalized_json, 'demo-') > 0
      OR positionCaseInsensitiveUTF8(process_command, 'demo-') > 0
  )
ORDER BY ts DESC
LIMIT 50;
```

Raw alerts:

```sql
SELECT
    ts,
    rule_id,
    rule_name,
    severity,
    status,
    entity_key,
    hits,
    source,
    left(context_json, 500) AS context
FROM siem.alerts_raw
WHERE ts >= now() - INTERVAL 2 HOUR
  AND rule_id IN (2604, 2605, 2708)
ORDER BY ts DESC
LIMIT 30;
```

Aggregated incidents for UI:

```sql
SELECT
    ts_last,
    rule_id,
    rule_name,
    severity_agg,
    status,
    entity_key,
    count_alerts,
    unique_entities,
    left(samples_json, 500) AS samples
FROM siem.alerts_agg
WHERE ts_last >= now() - INTERVAL 2 HOUR
  AND rule_id IN (2604, 2605, 2708)
ORDER BY ts_last DESC
LIMIT 30;
```

## UI Filters

Use these terms in `/app/events`:

- `demo-`
- `EncodedCommand`
- `RdegonDemoSvc`
- `siem-demo-invalid`

Use these terms in `/app/incidents` or the rule filter:

- `2604`
- `2605`
- `2708`
- `Windows Encoded PowerShell Command`
- `Windows Service Installed`
- `Linux SSH Invalid User Burst`

## Recording Rules

- Do not show private keys, passwords, browser password manager popups, unrelated tabs, or administrative consoles that are not part of the demo.
- Keep the terminal large enough for the watcher JSON to be readable.
- Use one run id for the whole recording wave.
- Prefer one successful scenario over three rushed scenarios.
- If a correlation delay occurs, pause recording and resume after the watcher returns a result.
- Keep the final cut focused on proof: source activity, stored event, alert, aggregated incident, UI evidence.
