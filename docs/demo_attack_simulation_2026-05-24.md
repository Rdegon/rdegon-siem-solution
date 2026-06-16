# Demo Attack Simulation - 2026-05-24

This demo path generates alerts through real source activity, not by inserting events into ClickHouse.

## Scenarios

| Script | Source activity | Expected rule |
| --- | --- | --- |
| `tools/demo_attack_windows.ps1 -Scenario EncodedPowerShell` | Runs a benign encoded PowerShell command on the Windows source | `2604 Windows Encoded PowerShell Command` |
| `tools/demo_attack_windows.ps1 -Scenario ServiceInstall` | Creates and removes a temporary benign Windows service | `2605 Windows Service Installed` |
| `tools/demo_attack_ssh_invalid_user.ps1` | Sends invalid SSH login attempts to a lab Linux source | `2708 Linux SSH Invalid User Burst` |

## Run

Use the same run id for the demo wave:

```powershell
$runId = "demo-" + (Get-Date -Format "yyyyMMddHHmmss")
```

Run Windows scenarios from the Windows source. `ServiceInstall` requires elevated PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File repo\tools\demo_attack_windows.ps1 -Scenario EncodedPowerShell -RunId $runId
powershell -ExecutionPolicy Bypass -File repo\tools\demo_attack_windows.ps1 -Scenario ServiceInstall -RunId $runId
```

Run Linux SSH invalid-user burst against a lab Linux source:

```powershell
powershell -ExecutionPolicy Bypass -File repo\tools\demo_attack_ssh_invalid_user.ps1 -TargetHost 10.20.30.123 -Attempts 8 -RunId $runId
```

If `10.20.30.123` is unreachable from the operator workstation, use another monitored Linux source with SSH enabled, for example `192.168.1.39`.

## Watch Alerts

Read-only ClickHouse check:

```powershell
python repo\tools\demo_alert_watch.py --minutes 60 --wait-seconds 180 --poll-interval 10 --output repo\runtime-control-plane\demo_alert_watch.json
```

Then open the SIEM UI and check `/app/incidents` and `/app/events`.

## Notes

- The scripts intentionally do not include `allowlist:` tags.
- The Windows service script removes the temporary service by default.
- The SSH script uses non-existent usernames and `NumberOfPasswordPrompts=0`; it should not authenticate.
- Do not run high attempt counts against hosts with aggressive lockout/fail2ban policy.
