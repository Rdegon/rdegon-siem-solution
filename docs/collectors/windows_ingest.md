# Windows Collection Foundation

Rdegon SIEM now contains a first-pass Windows normalizer for:

- Winlogbeat / Logstash-style JSON
- Windows Event XML
- Sysmon event payloads shipped as JSON or XML

Supported normalized event families:

- `windows_logon_success` (`4624`)
- `windows_logon_failure` (`4625`)
- `windows_explicit_credentials_logon` (`4648`)
- `windows_special_privileges_assigned` (`4672`)
- `windows_process_create` (`4688`, Sysmon `1`)
- `windows_network_connection` (Sysmon `3`)
- `windows_password_changed` (`4723`)
- `windows_password_reset` (`4724`)
- `windows_user_created` (`4720`)
- `windows_user_deleted` (`4726`)
- `windows_user_added_to_privileged_group` (`4728`, `4732`, `4756`)
- `windows_scheduled_task_created` (`4698`)
- `windows_audit_policy_changed` (`4719`)
- `windows_service_installed` (`7045`)
- `windows_audit_log_cleared` (`1102`)
- `windows_firewall_connection` (`5156`, `5157`)
- `windows_defender_malware_detected` (`1116`)
- `windows_defender_configuration_changed` (`5007`)
- `windows_rdp_auth_success` (`1149`)
- `windows_wmi_activity` (`5857`-`5861`)
- `windows_powershell_encoded_command`

## Recommended shipping options

1. Built-in PowerShell collector -> best fit today, because it already matches the current ingest and normalizer path.
2. Fluent Bit -> open source Windows agent option for later rollout, but it needs a schema adapter before it can replace the bundled collector cleanly.
3. Windows Event Forwarding (WEF/WEC) -> native Windows aggregation model for domain environments; forward from WEC into SIEM.
4. OpenTelemetry Collector Contrib -> future option once the ingest side exposes OTLP or a compatible adapter.

## Built-in collector deployment

Repository artifact:

- `deploy/windows/rdegon-siem-collector.ps1`
- `deploy/windows/rdegon-siem-bootstrap.cmd`

What it does:

- reads Security / System / Application / Sysmon / PowerShell plus Defender / WMI / RDP / Task Scheduler / WinRM channels
- tracks the last delivered `RecordId` per channel
- can use legacy dedicated ports (`9440`-`9443`) or path routing under one HTTPS base URL
- path routing sends to `/ingest/windows/base`, `/ingest/windows/security`, `/ingest/windows/sysmon`, `/ingest/windows/powershell`
- can attach `x-rdegon-ingest-secret` when the ingest runtime requires a shared secret
- can install itself as a scheduled task that runs every minute

Minimal deployment on a Windows host:

```powershell
powershell -ExecutionPolicy Bypass -File .\rdegon-siem-collector.ps1 -BaseUrl "https://192.168.1.35"
powershell -ExecutionPolicy Bypass -File .\rdegon-siem-collector.ps1 -InstallTask
```

Single-URL deployment through the main ingest base URL:

```powershell
powershell -ExecutionPolicy Bypass -File .\rdegon-siem-collector.ps1 -BaseUrl "https://192.168.1.35" -RoutingMode paths
```

If the ingest runtime uses a shared secret:

```powershell
powershell -ExecutionPolicy Bypass -File .\rdegon-siem-collector.ps1 -BaseUrl "https://192.168.1.35" -RoutingMode paths -SharedSecret "<shared-secret>"
```

If you do not have remote administrator rights on the Windows endpoint but you can write into the user's profile, place both files into `%USERPROFILE%\Documents\RdegonSIEM` and put `rdegon-siem-bootstrap.cmd` into the user's Startup folder. At the next interactive logon it will create a user-level scheduled task `RdegonSIEMCollector` that runs every 5 minutes and stores state in `%LOCALAPPDATA%\RdegonSIEM\collector-state.json`.

The discovery plane can now generate a per-host onboarding package with the collector, installer, and operator notes under the runtime control-plane artifact directory.

Notes:

- for Sysmon coverage, Sysmon must already be installed on the endpoint
- the collector accepts the current lab self-signed certificate
- if you move to a trusted TLS certificate, remove the permissive certificate callback from the script

## Minimal JSON example

```json
{
  "source_type": "json",
  "message": "{\"winlog\":{\"event_id\":4625,\"channel\":\"Security\",\"computer_name\":\"win-lab-01\",\"event_data\":{\"TargetUserName\":\"Administrator\",\"IpAddress\":\"10.10.10.5\",\"IpPort\":\"49823\",\"LogonType\":\"3\"}},\"event\":{\"code\":\"4625\"},\"host\":{\"name\":\"win-lab-01\"}}",
  "source": "10.10.10.10"
}
```

## Minimal XML example

```xml
<Event>
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" />
    <EventID>4625</EventID>
    <Channel>Security</Channel>
    <Computer>win-lab-01</Computer>
  </System>
  <EventData>
    <Data Name="TargetUserName">Administrator</Data>
    <Data Name="IpAddress">10.10.10.5</Data>
    <Data Name="IpPort">49823</Data>
  </EventData>
</Event>
```

## Initial Windows detections

- Windows Logon Failure Burst
- Windows Audit Log Cleared
- Windows Privileged Group Membership Changed
- Windows Suspicious PowerShell Encoded Command
- Windows Service Installed
- Windows User Created
