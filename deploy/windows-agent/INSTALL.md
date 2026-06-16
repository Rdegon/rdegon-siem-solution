# Rdegon Windows Event Agent: Install and Operations

This bundle contains a native Windows service agent and a native control application.

If you prefer working through exactly one executable, use the packaged setup application from the release root:

- `Rdegon.WindowsEventAgent.Setup-<version>-win-x64.exe`

## Bundle contents

- `Rdegon.WindowsEventAgent.exe`
- `appsettings.json`
- `tools\control\Rdegon.WindowsEventAgent.Control.exe`
- `get-windows-event-agent-status.ps1`
- `windows-agent-profile.local.example.json`
- `bundle-manifest.json`

## Before you install

1. Unzip the bundle on the target Windows host.
2. Copy `windows-agent-profile.local.example.json` to a local file such as:
   - `C:\Ops\windows-agent-profile.local.json`
3. Edit the local profile and set:
   - `baseUrl`
   - `sharedSecret`
   - `instanceName`
   - optional custom `installDir`, `stateDirectory`, `serviceName`, and `displayName`

## Recommended install flow

Open an elevated PowerShell session in the unzipped bundle root.

## Single EXE flow

The setup executable is the easiest operator entrypoint:

```powershell
.\Rdegon.WindowsEventAgent.Setup.exe write-profile-template --output C:\Ops\windows-agent-profile.local.json
.\Rdegon.WindowsEventAgent.Setup.exe doctor --profile C:\Ops\windows-agent-profile.local.json
.\Rdegon.WindowsEventAgent.Setup.exe install-service --profile C:\Ops\windows-agent-profile.local.json --start
```

## Bundle flow

Run a dry diagnostics pass first:

```powershell
.\tools\control\Rdegon.WindowsEventAgent.Control.exe doctor --profile C:\Ops\windows-agent-profile.local.json
```

If diagnostics look good, install and start the service:

```powershell
.\tools\control\Rdegon.WindowsEventAgent.Control.exe install-service --profile C:\Ops\windows-agent-profile.local.json --start
```

What this does:

- copies the bundle into the target install directory
- writes `appsettings.Production.json`
- registers the Windows service
- configures delayed auto-start
- configures service restart actions

## Common operator commands

Check status:

```powershell
.\tools\control\Rdegon.WindowsEventAgent.Control.exe status --profile C:\Ops\windows-agent-profile.local.json
```

Quick resource check from the host:

```powershell
Get-Process Rdegon.WindowsEventAgent | Select-Object Id,ProcessName,CPU,Handles,Threads,WS,PM
```

Live JSON watch for service health and memory:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\get-windows-event-agent-status.ps1 -Watch -Detailed
```

Run diagnostics:

```powershell
.\tools\control\Rdegon.WindowsEventAgent.Control.exe doctor --profile C:\Ops\windows-agent-profile.local.json
```

Restart the service:

```powershell
.\tools\control\Rdegon.WindowsEventAgent.Control.exe restart --profile C:\Ops\windows-agent-profile.local.json
```

Uninstall the service:

```powershell
.\tools\control\Rdegon.WindowsEventAgent.Control.exe uninstall-service --profile C:\Ops\windows-agent-profile.local.json
```

Remove install and state directories too:

```powershell
.\tools\control\Rdegon.WindowsEventAgent.Control.exe uninstall-service --profile C:\Ops\windows-agent-profile.local.json --remove-install-dir --remove-state-dir
```

## Runtime files on the endpoint

- `%ProgramData%\RdegonSIEM\WindowsEventAgent\bookmarks.json`
- `%ProgramData%\RdegonSIEM\WindowsEventAgent\status.json`
- `%ProgramData%\RdegonSIEM\WindowsEventAgent\spool\`

`status.json` now contains a `process` section with the current PID, working set, private memory, paged memory, virtual memory, handles, threads, CPU time, and uptime.

## Notes

- `install-service`, `uninstall-service`, `start`, `stop`, and `restart` require an elevated PowerShell session.
- `doctor` returns a non-zero exit code if critical checks fail.
- A missing `Microsoft-Windows-Sysmon/Operational` channel means Sysmon is not installed on that host yet.
- `allowInvalidServerCertificate=true` should only be used in lab environments.
