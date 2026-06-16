# Rdegon Windows Event Agent

This directory contains the first scaffold of a native Windows service agent for shipping Windows Event Log telemetry into the existing Rdegon SIEM ingest routes.

## Current scope

- .NET Worker Service targeting Windows
- native Windows Service host
- polling of Security, System, Application, Sysmon, and PowerShell channels
- bookmark persistence on disk
- spool-to-disk fallback when ingest is unavailable
- runtime status file for operators
- HTTP batching into:
  - `/ingest/windows/base`
  - `/ingest/windows/security`
  - `/ingest/windows/sysmon`
  - `/ingest/windows/powershell`

## Project layout

- `src/Rdegon.WindowsEventAgent.Common/Rdegon.WindowsEventAgent.Common.csproj`
- `src/Rdegon.WindowsEventAgent/Rdegon.WindowsEventAgent.csproj`
- `src/Rdegon.WindowsEventAgent/Program.cs`
- `src/Rdegon.WindowsEventAgent/AgentOptions.cs`
- `src/Rdegon.WindowsEventAgent/BookmarkStore.cs`
- `src/Rdegon.WindowsEventAgent/DiskSpoolQueue.cs`
- `src/Rdegon.WindowsEventAgent/IngestHttpClient.cs`
- `src/Rdegon.WindowsEventAgent/WindowsEventPayloadFactory.cs`
- `src/Rdegon.WindowsEventAgent/WindowsEventCollectorService.cs`
- `src/Rdegon.WindowsEventAgent/appsettings.json`
- `src/Rdegon.WindowsEventAgent.Control/Rdegon.WindowsEventAgent.Control.csproj`
- `src/Rdegon.WindowsEventAgent.Control/AgentControlApp.cs`
- `src/Rdegon.WindowsEventAgent.Setup/Rdegon.WindowsEventAgent.Setup.csproj`
- `src/Rdegon.WindowsEventAgent.Setup/SetupApp.cs`

## Expected runtime directories

- `%ProgramData%\RdegonSIEM\WindowsEventAgent\bookmarks.json`
- `%ProgramData%\RdegonSIEM\WindowsEventAgent\status.json`
- `%ProgramData%\RdegonSIEM\WindowsEventAgent\spool\*.json`

`status.json` now also carries a live process snapshot so operators can inspect the agent's memory footprint and runtime shape without attaching extra tooling.

## Build and install

Example commands on a Windows host with the .NET SDK installed:

```powershell
dotnet restore .\src\Rdegon.WindowsEventAgent\Rdegon.WindowsEventAgent.csproj
dotnet publish .\src\Rdegon.WindowsEventAgent\Rdegon.WindowsEventAgent.csproj -c Release -r win-x64 --self-contained false -o .\publish
sc.exe create RdegonWindowsEventAgent binPath= "\"C:\path\to\publish\Rdegon.WindowsEventAgent.exe\"" start= auto
sc.exe start RdegonWindowsEventAgent
```

Repository deployment helpers now exist under `deploy/windows-agent/`. For example:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\deploy\windows-agent\build-windows-event-agent.ps1 -CreateZip
powershell.exe -ExecutionPolicy Bypass -File .\deploy\windows-agent\install-windows-event-agent.ps1 -BaseUrl "https://192.168.1.35" -StartAfterInstall
```

For final distributable archives, use:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\deploy\windows-agent\package-windows-event-agent.ps1
```

That release now also includes a single-file setup executable:

- `Rdegon.WindowsEventAgent.Setup-<version>-win-x64.exe`

If you are not in an elevated PowerShell session, use `-SkipServiceRegistration` to prepare files and `appsettings.Production.json` without creating the Windows service yet.

The publish bundle now also includes a native operator tool under `tools\control\Rdegon.WindowsEventAgent.Control.exe`. It supports:

- `status`
- `doctor`
- `stage-config`
- `install-service`
- `uninstall-service`
- `start`
- `stop`
- `restart`

Example:

```powershell
.\tools\control\Rdegon.WindowsEventAgent.Control.exe doctor --profile C:\ops\windows-agent-profile.local.json
.\tools\control\Rdegon.WindowsEventAgent.Control.exe install-service --profile C:\ops\windows-agent-profile.local.json --start
```

`install-service` now copies the bundle into the target install directory before registering the service, so the archive can be used as the primary install source on a Windows endpoint.

If you want to operate through exactly one executable, use the setup application:

```powershell
.\Rdegon.WindowsEventAgent.Setup.exe write-profile-template --output C:\Ops\windows-agent-profile.local.json
.\Rdegon.WindowsEventAgent.Setup.exe doctor --profile C:\Ops\windows-agent-profile.local.json
.\Rdegon.WindowsEventAgent.Setup.exe install-service --profile C:\Ops\windows-agent-profile.local.json --start
```

Use `ops/windows-agent-profile.local.example.json` as the template for the ignored local profile file that stores operator-specific values.

Useful debug modes:

```powershell
.\Rdegon.WindowsEventAgent.exe --run-once
.\Rdegon.WindowsEventAgent.exe --print-config
.\Rdegon.WindowsEventAgent.exe --print-status-path
```

Quick runtime footprint checks on a live host:

```powershell
.\tools\control\Rdegon.WindowsEventAgent.Control.exe status --profile C:\Ops\windows-agent-profile.local.json
Get-Process Rdegon.WindowsEventAgent | Select-Object Id,ProcessName,CPU,Handles,Threads,WS,PM
powershell.exe -ExecutionPolicy Bypass -File .\deploy\windows-agent\get-windows-event-agent-status.ps1 -Watch -Detailed
```

## Next hardening steps

1. Replace RecordId polling with richer bookmark support where needed.
2. Add health endpoint or named-pipe diagnostics.
3. Add MSI packaging.
4. Add longer-term metrics export or central resource telemetry.
5. Add integration tests on a Windows runner.
