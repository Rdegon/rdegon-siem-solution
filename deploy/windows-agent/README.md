# Windows Agent Deployment Scripts

This directory contains the deployment scripts for the native Windows service agent.

## Scripts

- `build-windows-event-agent.ps1`
  - runs `dotnet publish`
  - falls back to `C:\Program Files\dotnet\dotnet.exe` if the current shell has not refreshed `PATH`
  - publishes the native control tool into `tools\control\`
- `package-windows-event-agent.ps1`
  - creates a self-contained release bundle
  - adds `INSTALL.md`, `bundle-manifest.json`, and the operator profile template
  - also builds a single-file `Rdegon.WindowsEventAgent.Setup.exe`
- `install-windows-event-agent.ps1`
  - installs the published agent as a Windows service
  - supports `-SkipServiceRegistration` to stage files and config without admin rights
- `uninstall-windows-event-agent.ps1`
  - removes the Windows service
- `get-windows-event-agent-status.ps1`
  - reads service state and the local runtime `status.json`

## Typical flow

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\deploy\windows-agent\build-windows-event-agent.ps1 -CreateZip
powershell.exe -ExecutionPolicy Bypass -File .\deploy\windows-agent\install-windows-event-agent.ps1 -BaseUrl "https://192.168.1.35" -StartAfterInstall
powershell.exe -ExecutionPolicy Bypass -File .\deploy\windows-agent\get-windows-event-agent-status.ps1 -Detailed
```

## Ready-to-ship packaging

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\deploy\windows-agent\package-windows-event-agent.ps1
```

This creates a self-contained release archive that already includes:

- the native service executable
- the native control executable
- `INSTALL.md`
- `windows-agent-profile.local.example.json`
- `bundle-manifest.json`
- a single-file setup executable in the release root

## Native control tool

The build bundle now contains `tools\control\Rdegon.WindowsEventAgent.Control.exe`.

Suggested operator flow:

```powershell
.\tools\control\Rdegon.WindowsEventAgent.Control.exe stage-config --profile C:\ops\windows-agent-profile.local.json
.\tools\control\Rdegon.WindowsEventAgent.Control.exe doctor --profile C:\ops\windows-agent-profile.local.json
.\tools\control\Rdegon.WindowsEventAgent.Control.exe install-service --profile C:\ops\windows-agent-profile.local.json --start
```

`install-service` can now copy the bundle from the unpacked archive into the final install directory before service registration.

## Single EXE setup flow

The release root now also contains `Rdegon.WindowsEventAgent.Setup-<version>-win-x64.exe`.

That executable embeds the bundle payload and can:

- print the install guide
- write the local operator profile template
- run `doctor`
- install, uninstall, start, stop, and restart the service

## Notes

- Registering the Windows service requires an elevated PowerShell session.
- In a non-elevated session you can still stage files and production config with `-SkipServiceRegistration`.
