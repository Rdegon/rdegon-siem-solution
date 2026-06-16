# Windows Collection Strategy

## Supported Collectors

Rdegon SIEM currently supports two Windows collection paths:

1. native Windows service agent for managed deployment and packaging
2. PowerShell collector for rapid onboarding only when a native rollout is not yet possible

## Native Windows Service Agent

Repo paths:

- `windows-event-agent/`
- `deploy/windows-agent/`
- `ops/windows-agent-profile.local.example.json`

Current capabilities:

- .NET Windows service host
- bookmark persistence
- spool-to-disk retry path
- runtime status file
- native control utility
- release packaging
- single-file setup executable packaging
- discovery-plane package generation for host-specific staged rollout

Typical workflow:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\deploy\windows-agent\build-windows-event-agent.ps1 -CreateZip
powershell.exe -ExecutionPolicy Bypass -File .\deploy\windows-agent\package-windows-event-agent.ps1
powershell.exe -ExecutionPolicy Bypass -File .\deploy\windows-agent\install-windows-event-agent.ps1 -BaseUrl "https://192.168.1.35" -StartAfterInstall
```

Discovery-plane workflow:

1. Open `Sources -> Discovery`.
2. Prepare the Windows onboarding job.
3. Generate the native-agent staging package.
4. Transfer the package to the endpoint or jump host.
5. Run `install-native-agent.cmd <shared-secret>` from an elevated shell.
6. Validate service/runtime state with `get-windows-event-agent-status.ps1 -Detailed`.

Runtime note:

- the live VM4 discovery plane now resolves package assets correctly both from the repo root and from the mirrored `services/web/app` runtime import path used in production deploys
- the standard VM4 rollout ships the Windows packaging scripts and example profile required for package generation; no separate manual file copy is needed on VM4

## PowerShell Collector

Repo paths:

- `deploy/windows/rdegon-siem-collector.ps1`
- `deploy/windows/rdegon-siem-bootstrap.cmd`

Use this path when:

- you need immediate stop-gap onboarding
- you cannot install the native service yet
- you need user-profile or scheduled-task based collection as an exception path

## Routing Targets

The Windows paths publish into:

- `/ingest/windows/base`
- `/ingest/windows/security`
- `/ingest/windows/sysmon`
- `/ingest/windows/powershell`

## Recommended Rollout

1. use the PowerShell collector for immediate coverage
2. move stable endpoints to the native service agent as the standard managed path
3. use discovery-plane package generation for repeatable host-specific staging
4. keep Sysmon optional per endpoint profile
5. use the packaged setup flow when reproducible release handling matters

## Operational Notes

- the current repo contains source and packaging scripts, not checked-in release bundles
- trusted TLS and VPN profile alignment are expected in the deployment profile
- MSI signing is out of scope for this pass and remains future hardening work
