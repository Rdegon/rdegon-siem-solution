param(
    [string]$VersionLabel = "20260322-remote-vpn-person-kits",
    [string]$SetupExePath = "C:\Users\lolol\Documents\Playground\remote-edit2\artifacts\windows-event-agent\releases\20260322-current-install-v2\Rdegon.WindowsEventAgent.Setup-20260322-current-install-v2-win-x64.exe",
    [Parameter(Mandatory = $true)]
    [string]$BaseOpenVpnProfilePath,
    [string]$OutputRoot = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Resolve-AbsolutePath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PathValue,

        [string]$BaseDirectory = (Get-Location).Path
    )

    $expanded = [Environment]::ExpandEnvironmentVariables($PathValue.Trim())
    if ([System.IO.Path]::IsPathRooted($expanded)) {
        return [System.IO.Path]::GetFullPath($expanded)
    }

    return [System.IO.Path]::GetFullPath((Join-Path $BaseDirectory $expanded))
}

$repoRoot = Resolve-AbsolutePath -PathValue (Join-Path $PSScriptRoot "..\..")
$resolvedSetupExePath = Resolve-AbsolutePath -PathValue $SetupExePath -BaseDirectory $repoRoot
$resolvedBaseOpenVpnProfilePath = Resolve-AbsolutePath -PathValue $BaseOpenVpnProfilePath -BaseDirectory $repoRoot

if (-not (Test-Path -LiteralPath $resolvedSetupExePath)) {
    throw "Setup exe not found: $resolvedSetupExePath"
}

if (-not (Test-Path -LiteralPath $resolvedBaseOpenVpnProfilePath)) {
    throw "Base OpenVPN profile not found: $resolvedBaseOpenVpnProfilePath"
}

if ([string]::IsNullOrWhiteSpace($OutputRoot)) {
    $OutputRoot = Join-Path $repoRoot "artifacts\windows-event-agent\remote-vpn-kit\$VersionLabel"
}

$resolvedOutputRoot = Resolve-AbsolutePath -PathValue $OutputRoot -BaseDirectory $repoRoot
if (Test-Path -LiteralPath $resolvedOutputRoot) {
    Remove-Item -LiteralPath $resolvedOutputRoot -Recurse -Force
}

[System.IO.Directory]::CreateDirectory($resolvedOutputRoot) | Out-Null

$packages = @(
    @{
        Name = "person-01-standard-no-sysmon"
        OpenVpnPreset = "siem-ingest-only"
        AgentProfile = "remote-vpn-profile-01-windows-agent-vpn-ingest-only-no-sysmon.json"
        Scenario = "Standard remote Windows host without Sysmon."
    },
    @{
        Name = "person-02-standard-sysmon"
        OpenVpnPreset = "siem-ingest-only"
        AgentProfile = "remote-vpn-profile-02-windows-agent-vpn-ingest-only-sysmon.json"
        Scenario = "Standard remote Windows host with Sysmon already installed."
    },
    @{
        Name = "person-03-high-latency-no-sysmon"
        OpenVpnPreset = "siem-ingest-only"
        AgentProfile = "remote-vpn-profile-03-windows-agent-vpn-high-latency-no-sysmon.json"
        Scenario = "Remote Windows host on a slower or less stable link, without Sysmon."
    },
    @{
        Name = "person-04-high-latency-sysmon"
        OpenVpnPreset = "siem-ingest-only"
        AgentProfile = "remote-vpn-profile-04-windows-agent-vpn-high-latency-sysmon.json"
        Scenario = "Remote Windows host on a slower or less stable link, with Sysmon."
    },
    @{
        Name = "person-05-catchup-no-sysmon"
        OpenVpnPreset = "siem-ingest-only"
        AgentProfile = "remote-vpn-profile-05-windows-agent-vpn-catchup-no-sysmon.json"
        Scenario = "Remote Windows host expected to drain a backlog quickly after reconnect."
    }
)

foreach ($package in $packages) {
    $packageRoot = Join-Path $resolvedOutputRoot $package.Name
    [System.IO.Directory]::CreateDirectory($packageRoot) | Out-Null

    Copy-Item -LiteralPath $resolvedSetupExePath -Destination (Join-Path $packageRoot "Rdegon.WindowsEventAgent.Setup-win-x64.exe") -Force
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot $package.AgentProfile) -Destination (Join-Path $packageRoot "windows-agent-profile.current-install.json") -Force
    Copy-Item -LiteralPath (Join-Path $repoRoot "docs\windows_agent_remote_vpn.md") -Destination (Join-Path $packageRoot "REMOTE_VPN_WINDOWS_AGENT_GUIDE.md") -Force
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot "get-windows-event-agent-status.ps1") -Destination (Join-Path $packageRoot "get-windows-event-agent-status.ps1") -Force

    & (Join-Path $PSScriptRoot "build-openvpn-route-profile.ps1") `
        -BaseProfilePath $resolvedBaseOpenVpnProfilePath `
        -PresetName $package.OpenVpnPreset `
        -OutputPath (Join-Path $packageRoot "remote-vpn-access.ovpn") | Out-Null

    @"
$($package.Scenario)

1. Import remote-vpn-access.ovpn into OpenVPN Connect.
2. Connect the tunnel.
3. Verify access:
   Test-NetConnection 192.168.1.35 -Port 443
4. Install the agent:
   .\Rdegon.WindowsEventAgent.Setup-win-x64.exe doctor --profile .\windows-agent-profile.current-install.json
   .\Rdegon.WindowsEventAgent.Setup-win-x64.exe install-service --profile .\windows-agent-profile.current-install.json --start
5. Watch resource usage after install:
   powershell.exe -ExecutionPolicy Bypass -File .\get-windows-event-agent-status.ps1 -Watch -Detailed

Notes:
- instanceName uses AUTO_MACHINE_NAME, so the agent will tag itself with the local computer name.
- this package uses the current lab ingest secret and a shared-lab OpenVPN identity.
"@ | Set-Content -Path (Join-Path $packageRoot "README_FIRST.txt") -Encoding ASCII

    @'
Security note
=============

This package contains:
- a working inline OpenVPN client profile
- the current Windows agent ingest profile with the current ingest shared secret

Treat the whole package as sensitive.
If you distribute beyond a controlled lab, replace the OpenVPN profile with a per-user inline client profile.
'@ | Set-Content -Path (Join-Path $packageRoot "SECURITY_NOTE.md") -Encoding ASCII

    $archivePath = Join-Path $resolvedOutputRoot ("{0}.zip" -f $package.Name)
    Compress-Archive -Path (Join-Path $packageRoot "*") -DestinationPath $archivePath -CompressionLevel Optimal -Force
}

Get-ChildItem -LiteralPath $resolvedOutputRoot -Filter "*.zip" | Select-Object FullName
