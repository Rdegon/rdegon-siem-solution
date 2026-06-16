param(
    [string]$VersionLabel = "20260322-remote-vpn",
    [string]$SetupExePath = "C:\Users\lolol\Documents\Playground\remote-edit2\artifacts\windows-event-agent\releases\20260322-current-install-v2\Rdegon.WindowsEventAgent.Setup-20260322-current-install-v2-win-x64.exe",
    [string]$BundleZipPath = "C:\Users\lolol\Documents\Playground\remote-edit2\artifacts\windows-event-agent\releases\20260322-current-install-v2\Rdegon.WindowsEventAgent-20260322-current-install-v2-win-x64.zip",
    [string]$BaseOpenVpnProfilePath = "",
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
$resolvedBundleZipPath = Resolve-AbsolutePath -PathValue $BundleZipPath -BaseDirectory $repoRoot

if (-not (Test-Path -LiteralPath $resolvedSetupExePath)) {
    throw "Setup exe not found: $resolvedSetupExePath"
}

if (-not (Test-Path -LiteralPath $resolvedBundleZipPath)) {
    throw "Bundle zip not found: $resolvedBundleZipPath"
}

if ([string]::IsNullOrWhiteSpace($OutputRoot)) {
    $OutputRoot = Join-Path $repoRoot "artifacts\windows-event-agent\remote-vpn-kit\$VersionLabel"
}

$resolvedOutputRoot = Resolve-AbsolutePath -PathValue $OutputRoot -BaseDirectory $repoRoot
$packageRoot = Join-Path $resolvedOutputRoot "package"
$openVpnOutputRoot = Join-Path $packageRoot "openvpn"
$sharedLabOutputRoot = Join-Path $openVpnOutputRoot "shared-lab"
$profileOutputRoot = Join-Path $packageRoot "agent-profiles"

if (Test-Path -LiteralPath $resolvedOutputRoot) {
    Remove-Item -LiteralPath $resolvedOutputRoot -Recurse -Force
}

[System.IO.Directory]::CreateDirectory($sharedLabOutputRoot) | Out-Null
[System.IO.Directory]::CreateDirectory($profileOutputRoot) | Out-Null

Copy-Item -LiteralPath $resolvedSetupExePath -Destination (Join-Path $packageRoot "Rdegon.WindowsEventAgent.Setup-win-x64.exe") -Force
Copy-Item -LiteralPath $resolvedBundleZipPath -Destination (Join-Path $packageRoot "Rdegon.WindowsEventAgent.bundle-win-x64.zip") -Force
Copy-Item -LiteralPath (Join-Path $PSScriptRoot "build-openvpn-route-profile.ps1") -Destination (Join-Path $openVpnOutputRoot "build-openvpn-route-profile.ps1") -Force
Copy-Item -LiteralPath (Join-Path $repoRoot "docs\windows_agent_remote_vpn.md") -Destination (Join-Path $packageRoot "REMOTE_VPN_WINDOWS_AGENT_GUIDE.md") -Force

Get-ChildItem -LiteralPath $PSScriptRoot -File -Filter "openvpn-routes-*.txt" |
    ForEach-Object {
        Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $openVpnOutputRoot $_.Name) -Force
    }

Get-ChildItem -LiteralPath $PSScriptRoot -File -Filter "remote-vpn-profile-*.json" |
    ForEach-Object {
        Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $profileOutputRoot $_.Name) -Force
    }

@'
OpenVPN path for remote Windows sources
======================================

1. Import one of the .ovpn files from openvpn\shared-lab into OpenVPN Connect.
2. Connect the tunnel.
3. Verify access to the ingest edge:
   Test-NetConnection 192.168.1.35 -Port 443
4. Choose a profile from agent-profiles\ and install the agent:
   .\Rdegon.WindowsEventAgent.Setup-win-x64.exe doctor --profile .\agent-profiles\<profile>.json
   .\Rdegon.WindowsEventAgent.Setup-win-x64.exe install-service --profile .\agent-profiles\<profile>.json --start

Read REMOTE_VPN_WINDOWS_AGENT_GUIDE.md before sending this kit to other people.
'@ | Set-Content -Path (Join-Path $packageRoot "README_FIRST.txt") -Encoding ASCII

@'
Security note
=============

This kit may include prebuilt OpenVPN profiles generated from one existing inline lab client profile.
That is convenient for lab rollout, but it is not a strong production model for broad distribution.

Recommended long-term path:
- issue a separate inline OpenVPN profile per person or site
- rebuild the route-limited .ovpn files with openvpn\build-openvpn-route-profile.ps1
- rotate client certificates if a package leaves your control

The Windows agent profiles in this kit contain the current ingest shared secret and should be treated as sensitive.
'@ | Set-Content -Path (Join-Path $packageRoot "SECURITY_NOTE.md") -Encoding ASCII

if (-not [string]::IsNullOrWhiteSpace($BaseOpenVpnProfilePath)) {
    $resolvedBaseOpenVpnProfilePath = Resolve-AbsolutePath -PathValue $BaseOpenVpnProfilePath -BaseDirectory $repoRoot
    if (-not (Test-Path -LiteralPath $resolvedBaseOpenVpnProfilePath)) {
        throw "Base OpenVPN profile not found: $resolvedBaseOpenVpnProfilePath"
    }

    $presets = @(
        @{ Name = "siem-ingest-only"; Output = "01-siem-ingest-only.shared-lab.ovpn" },
        @{ Name = "siem-ingest-and-web"; Output = "02-siem-ingest-and-web.shared-lab.ovpn" },
        @{ Name = "siem-core-admin"; Output = "03-siem-core-admin.shared-lab.ovpn" },
        @{ Name = "siem-full-lab"; Output = "04-siem-full-lab.shared-lab.ovpn" },
        @{ Name = "siem-operator-debug"; Output = "05-siem-operator-debug.shared-lab.ovpn" }
    )

    foreach ($preset in $presets) {
        & (Join-Path $PSScriptRoot "build-openvpn-route-profile.ps1") `
            -BaseProfilePath $resolvedBaseOpenVpnProfilePath `
            -PresetName $preset.Name `
            -OutputPath (Join-Path $sharedLabOutputRoot $preset.Output) | Out-Null
    }
}
else {
    @'
No base inline OpenVPN profile was supplied to package-remote-vpn-kit.ps1.
Use openvpn\build-openvpn-route-profile.ps1 together with your per-user inline profile
to generate route-limited .ovpn files from the route preset files in this folder.
'@ | Set-Content -Path (Join-Path $sharedLabOutputRoot "BUILD_FROM_YOUR_OWN_INLINE_PROFILE.txt") -Encoding ASCII
}

$archivePath = Join-Path $resolvedOutputRoot "Rdegon.WindowsEventAgent-remote-vpn-distribution-kit.zip"
Compress-Archive -Path (Join-Path $packageRoot "*") -DestinationPath $archivePath -CompressionLevel Optimal -Force
Write-Output $archivePath
