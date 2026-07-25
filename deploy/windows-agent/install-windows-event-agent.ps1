param(
    [string]$PublishDir = ".\artifacts\windows-event-agent\win-x64\publish",
    [string]$InstallDir = "$env:ProgramFiles\Rdegon\WindowsEventAgent",
    [string]$StateDirectory = "$env:ProgramData\RdegonSIEM\WindowsEventAgent",
    [string]$ServiceName = "RdegonWindowsEventAgent",
    [string]$DisplayName = "Rdegon Windows Event Agent",
    [string]$BaseUrl = "https://192.168.3.102:8443",
    [string]$SharedSecret = "",
    [string]$InstanceName = "default",
    [switch]$AllowInvalidServerCertificate,
    [switch]$SkipServiceRegistration,
    [switch]$StartAfterInstall
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Resolve-PathSafe([string]$PathValue) {
    if ([System.IO.Path]::IsPathRooted($PathValue)) {
        return [System.IO.Path]::GetFullPath($PathValue)
    }

    return [System.IO.Path]::GetFullPath((Join-Path (Get-Location) $PathValue))
}

function Test-IsElevated() {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

$resolvedPublishDir = Resolve-PathSafe $PublishDir
$resolvedInstallDir = Resolve-PathSafe $InstallDir
$resolvedStateDirectory = Resolve-PathSafe $StateDirectory
$resolvedSpoolDirectory = Join-Path $resolvedStateDirectory "spool"
$exePath = Join-Path $resolvedInstallDir "Rdegon.WindowsEventAgent.exe"
$isElevated = Test-IsElevated

if (-not (Test-Path $resolvedPublishDir)) {
    throw "Publish directory not found: $resolvedPublishDir"
}

if (-not (Test-Path (Join-Path $resolvedPublishDir "Rdegon.WindowsEventAgent.exe"))) {
    throw "Agent executable not found in publish directory: $resolvedPublishDir"
}

New-Item -ItemType Directory -Path $resolvedInstallDir -Force | Out-Null
New-Item -ItemType Directory -Path $resolvedStateDirectory -Force | Out-Null
New-Item -ItemType Directory -Path $resolvedSpoolDirectory -Force | Out-Null

Copy-Item -Path (Join-Path $resolvedPublishDir "*") -Destination $resolvedInstallDir -Recurse -Force

$productionConfig = @{
    Agent = @{
        InstanceName = $InstanceName
        BaseUrl = $BaseUrl
        StateDirectory = $resolvedStateDirectory
        SpoolDirectory = $resolvedSpoolDirectory
        AllowInvalidServerCertificate = [bool]$AllowInvalidServerCertificate
    }
}

if ($SharedSecret) {
    $productionConfig.Agent.SharedSecret = $SharedSecret
}

$productionConfigPath = Join-Path $resolvedInstallDir "appsettings.Production.json"
($productionConfig | ConvertTo-Json -Depth 6) | Set-Content -Path $productionConfigPath -Encoding UTF8

$eventLogSourceRegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\Rdegon.WindowsEventAgent"
if ($isElevated -and -not (Test-Path $eventLogSourceRegistryPath)) {
    try {
        New-EventLog -LogName Application -Source "Rdegon.WindowsEventAgent"
    }
    catch {
        Write-Warning "Unable to create Windows Event Log source 'Rdegon.WindowsEventAgent'. Run installation from an elevated PowerShell session if Event Log registration is required."
    }
} elseif (-not $isElevated) {
    Write-Warning "Skipping Windows Event Log source registration because the current PowerShell session is not elevated."
}

if (-not $SkipServiceRegistration) {
    if (-not $isElevated) {
        throw "Administrator privileges are required to register the Windows service. Re-run from an elevated PowerShell session or use -SkipServiceRegistration to stage files and configuration only."
    }

    $existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($existingService) {
        if ($existingService.Status -ne "Stopped") {
            Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
        }
        & sc.exe delete $ServiceName | Out-Null
        Start-Sleep -Seconds 2
    }

    New-Service -Name $ServiceName -BinaryPathName "`"$exePath`"" -DisplayName $DisplayName -Description "Native Windows Event Log collector for Rdegon SIEM." -StartupType Automatic
    & sc.exe config $ServiceName start= delayed-auto | Out-Null
    & sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/15000/restart/60000 | Out-Null

    Write-Host "Installed $ServiceName"
} else {
    Write-Host "Prepared agent files and configuration without registering the Windows service."
}

Write-Host "Executable: $exePath"
Write-Host "State directory: $resolvedStateDirectory"
Write-Host "Production config: $productionConfigPath"

if ($StartAfterInstall -and -not $SkipServiceRegistration) {
    Start-Service -Name $ServiceName
    Write-Host "Started $ServiceName"
} elseif ($StartAfterInstall -and $SkipServiceRegistration) {
    Write-Warning "StartAfterInstall was ignored because -SkipServiceRegistration was used."
}
