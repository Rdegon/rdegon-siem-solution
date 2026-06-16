param(
    [string]$InstallDir = "$env:ProgramFiles\Rdegon\WindowsEventAgent",
    [string]$StateDirectory = "$env:ProgramData\RdegonSIEM\WindowsEventAgent",
    [string]$ServiceName = "RdegonWindowsEventAgent",
    [string]$TaskName = "RdegonSIEMCollector",
    [string]$RepoRoot = "",
    [switch]$InstallSysmon
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Test-IsElevated {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Resolve-ScriptRoot {
    return Split-Path -Parent $PSCommandPath
}

function Resolve-StatusScriptPath([string]$ScriptRoot, [string]$ResolvedRepoRoot) {
    $localPath = Join-Path $ScriptRoot "get-windows-event-agent-status.ps1"
    if (Test-Path $localPath) {
        return $localPath
    }
    $repoPath = Join-Path $ResolvedRepoRoot "deploy\windows-agent\get-windows-event-agent-status.ps1"
    if (Test-Path $repoPath) {
        return $repoPath
    }
    throw "Unable to resolve get-windows-event-agent-status.ps1."
}

function Resolve-RepoRoot([string]$ExplicitRepoRoot, [string]$ScriptRoot) {
    $candidates = @()
    if ($ExplicitRepoRoot) {
        $candidates += $ExplicitRepoRoot
    }
    if ($env:SIEM_REPO_ROOT) {
        $candidates += $env:SIEM_REPO_ROOT
    }
    $candidates += @(
        (Split-Path -Parent (Split-Path -Parent $ScriptRoot)),
        (Join-Path $env:USERPROFILE "Projects\siem_xfer_2026-03-25\repo"),
        (Join-Path $env:USERPROFILE "Projects\siem_xfer_2026-03-25"),
        (Get-Location).Path
    )
    foreach ($candidate in $candidates) {
        if (-not $candidate) {
            continue
        }
        try {
            $resolvedCandidate = [System.IO.Path]::GetFullPath($candidate)
            $directAppSettings = Join-Path $resolvedCandidate "windows-event-agent\src\Rdegon.WindowsEventAgent\appsettings.json"
            if (Test-Path $directAppSettings) {
                return $resolvedCandidate
            }
            $nestedRepoAppSettings = Join-Path $resolvedCandidate "repo\windows-event-agent\src\Rdegon.WindowsEventAgent\appsettings.json"
            if (Test-Path $nestedRepoAppSettings) {
                return (Join-Path $resolvedCandidate "repo")
            }
        } catch {
        }
    }
    throw "Unable to resolve repo root. Pass -RepoRoot explicitly or set SIEM_REPO_ROOT."
}

function Ensure-Elevated {
    if (-not (Test-IsElevated)) {
        throw "Run this script from an elevated PowerShell session."
    }
}

function Read-JsonFile([string]$PathValue) {
    if (-not (Test-Path $PathValue)) {
        return $null
    }
    return Get-Content -Raw -Path $PathValue | ConvertFrom-Json
}

function Write-JsonFile([string]$PathValue, $Payload) {
    ($Payload | ConvertTo-Json -Depth 16) | Set-Content -Path $PathValue -Encoding UTF8
}

function Enable-EventChannel([string]$ChannelName) {
    try {
        & wevtutil.exe set-log $ChannelName /enabled:true | Out-Null
    } catch {
        Write-Warning ("Failed to enable event channel {0}: {1}" -f $ChannelName, $_.Exception.Message)
    }
}

function Get-ChannelWatermarks($ResolvedProductionConfig) {
    $watermarks = @{}
    foreach ($channel in @($ResolvedProductionConfig.agent.channels)) {
        if (-not $channel.enabled) {
            continue
        }
        $channelName = [string]$channel.name
        if (-not $channelName) {
            continue
        }
        try {
            $event = Get-WinEvent -LogName $channelName -MaxEvents 1 -ErrorAction Stop
            if ($event) {
                $watermarks[$channelName] = [int64]$event.RecordId
                continue
            }
        } catch {
        }
        $watermarks[$channelName] = 0
    }
    return $watermarks
}

function Ensure-Sysmon([string]$TempDirectory, [string]$ConfigPath) {
    $zipPath = Join-Path $TempDirectory "Sysmon.zip"
    $extractDir = Join-Path $TempDirectory "Sysmon"
    if (Test-Path $extractDir) {
        Remove-Item -LiteralPath $extractDir -Recurse -Force
    }
    Invoke-WebRequest -UseBasicParsing -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile $zipPath
    Expand-Archive -LiteralPath $zipPath -DestinationPath $extractDir -Force
    $sysmonExe = Join-Path $extractDir "Sysmon64.exe"
    if (-not (Test-Path $sysmonExe)) {
        throw "Sysmon64.exe was not found after archive extraction."
    }
    $existing = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
    if ($existing) {
        & $sysmonExe -accepteula -c $ConfigPath | Out-Null
    } else {
        & $sysmonExe -accepteula -i $ConfigPath | Out-Null
    }
}

function Read-AgentRuntimeStatus([string]$ResolvedStateDirectory) {
    $statusPath = Join-Path $ResolvedStateDirectory "status.json"
    if (-not (Test-Path $statusPath)) {
        return $null
    }
    return Get-Content -Raw -Path $statusPath | ConvertFrom-Json
}

function Get-RecentAgentErrors([int]$LookbackMinutes = 10) {
    try {
        return @(Get-WinEvent -FilterHashtable @{
                LogName = "Application"
                ProviderName = "Rdegon.WindowsEventAgent"
                StartTime = (Get-Date).AddMinutes(-1 * [Math]::Max(1, $LookbackMinutes))
                Level = 2
            } -MaxEvents 10 -ErrorAction Stop)
    } catch {
        return @()
    }
}

function Install-SystemCollectorFallback([string]$ResolvedRepoRoot, [string]$ResolvedTaskName, $ResolvedProductionConfig) {
    $collectorSourcePath = Join-Path $ResolvedRepoRoot "deploy\windows\rdegon-siem-collector.ps1"
    if (-not (Test-Path $collectorSourcePath)) {
        throw "Collector source script not found: $collectorSourcePath"
    }
    $collectorDirectory = Join-Path $env:ProgramData "RdegonSIEM"
    $collectorDestinationPath = Join-Path $collectorDirectory "rdegon-siem-collector.ps1"
    $collectorStatePath = Join-Path $collectorDirectory "collector-state.json"
    New-Item -ItemType Directory -Path $collectorDirectory -Force | Out-Null
    Copy-Item -LiteralPath $collectorSourcePath -Destination $collectorDestinationPath -Force

    $watermarks = Get-ChannelWatermarks -ResolvedProductionConfig $ResolvedProductionConfig
    ($watermarks | ConvertTo-Json -Depth 6) | Set-Content -Path $collectorStatePath -Encoding UTF8

    $arguments = @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", $collectorDestinationPath,
        "-InstallTask",
        "-TaskName", $ResolvedTaskName,
        "-StatePath", $collectorStatePath,
        "-BatchSize", "40",
        "-MaxSendBatch", "10",
        "-BaseUrl", [string]$ResolvedProductionConfig.agent.baseUrl,
        "-RoutingMode", "paths"
    )
    if ($ResolvedProductionConfig.agent.sharedSecret) {
        $arguments += @("-SharedSecret", [string]$ResolvedProductionConfig.agent.sharedSecret)
    }
    & powershell.exe @arguments
    Start-ScheduledTask -TaskName $ResolvedTaskName
}

Ensure-Elevated

$scriptRoot = Resolve-ScriptRoot
$repoRoot = Resolve-RepoRoot -ExplicitRepoRoot $RepoRoot -ScriptRoot $scriptRoot
$statusScriptPath = Resolve-StatusScriptPath -ScriptRoot $scriptRoot -ResolvedRepoRoot $repoRoot
$repoAppSettingsPath = Join-Path $repoRoot "windows-event-agent\src\Rdegon.WindowsEventAgent\appsettings.json"
$installedAppSettingsPath = Join-Path $InstallDir "appsettings.json"
$productionConfigPath = Join-Path $InstallDir "appsettings.Production.json"
$controlToolPath = Join-Path $InstallDir "tools\control\Rdegon.WindowsEventAgent.Control.exe"
$sysmonConfigPath = Join-Path $scriptRoot "sysmon-minimal.xml"

if (-not (Test-Path $repoAppSettingsPath)) {
    throw "Repo appsettings.json not found: $repoAppSettingsPath"
}
if (-not (Test-Path $installedAppSettingsPath)) {
    throw "Installed appsettings.json not found: $installedAppSettingsPath"
}
if (-not (Test-Path $productionConfigPath)) {
    throw "Installed appsettings.Production.json not found: $productionConfigPath"
}

$repoAppSettings = Read-JsonFile $repoAppSettingsPath
$productionConfig = Read-JsonFile $productionConfigPath
if (-not $repoAppSettings -or -not $productionConfig) {
    throw "Failed to load Windows agent configuration files."
}

if ($productionConfig.agent -and $repoAppSettings.Agent -and $repoAppSettings.Agent.Channels) {
    $productionConfig.agent.channels = @($repoAppSettings.Agent.Channels | ForEach-Object {
        [ordered]@{
            name = $_.Name
            routePath = $_.RoutePath
            enabled = [bool]$_.Enabled
        }
    })
}

if (-not $productionConfig.agent.instanceName) {
    $productionConfig.agent.instanceName = $env:COMPUTERNAME
}
if (-not $productionConfig.agent.stateDirectory) {
    $productionConfig.agent.stateDirectory = $StateDirectory
}
if (-not $productionConfig.agent.spoolDirectory) {
    $productionConfig.agent.spoolDirectory = (Join-Path $StateDirectory "spool")
}

Copy-Item -LiteralPath $repoAppSettingsPath -Destination $installedAppSettingsPath -Force
Write-JsonFile -PathValue $productionConfigPath -Payload $productionConfig

$channelsToEnable = @(
    "Microsoft-Windows-TaskScheduler/Operational",
    "Microsoft-Windows-Windows Defender/Operational",
    "Microsoft-Windows-WMI-Activity/Operational",
    "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
    "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
    "Microsoft-Windows-WinRM/Operational"
)
foreach ($channel in $channelsToEnable) {
    Enable-EventChannel -ChannelName $channel
}

if ($InstallSysmon) {
    if (-not (Test-Path $sysmonConfigPath)) {
        throw "Sysmon config not found: $sysmonConfigPath"
    }
    Ensure-Sysmon -TempDirectory $env:TEMP -ConfigPath $sysmonConfigPath
}

$task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($task) {
    Disable-ScheduledTask -TaskName $TaskName | Out-Null
}

$service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if (-not $service) {
    throw "Windows agent service is not installed: $ServiceName"
}

if ($service.Status -ne "Stopped") {
    Stop-Service -Name $ServiceName -Force
    Start-Sleep -Seconds 3
}
Set-Service -Name $ServiceName -StartupType Automatic
Start-Service -Name $ServiceName
Start-Sleep -Seconds 10

if (-not (Test-Path $controlToolPath)) {
    throw "Control tool not found: $controlToolPath"
}

$runtimeStatus = Read-AgentRuntimeStatus -ResolvedStateDirectory $StateDirectory
$recentAgentErrors = Get-RecentAgentErrors
$hasSuccessfulDelivery = $false
if ($runtimeStatus -and $runtimeStatus.lastSuccessfulDeliveryUtc) {
    $hasSuccessfulDelivery = -not [string]::IsNullOrWhiteSpace([string]$runtimeStatus.lastSuccessfulDeliveryUtc)
}
if ((-not $hasSuccessfulDelivery) -or $recentAgentErrors.Count -gt 0) {
    Write-Warning "Service-based Windows agent did not reach healthy delivery. Falling back to SYSTEM scheduled collector."
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    Set-Service -Name $ServiceName -StartupType Manual
    Install-SystemCollectorFallback -ResolvedRepoRoot $repoRoot -ResolvedTaskName $TaskName -ResolvedProductionConfig $productionConfig
    Start-Sleep -Seconds 10
}

& $controlToolPath doctor
Write-Host ""
Write-Host "Service status:"
Get-Service -Name $ServiceName | Select-Object Name, Status, StartType | Format-Table -AutoSize
Write-Host ""
Write-Host "Agent status:"
& $statusScriptPath -Detailed
