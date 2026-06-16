param(
    [string]$ServiceName = "RdegonWindowsEventAgent",
    [string]$StateDirectory = "$env:ProgramData\RdegonSIEM\WindowsEventAgent",
    [switch]$Detailed,
    [switch]$Watch,
    [int]$IntervalSeconds = 5
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-AgentStatusSnapshot {
    param(
        [string]$ResolvedServiceName,
        [string]$ResolvedStateDirectory,
        [switch]$IncludeDetailed
    )

    $statusPath = Join-Path $ResolvedStateDirectory "status.json"
    $service = Get-Service -Name $ResolvedServiceName -ErrorAction SilentlyContinue
    $serviceStatus = if ($service) { $service.Status.ToString() } else { "NotInstalled" }
    $payload = $null

    if (Test-Path $statusPath) {
        $payload = Get-Content -Raw -Path $statusPath | ConvertFrom-Json
    }

    $process = $null
    try {
        $serviceInstance = Get-CimInstance Win32_Service -Filter "Name = '$ResolvedServiceName'" -ErrorAction SilentlyContinue
        if ($serviceInstance -and $serviceInstance.ProcessId -gt 0) {
            $process = Get-Process -Id ([int]$serviceInstance.ProcessId) -ErrorAction SilentlyContinue
        }
    }
    catch {
    }

    $processSummary = $null
    if ($process) {
        $processSummary = [ordered]@{
            process_id = $process.Id
            process_name = $process.ProcessName
            working_set_mb = [math]::Round($process.WorkingSet64 / 1MB, 2)
            private_memory_mb = [math]::Round($process.PrivateMemorySize64 / 1MB, 2)
            paged_memory_mb = [math]::Round($process.PagedMemorySize64 / 1MB, 2)
            virtual_memory_mb = [math]::Round($process.VirtualMemorySize64 / 1MB, 2)
            handles = $process.HandleCount
            threads = $process.Threads.Count
            cpu_total_seconds = [math]::Round($process.CPU, 2)
            started_at = $process.StartTime.ToUniversalTime().ToString("O")
        }
    }

    $summary = [ordered]@{
        observed_at_utc = (Get-Date).ToUniversalTime().ToString("O")
        service_name = $ResolvedServiceName
        service_status = $serviceStatus
        status_path = $statusPath
        status_file_present = [bool](Test-Path $statusPath)
        pending_spool_files = if ($payload) { [int]($payload.pendingSpoolFiles) } else { (Get-ChildItem -Path (Join-Path $ResolvedStateDirectory "spool") -Filter *.json -ErrorAction SilentlyContinue | Measure-Object).Count }
        runtime_status = if ($payload) { [string]$payload.status } else { "" }
        last_successful_delivery_utc = if ($payload) { [string]$payload.lastSuccessfulDeliveryUtc } else { "" }
        last_error = if ($payload) { [string]$payload.lastError } else { "" }
        process = $processSummary
    }

    if ($IncludeDetailed -and $payload) {
        $summary.channels = $payload.channels
        if ($payload.PSObject.Properties["process"]) {
            $summary.runtime_process = $payload.process
        }
    }

    return [PSCustomObject]$summary
}

if ($Watch) {
    while ($true) {
        $snapshot = Get-AgentStatusSnapshot -ResolvedServiceName $ServiceName -ResolvedStateDirectory $StateDirectory -IncludeDetailed:$Detailed
        Clear-Host
        $snapshot | ConvertTo-Json -Depth 10
        Start-Sleep -Seconds ([Math]::Max(1, $IntervalSeconds))
    }
}

Get-AgentStatusSnapshot -ResolvedServiceName $ServiceName -ResolvedStateDirectory $StateDirectory -IncludeDetailed:$Detailed |
    ConvertTo-Json -Depth 10
