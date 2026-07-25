#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [string]$TaskName = "RdegonSIEMCollector",
    [string]$TargetPath = "C:\ProgramData\RdegonSIEM\rdegon-siem-collector.ps1",
    [string]$NewBaseUrl = "https://192.168.3.102:8443"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$sourcePath = Join-Path $PSScriptRoot "rdegon-siem-collector.ps1"
if (-not (Test-Path -LiteralPath $sourcePath)) {
    throw "Collector source not found: $sourcePath"
}
if (-not (Test-Path -LiteralPath $TargetPath)) {
    throw "Collector runtime not found: $TargetPath"
}

$timestamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
Copy-Item -LiteralPath $TargetPath -Destination "$TargetPath.bak-$timestamp" -Force
Copy-Item -LiteralPath $sourcePath -Destination $TargetPath -Force

$task = Get-ScheduledTask -TaskName $TaskName
$oldAction = $task.Actions | Select-Object -First 1
$newArguments = [string]$oldAction.Arguments -replace "https://192\.168\.1\.35", $NewBaseUrl
$actionParameters = @{
    Execute = $oldAction.Execute
    Argument = $newArguments
}
if (-not [string]::IsNullOrWhiteSpace([string]$oldAction.WorkingDirectory)) {
    $actionParameters.WorkingDirectory = [string]$oldAction.WorkingDirectory
}
$newAction = New-ScheduledTaskAction @actionParameters

Set-ScheduledTask -TaskName $TaskName -Action $newAction | Out-Null
Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
Start-ScheduledTask -TaskName $TaskName

Start-Sleep -Seconds 20
$updatedTask = Get-ScheduledTask -TaskName $TaskName
$info = $updatedTask | Get-ScheduledTaskInfo

[pscustomobject]@{
    TaskName = $TaskName
    State = [string]$updatedTask.State
    LastRunTime = $info.LastRunTime
    LastTaskResult = $info.LastTaskResult
    RuntimeUpdated = (Get-Content -LiteralPath $TargetPath -Raw) -match "RdegonSiemCertificatePolicy"
    BaseUrlUpdated = (($updatedTask.Actions | Select-Object -First 1).Arguments -match "192\.168\.3\.102:8443")
}
