param(
    [string]$ServiceName = "RdegonWindowsEventAgent",
    [string]$InstallDir = "$env:ProgramFiles\Rdegon\WindowsEventAgent",
    [string]$StateDirectory = "$env:ProgramData\RdegonSIEM\WindowsEventAgent",
    [switch]$RemoveInstallDir,
    [switch]$RemoveStateDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existingService) {
    if ($existingService.Status -ne "Stopped") {
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
    }

    & sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 2
    Write-Host "Deleted service $ServiceName"
} else {
    Write-Host "Service $ServiceName not found"
}

if ($RemoveInstallDir -and (Test-Path $InstallDir)) {
    Remove-Item -Path $InstallDir -Recurse -Force
    Write-Host "Removed install directory $InstallDir"
}

if ($RemoveStateDirectory -and (Test-Path $StateDirectory)) {
    Remove-Item -Path $StateDirectory -Recurse -Force
    Write-Host "Removed state directory $StateDirectory"
}
