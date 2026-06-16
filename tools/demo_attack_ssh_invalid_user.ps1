<#
.SYNOPSIS
Generates real SSH invalid-user attempts against a lab Linux source.

.DESCRIPTION
This script does not write SIEM events directly. It makes failed SSH authentication
attempts with non-existent usernames so the target's sshd/auth.log pipeline can produce
normal Linux telemetry.

Expected stream rule:
- 2708 Linux SSH Invalid User Burst, threshold 8, entity source.ip
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$TargetHost = "10.20.30.123",

    [int]$Port = 22,

    [int]$Attempts = 8,

    [int]$DelayMs = 350,

    [string]$RunId = ("demo-" + (Get-Date -Format "yyyyMMddHHmmss")),

    [string]$UserPrefix = "siem-demo-invalid"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ($Attempts -lt 1) {
    throw "Attempts must be >= 1"
}

$ssh = Get-Command ssh.exe -ErrorAction SilentlyContinue
if (-not $ssh) {
    throw "OpenSSH client ssh.exe was not found in PATH."
}

$safeRunId = ($RunId -replace "[^A-Za-z0-9_-]", "-")
$knownHostsPath = Join-Path $env:TEMP "siem-demo-known-hosts-$safeRunId"
$options = @(
    "-p", [string]$Port,
    "-o", "BatchMode=yes",
    "-o", "ConnectTimeout=5",
    "-o", "ConnectionAttempts=1",
    "-o", "PreferredAuthentications=publickey,password",
    "-o", "NumberOfPasswordPrompts=0",
    "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=$knownHostsPath"
)

$results = [System.Collections.Generic.List[object]]::new()
for ($index = 1; $index -le $Attempts; $index++) {
    $user = "$UserPrefix-$safeRunId-$index"
    $target = "$user@$TargetHost"
    if ($PSCmdlet.ShouldProcess($target, "Attempt benign invalid SSH login for rule 2708")) {
        $started = Get-Date
        $previousErrorActionPreference = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        try {
            $output = & $ssh.Source @options $target "true" 2>&1
            $exitCode = $LASTEXITCODE
        }
        finally {
            $ErrorActionPreference = $previousErrorActionPreference
        }
        $results.Add([pscustomobject]@{
            scenario = "SshInvalidUser"
            expected_rule_id = 2708
            expected_rule_name = "Linux SSH Invalid User Burst"
            run_id = $RunId
            target_host = $TargetHost
            port = $Port
            username = $user
            started = $started.ToString("o")
            exit_code = $exitCode
            output = ($output -join "`n")
        })
        if ($index -lt $Attempts) {
            Start-Sleep -Milliseconds $DelayMs
        }
    }
}

if (Test-Path -LiteralPath $knownHostsPath) {
    Remove-Item -LiteralPath $knownHostsPath -Force -ErrorAction SilentlyContinue
}

[pscustomobject]@{
    scenario = "SshInvalidUserBurst"
    expected_rule_id = 2708
    expected_rule_name = "Linux SSH Invalid User Burst"
    run_id = $RunId
    target_host = $TargetHost
    attempts = $Attempts
    note = "The rule threshold is 8 events inside 600 seconds. Wait for normal collector and correlation latency before checking UI."
    attempts_detail = $results
} | ConvertTo-Json -Depth 6
