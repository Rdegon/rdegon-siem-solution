<#
.SYNOPSIS
Runs benign Windows actions that should produce real telemetry for SIEM demo alerts.

.DESCRIPTION
This script does not write SIEM events directly. It creates normal Windows process/service
activity and relies on the installed Windows collector to forward resulting telemetry.

Expected stream rules:
- 2604 Windows Encoded PowerShell Command
- 2605 Windows Service Installed
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [ValidateSet("All", "EncodedPowerShell", "ServiceInstall")]
    [string[]]$Scenario = @("All"),

    [string]$RunId = ("demo-" + (Get-Date -Format "yyyyMMddHHmmss")),

    [switch]$KeepService
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function ConvertTo-SafeToken {
    param([Parameter(Mandatory = $true)][string]$Value)
    return ($Value -replace "[^A-Za-z0-9_-]", "-")
}

function Invoke-EncodedPowerShellDemo {
    param([Parameter(Mandatory = $true)][string]$RunId)

    $payload = @"
`$demoRunId = '$RunId'
Write-Output "SIEM demo encoded PowerShell run_id=`$demoRunId"
Start-Sleep -Milliseconds 200
"@
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($payload))
    $powershellPath = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"
    $arguments = @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-EncodedCommand", $encoded
    )

    if ($PSCmdlet.ShouldProcess("powershell.exe", "Run benign EncodedCommand demo for rule 2604")) {
        $process = Start-Process -FilePath $powershellPath -ArgumentList $arguments -NoNewWindow -Wait -PassThru
        [pscustomobject]@{
            scenario = "EncodedPowerShell"
            expected_rule_id = 2604
            expected_rule_name = "Windows Encoded PowerShell Command"
            run_id = $RunId
            exit_code = $process.ExitCode
            encoded_command = $encoded
        }
    }
}

function Invoke-ServiceInstallDemo {
    param([Parameter(Mandatory = $true)][string]$RunId)

    if (-not (Test-IsAdmin)) {
        throw "ServiceInstall requires an elevated PowerShell session."
    }

    $safeRunId = ConvertTo-SafeToken -Value $RunId
    $serviceName = "RdegonDemoSvc_$safeRunId"
    if ($serviceName.Length -gt 80) {
        $serviceName = $serviceName.Substring(0, 80)
    }
    $displayName = "Rdegon SIEM Demo Service $safeRunId"
    $binPath = "`"$env:ComSpec`" /c exit /b 0"

    if ($PSCmdlet.ShouldProcess($serviceName, "Create temporary benign service for rule 2605")) {
        $createOutput = & sc.exe create $serviceName binPath= $binPath DisplayName= $displayName start= demand 2>&1
        $descriptionOutput = & sc.exe description $serviceName "SIEM demo service install run_id=$RunId" 2>&1
        Start-Sleep -Seconds 2

        $deleteOutput = @()
        if (-not $KeepService) {
            $deleteOutput = & sc.exe delete $serviceName 2>&1
        }

        [pscustomobject]@{
            scenario = "ServiceInstall"
            expected_rule_id = 2605
            expected_rule_name = "Windows Service Installed"
            run_id = $RunId
            service_name = $serviceName
            service_kept = [bool]$KeepService
            create_output = ($createOutput -join "`n")
            description_output = ($descriptionOutput -join "`n")
            delete_output = ($deleteOutput -join "`n")
        }
    }
}

$selected = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($item in $Scenario) {
    if ($item -eq "All") {
        [void]$selected.Add("EncodedPowerShell")
        [void]$selected.Add("ServiceInstall")
    } else {
        [void]$selected.Add($item)
    }
}

$results = [System.Collections.Generic.List[object]]::new()
if ($selected.Contains("EncodedPowerShell")) {
    $results.Add((Invoke-EncodedPowerShellDemo -RunId $RunId))
}
if ($selected.Contains("ServiceInstall")) {
    $results.Add((Invoke-ServiceInstallDemo -RunId $RunId))
}

$results | ConvertTo-Json -Depth 6
