#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [string]$DestinationPrefix = "10.20.0.0/16",
    [string]$NextHop = "192.168.3.103"
)

$ErrorActionPreference = "Stop"

$interface = Get-NetRoute -AddressFamily IPv4 |
    Where-Object {
        $_.DestinationPrefix -eq "192.168.3.0/24" -and
        $_.NextHop -eq "0.0.0.0"
    } |
    Sort-Object RouteMetric, InterfaceMetric |
    Select-Object -First 1

if (-not $interface) {
    throw "No connected interface for 192.168.3.0/24 was found."
}

Get-NetRoute -DestinationPrefix $DestinationPrefix -ErrorAction SilentlyContinue |
    Remove-NetRoute -Confirm:$false

New-NetRoute `
    -DestinationPrefix $DestinationPrefix `
    -InterfaceIndex $interface.InterfaceIndex `
    -NextHop $NextHop `
    -RouteMetric 5 `
    -PolicyStore PersistentStore | Out-Null

$checks = @(
    @{ Name = "Arkime"; Host = "10.20.10.127"; Port = 8005 },
    @{ Name = "Velociraptor"; Host = "10.20.10.128"; Port = 8889 },
    @{ Name = "Greenbone"; Host = "10.20.30.122"; Port = 9392 },
    @{ Name = "MISP"; Host = "10.20.10.131"; Port = 443 },
    @{ Name = "MinIO"; Host = "10.20.10.133"; Port = 9001 }
)

$results = foreach ($check in $checks) {
    $probe = Test-NetConnection -ComputerName $check.Host -Port $check.Port -InformationLevel Quiet
    [pscustomobject]@{
        Service = $check.Name
        Endpoint = "$($check.Host):$($check.Port)"
        Reachable = [bool]$probe
    }
}

$results | Format-Table -AutoSize
if ($results.Reachable -contains $false) {
    throw "The route was installed, but one or more native consoles are still unreachable."
}
