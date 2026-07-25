[CmdletBinding()]
param(
    [string]$Gateway = "192.168.3.102",
    [string[]]$DestinationPrefixes = @(
        "10.20.10.0/24",
        "10.20.20.0/24",
        "10.20.30.0/24",
        "10.20.40.0/24"
    ),
    [int]$RouteMetric = 5,
    [switch]$Remove
)

$ErrorActionPreference = "Stop"

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
$isAdministrator = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdministrator) {
    throw "Run this script from an elevated PowerShell session."
}

$gatewayAddress = [ipaddress]$Gateway
$gatewayOctets = $gatewayAddress.GetAddressBytes()
$managementPrefix = "{0}.{1}.{2}.0/24" -f $gatewayOctets[0], $gatewayOctets[1], $gatewayOctets[2]
$managementRoute = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix $managementPrefix -ErrorAction SilentlyContinue |
    Where-Object { $_.NextHop -eq "0.0.0.0" } |
    Sort-Object RouteMetric, InterfaceMetric |
    Select-Object -First 1

if (-not $managementRoute) {
    throw "No connected route to $managementPrefix was found."
}

$interfaceIndex = [int]$managementRoute.InterfaceIndex
foreach ($destinationPrefix in $DestinationPrefixes) {
    $existing = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix $destinationPrefix -ErrorAction SilentlyContinue |
        Where-Object { $_.NextHop -eq $Gateway -and $_.InterfaceIndex -eq $interfaceIndex }

    if ($Remove) {
        $existing | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
        Write-Host "Removed $destinationPrefix via $Gateway"
        continue
    }

    if ($existing) {
        $existing | Set-NetRoute -RouteMetric $RouteMetric -ErrorAction Stop
        Write-Host "Updated $destinationPrefix via $Gateway"
        continue
    }

    New-NetRoute `
        -AddressFamily IPv4 `
        -DestinationPrefix $destinationPrefix `
        -InterfaceIndex $interfaceIndex `
        -NextHop $Gateway `
        -RouteMetric $RouteMetric `
        -PolicyStore PersistentStore | Out-Null
    Write-Host "Added $destinationPrefix via $Gateway"
}

if (-not $Remove) {
    $checks = @(
        "10.20.10.104",
        "10.20.20.120",
        "10.20.30.122",
        "10.20.40.1"
    )
    foreach ($address in $checks) {
        $route = Find-NetRoute -RemoteIPAddress $address
        Write-Host ("{0} -> interface {1}, next hop {2}" -f $address, $route.InterfaceIndex, $route.NextHop)
    }
}
