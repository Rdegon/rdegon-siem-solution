param(
    [Parameter(Mandatory = $true)]
    [string]$BaseProfilePath,

    [Parameter(Mandatory = $true)]
    [string]$OutputPath,

    [string]$PresetName,

    [string]$RoutesFilePath
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

function Get-PresetRoutesPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $known = @{
        "siem-ingest-only" = "openvpn-routes-01-siem-ingest-only.txt"
        "siem-ingest-and-web" = "openvpn-routes-02-siem-ingest-and-web.txt"
        "siem-core-admin" = "openvpn-routes-03-siem-core-admin.txt"
        "siem-full-lab" = "openvpn-routes-04-siem-full-lab.txt"
        "siem-operator-debug" = "openvpn-routes-05-siem-operator-debug.txt"
    }

    if (-not $known.ContainsKey($Name)) {
        throw "Unknown preset '$Name'. Supported presets: $($known.Keys -join ', ')"
    }

    return Join-Path $PSScriptRoot $known[$Name]
}

function Get-RouteLines {
    param(
        [string]$Name,
        [string]$FilePath
    )

    $resolvedPath = if ($FilePath) {
        Resolve-AbsolutePath -PathValue $FilePath -BaseDirectory $PSScriptRoot
    }
    else {
        Get-PresetRoutesPath -Name $Name
    }

    if (-not (Test-Path -LiteralPath $resolvedPath)) {
        throw "Routes file not found: $resolvedPath"
    }

    return Get-Content -LiteralPath $resolvedPath |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
}

$resolvedBaseProfilePath = Resolve-AbsolutePath -PathValue $BaseProfilePath
$resolvedOutputPath = Resolve-AbsolutePath -PathValue $OutputPath

if (-not (Test-Path -LiteralPath $resolvedBaseProfilePath)) {
    throw "Base OpenVPN profile not found: $resolvedBaseProfilePath"
}

if (-not $PresetName -and -not $RoutesFilePath) {
    throw "Specify either -PresetName or -RoutesFilePath."
}

$routeLines = Get-RouteLines -Name $PresetName -FilePath $RoutesFilePath
$raw = Get-Content -LiteralPath $resolvedBaseProfilePath -Raw
$marker = "<ca>"
$markerIndex = $raw.IndexOf($marker, [System.StringComparison]::OrdinalIgnoreCase)
if ($markerIndex -lt 0) {
    throw "Base profile must be an inline profile containing a <ca> block."
}

$header = $raw.Substring(0, $markerIndex)
$footer = $raw.Substring($markerIndex)

$filteredHeaderLines = [System.Collections.Generic.List[string]]::new()
foreach ($line in ($header -split "\r?\n")) {
    if ($line -match '^\s*route-nopull\s*$') {
        continue
    }

    if ($line -match '^\s*route\s+') {
        continue
    }

    if ($line -match '^\s*# BEGIN RDEGON ROUTES\s*$') {
        continue
    }

    if ($line -match '^\s*# END RDEGON ROUTES\s*$') {
        continue
    }

    $filteredHeaderLines.Add($line)
}

while ($filteredHeaderLines.Count -gt 0 -and [string]::IsNullOrWhiteSpace($filteredHeaderLines[$filteredHeaderLines.Count - 1])) {
    $filteredHeaderLines.RemoveAt($filteredHeaderLines.Count - 1)
}

$newHeaderLines = [System.Collections.Generic.List[string]]::new()
$newHeaderLines.AddRange($filteredHeaderLines)
$newHeaderLines.Add("")
$newHeaderLines.Add("# BEGIN RDEGON ROUTES")
foreach ($routeLine in $routeLines) {
    $newHeaderLines.Add($routeLine)
}
$newHeaderLines.Add("# END RDEGON ROUTES")
$newHeaderLines.Add("")

$encoding = [System.Text.UTF8Encoding]::new($false)
$content = ($newHeaderLines -join [Environment]::NewLine) + $footer

$outputDirectory = Split-Path -Parent $resolvedOutputPath
if (-not [string]::IsNullOrWhiteSpace($outputDirectory)) {
    [System.IO.Directory]::CreateDirectory($outputDirectory) | Out-Null
}

[System.IO.File]::WriteAllText($resolvedOutputPath, $content, $encoding)
Write-Output $resolvedOutputPath
