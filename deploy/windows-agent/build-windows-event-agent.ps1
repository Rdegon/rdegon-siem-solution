param(
    [string]$ProjectPath = ".\windows-event-agent\src\Rdegon.WindowsEventAgent\Rdegon.WindowsEventAgent.csproj",
    [string]$ControlProjectPath = ".\windows-event-agent\src\Rdegon.WindowsEventAgent.Control\Rdegon.WindowsEventAgent.Control.csproj",
    [string]$Runtime = "win-x64",
    [string]$Configuration = "Release",
    [string]$OutputDir = ".\artifacts\windows-event-agent\win-x64\publish",
    [switch]$SelfContained,
    [switch]$SkipControlTool,
    [switch]$CreateZip
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Resolve-PathSafe([string]$PathValue) {
    if ([System.IO.Path]::IsPathRooted($PathValue)) {
        return [System.IO.Path]::GetFullPath($PathValue)
    }

    return [System.IO.Path]::GetFullPath((Join-Path (Get-Location) $PathValue))
}

function Resolve-DotnetCommand() {
    $dotnetCommand = Get-Command dotnet -ErrorAction SilentlyContinue
    if ($dotnetCommand) {
        return $dotnetCommand.Source
    }

    $defaultPath = "C:\Program Files\dotnet\dotnet.exe"
    if (Test-Path $defaultPath) {
        return $defaultPath
    }

    throw "dotnet SDK is required to build the Windows agent."
}

$dotnetCommand = Resolve-DotnetCommand

$resolvedProjectPath = Resolve-PathSafe $ProjectPath
$resolvedControlProjectPath = Resolve-PathSafe $ControlProjectPath
$resolvedOutputDir = Resolve-PathSafe $OutputDir
$artifactRoot = Split-Path -Parent $resolvedOutputDir

if (-not (Test-Path $resolvedProjectPath)) {
    throw "Project file not found: $resolvedProjectPath"
}

if (-not $SkipControlTool -and -not (Test-Path $resolvedControlProjectPath)) {
    throw "Control project file not found: $resolvedControlProjectPath"
}

New-Item -ItemType Directory -Path $resolvedOutputDir -Force | Out-Null

$publishArgs = @(
    "publish",
    $resolvedProjectPath,
    "-c", $Configuration,
    "-r", $Runtime,
    "--self-contained", ($(if ($SelfContained) { "true" } else { "false" })),
    "-o", $resolvedOutputDir
)

Write-Host "Publishing Windows agent to $resolvedOutputDir"
& $dotnetCommand @publishArgs
if ($LASTEXITCODE -ne 0) {
    throw "dotnet publish failed with exit code $LASTEXITCODE"
}

if (-not $SkipControlTool) {
    $controlOutputDir = Join-Path $resolvedOutputDir "tools\control"
    New-Item -ItemType Directory -Path $controlOutputDir -Force | Out-Null

    $controlPublishArgs = @(
        "publish",
        $resolvedControlProjectPath,
        "-c", $Configuration,
        "-r", $Runtime,
        "--self-contained", ($(if ($SelfContained) { "true" } else { "false" })),
        "-o", $controlOutputDir
    )

    Write-Host "Publishing Windows agent control tool to $controlOutputDir"
    & $dotnetCommand @controlPublishArgs
    if ($LASTEXITCODE -ne 0) {
        throw "dotnet publish for the Windows agent control tool failed with exit code $LASTEXITCODE"
    }
}

if ($CreateZip) {
    New-Item -ItemType Directory -Path $artifactRoot -Force | Out-Null
    $zipPath = Join-Path $artifactRoot "Rdegon.WindowsEventAgent-$Runtime.zip"
    if (Test-Path $zipPath) {
        Remove-Item $zipPath -Force
    }
    Compress-Archive -Path (Join-Path $resolvedOutputDir "*") -DestinationPath $zipPath -Force
    Write-Host "Created package: $zipPath"
}

Write-Host "Windows agent publish complete."
