param(
    [string]$Runtime = "win-x64",
    [string]$Configuration = "Release",
    [string]$VersionLabel = "",
    [string]$ReleaseRoot = ".\artifacts\windows-event-agent\releases",
    [switch]$SkipControlTool,
    [switch]$SkipSetupExe
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

    throw "dotnet SDK is required to package the Windows agent."
}

if (-not $VersionLabel) {
    $VersionLabel = Get-Date -Format "yyyyMMdd-HHmmss"
}

$resolvedReleaseRoot = Resolve-PathSafe $ReleaseRoot
$releaseDir = Join-Path $resolvedReleaseRoot $VersionLabel
$bundleDir = Join-Path $releaseDir "bundle"
$zipPath = Join-Path $releaseDir "Rdegon.WindowsEventAgent-$VersionLabel-$Runtime.zip"

$buildScriptPath = Resolve-PathSafe ".\deploy\windows-agent\build-windows-event-agent.ps1"
$setupProjectPath = Resolve-PathSafe ".\windows-event-agent\src\Rdegon.WindowsEventAgent.Setup\Rdegon.WindowsEventAgent.Setup.csproj"
$installGuidePath = Resolve-PathSafe ".\deploy\windows-agent\INSTALL.md"
$statusScriptPath = Resolve-PathSafe ".\deploy\windows-agent\get-windows-event-agent-status.ps1"
$profileTemplatePath = Resolve-PathSafe ".\ops\windows-agent-profile.local.example.json"
$setupPublishDir = Join-Path $releaseDir "setup-publish"
$setupExePath = Join-Path $releaseDir "Rdegon.WindowsEventAgent.Setup-$VersionLabel-$Runtime.exe"
$dotnetCommand = Resolve-DotnetCommand

New-Item -ItemType Directory -Path $releaseDir -Force | Out-Null
if (Test-Path $bundleDir) {
    Remove-Item -Path $bundleDir -Recurse -Force
}
if (Test-Path $setupPublishDir) {
    Remove-Item -Path $setupPublishDir -Recurse -Force
}

$buildArgs = @(
    "-ExecutionPolicy", "Bypass",
    "-File", $buildScriptPath,
    "-Runtime", $Runtime,
    "-Configuration", $Configuration,
    "-OutputDir", $bundleDir,
    "-SelfContained"
)

if ($SkipControlTool) {
    $buildArgs += "-SkipControlTool"
}

& powershell.exe @buildArgs
if ($LASTEXITCODE -ne 0) {
    throw "build-windows-event-agent.ps1 failed with exit code $LASTEXITCODE"
}

Copy-Item -Path $installGuidePath -Destination (Join-Path $bundleDir "INSTALL.md") -Force
Copy-Item -Path $statusScriptPath -Destination (Join-Path $bundleDir "get-windows-event-agent-status.ps1") -Force
Copy-Item -Path $profileTemplatePath -Destination (Join-Path $bundleDir "windows-agent-profile.local.example.json") -Force

$manifest = [ordered]@{
    versionLabel = $VersionLabel
    runtime = $Runtime
    configuration = $Configuration
    selfContained = $true
    builtAtUtc = (Get-Date).ToUniversalTime().ToString("O")
    bundleDir = $bundleDir
    includes = @(
        "Rdegon.WindowsEventAgent.exe",
        "appsettings.json",
        "INSTALL.md",
        "get-windows-event-agent-status.ps1",
        "windows-agent-profile.local.example.json",
        "bundle-manifest.json"
    )
}

if (-not $SkipControlTool) {
    $manifest.includes += "tools/control/Rdegon.WindowsEventAgent.Control.exe"
}

($manifest | ConvertTo-Json -Depth 6) | Set-Content -Path (Join-Path $bundleDir "bundle-manifest.json") -Encoding UTF8

if (Test-Path $zipPath) {
    Remove-Item -Path $zipPath -Force
}

Compress-Archive -Path (Join-Path $bundleDir "*") -DestinationPath $zipPath -Force

if (-not $SkipSetupExe -and -not $SkipControlTool) {
    $setupPublishArgs = @(
        "publish",
        $setupProjectPath,
        "-c", $Configuration,
        "-r", $Runtime,
        "--self-contained", "true",
        "-o", $setupPublishDir,
        "-p:PublishSingleFile=true",
        "-p:EnableCompressionInSingleFile=true",
        "-p:DebugType=None",
        "-p:PayloadZipPath=$zipPath"
    )

    & $dotnetCommand @setupPublishArgs
    if ($LASTEXITCODE -ne 0) {
        throw "dotnet publish for the Windows agent setup executable failed with exit code $LASTEXITCODE"
    }

    Copy-Item -Path (Join-Path $setupPublishDir "Rdegon.WindowsEventAgent.Setup.exe") -Destination $setupExePath -Force
}

Write-Host "Packaged Windows agent bundle: $bundleDir"
Write-Host "Packaged Windows agent archive: $zipPath"
if (-not $SkipSetupExe -and -not $SkipControlTool) {
    Write-Host "Packaged Windows agent setup executable: $setupExePath"
}
