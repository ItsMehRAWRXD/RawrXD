# Install-RawrOffline.ps1 — extract-local install; OFFLINE=1; no network; no models.
# PROMOTE=0 · CLEAN_VM not claimed.

[CmdletBinding()]
param(
    [string]$TargetDir = "",
    [switch]$AddUserPath,
    [switch]$SkipHelpSmoke
)

$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$pkg = Split-Path -Parent $here
if (-not $TargetDir) {
    $TargetDir = Join-Path $env:LOCALAPPDATA "RawrXD\offline-M4"
}

$pins = Join-Path $pkg "PINS.txt"
if (-not (Test-Path -LiteralPath $pins)) { throw "MISSING_PINS=$pins" }

$srcBin = Join-Path $pkg "bin"
if (-not (Test-Path -LiteralPath $srcBin)) { throw "MISSING_BIN=$srcBin" }
New-Item -ItemType Directory -Path (Join-Path $TargetDir "bin") -Force | Out-Null
Get-ChildItem -LiteralPath $srcBin -File | ForEach-Object {
    Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $TargetDir "bin\$($_.Name)") -Force
}
Copy-Item -LiteralPath $pins -Destination (Join-Path $TargetDir "PINS.txt") -Force
$manSrc = Join-Path $pkg "OFFLINE_MANIFEST.txt"
if (Test-Path -LiteralPath $manSrc) {
    Copy-Item -LiteralPath $manSrc -Destination (Join-Path $TargetDir "OFFLINE_MANIFEST.txt") -Force
}

$rawr = Join-Path $TargetDir "bin\rawr.exe"
$gui  = Join-Path $TargetDir "bin\RawrXD-Win32IDE.exe"
$cliH = (Get-FileHash -LiteralPath $rawr -Algorithm SHA256).Hash.ToUpperInvariant()
$guiH = (Get-FileHash -LiteralPath $gui  -Algorithm SHA256).Hash.ToUpperInvariant()
$expCli = "15A119D148572A4B3011AA9A8AFFE605F8FF40D64B7BF83673ECC10A9393C967"
$expGui = "6754616EA30A566423727F82513AC66D8241FDB73343F9CD7A440FF9D4E43431"
if ($cliH -ne $expCli) { throw "POST_INSTALL_CLI_SHA_MISMATCH actual=$cliH" }
if ($guiH -ne $expGui) { throw "POST_INSTALL_GUI_SHA_MISMATCH actual=$guiH" }

if ($AddUserPath) {
    $bin = Join-Path $TargetDir "bin"
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if ($null -eq $userPath) { $userPath = "" }
    $parts = @($userPath -split ";" | Where-Object { $_ -and $_.Trim() -ne "" })
    if (-not ($parts | Where-Object { $_.TrimEnd("\") -eq $bin.TrimEnd("\") })) {
        $parts += $bin
        [Environment]::SetEnvironmentVariable("Path", ($parts -join ";"), "User")
        Write-Host "ADDED_TO_USER_PATH=$bin"
    } else {
        Write-Host "ALREADY_ON_USER_PATH=$bin"
    }
}

$helpOk = "SKIP"
if (-not $SkipHelpSmoke) {
    $prev = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $helpOut = (& $rawr 2>&1 | ForEach-Object { "$_" }) -join "`n"
    $ErrorActionPreference = $prev
    $helpOk = if ($helpOut -match "rawr\s+list" -or $helpOut -match "Usage:") { "PASS" } else { "FAIL" }
}

Write-Host "INSTALL_TARGET=$TargetDir"
Write-Host "CLI_SHA256=$cliH"
Write-Host "GUI_SHA256=$guiH"
Write-Host "HELP_SMOKE=$helpOk"
Write-Host "OFFLINE=1"
Write-Host "CLOUD_MODELS=0"
Write-Host "CLEAN_VM=0"
Write-Host "PROMOTE=0"
if ($helpOk -eq "FAIL") { exit 1 }
exit 0
