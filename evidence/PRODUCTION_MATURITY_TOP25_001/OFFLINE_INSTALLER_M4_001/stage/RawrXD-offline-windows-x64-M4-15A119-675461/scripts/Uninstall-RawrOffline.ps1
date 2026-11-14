# Uninstall-RawrOffline.ps1 — rollback local M4 offline install. PROMOTE=0
[CmdletBinding()]
param([string]$TargetDir = "")
$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$pkg = Split-Path -Parent $here
if (-not $TargetDir) { $TargetDir = Join-Path $env:LOCALAPPDATA "RawrXD\offline-M4" }
$sw = Join-Path $pkg "SetupWizard.exe"
if (Test-Path -LiteralPath $sw) {
    $p = Start-Process -FilePath $sw -ArgumentList @("/uninstall","/silent","/target=$TargetDir") -Wait -PassThru -NoNewWindow
    Write-Host "SETUPWIZARD_UNINSTALL_EXIT=$($p.ExitCode)"
}
if (Test-Path -LiteralPath $TargetDir) {
    Remove-Item -LiteralPath $TargetDir -Recurse -Force
}
$gone = -not (Test-Path -LiteralPath $TargetDir)
Write-Host "ROLLBACK_OK=$([int]$gone)"
Write-Host "OFFLINE=1"
Write-Host "PROMOTE=0"
if (-not $gone) { exit 1 }
exit 0
