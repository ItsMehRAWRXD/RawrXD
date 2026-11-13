# chocolateyinstall.ps1
# Phase H.2 Batch 2/5: Chocolatey Installation Script
#
# STATUS: NOT_PUBLISHED · DRAFT_SHA_BOUND · PROMOTE=0 · CERTIFIED=0
# checksum64 MEASURED for RawrXD-14.7.3-Windows-x64.zip (2026-11-13).
# MSI claim removed — asset was ABSENT. Clean-VM install witness = ABSENT.
# Authority: evidence/PRODUCTION_MATURITY_TOP25_001/TOP25_RECOGNITION_OPS_001/

$ErrorActionPreference = 'Stop'

$packageName = 'rawrxd'
$toolsDir = "$(Split-Path -Parent $MyInvocation.MyCommand.Definition)"
$url64 = 'https://github.com/ItsMehRAWRXD/RawrXD/releases/download/v14.7.3/RawrXD-14.7.3-Windows-x64.zip'
$checksum64 = 'DDEB7D50840C1097B2C79A5702C54C115BD076B108F9C43D15BCB4BE563B829D'
$checksumType64 = 'sha256'

Write-Warning "rawrxd Chocolatey script is NOT_PUBLISHED / DRAFT_SHA_BOUND — no community publish claim."

$packageArgs = @{
  packageName    = $packageName
  unzipLocation  = $toolsDir
  fileType       = 'zip'
  url64bit       = $url64
  checksum64     = $checksum64
  checksumType64 = $checksumType64
  validExitCodes = @(0)
}

# DRAFT only — do not treat Install-ChocolateyZipPackage success as Top-25 publish.
Install-ChocolateyZipPackage @packageArgs

# Add to PATH if not already present
$installPath = "${env:ProgramFiles}\RawrXD"
if (Test-Path $installPath) {
    $currentPath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    if ($currentPath -notlike "*$installPath*") {
        [Environment]::SetEnvironmentVariable('Path', "$currentPath;$installPath", 'Machine')
        Write-Host "Added RawrXD to system PATH" -ForegroundColor Green
    }
}

Write-Host "RawrXD Sovereign installed successfully!" -ForegroundColor Green
Write-Host "Run 'rawrxd --version' to verify installation" -ForegroundColor Gray
