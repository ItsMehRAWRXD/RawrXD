# chocolateyinstall.ps1
# Phase H.2 Batch 2/5: Chocolatey Installation Script

$ErrorActionPreference = 'Stop'

$packageName = 'rawrxd'
$toolsDir = "$(Split-Path -Parent $MyInvocation.MyCommand.Definition)"
$url64 = 'https://github.com/ItsMehRAWRXD/RawrXD/releases/download/v1.0.0/RawrXD-1.0.0-x64.msi'
$checksum64 = 'PLACEHOLDER_SHA256'
$checksumType64 = 'sha256'

$packageArgs = @{
  packageName    = $packageName
  unzipLocation  = $toolsDir
  fileType       = 'msi'
  url64bit       = $url64
  checksum64     = $checksum64
  checksumType64 = $checksumType64
  silentArgs     = "/qn /norestart /l*v `"$($env:TEMP)\$($packageName).log`""
  validExitCodes = @(0, 3010, 1641)
}

Install-ChocolateyPackage @packageArgs

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
