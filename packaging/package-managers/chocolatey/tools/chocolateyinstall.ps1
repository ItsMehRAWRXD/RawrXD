# chocolateyinstall.ps1
# Phase F.1 Batch 1/5: Chocolatey installation script

$ErrorActionPreference = 'Stop'

$packageName = 'rawrxd'
$toolsDir = "$(Split-Path -parent $MyInvocation.MyCommand.Definition)"
$installDir = "$env:ProgramFiles\RawrXD"

# Package parameters
$url64 = 'https://github.com/ItsMehRAWRXD/RawrXD/releases/download/v1.0.0/rawrxd-1.0.0-x64.msi'
$checksum64 = 'PLACEHOLDER_SHA256'
$checksumType64 = 'sha256'

# Install arguments
$silentArgs = "/qn /norestart /l*v `"$($env:TEMP)\$($packageName).$($env:chocolateyPackageVersion).MsiInstall.log`""
$validExitCodes = @(0, 3010, 1641)

# Install MSI
Install-ChocolateyPackage `
    -PackageName $packageName `
    -FileType 'msi' `
    -SilentArgs $silentArgs `
    -Url64bit $url64 `
    -Checksum64 $checksum64 `
    -ChecksumType64 $checksumType64 `
    -ValidExitCodes $validExitCodes

# Add to PATH if not already present
$binPath = "$installDir\bin"
if (-not ($env:PATH -contains $binPath)) {
    Install-ChocolateyPath -PathToInstall $binPath -PathType 'Machine'
}

# Create default config
$configDir = "$env:ProgramData\RawrXD"
if (-not (Test-Path $configDir)) {
    New-Item -ItemType Directory -Path $configDir -Force | Out-Null
}

if (-not (Test-Path "$configDir\config.yaml")) {
    @"
version: "1.0.0"
runtime:
  threads: auto
  gpu: true
  memory_limit_gb: 0
benchmark:
  default_model: "phi-3-mini-Q4"
  confidence_level: 0.95
"@ | Out-File -FilePath "$configDir\config.yaml" -Encoding UTF8
}

# Create data directories
$dataDirs = @(
    "$env:ProgramData\RawrXD\models",
    "$env:ProgramData\RawrXD\data",
    "$env:ProgramData\RawrXD\logs"
)

foreach ($dir in $dataDirs) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
}

Write-Host "RawrXD Sovereign Runtime has been installed!" -ForegroundColor Green
Write-Host "Run 'rawrxd --help' to get started" -ForegroundColor Cyan
