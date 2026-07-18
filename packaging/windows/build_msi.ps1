# build_msi.ps1
# Phase H.1 Batch 1/5: Windows MSI Installer Build

param(
    [string]$Version = "1.0.0",
    [string]$Configuration = "Release",
    [string]$OutputDir = ".\output",
    [switch]$Sign,
    [string]$CertificateThumbprint,
    [string]$TimestampUrl = "http://timestamp.digicert.com"
)

$ErrorActionPreference = "Stop"

Write-Host "Building RawrXD MSI v$Version..." -ForegroundColor Cyan

# Verify WiX Toolset
$wixPath = "${env:ProgramFiles(x86)}\WiX Toolset v3.11\bin"
if (-not (Test-Path $wixPath)) {
    throw "WiX Toolset not found. Install from https://wixtoolset.org/"
}

$env:PATH += ";$wixPath"

# Create output directory
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

# Compile WiX source
Write-Host "Compiling WiX source..." -ForegroundColor Yellow
& candle.exe -ext WixUtilExtension -dVersion=$Version -arch x64 -o "$OutputDir\RawrXD.wixobj" RawrXD.wxs
if ($LASTEXITCODE -ne 0) { throw "Candle compilation failed" }

# Link MSI
Write-Host "Linking MSI..." -ForegroundColor Yellow
& light.exe -ext WixUIExtension -ext WixUtilExtension -o "$OutputDir\RawrXD-$Version-x64.msi" "$OutputDir\RawrXD.wixobj"
if ($LASTEXITCODE -ne 0) { throw "Light linking failed" }

# Code signing
if ($Sign) {
    if (-not $CertificateThumbprint) {
        throw "CertificateThumbprint required for signing"
    }
    
    Write-Host "Signing MSI with Authenticode..." -ForegroundColor Yellow
    $cert = Get-ChildItem -Path Cert:\CurrentUser\My | Where-Object { $_.Thumbprint -eq $CertificateThumbprint }
    if (-not $cert) {
        throw "Certificate not found: $CertificateThumbprint"
    }
    
    Set-AuthenticodeSignature -FilePath "$OutputDir\RawrXD-$Version-x64.msi" -Certificate $cert -TimestampUrl $TimestampUrl
    Write-Host "MSI signed successfully" -ForegroundColor Green
}

# Generate checksum
$msiPath = "$OutputDir\RawrXD-$Version-x64.msi"
$hash = (Get-FileHash -Path $msiPath -Algorithm SHA256).Hash
$hash | Out-File "$msiPath.sha256"

Write-Host "MSI build complete: $msiPath" -ForegroundColor Green
Write-Host "SHA256: $hash" -ForegroundColor Gray
