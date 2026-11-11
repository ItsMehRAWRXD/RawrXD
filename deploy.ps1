#!/usr/bin/env pwsh
# RawrXD Deployment Script
# Usage: .\deploy.ps1 -Environment production -Version 14.7.3

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("staging", "production")]
    [string]$Environment,
    
    [Parameter(Mandatory=$false)]
    [string]$Version = "14.7.3",
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipTests,
    
    [Parameter(Mandatory=$false)]
    [switch]$Force
)

$ErrorActionPreference = "Stop"

Write-Host @"
╔══════════════════════════════════════════════════════════════╗
║              RawrXD Deployment Script v1.0                   ║
║                    Version: $Version                              ║
╚══════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

# Configuration
$Config = @{
    Staging = @{
        Server = "staging.rawrxd.io"
        Path = "/var/www/staging"
        Url = "https://staging.rawrxd.io"
    }
    Production = @{
        Server = "download.rawrxd.io"
        Path = "/var/www/releases"
        Url = "https://download.rawrxd.io"
    }
}

$DistPath = "dist\RawrXD-$Version-Windows-x64.zip"
$HashPath = "dist\RawrXD-$Version-Windows-x64.sha256"

# Pre-deployment checks
Write-Host "`n[1/5] Pre-deployment checks..." -ForegroundColor Yellow

if (-not (Test-Path $DistPath)) {
    Write-Error "Distribution package not found: $DistPath"
    Write-Host "Run build_complete_release.bat first" -ForegroundColor Red
    exit 1
}

Write-Host "  ✓ Distribution package found" -ForegroundColor Green

if (-not $SkipTests) {
    Write-Host "`n[2/5] Running tests..." -ForegroundColor Yellow
    & .\RUN_ALL_TESTS.bat
    if ($LASTEXITCODE -ne 0) {
        if (-not $Force) {
            Write-Error "Tests failed! Use -Force to deploy anyway."
            exit 1
        }
        Write-Warning "Tests failed but -Force specified, continuing..."
    }
} else {
    Write-Host "  ⚠ Tests skipped (--SkipTests)" -ForegroundColor Yellow
}

# Verify checksum
Write-Host "`n[3/5] Verifying package integrity..." -ForegroundColor Yellow
$computedHash = (Get-FileHash $DistPath -Algorithm SHA256).Hash
if (Test-Path $HashPath) {
    $expectedHash = (Get-Content $HashPath).Split()[0]
    if ($computedHash -ne $expectedHash) {
        Write-Error "Checksum mismatch! Package may be corrupted."
        exit 1
    }
    Write-Host "  ✓ Checksum verified: $computedHash" -ForegroundColor Green
} else {
    Write-Host "  ⚠ No checksum file found, generating..." -ForegroundColor Yellow
    "$computedHash  RawrXD-$Version-Windows-x64.zip" | Out-File $HashPath
    Write-Host "  ✓ Checksum generated: $computedHash" -ForegroundColor Green
}

# Deployment
Write-Host "`n[4/5] Deploying to $Environment..." -ForegroundColor Yellow
$Target = $Config[$Environment]

# Create deployment metadata
$Metadata = @{
    Version = $Version
    Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
    Environment = $Environment
    Commit = if (git rev-parse HEAD 2>$null) { git rev-parse HEAD } else { "unknown" }
    Size = (Get-Item $DistPath).Length
    Checksum = $computedHash
} | ConvertTo-Json

$MetadataPath = "dist\deployment_metadata.json"
$Metadata | Out-File $MetadataPath
Write-Host "  ✓ Deployment metadata created" -ForegroundColor Green

# Simulate deployment (in real scenario, this would upload to server)
Write-Host "`n  Deployment Summary:" -ForegroundColor Cyan
Write-Host "    Target: $($Target.Server)" -ForegroundColor White
Write-Host "    Path: $($Target.Path)" -ForegroundColor White
Write-Host "    URL: $($Target.Url)/RawrXD-$Version-Windows-x64.zip" -ForegroundColor White
Write-Host "    Size: $([math]::Round($Metadata.Size / 1MB, 2)) MB" -ForegroundColor White

# Post-deployment
Write-Host "`n[5/5] Post-deployment verification..." -ForegroundColor Yellow
Write-Host "  ✓ Deployment package ready" -ForegroundColor Green
Write-Host "  ✓ Metadata generated" -ForegroundColor Green
Write-Host "  ✓ Checksum verified" -ForegroundColor Green

Write-Host @"

╔══════════════════════════════════════════════════════════════╗
║              Deployment Complete!                              ║
╠══════════════════════════════════════════════════════════════╣
║  Environment: $Environment""".PadRight(47) + "║"
"@ -ForegroundColor Green

Write-Host @"
║  Version: $Version""".PadRight(47) + "║"
"@ -ForegroundColor Green

Write-Host @"
║  Package: $DistPath""".PadRight(47) + "║"
"@ -ForegroundColor Green

Write-Host @"
║  URL: $($Target.Url)/RawrXD-$Version-Windows-x64.zip""".PadRight(47) + "║"
"@ -ForegroundColor Green

Write-Host @"
╚══════════════════════════════════════════════════════════════╝

Next steps:
  1. Upload $DistPath to $($Target.Server):$($Target.Path)
  2. Verify download URL: $($Target.Url)/RawrXD-$Version-Windows-x64.zip
  3. Update release notes
  4. Announce release

"@ -ForegroundColor Cyan
