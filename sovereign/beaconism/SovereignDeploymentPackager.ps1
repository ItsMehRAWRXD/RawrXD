#Requires -Version 7.2
<#
.SYNOPSIS
    SovereignDeploymentPackager.ps1 - Compile hardened scripts into deployment bundle

.DESCRIPTION
    Packages all Beaconism modules, tests, and manifest into a single
    self-extracting deployment archive with integrity verification.

.NOTES
    Version: 1.0.0
#>

[CmdletBinding()]
param (
    [string]$OutputPath = "d:\rawrxd\sovereign\beaconism\SovereignBeaconism_v1.3.0.zip",
    [string]$SourceDir = "d:\rawrxd\sovereign\beaconism",
    [switch]$IncludeTests,
    [switch]$CreateInstaller
)

$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference = "SilentlyContinue"

Write-Output "[PACKAGER] Sovereign Deployment Packager v1.0.0"
Write-Output "[PACKAGER] Source: $SourceDir"
Write-Output "[PACKAGER] Output: $OutputPath"

# ============================================================================
# Gather files
# ============================================================================
$CoreFiles = @(
    "SovereignBeaconGenerator.ps1",
    "SovereignSwarmOrchestrator.ps1",
    "SovereignUnifiedOrchestrator.ps1",
    "SovereignDiskRemediator.ps1",
    "SovereignRuntimeMemoryPatch.ps1",
    "SovereignPingStream.ps1",
    "SovereignBeaconParser.ps1",
    "SovereignCryptoWrapper.ps1",
    "SovereignWMIEventConsumer.ps1",
    "SovereignOneClick.ps1",
    "MANIFEST.json"
)

$TestFiles = @(
    "Test-BeaconismStack.ps1",
    "Test-BeaconismGPU.ps1"
)

$FilesToPackage = [System.Collections.Generic.List[string]]::new()

foreach ($File in $CoreFiles) {
    $FullPath = Join-Path $SourceDir $File
    if (Test-Path $FullPath) {
        $FilesToPackage.Add($FullPath)
        Write-Output "[PACKAGER] Core: $File"
    } else {
        Write-Output "[PACKAGER] MISSING: $File"
    }
}

if ($IncludeTests) {
    foreach ($File in $TestFiles) {
        $FullPath = Join-Path $SourceDir $File
        if (Test-Path $FullPath) {
            $FilesToPackage.Add($FullPath)
            Write-Output "[PACKAGER] Test: $File"
        }
    }
}

# ============================================================================
# Generate SHA-256 hashes
# ============================================================================
$HashManifest = @()
foreach ($File in $FilesToPackage) {
    $Hash = (Get-FileHash -Path $File -Algorithm SHA256).Hash
    $RelativeName = Split-Path $File -Leaf
    $HashManifest += "$Hash  $RelativeName"
    Write-Output "[PACKAGER] Hash: $RelativeName = $Hash"
}

# Write hash manifest
$HashFile = Join-Path $SourceDir "SHA256SUMS"
$HashManifest | Out-File -FilePath $HashFile -Encoding UTF8
$FilesToPackage.Add($HashFile)

# ============================================================================
# Create ZIP archive
# ============================================================================
Add-Type -AssemblyName System.IO.Compression.FileSystem

if (Test-Path $OutputPath) {
    Remove-Item $OutputPath -Force
}

$TempDir = Join-Path $env:TEMP "sovereign_deploy_$(Get-Random)"
New-Item -ItemType Directory -Force -Path $TempDir | Out-Null

foreach ($File in $FilesToPackage) {
    Copy-Item $File $TempDir
}

[System.IO.Compression.ZipFile]::CreateFromDirectory($TempDir, $OutputPath)
Remove-Item $TempDir -Recurse -Force

$ZipSize = (Get-Item $OutputPath).Length
Write-Output "[PACKAGER] Archive created: $OutputPath ($ZipSize bytes)"

# ============================================================================
# Optional: Create self-extracting installer script
# ============================================================================
if ($CreateInstaller) {
    $InstallerPath = $OutputPath -replace '\.zip$', '_Installer.ps1'

    $InstallerScript = @"
#Requires -RunAsAdministrator
# Sovereign Beaconism v1.3.0 Self-Extracting Installer
param([string]`$InstallDir = "C:\Sovereign\Beaconism")

Write-Output "[INSTALL] Sovereign Beaconism v1.3.0"
Write-Output "[INSTALL] Target: `$InstallDir"

New-Item -ItemType Directory -Force -Path `$InstallDir | Out-Null

`$ZipPath = "`$PSScriptRoot\$(Split-Path $OutputPath -Leaf)"
if (-not (Test-Path `$ZipPath)) {
    Write-Output "[INSTALL] ERROR: Archive not found at `$ZipPath"
    exit 1
}

Add-Type -AssemblyName System.IO.Compression.FileSystem
[System.IO.Compression.ZipFile]::ExtractToDirectory(`$ZipPath, `$InstallDir)

Write-Output "[INSTALL] Extracted to: `$InstallDir"
Write-Output "[INSTALL] Run: `$InstallDir\SovereignOneClick.ps1 -FullRemediation"
"@

    $InstallerScript | Out-File -FilePath $InstallerPath -Encoding UTF8
    Write-Output "[PACKAGER] Installer created: $InstallerPath"
}

Write-Output "[PACKAGER] Deployment packaging complete."
Write-Output "[PACKAGER] Files packaged: $($FilesToPackage.Count)"
