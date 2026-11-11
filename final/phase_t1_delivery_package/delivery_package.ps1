#!/usr/bin/env pwsh
#requires -Version 7.0

<#
.SYNOPSIS
    Phase T.1: Delivery Package Generator
    
.DESCRIPTION
    Generates comprehensive delivery packages including all artifacts,
    documentation, and deployment materials for project handoff.
    
.PARAMETER PackageType
    Type of package: full, minimal, enterprise, source-only
    
.PARAMETER Version
    Release version for the package
    
.PARAMETER OutputPath
    Output directory for the package
    
.EXAMPLE
    .\delivery_package.ps1 -PackageType full -Version 1.0.0
    .\delivery_package.ps1 -PackageType enterprise -Version 1.0.0 -OutputPath .\packages
#

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("full", "minimal", "enterprise", "source-only")]
    [string]$PackageType = "full",
    
    [Parameter(Mandatory=$false)]
    [string]$Version = "1.0.0",
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = ".\delivery_packages"
)

$ErrorActionPreference = "Stop"

$script:PackageManifest = @{
    Version = $Version
    Type = $PackageType
    CreatedAt = Get-Date -Format "o"
    Artifacts = @()
    TotalSize = 0
}

function Write-DeliveryHeader {
    Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║  Phase T.1: Delivery Package Generator                           ║
║  Comprehensive artifact packaging for project handoff              ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan
}

function Initialize-PackageEnvironment {
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    
    $packageDir = Join-Path $OutputPath "rawrxd-v$Version-$PackageType"
    if (Test-Path $packageDir) {
        Remove-Item -Path $packageDir -Recurse -Force
    }
    New-Item -ItemType Directory -Path $packageDir -Force | Out-Null
    
    Write-Host "`nPackage Configuration:" -ForegroundColor Yellow
    Write-Host "  Version: $Version" -ForegroundColor White
    Write-Host "  Type: $PackageType" -ForegroundColor White
    Write-Host "  Output: $packageDir" -ForegroundColor White
    
    return $packageDir
}

function Add-PackageArtifact {
    param($SourcePath, $TargetPath, $Description, $Required = $true)
    
    $artifact = @{
        Source = $SourcePath
        Target = $TargetPath
        Description = $Description
        Required = $Required
        Included = $false
        Size = 0
    }
    
    if (Test-Path $SourcePath) {
        $item = Get-Item -Path $SourcePath
        $artifact.Size = if ($item.PSIsContainer) { 
            (Get-ChildItem -Path $SourcePath -Recurse -File | Measure-Object -Property Length -Sum).Sum 
        } else { 
            $item.Length 
        }
        $artifact.Included = $true
        
        $targetDir = Split-Path -Parent (Join-Path $script:PackageDir $TargetPath)
        if (-not (Test-Path $targetDir)) {
            New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
        }
        
        if ($item.PSIsContainer) {
            Copy-Item -Path $SourcePath -Destination (Join-Path $script:PackageDir $TargetPath) -Recurse -Force
        } else {
            Copy-Item -Path $SourcePath -Destination (Join-Path $script:PackageDir $TargetPath) -Force
        }
        
        Write-Host "  ✓ $Description" -ForegroundColor Green
    } else {
        if ($Required) {
            Write-Host "  ✗ $Description (MISSING)" -ForegroundColor Red
        } else {
            Write-Host "  - $Description (optional, not found)" -ForegroundColor Gray
        }
    }
    
    $script:PackageManifest.Artifacts += $artifact
    $script:PackageManifest.TotalSize += $artifact.Size
}

function New-FullPackage {
    Write-Host "`n[Building Full Package]" -ForegroundColor Yellow
    
    # Core binaries
    Add-PackageArtifact -SourcePath "..\..\bin\RawrXD.exe" -TargetPath "bin\RawrXD.exe" -Description "RawrXD Core Executable"
    Add-PackageArtifact -SourcePath "..\..\bin\RawrXD-Win32IDE.exe" -TargetPath "bin\RawrXD-Win32IDE.exe" -Description "RawrXD IDE Executable"
    Add-PackageArtifact -SourcePath "..\..\bin\RawrXD-Sovereign.exe" -TargetPath "bin\RawrXD-Sovereign.exe" -Description "Sovereign Engine"
    
    # Source code
    Add-PackageArtifact -SourcePath "..\..\src" -TargetPath "src" -Description "Source Code"
    Add-PackageArtifact -SourcePath "..\..\include" -TargetPath "include" -Description "Headers"
    
    # Documentation
    Add-PackageArtifact -SourcePath "..\..\docs" -TargetPath "docs" -Description "Documentation"
    Add-PackageArtifact -SourcePath "..\..\README.md" -TargetPath "README.md" -Description "Project README"
    
    # Configuration
    Add-PackageArtifact -SourcePath "..\..\config" -TargetPath "config" -Description "Configuration Files" -Required $false
    Add-PackageArtifact -SourcePath "..\..\examples" -TargetPath "examples" -Description "Example Configurations" -Required $false
    
    # Scripts
    Add-PackageArtifact -SourcePath "..\..\scripts" -TargetPath "scripts" -Description "Utility Scripts" -Required $false
    
    # Phase completions
    Add-PackageArtifact -SourcePath "..\..\saas\PHASE_M_COMPLETE.md" -TargetPath "phases\PHASE_M_COMPLETE.md" -Description "Phase M Completion"
    Add-PackageArtifact -SourcePath "..\..\operations\PHASE_N_COMPLETE.md" -TargetPath "phases\PHASE_N_COMPLETE.md" -Description "Phase N Completion"
    Add-PackageArtifact -SourcePath "..\..\analytics\PHASE_O_COMPLETE.md" -TargetPath "phases\PHASE_O_COMPLETE.md" -Description "Phase O Completion"
    Add-PackageArtifact -SourcePath "..\..\extensions\PHASE_P_COMPLETE.md" -TargetPath "phases\PHASE_P_COMPLETE.md" -Description "Phase P Completion"
    Add-PackageArtifact -SourcePath "..\..\docs\PHASE_Q_COMPLETE.md" -TargetPath "phases\PHASE_Q_COMPLETE.md" -Description "Phase Q Completion"
    Add-PackageArtifact -SourcePath "..\..\release\PHASE_R_COMPLETE.md" -TargetPath "phases\PHASE_R_COMPLETE.md" -Description "Phase R Completion"
    Add-PackageArtifact -SourcePath "..\..\system\PHASE_S_COMPLETE.md" -TargetPath "phases\PHASE_S_COMPLETE.md" -Description "Phase S Completion"
    Add-PackageArtifact -SourcePath "..\..\enterprise\phase_h1\PHASE_H1_COMPLETE.md" -TargetPath "phases\PHASE_H1_COMPLETE.md" -Description "Phase H.1 Completion"
    
    # Tests
    Add-PackageArtifact -SourcePath "..\..\tests" -TargetPath "tests" -Description "Test Suite" -Required $false
}

function New-MinimalPackage {
    Write-Host "`n[Building Minimal Package]" -ForegroundColor Yellow
    
    # Essential binaries only
    Add-PackageArtifact -SourcePath "..\..\bin\RawrXD.exe" -TargetPath "RawrXD.exe" -Description "RawrXD Core Executable"
    Add-PackageArtifact -SourcePath "..\..\README.md" -TargetPath "README.md" -Description "Project README"
    Add-PackageArtifact -SourcePath "..\..\LICENSE" -TargetPath "LICENSE" -Description "License File" -Required $false
}

function New-EnterprisePackage {
    Write-Host "`n[Building Enterprise Package]" -ForegroundColor Yellow
    
    # Full package contents
    New-FullPackage
    
    # Enterprise additions
    Add-PackageArtifact -SourcePath "..\..\enterprise" -TargetPath "enterprise" -Description "Enterprise Components"
    Add-PackageArtifact -SourcePath "..\..\security" -TargetPath "security" -Description "Security Framework"
    
    # Deployment templates
    Add-PackageArtifact -SourcePath "..\..\k8s" -TargetPath "k8s" -Description "Kubernetes Templates" -Required $false
    Add-PackageArtifact -SourcePath "..\..\docker" -TargetPath "docker" -Description "Docker Configuration" -Required $false
    
    # Compliance documentation
    Add-PackageArtifact -SourcePath "..\..\enterprise\phase_h1\batch2_compliance_framework\compliance_framework.md" -TargetPath "compliance\compliance_framework.md" -Description "Compliance Documentation"
    Add-PackageArtifact -SourcePath "..\..\enterprise\phase_h1\batch3_sla_guarantees\sla_framework.md" -TargetPath "compliance\sla_framework.md" -Description "SLA Documentation"
}

function New-SourcePackage {
    Write-Host "`n[Building Source-Only Package]" -ForegroundColor Yellow
    
    # Source only
    Add-PackageArtifact -SourcePath "..\..\src" -TargetPath "src" -Description "Source Code"
    Add-PackageArtifact -SourcePath "..\..\include" -TargetPath "include" -Description "Headers"
    Add-PackageArtifact -SourcePath "..\..\CMakeLists.txt" -TargetPath "CMakeLists.txt" -Description "Build Configuration"
    Add-PackageArtifact -SourcePath "..\..\README.md" -TargetPath "README.md" -Description "Project README"
    Add-PackageArtifact -SourcePath "..\..\LICENSE" -TargetPath "LICENSE" -Description "License File" -Required $false
    
    # Build scripts
    Add-PackageArtifact -SourcePath "..\..\build.ps1" -TargetPath "build.ps1" -Description "Build Script" -Required $false
    Add-PackageArtifact -SourcePath "..\..\build.bat" -TargetPath "build.bat" -Description "Windows Build Script" -Required $false
}

function Export-PackageManifest {
    $manifestPath = Join-Path $script:PackageDir "PACKAGE_MANIFEST.json"
    $script:PackageManifest | ConvertTo-Json -Depth 10 | Set-Content -Path $manifestPath
    
    # README for package
    $readmeContent = @"
# RawrXD v$Version - $PackageType Package

## Contents

This package contains the following components:

$(foreach ($artifact in $script:PackageManifest.Artifacts | Where-Object { $_.Included }) { "- $($artifact.Description)`n" })

## Package Information

- **Version**: $Version
- **Type**: $PackageType
- **Created**: $($script:PackageManifest.CreatedAt)
- **Total Size**: $([math]::Round($script:PackageManifest.TotalSize / 1MB, 2)) MB

## Installation

See the main project README.md for installation instructions.

## Support

For support, visit https://support.rawrxd.io

---
*Generated by Phase T.1 Delivery Package Generator*
"@
    
    $readmePath = Join-Path $script:PackageDir "PACKAGE_README.md"
    $readmeContent | Set-Content -Path $readmePath
    
    Write-Host "`n✓ Package manifest generated" -ForegroundColor Green
}

function Compress-Package {
    $zipPath = "$script:PackageDir.zip"
    
    Write-Host "`nCompressing package..." -ForegroundColor Yellow
    Compress-Archive -Path "$script:PackageDir\*" -DestinationPath $zipPath -Force
    
    $zipSize = (Get-Item -Path $zipPath).Length
    Write-Host "  ✓ Package compressed: $zipPath" -ForegroundColor Green
    Write-Host "  Size: $([math]::Round($zipSize / 1MB, 2)) MB" -ForegroundColor Gray
}

# Main execution
Write-DeliveryHeader
$script:PackageDir = Initialize-PackageEnvironment

switch ($PackageType) {
    "full" { New-FullPackage }
    "minimal" { New-MinimalPackage }
    "enterprise" { New-EnterprisePackage }
    "source-only" { New-SourcePackage }
}

Export-PackageManifest
Compress-Package

# Summary
Write-Host "`n═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "                    PACKAGE SUMMARY" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  Version: $Version" -ForegroundColor White
Write-Host "  Type: $PackageType" -ForegroundColor White
Write-Host "  Artifacts: $(($script:PackageManifest.Artifacts | Where-Object { $_.Included }).Count)" -ForegroundColor White
Write-Host "  Total Size: $([math]::Round($script:PackageManifest.TotalSize / 1MB, 2)) MB" -ForegroundColor White
Write-Host "  Location: $script:PackageDir.zip" -ForegroundColor White
Write-Host "`n✅ Delivery package complete!" -ForegroundColor Green
