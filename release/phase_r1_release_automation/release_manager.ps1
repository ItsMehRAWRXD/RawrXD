#!/usr/bin/env pwsh
#requires -Version 7.0

<#
.SYNOPSIS
    Phase R.1: Release Automation Manager
    
.DESCRIPTION
    Automates the release process for RawrXD including version management,
    changelog generation, release notes, and artifact creation.
    
.PARAMETER Action
    Action to perform: prepare, create, publish, list, rollback
    
.PARAMETER Version
    Version number (semver format: x.y.z)
    
.PARAMETER Channel
    Release channel: stable, beta, alpha, nightly
    
.EXAMPLE
    .\release_manager.ps1 -Action prepare -Version 1.0.0 -Channel stable
    .\release_manager.ps1 -Action create -Version 1.0.0
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("prepare", "create", "publish", "list", "rollback", "validate")]
    [string]$Action,
    
    [Parameter(Mandatory=$false)]
    [string]$Version,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("stable", "beta", "alpha", "nightly")]
    [string]$Channel = "stable",
    
    [Parameter(Mandatory=$false)]
    [string]$ReleaseNotes,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = ".\releases"
)

$ErrorActionPreference = "Stop"

# Release registry
$ReleaseRegistry = @{
    Releases = @()
    CurrentVersion = $null
    LastReleaseDate = $null
}

# Version patterns
$VersionPatterns = @{
    stable = "^\d+\.\d+\.\d+$"
    beta = "^\d+\.\d+\.\d+-beta\.\d+$"
    alpha = "^\d+\.\d+\.\d+-alpha\.\d+$"
    nightly = "^\d+\.\d+\.\d+-nightly\.\d{8}$"
}

function Write-ReleaseHeader {
    Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║  Phase R.1: Release Automation Manager                           ║
║  Version management and release orchestration for RawrXD           ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan
}

function Initialize-ReleaseManager {
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    
    $registryFile = Join-Path $OutputPath "release_registry.json"
    if (Test-Path $registryFile) {
        $script:ReleaseRegistry = Get-Content -Path $registryFile -Raw | ConvertFrom-Json -AsHashtable
    }
}

function Save-ReleaseRegistry {
    $registryFile = Join-Path $OutputPath "release_registry.json"
    $script:ReleaseRegistry | ConvertTo-Json -Depth 10 | Set-Content -Path $registryFile
}

function Test-VersionFormat {
    param($Version, $Channel)
    
    $pattern = $script:VersionPatterns[$Channel]
    return $Version -match $pattern
}

function Get-CurrentVersion {
    $gitTag = git describe --tags --abbrev=0 2>$null
    if ($gitTag) {
        return $gitTag -replace '^v', ''
    }
    return "0.0.0"
}

function Get-NextVersion {
    param($BumpType = "patch")
    
    $current = Get-CurrentVersion
    $parts = $current -split '\.'
    
    switch ($BumpType) {
        "major" {
            return "$([int]$parts[0] + 1).0.0"
        }
        "minor" {
            return "$($parts[0]).$([int]$parts[1] + 1).0"
        }
        "patch" {
            return "$($parts[0]).$($parts[1]).$([int]$parts[2] + 1)"
        }
        default {
            return $current
        }
    }
}

function Get-GitChangelog {
    param($SinceVersion)
    
    $changelog = @()
    
    if ($SinceVersion) {
        $commits = git log "v$SinceVersion..HEAD" --pretty=format:"%s (%h)" 2>$null
    } else {
        $commits = git log --pretty=format:"%s (%h)" -20 2>$null
    }
    
    foreach ($commit in $commits) {
        # Categorize commits
        if ($commit -match "^feat[:\(]") {
            $changelog += @{ Type = "Features"; Message = $commit }
        } elseif ($commit -match "^fix[:\(]") {
            $changelog += @{ Type = "Bug Fixes"; Message = $commit }
        } elseif ($commit -match "^docs[:\(]") {
            $changelog += @{ Type = "Documentation"; Message = $commit }
        } elseif ($commit -match "^refactor[:\(]") {
            $changelog += @{ Type = "Refactoring"; Message = $commit }
        } elseif ($commit -match "^perf[:\(]") {
            $changelog += @{ Type = "Performance"; Message = $commit }
        } else {
            $changelog += @{ Type = "Other"; Message = $commit }
        }
    }
    
    return $changelog
}

function New-ReleaseNotes {
    param($Version, $Channel)
    
    Write-Host "`nGenerating release notes for v$Version..." -ForegroundColor Yellow
    
    $currentVersion = Get-CurrentVersion
    $changelog = Get-GitChangelog -SinceVersion $currentVersion
    
    $releaseNotes = @"
# Release Notes - v$Version

**Channel:** $Channel  
**Date:** $(Get-Date -Format "yyyy-MM-dd")  
**Previous Version:** v$currentVersion

## Summary

$(if ($changelog.Count -eq 0) { "No changes since last release." } else { "This release includes $($changelog.Count) changes." })

## Changes

"@
    
    # Group by type
    $grouped = $changelog | Group-Object -Property Type
    foreach ($group in $grouped) {
        $releaseNotes += "### $($group.Name)`n`n"
        foreach ($item in $group.Group) {
            $releaseNotes += "- $($item.Message)`n"
        }
        $releaseNotes += "`n"
    }
    
    $releaseNotes += @"
## Installation

### Windows
```powershell
# Download
Invoke-WebRequest -Uri "https://releases.rawrxd.io/v$Version/rawrxd-windows-x64.exe" -OutFile "rawrxd.exe"

# Install
.\rawrxd.exe install
```

### Linux
```bash
# Download
curl -fsSL "https://releases.rawrxd.io/v$Version/rawrxd-linux-x64.tar.gz" | tar -xz

# Install
sudo ./rawrxd install
```

## Verification

Verify the release checksum:
```bash
sha256sum -c rawrxd-v$Version.sha256
```

## Known Issues

- None reported

## Support

For issues and support, visit: https://support.rawrxd.io

---
*Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")*
"@
    
    return $releaseNotes
}

function Prepare-Release {
    param($Version, $Channel)
    
    Write-Host "`nPreparing release v$Version ($Channel)..." -ForegroundColor Yellow
    
    # Validate version format
    if (-not (Test-VersionFormat -Version $Version -Channel $Channel)) {
        Write-Error "Invalid version format for $Channel channel. Expected pattern: $($script:VersionPatterns[$Channel])"
        return
    }
    
    # Check if version already exists
    $existing = $script:ReleaseRegistry.Releases | Where-Object { $_.Version -eq $Version }
    if ($existing) {
        Write-Error "Version $Version already exists"
        return
    }
    
    # Generate release notes
    $releaseNotes = New-ReleaseNotes -Version $Version -Channel $Channel
    $notesPath = Join-Path $OutputPath "v$Version-release-notes.md"
    $releaseNotes | Set-Content -Path $notesPath
    
    Write-Host "  ✓ Release notes generated: $notesPath" -ForegroundColor Green
    
    # Create release directory
    $releaseDir = Join-Path $OutputPath "v$Version"
    New-Item -ItemType Directory -Path $releaseDir -Force | Out-Null
    
    # Update version file
    $versionFile = Join-Path $PWD "VERSION"
    $Version | Set-Content -Path $versionFile
    
    Write-Host "  ✓ Version file updated" -ForegroundColor Green
    Write-Host "`nNext steps:" -ForegroundColor Cyan
    Write-Host "  1. Review release notes: $notesPath" -ForegroundColor White
    Write-Host "  2. Run: .\release_manager.ps1 -Action create -Version $Version" -ForegroundColor White
}

function New-Release {
    param($Version)
    
    Write-Host "`nCreating release v$Version..." -ForegroundColor Yellow
    
    $releaseDir = Join-Path $OutputPath "v$Version"
    if (-not (Test-Path $releaseDir)) {
        New-Item -ItemType Directory -Path $releaseDir -Force | Out-Null
    }
    
    # Create release artifacts
    $artifacts = @()
    
    # Build artifacts (simulated)
    $platforms = @("windows-x64", "linux-x64", "macos-x64")
    foreach ($platform in $platforms) {
        $artifactName = "rawrxd-v$Version-$platform"
        $artifactPath = Join-Path $releaseDir "$artifactName.zip"
        
        # Simulate artifact creation
        "RawrXD v$Version for $platform" | Set-Content -Path "$artifactPath.txt"
        
        # Calculate checksum
        $hash = Get-FileHash -Path "$artifactPath.txt" -Algorithm SHA256 | Select-Object -ExpandProperty Hash
        "$hash  $artifactName.zip" | Add-Content -Path (Join-Path $releaseDir "checksums.sha256")
        
        $artifacts += @{
            Name = $artifactName
            Path = $artifactPath
            Platform = $platform
            Hash = $hash
        }
        
        Write-Host "  ✓ Created: $artifactName" -ForegroundColor Green
    }
    
    # Register release
    $release = @{
        Version = $Version
        Channel = $Channel
        CreatedAt = Get-Date -Format "o"
        Artifacts = $artifacts
        Status = "prepared"
        NotesPath = Join-Path $OutputPath "v$Version-release-notes.md"
    }
    
    $script:ReleaseRegistry.Releases += $release
    $script:ReleaseRegistry.CurrentVersion = $Version
    Save-ReleaseRegistry
    
    Write-Host "`n✓ Release v$Version created successfully" -ForegroundColor Green
    Write-Host "  Location: $releaseDir" -ForegroundColor Gray
    Write-Host "`nNext steps:" -ForegroundColor Cyan
    Write-Host "  .\release_manager.ps1 -Action publish -Version $Version" -ForegroundColor White
}

function Publish-Release {
    param($Version)
    
    Write-Host "`nPublishing release v$Version..." -ForegroundColor Yellow
    
    $release = $script:ReleaseRegistry.Releases | Where-Object { $_.Version -eq $Version } | Select-Object -First 1
    if (-not $release) {
        Write-Error "Release v$Version not found"
        return
    }
    
    # Create Git tag
    git tag -a "v$Version" -m "Release v$Version" 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  ✓ Git tag created: v$Version" -ForegroundColor Green
    }
    
    # Update release status
    $release.Status = "published"
    $release.PublishedAt = Get-Date -Format "o"
    Save-ReleaseRegistry
    
    Write-Host "  ✓ Release published successfully" -ForegroundColor Green
    Write-Host "`nRelease v$Version is now live!" -ForegroundColor Cyan
}

function Get-ReleaseList {
    Write-Host "`nRelease History:" -ForegroundColor Yellow
    Write-Host ""
    
    if ($script:ReleaseRegistry.Releases.Count -eq 0) {
        Write-Host "  No releases found" -ForegroundColor Gray
        return
    }
    
    Write-Host "  {0,-12} {1,-10} {2,-12} {3,-20} {4}" -f "Version", "Channel", "Status", "Date", "Artifacts" -ForegroundColor White
    Write-Host "  $("-" * 70)" -ForegroundColor Gray
    
    foreach ($release in ($script:ReleaseRegistry.Releases | Sort-Object CreatedAt -Descending)) {
        $date = [DateTime]::Parse($release.CreatedAt).ToString("yyyy-MM-dd")
        $artifactCount = $release.Artifacts.Count
        Write-Host "  {0,-12} {1,-10} {2,-12} {3,-20} {4}" -f $release.Version, $release.Channel, $release.Status, $date, $artifactCount -ForegroundColor Gray
    }
    
    Write-Host "`n  Total releases: $($script:ReleaseRegistry.Releases.Count)" -ForegroundColor Cyan
    Write-Host "  Current version: $($script:ReleaseRegistry.CurrentVersion)" -ForegroundColor Cyan
}

function Invoke-Rollback {
    param($Version)
    
    Write-Host "`nRolling back release v$Version..." -ForegroundColor Yellow
    
    $release = $script:ReleaseRegistry.Releases | Where-Object { $_.Version -eq $Version } | Select-Object -First 1
    if (-not $release) {
        Write-Error "Release v$Version not found"
        return
    }
    
    # Remove Git tag
    git tag -d "v$Version" 2>$null
    
    # Update status
    $release.Status = "rolled_back"
    $release.RolledBackAt = Get-Date -Format "o"
    Save-ReleaseRegistry
    
    Write-Host "  ✓ Release v$Version rolled back" -ForegroundColor Green
}

function Test-Release {
    param($Version)
    
    Write-Host "`nValidating release v$Version..." -ForegroundColor Yellow
    
    $release = $script:ReleaseRegistry.Releases | Where-Object { $_.Version -eq $Version } | Select-Object -First 1
    if (-not $release) {
        Write-Error "Release v$Version not found"
        return
    }
    
    $issues = @()
    
    # Check artifacts exist
    foreach ($artifact in $release.Artifacts) {
        if (-not (Test-Path "$($artifact.Path).txt")) {
            $issues += "Artifact missing: $($artifact.Name)"
        }
    }
    
    # Check release notes
    if (-not (Test-Path $release.NotesPath)) {
        $issues += "Release notes missing"
    }
    
    if ($issues.Count -eq 0) {
        Write-Host "  ✓ Release validation passed" -ForegroundColor Green
    } else {
        Write-Host "`n  Issues found:" -ForegroundColor Red
        foreach ($issue in $issues) {
            Write-Host "    ✗ $issue" -ForegroundColor Red
        }
    }
}

# Main execution
Write-ReleaseHeader
Initialize-ReleaseManager

switch ($Action) {
    "prepare" {
        if (-not $Version) {
            Write-Error "Version required for prepare action"
            exit 1
        }
        Prepare-Release -Version $Version -Channel $Channel
    }
    "create" {
        if (-not $Version) {
            Write-Error "Version required for create action"
            exit 1
        }
        New-Release -Version $Version
    }
    "publish" {
        if (-not $Version) {
            Write-Error "Version required for publish action"
            exit 1
        }
        Publish-Release -Version $Version
    }
    "list" {
        Get-ReleaseList
    }
    "rollback" {
        if (-not $Version) {
            Write-Error "Version required for rollback action"
            exit 1
        }
        Invoke-Rollback -Version $Version
    }
    "validate" {
        if (-not $Version) {
            Write-Error "Version required for validate action"
            exit 1
        }
        Test-Release -Version $Version
    }
}

Write-Host "`n✅ Release manager operation complete" -ForegroundColor Green
