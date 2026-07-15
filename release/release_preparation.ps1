# RawrXD Release Preparation
# Phase I Batch 1/5: Version Tagging and Release Notes
# Prepares the release artifacts and documentation

param(
    [Parameter()]
    [ValidateSet("Prepare", "Tag", "Notes", "Checklist", "ShowStatus")]
    [string]$Action = "Prepare",
    
    [Parameter()]
    [string]$Version,
    
    [Parameter()]
    [string]$ReleaseBranch = "main",
    
    [Parameter()]
    [string]$OutputPath = "$PSScriptRoot\artifacts",
    
    [Parameter()]
    [string]$LogPath = "$PSScriptRoot\..\logs\release",
    
    [Parameter()]
    [string]$PreviousVersion,
    
    [Parameter()]
    [switch]$Draft
)

# Release configuration
$ReleaseConfig = @{
    ProductName = "RawrXD"
    Description = "Sovereign AI Inference Runtime"
    Repository = "https://github.com/ItsMehRAWRXD/RawrXD"
    License = "MIT"
    MinPowerShellVersion = "7.0"
    SupportedPlatforms = @("Windows", "Linux")
}

# Ensure directories exist
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}
if (-not (Test-Path $LogPath)) {
    New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
}

# State file
$StateFile = "$PSScriptRoot\release_state.json"

function Write-ReleaseLog {
    param([string]$Message, [string]$Level = "INFO")
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    $logFile = Join-Path $LogPath "release_$(Get-Date -Format 'yyyyMMdd').log"
    Add-Content -Path $logFile -Value $logEntry
    
    $color = switch ($Level) {
        "ERROR" { "Red" }
        "WARN"  { "Yellow" }
        "SUCCESS" { "Green" }
        "RELEASE" { "Cyan" }
        default { "White" }
    }
    Write-Host $logEntry -ForegroundColor $color
}

function Get-ReleaseState {
    if (Test-Path $StateFile) {
        return Get-Content $StateFile | ConvertFrom-Json
    }
    return @{
        CurrentVersion = $null
        LastReleaseDate = $null
        Releases = @()
        PreparationComplete = $false
        ValidationComplete = $false
        PackagingComplete = $false
        DocumentationComplete = $false
        Released = $false
    }
}

function Save-ReleaseState {
    param($State)
    $State | ConvertTo-Json -Depth 10 | Out-File $StateFile -Encoding UTF8
}

function Get-VersionFromGit {
    try {
        $tag = git describe --tags --abbrev=0 2>$null
        if ($tag) {
            return $tag -replace '^v', ''
        }
    }
    catch {
        Write-ReleaseLog "No git tags found" "WARN"
    }
    return "0.0.0"
}

function Get-GitChanges {
    param([string]$SinceVersion)
    
    $changes = @{
        Features = @()
        Fixes = @()
        Improvements = @()
        Breaking = @()
        Other = @()
    }
    
    try {
        $log = git log --pretty=format:"%s" "v$SinceVersion..HEAD" 2>$null
        if ($log) {
            $commits = $log -split "`n"
            foreach ($commit in $commits) {
                if ($commit -match "^feat[:\(]") {
                    $changes.Features += $commit
                }
                elseif ($commit -match "^fix[:\(]") {
                    $changes.Fixes += $commit
                }
                elseif ($commit -match "^docs[:\(]|^perf[:\(]|^refactor[:\(]") {
                    $changes.Improvements += $commit
                }
                elseif ($commit -match "^BREAKING|^breaking") {
                    $changes.Breaking += $commit
                }
                else {
                    $changes.Other += $commit
                }
            }
        }
    }
    catch {
        Write-ReleaseLog "Could not retrieve git changes: $_" "WARN"
    }
    
    return $changes
}

function New-ReleaseNotes {
    param(
        [string]$Version,
        [hashtable]$Changes
    )
    
    $notes = @"
# RawrXD v$Version Release Notes

**Release Date:** $(Get-Date -Format "yyyy-MM-dd")  
**Status:** $(if($Draft){"Draft"}else{"Final"})  
**Branch:** $ReleaseBranch

## Overview

This release of RawrXD includes $(($Changes.Features.Count + $Changes.Fixes.Count + $Changes.Improvements.Count)) changes.

## What's New

"@
    
    if ($Changes.Features.Count -gt 0) {
        $notes += "### ✨ New Features`n`n"
        foreach ($feature in $Changes.Features) {
            $notes += "- $feature`n"
        }
        $notes += "`n"
    }
    
    if ($Changes.Improvements.Count -gt 0) {
        $notes += "### 🚀 Improvements`n`n"
        foreach ($improvement in $Changes.Improvements) {
            $notes += "- $improvement`n"
        }
        $notes += "`n"
    }
    
    if ($Changes.Fixes.Count -gt 0) {
        $notes += "### 🐛 Bug Fixes`n`n"
        foreach ($fix in $Changes.Fixes) {
            $notes += "- $fix`n"
        }
        $notes += "`n"
    }
    
    if ($Changes.Breaking.Count -gt 0) {
        $notes += "### ⚠️ Breaking Changes`n`n"
        foreach ($breaking in $Changes.Breaking) {
            $notes += "- $breaking`n"
        }
        $notes += "`n"
    }
    
    $notes += @"

## Installation

```powershell
# Download and install
Invoke-Expression (Invoke-RestMethod -Uri '$($ReleaseConfig.Repository)/releases/download/v$Version/install.ps1')
```

## System Requirements

- PowerShell $($ReleaseConfig.MinPowerShellVersion) or higher
- Windows 10/11 or Linux
- 8GB RAM minimum (16GB recommended)

## Documentation

- [Getting Started](docs/getting-started.md)
- [API Reference](docs/api-reference.md)
- [Architecture](docs/architecture.md)

## Known Issues

None reported.

## Feedback

Please report issues at: $($ReleaseConfig.Repository)/issues

---

**Full Changelog**: $($ReleaseConfig.Repository)/compare/v$PreviousVersion...v$Version
"@
    
    return $notes
}

function Invoke-ReleasePreparation {
    param([string]$Version)
    
    Write-ReleaseLog "Preparing release v$Version..." "RELEASE"
    
    $state = Get-ReleaseState
    $previousVersion = if ($state.CurrentVersion) { $state.CurrentVersion } else { Get-VersionFromGit }
    
    # Get changes since last version
    Write-ReleaseLog "Retrieving changes since v$previousVersion..." "RELEASE"
    $changes = Get-GitChanges -SinceVersion $previousVersion
    
    Write-ReleaseLog "Found: $($changes.Features.Count) features, $($changes.Fixes.Count) fixes, $($changes.Improvements.Count) improvements" "INFO"
    
    # Generate release notes
    $releaseNotes = New-ReleaseNotes -Version $Version -Changes $changes
    $notesPath = Join-Path $OutputPath "RELEASE_NOTES_v$Version.md"
    $releaseNotes | Out-File $notesPath -Encoding UTF8
    Write-ReleaseLog "Release notes generated: $notesPath" "SUCCESS"
    
    # Create version file
    $versionInfo = @{
        Version = $Version
        PreviousVersion = $previousVersion
        ReleaseDate = Get-Date -Format "yyyy-MM-dd"
        Branch = $ReleaseBranch
        Changes = $changes
        Generated = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
    $versionPath = Join-Path $OutputPath "version_v$Version.json"
    $versionInfo | ConvertTo-Json -Depth 10 | Out-File $versionPath -Encoding UTF8
    Write-ReleaseLog "Version info saved: $versionPath" "SUCCESS"
    
    # Create checklist
    $checklist = @"
# Release v$Version Checklist

## Pre-Release
- [ ] All tests passing
- [ ] Documentation updated
- [ ] Security audit passed
- [ ] Performance benchmarks met
- [ ] Breaking changes documented

## Release
- [ ] Version tagged in git
- [ ] Release notes published
- [ ] Binaries built and signed
- [ ] Packages created
- [ ] GitHub release created

## Post-Release
- [ ] Announcement published
- [ ] Documentation site updated
- [ ] Support channels monitored
- [ ] Hotfix plan ready

Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
"@
    $checklistPath = Join-Path $OutputPath "CHECKLIST_v$Version.md"
    $checklist | Out-File $checklistPath -Encoding UTF8
    Write-ReleaseLog "Checklist created: $checklistPath" "SUCCESS"
    
    # Update state
    $state.CurrentVersion = $Version
    $state.PreparationComplete = $true
    Save-ReleaseState -State $state
    
    Write-ReleaseLog "Release preparation complete for v$Version" "SUCCESS"
    
    return @{
        Version = $Version
        PreviousVersion = $previousVersion
        ReleaseNotesPath = $notesPath
        VersionInfoPath = $versionPath
        ChecklistPath = $checklistPath
        Changes = $changes
    }
}

function Invoke-VersionTag {
    param([string]$Version)
    
    Write-ReleaseLog "Creating git tag for v$Version..." "RELEASE"
    
    try {
        # Create annotated tag
        $tagMessage = "Release v$Version`n`n$(Get-Date -Format 'yyyy-MM-dd')`n`nSee RELEASE_NOTES_v$Version.md for details"
        git tag -a "v$Version" -m $tagMessage
        
        Write-ReleaseLog "Git tag v$Version created" "SUCCESS"
        
        # Push tag
        git push origin "v$Version"
        Write-ReleaseLog "Git tag v$Version pushed to origin" "SUCCESS"
        
        return $true
    }
    catch {
        Write-ReleaseLog "Failed to create git tag: $_" "ERROR"
        return $false
    }
}

function Show-ReleaseStatus {
    $state = Get-ReleaseState
    
    Write-Host "`n╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║           RawrXD Release Preparation Status                   ║" -ForegroundColor Cyan
    Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "║ Current Version: $($state.CurrentVersion)" -ForegroundColor Cyan
    Write-Host "║ Last Release: $($state.LastReleaseDate)" -ForegroundColor Cyan
    Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "║ Preparation Steps:" -ForegroundColor Cyan
    Write-Host "║   [$(if($state.PreparationComplete){'x'}else{' '})] Release Preparation" -ForegroundColor $(if($state.PreparationComplete){"Green"}else{"Gray"})
    Write-Host "║   [$(if($state.ValidationComplete){'x'}else{' '})] Final Validation" -ForegroundColor $(if($state.ValidationComplete){"Green"}else{"Gray"})
    Write-Host "║   [$(if($state.PackagingComplete){'x'}else{' '})] Packaging" -ForegroundColor $(if($state.PackagingComplete){"Green"}else{"Gray"})
    Write-Host "║   [$(if($state.DocumentationComplete){'x'}else{' '})] Documentation" -ForegroundColor $(if($state.DocumentationComplete){"Green"}else{"Gray"})
    Write-Host "║   [$(if($state.Released){'x'}else{' '})] Released" -ForegroundColor $(if($state.Released){"Green"}else{"Gray"})
    Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    
    if ($state.Releases.Count -gt 0) {
        Write-Host "║ Release History:" -ForegroundColor Cyan
        foreach ($release in $state.Releases | Select-Object -Last 5) {
            Write-Host "║   v$($release.Version) - $($release.Date) ($(if($release.Success){'Success'}else{'Failed'}))" -ForegroundColor $(if($release.Success){"Green"}else{"Red"})
        }
    }
    
    Write-Host "╚══════════════════════════════════════════════════════════════╝`n" -ForegroundColor Cyan
}

# Main execution
switch ($Action) {
    "Prepare" {
        if (-not $Version) {
            Write-ReleaseLog "Version parameter required" "ERROR"
            exit 1
        }
        $result = Invoke-ReleasePreparation -Version $Version
        $result | ConvertTo-Json -Depth 10
    }
    "Tag" {
        if (-not $Version) {
            Write-ReleaseLog "Version parameter required" "ERROR"
            exit 1
        }
        $success = Invoke-VersionTag -Version $Version
        exit ($success ? 0 : 1)
    }
    "Notes" {
        if (-not $Version) {
            $Version = Get-VersionFromGit
        }
        $previousVersion = if ($PreviousVersion) { $PreviousVersion } else { "0.0.0" }
        $changes = Get-GitChanges -SinceVersion $previousVersion
        $notes = New-ReleaseNotes -Version $Version -Changes $changes
        $notes
    }
    "Checklist" {
        if (-not $Version) {
            Write-ReleaseLog "Version parameter required" "ERROR"
            exit 1
        }
        $checklist = @"
# Release v$Version Checklist

## Pre-Release
- [ ] All tests passing
- [ ] Documentation updated
- [ ] Security audit passed
- [ ] Performance benchmarks met
- [ ] Breaking changes documented

## Release
- [ ] Version tagged in git
- [ ] Release notes published
- [ ] Binaries built and signed
- [ ] Packages created
- [ ] GitHub release created

## Post-Release
- [ ] Announcement published
- [ ] Documentation site updated
- [ ] Support channels monitored
- [ ] Hotfix plan ready
"@
        $checklist
    }
    "ShowStatus" {
        Show-ReleaseStatus
    }
}
