# version_manager.ps1
# Phase F.1 Batch 4/5: Version management and release preparation

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("major", "minor", "patch", "prerelease", "show")]
    [string]$Bump,
    
    [string]$PrereleaseLabel = "",
    [switch]$DryRun,
    [switch]$CreateTag,
    [switch]$Push,
    [string]$ChangelogPath = "CHANGELOG.md"
)

$ErrorActionPreference = "Stop"

# ============================================================================
# Configuration
# ============================================================================

$VersionFile = "version.json"
$CMakeListsFile = "CMakeLists.txt"
$HeaderVersionFile = "include/rawrxd/version.h"

# ============================================================================
# Logging
# ============================================================================

function Write-Status($Message) {
    Write-Host "[VERSION] $Message" -ForegroundColor Cyan
}

function Write-Success($Message) {
    Write-Host "[SUCCESS] $Message" -ForegroundColor Green
}

function Write-Error($Message) {
    Write-Host "[ERROR] $Message" -ForegroundColor Red
}

# ============================================================================
# Version Parsing
# ============================================================================

function Get-CurrentVersion {
    if (Test-Path $VersionFile) {
        $content = Get-Content $VersionFile | ConvertFrom-Json
        return $content.version
    }
    
    # Try to parse from CMakeLists.txt
    if (Test-Path $CMakeListsFile) {
        $content = Get-Content $CMakeListsFile -Raw
        if ($content -match 'project\s*\(\s*\w+\s+VERSION\s+(\d+\.\d+\.\d+)') {
            return $Matches[1]
        }
    }
    
    return "1.0.0"
}

function Parse-Version($VersionString) {
    $parts = $VersionString -split '\.'
    $prerelease = $null
    
    if ($parts[2] -match '(\d+)-(.+)') {
        $prerelease = $Matches[2]
        $parts[2] = $Matches[1]
    }
    
    return @{
        major = [int]$parts[0]
        minor = [int]$parts[1]
        patch = [int]$parts[2]
        prerelease = $prerelease
        original = $VersionString
    }
}

function Format-Version($Version) {
    $base = "$($Version.major).$($Version.minor).$($Version.patch)"
    if ($Version.prerelease) {
        return "$base-$($Version.prerelease)"
    }
    return $base
}

# ============================================================================
# Version Bumping
# ============================================================================

function Bump-Version($Current, $BumpType, $Label) {
    $version = Parse-Version $Current
    
    switch ($BumpType) {
        "major" {
            $version.major++
            $version.minor = 0
            $version.patch = 0
            $version.prerelease = $null
        }
        "minor" {
            $version.minor++
            $version.patch = 0
            $version.prerelease = $null
        }
        "patch" {
            $version.patch++
            $version.prerelease = $null
        }
        "prerelease" {
            if ($Label) {
                $version.prerelease = $Label
            } elseif ($version.prerelease) {
                # Increment prerelease number
                if ($version.prerelease -match '^(\D+)(\d+)$') {
                    $prefix = $Matches[1]
                    $num = [int]$Matches[2] + 1
                    $version.prerelease = "$prefix$num"
                } else {
                    $version.prerelease = "$($version.prerelease).1"
                }
            } else {
                $version.patch++
                $version.prerelease = "alpha1"
            }
        }
    }
    
    return Format-Version $version
}

# ============================================================================
# File Updates
# ============================================================================

function Update-VersionFile($NewVersion) {
    Write-Status "Updating $VersionFile..."
    
    $content = @{
        version = $NewVersion
        timestamp = Get-Date -Format "o"
        channel = if ($NewVersion -match '-') { "prerelease" } else { "stable" }
    }
    
    $content | ConvertTo-Json | Out-File $VersionFile -Encoding UTF8
    Write-Success "Updated $VersionFile"
}

function Update-CMakeLists($NewVersion) {
    if (-not (Test-Path $CMakeListsFile)) { return }
    
    Write-Status "Updating $CMakeListsFile..."
    
    $content = Get-Content $CMakeListsFile -Raw
    $version = Parse-Version $NewVersion
    
    # Update project version
    $content = $content -replace 'project\s*\(\s*(\w+)\s+VERSION\s+\d+\.\d+\.\d+', "project(`$1 VERSION $($version.major).$($version.minor).$($version.patch)"
    
    $content | Out-File $CMakeListsFile -Encoding UTF8 -NoNewline
    Write-Success "Updated $CMakeListsFile"
}

function Update-HeaderVersion($NewVersion) {
    if (-not (Test-Path $HeaderVersionFile)) { return }
    
    Write-Status "Updating $HeaderVersionFile..."
    
    $version = Parse-Version $NewVersion
    $content = @"
#pragma once

#define RWRXD_VERSION_MAJOR $($version.major)
#define RWRXD_VERSION_MINOR $($version.minor)
#define RWRXD_VERSION_PATCH $($version.patch)
#define RWRXD_VERSION_STRING "$NewVersion"

#define RWRXD_VERSION ((RWRXD_VERSION_MAJOR << 16) | (RWRXD_VERSION_MINOR << 8) | RWRXD_VERSION_PATCH)
"@
    
    $content | Out-File $HeaderVersionFile -Encoding UTF8
    Write-Success "Updated $HeaderVersionFile"
}

function Update-PackageManifests($NewVersion) {
    Write-Status "Updating package manager manifests..."
    
    # Update Homebrew formula
    $homebrewFile = "packaging/package-managers/homebrew/rawrxd.rb"
    if (Test-Path $homebrewFile) {
        $content = Get-Content $homebrewFile -Raw
        $content = $content -replace 'version\s+"[^"]+"', "version `"$NewVersion`""
        $content | Out-File $homebrewFile -Encoding UTF8 -NoNewline
        Write-Success "Updated Homebrew formula"
    }
    
    # Update Chocolatey nuspec
    $chocoFile = "packaging/package-managers/chocolatey/rawrxd.nuspec"
    if (Test-Path $chocoFile) {
        $content = Get-Content $chocoFile -Raw
        $content = $content -replace '<version>[^<]+</version>', "<version>$NewVersion</version>"
        $content | Out-File $chocoFile -Encoding UTF8 -NoNewline
        Write-Success "Updated Chocolatey nuspec"
    }
    
    # Update winget manifest
    $wingetFile = "packaging/package-managers/winget/rawrxd.yaml"
    if (Test-Path $wingetFile) {
        $content = Get-Content $wingetFile -Raw
        $content = $content -replace 'PackageVersion:\s*\S+', "PackageVersion: $NewVersion"
        $content = $content -replace 'DisplayVersion:\s*\S+', "DisplayVersion: $NewVersion"
        $content | Out-File $wingetFile -Encoding UTF8 -NoNewline
        Write-Success "Updated winget manifest"
    }
}

# ============================================================================
# Changelog
# ============================================================================

function Update-Changelog($NewVersion) {
    if (-not (Test-Path $ChangelogPath)) {
        @"# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

"@ | Out-File $ChangelogPath -Encoding UTF8
    }
    
    Write-Status "Updating $ChangelogPath..."
    
    $date = Get-Date -Format "yyyy-MM-dd"
    $newEntry = @"

## [$NewVersion] - $date

### Added
- 

### Changed
- 

### Fixed
- 

"@
    
    $content = Get-Content $ChangelogPath -Raw
    $content = $content -replace "(# Changelog.*?\n\n)", "`$1$newEntry"
    $content | Out-File $ChangelogPath -Encoding UTF8 -NoNewline
    
    Write-Success "Updated $ChangelogPath"
}

# ============================================================================
# Git Operations
# ============================================================================

function Invoke-GitCommit($Version) {
    Write-Status "Creating git commit..."
    
    git add -A
    git commit -m "chore(release): bump version to $Version"
    
    Write-Success "Created commit"
}

function Invoke-GitTag($Version) {
    Write-Status "Creating git tag..."
    
    $tag = "v$Version"
    git tag -a $tag -m "Release $tag"
    
    Write-Success "Created tag: $tag"
    return $tag
}

function Invoke-GitPush($Tag) {
    Write-Status "Pushing to remote..."
    
    git push origin HEAD
    git push origin $Tag
    
    Write-Success "Pushed to remote"
}

# ============================================================================
# Main Execution
# ============================================================================

function Main {
    Write-Host ""
    Write-Host "=== RawrXD Version Manager ===" -ForegroundColor Cyan
    Write-Host ""
    
    $current = Get-CurrentVersion
    Write-Status "Current version: $current"
    
    if ($Bump -eq "show") {
        exit 0
    }
    
    $newVersion = Bump-Version $current $Bump $PrereleaseLabel
    Write-Status "New version: $newVersion"
    
    if ($DryRun) {
        Write-Host ""
        Write-Host "Dry run - no changes made" -ForegroundColor Yellow
        exit 0
    }
    
    # Update all version files
    Update-VersionFile $newVersion
    Update-CMakeLists $newVersion
    Update-HeaderVersion $newVersion
    Update-PackageManifests $newVersion
    Update-Changelog $newVersion
    
    # Git operations
    Invoke-GitCommit $newVersion
    
    if ($CreateTag) {
        $tag = Invoke-GitTag $newVersion
        
        if ($Push) {
            Invoke-GitPush $tag
        }
    }
    
    Write-Host ""
    Write-Success "Version bumped to $newVersion"
    Write-Host ""
}

Main
