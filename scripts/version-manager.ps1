# RawrXD Version Manager
# Phase F.1 Batch 2/5: Automated Version Management
# Usage: .\scripts\version-manager.ps1 [major|minor|patch|prerelease|finalize]

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("major", "minor", "patch", "prerelease", "finalize", "show", "validate")]
    [string]$Action,
    
    [string]$Message = "",
    [switch]$Force,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"

# Configuration
$VersionFile = "version.json"
$ChangelogFile = "CHANGELOG.md"
$VersionPattern = "^(\d+)\.(\d+)\.(\d+)(?:-([a-zA-Z0-9.]+))?$"

# ============================================================================
# Helper Functions
# ============================================================================

function Get-CurrentVersion {
    if (Test-Path $VersionFile) {
        $json = Get-Content $VersionFile | ConvertFrom-Json
        return $json.version
    }
    
    # Try to get from git tags
    $tag = git describe --tags --abbrev=0 2>$null
    if ($tag -and $tag -match "^v(\d+\.\d+\.\d+.*)$") {
        return $matches[1]
    }
    
    return "0.0.0"
}

function Parse-Version($version) {
    if ($version -match $VersionPattern) {
        return @{
            Major = [int]$matches[1]
            Minor = [int]$matches[2]
            Patch = [int]$matches[3]
            Prerelease = if ($matches[4]) { $matches[4] } else { $null }
        }
    }
    throw "Invalid version format: $version"
}

function Format-Version($parsed) {
    $version = "$($parsed.Major).$($parsed.Minor).$($parsed.Patch)"
    if ($parsed.Prerelease) {
        $version += "-$($parsed.Prerelease)"
    }
    return $version
}

function Bump-Version($current, $type) {
    $parsed = Parse-Version $current
    
    switch ($type) {
        "major" {
            $parsed.Major++
            $parsed.Minor = 0
            $parsed.Patch = 0
            $parsed.Prerelease = $null
        }
        "minor" {
            $parsed.Minor++
            $parsed.Patch = 0
            $parsed.Prerelease = $null
        }
        "patch" {
            $parsed.Patch++
            $parsed.Prerelease = $null
        }
        "prerelease" {
            if ($parsed.Prerelease -match "^(\w+)(\d+)$") {
                $num = [int]$matches[2] + 1
                $parsed.Prerelease = "$($matches[1])$num"
            } else {
                $parsed.Prerelease = "alpha1"
            }
        }
        "finalize" {
            $parsed.Prerelease = $null
        }
    }
    
    return Format-Version $parsed
}

function Get-GitChanges {
    $changes = @()
    
    # Get commits since last tag
    $lastTag = git describe --tags --abbrev=0 2>$null
    if ($lastTag) {
        $log = git log "$lastTag..HEAD" --pretty=format:"%s|%h|%an" 2>$null
    } else {
        $log = git log --pretty=format:"%s|%h|%an" 2>$null
    }
    
    foreach ($line in $log -split "`n") {
        if ($line -match "^(.+)\|(.+)\|(.+)$") {
            $changes += @{
                Message = $matches[1]
                Hash = $matches[2]
                Author = $matches[3]
                Category = Categorize-Commit $matches[1]
            }
        }
    }
    
    return $changes
}

function Categorize-Commit($message) {
    if ($message -match "^\[(feat|feature)\]|^feat:|^feature:") { return "feature" }
    if ($message -match "^\[(fix|bugfix)\]|^fix:|^bugfix:") { return "fix" }
    if ($message -match "^\[(perf|performance)\]|^perf:") { return "performance" }
    if ($message -match "^\[(docs|doc)\]|^docs:") { return "docs" }
    if ($message -match "^\[(test)\]|^test:") { return "test" }
    if ($message -match "^\[(refactor)\]|^refactor:") { return "refactor" }
    if ($message -match "^\[(chore)\]|^chore:") { return "chore" }
    if ($message -match "^\[(security|sec)\]|^security:") { return "security" }
    return "other"
}

function Generate-ChangelogSection($version, $changes, $date) {
    $section = @"
## [$version] - $date

"@
    
    $categories = @{
        "feature" = "### 🚀 Features"
        "fix" = "### 🐛 Bug Fixes"
        "performance" = "### ⚡ Performance"
        "security" = "### 🔒 Security"
        "docs" = "### 📚 Documentation"
        "test" = "### ✅ Tests"
        "refactor" = "### ♻️ Refactoring"
        "chore" = "### 🔧 Chores"
        "other" = "### 📝 Other"
    }
    
    foreach ($cat in $categories.Keys) {
        $catChanges = $changes | Where-Object { $_.Category -eq $cat }
        if ($catChanges) {
            $section += $categories[$cat] + "`n"
            foreach ($change in $catChanges) {
                $section += "- $($change.Message) (@$($change.Author))`n"
            }
            $section += "`n"
        }
    }
    
    return $section
}

function Update-VersionFile($version, $date) {
    $content = @{
        version = $version
        buildDate = $date
        buildNumber = if ($env:GITHUB_RUN_NUMBER) { $env:GITHUB_RUN_NUMBER } else { 0 }
        commit = (git rev-parse HEAD).Substring(0, 7)
        branch = git branch --show-current
    }
    
    $content | ConvertTo-Json -Depth 10 | Set-Content $VersionFile
}

function Update-AssemblyInfo($version) {
    $parsed = Parse-Version $version
    $assemblyVersion = "$($parsed.Major).$($parsed.Minor).$($parsed.Patch).0"
    $fileVersion = "$($parsed.Major).$($parsed.Minor).$($parsed.Patch).$($env:GITHUB_RUN_NUMBER)"
    
    # Update C++ version header
    $versionHeader = @"
#pragma once

#define RAWRXD_VERSION_MAJOR $($parsed.Major)
#define RAWRXD_VERSION_MINOR $($parsed.Minor)
#define RAWRXD_VERSION_PATCH $($parsed.Patch)
#define RAWRXD_VERSION_PRERELEASE "$($parsed.Prerelease)"
#define RAWRXD_VERSION_STRING "$version"
#define RAWRXD_VERSION_ASSEMBLY "$assemblyVersion"
#define RAWRXD_VERSION_FILE "$fileVersion"
"@
    
    $versionHeader | Set-Content "include/rawrxd_version.h"
    
    # Update PowerShell module manifest
    if (Test-Path "RawrXD.psd1") {
        (Get-Content "RawrXD.psd1") -replace "ModuleVersion\s*=\s*'[^']+'", "ModuleVersion = '$($parsed.Major).$($parsed.Minor).$($parsed.Patch)'" |
            Set-Content "RawrXD.psd1"
    }
}

# ============================================================================
# Main Execution
# ============================================================================

Write-Host "RawrXD Version Manager" -ForegroundColor Cyan
Write-Host "======================" -ForegroundColor Cyan
Write-Host ""

$currentVersion = Get-CurrentVersion
Write-Host "Current version: $currentVersion" -ForegroundColor Yellow

if ($Action -eq "show") {
    $changes = Get-GitChanges
    Write-Host "`nChanges since last version:" -ForegroundColor Cyan
    foreach ($change in $changes) {
        Write-Host "  [$($change.Category)] $($change.Message)" -ForegroundColor Gray
    }
    exit 0
}

if ($Action -eq "validate") {
    try {
        Parse-Version $currentVersion | Out-Null
        Write-Host "✅ Version format is valid" -ForegroundColor Green
        exit 0
    } catch {
        Write-Host "❌ Version format is invalid: $_" -ForegroundColor Red
        exit 1
    }
}

# Calculate new version
$newVersion = Bump-Version $currentVersion $Action
Write-Host "New version: $newVersion" -ForegroundColor Green

if ($DryRun) {
    Write-Host "`nDry run - no changes made" -ForegroundColor Yellow
    exit 0
}

# Confirm
if (-not $Force) {
    $confirm = Read-Host "Proceed with version bump? [Y/n]"
    if ($confirm -and $confirm -ne "Y" -and $confirm -ne "y") {
        Write-Host "Aborted" -ForegroundColor Red
        exit 1
    }
}

# Execute version bump
$date = Get-Date -Format "yyyy-MM-dd"
$changes = Get-GitChanges

Write-Host "`nExecuting version bump..." -ForegroundColor Cyan

# Update version file
Update-VersionFile $newVersion $date
Write-Host "  ✓ Updated $VersionFile" -ForegroundColor Green

# Update assembly info
Update-AssemblyInfo $newVersion
Write-Host "  ✓ Updated assembly info" -ForegroundColor Green

# Update CHANGELOG
$changelogSection = Generate-ChangelogSection $newVersion $changes $date

if (Test-Path $ChangelogFile) {
    $existing = Get-Content $ChangelogFile -Raw
    $newContent = $changelogSection + "`n" + $existing
    $newContent | Set-Content $ChangelogFile
} else {
    $header = @"
# Changelog

All notable changes to RawrXD will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

"@
    ($header + $changelogSection) | Set-Content $ChangelogFile
}
Write-Host "  ✓ Updated $ChangelogFile" -ForegroundColor Green

# Create git tag
$tagMessage = if ($Message) { $Message } else { "Release v$newVersion" }
git add -A
git commit -m "chore(release): bump version to v$newVersion`n`n$tagMessage" --allow-empty
git tag -a "v$newVersion" -m $tagMessage

Write-Host "  ✓ Created git tag v$newVersion" -ForegroundColor Green

Write-Host "`n✅ Version bump complete!" -ForegroundColor Green
Write-Host "`nNext steps:" -ForegroundColor Cyan
Write-Host "  1. Review the changes: git show HEAD" -ForegroundColor White
Write-Host "  2. Push the tag: git push origin v$newVersion" -ForegroundColor White
Write-Host "  3. The release workflow will trigger automatically" -ForegroundColor White
