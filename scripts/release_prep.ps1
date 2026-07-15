#!/usr/bin/env pwsh
#Requires -Version 7.0
<#
.SYNOPSIS
    Release Preparation Script for RawrXD

.DESCRIPTION
    Automates release preparation tasks:
    - Version bumping across all relevant files
    - Changelog generation from git commits
    - Release notes preparation
    - Artifact validation
    - Git tag creation
    - Pre-release checks

.EXAMPLE
    .\scripts\release_prep.ps1 -Version 1.2.0
    .\scripts\release_prep.ps1 -Version 1.2.0-rc1 -PreRelease
    .\scripts\release_prep.ps1 -Version 1.2.0 -CreateTag -Push

.NOTES
    Part of RawrXD Phase AB: CI/CD Pipeline & Automation
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)]
    [string]$Version,

    [Parameter()]
    [switch]$PreRelease,

    [Parameter()]
    [string]$PreviousVersion = "",

    [Parameter()]
    [switch]$CreateTag,

    [Parameter()]
    [switch]$Push,

    [Parameter()]
    [string]$ReleaseNotesFile = "RELEASE_NOTES.md",

    [Parameter()]
    [string]$ChangelogFile = "CHANGELOG.md",

    [Parameter()]
    [switch]$SkipTests,

    [Parameter()]
    [switch]$Force
)

# ============================================================================
# Configuration
# ============================================================================

$Config = @{
    VersionFiles = @(
        @{ Path = "CMakeLists.txt"; Pattern = 'project\s*\(\s*RawrXD\s+VERSION\s+([\d.]+)'; Template = 'project(RawrXD VERSION {0})' }
        @{ Path = "package.json"; Pattern = '"version"\s*:\s*"([\d.]+)"'; Template = '"version": "{0}"' }
        @{ Path = "src/core/version.hpp"; Pattern = 'RAWRXD_VERSION\s+"([\d.]+)"'; Template = '#define RAWRXD_VERSION "{0}"' }
        @{ Path = "include/rawrxd/core.hpp"; Pattern = 'RAWRXD_VERSION_STR\s+"([\d.]+)"'; Template = '#define RAWRXD_VERSION_STR "{0}"' }
    )

    RequiredFiles = @(
        "README.md"
        "LICENSE"
        "CHANGELOG.md"
        "CMakeLists.txt"
    )

    ArtifactPaths = @(
        "build*/bin/*"
        "build*/Release/*"
        "build*/RelWithDebInfo/*"
    )
}

$script:ChangesMade = $false
$script:Errors = @()

# ============================================================================
# Helper Functions
# ============================================================================

function Write-Status {
    param([string]$Message, [string]$Status = "Info")
    $colors = @{ Info = "Cyan"; Success = "Green"; Warning = "Yellow"; Error = "Red" }
    Write-Host "[$Status] " -ForegroundColor $colors[$Status] -NoNewline
    Write-Host $Message
}

function Write-Section {
    param([string]$Title)
    Write-Host "`n========================================" -ForegroundColor Blue
    Write-Host $Title -ForegroundColor Blue
    Write-Host "========================================" -ForegroundColor Blue
}

function Test-VersionFormat {
    param([string]$Ver)
    # Support formats: 1.2.3, 1.2.3-rc1, 1.2.3-beta.1, etc.
    return $Ver -match '^\d+\.\d+\.\d+(-[a-zA-Z0-9.]+)?$'
}

function Get-GitCommitsSince {
    param([string]$SinceTag)

    if ([string]::IsNullOrEmpty($SinceTag)) {
        # Get last 20 commits if no previous version specified
        $commits = git log --pretty=format:"%h|%s|%an|%ad" --date=short -20 2>$null
    } else {
        $commits = git log --pretty=format:"%h|%s|%an|%ad" "$SinceTag..HEAD" 2>$null
    }

    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrEmpty($commits)) {
        return @()
    }

    return $commits | ForEach-Object {
        $parts = $_ -split '\|', 4
        [PSCustomObject]@{
            Hash = $parts[0]
            Subject = $parts[1]
            Author = $parts[2]
            Date = $parts[3]
            Category = Get-CommitCategory $parts[1]
        }
    }
}

function Get-CommitCategory {
    param([string]$Subject)
    if ($Subject -match "^feat(\(.+\))?:") { return "Features" }
    if ($Subject -match "^fix(\(.+\))?:") { return "Bug Fixes" }
    if ($Subject -match "^docs(\(.+\))?:") { return "Documentation" }
    if ($Subject -match "^perf(\(.+\))?:") { return "Performance" }
    if ($Subject -match "^refactor(\(.+\))?:") { return "Refactoring" }
    if ($Subject -match "^test(\(.+\))?:") { return "Tests" }
    if ($Subject -match "^chore(\(.+\))?:") { return "Chores" }
    if ($Subject -match "^security(\(.+\))?:") { return "Security" }
    return "Other"
}

# ============================================================================
# Pre-Release Checks
# ============================================================================

function Test-PreReleaseChecks {
    Write-Section "Pre-Release Checks"

    # Check git status
    $gitStatus = git status --porcelain 2>$null
    if ($gitStatus) {
        Write-Status "Working directory has uncommitted changes" "Error"
        if (-not $Force) {
            $script:Errors += "Uncommitted changes in working directory"
            return $false
        }
    } else {
        Write-Status "Working directory is clean" "Success"
    }

    # Check required files exist
    foreach ($file in $Config.RequiredFiles) {
        if (Test-Path $file) {
            Write-Status "Required file exists: $file" "Success"
        } else {
            Write-Status "Required file missing: $file" "Error"
            $script:Errors += "Missing required file: $file"
        }
    }

    # Check version format
    if (Test-VersionFormat $Version) {
        Write-Status "Version format is valid: $Version" "Success"
    } else {
        Write-Status "Invalid version format: $Version" "Error"
        $script:Errors += "Invalid version format. Expected: X.Y.Z or X.Y.Z-prerelease"
        return $false
    }

    # Check if version already exists
    $existingTag = git tag -l "v$Version" 2>$null
    if ($existingTag) {
        Write-Status "Version tag already exists: v$Version" "Error"
        if (-not $Force) {
            $script:Errors += "Version v$Version already exists"
            return $false
        }
    }

    # Run tests if not skipped
    if (-not $SkipTests) {
        Write-Status "Running test suite..." "Info"
        $testResult = & "$PSScriptRoot/ci_test.ps1" -Configuration Release -OutputFormat JUnit 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Status "Tests failed" "Error"
            if (-not $Force) {
                $script:Errors += "Test suite failed"
                return $false
            }
        } else {
            Write-Status "All tests passed" "Success"
        }
    }

    return ($script:Errors.Count -eq 0)
}

# ============================================================================
# Version Bumping
# ============================================================================

function Update-VersionFiles {
    Write-Section "Updating Version Files"

    foreach ($fileConfig in $Config.VersionFiles) {
        $filePath = $fileConfig.Path

        if (-not (Test-Path $filePath)) {
            Write-Status "File not found, skipping: $filePath" "Warning"
            continue
        }

        $content = Get-Content -Path $filePath -Raw
        $pattern = $fileConfig.Pattern

        if ($content -match $pattern) {
            $oldVersion = $Matches[1]
            $newContent = $content -replace $pattern, ($fileConfig.Template -f $Version)

            if ($PSCmdlet.ShouldProcess($filePath, "Update version from $oldVersion to $Version")) {
                $newContent | Set-Content -Path $filePath -NoNewline
                Write-Status "Updated $filePath`: $oldVersion -> $Version" "Success"
                $script:ChangesMade = $true
            }
        } else {
            Write-Status "Version pattern not found in: $filePath" "Warning"
        }
    }
}

# ============================================================================
# Changelog Generation
# ============================================================================

function Update-Changelog {
    Write-Section "Generating Changelog"

    $commits = Get-GitCommitsSince -SinceTag $PreviousVersion

    if ($commits.Count -eq 0) {
        Write-Status "No commits found since $PreviousVersion" "Warning"
        return
    }

    Write-Status "Found $($commits.Count) commits since $PreviousVersion" "Info"

    # Group commits by category
    $grouped = $commits | Group-Object -Property Category

    # Generate changelog entry
    $date = Get-Date -Format "yyyy-MM-dd"
    $changelogEntry = @"
## [$Version] - $date

"@

    foreach ($group in $grouped | Sort-Object Name) {
        $changelogEntry += "### $($group.Name)`n`n"
        foreach ($commit in $group.Group) {
            $changelogEntry += "- $($commit.Subject) ($($commit.Hash))`n"
        }
        $changelogEntry += "`n"
    }

    # Prepend to CHANGELOG.md
    if (Test-Path $ChangelogFile) {
        $existingContent = Get-Content -Path $ChangelogFile -Raw
        $newContent = $changelogEntry + "`n" + $existingContent
    } else {
        $newContent = "# Changelog`n`n" + $changelogEntry
    }

    if ($PSCmdlet.ShouldProcess($ChangelogFile, "Update changelog")) {
        $newContent | Set-Content -Path $ChangelogFile -Encoding UTF8
        Write-Status "Updated $ChangelogFile" "Success"
        $script:ChangesMade = $true
    }
}

# ============================================================================
# Release Notes Generation
# ============================================================================

function New-ReleaseNotes {
    Write-Section "Generating Release Notes"

    $commits = Get-GitCommitsSince -SinceTag $PreviousVersion
    $grouped = $commits | Group-Object -Property Category

    $releaseType = if ($PreRelease) { "Pre-Release" } else { "Release" }

    $releaseNotes = @"
# RawrXD $releaseType v$Version

**Release Date:** $(Get-Date -Format "yyyy-MM-dd")  
**Status:** $(if ($PreRelease) { "⚠️ Pre-Release" } else { "✅ Stable" })

## Highlights

$(if ($PreRelease) { "> ⚠️ This is a pre-release version for testing purposes." } else { "> This release includes stability improvements and new features." })

## Changes

"@

    foreach ($group in $grouped | Sort-Object Name) {
        $releaseNotes += "### $($group.Name)`n`n"
        foreach ($commit in $group.Group) {
            $releaseNotes += "- $($commit.Subject)`n"
        }
        $releaseNotes += "`n"
    }

    $releaseNotes += @"
## Installation

### Windows
```powershell
# Download and install
Invoke-WebRequest -Uri "https://github.com/ItsMehRAWRXD/RawrXD/releases/download/v$Version/RawrXD-v$Version-win64.zip" -OutFile "rawrxd.zip"
Expand-Archive -Path "rawrxd.zip" -DestinationPath "C:\Program Files\RawrXD"
```

### Linux
```bash
# Download and install
wget https://github.com/ItsMehRAWRXD/RawrXD/releases/download/v$Version/RawrXD-v$Version-linux-x64.tar.gz
tar -xzf RawrXD-v$Version-linux-x64.tar.gz
sudo cp -r RawrXD /opt/
```

### macOS
```bash
# Using Homebrew
brew install rawrxd
```

## Artifacts

| Platform | Architecture | Download |
|----------|-------------|----------|
| Windows | x64 | [RawrXD-v$Version-win64.zip](https://github.com/ItsMehRAWRXD/RawrXD/releases/download/v$Version/RawrXD-v$Version-win64.zip) |
| Linux | x64 | [RawrXD-v$Version-linux-x64.tar.gz](https://github.com/ItsMehRAWRXD/RawrXD/releases/download/v$Version/RawrXD-v$Version-linux-x64.tar.gz) |
| macOS | x64 | [RawrXD-v$Version-macos-x64.tar.gz](https://github.com/ItsMehRAWRXD/RawrXD/releases/download/v$Version/RawrXD-v$Version-macos-x64.tar.gz) |
| macOS | ARM64 | [RawrXD-v$Version-macos-arm64.tar.gz](https://github.com/ItsMehRAWRXD/RawrXD/releases/download/v$Version/RawrXD-v$Version-macos-arm64.tar.gz) |

## Checksums

```
# SHA-256 checksums will be added here after artifact generation
```

## Known Issues

$(if ($PreRelease) { "- This is a pre-release and may contain bugs" } else { "- None reported" })

## Full Changelog

See [CHANGELOG.md](./CHANGELOG.md) for the complete version history.

---
*Generated by RawrXD Release Preparation Script*
"@

    if ($PSCmdlet.ShouldProcess($ReleaseNotesFile, "Create release notes")) {
        $releaseNotes | Set-Content -Path $ReleaseNotesFile -Encoding UTF8
        Write-Status "Created $ReleaseNotesFile" "Success"
        $script:ChangesMade = $true
    }
}

# ============================================================================
# Git Operations
# ============================================================================

function Invoke-GitOperations {
    Write-Section "Git Operations"

    if (-not $script:ChangesMade) {
        Write-Status "No changes to commit" "Warning"
        return
    }

    # Stage changes
    if ($PSCmdlet.ShouldProcess("Git", "Stage version file changes")) {
        git add -A
        Write-Status "Staged changes" "Success"
    }

    # Commit
    $commitMessage = "Release v$Version`n`n- Bump version to $Version`n- Update CHANGELOG.md`n- Add release notes"
    if ($PreRelease) {
        $commitMessage = "Pre-release v$Version`n`n- Bump version to $Version`n- Update CHANGELOG.md`n- Add pre-release notes"
    }

    if ($PSCmdlet.ShouldProcess("Git", "Create release commit")) {
        git commit -m $commitMessage
        Write-Status "Created release commit" "Success"
    }

    # Create tag
    if ($CreateTag) {
        $tagName = "v$Version"
        $tagMessage = "Release $tagName"

        if ($PSCmdlet.ShouldProcess("Git", "Create tag $tagName")) {
            git tag -a $tagName -m $tagMessage
            Write-Status "Created tag: $tagName" "Success"
        }

        # Push
        if ($Push) {
            if ($PSCmdlet.ShouldProcess("Git", "Push commit and tag to origin")) {
                git push origin HEAD
                git push origin $tagName
                Write-Status "Pushed to origin" "Success"
            }
        }
    }
}

# ============================================================================
# Summary
# ============================================================================

function Write-Summary {
    Write-Section "Release Preparation Summary"

    Write-Host "Version: $Version" -ForegroundColor Cyan
    Write-Host "Pre-release: $PreRelease" -ForegroundColor Cyan
    Write-Host "Changes made: $script:ChangesMade" -ForegroundColor Cyan
    Write-Host ""

    if ($script:Errors.Count -gt 0) {
        Write-Host "Errors encountered:" -ForegroundColor Red
        foreach ($error in $script:Errors) {
            Write-Host "  - $error" -ForegroundColor Red
        }
        return 1
    }

    if ($script:ChangesMade) {
        Write-Host "✅ Release preparation complete!" -ForegroundColor Green
        Write-Host ""
        Write-Host "Next steps:" -ForegroundColor Yellow
        if (-not $CreateTag) {
            Write-Host "  1. Review the changes" -ForegroundColor White
            Write-Host "  2. Run: .\scripts\release_prep.ps1 -Version $Version -CreateTag" -ForegroundColor White
        } elseif (-not $Push) {
            Write-Host "  1. Review the commit and tag" -ForegroundColor White
            Write-Host "  2. Run: git push origin HEAD && git push origin v$Version" -ForegroundColor White
        } else {
            Write-Host "  1. GitHub Actions will build and publish the release" -ForegroundColor White
            Write-Host "  2. Verify the release at: https://github.com/ItsMehRAWRXD/RawrXD/releases" -ForegroundColor White
        }
    } else {
        Write-Host "ℹ️ No changes were made (dry run or no changes needed)" -ForegroundColor Yellow
    }

    return 0
}

# ============================================================================
# Main Execution
# ============================================================================

function Main {
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "RawrXD Release Preparation Tool" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""

    # Auto-detect previous version if not specified
    if ([string]::IsNullOrEmpty($PreviousVersion)) {
        $latestTag = git describe --tags --abbrev=0 2>$null
        if ($latestTag) {
            $PreviousVersion = $latestTag
            Write-Status "Auto-detected previous version: $PreviousVersion" "Info"
        }
    }

    # Run pre-release checks
    if (-not (Test-PreReleaseChecks)) {
        Write-Status "Pre-release checks failed. Use -Force to override." "Error"
        exit 1
    }

    # Execute release preparation steps
    Update-VersionFiles
    Update-Changelog
    New-ReleaseNotes
    Invoke-GitOperations

    # Show summary
    $exitCode = Write-Summary
    exit $exitCode
}

# Run main
Main
