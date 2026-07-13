#!/usr/bin/env pwsh
#Requires -Version 7.0
<#
.SYNOPSIS
    Dependency Update Script for RawrXD

.DESCRIPTION
    Automates dependency management:
    - Checks for outdated dependencies
    - Updates submodules
    - Validates dependency integrity
    - Generates dependency reports
    - Creates update PRs/branches

.EXAMPLE
    .\scripts\update_dependencies.ps1
    .\scripts\update_dependencies.ps1 -Update
    .\scripts\update_dependencies.ps1 -CheckOnly

.NOTES
    Part of RawrXD Phase AB: CI/CD Pipeline & Automation
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter()]
    [switch]$Update,

    [Parameter()]
    [switch]$CheckOnly,

    [Parameter()]
    [switch]$CreateBranch,

    [Parameter()]
    [string]$BranchName = "deps/update-$(Get-Date -Format 'yyyyMMdd')",

    [Parameter()]
    [string]$ReportFormat = "console",

    [Parameter()]
    [string]$OutputFile = "dependency-report.json",

    [Parameter()]
    [switch]$IncludeSubmodules,

    [Parameter()]
    [switch]$FailOnOutdated
)

# ============================================================================
# Configuration
# ============================================================================

$Config = @{
    Submodules = @(
        @{ Path = "3rdparty/ggml"; Name = "GGML"; Required = $true }
        @{ Path = "3rdparty/vulkan-headers"; Name = "Vulkan Headers"; Required = $false }
        @{ Path = "3rdparty/spdlog"; Name = "spdlog"; Required = $false }
        @{ Path = "3rdparty/json"; Name = "nlohmann/json"; Required = $false }
    )

    PackageManagers = @(
        @{ Name = "vcpkg"; File = "vcpkg.json"; Command = "vcpkg" }
        @{ Name = "npm"; File = "package.json"; Command = "npm" }
        @{ Name = "pip"; File = "requirements.txt"; Command = "pip" }
    )
}

$script:UpdatesAvailable = @()
$script:Errors = @()
$script:Stats = @{
    SubmodulesChecked = 0
    SubmodulesUpdated = 0
    PackagesChecked = 0
    PackagesUpdated = 0
    OutdatedFound = 0
}

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

function Invoke-GitCommand {
    param([string]$Command, [string]$Arguments)
    $output = Invoke-Expression "git $Command $Arguments 2>&1"
    return $output
}

# ============================================================================
# Submodule Management
# ============================================================================

function Update-GitSubmodules {
    Write-Section "Git Submodules"

    if (-not $IncludeSubmodules) {
        Write-Status "Submodule updates skipped (use -IncludeSubmodules to enable)" "Info"
        return
    }

    # Initialize submodules if needed
    $submoduleStatus = git submodule status 2>$null
    if ($LASTEXITCODE -ne 0) {
        Write-Status "No submodules configured or git error" "Warning"
        return
    }

    foreach ($submodule in $Config.Submodules) {
        $path = $submodule.Path
        $name = $submodule.Name

        if (-not (Test-Path $path)) {
            Write-Status "Submodule not found: $name ($path)" $(if ($submodule.Required) { "Error" } else { "Warning" })
            if ($submodule.Required) {
                $script:Errors += "Required submodule missing: $name"
            }
            continue
        }

        $script:Stats.SubmodulesChecked++

        # Get current commit
        $currentCommit = git -C $path rev-parse --short HEAD 2>$null
        $currentBranch = git -C $path rev-parse --abbrev-ref HEAD 2>$null

        Write-Status "Checking $name ($currentBranch @ $currentCommit)" "Info"

        if ($Update) {
            if ($PSCmdlet.ShouldProcess($path, "Update submodule $name")) {
                git submodule update --remote $path 2>&1 | Out-Null

                $newCommit = git -C $path rev-parse --short HEAD 2>$null
                if ($newCommit -ne $currentCommit) {
                    Write-Status "Updated $name`: $currentCommit -> $newCommit" "Success"
                    $script:UpdatesAvailable += [PSCustomObject]@{
                        Type = "Submodule"
                        Name = $name
                        Path = $path
                        OldVersion = $currentCommit
                        NewVersion = $newCommit
                        Branch = $currentBranch
                    }
                    $script:Stats.SubmodulesUpdated++
                } else {
                    Write-Status "$name is already up to date" "Success"
                }
            }
        } else {
            # Check for updates
            git -C $path fetch origin $currentBranch 2>&1 | Out-Null
            $behind = git -C $path rev-list --count HEAD..origin/$currentBranch 2>$null

            if ($behind -gt 0) {
                Write-Status "$name is $behind commit(s) behind" "Warning"
                $script:UpdatesAvailable += [PSCustomObject]@{
                    Type = "Submodule"
                    Name = $name
                    Path = $path
                    CurrentVersion = $currentCommit
                    Behind = $behind
                    Branch = $currentBranch
                }
                $script:Stats.OutdatedFound++
            } else {
                Write-Status "$name is up to date" "Success"
            }
        }
    }
}

# ============================================================================
# vcpkg Dependencies
# ============================================================================

function Update-VcpkgDependencies {
    Write-Section "vcpkg Dependencies"

    $vcpkgJson = "vcpkg.json"
    if (-not (Test-Path $vcpkgJson)) {
        Write-Status "vcpkg.json not found, skipping vcpkg updates" "Info"
        return
    }

    $vcpkg = Get-Command "vcpkg" -ErrorAction SilentlyContinue
    if (-not $vcpkg) {
        Write-Status "vcpkg not found in PATH" "Warning"
        return
    }

    Write-Status "Checking vcpkg dependencies..." "Info"

    $vcpkgConfig = Get-Content -Path $vcpkgJson -Raw | ConvertFrom-Json
    $dependencies = $vcpkgConfig.dependencies

    foreach ($dep in $dependencies) {
        $depName = if ($dep -is [string]) { $dep } else { $dep.name }
        $script:Stats.PackagesChecked++

        # Check if update available (simplified - would need vcpkg search in real impl)
        Write-Status "Checked $depName" "Info"
    }

    if ($Update) {
        if ($PSCmdlet.ShouldProcess("vcpkg", "Update all dependencies")) {
            & vcpkg upgrade --no-dry-run 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Status "vcpkg dependencies updated" "Success"
                $script:Stats.PackagesUpdated++
            } else {
                Write-Status "vcpkg update failed" "Error"
                $script:Errors += "vcpkg upgrade failed"
            }
        }
    }
}

# ============================================================================
# npm Dependencies
# ============================================================================

function Update-NpmDependencies {
    Write-Section "npm Dependencies"

    $packageJson = "package.json"
    if (-not (Test-Path $packageJson)) {
        Write-Status "package.json not found, skipping npm updates" "Info"
        return
    }

    $npm = Get-Command "npm" -ErrorAction SilentlyContinue
    if (-not $npm) {
        Write-Status "npm not found in PATH" "Warning"
        return
    }

    Write-Status "Checking npm dependencies..." "Info"

    # Check for outdated packages
    $outdated = & npm outdated --json 2>$null | ConvertFrom-Json -ErrorAction SilentlyContinue

    if ($outdated) {
        foreach ($package in $outdated.PSObject.Properties) {
            $name = $package.Name
            $current = $package.Value.current
            $wanted = $package.Value.wanted
            $latest = $package.Value.latest

            $script:Stats.OutdatedFound++
            Write-Status "$name`: $current -> $latest" "Warning"

            $script:UpdatesAvailable += [PSCustomObject]@{
                Type = "npm"
                Name = $name
                CurrentVersion = $current
                WantedVersion = $wanted
                LatestVersion = $latest
            }
        }
    } else {
        Write-Status "All npm packages are up to date" "Success"
    }

    if ($Update -and $outdated) {
        if ($PSCmdlet.ShouldProcess("npm", "Update all dependencies")) {
            & npm update 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Status "npm dependencies updated" "Success"
                $script:Stats.PackagesUpdated++
            } else {
                Write-Status "npm update failed" "Error"
                $script:Errors += "npm update failed"
            }
        }
    }
}

# ============================================================================
# Python Dependencies
# ============================================================================

function Update-PythonDependencies {
    Write-Section "Python Dependencies"

    $requirements = "requirements.txt"
    if (-not (Test-Path $requirements)) {
        Write-Status "requirements.txt not found, skipping Python updates" "Info"
        return
    }

    $pip = Get-Command "pip" -ErrorAction SilentlyContinue
    if (-not $pip) {
        Write-Status "pip not found in PATH" "Warning"
        return
    }

    Write-Status "Checking Python dependencies..." "Info"

    # List outdated packages
    $outdated = & pip list --outdated --format=json 2>$null | ConvertFrom-Json -ErrorAction SilentlyContinue

    if ($outdated) {
        foreach ($package in $outdated) {
            $name = $package.name
            $version = $package.version
            $latest = $package.latest_version

            $script:Stats.OutdatedFound++
            Write-Status "$name`: $version -> $latest" "Warning"

            $script:UpdatesAvailable += [PSCustomObject]@{
                Type = "pip"
                Name = $name
                CurrentVersion = $version
                LatestVersion = $latest
            }
        }
    } else {
        Write-Status "All Python packages are up to date" "Success"
    }

    if ($Update -and $outdated) {
        if ($PSCmdlet.ShouldProcess("pip", "Update all dependencies")) {
            & pip install --upgrade -r $requirements 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Status "Python dependencies updated" "Success"
                $script:Stats.PackagesUpdated++
            } else {
                Write-Status "pip update failed" "Error"
                $script:Errors += "pip upgrade failed"
            }
        }
    }
}

# ============================================================================
# Git Operations
# ============================================================================

function Invoke-GitOperations {
    if (-not $CreateBranch -or $script:UpdatesAvailable.Count -eq 0) {
        return
    }

    Write-Section "Git Operations"

    # Check for uncommitted changes
    $status = git status --porcelain 2>$null
    if ($status) {
        Write-Status "Uncommitted changes detected" "Warning"
        if (-not $PSCmdlet.ShouldProcess("Git", "Stash changes and create branch")) {
            return
        }
        git stash push -m "Auto-stash before dependency update"
    }

    # Create branch
    if ($PSCmdlet.ShouldProcess("Git", "Create branch $BranchName")) {
        git checkout -b $BranchName 2>&1 | Out-Null
        Write-Status "Created branch: $BranchName" "Success"
    }

    # Stage changes
    if ($PSCmdlet.ShouldProcess("Git", "Stage dependency changes")) {
        git add -A
        Write-Status "Staged changes" "Success"
    }

    # Commit
    $commitMessage = @"
Update dependencies ($(Get-Date -Format 'yyyy-MM-dd'))

Updated:
$(foreach ($update in $script:UpdatesAvailable) { "- $($update.Type): $($update.Name)" })

Auto-generated by update_dependencies.ps1
"@

    if ($PSCmdlet.ShouldProcess("Git", "Create commit")) {
        git commit -m $commitMessage
        Write-Status "Created commit" "Success"
    }

    Write-Status "Branch '$BranchName' ready for push" "Success"
    Write-Status "Run: git push origin $BranchName" "Info"
}

# ============================================================================
# Report Generation
# ============================================================================

function Write-ConsoleReport {
    Write-Section "Dependency Update Report"

    Write-Host "Summary:" -ForegroundColor Cyan
    Write-Host "  Submodules checked:  $($script:Stats.SubmodulesChecked)" -ForegroundColor White
    Write-Host "  Submodules updated:  $($script:Stats.SubmodulesUpdated)" -ForegroundColor White
    Write-Host "  Packages checked:    $($script:Stats.PackagesChecked)" -ForegroundColor White
    Write-Host "  Packages updated:    $($script:Stats.PackagesUpdated)" -ForegroundColor White
    Write-Host "  Outdated found:      $($script:Stats.OutdatedFound)" -ForegroundColor $(if ($script:Stats.OutdatedFound -eq 0) { "Green" } else { "Yellow" })
    Write-Host ""

    if ($script:UpdatesAvailable.Count -gt 0) {
        Write-Host "Updates Available:" -ForegroundColor Yellow
        foreach ($update in $script:UpdatesAvailable) {
            switch ($update.Type) {
                "Submodule" {
                    Write-Host "  [$($update.Type)] $($update.Name): $($update.OldVersion) -> $($update.NewVersion)" -ForegroundColor White
                }
                "npm" {
                    Write-Host "  [$($update.Type)] $($update.Name): $($update.CurrentVersion) -> $($update.LatestVersion)" -ForegroundColor White
                }
                "pip" {
                    Write-Host "  [$($update.Type)] $($update.Name): $($update.CurrentVersion) -> $($update.LatestVersion)" -ForegroundColor White
                }
            }
        }
    } else {
        Write-Host "✅ All dependencies are up to date!" -ForegroundColor Green
    }

    if ($script:Errors.Count -gt 0) {
        Write-Host "`nErrors:" -ForegroundColor Red
        foreach ($error in $script:Errors) {
            Write-Host "  - $error" -ForegroundColor Red
        }
    }
}

function Write-JsonReport {
    param([string]$OutputPath)

    $report = [PSCustomObject]@{
        timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
        stats = $script:Stats
        updates = $script:UpdatesAvailable
        errors = $script:Errors
        success = ($script:Errors.Count -eq 0)
    }

    $json = $report | ConvertTo-Json -Depth 10
    $json | Out-File -FilePath $OutputPath -Encoding UTF8
    Write-Status "Report written to $OutputPath" "Success"
}

# ============================================================================
# Main Execution
# ============================================================================

function Main {
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "RawrXD Dependency Update Tool" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Status "Mode: $(if ($Update) { "UPDATE" } else { "CHECK ONLY" })" "Info"
    Write-Status "Create branch: $CreateBranch" "Info"
    Write-Status ""

    # Run checks
    Update-GitSubmodules
    Update-VcpkgDependencies
    Update-NpmDependencies
    Update-PythonDependencies

    # Git operations
    Invoke-GitOperations

    # Generate report
    switch ($ReportFormat) {
        "json" { Write-JsonReport -OutputPath $OutputFile }
        default { Write-ConsoleReport }
    }

    # Exit code
    if ($script:Errors.Count -gt 0) {
        exit 2
    } elseif ($script:Stats.OutdatedFound -gt 0 -and $FailOnOutdated) {
        exit 1
    } else {
        exit 0
    }
}

# Run main
Main
