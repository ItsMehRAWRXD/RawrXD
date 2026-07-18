#!/usr/bin/env pwsh
#requires -Version 7.0

<#
.SYNOPSIS
    Phase L.4/5: Release Readiness Check
    
.DESCRIPTION
    Comprehensive pre-release validation:
    - Automated test suite execution
    - Security scan validation
    - Documentation completeness check
    - Performance regression testing
    - Dependency verification
    - Sign-off workflow
    
.PARAMETER Version
    Version being released
    
.PARAMETER SkipTests
    Skip test execution
    
.PARAMETER SkipSecurity
    Skip security scan
    
.PARAMETER Force
    Force release even with warnings
    
.PARAMETER OutputReport
    Generate readiness report
    
.EXAMPLE
    .\release-readiness-check.ps1 -Version 1.1.0
    
.EXAMPLE
    .\release-readiness-check.ps1 -Version 1.1.0 -OutputReport
#
>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$Version,
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipTests,
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipSecurity,
    
    [Parameter(Mandatory=$false)]
    [switch]$Force,
    
    [Parameter(Mandatory=$false)]
    [switch]$OutputReport
)

$ErrorActionPreference = "Stop"

# Banner
Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║  Phase L.4/5: Release Readiness Check                              ║
║  Pre-Release Validation and Sign-off                               ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

Write-Host "Configuration:" -ForegroundColor Yellow
Write-Host "  Version: $Version"
Write-Host "  Skip Tests: $SkipTests"
Write-Host "  Skip Security: $SkipSecurity"
Write-Host "  Force: $Force"
Write-Host ""

$checkResults = @{
    version = $Version
    timestamp = Get-Date -Format "o"
    checks = @{}
    overall_status = "PENDING"
    blockers = @()
    warnings = @()
}

# Phase 1: Version Validation
Write-Host "[Phase 1/6] Validating version..." -ForegroundColor Green

$versionPattern = '^\d+\.\d+\.\d+(-[a-zA-Z0-9]+)?$'
if ($Version -notmatch $versionPattern) {
    $checkResults.blockers += "Invalid version format: $Version (expected: X.Y.Z or X.Y.Z-prerelease)"
    $checkResults.checks.version = "FAILED"
} else {
    # Check if version already exists
    $existingTag = git tag -l "v$Version" 2>$null
    if ($existingTag) {
        $checkResults.blockers += "Version v$Version already exists as a tag"
        $checkResults.checks.version = "FAILED"
    } else {
        $checkResults.checks.version = "PASSED"
        Write-Host "  ✓ Version format valid and unique"
    }
}

# Phase 2: Test Suite Execution
Write-Host "[Phase 2/6] Executing test suite..." -ForegroundColor Green

if (-not $SkipTests) {
    # Unit tests
    Write-Host "  Running unit tests..." -NoNewline
    $unitTestOutput = npm test 2>$1
    $unitTestsPassed = $LASTEXITCODE -eq 0
    
    if ($unitTestsPassed) {
        Write-Host " ✓ PASSED" -ForegroundColor Green
        $checkResults.checks.unit_tests = "PASSED"
    } else {
        Write-Host " ✗ FAILED" -ForegroundColor Red
        $checkResults.checks.unit_tests = "FAILED"
        $checkResults.blockers += "Unit tests failed"
    }
    
    # Integration tests
    Write-Host "  Running integration tests..." -NoNewline
    $intTestOutput = npm run test:integration 2>$1
    $intTestsPassed = $LASTEXITCODE -eq 0
    
    if ($intTestsPassed) {
        Write-Host " ✓ PASSED" -ForegroundColor Green
        $checkResults.checks.integration_tests = "PASSED"
    } else {
        Write-Host " ✗ FAILED" -ForegroundColor Red
        $checkResults.checks.integration_tests = "FAILED"
        $checkResults.blockers += "Integration tests failed"
    }
    
    # Performance regression tests
    Write-Host "  Running performance regression tests..." -NoNewline
    $perfTestOutput = npm run test:performance 2>$1
    $perfTestsPassed = $LASTEXITCODE -eq 0
    
    if ($perfTestsPassed) {
        Write-Host " ✓ PASSED" -ForegroundColor Green
        $checkResults.checks.performance_tests = "PASSED"
    } else {
        Write-Host " ⚠️ WARNING" -ForegroundColor Yellow
        $checkResults.checks.performance_tests = "WARNING"
        $checkResults.warnings += "Performance regression detected"
    }
} else {
    Write-Host "  ⚠️ SKIPPED" -ForegroundColor Yellow
    $checkResults.checks.unit_tests = "SKIPPED"
    $checkResults.checks.integration_tests = "SKIPPED"
    $checkResults.checks.performance_tests = "SKIPPED"
    $checkResults.warnings += "Tests were skipped"
}

# Phase 3: Security Scan
Write-Host "[Phase 3/6] Running security scan..." -ForegroundColor Green

if (-not $SkipSecurity) {
    # Dependency vulnerabilities
    Write-Host "  Scanning dependencies..." -NoNewline
    $auditOutput = npm audit --json 2>$null | ConvertFrom-Json -ErrorAction SilentlyContinue
    
    $criticalVulns = 0
    $highVulns = 0
    
    if ($auditOutput -and $auditOutput.vulnerabilities) {
        foreach ($vuln in $auditOutput.vulnerabilities.PSObject.Properties) {
            if ($vuln.Value.severity -eq "critical") { $criticalVulns++ }
            if ($vuln.Value.severity -eq "high") { $highVulns++ }
        }
    }
    
    if ($criticalVulns -eq 0 -and $highVulns -eq 0) {
        Write-Host " ✓ PASSED" -ForegroundColor Green
        $checkResults.checks.security_scan = "PASSED"
    } elseif ($criticalVulns -eq 0) {
        Write-Host " ⚠️ WARNING ($highVulns high severity)" -ForegroundColor Yellow
        $checkResults.checks.security_scan = "WARNING"
        $checkResults.warnings += "$highVulns high severity vulnerabilities found"
    } else {
        Write-Host " ✗ FAILED ($criticalVulns critical)" -ForegroundColor Red
        $checkResults.checks.security_scan = "FAILED"
        $checkResults.blockers += "$criticalVulns critical security vulnerabilities found"
    }
    
    # Secret scanning
    Write-Host "  Scanning for secrets..." -NoNewline
    $secretScan = git log --all --source --remotes --pretty=format:"%H" | ForEach-Object {
        git show $_ | Select-String -Pattern "(api[_-]?key|password|secret|token)\s*[=:]\s*['\"][^'\"]+['\"]" -Quiet
    }
    
    if (-not $secretScan) {
        Write-Host " ✓ PASSED" -ForegroundColor Green
        $checkResults.checks.secret_scan = "PASSED"
    } else {
        Write-Host " ⚠️ WARNING" -ForegroundColor Yellow
        $checkResults.checks.secret_scan = "WARNING"
        $checkResults.warnings += "Potential secrets detected in git history"
    }
} else {
    Write-Host "  ⚠️ SKIPPED" -ForegroundColor Yellow
    $checkResults.checks.security_scan = "SKIPPED"
    $checkResults.checks.secret_scan = "SKIPPED"
    $checkResults.warnings += "Security scan was skipped"
}

# Phase 4: Documentation Check
Write-Host "[Phase 4/6] Checking documentation..." -ForegroundColor Green

$requiredDocs = @(
    "README.md",
    "CHANGELOG.md",
    "docs/RELEASE_NOTES.md",
    "docs/api/openapi.yaml",
    "docs/guides/installation.md"
)

$missingDocs = @()
foreach ($doc in $requiredDocs) {
    if (-not (Test-Path $doc)) {
        $missingDocs += $doc
    }
}

if ($missingDocs.Count -eq 0) {
    Write-Host "  ✓ All required documentation present"
    $checkResults.checks.documentation = "PASSED"
} else {
    Write-Host "  ✗ Missing documentation: $($missingDocs -join ', ')"
    $checkResults.checks.documentation = "FAILED"
    $checkResults.blockers += "Missing required documentation: $($missingDocs -join ', ')"
}

# Check CHANGELOG has entry for this version
$changelogContent = Get-Content "CHANGELOG.md" -Raw -ErrorAction SilentlyContinue
if ($changelogContent -match "## \[$Version\]") {
    Write-Host "  ✓ CHANGELOG entry exists for v$Version"
} else {
    Write-Host "  ✗ No CHANGELOG entry for v$Version"
    $checkResults.warnings += "CHANGELOG missing entry for v$Version"
}

# Phase 5: Dependency Verification
Write-Host "[Phase 5/6] Verifying dependencies..." -ForegroundColor Green

# Check package.json exists and is valid
if (Test-Path "package.json") {
    try {
        $packageJson = Get-Content "package.json" | ConvertFrom-Json
        if ($packageJson.version -eq $Version) {
            Write-Host "  ✓ package.json version matches"
            $checkResults.checks.dependencies = "PASSED"
        } else {
            Write-Host "  ✗ package.json version mismatch (expected: $Version, actual: $($packageJson.version))"
            $checkResults.checks.dependencies = "FAILED"
            $checkResults.blockers += "package.json version does not match release version"
        }
    } catch {
        Write-Host "  ✗ Invalid package.json"
        $checkResults.checks.dependencies = "FAILED"
        $checkResults.blockers += "Invalid package.json"
    }
} else {
    Write-Host "  ⚠️ No package.json found"
    $checkResults.checks.dependencies = "WARNING"
    $checkResults.warnings += "No package.json found"
}

# Check for outdated dependencies
Write-Host "  Checking for outdated dependencies..." -NoNewline
$outdated = npm outdated --json 2>$null | ConvertFrom-Json -ErrorAction SilentlyContinue
if ($outdated) {
    $outdatedCount = ($outdated | Get-Member -MemberType NoteProperty).Count
    if ($outdatedCount -gt 0) {
        Write-Host " ⚠️ $outdatedCount outdated" -ForegroundColor Yellow
        $checkResults.warnings += "$outdatedCount outdated dependencies"
    } else {
        Write-Host " ✓ All up to date"
    }
} else {
    Write-Host " ✓ All up to date"
}

# Phase 6: Final Sign-off
Write-Host "[Phase 6/6] Final sign-off..." -ForegroundColor Green

# Calculate overall status
if ($checkResults.blockers.Count -gt 0) {
    $checkResults.overall_status = "BLOCKED"
} elseif ($checkResults.warnings.Count -gt 0) {
    $checkResults.overall_status = "READY_WITH_WARNINGS"
} else {
    $checkResults.overall_status = "READY"
}

# Override with force flag
if ($Force -and $checkResults.overall_status -eq "BLOCKED") {
    $checkResults.overall_status = "READY_WITH_FORCE"
    $checkResults.warnings += "Release forced despite blockers"
}

Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "RELEASE READINESS CHECK COMPLETE" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "Version: $Version"
Write-Host "Status: $($checkResults.overall_status)"
Write-Host ""
Write-Host "Check Results:" -ForegroundColor Yellow
foreach ($check in $checkResults.checks.GetEnumerator()) {
    $color = switch ($check.Value) {
        "PASSED" { "Green" }
        "FAILED" { "Red" }
        "WARNING" { "Yellow" }
        "SKIPPED" { "Gray" }
        default { "White" }
    }
    Write-Host "  $($check.Key): $($check.Value)" -ForegroundColor $color
}

if ($checkResults.blockers.Count -gt 0) {
    Write-Host ""
    Write-Host "BLOCKERS:" -ForegroundColor Red
    foreach ($blocker in $checkResults.blockers) {
        Write-Host "  ✗ $blocker" -ForegroundColor Red
    }
}

if ($checkResults.warnings.Count -gt 0) {
    Write-Host ""
    Write-Host "WARNINGS:" -ForegroundColor Yellow
    foreach ($warning in $checkResults.warnings) {
        Write-Host "  ⚠️ $warning" -ForegroundColor Yellow
    }
}

Write-Host ""

# Generate report
if ($OutputReport) {
    $reportFile = "release-readiness-$Version.json"
    $checkResults | ConvertTo-Json -Depth 10 | Out-File -FilePath $reportFile
    Write-Host "Report saved: $reportFile" -ForegroundColor Cyan
}

# Exit code based on status
if ($checkResults.overall_status -eq "BLOCKED") {
    Write-Host "❌ Release BLOCKED - fix blockers before proceeding" -ForegroundColor Red
    exit 1
} elseif ($checkResults.overall_status -eq "READY_WITH_WARNINGS" -or $checkResults.overall_status -eq "READY_WITH_FORCE") {
    Write-Host "⚠️ Release READY WITH WARNINGS - review warnings before proceeding" -ForegroundColor Yellow
    exit 0
} else {
    Write-Host "✅ Release READY - all checks passed!" -ForegroundColor Green
    exit 0
}
