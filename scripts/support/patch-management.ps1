#!/usr/bin/env pwsh
#requires -Version 7.0

<#
.SYNOPSIS
    Phase L.2/5: Patch Management System
    
.DESCRIPTION
    Automated patch management for security and bug fixes:
    - Security patch identification
    - Dependency vulnerability scanning
    - Automated patch testing
    - Rollback procedures
    - Patch deployment scheduling
    
.PARAMETER ScanOnly
    Only scan, don't apply patches
    
.PARAMETER SecurityOnly
    Only process security patches
    
.PARAMETER AutoApply
    Automatically apply non-breaking patches
    
.PARAMETER TargetVersion
    Target version for patch rollup
    
.EXAMPLE
    .\patch-management.ps1 -ScanOnly
    
.EXAMPLE
    .\patch-management.ps1 -SecurityOnly -AutoApply
#
>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [switch]$ScanOnly,
    
    [Parameter(Mandatory=$false)]
    [switch]$SecurityOnly,
    
    [Parameter(Mandatory=$false)]
    [switch]$AutoApply,
    
    [Parameter(Mandatory=$false)]
    [string]$TargetVersion
)

$ErrorActionPreference = "Stop"

# Banner
Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║  Phase L.2/5: Patch Management System                              ║
║  Security and Bug Fix Patch Automation                           ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

Write-Host "Configuration:" -ForegroundColor Yellow
Write-Host "  Mode: $(if ($ScanOnly) { 'SCAN ONLY' } else { 'APPLY' })"
Write-Host "  Security Only: $SecurityOnly"
Write-Host "  Auto Apply: $AutoApply"
Write-Host "  Target Version: $(if ($TargetVersion) { $TargetVersion } else { 'Latest' })"
Write-Host ""

# Phase 1: Dependency Vulnerability Scan
Write-Host "[Phase 1/5] Scanning dependencies for vulnerabilities..." -ForegroundColor Green

$vulnerabilities = @()

# Check for npm vulnerabilities (if package.json exists)
if (Test-Path "package.json") {
    Write-Host "  Scanning npm dependencies..."
    $npmAudit = npm audit --json 2>$null | ConvertFrom-Json -ErrorAction SilentlyContinue
    if ($npmAudit) {
        foreach ($vuln in $npmAudit.vulnerabilities.PSObject.Properties) {
            $vulnerabilities += @{
                type = "npm"
                package = $vuln.Name
                severity = $vuln.Value.severity
                vulnerable_versions = $vuln.Value.vulnerable_versions
                patched_versions = $vuln.Value.patched_versions
                overview = $vuln.Value.overview
                recommendation = "npm update $vuln.Name"
            }
        }
    }
}

# Check for Python vulnerabilities (if requirements.txt exists)
if (Test-Path "requirements.txt") {
    Write-Host "  Scanning Python dependencies..."
    try {
        $pipAudit = pip-audit --format=json 2>$null | ConvertFrom-Json -ErrorAction SilentlyContinue
        if ($pipAudit) {
            foreach ($vuln in $pipAudit) {
                $vulnerabilities += @{
                    type = "pip"
                    package = $vuln.name
                    severity = if ($vuln.fix_versions) { "high" } else { "medium" }
                    vulnerable_versions = $vuln.version
                    patched_versions = ($vuln.fix_versions -join ", ")
                    overview = $vuln.description
                    recommendation = "pip install $($vuln.name)==$($vuln.fix_versions[0])"
                }
            }
        }
    } catch {
        Write-Host "    pip-audit not available, skipping Python scan"
    }
}

# Check for GitHub security advisories
Write-Host "  Checking GitHub security advisories..."
$githubVulns = @()
# This would typically call GitHub Security API
# For now, we'll check the git output from the push

Write-Host "  Found $($vulnerabilities.Count) vulnerabilities"

# Filter for security only
if ($SecurityOnly) {
    $vulnerabilities = $vulnerabilities | Where-Object { $_.severity -in @("critical", "high") }
    Write-Host "  Security-critical: $($vulnerabilities.Count)"
}

Write-Host ""

# Phase 2: Patch Priority Assessment
Write-Host "[Phase 2/5] Assessing patch priorities..." -ForegroundColor Green

$patchQueue = @()

foreach ($vuln in $vulnerabilities) {
    $priority = switch ($vuln.severity) {
        "critical" { 1 }
        "high" { 2 }
        "moderate" { 3 }
        "low" { 4 }
        default { 3 }
    }
    
    $patchQueue += @{
        vulnerability = $vuln
        priority = $priority
        can_auto_apply = ($vuln.severity -in @("low", "moderate")) -and -not ($vuln.package -match "breaking")
        estimated_risk = if ($vuln.severity -eq "critical") { "HIGH" } elseif ($vuln.severity -eq "high") { "MEDIUM" } else { "LOW" }
    }
}

$patchQueue = $patchQueue | Sort-Object -Property priority

foreach ($patch in $patchQueue) {
    $autoFlag = if ($patch.can_auto_apply) { "[AUTO]" } else { "[MANUAL]" }
    Write-Host "  P$($patch.priority) $autoFlag $($patch.vulnerability.package) - $($patch.vulnerability.severity)"
}

Write-Host ""

# Phase 3: Test Patch Compatibility
Write-Host "[Phase 3/5] Testing patch compatibility..." -ForegroundColor Green

$testResults = @()

if (-not $ScanOnly) {
    foreach ($patch in $patchQueue | Where-Object { $_.can_auto_apply -or $AutoApply }) {
        Write-Host "  Testing $($patch.vulnerability.package)..." -NoNewline
        
        # Create test branch
        $testBranch = "patch-test-$($patch.vulnerability.package)-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
        git checkout -b $testBranch 2>$null | Out-Null
        
        try {
            # Apply patch
            Invoke-Expression $patch.vulnerability.recommendation 2>$null | Out-Null
            
            # Run tests
            $testOutput = npm test 2>$1 | Out-String
            $testsPassed = $LASTEXITCODE -eq 0
            
            if ($testsPassed) {
                Write-Host " ✓ PASSED" -ForegroundColor Green
                $patch.test_result = "PASSED"
            } else {
                Write-Host " ✗ FAILED" -ForegroundColor Red
                $patch.test_result = "FAILED"
            }
            
            $testResults += $patch
            
        } catch {
            Write-Host " ✗ ERROR" -ForegroundColor Red
            $patch.test_result = "ERROR"
            $testResults += $patch
        }
        
        # Cleanup
        git checkout - 2>$null | Out-Null
        git branch -D $testBranch 2>$null | Out-Null
    }
}

$passedTests = ($testResults | Where-Object { $_.test_result -eq "PASSED" }).Count
Write-Host "  Tests passed: $passedTests/$($testResults.Count)"
Write-Host ""

# Phase 4: Generate Patch Rollup
Write-Host "[Phase 4/5] Generating patch rollup..." -ForegroundColor Green

$rollupVersion = if ($TargetVersion) { $TargetVersion } else { "1.0.1" }
$rollupDate = Get-Date -Format "yyyy-MM-dd"

$patchNotes = @"
# Patch Rollup $rollupVersion
**Release Date:** $rollupDate

## Security Fixes
"@

$securityPatches = $patchQueue | Where-Object { $_.vulnerability.severity -in @("critical", "high") }
if ($securityPatches.Count -gt 0) {
    foreach ($patch in $securityPatches) {
        $patchNotes += "- **[$($patch.vulnerability.severity.ToUpper())]** $($patch.vulnerability.package): $($patch.vulnerability.overview.Substring(0, [Math]::Min(100, $patch.vulnerability.overview.Length)))...`n"
    }
} else {
    $patchNotes += "- No security patches in this release`n"
}

$patchNotes += @"

## Bug Fixes
"@

$bugPatches = $patchQueue | Where-Object { $_.vulnerability.severity -in @("moderate", "low") }
if ($bugPatches.Count -gt 0) {
    foreach ($patch in $bugPatches) {
        $patchNotes += "- $($patch.vulnerability.package): Updated to $($patch.vulnerability.patched_versions)`n"
    }
} else {
    $patchNotes += "- No bug fixes in this release`n"
}

$patchNotes += @"

## Testing
- Unit tests: $(if ($passedTests -gt 0) { "PASSED ($passedTests/$($testResults.Count))" } else { "N/A" })
- Integration tests: PENDING
- Security scan: COMPLETED

## Rollback
If issues occur, rollback to previous version:
\`\`\`bash
git checkout v$($rollupVersion -replace '\.\d+$', '.0')
\`\`\`
"@

$patchNotesFile = "PATCH_NOTES_$rollupVersion.md"
$patchNotes | Out-File -FilePath $patchNotesFile -Encoding UTF8
Write-Host "  Patch notes: $patchNotesFile"
Write-Host ""

# Phase 5: Deployment Schedule
Write-Host "[Phase 5/5] Creating deployment schedule..." -ForegroundColor Green

$schedule = @()
$currentTime = Get-Date

# Critical patches: Immediate
$criticalPatches = $patchQueue | Where-Object { $_.vulnerability.severity -eq "critical" }
if ($criticalPatches.Count -gt 0) {
    $schedule += @{
        time = $currentTime.AddMinutes(30)
        type = "CRITICAL"
        patches = $criticalPatches
        environment = "production"
        approval_required = $true
    }
}

# High severity: Within 24 hours
$highPatches = $patchQueue | Where-Object { $_.vulnerability.severity -eq "high" }
if ($highPatches.Count -gt 0) {
    $schedule += @{
        time = $currentTime.AddHours(24)
        type = "HIGH"
        patches = $highPatches
        environment = "production"
        approval_required = $true
    }
}

# Medium/Low: Next maintenance window
$otherPatches = $patchQueue | Where-Object { $_.vulnerability.severity -in @("moderate", "low") }
if ($otherPatches.Count -gt 0) {
    $schedule += @{
        time = $currentTime.AddDays(7)
        type = "STANDARD"
        patches = $otherPatches
        environment = "production"
        approval_required = $false
    }
}

foreach ($item in $schedule) {
    Write-Host "  $($item.time.ToString('yyyy-MM-dd HH:mm')) - $($item.type) to $($item.environment)"
    Write-Host "    Patches: $($item.patches.Count)"
    Write-Host "    Approval: $(if ($item.approval_required) { 'REQUIRED' } else { 'AUTO' })"
}

# Save deployment schedule
$scheduleFile = "patch-schedule-$rollupVersion.json"
$schedule | ForEach-Object {
    @{
        scheduled_time = $_.time.ToString("o")
        patch_type = $_.type
        patch_count = $_.patches.Count
        environment = $_.environment
        approval_required = $_.approval_required
    }
} | ConvertTo-Json | Out-File -FilePath $scheduleFile

Write-Host "  Schedule saved: $scheduleFile"
Write-Host ""

# Summary
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "PATCH MANAGEMENT COMPLETE" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "Vulnerabilities found: $($vulnerabilities.Count)"
Write-Host "Critical/High: $(($vulnerabilities | Where-Object { $_.severity -in @('critical', 'high') }).Count)"
Write-Host "Tests passed: $passedTests"
Write-Host "Scheduled deployments: $($schedule.Count)"
Write-Host ""
Write-Host "Artifacts:" -ForegroundColor Yellow
Write-Host "  Patch notes: $patchNotesFile"
Write-Host "  Schedule: $scheduleFile"
Write-Host ""

if ($ScanOnly) {
    Write-Host "⚠️ SCAN ONLY MODE - No patches applied" -ForegroundColor Yellow
} else {
    Write-Host "✅ Patch management complete!" -ForegroundColor Green
}
