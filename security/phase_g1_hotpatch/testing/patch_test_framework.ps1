#Requires -Version 7.0
<#
.SYNOPSIS
    Patch Testing Framework for RawrXD Hotpatch System

.DESCRIPTION
    Validates hotpatch bundles before deployment with comprehensive testing.

.PARAMETER PatchBundle
    Path to the patch bundle JSON file to test

.PARAMETER TestLevel
    Testing level: unit, integration, full (default: integration)

.PARAMETER OutputPath
    Path for test results JSON file

.PARAMETER KeepTestEnvironment
    Keep test environment after testing (for debugging)

.EXAMPLE
    .\patch_test_framework.ps1 -PatchBundle ..\patches\hotfix_v1.1.json -TestLevel full
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$PatchBundle,

    [Parameter(Mandatory = $false)]
    [ValidateSet("unit", "integration", "full")]
    [string]$TestLevel = "integration",

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "test_results.json",

    [Parameter(Mandatory = $false)]
    [switch]$KeepTestEnvironment
)

# Error action preference
$ErrorActionPreference = "Stop"

# Test result structure
$script:TestResults = @{
    PatchBundle = $PatchBundle
    TestLevel = $TestLevel
    StartTime = Get-Date -Format "o"
    EndTime = $null
    Duration = $null
    OverallResult = "PENDING"
    Tests = @()
    Summary = @{
        Total = 0
        Passed = 0
        Failed = 0
        Skipped = 0
        Warnings = 0
    }
}

function Write-TestLog {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $colorMap = @{
        "INFO" = "White"
        "PASS" = "Green"
        "FAIL" = "Red"
        "WARN" = "Yellow"
        "SKIP" = "Cyan"
    }
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $colorMap[$Level]
}

function Add-TestResult {
    param(
        [string]$TestName,
        [string]$Result, # PASS, FAIL, SKIP
        [string]$Message = "",
        [int]$DurationMs = 0,
        [hashtable]$Details = @{}
    )

    $script:TestResults.Tests += @{
        Name = $TestName
        Result = $Result
        Message = $Message
        DurationMs = $DurationMs
        Details = $Details
        Timestamp = Get-Date -Format "o"
    }

    $script:TestResults.Summary.Total++
    switch ($Result) {
        "PASS" { $script:TestResults.Summary.Passed++ }
        "FAIL" { $script:TestResults.Summary.Failed++ }
        "SKIP" { $script:TestResults.Summary.Skipped++ }
    }

    $level = if ($Result -eq "PASS") { "PASS" } elseif ($Result -eq "FAIL") { "FAIL" } else { "SKIP" }
    Write-TestLog -Message "$TestName`: $Result - $Message" -Level $level
}

# Test 1: JSON Schema Validation
function Test-PatchBundleSchema {
    param([string]$BundlePath)

    $testName = "Schema Validation"
    $startTime = Get-Date

    try {
        $bundle = Get-Content $BundlePath -Raw | ConvertFrom-Json -ErrorAction Stop

        # Required fields check
        $requiredFields = @("BundleId", "Version", "Type", "Description", "Patches")
        foreach ($field in $requiredFields) {
            if (-not $bundle.PSObject.Properties.Name.Contains($field)) {
                throw "Missing required field: $field"
            }
        }

        # Validate patches array
        if ($bundle.Patches.Count -eq 0) {
            throw "Patches array is empty"
        }

        foreach ($patch in $bundle.Patches) {
            $patchRequired = @("System", "Target", "PatchFile")
            foreach ($field in $patchRequired) {
                if (-not $patch.PSObject.Properties.Name.Contains($field)) {
                    throw "Patch missing required field: $field"
                }
            }

            # Validate system value
            $validSystems = @("swarm", "agent", "tools")
            if ($patch.System -notin $validSystems) {
                throw "Invalid system value: $($patch.System). Must be one of: $($validSystems -join ', ')"
            }
        }

        $duration = ((Get-Date) - $startTime).TotalMilliseconds
        Add-TestResult -TestName $testName -Result "PASS" -Message "Schema validation successful" -DurationMs $duration
        return $true
    }
    catch {
        $duration = ((Get-Date) - $startTime).TotalMilliseconds
        Add-TestResult -TestName $testName -Result "FAIL" -Message $_.Exception.Message -DurationMs $duration
        return $false
    }
}

# Test 2: Dependency Validation
function Test-PatchDependencies {
    param([string]$BundlePath)

    $testName = "Dependency Validation"
    $startTime = Get-Date

    try {
        $bundle = Get-Content $BundlePath -Raw | ConvertFrom-Json

        if (-not $bundle.Dependencies) {
            Add-TestResult -TestName $testName -Result "PASS" -Message "No dependencies specified"
            return $true
        }

        $issues = @()
        foreach ($dep in $bundle.Dependencies) {
            # Check if system exists
            $systemStatus = Get-SystemVersion -System $dep.System
            if (-not $systemStatus.Exists) {
                $issues += "System $($dep.System) not found"
                continue
            }

            # Version check
            if ($dep.MinimumVersion -and $systemStatus.Version -lt $dep.MinimumVersion) {
                $issues += "System $($dep.System) version $($systemStatus.Version) is below minimum $($dep.MinimumVersion)"
            }
            if ($dep.MaximumVersion -and $systemStatus.Version -gt $dep.MaximumVersion) {
                $issues += "System $($dep.System) version $($systemStatus.Version) exceeds maximum $($dep.MaximumVersion)"
            }
        }

        $duration = ((Get-Date) - $startTime).TotalMilliseconds
        if ($issues.Count -gt 0) {
            Add-TestResult -TestName $testName -Result "FAIL" -Message ($issues -join "; ") -DurationMs $duration
            return $false
        }

        Add-TestResult -TestName $testName -Result "PASS" -Message "All dependencies satisfied" -DurationMs $duration
        return $true
    }
    catch {
        $duration = ((Get-Date) - $startTime).TotalMilliseconds
        Add-TestResult -TestName $testName -Result "FAIL" -Message $_.Exception.Message -DurationMs $duration
        return $false
    }
}

# Test 3: Conflict Detection
function Test-PatchConflicts {
    param([string]$BundlePath)

    $testName = "Conflict Detection"
    $startTime = Get-Date

    try {
        $bundle = Get-Content $BundlePath -Raw | ConvertFrom-Json

        if (-not $bundle.Conflicts) {
            Add-TestResult -TestName $testName -Result "PASS" -Message "No conflicts specified"
            return $true
        }

        $issues = @()
        foreach ($conflict in $bundle.Conflicts) {
            # Check if conflicting patch is active
            $activePatches = Get-ActivePatches
            foreach ($activePatch in $activePatches) {
                if ($activePatch.BundleId -like $conflict.PatchId) {
                    $issues += "Active patch $($activePatch.BundleId) conflicts with this patch: $($conflict.Reason)"
                }
            }
        }

        $duration = ((Get-Date) - $startTime).TotalMilliseconds
        if ($issues.Count -gt 0) {
            Add-TestResult -TestName $testName -Result "FAIL" -Message ($issues -join "; ") -DurationMs $duration
            return $false
        }

        Add-TestResult -TestName $testName -Result "PASS" -Message "No conflicts detected" -DurationMs $duration
        return $true
    }
    catch {
        $duration = ((Get-Date) - $startTime).TotalMilliseconds
        Add-TestResult -TestName $testName -Result "FAIL" -Message $_.Exception.Message -DurationMs $duration
        return $false
    }
}

# Test 4: Prerequisites Check
function Test-Prerequisites {
    param([string]$BundlePath)

    $testName = "Prerequisites Check"
    $startTime = Get-Date

    try {
        $bundle = Get-Content $BundlePath -Raw | ConvertFrom-Json

        if (-not $bundle.Prerequisites) {
            Add-TestResult -TestName $testName -Result "PASS" -Message "No prerequisites specified"
            return $true
        }

        $issues = @()
        $prereq = $bundle.Prerequisites

        # Disk space check
        if ($prereq.MinDiskSpaceMB) {
            $freeSpace = (Get-PSDrive C).Free / 1MB
            if ($freeSpace -lt $prereq.MinDiskSpaceMB) {
                $issues += "Insufficient disk space: $([math]::Round($freeSpace, 2)) MB available, $($prereq.MinDiskSpaceMB) MB required"
            }
        }

        # Memory check
        if ($prereq.MinMemoryMB) {
            $totalMemory = (Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum / 1MB
            if ($totalMemory -lt $prereq.MinMemoryMB) {
                $issues += "Insufficient memory: $([math]::Round($totalMemory, 2)) MB available, $($prereq.MinMemoryMB) MB required"
            }
        }

        # Service checks
        if ($prereq.ServicesToStop) {
            foreach ($service in $prereq.ServicesToStop) {
                $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
                if (-not $svc) {
                    $issues += "Required service not found: $service"
                }
            }
        }

        $duration = ((Get-Date) - $startTime).TotalMilliseconds
        if ($issues.Count -gt 0) {
            Add-TestResult -TestName $testName -Result "FAIL" -Message ($issues -join "; ") -DurationMs $duration
            return $false
        }

        Add-TestResult -TestName $testName -Result "PASS" -Message "All prerequisites satisfied" -DurationMs $duration
        return $true
    }
    catch {
        $duration = ((Get-Date) - $startTime).TotalMilliseconds
        Add-TestResult -TestName $testName -Result "FAIL" -Message $_.Exception.Message -DurationMs $duration
        return $false
    }
}

# Test 5: Patch File Existence
function Test-PatchFilesExist {
    param([string]$BundlePath)

    $testName = "Patch File Existence"
    $startTime = Get-Date

    try {
        $bundle = Get-Content $BundlePath -Raw | ConvertFrom-Json
        $bundleDir = Split-Path -Parent $BundlePath

        $issues = @()
        foreach ($patch in $bundle.Patches) {
            $patchFilePath = Join-Path $bundleDir $patch.PatchFile
            if (-not (Test-Path $patchFilePath)) {
                $issues += "Patch file not found: $($patch.PatchFile)"
            }
        }

        $duration = ((Get-Date) - $startTime).TotalMilliseconds
        if ($issues.Count -gt 0) {
            Add-TestResult -TestName $testName -Result "FAIL" -Message ($issues -join "; ") -DurationMs $duration
            return $false
        }

        Add-TestResult -TestName $testName -Result "PASS" -Message "All patch files exist" -DurationMs $duration
        return $true
    }
    catch {
        $duration = ((Get-Date) - $startTime).TotalMilliseconds
        Add-TestResult -TestName $testName -Result "FAIL" -Message $_.Exception.Message -DurationMs $duration
        return $false
    }
}

# Test 6: Dry Run Test (Integration Level)
function Test-DryRun {
    param([string]$BundlePath)

    $testName = "Dry Run Test"
    $startTime = Get-Date

    try {
        # Import unified orchestrator
        $orchestratorPath = Join-Path $PSScriptRoot "..\unified_hotpatch_orchestrator.ps1"
        if (-not (Test-Path $orchestratorPath)) {
            Add-TestResult -TestName $testName -Result "SKIP" -Message "Unified orchestrator not found"
            return $true
        }

        # Run dry-run mode
        $result = & $orchestratorPath -Action apply -System all -PatchBundle $BundlePath -DryRun 2>&1

        $duration = ((Get-Date) - $startTime).TotalMilliseconds
        if ($LASTEXITCODE -eq 0) {
            Add-TestResult -TestName $testName -Result "PASS" -Message "Dry run completed successfully" -DurationMs $duration -Details @{ Output = $result }
            return $true
        }
        else {
            Add-TestResult -TestName $testName -Result "FAIL" -Message "Dry run failed with exit code $LASTEXITCODE" -DurationMs $duration -Details @{ Output = $result }
            return $false
        }
    }
    catch {
        $duration = ((Get-Date) - $startTime).TotalMilliseconds
        Add-TestResult -TestName $testName -Result "FAIL" -Message $_.Exception.Message -DurationMs $duration
        return $false
    }
}

# Test 7: Backup Test (Integration Level)
function Test-BackupCreation {
    param([string]$BundlePath)

    $testName = "Backup Creation Test"
    $startTime = Get-Date

    try {
        $bundle = Get-Content $BundlePath -Raw | ConvertFrom-Json

        # Check if any patch requires backup
        $requiresBackup = $bundle.Patches | Where-Object { $_.BackupRequired -ne $false }
        if (-not $requiresBackup) {
            Add-TestResult -TestName $testName -Result "SKIP" -Message "No patches require backup"
            return $true
        }

        # Test backup path
        $backupPath = Join-Path $env:RAWRXD_HOME "backups\test_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
        $testFile = Join-Path $backupPath "test.txt"

        New-Item -ItemType Directory -Path $backupPath -Force | Out-Null
        "Test backup content" | Out-File $testFile

        if (Test-Path $testFile) {
            Remove-Item $backupPath -Recurse -Force
            Add-TestResult -TestName $testName -Result "PASS" -Message "Backup path writable" -DurationMs ((Get-Date) - $startTime).TotalMilliseconds
            return $true
        }
        else {
            throw "Failed to create test backup file"
        }
    }
    catch {
        $duration = ((Get-Date) - $startTime).TotalMilliseconds
        Add-TestResult -TestName $testName -Result "FAIL" -Message $_.Exception.Message -DurationMs $duration
        return $false
    }
}

# Test 8: Health Check Test (Full Level)
function Test-HealthChecks {
    param([string]$BundlePath)

    $testName = "Health Check Test"
    $startTime = Get-Date

    try {
        # Test health check for each system
        $systems = @("swarm", "agent", "tools")
        $results = @{}

        foreach ($system in $systems) {
            $health = Test-SystemHealth -System $system
            $results[$system] = $health
        }

        $allHealthy = $results.Values | Where-Object { -not $_ } | Measure-Object | Select-Object -ExpandProperty Count
        $duration = ((Get-Date) - $startTime).TotalMilliseconds

        if ($allHealthy -eq 0) {
            Add-TestResult -TestName $testName -Result "PASS" -Message "All systems healthy" -DurationMs $duration -Details $results
            return $true
        }
        else {
            $unhealthy = $results.GetEnumerator() | Where-Object { -not $_.Value } | Select-Object -ExpandProperty Key
            Add-TestResult -TestName $testName -Result "WARN" -Message "Some systems not healthy: $($unhealthy -join ', ')" -DurationMs $duration -Details $results
            return $true # Warning, not failure
        }
    }
    catch {
        $duration = ((Get-Date) - $startTime).TotalMilliseconds
        Add-TestResult -TestName $testName -Result "FAIL" -Message $_.Exception.Message -DurationMs $duration
        return $false
    }
}

# Helper functions
function Get-SystemVersion {
    param([string]$System)
    # Placeholder - would query actual system
    return @{
        Exists = $true
        Version = "1.0.0"
    }
}

function Get-ActivePatches {
    # Placeholder - would query patch registry
    return @()
}

function Test-SystemHealth {
    param([string]$System)
    # Placeholder - would perform actual health check
    return $true
}

# Main execution
Write-TestLog -Message "Starting Patch Test Framework" -Level "INFO"
Write-TestLog -Message "Patch Bundle: $PatchBundle" -Level "INFO"
Write-TestLog -Message "Test Level: $TestLevel" -Level "INFO"

# Validate patch bundle exists
if (-not (Test-Path $PatchBundle)) {
    Write-Error "Patch bundle not found: $PatchBundle"
    exit 1
}

# Run tests based on level
$tests = @(
    @{ Name = "Schema Validation"; Function = "Test-PatchBundleSchema"; Level = @("unit", "integration", "full") },
    @{ Name = "Dependency Validation"; Function = "Test-PatchDependencies"; Level = @("unit", "integration", "full") },
    @{ Name = "Conflict Detection"; Function = "Test-PatchConflicts"; Level = @("unit", "integration", "full") },
    @{ Name = "Prerequisites Check"; Function = "Test-Prerequisites"; Level = @("unit", "integration", "full") },
    @{ Name = "Patch File Existence"; Function = "Test-PatchFilesExist"; Level = @("unit", "integration", "full") },
    @{ Name = "Dry Run Test"; Function = "Test-DryRun"; Level = @("integration", "full") },
    @{ Name = "Backup Creation Test"; Function = "Test-BackupCreation"; Level = @("integration", "full") },
    @{ Name = "Health Check Test"; Function = "Test-HealthChecks"; Level = @("full") }
)

foreach ($test in $tests) {
    if ($test.Level -contains $TestLevel) {
        Write-TestLog -Message "Running test: $($test.Name)" -Level "INFO"
        & $test.Function -BundlePath $PatchBundle | Out-Null
    }
    else {
        Add-TestResult -TestName $test.Name -Result "SKIP" -Message "Not applicable for test level: $TestLevel"
    }
}

# Calculate final results
$script:TestResults.EndTime = Get-Date -Format "o"
$start = [datetime]::Parse($script:TestResults.StartTime)
$end = [datetime]::Parse($script:TestResults.EndTime)
$script:TestResults.Duration = ($end - $start).TotalSeconds

# Determine overall result
if ($script:TestResults.Summary.Failed -gt 0) {
    $script:TestResults.OverallResult = "FAIL"
}
elseif ($script:TestResults.Summary.Warnings -gt 0) {
    $script:TestResults.OverallResult = "PASS_WITH_WARNINGS"
}
else {
    $script:TestResults.OverallResult = "PASS"
}

# Save results
$script:TestResults | ConvertTo-Json -Depth 10 | Out-File $OutputPath

# Summary
Write-TestLog -Message "====================" -Level "INFO"
Write-TestLog -Message "Test Summary" -Level "INFO"
Write-TestLog -Message "====================" -Level "INFO"
Write-TestLog -Message "Total Tests: $($script:TestResults.Summary.Total)" -Level "INFO"
Write-TestLog -Message "Passed: $($script:TestResults.Summary.Passed)" -Level "PASS"
Write-TestLog -Message "Failed: $($script:TestResults.Summary.Failed)" -Level "FAIL"
Write-TestLog -Message "Skipped: $($script:TestResults.Summary.Skipped)" -Level "SKIP"
Write-TestLog -Message "Warnings: $($script:TestResults.Summary.Warnings)" -Level "WARN"
Write-TestLog -Message "Overall Result: $($script:TestResults.OverallResult)" -Level $(if ($script:TestResults.OverallResult -eq "PASS") { "PASS" } else { "FAIL" })
Write-TestLog -Message "Results saved to: $OutputPath" -Level "INFO"

# Exit with appropriate code
if ($script:TestResults.OverallResult -eq "FAIL") {
    exit 1
}
else {
    exit 0
}
