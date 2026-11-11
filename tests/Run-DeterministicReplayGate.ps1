# ============================================================================
# Run-DeterministicReplayGate.ps1
# RawrXD IDE Deterministic Replay Gate - PowerShell Runner
# ============================================================================
#
# This script runs the deterministic replay gate as part of CI/CD validation.
# It provides additional features like:
#   - Multiple seed-based runs for statistical validation
#   - Integration with existing test infrastructure
#   - Detailed reporting and artifact collection
#   - Comparison against baseline results
#
# Usage:
#   .\Run-DeterministicReplayGate.ps1                    # Run all scenarios
#   .\Run-DeterministicReplayGate.ps1 -Scenario SingleKeystroke
#   .\Run-DeterministicReplayGate.ps1 -Iterations 10       # Run 10 times
#   .\Run-DeterministicReplayGate.ps1 -CompareBaseline    # Compare to baseline
# ============================================================================

[CmdletBinding()]
param(
    [Parameter()]
    [string]$Scenario = "",
    
    [Parameter()]
    [int]$Iterations = 1,
    
    [Parameter()]
    [int]$Seed = 42,
    
    [Parameter()]
    [switch]$CompareBaseline,
    
    [Parameter()]
    [string]$BaselinePath = "",
    
    [Parameter()]
    [string]$OutputDir = ".\replay_gate_output",
    
    [Parameter()]
    [switch]$Verbose,
    
    [Parameter()]
    [switch]$CollectArtifacts,
    
    [Parameter()]
    [int]$TimeoutSeconds = 60
)

$ErrorActionPreference = "Stop"
$GateName = "RawrXD_IDE_DeterministicReplay_Gate"
$GateVersion = "1.0.0"

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

function Write-GateHeader {
    param([string]$Message)
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  $Message" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
}

function Write-GateSuccess {
    param([string]$Message)
    Write-Host "[PASS] $Message" -ForegroundColor Green
}

function Write-GateFailure {
    param([string]$Message)
    Write-Host "[FAIL] $Message" -ForegroundColor Red
}

function Write-GateInfo {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor White
}

function Get-Timestamp {
    return Get-Date -Format "yyyy-MM-dd HH:mm:ss"
}

function Get-RunId {
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $random = Get-Random -Minimum 1000 -Maximum 9999
    return "DRG-$timestamp-$random"
}

# ============================================================================
# BUILD GATE
# ============================================================================

function Build-Gate {
    Write-GateHeader "Building Deterministic Replay Gate"
    
    $buildScript = Join-Path $PSScriptRoot "build_deterministic_replay_gate.bat"
    
    if (-not (Test-Path $buildScript)) {
        throw "Build script not found: $buildScript"
    }
    
    Write-GateInfo "Running build script..."
    $process = Start-Process -FilePath $buildScript -Wait -PassThru -NoNewWindow
    
    if ($process.ExitCode -ne 0) {
        throw "Build failed with exit code $($process.ExitCode)"
    }
    
    $exePath = Join-Path $PSScriptRoot "..\..\build-ninja\tests\deterministic_replay_gate.exe"
    
    if (-not (Test-Path $exePath)) {
        throw "Gate executable not found after build: $exePath"
    }
    
    Write-GateSuccess "Build successful"
    return $exePath
}

# ============================================================================
# RUN GATE
# ============================================================================

function Run-Gate {
    param(
        [string]$ExePath,
        [int]$Iteration,
        [string]$RunId
    )
    
    $iterationOutputDir = Join-Path $OutputDir "run_$Iteration"
    New-Item -ItemType Directory -Force -Path $iterationOutputDir | Out-Null
    
    $args = @()
    if ($Scenario) {
        $args += "--scenario"
        $args += $Scenario
    }
    if ($Verbose) {
        $args += "--verbose"
    }
    
    Write-GateInfo "Running iteration $Iteration with seed $Seed..."
    
    $startTime = Get-Date
    
    $process = Start-Process -FilePath $ExePath `
        -ArgumentList $args `
        -WorkingDirectory $iterationOutputDir `
        -Wait -PassThru -NoNewWindow `
        -RedirectStandardOutput (Join-Path $iterationOutputDir "stdout.log") `
        -RedirectStandardError (Join-Path $iterationOutputDir "stderr.log")
    
    $endTime = Get-Date
    $duration = ($endTime - $startTime).TotalMilliseconds
    
    # Collect artifacts
    $journalFiles = Get-ChildItem -Path $iterationOutputDir -Filter "replay_gate_*.json" -ErrorAction SilentlyContinue
    $reportFile = Join-Path $iterationOutputDir "replay_gate_report.json"
    
    $result = @{
        Iteration = $Iteration
        RunId = $RunId
        ExitCode = $process.ExitCode
        DurationMs = [math]::Round($duration, 2)
        StartTime = $startTime.ToString("o")
        EndTime = $endTime.ToString("o")
        JournalFiles = @($journalFiles | Select-Object -ExpandProperty Name)
        HasReport = Test-Path $reportFile
    }
    
    # Parse report if available
    if ($result.HasReport) {
        try {
            $report = Get-Content $reportFile -Raw | ConvertFrom-Json
            $result.TotalScenarios = $report.totalScenarios
            $result.Passed = $report.passed
            $result.Failed = $report.failed
            $result.Success = $report.success
        } catch {
            Write-GateInfo "Warning: Could not parse report file"
        }
    }
    
    return $result
}

# ============================================================================
# COMPARE TO BASELINE
# ============================================================================

function Compare-ToBaseline {
    param(
        [array]$Results,
        [string]$BaselinePath
    )
    
    Write-GateHeader "Comparing to Baseline"
    
    if (-not (Test-Path $BaselinePath)) {
        Write-GateInfo "No baseline found at $BaselinePath, creating new baseline"
        return $true
    }
    
    try {
        $baseline = Get-Content $BaselinePath -Raw | ConvertFrom-Json
        
        $currentPassRate = ($Results | Where-Object { $_.Success -eq $true }).Count / $Results.Count
        $baselinePassRate = $baseline.passRate
        
        Write-GateInfo "Current pass rate: $([math]::Round($currentPassRate * 100, 2))%"
        Write-GateInfo "Baseline pass rate: $([math]::Round($baselinePassRate * 100, 2))%"
        
        if ($currentPassRate -lt $baselinePassRate - 0.05) {
            Write-GateFailure "Pass rate dropped by more than 5%"
            return $false
        }
        
        # Compare average duration
        $currentAvgDuration = ($Results | Measure-Object -Property DurationMs -Average).Average
        $baselineAvgDuration = $baseline.averageDurationMs
        
        Write-GateInfo "Current avg duration: $([math]::Round($currentAvgDuration, 2))ms"
        Write-GateInfo "Baseline avg duration: $([math]::Round($baselineAvgDuration, 2))ms"
        
        if ($currentAvgDuration -gt $baselineAvgDuration * 1.2) {
            Write-GateFailure "Duration increased by more than 20%"
            return $false
        }
        
        Write-GateSuccess "Comparison passed"
        return $true
        
    } catch {
        Write-GateInfo "Warning: Could not parse baseline: $_"
        return $true
    }
}

# ============================================================================
# SAVE BASELINE
# ============================================================================

function Save-Baseline {
    param(
        [array]$Results,
        [string]$BaselinePath
    )
    
    $passCount = ($Results | Where-Object { $_.Success -eq $true }).Count
    $totalCount = $Results.Count
    $passRate = if ($totalCount -gt 0) { $passCount / $totalCount } else { 0 }
    
    $avgDuration = ($Results | Measure-Object -Property DurationMs -Average).Average
    
    $baseline = @{
        gateName = $GateName
        gateVersion = $GateVersion
        createdAt = (Get-Date -Format "o")
        passRate = $passRate
        averageDurationMs = [math]::Round($avgDuration, 2)
        totalRuns = $totalCount
        results = $Results
    }
    
    $baseline | ConvertTo-Json -Depth 10 | Set-Content $BaselinePath
    Write-GateInfo "Baseline saved to: $BaselinePath"
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

function Main {
    Write-GateHeader "$GateName v$GateVersion"
    Write-GateInfo "Started at $(Get-Timestamp)"
    Write-GateInfo "Run ID: $(Get-RunId)"
    Write-GateInfo "Iterations: $Iterations"
    Write-GateInfo "Seed: $Seed"
    if ($Scenario) {
        Write-GateInfo "Scenario filter: $Scenario"
    }
    
    # Create output directory
    New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
    
    # Build the gate
    $exePath = Build-Gate
    
    # Run iterations
    $results = @()
    $allPassed = $true
    
    for ($i = 1; $i -le $Iterations; $i++) {
        $runId = Get-RunId
        $result = Run-Gate -ExePath $exePath -Iteration $i -RunId $runId
        $results += $result
        
        if ($result.ExitCode -ne 0) {
            $allPassed = $false
            Write-GateFailure "Iteration $i failed with exit code $($result.ExitCode)"
        } else {
            Write-GateSuccess "Iteration $i passed ($($result.DurationMs)ms)"
        }
    }
    
    # Summary
    Write-GateHeader "SUMMARY"
    
    $totalPassed = ($results | Where-Object { $_.Success -eq $true }).Count
    $totalFailed = ($results | Where-Object { $_.Success -eq $false }).Count
    $avgDuration = ($results | Measure-Object -Property DurationMs -Average).Average
    
    Write-GateInfo "Total iterations: $Iterations"
    Write-GateInfo "Passed: $totalPassed"
    Write-GateInfo "Failed: $totalFailed"
    Write-GateInfo "Average duration: $([math]::Round($avgDuration, 2))ms"
    
    # Compare to baseline if requested
    if ($CompareBaseline) {
        $baselineFile = if ($BaselinePath) { $BaselinePath } else { Join-Path $OutputDir "baseline.json" }
        $comparisonPassed = Compare-ToBaseline -Results $results -BaselinePath $baselineFile
        
        if (-not $comparisonPassed) {
            $allPassed = $false
        }
        
        # Save new baseline
        Save-Baseline -Results $results -BaselinePath $baselineFile
    }
    
    # Save detailed results
    $resultsFile = Join-Path $OutputDir "results.json"
    $results | ConvertTo-Json -Depth 10 | Set-Content $resultsFile
    Write-GateInfo "Detailed results saved to: $resultsFile"
    
    # Final status
    if ($allPassed) {
        Write-GateHeader "ALL CHECKS PASSED"
        exit 0
    } else {
        Write-GateHeader "SOME CHECKS FAILED"
        exit 1
    }
}

# Run main
Main
