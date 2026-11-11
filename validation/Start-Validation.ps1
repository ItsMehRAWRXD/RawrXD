# RawrXD Validation Quick Start Wrapper
# Convenience script for common validation workflows

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("Quick", "Full", "CI", "Debug", "HardwareOnly")]
    [string]$Mode = "Quick",
    
    [Parameter(Mandatory=$false)]
    [string]$TargetUrl = "http://127.0.0.1:8080",
    
    [Parameter(Mandatory=$false)]
    [int]$BenchmarkRuns = 0,  # 0 = use default for mode
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = "",
    
    [Parameter(Mandatory=$false)]
    [switch]$Build,
    
    [Parameter(Mandatory=$false)]
    [switch]$OpenDashboard,
    
    [Parameter(Mandatory=$false)]
    [switch]$GenerateReport,
    
    [Parameter(Mandatory=$false)]
    [switch]$CompareWithLast,
    
    [Parameter(Mandatory=$false)]
    [switch]$Help
)

$ErrorActionPreference = "Stop"

# Mode configurations
$ModeConfig = @{
    Quick = @{
        BenchmarkRuns = 10
        HardwareValidation = $false
        Description = "Quick smoke test (10 iterations)"
    }
    Full = @{
        BenchmarkRuns = 100
        HardwareValidation = $true
        Description = "Full production validation (100 iterations)"
    }
    CI = @{
        BenchmarkRuns = 50
        HardwareValidation = $false
        Description = "CI-friendly validation (50 iterations)"
    }
    Debug = @{
        BenchmarkRuns = 5
        HardwareValidation = $false
        Description = "Debug mode (5 iterations, verbose)"
    }
    HardwareOnly = @{
        BenchmarkRuns = 0
        HardwareValidation = $true
        Description = "Hardware detection only"
    }
}

function Show-Help {
    Write-Host @"
RawrXD Validation Quick Start
==============================

Usage: .\Start-Validation.ps1 [options]

Modes:
  -Mode Quick        Quick smoke test (10 iterations) [default]
  -Mode Full         Full production validation (100 iterations)
  -Mode CI           CI-friendly validation (50 iterations)
  -Mode Debug        Debug mode (5 iterations, verbose)
  -Mode HardwareOnly Hardware detection only

Options:
  -TargetUrl         RawrXD endpoint URL [default: http://127.0.0.1:8080]
  -BenchmarkRuns     Override iteration count
  -OutputPath        Custom output directory
  -Build             Build framework before running
  -OpenDashboard     Open dashboard after validation
  -GenerateReport    Generate reports after validation
  -CompareWithLast   Compare with previous run
  -Help              Show this help

Examples:
  # Quick validation
  .\Start-Validation.ps1

  # Full validation with reports
  .\Start-Validation.ps1 -Mode Full -GenerateReport

  # CI mode with custom URL
  .\Start-Validation.ps1 -Mode CI -TargetUrl "http://192.168.1.100:8080"

  # Build and validate
  .\Start-Validation.ps1 -Build -Mode Full

  # Compare with last run
  .\Start-Validation.ps1 -Mode Full -CompareWithLast

"@ -ForegroundColor Cyan
}

function Show-Banner {
    Write-Host @"
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║           RawrXD Production Validation Framework             ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan
}

function Test-FrameworkBuilt {
    $exePath = "harness\ValidationHarness.exe"
    if (-not (Test-Path $exePath)) {
        Write-Host "Validation framework not built. Building now..." -ForegroundColor Yellow
        return $false
    }
    return $true
}

function Build-Framework {
    Write-Host "Building validation framework..." -ForegroundColor Cyan
    
    Push-Location "harness"
    try {
        $result = & .\build.bat 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "Build failed with exit code $LASTEXITCODE"
        }
        Write-Host "Build successful!" -ForegroundColor Green
    } finally {
        Pop-Location
    }
}

function Get-LastRunPath {
    $outputDir = "validation_output"
    if (-not (Test-Path $outputDir)) {
        return $null
    }
    
    $runs = Get-ChildItem -Directory -Path $outputDir | Sort-Object LastWriteTime -Descending
    if ($runs.Count -eq 0) {
        return $null
    }
    
    return Join-Path $runs[0].FullName "final_validation_report.json"
}

# ============================================================================
# Main Execution
# ============================================================================

if ($Help) {
    Show-Help
    exit 0
}

Show-Banner

# Show mode info
$config = $ModeConfig[$Mode]
Write-Host "Mode: $Mode - $($config.Description)" -ForegroundColor Cyan
Write-Host "Target: $TargetUrl" -ForegroundColor Gray
Write-Host ""

# Determine benchmark runs
$runs = if ($BenchmarkRuns -gt 0) { $BenchmarkRuns } else { $config.BenchmarkRuns }

# Build if requested or needed
if ($Build -or -not (Test-FrameworkBuilt)) {
    Build-Framework
    Write-Host ""
}

# Determine output path
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$outPath = if ($OutputPath) { $OutputPath } else { "validation_output\run_$timestamp" }

# Run validation based on mode
switch ($Mode) {
    "HardwareOnly" {
        Write-Host "Running hardware validation..." -ForegroundColor Cyan
        & .\Validate-Production.ps1 `
            -HardwareValidationOnly `
            -OutputPath $outPath
    }
    
    "CI" {
        Write-Host "Running CI validation..." -ForegroundColor Cyan
        & .\ci\Validate-CI.ps1 `
            -TargetUrl $TargetUrl `
            -BenchmarkRuns $runs `
            -OutputPath $outPath `
            -GenerateReport
    }
    
    default {
        Write-Host "Running validation ($runs iterations)..." -ForegroundColor Cyan
        $params = @{
            TargetUrl = $TargetUrl
            BenchmarkRuns = $runs
            OutputPath = $outPath
        }
        
        if ($config.HardwareValidation) {
            $params['HardwareValidation'] = $true
        }
        
        & .\Validate-Production.ps1 @params
    }
}

if ($LASTEXITCODE -ne 0) {
    Write-Host "Validation failed!" -ForegroundColor Red
    exit $LASTEXITCODE
}

Write-Host ""
Write-Host "Validation complete!" -ForegroundColor Green
Write-Host "Output: $outPath" -ForegroundColor Gray

# Generate report if requested
if ($GenerateReport) {
    Write-Host ""
    Write-Host "Generating reports..." -ForegroundColor Cyan
    
    & .\tools\Generate-ValidationReport.ps1 `
        -ValidationOutputPath $outPath `
        -ReportType Full
}

# Compare with last run if requested
if ($CompareWithLast) {
    Write-Host ""
    Write-Host "Comparing with previous run..." -ForegroundColor Cyan
    
    $lastRun = Get-LastRunPath
    if ($lastRun) {
        $currentRun = Join-Path $outPath "final_validation_report.json"
        & .\tools\Compare-ValidationResults.ps1 `
            -BaselinePath $lastRun `
            -CurrentPath $currentRun `
            -GenerateHTML
    } else {
        Write-Host "No previous run found for comparison" -ForegroundColor Yellow
    }
}

# Open dashboard if requested
if ($OpenDashboard) {
    Write-Host ""
    Write-Host "Opening dashboard..." -ForegroundColor Cyan
    
    $dashboardPath = Resolve-Path "dashboard\ValidationDashboard.html"
    Start-Process $dashboardPath
}

# Show summary
Write-Host ""
Write-Host "Summary" -ForegroundColor Cyan
Write-Host "=======" -ForegroundColor Cyan

$reportPath = Join-Path $outPath "final_validation_report.json"
if (Test-Path $reportPath) {
    $report = Get-Content $reportPath | ConvertFrom-Json
    
    if ($report.certification) {
        $status = if ($report.certification.all_passed) { "✅ PASSED" } else { "❌ FAILED" }
        Write-Host "Certification: $status" -ForegroundColor $(if ($report.certification.all_passed) { "Green" } else { "Red" })
    }
    
    if ($report.inference) {
        Write-Host "TPS: $([math]::Round($report.inference.avg_tps, 1))" -ForegroundColor Gray
        Write-Host "Latency: $([math]::Round($report.inference.avg_latency_ms, 0))ms" -ForegroundColor Gray
        Write-Host "TTFT: $([math]::Round($report.inference.avg_ttft_ms, 0))ms" -ForegroundColor Gray
    }
}

Write-Host ""
Write-Host "Done!" -ForegroundColor Green
