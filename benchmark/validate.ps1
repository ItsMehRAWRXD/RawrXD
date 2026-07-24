#!/usr/bin/env pwsh
# RawrXD Validation Suite
# Validates correctness against reference implementations

param(
    [string]$BuildDir = "build",
    [string]$ReportDir = "benchmark\reports",
    [string]$ModelsDir = "benchmark\models",
    [switch]$Quick = $false
)

$ErrorActionPreference = "Stop"

# Validation configuration
$Validations = @(
    @{ Name = "Tokenizer Parity"; Script = "test_tokenizer.ps1"; Reference = "HuggingFace Transformers"; Tolerance = "100%"; Critical = $true },
    @{ Name = "Tensor Loading"; Script = "test_tensors.ps1"; Reference = "PyTorch"; Tolerance = "Bit-exact"; Critical = $true },
    @{ Name = "Layer Forward"; Script = "test_layers.ps1"; Reference = "llama.cpp"; Tolerance = "< 0.1% RMSE"; Critical = $true },
    @{ Name = "KV Cache"; Script = "test_kv_cache.ps1"; Reference = "Reference impl"; Tolerance = "Bit-exact"; Critical = $true },
    @{ Name = "End-to-End"; Script = "test_e2e.ps1"; Reference = "Known outputs"; Tolerance = "Perplexity match"; Critical = $false },
    @{ Name = "Long Context"; Script = "test_long_context.ps1"; Reference = "Reference"; Tolerance = "Stable to 128K"; Critical = $false }
)

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "RawrXD Validation Suite" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Build:   $BuildDir"
Write-Host "Report:  $ReportDir"
Write-Host "Quick:   $Quick"
Write-Host ""

# Check prerequisites
if (-not (Test-Path "$BuildDir\RawrXD.exe")) {
    Write-Host "ERROR: RawrXD.exe not found. Run build.ps1 first." -ForegroundColor Red
    exit 1
}

New-Item -ItemType Directory -Force -Path $ReportDir | Out-Null

$Results = @()
$StartTime = Get-Date

foreach ($val in $Validations) {
    if ($Quick -and -not $val.Critical) {
        Write-Host "[SKIP] $($val.Name) (non-critical in quick mode)" -ForegroundColor Gray
        continue
    }
    
    Write-Host "[TEST] $($val.Name)..." -NoNewline
    $testStart = Get-Date
    
    $testPath = "benchmark\$($val.Script)"
    if (Test-Path $testPath) {
        try {
            $output = & $testPath -BuildDir $BuildDir -ModelsDir $ModelsDir 2>&1
            $exitCode = $LASTEXITCODE
        } catch {
            $output = $_.Exception.Message
            $exitCode = 1
        }
    } else {
        # Test script doesn't exist yet - mark as pending
        $output = "Test script not yet implemented"
        $exitCode = 2
    }
    
    $duration = (Get-Date) - $testStart
    
    $result = @{
        Name = $val.Name
        Reference = $val.Reference
        Tolerance = $val.Tolerance
        Status = switch ($exitCode) { 0 { "PASS" } 2 { "PENDING" } default { "FAIL" } }
        Duration = $duration.TotalSeconds
        Output = $output
        Critical = $val.Critical
    }
    $Results += $result
    
    $color = switch ($result.Status) { "PASS" { "Green" } "PENDING" { "Yellow" } default { "Red" } }
    Write-Host " $($result.Status) ($($duration.TotalSeconds.ToString('F1'))s)" -ForegroundColor $color
}

$totalDuration = (Get-Date) - $StartTime

# Generate report
$report = @{
    timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
    commit = (git rev-parse HEAD 2>$null) || "unknown"
    duration_seconds = [math]::Round($totalDuration.TotalSeconds, 2)
    summary = @{
        total = $Results.Count
        passed = ($Results | Where-Object { $_.Status -eq "PASS" }).Count
        failed = ($Results | Where-Object { $_.Status -eq "FAIL" }).Count
        pending = ($Results | Where-Object { $_.Status -eq "PENDING" }).Count
    }
    results = $Results
}

$reportPath = "$ReportDir\validation_report.json"
$report | ConvertTo-Json -Depth 4 | Set-Content $reportPath

# Print summary
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Validation Summary" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Total:   $($report.summary.total)"
Write-Host "Passed:  $($report.summary.passed)" -ForegroundColor Green
Write-Host "Failed:  $($report.summary.failed)" -ForegroundColor Red
Write-Host "Pending: $($report.summary.pending)" -ForegroundColor Yellow
Write-Host "Time:    $($totalDuration.TotalMinutes.ToString('F1')) minutes"
Write-Host ""
Write-Host "Report:  $reportPath"

# Exit with error code if any critical tests failed
$criticalFailures = $Results | Where-Object { $_.Critical -and $_.Status -eq "FAIL" }
if ($criticalFailures.Count -gt 0) {
    Write-Host ""
    Write-Host "ERROR: $($criticalFailures.Count) critical validation(s) failed" -ForegroundColor Red
    exit 1
}

exit 0
