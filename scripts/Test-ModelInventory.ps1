<#
.SYNOPSIS
    Bulk Model Loading and Layout Verification Test Suite.
.DESCRIPTION
    Validates model dimensions, metadata keys, and layer configurations
    across your entire linked model cache sequentially.
#>
param (
    [string]$ModelsDir = "G:\~dev\rawrxd\models",
    [string]$EngineExe = "build\bin\Deep2Engine_Benchmark.exe",
    [string]$ReportPath = "build\inventory_audit_report.log"
)

Write-Host "====================================================" -ForegroundColor Cyan
Write-Host "         DEEP2ENGINE MULTI-FAMILY AUDIT MATRIX      " -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan

if (-not (Test-Path $EngineExe)) {
    Write-Error "[BUILD_ERR] Engine binary target not found at $EngineExe. Run compilation sweep first."
    exit 1
}

$modelFiles = Get-ChildItem -Path $ModelsDir -Filter "*.gguf"
if ($modelFiles.Count -eq 0) {
    Write-Warning "[WARN] Zero model symlinks found in $ModelsDir. Execute mapper script first."
    exit 0
}

$reportLines = @()
$reportLines += "====================================================================="
$reportLines += "DEEP2ENGINE AUTOMATED MULTI-FAMILY AUDIT REPORT - $(Get-Date)"
$reportLines += "====================================================================="

$passedCount = 0
$failedCount = 0

foreach ($model in $modelFiles) {
    Write-Host "`n[AUDIT] Launching layout parsing sweep for: $($model.Name)" -ForegroundColor Yellow
    
    # Execute model initialization phase and intercept standard error channels
    $processOutput = & $EngineExe $model.FullName --verify-init-only 2>&1 | Out-String
    
    # Scan output string buffers for successful boot confirmations
    if ($processOutput -like "*Deep2Engine::initialize SUCCESS*") {
        Write-Host "  -> STATUS: [PASS] Geometry verified successfully." -ForegroundColor Green
        $status = "PASS"
        $passedCount++
    } else {
        # Extract trailing error context from log payload
        $errorStage = "UNKNOWN_FAILURE"
        if ($processOutput -match "stage=(\w+)") { $errorStage = $Matches[1] }
        
        Write-Host "  -> STATUS: [FAIL] Initializer halted at step: $errorStage" -ForegroundColor Red
        $status = "FAIL ($errorStage)"
        $failedCount++
    }
    
    $reportLines += [string]::Format("{0,-50} | {1}", $model.Name, $status)
}

# Output final statistical summary logs
$summary = "`nAudit Sweeps Concluded. Total Passed: $passedCount | Total Failed: $failedCount"
Write-Host $summary -ForegroundColor Cyan
$reportLines += "`n" + $summary

Set-Content -Path $ReportPath -Value $reportLines -Force
Write-Host "[REPORT] Detailed audit telemetry written to: $ReportPath" -ForegroundColor Gray