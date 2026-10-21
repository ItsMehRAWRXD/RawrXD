# B009 Performance Validation Script
# Compares B009 batched prefill results against B007 baseline

param(
    [string]$B009Log = "B009/logs/test_run.log",
    [string]$B007Baseline = "B008/performance/b007_baseline.json",
    [string]$OutputPath = "B009/performance/b009_vs_b007.json"
)

$ErrorActionPreference = "Stop"

Write-Host "=== B009 Performance Validator ===" -ForegroundColor Cyan
Write-Host ""

# Load B007 baseline
if (-not (Test-Path $B007Baseline)) {
    Write-Warning "B007 baseline not found at $B007Baseline - using hardcoded values"
    $baseline = @{
        prefill_ms = 12381.83
        decode_ms = 4448.29
        layer_executions = 84
    }
} else {
    $baseline = Get-Content $B007Baseline | ConvertFrom-Json
}

Write-Host "B007 Baseline:" -ForegroundColor Yellow
Write-Host "  Prefill: $($baseline.prefill_ms) ms"
Write-Host "  Decode:  $($baseline.decode_ms) ms"
Write-Host "  Layers:  $($baseline.layer_executions) executions"
Write-Host ""

# Parse B009 test output
if (-not (Test-Path $B009Log)) {
    Write-Error "B009 test log not found at $B009Log"
    exit 1
}

$log = Get-Content $B009Log -Raw

# Extract metrics (adapt regex to match actual output format)
$prefillMatch = $log | Select-String -Pattern "Prefill:\s*([\d.]+)\s*ms"
$decodeMatch = $log | Select-String -Pattern "Decode:\s*([\d.]+)\s*ms"
$layerExecMatch = $log | Select-String -Pattern "layer_executions=(\d+)"

$prefillMs = if ($prefillMatch) { [double]$prefillMatch.Matches[0].Groups[1].Value } else { 0 }
$decodeMs = if ($decodeMatch) { [double]$decodeMatch.Matches[0].Groups[1].Value } else { 0 }
$layerExecs = if ($layerExecMatch) { [int]$layerExecMatch.Matches[0].Groups[1].Value } else { 0 }

Write-Host "B009 Results:" -ForegroundColor Green
Write-Host "  Prefill: $prefillMs ms"
Write-Host "  Decode:  $decodeMs ms"
Write-Host "  Layers:  $layerExecs executions"
Write-Host ""

# Calculate deltas
$prefillSpeedup = if ($baseline.prefill_ms -gt 0) { $baseline.prefill_ms / $prefillMs } else { 0 }
$decodeDeltaPct = if ($baseline.decode_ms -gt 0) { (($decodeMs - $baseline.decode_ms) / $baseline.decode_ms) * 100 } else { 0 }
$layerReduction = if ($baseline.layer_executions -gt 0) { (($baseline.layer_executions - $layerExecs) / $baseline.layer_executions) * 100 } else { 0 }

Write-Host "Analysis:" -ForegroundColor Cyan
Write-Host "  Prefill speedup: ${prefillSpeedup:N2}x"
Write-Host "  Decode delta:    ${decodeDeltaPct:N1}%"
Write-Host "  Layer reduction: ${layerReduction:N1}%"
Write-Host ""

# Gate checks
$gates = @{
    prefill_speedup = @{ target = 2.5; actual = $prefillSpeedup; pass = ($prefillSpeedup -ge 2.5) }
    decode_regression = @{ target = 5.0; actual = $decodeDeltaPct; pass = ($decodeDeltaPct -le 5.0) }
    layer_reduction = @{ target = 60.0; actual = $layerReduction; pass = ($layerReduction -ge 60.0) }
}

$allPass = $true
Write-Host "Gate Results:" -ForegroundColor White
foreach ($gate in $gates.GetEnumerator()) {
    $status = if ($gate.Value.pass) { "PASS" } else { "FAIL" }
    $color = if ($gate.Value.pass) { "Green" } else { "Red" }
    Write-Host "  $($gate.Key): $status (target: $($gate.Value.target), actual: $($gate.Value.actual))" -ForegroundColor $color
    if (-not $gate.Value.pass) { $allPass = $false }
}

Write-Host ""
if ($allPass) {
    Write-Host "=== ALL GATES PASS ===" -ForegroundColor Green
} else {
    Write-Host "=== SOME GATES FAILED ===" -ForegroundColor Red
}

# Write JSON report
$report = @{
    timestamp = (Get-Date -Format "o")
    baseline = $baseline
    b009 = @{
        prefill_ms = $prefillMs
        decode_ms = $decodeMs
        layer_executions = $layerExecs
    }
    analysis = @{
        prefill_speedup = $prefillSpeedup
        decode_delta_pct = $decodeDeltaPct
        layer_reduction_pct = $layerReduction
    }
    gates = $gates
    overall = if ($allPass) { "PASS" } else { "FAIL" }
}

$report | ConvertTo-Json -Depth 4 | Set-Content $OutputPath
Write-Host ""
Write-Host "Report written to: $OutputPath"

exit ($allPass ? 0 : 1)
