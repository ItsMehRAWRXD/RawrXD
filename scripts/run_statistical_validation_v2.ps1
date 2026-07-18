#!/usr/bin/env pwsh
# Gate D Statistical Validation - Simplified Version

param([int]$Iterations = 100)

Write-Host "Gate D Statistical Validation - $Iterations iterations" -ForegroundColor Cyan

$TestExe = "d:\rawrxd-ci-bootstrap\build-ninja\tests\test_gate_d_intrinsics.exe"

$rmsnormSpeedups = @()
$softmaxSpeedups = @()

for ($i = 1; $i -le $Iterations; $i++) {
    $result = & $TestExe 2>&1
    $resultString = $result -join "`n"
    
    # Extract RMSNorm speedup
    if ($resultString -match "RMSNorm.*Speedup:\s+([0-9.]+)") {
        $val = [float]$matches[1]
        $rmsnormSpeedups += $val
    }
    
    # Extract Softmax speedup
    if ($resultString -match "Softmax.*Speedup:\s+([0-9.]+)") {
        $val = [float]$matches[1]
        $softmaxSpeedups += $val
    }
    
    if ($i % 10 -eq 0) { Write-Host "  $i/$Iterations" }
}

# Calculate statistics
$rmsnormMean = ($rmsnormSpeedups | Measure-Object -Average).Average
$softmaxMean = ($softmaxSpeedups | Measure-Object -Average).Average

$rmsnormSorted = $rmsnormSpeedups | Sort-Object
$softmaxSorted = $softmaxSpeedups | Sort-Object

Write-Host ""
Write-Host "=== Results ===" -ForegroundColor Green
Write-Host "RMSNorm: Mean = $([math]::Round($rmsnormMean, 2))x, Min = $($rmsnormSorted[0])x, Max = $($rmsnormSorted[-1])x"
Write-Host "Softmax: Mean = $([math]::Round($softmaxMean, 2))x, Min = $($softmaxSorted[0])x, Max = $($softmaxSorted[-1])x"

# Save results
$rmsnormSpeedups | Out-File "d:\rawrxd-ci-bootstrap\evidence\gate_d\rmsnorm_speedups.csv"
$softmaxSpeedups | Out-File "d:\rawrxd-ci-bootstrap\evidence\gate_d\softmax_speedups.csv"

Write-Host "Results saved to evidence/gate_d/"
