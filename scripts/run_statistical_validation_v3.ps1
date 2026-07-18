#!/usr/bin/env pwsh
# Gate D Statistical Validation - Working Version

param([int]$Iterations = 100)

Write-Host "Gate D Statistical Validation - $Iterations iterations" -ForegroundColor Cyan
Write-Host ""

$TestExe = "d:\rawrxd-ci-bootstrap\build-ninja\tests\test_gate_d_intrinsics.exe"

$rmsnormSpeedups = @()
$softmaxSpeedups = @()

for ($i = 1; $i -le $Iterations; $i++) {
    # Run test and capture output as array of strings
    $result = & $TestExe 2>&1
    
    # Find lines with Speedup
    $speedupLines = $result | Select-String "Speedup:"
    
    if ($speedupLines.Count -ge 2) {
        # First line is RMSNorm
        if ($speedupLines[0] -match "Speedup:\s+([0-9.]+)") {
            $rmsnormSpeedups += [float]$matches[1]
        }
        # Second line is Softmax
        if ($speedupLines[1] -match "Speedup:\s+([0-9.]+)") {
            $softmaxSpeedups += [float]$matches[1]
        }
    }
    
    if ($i % 10 -eq 0) { Write-Host "  $i/$Iterations" -ForegroundColor Gray }
}

Write-Host ""
Write-Host "=== Statistical Results ===" -ForegroundColor Green

if ($rmsnormSpeedups.Count -gt 0) {
    $rmsnormMean = ($rmsnormSpeedups | Measure-Object -Average).Average
    $rmsnormMin = ($rmsnormSpeedups | Measure-Object -Minimum).Minimum
    $rmsnormMax = ($rmsnormSpeedups | Measure-Object -Maximum).Maximum
    $rmsnormSorted = $rmsnormSpeedups | Sort-Object
    $rmsnormP5 = $rmsnormSorted[[int]($rmsnormSorted.Count * 0.05)]
    $rmsnormP95 = $rmsnormSorted[[int]($rmsnormSorted.Count * 0.95)]
    
    Write-Host "RMSNorm AVX2:" -ForegroundColor Yellow
    Write-Host "  Mean Speedup: $([math]::Round($rmsnormMean, 2))x"
    Write-Host "  Range: $([math]::Round($rmsnormMin, 2))x - $([math]::Round($rmsnormMax, 2))x"
    Write-Host "  90% CI: $([math]::Round($rmsnormP5, 2))x - $([math]::Round($rmsnormP95, 2))x"
    Write-Host "  Status: $(if ($rmsnormMean -ge 3.0) { 'PASS' } else { 'FAIL' })" -ForegroundColor $(if ($rmsnormMean -ge 3.0) { 'Green' } else { 'Red' })
}

if ($softmaxSpeedups.Count -gt 0) {
    $softmaxMean = ($softmaxSpeedups | Measure-Object -Average).Average
    $softmaxMin = ($softmaxSpeedups | Measure-Object -Minimum).Minimum
    $softmaxMax = ($softmaxSpeedups | Measure-Object -Maximum).Maximum
    $softmaxSorted = $softmaxSpeedups | Sort-Object
    $softmaxP5 = $softmaxSorted[[int]($softmaxSorted.Count * 0.05)]
    $softmaxP95 = $softmaxSorted[[int]($softmaxSorted.Count * 0.95)]
    
    Write-Host "Softmax AVX2:" -ForegroundColor Yellow
    Write-Host "  Mean Speedup: $([math]::Round($softmaxMean, 2))x"
    Write-Host "  Range: $([math]::Round($softmaxMin, 2))x - $([math]::Round($softmaxMax, 2))x"
    Write-Host "  90% CI: $([math]::Round($softmaxP5, 2))x - $([math]::Round($softmaxP95, 2))x"
    Write-Host "  Status: $(if ($softmaxMean -ge 2.0) { 'PASS' } else { 'FAIL' })" -ForegroundColor $(if ($softmaxMean -ge 2.0) { 'Green' } else { 'Red' })
}

# Save results
New-Item -ItemType Directory -Force -Path "d:\rawrxd-ci-bootstrap\evidence\gate_d" | Out-Null
$rmsnormSpeedups | Out-File "d:\rawrxd-ci-bootstrap\evidence\gate_d\rmsnorm_speedups.csv"
$softmaxSpeedups | Out-File "d:\rawrxd-ci-bootstrap\evidence\gate_d\softmax_speedups.csv"

Write-Host ""
Write-Host "Results saved to evidence/gate_d/" -ForegroundColor Cyan
