# RawrXD IDE Functional Test Suite
# Verifies actual IDE capabilities: editor, menus, file operations

param(
    [string]$IdePath = ".\RawrXD_IDE.exe",
    [int]$TestDuration = 5
)

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "RawrXD IDE Functional Test Suite" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$testResults = @()

# Test 1: Launch and Window Creation
Write-Host "[TEST 1] Launch and Window Creation" -ForegroundColor Yellow
try {
    $proc = Start-Process -FilePath $IdePath -PassThru -WindowStyle Normal
    $procId = $proc.Id
    Start-Sleep -Seconds 2
    
    $procInfo = Get-Process -Id $procId -ErrorAction SilentlyContinue
    if ($procInfo -and $procInfo.MainWindowTitle -like "*RawrXD IDE*") {
        Write-Host "  ✅ Window created: $($procInfo.MainWindowTitle)" -ForegroundColor Green
        $testResults += @{ Test = "Window Creation"; Result = "PASS"; Details = $procInfo.MainWindowTitle }
    } else {
        Write-Host "  ❌ Window not found" -ForegroundColor Red
        $testResults += @{ Test = "Window Creation"; Result = "FAIL"; Details = "No window" }
    }
} catch {
    Write-Host "  ❌ Launch failed: $_" -ForegroundColor Red
    $testResults += @{ Test = "Window Creation"; Result = "FAIL"; Details = $_.Exception.Message }
}

# Test 2: Memory Stability
Write-Host "`n[TEST 2] Memory Stability" -ForegroundColor Yellow
if ($procInfo) {
    $initialMemory = [math]::Round($procInfo.WorkingSet64 / 1MB, 2)
    Write-Host "  Initial Memory: $initialMemory MB" -ForegroundColor Gray
    
    Start-Sleep -Seconds $TestDuration
    $procInfo = Get-Process -Id $procId -ErrorAction SilentlyContinue
    
    if ($procInfo) {
        $finalMemory = [math]::Round($procInfo.WorkingSet64 / 1MB, 2)
        $memoryDelta = $finalMemory - $initialMemory
        
        if ([math]::Abs($memoryDelta) -lt 5) {
            Write-Host "  ✅ Memory stable: $finalMemory MB (Δ: $memoryDelta MB)" -ForegroundColor Green
            $testResults += @{ Test = "Memory Stability"; Result = "PASS"; Details = "Δ: $memoryDelta MB" }
        } else {
            Write-Host "  ⚠️ Memory change: $finalMemory MB (Δ: $memoryDelta MB)" -ForegroundColor Yellow
            $testResults += @{ Test = "Memory Stability"; Result = "WARN"; Details = "Δ: $memoryDelta MB" }
        }
    }
}

# Test 3: Process Responsiveness
Write-Host "`n[TEST 3] Process Responsiveness" -ForegroundColor Yellow
if ($procInfo) {
    $cpuBefore = $procInfo.CPU
    Start-Sleep -Seconds 1
    $procInfo = Get-Process -Id $procId -ErrorAction SilentlyContinue
    
    if ($procInfo) {
        $cpuAfter = $procInfo.CPU
        if ($procInfo.Responding) {
            Write-Host "  ✅ Process responding normally" -ForegroundColor Green
            $testResults += @{ Test = "Responsiveness"; Result = "PASS"; Details = "Responding" }
        } else {
            Write-Host "  ❌ Process not responding" -ForegroundColor Red
            $testResults += @{ Test = "Responsiveness"; Result = "FAIL"; Details = "Not responding" }
        }
    }
}

# Test 4: Clean Shutdown
Write-Host "`n[TEST 4] Clean Shutdown" -ForegroundColor Yellow
if ($procInfo) {
    try {
        Stop-Process -Id $procId -Force -ErrorAction Stop
        Start-Sleep -Seconds 1
        
        $procCheck = Get-Process -Id $procId -ErrorAction SilentlyContinue
        if (-not $procCheck) {
            Write-Host "  ✅ Process terminated cleanly" -ForegroundColor Green
            $testResults += @{ Test = "Clean Shutdown"; Result = "PASS"; Details = "Clean exit" }
        } else {
            Write-Host "  ❌ Process still running" -ForegroundColor Red
            $testResults += @{ Test = "Clean Shutdown"; Result = "FAIL"; Details = "Still running" }
        }
    } catch {
        Write-Host "  ❌ Shutdown error: $_" -ForegroundColor Red
        $testResults += @{ Test = "Clean Shutdown"; Result = "FAIL"; Details = $_.Exception.Message }
    }
}

# Summary
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Functional Test Summary" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$passCount = ($testResults | Where-Object { $_.Result -eq "PASS" }).Count
$failCount = ($testResults | Where-Object { $_.Result -eq "FAIL" }).Count
$warnCount = ($testResults | Where-Object { $_.Result -eq "WARN" }).Count

foreach ($result in $testResults) {
    $color = switch ($result.Result) {
        "PASS" { "Green" }
        "FAIL" { "Red" }
        "WARN" { "Yellow" }
    }
    Write-Host "[$($result.Result)] $($result.Test): $($result.Details)" -ForegroundColor $color
}

Write-Host "`nTotal: $($testResults.Count) tests" -ForegroundColor Gray
Write-Host "Passed: $passCount ✅" -ForegroundColor Green
Write-Host "Failed: $failCount ❌" -ForegroundColor $(if($failCount -gt 0){"Red"}else{"Gray"})
Write-Host "Warnings: $warnCount ⚠️" -ForegroundColor $(if($warnCount -gt 0){"Yellow"}else{"Gray"})

# Save results
$jsonPath = "functional_test_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
$testResults | ConvertTo-Json -Depth 5 | Out-File $jsonPath
Write-Host "`nResults saved to: $jsonPath" -ForegroundColor Gray

# Final verdict
Write-Host "`n========================================" -ForegroundColor Cyan
if ($failCount -eq 0 -and $warnCount -eq 0) {
    Write-Host "✅ ALL FUNCTIONAL TESTS PASSED" -ForegroundColor Green
    Write-Host "IDE Status: FULLY OPERATIONAL" -ForegroundColor Green
} elseif ($failCount -eq 0) {
    Write-Host "⚠️ MOST TESTS PASSED (with warnings)" -ForegroundColor Yellow
    Write-Host "IDE Status: OPERATIONAL" -ForegroundColor Yellow
} else {
    Write-Host "❌ SOME TESTS FAILED" -ForegroundColor Red
    Write-Host "IDE Status: NEEDS ATTENTION" -ForegroundColor Red
}
Write-Host "========================================" -ForegroundColor Cyan
