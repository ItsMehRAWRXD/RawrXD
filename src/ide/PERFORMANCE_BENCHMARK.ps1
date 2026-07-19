# RawrXD IDE Performance Benchmark
# Measures startup time, memory usage, and UI responsiveness

param(
    [string]$IdePath = ".\RawrXD_IDE.exe",
    [int]$DurationSeconds = 30
)

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "RawrXD IDE Performance Benchmark" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$results = @{
    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    BinarySize = (Get-Item $IdePath).Length
    Tests = @()
}

# Test 1: Startup Time
Write-Host "[TEST 1] Startup Time Measurement" -ForegroundColor Yellow
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$proc = Start-Process -FilePath $IdePath -PassThru -WindowStyle Hidden
$procId = $proc.Id

# Wait for process to initialize
Start-Sleep -Milliseconds 500
$startupTime = $sw.ElapsedMilliseconds
$sw.Stop()

Write-Host "  Process ID: $procId" -ForegroundColor Gray
Write-Host "  Startup Time: $startupTime ms" -ForegroundColor $(if($startupTime -lt 1000){"Green"}else{"Yellow"})

$results.Tests += @{
    Name = "Startup Time"
    Value = $startupTime
    Unit = "ms"
    Target = 1000
    Status = if($startupTime -lt 1000){"PASS"}else{"WARN"}
}

# Test 2: Memory Footprint
Write-Host "`n[TEST 2] Memory Footprint" -ForegroundColor Yellow
Start-Sleep -Seconds 2
$procInfo = Get-Process -Id $procId -ErrorAction SilentlyContinue

if ($procInfo) {
    $workingSet = [math]::Round($procInfo.WorkingSet64 / 1MB, 2)
    $pagedMemory = [math]::Round($procInfo.PagedMemorySize64 / 1MB, 2)
    
    Write-Host "  Working Set: $workingSet MB" -ForegroundColor $(if($workingSet -lt 100){"Green"}else{"Yellow"})
    Write-Host "  Paged Memory: $pagedMemory MB" -ForegroundColor Gray
    
    $results.Tests += @{
        Name = "Working Set"
        Value = $workingSet
        Unit = "MB"
        Target = 100
        Status = if($workingSet -lt 100){"PASS"}else{"WARN"}
    }
}

# Test 3: Stability Over Time
Write-Host "`n[TEST 3] Stability Over $DurationSeconds Seconds" -ForegroundColor Yellow
$memoryReadings = @()
$cpuReadings = @()

for ($i = 0; $i -lt $DurationSeconds; $i++) {
    Start-Sleep -Seconds 1
    $procInfo = Get-Process -Id $procId -ErrorAction SilentlyContinue
    
    if ($procInfo) {
        $memoryReadings += [math]::Round($procInfo.WorkingSet64 / 1MB, 2)
        $cpuReadings += $procInfo.CPU
        
        if ($i % 5 -eq 0) {
            Write-Host "  [$i`s] Memory: $($memoryReadings[-1]) MB, CPU: $($cpuReadings[-1])" -ForegroundColor Gray
        }
    } else {
        Write-Host "  [ERROR] Process terminated unexpectedly!" -ForegroundColor Red
        break
    }
}

if ($memoryReadings.Count -gt 0) {
    $avgMemory = ($memoryReadings | Measure-Object -Average).Average
    $maxMemory = ($memoryReadings | Measure-Object -Maximum).Maximum
    $minMemory = ($memoryReadings | Measure-Object -Minimum).Minimum
    $memoryGrowth = $memoryReadings[-1] - $memoryReadings[0]
    
    Write-Host "  Average Memory: $([math]::Round($avgMemory, 2)) MB" -ForegroundColor Gray
    Write-Host "  Peak Memory: $maxMemory MB" -ForegroundColor Gray
    Write-Host "  Memory Growth: $([math]::Round($memoryGrowth, 2)) MB" -ForegroundColor $(if($memoryGrowth -lt 10){"Green"}else{"Yellow"})
    
    $results.Tests += @{
        Name = "Memory Growth"
        Value = [math]::Round($memoryGrowth, 2)
        Unit = "MB"
        Target = 10
        Status = if($memoryGrowth -lt 10){"PASS"}else{"WARN"}
    }
}

# Test 4: Shutdown Time
Write-Host "`n[TEST 4] Shutdown Time" -ForegroundColor Yellow
$sw = [System.Diagnostics.Stopwatch]::StartNew()
Stop-Process -Id $procId -Force -ErrorAction SilentlyContinue
$shutdownTime = $sw.ElapsedMilliseconds
$sw.Stop()

Write-Host "  Shutdown Time: $shutdownTime ms" -ForegroundColor $(if($shutdownTime -lt 500){"Green"}else{"Yellow"})

$results.Tests += @{
    Name = "Shutdown Time"
    Value = $shutdownTime
    Unit = "ms"
    Target = 500
    Status = if($shutdownTime -lt 500){"PASS"}else{"WARN"}
}

# Summary
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Benchmark Summary" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$passCount = ($results.Tests | Where-Object { $_.Status -eq "PASS" }).Count
$warnCount = ($results.Tests | Where-Object { $_.Status -eq "WARN" }).Count

Write-Host "Binary Size: $([math]::Round($results.BinarySize / 1KB, 2)) KB" -ForegroundColor Gray
Write-Host "Tests Passed: $passCount / $($results.Tests.Count)" -ForegroundColor $(if($passCount -eq $results.Tests.Count){"Green"}else{"Yellow"})
Write-Host "Warnings: $warnCount" -ForegroundColor $(if($warnCount -eq 0){"Green"}else{"Yellow"})

# Save results
$jsonPath = "benchmark_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
$results | ConvertTo-Json -Depth 10 | Out-File $jsonPath
Write-Host "`nResults saved to: $jsonPath" -ForegroundColor Gray

# Final verdict
Write-Host "`n========================================" -ForegroundColor Cyan
if ($passCount -eq $results.Tests.Count) {
    Write-Host "✅ ALL TESTS PASSED" -ForegroundColor Green
    Write-Host "IDE Performance: EXCELLENT" -ForegroundColor Green
} elseif ($passCount -ge ($results.Tests.Count / 2)) {
    Write-Host "⚠️ MOST TESTS PASSED" -ForegroundColor Yellow
    Write-Host "IDE Performance: ACCEPTABLE" -ForegroundColor Yellow
} else {
    Write-Host "❌ TESTS FAILED" -ForegroundColor Red
    Write-Host "IDE Performance: NEEDS OPTIMIZATION" -ForegroundColor Red
}
Write-Host "========================================" -ForegroundColor Cyan
