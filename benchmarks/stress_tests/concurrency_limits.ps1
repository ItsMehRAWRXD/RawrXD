# Concurrency Stress Test
# Finds the breaking point of the system

param(
    [int]$StartConcurrency = 1,
    [int]$MaxConcurrency = 200,
    [int]$StepMultiplier = 2,
    [int]$DurationPerStep = 30,
    [int]$SuccessRateThreshold = 95,
    [int]$LatencyThresholdMs = 5000
)

$SecureHotpatchPath = "security/integration/secure_hotpatch.ps1"

function Test-ConcurrencyLevel {
    param([int]$Concurrency, [int]$Duration)
    
    Write-Host "  Testing concurrency: $Concurrency" -ForegroundColor Gray
    
    $jobs = @()
    $metrics = @{
        requests = 0
        successes = 0
        failures = 0
        latencies = @()
    }
    
    # Start workers
    for ($i = 0; $i -lt $Concurrency; $i++) {
        $jobs += Start-Job -ScriptBlock {
            param($Path, $Duration)
            $localMetrics = @{
                requests = 0
                successes = 0
                failures = 0
                latencies = @()
            }
            
            $endTime = (Get-Date).AddSeconds($Duration)
            while ((Get-Date) -lt $endTime) {
                $sw = [System.Diagnostics.Stopwatch]::StartNew()
                try {
                    & $Path -Operation status | Out-Null
                    $localMetrics.successes++
                }
                catch {
                    $localMetrics.failures++
                }
                $sw.Stop()
                
                $localMetrics.requests++
                $localMetrics.latencies += $sw.ElapsedMilliseconds
            }
            
            return $localMetrics
        } -ArgumentList $SecureHotpatchPath, $Duration
    }
    
    # Collect results
    $results = $jobs | Wait-Job | Receive-Job
    $jobs | Remove-Job
    
    foreach ($result in $results) {
        $metrics.requests += $result.requests
        $metrics.successes += $result.successes
        $metrics.failures += $result.failures
        $metrics.latencies += $result.latencies
    }
    
    # Calculate statistics
    $sorted = $metrics.latencies | Sort-Object
    $successRate = if ($metrics.requests -gt 0) { ($metrics.successes / $metrics.requests) * 100 } else { 0 }
    $tps = if ($Duration -gt 0) { $metrics.requests / $Duration } else { 0 }
    
    return @{
        concurrency = $Concurrency
        duration = $Duration
        total_requests = $metrics.requests
        success_rate = [math]::Round($successRate, 2)
        tps = [math]::Round($tps, 2)
        latency_ms = @{
            avg = [math]::Round(($metrics.latencies | Measure-Object -Average).Average, 2)
            p50 = $sorted[[int]($sorted.Count * 0.5)]
            p95 = $sorted[[int]($sorted.Count * 0.95)]
            p99 = $sorted[[int]($sorted.Count * 0.99)]
        }
        is_breaking_point = ($successRate -lt $SuccessRateThreshold) -or ($sorted[[int]($sorted.Count * 0.95)] -gt $LatencyThresholdMs)
    }
}

function Invoke-ConcurrencyStressTest {
    Write-Host "Concurrency Stress Test" -ForegroundColor Cyan
    Write-Host "=======================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Configuration:" -ForegroundColor Yellow
    Write-Host "  Start: $StartConcurrency" -ForegroundColor Gray
    Write-Host "  Max: $MaxConcurrency" -ForegroundColor Gray
    Write-Host "  Step Multiplier: $StepMultiplier" -ForegroundColor Gray
    Write-Host "  Duration per step: ${DurationPerStep}s" -ForegroundColor Gray
    Write-Host "  Success threshold: ${SuccessRateThreshold}%" -ForegroundColor Gray
    Write-Host "  Latency threshold: ${LatencyThresholdMs}ms" -ForegroundColor Gray
    Write-Host ""
    
    $results = @()
    $concurrency = $StartConcurrency
    $breakingPointFound = $false
    
    while ($concurrency -le $MaxConcurrency -and -not $breakingPointFound) {
        Write-Host "Testing concurrency level: $concurrency" -ForegroundColor Yellow
        
        $result = Test-ConcurrencyLevel -Concurrency $concurrency -Duration $DurationPerStep
        $results += $result
        
        Write-Host "  Results:" -ForegroundColor Gray
        Write-Host "    TPS: $($result.tps)" -ForegroundColor Gray
        Write-Host "    Success Rate: $($result.success_rate)%" -ForegroundColor Gray
        Write-Host "    Latency (p95): $($result.latency_ms.p95)ms" -ForegroundColor Gray
        
        if ($result.is_breaking_point) {
            Write-Host "  ⚠️ BREAKING POINT DETECTED" -ForegroundColor Red
            $breakingPointFound = $true
            break
        }
        
        Write-Host "  ✅ Passed" -ForegroundColor Green
        Write-Host ""
        
        # Increase concurrency
        $concurrency = [math]::Floor($concurrency * $StepMultiplier)
        if ($concurrency -gt $MaxConcurrency) { $concurrency = $MaxConcurrency }
    }
    
    # Summary
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Stress Test Summary" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    
    if ($breakingPointFound) {
        $lastGood = $results[-2]
        Write-Host "Breaking Point: $($results[-1].concurrency) concurrent users" -ForegroundColor Red
        Write-Host "Last Stable: $($lastGood.concurrency) concurrent users" -ForegroundColor Yellow
        Write-Host "Max TPS Achieved: $($lastGood.tps)" -ForegroundColor Green
    } else {
        $maxResult = $results | Sort-Object tps -Descending | Select-Object -First 1
        Write-Host "No breaking point found up to $MaxConcurrency users" -ForegroundColor Green
        Write-Host "Max TPS: $($maxResult.tps) at $($maxResult.concurrency) users" -ForegroundColor Green
    }
    
    # Export results
    $outputFile = "benchmarks/reports/concurrency-stress-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
    $results | ConvertTo-Json -Depth 10 | Out-File $outputFile
    Write-Host "`nResults saved to: $outputFile" -ForegroundColor Green
    
    return $results
}

# Run stress test
Invoke-ConcurrencyStressTest
