# RawrXD Performance Benchmark Runner
# Measures TPS, latency, and resource utilization under various loads

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("Load", "Stress", "Spike", "Soak", "All")]
    [string]$TestType = "All",
    
    [int]$DurationSeconds = 60,
    [int]$WarmupSeconds = 10,
    [int[]]$ConcurrencyLevels = @(1, 5, 10, 25, 50),
    [string]$OutputPath = "benchmarks/reports",
    [switch]$CompareBaseline,
    [string]$BaselinePath,
    [switch]$GenerateReport
)

$ErrorActionPreference = "Stop"

# Configuration
$script:Config = @{
    TestDuration = $DurationSeconds
    WarmupDuration = $WarmupSeconds
    ConcurrencyLevels = $ConcurrencyLevels
    OutputPath = $OutputPath
    MetricsInterval = 1000  # milliseconds
}

# Results storage
$script:Results = @{
    timestamp = Get-Date -Format "o"
    test_type = $TestType
    duration_seconds = $DurationSeconds
    concurrency_levels = $ConcurrencyLevels
    scenarios = @()
    summary = @{}
}

function Initialize-BenchmarkEnvironment {
    Write-Host "Initializing benchmark environment..." -ForegroundColor Cyan
    
    # Create output directory
    if (-not (Test-Path $script:Config.OutputPath)) {
        New-Item -ItemType Directory -Path $script:Config.OutputPath -Force | Out-Null
    }
    
    # Check system resources
    $os = Get-CimInstance Win32_OperatingSystem
    $cpu = Get-CimInstance Win32_Processor
    
    $script:Results.system_info = @{
        os = $os.Caption
        cpu = $cpu.Name
        cpu_cores = $cpu.NumberOfLogicalProcessors
        memory_gb = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
        powershell_version = $PSVersionTable.PSVersion.ToString()
    }
    
    Write-Host "System: $($script:Results.system_info.cpu)" -ForegroundColor Gray
    Write-Host "Memory: $($script:Results.system_info.memory_gb) GB" -ForegroundColor Gray
    Write-Host "Cores: $($script:Results.system_info.cpu_cores)" -ForegroundColor Gray
    Write-Host ""
}

function Measure-Operation {
    param(
        [scriptblock]$Operation,
        [string]$Name,
        [hashtable]$Context = @{}
    )
    
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $success = $false
    $error_message = $null
    
    try {
        $result = & $Operation @Context
        $success = $true
    }
    catch {
        $error_message = $_.Exception.Message
        $success = $false
    }
    
    $sw.Stop()
    
    return @{
        name = $Name
        duration_ms = $sw.ElapsedMilliseconds
        success = $success
        error = $error_message
        timestamp = Get-Date -Format "o"
    }
}

function Invoke-LoadTest {
    param(
        [int]$Concurrency,
        [int]$Duration,
        [string]$Scenario
    )
    
    Write-Host "Running load test: $Scenario (Concurrency: $Concurrency)" -ForegroundColor Yellow
    
    $metrics = @{
        total_requests = 0
        successful_requests = 0
        failed_requests = 0
        latencies = @()
        start_time = Get-Date
        end_time = $null
    }
    
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $cancellationToken = $false
    
    # Warmup phase
    if ($script:Config.WarmupDuration -gt 0) {
        Write-Host "  Warmup phase ($($script:Config.WarmupDuration)s)..." -ForegroundColor Gray
        $warmupEnd = (Get-Date).AddSeconds($script:Config.WarmupDuration)
        while ((Get-Date) -lt $warmupEnd -and -not $cancellationToken) {
            $null = Measure-Operation -Operation {
                & "security/integration/secure_hotpatch.ps1" -Operation status
            } -Name "warmup"
            Start-Sleep -Milliseconds 100
        }
    }
    
    # Main test phase
    Write-Host "  Testing phase (${Duration}s)..." -ForegroundColor Gray
    $testEnd = (Get-Date).AddSeconds($Duration)
    $jobs = @()
    
    for ($i = 0; $i -lt $Concurrency; $i++) {
        $job = Start-Job -ScriptBlock {
            param($Duration, $Config)
            
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
                    & "security/integration/secure_hotpatch.ps1" -Operation status | Out-Null
                    $localMetrics.successes++
                }
                catch {
                    $localMetrics.failures++
                }
                $sw.Stop()
                
                $localMetrics.requests++
                $localMetrics.latencies += $sw.ElapsedMilliseconds
                
                Start-Sleep -Milliseconds (Get-Random -Minimum 50 -Maximum 200)
            }
            
            return $localMetrics
        } -ArgumentList $Duration, $script:Config
        
        $jobs += $job
    }
    
    # Wait for all jobs
    $results = $jobs | Wait-Job | Receive-Job
    $jobs | Remove-Job
    
    # Aggregate results
    foreach ($result in $results) {
        $metrics.total_requests += $result.requests
        $metrics.successful_requests += $result.successes
        $metrics.failed_requests += $result.failures
        $metrics.latencies += $result.latencies
    }
    
    $metrics.end_time = Get-Date
    $stopwatch.Stop()
    
    # Calculate statistics
    $testDuration = ($metrics.end_time - $metrics.start_time).TotalSeconds
    $tps = if ($testDuration -gt 0) { $metrics.total_requests / $testDuration } else { 0 }
    
    $sortedLatencies = $metrics.latencies | Sort-Object
    $latency50 = if ($sortedLatencies.Count -gt 0) { $sortedLatencies[[int]($sortedLatencies.Count * 0.5)] } else { 0 }
    $latency95 = if ($sortedLatencies.Count -gt 0) { $sortedLatencies[[int]($sortedLatencies.Count * 0.95)] } else { 0 }
    $latency99 = if ($sortedLatencies.Count -gt 0) { $sortedLatencies[[int]($sortedLatencies.Count * 0.99)] } else { 0 }
    
    $scenarioResult = @{
        scenario = $Scenario
        concurrency = $Concurrency
        duration_seconds = $testDuration
        total_requests = $metrics.total_requests
        successful_requests = $metrics.successful_requests
        failed_requests = $metrics.failed_requests
        success_rate = if ($metrics.total_requests -gt 0) { ($metrics.successful_requests / $metrics.total_requests) * 100 } else { 0 }
        tps = [math]::Round($tps, 2)
        latency_ms = @{
            min = if ($sortedLatencies.Count -gt 0) { $sortedLatencies[0] } else { 0 }
            max = if ($sortedLatencies.Count -gt 0) { $sortedLatencies[-1] } else { 0 }
            avg = if ($sortedLatencies.Count -gt 0) { [math]::Round(($sortedLatencies | Measure-Object -Average).Average, 2) } else { 0 }
            p50 = $latency50
            p95 = $latency95
            p99 = $latency99
        }
    }
    
    # Display results
    Write-Host "  Results:" -ForegroundColor Green
    Write-Host "    TPS: $($scenarioResult.tps)" -ForegroundColor Gray
    Write-Host "    Success Rate: $([math]::Round($scenarioResult.success_rate, 2))%" -ForegroundColor Gray
    Write-Host "    Latency (p50/p95/p99): $($scenarioResult.latency_ms.p50)ms / $($scenarioResult.latency_ms.p95)ms / $($scenarioResult.latency_ms.p99)ms" -ForegroundColor Gray
    Write-Host ""
    
    return $scenarioResult
}

function Invoke-StressTest {
    param([int]$Duration)
    
    Write-Host "Running stress test (Duration: ${Duration}s)..." -ForegroundColor Yellow
    
    # Gradually increase load until failure or timeout
    $concurrency = 1
    $maxConcurrency = 100
    $results = @()
    
    while ($concurrency -le $maxConcurrency) {
        Write-Host "  Testing with concurrency: $concurrency" -ForegroundColor Gray
        
        $result = Invoke-LoadTest -Concurrency $concurrency -Duration 10 -Scenario "stress-$concurrency"
        $results += $result
        
        # Check if we've hit breaking point
        if ($result.success_rate -lt 95 -or $result.latency_ms.p95 -gt 5000) {
            Write-Host "  Breaking point reached at concurrency: $concurrency" -ForegroundColor Red
            break
        }
        
        $concurrency = [math]::Floor($concurrency * 1.5)
        if ($concurrency -gt $maxConcurrency) { $concurrency = $maxConcurrency }
    }
    
    return $results
}

function Invoke-SpikeTest {
    param([int]$Duration)
    
    Write-Host "Running spike test (Duration: ${Duration}s)..." -ForegroundColor Yellow
    
    # Sudden spike in traffic
    $results = @()
    
    # Normal load
    Write-Host "  Phase 1: Normal load (10s)" -ForegroundColor Gray
    $results += Invoke-LoadTest -Concurrency 5 -Duration 10 -Scenario "spike-normal"
    
    # Spike
    Write-Host "  Phase 2: Spike load (10s)" -ForegroundColor Gray
    $results += Invoke-LoadTest -Concurrency 50 -Duration 10 -Scenario "spike-peak"
    
    # Recovery
    Write-Host "  Phase 3: Recovery (10s)" -ForegroundColor Gray
    $results += Invoke-LoadTest -Concurrency 5 -Duration 10 -Scenario "spike-recovery"
    
    return $results
}

function Invoke-SoakTest {
    param([int]$Duration)
    
    Write-Host "Running soak test (Duration: ${Duration}s)..." -ForegroundColor Yellow
    
    # Extended duration test
    return Invoke-LoadTest -Concurrency 10 -Duration $Duration -Scenario "soak"
}

function Save-BenchmarkResults {
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $outputFile = "$($script:Config.OutputPath)/benchmark-$timestamp.json"
    
    $script:Results | ConvertTo-Json -Depth 10 | Out-File $outputFile
    Write-Host "Results saved to: $outputFile" -ForegroundColor Green
    
    return $outputFile
}

function Show-BenchmarkSummary {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Benchmark Summary" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    
    foreach ($scenario in $script:Results.scenarios) {
        Write-Host "`nScenario: $($scenario.scenario)" -ForegroundColor Yellow
        Write-Host "  Concurrency: $($scenario.concurrency)" -ForegroundColor White
        Write-Host "  TPS: $($scenario.tps)" -ForegroundColor White
        Write-Host "  Success Rate: $([math]::Round($scenario.success_rate, 2))%" -ForegroundColor White
        Write-Host "  Latency (p50/p95/p99): $($scenario.latency_ms.p50)ms / $($scenario.latency_ms.p95)ms / $($scenario.latency_ms.p99)ms" -ForegroundColor White
    }
    
    # Find best TPS
    $bestTps = ($script:Results.scenarios | Sort-Object tps -Descending | Select-Object -First 1)
    if ($bestTps) {
        Write-Host "`nBest TPS: $($bestTps.tps) (Concurrency: $($bestTps.concurrency))" -ForegroundColor Green
    }
}

function Compare-WithBaseline {
    param([string]$CurrentResults, [string]$BaselinePath)
    
    if (-not (Test-Path $BaselinePath)) {
        Write-Warning "Baseline not found: $BaselinePath"
        return
    }
    
    $baseline = Get-Content $BaselinePath | ConvertFrom-Json
    $current = Get-Content $CurrentResults | ConvertFrom-Json
    
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Comparison with Baseline" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    
    # Compare TPS
    $baselineTps = ($baseline.scenarios | Measure-Object tps -Average).Average
    $currentTps = ($current.scenarios | Measure-Object tps -Average).Average
    $tpsChange = if ($baselineTps -gt 0) { (($currentTps - $baselineTps) / $baselineTps) * 100 } else { 0 }
    
    $color = if ($tpsChange -ge 0) { "Green" } else { "Red" }
    Write-Host "TPS Change: $([math]::Round($tpsChange, 2))%" -ForegroundColor $color
    
    # Compare latency
    $baselineLatency = ($baseline.scenarios.latency_ms.p95 | Measure-Object -Average).Average
    $currentLatency = ($current.scenarios.latency_ms.p95 | Measure-Object -Average).Average
    $latencyChange = if ($baselineLatency -gt 0) { (($currentLatency - $baselineLatency) / $baselineLatency) * 100 } else { 0 }
    
    $color = if ($latencyChange -le 0) { "Green" } else { "Red" }
    Write-Host "Latency (p95) Change: $([math]::Round($latencyChange, 2))%" -ForegroundColor $color
}

# Main execution
function Invoke-BenchmarkRunner {
    Write-Host "RawrXD Performance Benchmark" -ForegroundColor Cyan
    Write-Host "============================" -ForegroundColor Cyan
    Write-Host ""
    
    Initialize-BenchmarkEnvironment
    
    switch ($TestType) {
        "Load" {
            foreach ($concurrency in $script:Config.ConcurrencyLevels) {
                $result = Invoke-LoadTest -Concurrency $concurrency -Duration $script:Config.TestDuration -Scenario "load-$concurrency"
                $script:Results.scenarios += $result
            }
        }
        "Stress" {
            $script:Results.scenarios = Invoke-StressTest -Duration $script:Config.TestDuration
        }
        "Spike" {
            $script:Results.scenarios = Invoke-SpikeTest -Duration $script:Config.TestDuration
        }
        "Soak" {
            $result = Invoke-SoakTest -Duration $script:Config.TestDuration
            $script:Results.scenarios += $result
        }
        "All" {
            # Run all test types
            foreach ($concurrency in $script:Config.ConcurrencyLevels) {
                $result = Invoke-LoadTest -Concurrency $concurrency -Duration 30 -Scenario "load-$concurrency"
                $script:Results.scenarios += $result
            }
            
            $script:Results.scenarios += Invoke-StressTest -Duration 60
            $script:Results.scenarios += Invoke-SpikeTest -Duration 30
        }
    }
    
    # Save results
    $resultsFile = Save-BenchmarkResults
    
    # Show summary
    Show-BenchmarkSummary
    
    # Compare with baseline if requested
    if ($CompareBaseline -and $BaselinePath) {
        Compare-WithBaseline -CurrentResults $resultsFile -BaselinePath $BaselinePath
    }
    
    Write-Host "`nBenchmark complete!" -ForegroundColor Green
}

# Run benchmarks
Invoke-BenchmarkRunner
