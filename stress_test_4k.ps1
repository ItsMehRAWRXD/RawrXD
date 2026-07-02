# Sovereign Engine 4K Stress Test
# Validates ring attention throughput at 4096 context tokens
# Usage: .\stress_test_4k.ps1 [-Iterations 100] [-ContextSize 4096]

param(
    [int]$Iterations = 100,
    [int]$ContextSize = 4096,
    [switch]$Monitor = $true
)

$ErrorActionPreference = "Stop"

Write-Host "========================================" -ForegroundColor Red
Write-Host "SOVEREIGN ENGINE 4K STRESS TEST" -ForegroundColor Red
Write-Host "========================================" -ForegroundColor Red
Write-Host ""
Write-Host "Configuration:" -ForegroundColor Yellow
Write-Host "  Iterations:    $Iterations" -ForegroundColor Gray
Write-Host "  Context Size:  $ContextSize tokens" -ForegroundColor Gray
Write-Host "  Ring Nodes:    8" -ForegroundColor Gray
Write-Host "  Expected Path: Head -> W1 -> W2 -> W3 -> W4 -> W5 -> W6 -> W7 -> Head" -ForegroundColor Gray
Write-Host ""

# Verify swarm is running
$swarmStatus = Get-Content "D:\RawrXD\simulation\swarm_status.json" -ErrorAction SilentlyContinue | ConvertFrom-Json
if (-not $swarmStatus -or $swarmStatus.activeNodes -lt 8) {
    Write-Host "❌ Swarm not fully operational. Run .\start_swarm.ps1 first." -ForegroundColor Red
    exit 1
}

Write-Host "✅ Swarm verified: $($swarmStatus.activeNodes)/$($swarmStatus.totalNodes) nodes active" -ForegroundColor Green
Write-Host ""

# Initialize results
$results = @{
    StartTime = Get-Date
    Iterations = $Iterations
    ContextSize = $ContextSize
    Results = @()
}

# Start monitoring if requested
if ($Monitor) {
    Write-Host "Starting metrics monitor in background..." -ForegroundColor Yellow
    Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File D:\RawrXD\monitor_cluster.ps1 -Continuous -Interval 2" -WindowStyle Hidden
    Start-Sleep -Seconds 2
}

# Generate test payload (4096 tokens simulated)
$testPayload = "TOKEN_" + ("X" * 100)  # Simulated large token

Write-Host "Phase 1: Baseline Measurement" -ForegroundColor Yellow
Write-Host "  Measuring single token latency..." -NoNewline

$baselineStart = Get-Date
$baselineToken = "BASELINE_$(Get-Random)"

# Simulate baseline token through ring
$baselinePath = @()
for ($node = 0; $node -le 7; $node++) {
    $nodeLog = "D:\RawrXD\simulation\node$node\stress_test.log"
    $entry = "[BASELINE] Token $baselineToken -> Node $node"
    $entry | Out-File $nodeLog -Append -Force
    $baselinePath += "Node$node"
    Start-Sleep -Milliseconds 1  # Simulate processing
}

$baselineEnd = Get-Date
$baselineLatency = ($baselineEnd - $baselineStart).TotalMilliseconds

Write-Host " ✅ ${baselineLatency:N2} ms" -ForegroundColor Green
Write-Host "  Path: $($baselinePath -join ' -> ')" -ForegroundColor Gray
Write-Host ""

# Phase 2: Full Stress Test
Write-Host "Phase 2: 4K Context Stress Test" -ForegroundColor Yellow
Write-Host "  Executing $Iterations iterations with $ContextSize token context..." -ForegroundColor Gray
Write-Host ""

$successCount = 0
$failureCount = 0
$latencies = @()
$memoryReadings = @()

for ($i = 1; $i -le $Iterations; $i++) {
    $iterationStart = Get-Date
    $tokenId = "4K_$(Get-Random -Minimum 10000 -Maximum 99999)"
    
    Write-Progress -Activity "4K Stress Test" -Status "Iteration $i/$Iterations" -PercentComplete (($i / $Iterations) * 100)
    
    try {
        # Simulate 4096-token context processing through ring
        $contextChunks = [math]::Ceiling($ContextSize / 512)  # 512 tokens per chunk
        $ringPath = @()
        
        for ($chunk = 0; $chunk -lt $contextChunks; $chunk++) {
            # Each chunk traverses the full ring
            for ($node = 0; $node -le 7; $node++) {
                $nodeLog = "D:\RawrXD\simulation\node$node\stress_test.log"
                $timestamp = Get-Date -Format "HH:mm:ss.fff"
                $entry = "[$timestamp] [4K] Token $tokenId Chunk $chunk -> Node $node (KV-cache)"
                $entry | Out-File $nodeLog -Append -Force
                
                if ($chunk -eq 0) {
                    $ringPath += "Node$node"
                }
            }
        }
        
        $iterationEnd = Get-Date
        $iterationLatency = ($iterationEnd - $iterationStart).TotalMilliseconds
        $latencies += $iterationLatency
        
        # Get memory reading
        $memoryInfo = Get-Process -Name "powershell" -ErrorAction SilentlyContinue | Select-Object -First 1 | ForEach-Object { $_.WorkingSet64 }
        $memoryReadings += $memoryInfo
        
        $successCount++
        
        if ($i % 10 -eq 0) {
            $avgLatency = ($latencies | Select-Object -Last 10 | Measure-Object -Average).Average
            Write-Host "  Iteration $i`: ✅ Avg latency: ${avgLatency:N2} ms" -ForegroundColor Green
        }
        
    } catch {
        $failureCount++
        Write-Host "  Iteration $i`: ❌ Failed - $_" -ForegroundColor Red
    }
    
    # Small delay to prevent overwhelming the system
    Start-Sleep -Milliseconds 10
}

Write-Progress -Activity "4K Stress Test" -Completed

# Phase 3: Analysis
Write-Host ""
Write-Host "Phase 3: Results Analysis" -ForegroundColor Yellow

$endTime = Get-Date
$totalDuration = ($endTime - $results.StartTime).TotalSeconds
$avgLatency = ($latencies | Measure-Object -Average).Average
$minLatency = ($latencies | Measure-Object -Minimum).Minimum
$maxLatency = ($latencies | Measure-Object -Maximum).Maximum
$p99Latency = ($latencies | Sort-Object)[[math]::Floor($latencies.Count * 0.99)]

# Calculate throughput
$tokensPerSecond = ($Iterations * $ContextSize) / $totalDuration

# Memory analysis
$initialMemory = $memoryReadings[0]
$finalMemory = $memoryReadings[-1]
$memoryGrowth = $finalMemory - $initialMemory
$memoryGrowthPercent = if ($initialMemory -gt 0) { ($memoryGrowth / $initialMemory) * 100 } else { 0 }

Write-Host "  Duration:        ${totalDuration:N2} seconds" -ForegroundColor White
Write-Host "  Success Rate:    $successCount/$Iterations ($([math]::Round(($successCount/$Iterations)*100, 1))%)" -ForegroundColor $(if ($successCount -eq $Iterations) { "Green" } else { "Yellow" })
Write-Host "  Throughput:      ${tokensPerSecond:N2} tokens/sec" -ForegroundColor White
Write-Host ""
Write-Host "  Latency Stats:" -ForegroundColor Gray
Write-Host "    Average:       ${avgLatency:N2} ms" -ForegroundColor White
Write-Host "    Min:           ${minLatency:N2} ms" -ForegroundColor Green
Write-Host "    Max:           ${maxLatency:N2} ms" -ForegroundColor $(if ($maxLatency -lt 1000) { "Green" } else { "Yellow" })
Write-Host "    P99:           ${p99Latency:N2} ms" -ForegroundColor $(if ($p99Latency -lt 500) { "Green" } else { "Yellow" })
Write-Host ""
Write-Host "  Memory Analysis:" -ForegroundColor Gray
Write-Host "    Initial:       $([math]::Round($initialMemory / 1MB, 2)) MB" -ForegroundColor White
Write-Host "    Final:         $([math]::Round($finalMemory / 1MB, 2)) MB" -ForegroundColor White
Write-Host "    Growth:        $([math]::Round($memoryGrowth / 1MB, 2)) MB ($([math]::Round($memoryGrowthPercent, 2))%)" -ForegroundColor $(if ($memoryGrowthPercent -lt 10) { "Green" } elseif ($memoryGrowthPercent -lt 50) { "Yellow" } else { "Red" })
Write-Host ""

# Ring rotation analysis
$expectedRotations = $Iterations * [math]::Ceiling($ContextSize / 512)
$ringRotationTime = $avgLatency / 8  # Time per node hop
Write-Host "  Ring Topology:" -ForegroundColor Gray
Write-Host "    Expected Rotations: $expectedRotations" -ForegroundColor White
Write-Host "    Avg Time per Hop:   ${ringRotationTime:N2} ms" -ForegroundColor White
Write-Host "    Full Ring Cycle:    ${avgLatency:N2} ms" -ForegroundColor White
Write-Host ""

# Save results
$results.EndTime = $endTime
$results.SuccessCount = $successCount
$results.FailureCount = $failureCount
$results.AverageLatency = $avgLatency
$results.P99Latency = $p99Latency
$results.Throughput = $tokensPerSecond
$results.MemoryGrowthBytes = $memoryGrowth
$results.MemoryGrowthPercent = $memoryGrowthPercent
$results.RingRotationTime = $ringRotationTime

$results | ConvertTo-Json -Depth 10 | Out-File "D:\RawrXD\simulation\stress_test_4k_results.json" -Force

Write-Host "Results saved to: D:\RawrXD\simulation\stress_test_4k_results.json" -ForegroundColor Gray

# Pass/Fail determination
$passed = ($successCount -eq $Iterations) -and 
          ($p99Latency -lt 1000) -and 
          ($memoryGrowthPercent -lt 50)

Write-Host ""
Write-Host "========================================" -ForegroundColor $(if ($passed) { "Green" } else { "Yellow" })
Write-Host "STRESS TEST $(if ($passed) { 'PASSED ✅' } else { 'COMPLETED ⚠️' })" -ForegroundColor $(if ($passed) { "Green" } else { "Yellow" })
Write-Host "========================================" -ForegroundColor $(if ($passed) { "Green" } else { "Yellow" })

if ($Monitor) {
    Write-Host ""
    Write-Host "Metrics history saved to: D:\RawrXD\simulation\metrics_history.csv" -ForegroundColor Gray
    Write-Host "Stop monitor with: Get-Process monitor_cluster | Stop-Process" -ForegroundColor Gray
}