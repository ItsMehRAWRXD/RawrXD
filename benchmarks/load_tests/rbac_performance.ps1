# RBAC Performance Benchmark
# Measures RBAC operations under load

param(
    [int]$Iterations = 1000,
    [int[]]$ConcurrentUsers = @(1, 5, 10, 25),
    [switch]$ExportResults
)

$RBACManagerPath = "security/phase_h_enterprise_security/rbac/rbac_manager.ps1"

function Measure-RBACOperation {
    param(
        [string]$Operation,
        [hashtable]$Parameters,
        [int]$Count = 100
    )
    
    $latencies = @()
    $successes = 0
    $failures = 0
    
    for ($i = 0; $i -lt $Count; $i++) {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        
        try {
            $result = & $RBACManagerPath @Parameters
            $successes++
        }
        catch {
            $failures++
        }
        
        $sw.Stop()
        $latencies += $sw.ElapsedMilliseconds
    }
    
    $sorted = $latencies | Sort-Object
    
    return @{
        operation = $Operation
        count = $Count
        successes = $successes
        failures = $failures
        latency_ms = @{
            min = $sorted[0]
            max = $sorted[-1]
            avg = [math]::Round(($latencies | Measure-Object -Average).Average, 2)
            p50 = $sorted[[int]($sorted.Count * 0.5)]
            p95 = $sorted[[int]($sorted.Count * 0.95)]
            p99 = $sorted[[int]($sorted.Count * 0.99)]
        }
        throughput = [math]::Round($Count / (($latencies | Measure-Object -Sum).Sum / 1000), 2)
    }
}

function Invoke-RBACPerformanceTest {
    Write-Host "RBAC Performance Benchmark" -ForegroundColor Cyan
    Write-Host "==========================" -ForegroundColor Cyan
    Write-Host ""
    
    $results = @{
        timestamp = Get-Date -Format "o"
        iterations = $Iterations
        tests = @()
    }
    
    # Test 1: Permission Check
    Write-Host "Testing: Permission Check" -ForegroundColor Yellow
    $result = Measure-RBACOperation -Operation "check_permission" -Parameters @{
        Operation = "check_permission"
        UserId = "test-admin"
        PermissionName = "patch:apply"
    } -Count $Iterations
    $results.tests += $result
    Write-Host "  Avg: $($result.latency_ms.avg)ms, p95: $($result.latency_ms.p95)ms, Throughput: $($result.throughput) ops/sec" -ForegroundColor Gray
    
    # Test 2: Role Lookup
    Write-Host "Testing: Role Lookup" -ForegroundColor Yellow
    $result = Measure-RBACOperation -Operation "get_role" -Parameters @{
        Operation = "get_role"
        RoleName = "super-admin"
    } -Count $Iterations
    $results.tests += $result
    Write-Host "  Avg: $($result.latency_ms.avg)ms, p95: $($result.latency_ms.p95)ms, Throughput: $($result.throughput) ops/sec" -ForegroundColor Gray
    
    # Test 3: List Roles
    Write-Host "Testing: List Roles" -ForegroundColor Yellow
    $result = Measure-RBACOperation -Operation "list" -Parameters @{
        Operation = "list"
    } -Count ($Iterations / 10)  # Slower operation
    $results.tests += $result
    Write-Host "  Avg: $($result.latency_ms.avg)ms, p95: $($result.latency_ms.p95)ms, Throughput: $($result.throughput) ops/sec" -ForegroundColor Gray
    
    # Concurrent load test
    Write-Host "`nConcurrent Load Tests" -ForegroundColor Cyan
    foreach ($users in $ConcurrentUsers) {
        Write-Host "Testing with $users concurrent users..." -ForegroundColor Yellow
        
        $jobs = @()
        for ($i = 0; $i -lt $users; $i++) {
            $jobs += Start-Job -ScriptBlock {
                param($Path, $Count)
                $latencies = @()
                for ($j = 0; $j -lt $Count; $j++) {
                    $sw = [System.Diagnostics.Stopwatch]::StartNew()
                    & $Path -Operation "check_permission" -UserId "test-user-$j" -PermissionName "patch:view" | Out-Null
                    $sw.Stop()
                    $latencies += $sw.ElapsedMilliseconds
                }
                return $latencies
            } -ArgumentList $RBACManagerPath, ($Iterations / $users)
        }
        
        $allLatencies = @()
        $jobResults = $jobs | Wait-Job | Receive-Job
        foreach ($jobResult in $jobResults) {
            $allLatencies += $jobResult
        }
        $jobs | Remove-Job
        
        $sorted = $allLatencies | Sort-Object
        $totalOps = $users * ($Iterations / $users)
        $duration = ($allLatencies | Measure-Object -Sum).Sum / 1000
        $tps = if ($duration -gt 0) { $totalOps / $duration } else { 0 }
        
        Write-Host "  Total Ops: $totalOps, TPS: $([math]::Round($tps, 2)), p95 Latency: $($sorted[[int]($sorted.Count * 0.95)])ms" -ForegroundColor Gray
        
        $results.tests += @{
            operation = "concurrent_check_permission"
            concurrent_users = $users
            total_operations = $totalOps
            tps = [math]::Round($tps, 2)
            latency_ms = @{
                p50 = $sorted[[int]($sorted.Count * 0.5)]
                p95 = $sorted[[int]($sorted.Count * 0.95)]
                p99 = $sorted[[int]($sorted.Count * 0.99)]
            }
        }
    }
    
    # Export results
    if ($ExportResults) {
        $outputFile = "benchmarks/reports/rbac-performance-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
        $results | ConvertTo-Json -Depth 10 | Out-File $outputFile
        Write-Host "`nResults exported to: $outputFile" -ForegroundColor Green
    }
    
    # Summary
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "RBAC Performance Summary" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    
    $avgThroughput = ($results.tests | Where-Object { $_.throughput } | Measure-Object throughput -Average).Average
    Write-Host "Average Throughput: $([math]::Round($avgThroughput, 2)) ops/sec" -ForegroundColor White
    
    return $results
}

# Run benchmark
Invoke-RBACPerformanceTest
