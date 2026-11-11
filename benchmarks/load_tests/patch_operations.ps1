# Patch Operations Performance Benchmark
# Measures patch apply/rollback/dryrun performance

param(
    [int]$Iterations = 100,
    [switch]$IncludeDryRun,
    [switch]$IncludeApply,
    [switch]$ExportResults
)

$SecureHotpatchPath = "security/integration/secure_hotpatch.ps1"

# Create test patches of various sizes
function New-TestPatch {
    param([int]$ComponentCount = 1, [int]$FileCount = 1)
    
    $components = @()
    for ($i = 0; $i -lt $ComponentCount; $i++) {
        $components += "component-$i"
    }
    
    $files = @()
    for ($i = 0; $i -lt $FileCount; $i++) {
        $files += @{
            path = "test/file-$i.txt"
            checksum = (Get-Random -Minimum 1000000000 -Maximum 9999999999).ToString()
            content = "dGVzdA=="  # "test" base64
        }
    }
    
    return @{
        patch_id = "perf-test-$(New-Guid)"
        version = "1.0.0"
        system_type = "swarm"
        components = $components
        files = $files
        security = @{
            signature = "test-sig"
            approved_by = @("admin")
        }
    }
}

function Measure-PatchOperation {
    param(
        [string]$Operation,
        [string]$PatchPath,
        [int]$Count = 10
    )
    
    $latencies = @()
    $successes = 0
    $failures = 0
    
    for ($i = 0; $i -lt $Count; $i++) {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        
        try {
            $result = & $SecureHotpatchPath -SystemType "swarm" -Operation $Operation -PatchPath $PatchPath
            $successes++
        }
        catch {
            $failures++
        }
        
        $sw.Stop()
        $latencies += $sw.ElapsedMilliseconds
        
        # Small delay between operations
        Start-Sleep -Milliseconds 10
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
    }
}

function Invoke-PatchPerformanceTest {
    Write-Host "Patch Operations Performance Benchmark" -ForegroundColor Cyan
    Write-Host "=======================================" -ForegroundColor Cyan
    Write-Host ""
    
    $results = @{
        timestamp = Get-Date -Format "o"
        iterations = $Iterations
        tests = @()
    }
    
    # Test different patch sizes
    $patchSizes = @(
        @{ Components = 1; Files = 1; Name = "small" }
        @{ Components = 5; Files = 10; Name = "medium" }
        @{ Components = 10; Files = 25; Name = "large" }
    )
    
    foreach ($size in $patchSizes) {
        Write-Host "Testing patch size: $($size.Name) ($($size.Components) components, $($size.Files) files)" -ForegroundColor Yellow
        
        # Create test patch
        $patch = New-TestPatch -ComponentCount $size.Components -FileCount $size.Files
        $patchPath = "benchmarks/temp-$($size.Name)-patch.json"
        $patch | ConvertTo-Json -Depth 10 | Out-File $patchPath
        
        # Test dry-run
        if ($IncludeDryRun) {
            Write-Host "  Testing: dryrun" -ForegroundColor Gray
            $result = Measure-PatchOperation -Operation "dryrun" -PatchPath $patchPath -Count $Iterations
            $result.patch_size = $size.Name
            $results.tests += $result
            Write-Host "    Avg: $($result.latency_ms.avg)ms, p95: $($result.latency_ms.p95)ms" -ForegroundColor Gray
        }
        
        # Test status check (lightweight)
        Write-Host "  Testing: status" -ForegroundColor Gray
        $result = Measure-PatchOperation -Operation "status" -PatchPath $patchPath -Count ($Iterations * 5)
        $result.patch_size = $size.Name
        $results.tests += $result
        Write-Host "    Avg: $($result.latency_ms.avg)ms, p95: $($result.latency_ms.p95)ms" -ForegroundColor Gray
        
        # Cleanup
        Remove-Item $patchPath -ErrorAction SilentlyContinue
    }
    
    # Test list operations
    Write-Host "`nTesting: list patches" -ForegroundColor Yellow
    $latencies = @()
    for ($i = 0; $i -lt $Iterations; $i++) {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        & $SecureHotpatchPath -SystemType "swarm" -Operation "list" | Out-Null
        $sw.Stop()
        $latencies += $sw.ElapsedMilliseconds
    }
    
    $sorted = $latencies | Sort-Object
    $results.tests += @{
        operation = "list"
        count = $Iterations
        latency_ms = @{
            avg = [math]::Round(($latencies | Measure-Object -Average).Average, 2)
            p50 = $sorted[[int]($sorted.Count * 0.5)]
            p95 = $sorted[[int]($sorted.Count * 0.95)]
        }
    }
    Write-Host "  Avg: $([math]::Round(($latencies | Measure-Object -Average).Average, 2))ms, p95: $($sorted[[int]($sorted.Count * 0.95)])ms" -ForegroundColor Gray
    
    # Export results
    if ($ExportResults) {
        $outputFile = "benchmarks/reports/patch-operations-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
        $results | ConvertTo-Json -Depth 10 | Out-File $outputFile
        Write-Host "`nResults exported to: $outputFile" -ForegroundColor Green
    }
    
    # Summary
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Patch Operations Summary" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    
    $avgLatency = ($results.tests.latency_ms.avg | Measure-Object -Average).Average
    Write-Host "Average Latency: $([math]::Round($avgLatency, 2))ms" -ForegroundColor White
    
    return $results
}

# Run benchmark
Invoke-PatchPerformanceTest
