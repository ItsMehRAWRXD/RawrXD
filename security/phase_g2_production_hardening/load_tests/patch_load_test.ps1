#Requires -Version 7.0
<#
.SYNOPSIS
    Load Testing Framework for RawrXD Hotpatch System

.DESCRIPTION
    Simulates high-volume patch operations to validate system performance under load.

.PARAMETER TestDuration
    Test duration in minutes (default: 10)

.PARAMETER ConcurrentPatches
    Number of concurrent patches to apply (default: 5)

.PARAMETER PatchRate
    Patches per minute (default: 10)

.PARAMETER OutputPath
    Path for test results

.EXAMPLE
    .\patch_load_test.ps1 -TestDuration 30 -ConcurrentPatches 10 -PatchRate 20
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [int]$TestDuration = 10,

    [Parameter(Mandatory = $false)]
    [int]$ConcurrentPatches = 5,

    [Parameter(Mandatory = $false)]
    [int]$PatchRate = 10,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "load_test_results.json"
)

# Test configuration
$script:TestConfig = @{
    StartTime = $null
    EndTime = $null
    TotalPatches = 0
    SuccessfulPatches = 0
    FailedPatches = 0
    Rollbacks = 0
    Latencies = @()
    Throughput = @()
    Errors = @()
}

# Test patch templates
$script:TestPatchTemplates = @(
    @{
        Name = "config_update"
        Type = "configuration"
        Severity = "low"
        Duration = 2
    },
    @{
        Name = "performance_tweak"
        Type = "performance"
        Severity = "medium"
        Duration = 5
    },
    @{
        Name = "security_hotfix"
        Type = "security"
        Severity = "critical"
        Duration = 8
    }
)

function Write-TestLog {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $colors = @{ "INFO" = "White"; "PASS" = "Green"; "FAIL" = "Red"; "WARN" = "Yellow" }
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $colors[$Level]
}

function Initialize-LoadTest {
    Write-TestLog "Initializing load test..." -Level "INFO"
    Write-TestLog "Duration: $TestDuration minutes" -Level "INFO"
    Write-TestLog "Concurrent Patches: $ConcurrentPatches" -Level "INFO"
    Write-TestLog "Patch Rate: $PatchRate per minute" -Level "INFO"

    $script:TestConfig.StartTime = Get-Date
    $script:TestConfig.EndTime = $script:TestConfig.StartTime.AddMinutes($TestDuration)

    # Create test patches directory
    $testPatchesDir = "TestPatches_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    New-Item -ItemType Directory -Path $testPatchesDir -Force | Out-Null

    return $testPatchesDir
}

function New-TestPatch {
    param([string]$OutputDir, [int]$Index)

    $template = $script:TestPatchTemplates | Get-Random
    $patchId = "load-test-$Index-$(Get-Date -Format 'yyyyMMddHHmmss')"

    $patch = @{
        BundleId = $patchId
        Version = "1.0.0"
        Type = $template.Type
        Severity = $template.Severity
        Description = "Load test patch $Index"
        Author = "load-test@rawrxd.ai"
        CreatedAt = Get-Date -Format "o"
        ExpiresAt = (Get-Date).AddHours(1).ToString("o")
        Patches = @(
            @{
                System = @("swarm", "agent", "tools") | Get-Random
                Target = "config"
                PatchFile = "test_patch.json"
                Priority = 1
                RequiresRestart = $false
                BackupRequired = $true
            }
        )
        ExpectedDuration = $template.Duration
    }

    $patchPath = Join-Path $OutputDir "$patchId.json"
    $patch | ConvertTo-Json -Depth 5 | Out-File $patchPath -Encoding UTF8

    return $patchPath
}

function Invoke-PatchOperation {
    param([string]$PatchPath)

    $startTime = Get-Date
    $patch = Get-Content $PatchPath -Raw | ConvertFrom-Json

    # Simulate patch application
    Start-Sleep -Seconds $patch.ExpectedDuration

    # Simulate success/failure (95% success rate)
    $success = (Get-Random -Minimum 1 -Maximum 100) -le 95

    $endTime = Get-Date
    $latency = ($endTime - $startTime).TotalMilliseconds

    $result = @{
        PatchId = $patch.BundleId
        Success = $success
        Latency = $latency
        Timestamp = Get-Date -Format "o"
        Type = $patch.Type
        Severity = $patch.Severity
    }

    return $result
}

function Start-LoadTest {
    param([string]$TestPatchesDir)

    Write-TestLog "Starting load test..." -Level "INFO"

    $patchInterval = [math]::Max(1, [math]::Floor(60 / $PatchRate))
    $patchIndex = 0
    $activeJobs = @()

    while ((Get-Date) -lt $script:TestConfig.EndTime) {
        # Generate new patches up to concurrent limit
        while ($activeJobs.Count -lt $ConcurrentPatches) {
            $patchIndex++
            $patchPath = New-TestPatch -OutputDir $TestPatchesDir -Index $patchIndex

            $job = Start-Job -ScriptBlock {
                param($Path, $Func)
                Invoke-Expression $Func
                Invoke-PatchOperation -PatchPath $Path
            } -ArgumentList $patchPath, ${function:Invoke-PatchOperation}

            $activeJobs += @{
                Job = $job
                PatchPath = $patchPath
                StartTime = Get-Date
            }

            $script:TestConfig.TotalPatches++
        }

        # Check completed jobs
        $completedJobs = @()
        foreach ($activeJob in $activeJobs) {
            if ($activeJob.Job.State -eq "Completed") {
                $result = Receive-Job $activeJob.Job
                Remove-Job $activeJob.Job

                $script:TestConfig.Latencies += $result.Latency

                if ($result.Success) {
                    $script:TestConfig.SuccessfulPatches++
                    Write-TestLog "Patch $($result.PatchId) succeeded ($([math]::Round($result.Latency, 2))ms)" -Level "PASS"
                } else {
                    $script:TestConfig.FailedPatches++
                    $script:TestConfig.Errors += $result
                    Write-TestLog "Patch $($result.PatchId) failed" -Level "FAIL"
                }

                $completedJobs += $activeJob
            }
        }

        # Remove completed jobs from active list
        $activeJobs = $activeJobs | Where-Object { $_ -notin $completedJobs }

        # Calculate current throughput
        $elapsed = ((Get-Date) - $script:TestConfig.StartTime).TotalMinutes
        if ($elapsed -gt 0) {
            $currentThroughput = $script:TestConfig.TotalPatches / $elapsed
            $script:TestConfig.Throughput += $currentThroughput
        }

        Start-Sleep -Seconds $patchInterval
    }

    # Wait for remaining jobs
    Write-TestLog "Waiting for remaining patches to complete..." -Level "INFO"
    $remainingJobs = $activeJobs | Where-Object { $_.Job.State -eq "Running" }
    if ($remainingJobs) {
        Wait-Job $remainingJobs.Job -Timeout 300
    }
}

function Get-LoadTestResults {
    $endTime = Get-Date
    $duration = ($endTime - $script:TestConfig.StartTime).TotalMinutes

    $results = @{
        TestConfig = @{
            Duration = $TestDuration
            ConcurrentPatches = $ConcurrentPatches
            TargetPatchRate = $PatchRate
        }
        Summary = @{
            TotalPatches = $script:TestConfig.TotalPatches
            SuccessfulPatches = $script:TestConfig.SuccessfulPatches
            FailedPatches = $script:TestConfig.FailedPatches
            SuccessRate = if ($script:TestConfig.TotalPatches -gt 0) {
                $script:TestConfig.SuccessfulPatches / $script:TestConfig.TotalPatches
            } else { 0 }
            Duration = $duration
            ActualPatchRate = if ($duration -gt 0) {
                $script:TestConfig.TotalPatches / $duration
            } else { 0 }
        }
        Performance = @{
            AvgLatency = if ($script:TestConfig.Latencies.Count -gt 0) {
                ($script:TestConfig.Latencies | Measure-Object -Average).Average
            } else { 0 }
            MinLatency = if ($script:TestConfig.Latencies.Count -gt 0) {
                ($script:TestConfig.Latencies | Measure-Object -Minimum).Minimum
            } else { 0 }
            MaxLatency = if ($script:TestConfig.Latencies.Count -gt 0) {
                ($script:TestConfig.Latencies | Measure-Object -Maximum).Maximum
            } else { 0 }
            P95Latency = if ($script:TestConfig.Latencies.Count -gt 0) {
                $sorted = $script:TestConfig.Latencies | Sort-Object
                $index = [math]::Floor($sorted.Count * 0.95)
                $sorted[$index]
            } else { 0 }
            P99Latency = if ($script:TestConfig.Latencies.Count -gt 0) {
                $sorted = $script:TestConfig.Latencies | Sort-Object
                $index = [math]::Floor($sorted.Count * 0.99)
                $sorted[$index]
            } else { 0 }
        }
        Throughput = @{
            Average = if ($script:TestConfig.Throughput.Count -gt 0) {
                ($script:TestConfig.Throughput | Measure-Object -Average).Average
            } else { 0 }
            Peak = if ($script:TestConfig.Throughput.Count -gt 0) {
                ($script:TestConfig.Throughput | Measure-Object -Maximum).Maximum
            } else { 0 }
        }
        Errors = $script:TestConfig.Errors
        Timestamp = Get-Date -Format "o"
    }

    return $results
}

function Show-LoadTestReport {
    param([hashtable]$Results)

    Write-Host ""
    Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║                  LOAD TEST RESULTS                               ║" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""

    Write-Host "Configuration:" -ForegroundColor Yellow
    Write-Host "  Duration: $($Results.TestConfig.Duration) minutes"
    Write-Host "  Concurrent Patches: $($Results.TestConfig.ConcurrentPatches)"
    Write-Host "  Target Patch Rate: $($Results.TestConfig.TargetPatchRate) per minute"
    Write-Host ""

    Write-Host "Summary:" -ForegroundColor Yellow
    Write-Host "  Total Patches: $($Results.Summary.TotalPatches)" -ForegroundColor White
    Write-Host "  Successful: $($Results.Summary.SuccessfulPatches)" -ForegroundColor Green
    Write-Host "  Failed: $($Results.Summary.FailedPatches)" -ForegroundColor Red
    Write-Host "  Success Rate: $([math]::Round($Results.Summary.SuccessRate * 100, 2))%" -ForegroundColor $(if ($Results.Summary.SuccessRate -ge 0.95) { "Green" } else { "Red" })
    Write-Host "  Actual Duration: $([math]::Round($Results.Summary.Duration, 2)) minutes"
    Write-Host "  Actual Patch Rate: $([math]::Round($Results.Summary.ActualPatchRate, 2)) per minute"
    Write-Host ""

    Write-Host "Performance:" -ForegroundColor Yellow
    Write-Host "  Avg Latency: $([math]::Round($Results.Performance.AvgLatency, 2)) ms"
    Write-Host "  Min Latency: $([math]::Round($Results.Performance.MinLatency, 2)) ms"
    Write-Host "  Max Latency: $([math]::Round($Results.Performance.MaxLatency, 2)) ms"
    Write-Host "  P95 Latency: $([math]::Round($Results.Performance.P95Latency, 2)) ms"
    Write-Host "  P99 Latency: $([math]::Round($Results.Performance.P99Latency, 2)) ms"
    Write-Host ""

    Write-Host "Throughput:" -ForegroundColor Yellow
    Write-Host "  Average: $([math]::Round($Results.Throughput.Average, 2)) patches/min"
    Write-Host "  Peak: $([math]::Round($Results.Throughput.Peak, 2)) patches/min"
    Write-Host ""

    if ($Results.Errors.Count -gt 0) {
        Write-Host "Errors ($($Results.Errors.Count)):" -ForegroundColor Red
        foreach ($error in $Results.Errors | Select-Object -First 5) {
            Write-Host "  - $($error.PatchId): $($error.Type)" -ForegroundColor Gray
        }
    }

    Write-Host ""

    # Pass/Fail criteria
    $passed = $true
    $criteria = @()

    if ($Results.Summary.SuccessRate -lt 0.95) {
        $passed = $false
        $criteria += "❌ Success rate below 95%"
    } else {
        $criteria += "✅ Success rate >= 95%"
    }

    if ($Results.Performance.P95Latency -gt 10000) {
        $passed = $false
        $criteria += "❌ P95 latency above 10s"
    } else {
        $criteria += "✅ P95 latency <= 10s"
    }

    if ($Results.Throughput.Average -lt $Results.TestConfig.TargetPatchRate * 0.8) {
        $passed = $false
        $criteria += "❌ Throughput below target"
    } else {
        $criteria += "✅ Throughput meets target"
    }

    Write-Host "Pass/Fail Criteria:" -ForegroundColor Yellow
    foreach ($criterion in $criteria) {
        Write-Host "  $criterion"
    }

    Write-Host ""
    if ($passed) {
        Write-Host "✅ LOAD TEST PASSED" -ForegroundColor Green
    } else {
        Write-Host "❌ LOAD TEST FAILED" -ForegroundColor Red
    }
    Write-Host ""
}

# Main execution
Write-Host ""
Write-Host "RawrXD Hotpatch Load Testing Framework" -ForegroundColor Cyan
Write-Host "======================================" -ForegroundColor Cyan
Write-Host ""

$testPatchesDir = Initialize-LoadTest
Start-LoadTest -TestPatchesDir $testPatchesDir
$results = Get-LoadTestResults

# Save results
$results | ConvertTo-Json -Depth 10 | Out-File $OutputPath -Encoding UTF8
Write-TestLog "Results saved to: $OutputPath" -Level "INFO"

# Show report
Show-LoadTestReport -Results $results

# Cleanup
Remove-Item $testPatchesDir -Recurse -Force -ErrorAction SilentlyContinue

# Exit with appropriate code
exit $(if ($results.Summary.SuccessRate -ge 0.95) { 0 } else { 1 })
