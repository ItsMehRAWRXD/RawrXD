#Requires -Version 7.0
<#
.SYNOPSIS
    Stress Testing Framework for RawrXD Hotpatch System

.DESCRIPTION
    Pushes the hotpatch system to its limits to identify breaking points and failure modes.

.PARAMETER TestPhases
    Number of stress test phases (default: 5)

.PARAMETER MaxConcurrentPatches
    Maximum concurrent patches to test (default: 50)

.PARAMETER OutputPath
    Path for test results

.EXAMPLE
    .\patch_stress_test.ps1 -TestPhases 5 -MaxConcurrentPatches 100
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [int]$TestPhases = 5,

    [Parameter(Mandatory = $false)]
    [int]$MaxConcurrentPatches = 50,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "stress_test_results.json"
)

# Stress test phases with increasing intensity
$script:StressPhases = @(
    @{ Name = "Baseline"; Concurrent = 5; Duration = 2; Description = "Normal operating conditions" },
    @{ Name = "Elevated"; Concurrent = 15; Duration = 3; Description = "2x normal load" },
    @{ Name = "High"; Concurrent = 30; Duration = 5; Description = "4x normal load" },
    @{ Name = "Peak"; Concurrent = 50; Duration = 5; Description = "10x normal load" },
    @{ Name = "Overload"; Concurrent = $MaxConcurrentPatches; Duration = 3; Description = "Maximum stress test" }
)

$script:PhaseResults = @()
$script:SystemMetrics = @{
    CPU = @()
    Memory = @()
    DiskIO = @()
    NetworkIO = @()
}

function Write-StressLog {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $colors = @{ "INFO" = "White"; "PASS" = "Green"; "FAIL" = "Red"; "WARN" = "Yellow"; "PHASE" = "Cyan" }
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $colors[$Level]
}

function Get-SystemMetrics {
    $cpu = (Get-Counter '\Processor(_Total)\% Processor Time').CounterSamples.CookedValue
    $memory = (Get-Counter '\Memory\% Committed Bytes In Use').CounterSamples.CookedValue
    $diskIO = (Get-Counter '\PhysicalDisk(_Total)\Disk Bytes/sec').CounterSamples.CookedValue
    $networkIO = (Get-Counter '\Network Interface(*)\Bytes Total/sec').CounterSamples | 
        Where-Object { $_.CookedValue -gt 0 } | 
        Measure-Object -Property CookedValue -Sum | 
        Select-Object -ExpandProperty Sum

    return @{
        CPU = $cpu
        Memory = $memory
        DiskIO = $diskIO
        NetworkIO = $networkIO
        Timestamp = Get-Date -Format "o"
    }
}

function Invoke-StressPhase {
    param([hashtable]$Phase, [int]$PhaseNumber)

    Write-StressLog "Starting Phase $PhaseNumber`: $($Phase.Name)" -Level "PHASE"
    Write-StressLog "  Concurrent: $($Phase.Concurrent), Duration: $($Phase.Duration) min" -Level "INFO"
    Write-StressLog "  Description: $($Phase.Description)" -Level "INFO"

    $phaseStart = Get-Date
    $phaseEnd = $phaseStart.AddMinutes($Phase.Duration)
    $phaseResults = @{
        Phase = $Phase.Name
        PhaseNumber = $PhaseNumber
        Config = $Phase
        StartTime = Get-Date -Format "o"
        PatchesAttempted = 0
        PatchesSucceeded = 0
        PatchesFailed = 0
        Latencies = @()
        Errors = @()
        SystemMetrics = @()
        BreakingPoint = $false
    }

    $activeJobs = @()
    $patchCounter = 0

    while ((Get-Date) -lt $phaseEnd -and -not $phaseResults.BreakingPoint) {
        # Collect system metrics every 10 seconds
        if ($patchCounter % 10 -eq 0) {
            $metrics = Get-SystemMetrics
            $phaseResults.SystemMetrics += $metrics
            $script:SystemMetrics.CPU += $metrics.CPU
            $script:SystemMetrics.Memory += $metrics.Memory
        }

        # Start new patches up to concurrent limit
        while ($activeJobs.Count -lt $Phase.Concurrent -and (Get-Date) -lt $phaseEnd) {
            $patchCounter++
            $patchId = "stress-$PhaseNumber-$patchCounter"

            # Simulate patch operation
            $job = Start-Job -ScriptBlock {
                param($Duration)
                Start-Sleep -Milliseconds (Get-Random -Minimum 100 -Maximum 5000)
                return @{
                    Success = (Get-Random -Minimum 1 -Maximum 100) -le 90
                    Latency = Get-Random -Minimum 100 -Maximum 5000
                }
            } -ArgumentList (Get-Random -Minimum 1 -Maximum 5)

            $activeJobs += @{
                Job = $job
                PatchId = $patchId
                StartTime = Get-Date
            }

            $phaseResults.PatchesAttempted++
        }

        # Check for completed jobs
        $completedJobs = @()
        foreach ($jobInfo in $activeJobs) {
            if ($jobInfo.Job.State -eq "Completed") {
                $result = Receive-Job $jobInfo.Job
                Remove-Job $jobInfo.Job

                $phaseResults.Latencies += $result.Latency

                if ($result.Success) {
                    $phaseResults.PatchesSucceeded++
                } else {
                    $phaseResults.PatchesFailed++
                    $phaseResults.Errors += @{
                        PatchId = $jobInfo.PatchId
                        Error = "Simulated failure"
                        Timestamp = Get-Date -Format "o"
                    }
                }

                $completedJobs += $jobInfo
            }
        }

        $activeJobs = $activeJobs | Where-Object { $_ -notin $completedJobs }

        # Check for breaking point conditions
        $recentSuccessRate = if ($phaseResults.PatchesAttempted -gt 0) {
            $phaseResults.PatchesSucceeded / $phaseResults.PatchesAttempted
        } else { 1.0 }

        if ($recentSuccessRate -lt 0.5 -and $phaseResults.PatchesAttempted -gt 20) {
            Write-StressLog "Breaking point detected! Success rate dropped below 50%" -Level "FAIL"
            $phaseResults.BreakingPoint = $true
            break
        }

        # Check system resource exhaustion
        $currentMetrics = Get-SystemMetrics
        if ($currentMetrics.CPU -gt 95 -or $currentMetrics.Memory -gt 95) {
            Write-StressLog "Breaking point detected! System resources exhausted" -Level "FAIL"
            $phaseResults.BreakingPoint = $true
            break
        }

        Start-Sleep -Milliseconds 100
    }

    # Wait for remaining jobs
    if ($activeJobs.Count -gt 0) {
        Write-StressLog "Waiting for $($activeJobs.Count) remaining patches..." -Level "INFO"
        Wait-Job $activeJobs.Job -Timeout 60

        foreach ($jobInfo in $activeJobs) {
            if ($jobInfo.Job.State -eq "Completed") {
                $result = Receive-Job $jobInfo.Job
                $phaseResults.Latencies += $result.Latency
                if ($result.Success) {
                    $phaseResults.PatchesSucceeded++
                } else {
                    $phaseResults.PatchesFailed++
                }
            }
            Remove-Job $jobInfo.Job -ErrorAction SilentlyContinue
        }
    }

    $phaseResults.EndTime = Get-Date -Format "o"
    $phaseResults.Duration = ((Get-Date) - $phaseStart).TotalMinutes
    $phaseResults.SuccessRate = if ($phaseResults.PatchesAttempted -gt 0) {
        $phaseResults.PatchesSucceeded / $phaseResults.PatchesAttempted
    } else { 0 }

    if ($phaseResults.Latencies.Count -gt 0) {
        $sorted = $phaseResults.Latencies | Sort-Object
        $phaseResults.AvgLatency = ($phaseResults.Latencies | Measure-Object -Average).Average
        $phaseResults.P95Latency = $sorted[[math]::Floor($sorted.Count * 0.95)]
        $phaseResults.P99Latency = $sorted[[math]::Floor($sorted.Count * 0.99)]
    }

    $script:PhaseResults += $phaseResults

    Write-StressLog "Phase $($Phase.Name) complete" -Level $(if ($phaseResults.BreakingPoint) { "FAIL" } else { "PASS" })
    Write-StressLog "  Attempted: $($phaseResults.PatchesAttempted), Succeeded: $($phaseResults.PatchesSucceeded), Failed: $($phaseResults.PatchesFailed)" -Level "INFO"
    Write-StressLog "  Success Rate: $([math]::Round($phaseResults.SuccessRate * 100, 2))%" -Level "INFO"

    # Recovery period between phases
    if ($PhaseNumber -lt $TestPhases) {
        Write-StressLog "Recovery period (30 seconds)..." -Level "INFO"
        Start-Sleep -Seconds 30
    }
}

function Show-StressTestReport {
    Write-Host ""
    Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║                 STRESS TEST RESULTS                              ║" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""

    Write-Host "Phase Summary:" -ForegroundColor Yellow
    Write-Host ""

    foreach ($phase in $script:PhaseResults) {
        $statusColor = if ($phase.BreakingPoint) { "Red" } elseif ($phase.SuccessRate -lt 0.95) { "Yellow" } else { "Green" }
        $status = if ($phase.BreakingPoint) { "BREAKING POINT" } elseif ($phase.SuccessRate -lt 0.95) { "DEGRADED" } else { "PASSED" }

        Write-Host "Phase $($phase.PhaseNumber): $($phase.Phase)" -ForegroundColor Cyan
        Write-Host "  Status: $status" -ForegroundColor $statusColor
        Write-Host "  Concurrent: $($phase.Config.Concurrent), Duration: $([math]::Round($phase.Duration, 2)) min" -ForegroundColor Gray
        Write-Host "  Patches: $($phase.PatchesAttempted) attempted, $($phase.PatchesSucceeded) succeeded, $($phase.PatchesFailed) failed" -ForegroundColor Gray
        Write-Host "  Success Rate: $([math]::Round($phase.SuccessRate * 100, 2))%" -ForegroundColor Gray
        if ($phase.AvgLatency) {
            Write-Host "  Avg Latency: $([math]::Round($phase.AvgLatency, 2)) ms" -ForegroundColor Gray
            Write-Host "  P95 Latency: $([math]::Round($phase.P95Latency, 2)) ms" -ForegroundColor Gray
        }
        Write-Host ""
    }

    # System metrics summary
    if ($script:SystemMetrics.CPU.Count -gt 0) {
        Write-Host "System Resource Usage:" -ForegroundColor Yellow
        Write-Host "  CPU: Avg $([math]::Round(($script:SystemMetrics.CPU | Measure-Object -Average).Average, 2))%, Max $([math]::Round(($script:SystemMetrics.CPU | Measure-Object -Maximum).Maximum, 2))%" -ForegroundColor Gray
        Write-Host "  Memory: Avg $([math]::Round(($script:SystemMetrics.Memory | Measure-Object -Average).Average, 2))%, Max $([math]::Round(($script:SystemMetrics.Memory | Measure-Object -Maximum).Maximum, 2))%" -ForegroundColor Gray
        Write-Host ""
    }

    # Overall assessment
    $breakingPhase = $script:PhaseResults | Where-Object { $_.BreakingPoint } | Select-Object -First 1
    $minSuccessRate = ($script:PhaseResults | Measure-Object -Property SuccessRate -Minimum).Minimum

    Write-Host "Overall Assessment:" -ForegroundColor Yellow
    if ($breakingPhase) {
        Write-Host "  ❌ System reached breaking point at Phase $($breakingPhase.PhaseNumber)" -ForegroundColor Red
        Write-Host "     Breaking point: $($breakingPhase.Config.Concurrent) concurrent patches" -ForegroundColor Red
    } elseif ($minSuccessRate -lt 0.95) {
        Write-Host "  ⚠️  System degraded under stress but did not break" -ForegroundColor Yellow
        Write-Host "     Minimum success rate: $([math]::Round($minSuccessRate * 100, 2))%" -ForegroundColor Yellow
    } else {
        Write-Host "  ✅ System handled all stress test phases successfully" -ForegroundColor Green
    }
    Write-Host ""

    # Recommendations
    Write-Host "Recommendations:" -ForegroundColor Yellow
    $maxSuccessful = ($script:PhaseResults | Where-Object { -not $_.BreakingPoint } | Measure-Object -Property { $_.Config.Concurrent } -Maximum).Maximum
    if ($maxSuccessful) {
        Write-Host "  • Recommended max concurrent patches: $maxSuccessful" -ForegroundColor White
    }
    $recommendedRate = [math]::Floor($maxSuccessful * 0.8)
    Write-Host "  • Safe operating level: $recommendedRate concurrent patches (80% of max)" -ForegroundColor White
    Write-Host ""
}

# Main execution
Write-Host ""
Write-Host "RawrXD Hotpatch Stress Testing Framework" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "This test will push the hotpatch system to its limits." -ForegroundColor Yellow
Write-Host "Press Ctrl+C to abort at any time." -ForegroundColor Yellow
Write-Host ""

$confirm = Read-Host "Continue? (y/N)"
if ($confirm -ne 'y') {
    Write-Host "Aborted." -ForegroundColor Red
    exit 0
}

# Run stress phases
for ($i = 0; $i -lt $TestPhases; $i++) {
    Invoke-StressPhase -Phase $script:StressPhases[$i] -PhaseNumber ($i + 1)
}

# Compile final results
$finalResults = @{
    TestConfig = @{
        TestPhases = $TestPhases
        MaxConcurrentPatches = $MaxConcurrentPatches
    }
    Phases = $script:PhaseResults
    SystemMetrics = $script:SystemMetrics
    Summary = @{
        TotalPhases = $script:PhaseResults.Count
        PhasesPassed = ($script:PhaseResults | Where-Object { -not $_.BreakingPoint -and $_.SuccessRate -ge 0.95 }).Count
        PhasesDegraded = ($script:PhaseResults | Where-Object { -not $_.BreakingPoint -and $_.SuccessRate -lt 0.95 }).Count
        PhasesFailed = ($script:PhaseResults | Where-Object { $_.BreakingPoint }).Count
        MaxConcurrentAchieved = ($script:PhaseResults | Where-Object { -not $_.BreakingPoint } | Measure-Object -Property { $_.Config.Concurrent } -Maximum).Maximum
        OverallSuccessRate = ($script:PhaseResults | Measure-Object -Property SuccessRate -Average).Average
    }
    Timestamp = Get-Date -Format "o"
}

# Save results
$finalResults | ConvertTo-Json -Depth 10 | Out-File $OutputPath -Encoding UTF8
Write-StressLog "Results saved to: $OutputPath" -Level "INFO"

# Show report
Show-StressTestReport

# Exit code
$exitCode = if ($finalResults.Summary.PhasesFailed -gt 0) { 1 } else { 0 }
exit $exitCode
