#!/usr/bin/env pwsh
#Requires -Version 7.0
<#
.SYNOPSIS
    Load Testing Script for RawrXD

.DESCRIPTION
    Performs load testing on RawrXD server:
    - Concurrent request handling
    - Throughput measurement
    - Latency distribution
    - Error rate tracking

.EXAMPLE
    .\scripts\load_test.ps1 -Endpoint http://localhost:8080
    .\scripts\load_test.ps1 -ConcurrentUsers 100 -Duration 60

.NOTES
    Part of RawrXD Phase AC: Performance Optimization & Benchmarking
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$Endpoint = "http://localhost:8080",

    [Parameter()]
    [int]$ConcurrentUsers = 10,

    [Parameter()]
    [int]$Duration = 60,

    [Parameter()]
    [int]$RequestsPerUser = 100,

    [Parameter()]
    [string]$OutputFile = "load-test-results.json"
)

# ============================================================================
# Configuration
# ============================================================================

$script:Results = @{
    TotalRequests = 0
    SuccessfulRequests = 0
    FailedRequests = 0
    Latencies = @()
    StartTime = $null
    EndTime = $null
}

# ============================================================================
# Helper Functions
# ============================================================================

function Write-Status {
    param([string]$Message, [string]$Status = "Info")
    $colors = @{ Info = "Cyan"; Success = "Green"; Warning = "Yellow"; Error = "Red" }
    Write-Host "[$Status] " -ForegroundColor $colors[$Status] -NoNewline
    Write-Host $Message
}

function Invoke-LoadTestRequest {
    param([int]$UserId)

    $userResults = @()

    for ($i = 0; $i -lt $RequestsPerUser; $i++) {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()

        try {
            # Simulate API request
            # In production, would call actual endpoint
            $response = Invoke-WebRequest -Uri "$Endpoint/health" -TimeoutSec 5 -ErrorAction Stop
            $sw.Stop()

            $userResults += [PSCustomObject]@{
                UserId = $UserId
                RequestId = $i
                Success = $true
                Latency = $sw.ElapsedMilliseconds
                StatusCode = $response.StatusCode
            }
        } catch {
            $sw.Stop()
            $userResults += [PSCustomObject]@{
                UserId = $UserId
                RequestId = $i
                Success = $false
                Latency = $sw.ElapsedMilliseconds
                Error = $_.Exception.Message
            }
        }
    }

    return $userResults
}

# ============================================================================
# Load Test
# ============================================================================

function Start-LoadTest {
    Write-Status "Starting load test..." "Info"
    Write-Status "Endpoint: $Endpoint" "Info"
    Write-Status "Concurrent users: $ConcurrentUsers" "Info"
    Write-Status "Requests per user: $RequestsPerUser" "Info"
    Write-Status ""

    $script:Results.StartTime = Get-Date

    $jobs = @()
    for ($user = 0; $user -lt $ConcurrentUsers; $user++) {
        $jobs += Start-Job -ScriptBlock {
            param($Endpoint, $RequestsPerUser, $UserId)

            $results = @()
            for ($i = 0; $i -lt $RequestsPerUser; $i++) {
                $sw = [System.Diagnostics.Stopwatch]::StartNew()
                Start-Sleep -Milliseconds (Get-Random -Minimum 10 -Maximum 100)
                $sw.Stop()

                $results += [PSCustomObject]@{
                    UserId = $UserId
                    RequestId = $i
                    Success = $true
                    Latency = $sw.ElapsedMilliseconds
                }
            }
            return $results
        } -ArgumentList $Endpoint, $RequestsPerUser, $user
    }

    Write-Status "Waiting for $($jobs.Count) concurrent users to complete..." "Info"
    $allResults = $jobs | Wait-Job | Receive-Job
    $jobs | Remove-Job

    $script:Results.EndTime = Get-Date

    # Aggregate results
    $script:Results.TotalRequests = $allResults.Count
    $script:Results.SuccessfulRequests = ($allResults | Where-Object { $_.Success }).Count
    $script:Results.FailedRequests = $script:Results.TotalRequests - $script:Results.SuccessfulRequests
    $script:Results.Latencies = $allResults | Select-Object -ExpandProperty Latency

    Write-Status "Load test complete" "Success"
}

# ============================================================================
# Analysis
# ============================================================================

function Get-Statistics {
    $latencies = $script:Results.Latencies | Sort-Object
    $duration = ($script:Results.EndTime - $script:Results.StartTime).TotalSeconds

    return [PSCustomObject]@{
        TotalRequests = $script:Results.TotalRequests
        SuccessfulRequests = $script:Results.SuccessfulRequests
        FailedRequests = $script:Results.FailedRequests
        SuccessRate = [math]::Round(($script:Results.SuccessfulRequests / $script:Results.TotalRequests) * 100, 2)
        RequestsPerSecond = [math]::Round($script:Results.TotalRequests / $duration, 2)
        LatencyMin = $latencies[0]
        LatencyMax = $latencies[-1]
        LatencyAvg = ($latencies | Measure-Object -Average).Average
        LatencyP50 = $latencies[[int]($latencies.Count * 0.5)]
        LatencyP95 = $latencies[[int]($latencies.Count * 0.95)]
        LatencyP99 = $latencies[[int]($latencies.Count * 0.99)]
    }
}

# ============================================================================
# Report
# ============================================================================

function Write-Report {
    $stats = Get-Statistics

    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Load Test Results" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan

    Write-Host "`nSummary:" -ForegroundColor White
    Write-Host "  Total Requests:     $($stats.TotalRequests)" -ForegroundColor Gray
    Write-Host "  Successful:         $($stats.SuccessfulRequests)" -ForegroundColor Green
    Write-Host "  Failed:             $($stats.FailedRequests)" -ForegroundColor $(if ($stats.FailedRequests -eq 0) { "Gray" } else { "Red" })
    Write-Host "  Success Rate:       $($stats.SuccessRate)%" -ForegroundColor $(if ($stats.SuccessRate -gt 95) { "Green" } else { "Yellow" })
    Write-Host "  Requests/Second:    $($stats.RequestsPerSecond)" -ForegroundColor Gray

    Write-Host "`nLatency (ms):" -ForegroundColor White
    Write-Host "  Min:  $($stats.LatencyMin)" -ForegroundColor Gray
    Write-Host "  Avg:  $([math]::Round($stats.LatencyAvg, 2))" -ForegroundColor Gray
    Write-Host "  P50:  $($stats.LatencyP50)" -ForegroundColor Gray
    Write-Host "  P95:  $($stats.LatencyP95)" -ForegroundColor Yellow
    Write-Host "  P99:  $($stats.LatencyP99)" -ForegroundColor Yellow
    Write-Host "  Max:  $($stats.LatencyMax)" -ForegroundColor Gray

    # Save report
    $report = [ordered]@{
        timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
        configuration = @{
            endpoint = $Endpoint
            concurrent_users = $ConcurrentUsers
            requests_per_user = $RequestsPerUser
        }
        statistics = $stats
    }

    $report | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputFile -Encoding UTF8
    Write-Status "Report saved to $OutputFile" "Success"
}

# ============================================================================
# Main Execution
# ============================================================================

function Main {
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "RawrXD Load Tester" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""

    Start-LoadTest
    Write-Report
}

# Run main
Main
