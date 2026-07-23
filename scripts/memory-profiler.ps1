# RawrXD Memory Profiler
# Profiles memory usage during inference and identifies optimization opportunities

param(
    [string]$ProcessName = "rawrxd",
    [int]$ProcessId,
    [int]$DurationSeconds = 60,
    [int]$SampleIntervalMs = 1000,
    [switch]$TrackAllocations,
    [switch]$FindLeaks,
    [switch]$GenerateReport,
    [string]$OutputFormat = "html"
)

$ErrorActionPreference = "Stop"

$script:MemState = @{
    StartTime = Get-Date
    Samples = @()
    PeakWorkingSet = 0
    PeakPrivateBytes = 0
    LeakSuspects = @()
}

function Write-Status { param([string]$Message) Write-Host "[*] $Message" -ForegroundColor Cyan }
function Write-Success { param([string]$Message) Write-Host "[✓] $Message" -ForegroundColor Green }
function Write-Warning { param([string]$Message) Write-Host "[!] $Message" -ForegroundColor Yellow }

function Get-TargetProcess {
    if ($ProcessId) {
        return Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
    }
    
    return Get-Process -Name $ProcessName -ErrorAction SilentlyContinue | Select-Object -First 1
}

function Sample-Memory {
    param([System.Diagnostics.Process]$Process)
    
    $sample = @{
        Timestamp = Get-Date
        WorkingSetMB = [math]::Round($Process.WorkingSet64 / 1MB, 2)
        PrivateBytesMB = [math]::Round($Process.PrivateMemorySize64 / 1MB, 2)
        VirtualMemoryMB = [math]::Round($Process.VirtualMemorySize64 / 1MB, 2)
        Handles = $Process.HandleCount
        Threads = $Process.Threads.Count
        GCTotalMemory = 0
    }
    
    # Update peaks
    if ($sample.WorkingSetMB -gt $script:MemState.PeakWorkingSet) {
        $script:MemState.PeakWorkingSet = $sample.WorkingSetMB
    }
    if ($sample.PrivateBytesMB -gt $script:MemState.PeakPrivateBytes) {
        $script:MemState.PeakPrivateBytes = $sample.PrivateBytesMB
    }
    
    return $sample
}

function Invoke-MemoryProfiling {
    Write-Status "Starting memory profiling for $DurationSeconds seconds..."
    
    $process = Get-TargetProcess
    if (-not $process) {
        Write-Error "Process not found: $ProcessName"
        exit 1
    }
    
    Write-Success "Attached to process: $($process.ProcessName) (PID: $($process.Id))"
    
    $endTime = (Get-Date).AddSeconds($DurationSeconds)
    $sampleCount = 0
    
    while ((Get-Date) -lt $endTime) {
        $process.Refresh()
        $sample = Sample-Memory -Process $process
        $script:MemState.Samples += $sample
        
        $sampleCount++
        Write-Progress -Activity "Memory Profiling" -Status "Sample $sampleCount" -PercentComplete ((($DurationSeconds - ($endTime - (Get-Date)).TotalSeconds) / $DurationSeconds) * 100)
        
        Start-Sleep -Milliseconds $SampleIntervalMs
    }
    
    Write-Progress -Activity "Memory Profiling" -Completed
    
    Write-Success "Profiling complete: $sampleCount samples collected"
}

function Find-MemoryLeaks {
    if (-not $FindLeaks) { return }
    
    Write-Status "Analyzing for memory leaks..."
    
    # Simple leak detection: check if memory is consistently growing
    if ($script:MemState.Samples.Count -lt 10) { return }
    
    $firstHalf = $script:MemState.Samples | Select-Object -First ($script:MemState.Samples.Count / 2)
    $secondHalf = $script:MemState.Samples | Select-Object -Last ($script:MemState.Samples.Count / 2)
    
    $firstAvg = ($firstHalf | Measure-Object -Property WorkingSetMB -Average).Average
    $secondAvg = ($secondHalf | Measure-Object -Property WorkingSetMB -Average).Average
    
    $growth = $secondAvg - $firstAvg
    $growthRate = $growth / ($DurationSeconds / 2)
    
    if ($growthRate -gt 1) { # More than 1 MB per second growth
        $script:MemState.LeakSuspects += @{
            Type = "Working Set Growth"
            Rate = $growthRate
            Severity = if ($growthRate -gt 10) { "High" } else { "Medium" }
            Recommendation = "Investigate memory allocations in hot paths"
        }
    }
    
    Write-Success "Leak analysis complete"
}

function Export-MemoryReport {
    if (-not $GenerateReport) { return }
    
    $report = @{
        Timestamp = Get-Date -Format "o"
        Process = $ProcessName
        Duration = $DurationSeconds
        Samples = $script:MemState.Samples.Count
        PeakWorkingSetMB = $script:MemState.PeakWorkingSet
        PeakPrivateBytesMB = $script:MemState.PeakPrivateBytes
        AverageWorkingSetMB = ($script:MemState.Samples | Measure-Object -Property WorkingSetMB -Average).Average
        LeakSuspects = $script:MemState.LeakSuspects
    }
    
    switch ($OutputFormat) {
        "json" {
            $report | ConvertTo-Json -Depth 5 | Out-File "memory-profile-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
        }
        "html" {
            Export-HtmlReport
        }
    }
    
    Write-Success "Report exported"
}

function Export-HtmlReport {
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Memory Profile Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1000px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; }
        h1 { color: #333; }
        .stats { display: grid; grid-template-columns: repeat(3, 1fr); gap: 15px; margin: 20px 0; }
        .stat-card { background: #f8f9fa; padding: 15px; border-radius: 8px; text-align: center; }
        .stat-value { font-size: 2em; font-weight: bold; color: #667eea; }
        .chart { height: 300px; background: #f8f9fa; border-radius: 8px; margin: 20px 0; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Memory Profile Report</h1>
        <div class="stats">
            <div class="stat-card">
                <div class="stat-value">$($script:MemState.PeakWorkingSet) MB</div>
                <div>Peak Working Set</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">$($script:MemState.PeakPrivateBytes) MB</div>
                <div>Peak Private Bytes</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">$($script:MemState.Samples.Count)</div>
                <div>Samples</div>
            </div>
        </div>
    </div>
</body>
</html>
"@
    
    $html | Out-File "memory-profile-$(Get-Date -Format 'yyyyMMdd-HHmmss').html" -Encoding UTF8
}

function Show-Summary {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Memory Profiling Summary" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Process: $ProcessName" -ForegroundColor White
    Write-Host "Samples: $($script:MemState.Samples.Count)" -ForegroundColor White
    Write-Host ""
    Write-Host "Peak Working Set: $($script:MemState.PeakWorkingSet) MB" -ForegroundColor Yellow
    Write-Host "Peak Private Bytes: $($script:MemState.PeakPrivateBytes) MB" -ForegroundColor Yellow
    Write-Host ""
    
    if ($script:MemState.LeakSuspects.Count -gt 0) {
        Write-Warning "Potential memory leaks detected:"
        foreach ($leak in $script:MemState.LeakSuspects) {
            Write-Host "  [$($leak.Severity)] $($leak.Type): $([math]::Round($leak.Rate, 2)) MB/s" -ForegroundColor Red
        }
    } else {
        Write-Success "No memory leaks detected"
    }
}

# Main execution
function Main {
    Write-Host "RawrXD Memory Profiler" -ForegroundColor Cyan
    Write-Host "=====================" -ForegroundColor Cyan
    Write-Host ""
    
    Invoke-MemoryProfiling
    Find-MemoryLeaks
    Export-MemoryReport
    Show-Summary
    
    Write-Host ""
    Write-Success "Memory profiling complete!"
}

Main
