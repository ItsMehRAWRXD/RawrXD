# RawrXD Log Correlation Analyzer
# Correlates logs across services for distributed tracing
# Version: 1.0.0
# Author: RawrXD DevOps Team

param(
    [Parameter()]
    [ValidateSet("Analyze", "Trace", "Report", "Search")]
    [string]$Action = "Analyze",
    
    [Parameter()]
    [string]$TraceId,
    
    [Parameter()]
    [string]$CorrelationId,
    
    [Parameter()]
    [string]$TimeRange = "1h",
    
    [Parameter()]
    [string[]]$Services = @("api", "worker", "database"),
    
    [Parameter()]
    [string]$Query,
    
    [Parameter()]
    [string]$OutputPath = "correlation-report.json"
)

$ErrorActionPreference = "Stop"
$script:Version = "1.0.0"

function Write-Status { param([string]$Message) Write-Host "[INFO] $Message" -ForegroundColor Cyan }
function Write-Success { param([string]$Message) Write-Host "[OK] $Message" -ForegroundColor Green }

function Get-SimulatedLogs {
    param([string]$Service, [string]$Trace)
    
    $logs = @()
    $baseTime = Get-Date
    
    for ($i = 0; $i -lt 5; $i++) {
        $logs += [PSCustomObject]@{
            Timestamp = $baseTime.AddSeconds($i * 2).ToString("o")
            Service = $Service
            TraceId = $Trace
            SpanId = [Guid]::NewGuid().ToString().Substring(0, 8)
            Level = @("INFO", "INFO", "DEBUG", "INFO", "WARN") | Get-Random
            Message = "Operation completed in service $Service"
            Duration = Get-Random -Minimum 10 -Maximum 500
        }
    }
    
    return $logs
}

function Invoke-LogCorrelation {
    Write-Status "Analyzing log correlation..."
    Write-Status "Time Range: $TimeRange"
    Write-Status "Services: $($Services -join ', ')"
    Write-Host ""
    
    $allLogs = @()
    $traceId = if ($TraceId) { $TraceId } else { [Guid]::NewGuid().ToString() }
    
    foreach ($service in $Services) {
        Write-Status "  Collecting logs from $service..."
        $logs = Get-SimulatedLogs -Service $service -Trace $traceId
        $allLogs += $logs
    }
    
    # Sort by timestamp
    $allLogs = $allLogs | Sort-Object Timestamp
    
    Write-Host "Log Correlation Analysis" -ForegroundColor Cyan
    Write-Host "=======================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Trace ID: $traceId"
    Write-Host "Total Events: $($allLogs.Count)"
    Write-Host "Services: $($allLogs.Service | Select-Object -Unique | Measure-Object).Count"
    Write-Host ""
    
    Write-Host "Timeline:"
    Write-Host "Time                Service     Level    Duration    Message"
    Write-Host "----                -------     -----    --------    -------"
    
    foreach ($log in $allLogs) {
        $color = switch ($log.Level) {
            "ERROR" { "Red" }
            "WARN" { "Yellow" }
            default { "White" }
        }
        
        Write-Host ([datetime]$log.Timestamp).ToString("HH:mm:ss.fff").PadRight(20) -NoNewline
        Write-Host $log.Service.PadRight(12) -NoNewline
        Write-Host $log.Level.PadRight(9) -ForegroundColor $color -NoNewline
        Write-Host "$($log.Duration)ms".PadRight(12) -NoNewline
        Write-Host $log.Message
    }
    Write-Host ""
    
    # Calculate trace metrics
    $totalDuration = ($allLogs | Measure-Object -Property Duration -Sum).Sum
    $avgDuration = ($allLogs | Measure-Object -Property Duration -Average).Average
    
    Write-Host "Trace Metrics:"
    Write-Host "  Total Duration: $totalDuration ms"
    Write-Host "  Average Duration: $([math]::Round($avgDuration, 2)) ms"
    Write-Host "  Span Count: $($allLogs.Count)"
    
    # Export report
    $report = @{
        TraceId = $traceId
        GeneratedAt = (Get-Date).ToString("o")
        TimeRange = $TimeRange
        Services = $Services
        Metrics = @{
            TotalEvents = $allLogs.Count
            TotalDuration = $totalDuration
            AverageDuration = [math]::Round($avgDuration, 2)
        }
        Events = $allLogs
    }
    
    $report | ConvertTo-Json -Depth 5 | Set-Content $OutputPath
    Write-Success "Correlation report saved to: $OutputPath"
}

function Trace-Request {
    if (-not $TraceId) {
        throw "TraceId parameter required for Trace action"
    }
    
    Write-Status "Tracing request: $TraceId"
    
    # Simulate trace reconstruction
    $spans = @()
    $services = @("api-gateway", "auth-service", "rawrxd-api", "database")
    $baseTime = (Get-Date).AddMinutes(-5)
    
    foreach ($service in $services) {
        $duration = Get-Random -Minimum 10 -Maximum 200
        $spans += [PSCustomObject]@{
            Service = $service
            StartTime = $baseTime.ToString("o")
            Duration = $duration
            Status = "OK"
        }
        $baseTime = $baseTime.AddMilliseconds($duration)
    }
    
    Write-Host "Request Trace: $TraceId" -ForegroundColor Cyan
    Write-Host "=======================" -ForegroundColor Cyan
    Write-Host ""
    
    $totalTime = ($spans | Measure-Object -Property Duration -Sum).Sum
    
    foreach ($span in $spans) {
        $indent = "  " * ($services.IndexOf($span.Service))
        Write-Host "$indent→ $($span.Service): $($span.Duration)ms"
    }
    
    Write-Host ""
    Write-Host "Total Request Time: $totalTime ms"
}

function Search-Logs {
    if (-not $Query) {
        throw "Query parameter required for Search action"
    }
    
    Write-Status "Searching logs for: $Query"
    
    # Simulate search results
    $results = @(
        @{ Service = "api"; Message = "Request processed successfully"; Timestamp = (Get-Date).AddMinutes(-5).ToString("o") },
        @{ Service = "worker"; Message = "Job completed"; Timestamp = (Get-Date).AddMinutes(-3).ToString("o") }
    )
    
    Write-Host "Search Results for '$Query'" -ForegroundColor Cyan
    Write-Host "=========================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Found $($results.Count) matches"
    Write-Host ""
    
    foreach ($result in $results) {
        Write-Host "[$($result.Timestamp)] $($result.Service): $($result.Message)"
    }
}

# Main execution
try {
    switch ($Action) {
        "Analyze" { Invoke-LogCorrelation }
        "Trace" { Trace-Request }
        "Report" { Invoke-LogCorrelation }
        "Search" { Search-Logs }
    }
}
catch {
    Write-Error $_.Exception.Message
    exit 1
}
