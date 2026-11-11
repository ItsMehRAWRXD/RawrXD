# RawrXD Inference Monitor
# Real-time monitoring of inference requests and performance

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("Watch", "Stats", "Export", "Alert")]
    [string]$Action = "Watch",
    
    [int]$RefreshInterval = 5,
    [string]$LogPath = "logs/inference.log",
    [string]$OutputPath = "monitoring-reports",
    [int]$Duration = 0,
    [switch]$ShowTokens,
    [switch]$ShowLatency
)

$ErrorActionPreference = "Stop"

$script:Running = $true
$script:Stats = @{
    TotalRequests = 0
    SuccessfulRequests = 0
    FailedRequests = 0
    TotalTokens = 0
    AvgLatency = 0
    Latencies = @()
    StartTime = Get-Date
}

function Write-Status { param([string]$Message); Write-Host "[*] $Message" -ForegroundColor Cyan }
function Write-Success { param([string]$Message); Write-Host "[✓] $Message" -ForegroundColor Green }
function Write-Error { param([string]$Message); Write-Host "[✗] $Message" -ForegroundColor Red }
function Write-Warning { param([string]$Message); Write-Host "[!] $Message" -ForegroundColor Yellow }

function Initialize-Monitor {
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    Write-Status "Inference Monitor initialized"
}

function Show-LiveStats {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "RawrXD Inference Monitor" -ForegroundColor Cyan
    Write-Host "Press Ctrl+C to stop" -ForegroundColor Gray
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    
    $startTime = Get-Date
    
    while ($script:Running) {
        # Clear previous stats (simulated)
        $currentStats = Get-SimulatedStats
        
        # Update cumulative stats
        $script:Stats.TotalRequests += $currentStats.Requests
        $script:Stats.SuccessfulRequests += $currentStats.Success
        $script:Stats.FailedRequests += $currentStats.Failures
        $script:Stats.TotalTokens += $currentStats.Tokens
        $script:Stats.Latencies += $currentStats.Latency
        
        # Calculate averages
        if ($script:Stats.Latencies.Count -gt 0) {
            $script:Stats.AvgLatency = ($script:Stats.Latencies | Measure-Object -Average).Average
        }
        
        # Display stats
        $elapsed = (Get-Date) - $script:Stats.StartTime
        $rps = if ($elapsed.TotalSeconds -gt 0) { [math]::Round($script:Stats.TotalRequests / $elapsed.TotalSeconds, 2) } else { 0 }
        
        Clear-Host
        Write-Host "RawrXD Inference Monitor - $(Get-Date -Format 'HH:mm:ss')" -ForegroundColor Cyan
        Write-Host "========================================" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "Requests: $($script:Stats.TotalRequests) total | $($script:Stats.SuccessfulRequests) success | $($script:Stats.FailedRequests) failed" -ForegroundColor White
        Write-Host "Rate: $rps req/sec | Uptime: $($elapsed.ToString('hh\:mm\:ss'))" -ForegroundColor Gray
        
        if ($ShowTokens) {
            Write-Host "Tokens: $($script:Stats.TotalTokens) total | $([math]::Round($script:Stats.TotalTokens / $script:Stats.TotalRequests, 1)) avg/request" -ForegroundColor White
        }
        
        if ($ShowLatency -and $script:Stats.Latencies.Count -gt 0) {
            $min = ($script:Stats.Latencies | Measure-Object -Minimum).Minimum
            $max = ($script:Stats.Latencies | Measure-Object -Maximum).Maximum
            $avg = ($script:Stats.Latencies | Measure-Object -Average).Average
            Write-Host "Latency: $([math]::Round($avg, 1))ms avg | $([math]::Round($min, 1))ms min | $([math]::Round($max, 1))ms max" -ForegroundColor White
        }
        
        Write-Host ""
        Write-Host "Current Activity:" -ForegroundColor White
        foreach ($req in $currentStats.RecentRequests) {
            $color = if ($req.Status -eq "success") { "Green" } else { "Red" }
            Write-Host "  [$($req.Status)] $($req.Model) - $($req.Tokens) tokens in $($req.Latency)ms" -ForegroundColor $color
        }
        
        # Check duration limit
        if ($Duration -gt 0 -and $elapsed.TotalSeconds -ge $Duration) {
            $script:Running = $false
        }
        
        Start-Sleep -Seconds $RefreshInterval
    }
}

function Get-SimulatedStats {
    # In real implementation, this would read from actual logs/API
    $requests = Get-Random -Minimum 0 -Maximum 5
    $success = [math]::Floor($requests * 0.9)
    $failures = $requests - $success
    $tokens = Get-Random -Minimum 50 -Maximum 500
    $latency = Get-Random -Minimum 100 -Maximum 500
    
    $recent = @()
    for ($i = 0; $i -lt [math]::Min($requests, 5); $i++) {
        $recent += @{
            Status = if (Get-Random -Maximum 10 -gt 1) { "success" } else { "failed" }
            Model = @("llama-2-7b", "mistral-7b", "codellama-7b") | Get-Random
            Tokens = Get-Random -Minimum 50 -Maximum 500
            Latency = Get-Random -Minimum 100 -Maximum 500
        }
    }
    
    return @{
        Requests = $requests
        Success = $success
        Failures = $failures
        Tokens = $tokens
        Latency = $latency
        RecentRequests = $recent
    }
}

function Show-Statistics {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Inference Statistics" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    
    if ($script:Stats.TotalRequests -eq 0) {
        Write-Host "No data collected yet. Run with -Action Watch first." -ForegroundColor Gray
        return
    }
    
    $elapsed = (Get-Date) - $script:Stats.StartTime
    $rps = if ($elapsed.TotalSeconds -gt 0) { [math]::Round($script:Stats.TotalRequests / $elapsed.TotalSeconds, 2) } else { 0 }
    $successRate = if ($script:Stats.TotalRequests -gt 0) { [math]::Round(($script:Stats.SuccessfulRequests / $script:Stats.TotalRequests) * 100, 1) } else { 0 }
    
    Write-Host "Total Requests: $($script:Stats.TotalRequests)" -ForegroundColor White
    Write-Host "Successful: $($script:Stats.SuccessfulRequests) ($successRate%)" -ForegroundColor Green
    Write-Host "Failed: $($script:Stats.FailedRequests)" -ForegroundColor Red
    Write-Host "Total Tokens: $($script:Stats.TotalTokens)" -ForegroundColor White
    Write-Host "Avg Latency: $([math]::Round($script:Stats.AvgLatency, 1))ms" -ForegroundColor White
    Write-Host "Requests/sec: $rps" -ForegroundColor White
    Write-Host "Uptime: $($elapsed.ToString('hh\:mm\:ss'))" -ForegroundColor Gray
    Write-Host ""
}

function Export-Stats {
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $reportFile = "$OutputPath\inference-stats-$timestamp.json"
    
    $report = @{
        Timestamp = Get-Date -Format "o"
        Stats = $script:Stats
        Duration = ((Get-Date) - $script:Stats.StartTime).ToString()
    }
    
    $report | ConvertTo-Json -Depth 5 | Out-File $reportFile
    Write-Success "Statistics exported to: $reportFile"
}

function Set-AlertThresholds {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Alert Configuration" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    
    $alerts = @{
        HighLatency = 1000
        ErrorRate = 5
        LowThroughput = 10
    }
    
    Write-Host "Current Thresholds:" -ForegroundColor White
    Write-Host "  High Latency Alert: $($alerts.HighLatency)ms" -ForegroundColor Gray
    Write-Host "  Error Rate Alert: $($alerts.ErrorRate)%" -ForegroundColor Gray
    Write-Host "  Low Throughput Alert: $($alerts.LowThroughput) req/min" -ForegroundColor Gray
    Write-Host ""
    Write-Success "Alert thresholds configured"
}

# Handle Ctrl+C
$null = Register-EngineEvent -SourceIdentifier "PowerShell.Exiting" -Action {
    $script:Running = $false
}

# Main execution
function Main {
    Write-Host "RawrXD Inference Monitor" -ForegroundColor Cyan
    Write-Host "========================" -ForegroundColor Cyan
    Write-Host ""
    
    Initialize-Monitor
    
    switch ($Action) {
        "Watch" { Show-LiveStats }
        "Stats" { Show-Statistics }
        "Export" { Export-Stats }
        "Alert" { Set-AlertThresholds }
        default { Write-Host "Usage: .\inference-monitor.ps1 -Action [Watch|Stats|Export|Alert]" }
    }
    
    Write-Host ""
}

Main
