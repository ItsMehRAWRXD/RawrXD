# RawrXD Telemetry Quick Start
# One-command setup for the complete observability stack

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("start", "stop", "status", "simulate", "dashboard-only")]
    [string]$Command = "status",
    
    [int]$Port = 9090,
    [switch]$Verbose
)

$ErrorActionPreference = "Stop"

# =============================================================================
# Configuration
# =============================================================================
$Config = @{
    DashboardScript = "d:\RawrXD\telemetry-dashboard.ps1"
    GrafanaConfig = "d:\RawrXD\grafana-dashboard.json"
    PrometheusPort = $Port
    ProcessName = "powershell"
}

# =============================================================================
# Helper Functions
# =============================================================================
function Write-Header($text) {
    Write-Host ""
    Write-Host "================================================" -ForegroundColor Cyan
    Write-Host $text -ForegroundColor Cyan
    Write-Host "================================================" -ForegroundColor Cyan
    Write-Host ""
}

function Write-Status($text, $type = "info") {
    switch ($type) {
        "success" { Write-Host "  ✓ $text" -ForegroundColor Green }
        "error" { Write-Host "  ✗ $text" -ForegroundColor Red }
        "warning" { Write-Host "  ⚠ $text" -ForegroundColor Yellow }
        "info" { Write-Host "  ℹ $text" -ForegroundColor Gray }
    }
}

function Get-TelemetryStatus {
    $jobs = Get-Job -Name "RawrXD*" -ErrorAction SilentlyContinue
    $dashboardRunning = $jobs | Where-Object { $_.Name -eq "RawrXD-Dashboard" -and $_.State -eq "Running" }
    $simulationRunning = $jobs | Where-Object { $_.Name -eq "RawrXD-Simulation" -and $_.State -eq "Running" }
    
    # Check if port is listening
    $portListening = $false
    try {
        $listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, $Config.PrometheusPort)
        $listener.Start()
        $listener.Stop()
    } catch {
        $portListening = $true
    }
    
    return @{
        DashboardRunning = [bool]$dashboardRunning
        SimulationRunning = [bool]$simulationRunning
        PortListening = $portListening
        Jobs = $jobs
    }
}

# =============================================================================
# Commands
# =============================================================================
function Start-TelemetryStack {
    Write-Header "Starting RawrXD Telemetry Stack"
    
    $status = Get-TelemetryStatus
    
    if ($status.DashboardRunning) {
        Write-Status "Telemetry dashboard already running" "warning"
        return
    }
    
    # Check if dashboard script exists
    if (-not (Test-Path $Config.DashboardScript)) {
        Write-Status "Dashboard script not found: $($Config.DashboardScript)" "error"
        return
    }
    
    Write-Status "Starting telemetry dashboard on port $($Config.PrometheusPort)..." "info"
    
    # Start the dashboard in a background job
    $job = Start-Job -Name "RawrXD-Dashboard" -ScriptBlock {
        param($script, $port)
        & $script -Port $port
    } -ArgumentList $Config.DashboardScript, $Config.PrometheusPort
    
    Start-Sleep -Seconds 2
    
    # Check if job is running
    $job.Refresh()
    if ($job.State -eq "Running") {
        Write-Status "Telemetry dashboard started successfully" "success"
        Write-Status "Prometheus endpoint: http://localhost:$($Config.PrometheusPort)/metrics" "info"
        Write-Status "Health check: http://localhost:$($Config.PrometheusPort)/health" "info"
    } else {
        Write-Status "Failed to start dashboard" "error"
        Receive-Job $job
    }
    
    Write-Host ""
    Write-Host "Quick Commands:" -ForegroundColor Yellow
    Write-Host "  curl http://localhost:$($Config.PrometheusPort)/metrics" -ForegroundColor Gray
    Write-Host "  Invoke-RestMethod -Uri http://localhost:$($Config.PrometheusPort)/metrics" -ForegroundColor Gray
}

function Start-SimulationMode {
    Write-Header "Starting Simulation Mode"
    
    $status = Get-TelemetryStatus
    
    if ($status.SimulationRunning) {
        Write-Status "Simulation already running" "warning"
        return
    }
    
    Write-Status "Starting synthetic metrics generation..." "info"
    
    $job = Start-Job -Name "RawrXD-Simulation" -ScriptBlock {
        $Metrics = @{
            InferenceCount = 0
            TokenCount = 0
            LatencyTotal = 0
            CacheHits = 0
            CacheMisses = 0
            INT8Count = 0
            BF16Count = 0
            FP32Count = 0
        }
        
        while ($true) {
            ${script:Metrics}.InferenceCount += (Get-Random -Minimum 1 -Maximum 5)
            ${script:Metrics}.TokenCount += (Get-Random -Minimum 10 -Maximum 100)
            ${script:Metrics}.LatencyTotal += (Get-Random -Minimum 15000 -Maximum 25000)
            
            if ((Get-Random) -gt 0.1) { ${script:Metrics}.CacheHits++ }
            else { ${script:Metrics}.CacheMisses++ }
            
            $r = Get-Random
            if ($r -lt 0.85) { ${script:Metrics}.INT8Count++ }
            elseif ($r -lt 0.95) { ${script:Metrics}.BF16Count++ }
            else { ${script:Metrics}.FP32Count++ }
            
            Start-Sleep -Milliseconds 500
        }
    }
    
    Start-Sleep -Seconds 1
    $job.Refresh()
    
    if ($job.State -eq "Running") {
        Write-Status "Simulation started - generating synthetic metrics" "success"
    } else {
        Write-Status "Simulation failed to start" "error"
    }
}

function Stop-TelemetryStack {
    Write-Header "Stopping RawrXD Telemetry Stack"
    
    $jobs = Get-Job -Name "RawrXD*" -ErrorAction SilentlyContinue
    
    if ($jobs.Count -eq 0) {
        Write-Status "No telemetry jobs running" "info"
        return
    }
    
    foreach ($job in $jobs) {
        Write-Status "Stopping $($job.Name)..." "info"
        Stop-Job $job -ErrorAction SilentlyContinue
        Remove-Job $job -ErrorAction SilentlyContinue
    }
    
    Write-Status "All telemetry jobs stopped" "success"
}

function Show-TelemetryStatus {
    Write-Header "RawrXD Telemetry Status"
    
    $status = Get-TelemetryStatus
    
    Write-Host "Dashboard Status:" -ForegroundColor Yellow
    if ($status.DashboardRunning) {
        Write-Status "Running" "success"
        Write-Status "Endpoint: http://localhost:$($Config.PrometheusPort)/metrics" "info"
    } else {
        Write-Status "Stopped" "error"
    }
    
    Write-Host ""
    Write-Host "Simulation Status:" -ForegroundColor Yellow
    if ($status.SimulationRunning) {
        Write-Status "Running" "success"
    } else {
        Write-Status "Stopped" "info"
    }
    
    Write-Host ""
    Write-Host "Port Status:" -ForegroundColor Yellow
    if ($status.PortListening) {
        Write-Status "Port $($Config.PrometheusPort) is active" "success"
    } else {
        Write-Status "Port $($Config.PrometheusPort) is available" "info"
    }
    
    if ($status.Jobs.Count -gt 0) {
        Write-Host ""
        Write-Host "Active Jobs:" -ForegroundColor Yellow
        $status.Jobs | Format-Table Name, State, Command -AutoSize | Out-String | Write-Host -ForegroundColor Gray
    }
}

function Show-DashboardOnly {
    Write-Header "RawrXD Console Dashboard"
    
    # Simple console dashboard without HTTP server
    $Metrics = @{
        InferenceCount = 0
        TokenCount = 0
        LatencyTotal = 0
        CacheHits = 0
        CacheMisses = 0
        INT8Count = 0
        BF16Count = 0
        FP32Count = 0
        SecurityEvents = 0
    }
    
    # Start simulation in background
    $simJob = Start-Job -ScriptBlock {
        while ($true) {
            Start-Sleep -Milliseconds 500
            Write-Output "TICK"
        }
    }
    
    try {
        while ($true) {
            # Update metrics
            $Metrics.InferenceCount += (Get-Random -Minimum 1 -Maximum 5)
            $Metrics.TokenCount += (Get-Random -Minimum 10 -Maximum 100)
            $Metrics.LatencyTotal += (Get-Random -Minimum 15000 -Maximum 25000)
            
            if ((Get-Random) -gt 0.1) { $Metrics.CacheHits++ }
            else { $Metrics.CacheMisses++ }
            
            $r = Get-Random
            if ($r -lt 0.85) { $Metrics.INT8Count++ }
            elseif ($r -lt 0.95) { $Metrics.BF16Count++ }
            else { $Metrics.FP32Count++ }
            
            Clear-Host
            
            Write-Host "================================================" -ForegroundColor Cyan
            Write-Host "RawrXD Telemetry Dashboard (Console Mode)" -ForegroundColor Cyan
            Write-Host "================================================" -ForegroundColor Cyan
            Write-Host ""
            
            # Inference stats
            Write-Host "Inference Metrics:" -ForegroundColor Yellow
            Write-Host "  Total Inferences: $($Metrics.InferenceCount)" -ForegroundColor White
            Write-Host "  Total Tokens: $($Metrics.TokenCount)" -ForegroundColor White
            
            $avgLatency = $(if ($Metrics.InferenceCount -gt 0) { 
                [math]::Round($Metrics.LatencyTotal / $Metrics.InferenceCount / 1000.0, 2) 
            } else { 0 }
            $latencyColor = $(if ($avgLatency -lt 25){"Green"}elseif($avgLatency -lt 50){"Yellow"}else{"Red"}
            Write-Host "  Avg Latency: $avgLatency ms" -ForegroundColor $latencyColor
            
            Write-Host ""
            
            # Cache stats
            Write-Host "Cache Metrics:" -ForegroundColor Yellow
            $cacheTotal = $Metrics.CacheHits + $Metrics.CacheMisses
            $cacheHitRate = $(if ($cacheTotal -gt 0) { 
                [math]::Round($Metrics.CacheHits / $cacheTotal * 100, 1) 
            } else { 0 }
            $cacheColor = $(if ($cacheHitRate -gt 90){"Green"}elseif($cacheHitRate -gt 80){"Yellow"}else{"Red"}
            Write-Host "  Hit Rate: $cacheHitRate%" -ForegroundColor $cacheColor
            Write-Host "  Hits: $($Metrics.CacheHits) | Misses: $($Metrics.CacheMisses)" -ForegroundColor Gray
            
            Write-Host ""
            
            # Quantization distribution
            Write-Host "Quantization Distribution:" -ForegroundColor Yellow
            $totalQuant = $Metrics.INT8Count + $Metrics.BF16Count + $Metrics.FP32Count
            if ($totalQuant -gt 0) {
                $int8Pct = [math]::Round($Metrics.INT8Count / $totalQuant * 100, 1)
                $bf16Pct = [math]::Round($Metrics.BF16Count / $totalQuant * 100, 1)
                $fp32Pct = [math]::Round($Metrics.FP32Count / $totalQuant * 100, 1)
                
                Write-Host "  INT8: $int8Pct% ($($Metrics.INT8Count))" -ForegroundColor Green
                Write-Host "  BF16: $bf16Pct% ($($Metrics.BF16Count))" -ForegroundColor Cyan
                Write-Host "  FP32: $fp32Pct% ($($Metrics.FP32Count))" -ForegroundColor Yellow
            }
            
            Write-Host ""
            
            # Security
            Write-Host "Security:" -ForegroundColor Yellow
            $secColor = $(if ($Metrics.SecurityEvents -eq 0){"Green"}else{"Red"}
            Write-Host "  Events: $($Metrics.SecurityEvents)" -ForegroundColor $secColor
            
            Write-Host ""
            Write-Host "================================================" -ForegroundColor Cyan
            Write-Host "Press Ctrl+C to exit" -ForegroundColor DarkGray
            
            Start-Sleep -Seconds 2
        }
    } finally {
        Stop-Job $simJob -ErrorAction SilentlyContinue
        Remove-Job $simJob -ErrorAction SilentlyContinue
    }
}

# =============================================================================
# Main Execution
# =============================================================================
switch ($Command.ToLower()) {
    "start" { Start-TelemetryStack }
    "stop" { Stop-TelemetryStack }
    "status" { Show-TelemetryStatus }
    "simulate" { Start-SimulationMode }
    "dashboard-only" { Show-DashboardOnly }
    default { 
        Write-Host "Usage: .\telemetry-start.ps1 -Command [start|stop|status|simulate|dashboard-only]" -ForegroundColor Yellow
        Show-TelemetryStatus
    }
}
