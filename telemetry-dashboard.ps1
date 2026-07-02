# RawrXD Telemetry Dashboard
# PowerShell-based metrics collector and Prometheus exporter

param(
    [int]$Port = 9090,
    [int]$FlushInterval = 5,
    [switch]$EnableGrafana = $false
)

$ErrorActionPreference = "Stop"

# =============================================================================
# Configuration
# =============================================================================
$Config = @{
    BufferName = "Global\RawrXD_Telemetry_Buffer"
    BufferSize = 65536
    EventSize = 64
    MaxEvents = 1024
    Port = $Port
    FlushInterval = $FlushInterval
}

# Metric storage
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
    
    # Histogram buckets for latency
    LatencyBuckets = @(0, 0, 0, 0, 0)  # <10ms, <20ms, <50ms, <100ms, >100ms
}

# =============================================================================
# Banner
# =============================================================================
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "RawrXD Telemetry Dashboard" -ForegroundColor Cyan
Write-Host "Prometheus Endpoint: http://localhost:$Port/metrics" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""

# =============================================================================
# Memory-Mapped Buffer Access
# =============================================================================
function Connect-TelemetryBuffer {
    Write-Host "[Setup] Connecting to telemetry buffer..." -ForegroundColor Yellow
    
    try {
        # Open existing file mapping
        $hMapFile = [System.IO.MemoryMappedFiles.MemoryMappedFile]::OpenExisting($Config.BufferName)
        $accessor = $hMapFile.CreateViewAccessor()
        
        Write-Host "  ✓ Connected to telemetry buffer" -ForegroundColor Green
        return @{
            Handle = $hMapFile
            Accessor = $accessor
        }
    } catch {
        Write-Host "  ✗ Failed to connect: $_" -ForegroundColor Red
        Write-Host "  Starting in simulation mode..." -ForegroundColor Yellow
        return $null
    }
}

# =============================================================================
# Event Processing
# =============================================================================
function Process-TelemetryEvent {
    param($EventData)
    
    # Parse event structure
    $timestamp = [BitConverter]::ToUInt64($EventData, 0)
    $metricType = [BitConverter]::ToUInt32($EventData, 8)
    $sessionId = [BitConverter]::ToUInt32($EventData, 12)
    $tokenCount = [BitConverter]::ToUInt32($EventData, 16)
    $latencyUs = [BitConverter]::ToUInt32($EventData, 20)
    $quantType = $EventData[24]
    $cacheHit = $EventData[25]
    
    # Update counters
    switch ($metricType) {
        1 { $script:Metrics.InferenceCount++ }  # INFERENCE_START
        3 { $script:Metrics.TokenCount += $tokenCount }  # TOKEN_GENERATED
        7 { $script:Metrics.SecurityEvents++ }  # SECURITY_EVENT
    }
    
    # Update latency
    if ($latencyUs -gt 0) {
        $script:Metrics.LatencyTotal += $latencyUs
        
        # Update histogram
        $latencyMs = $latencyUs / 1000.0
        if ($latencyMs -lt 10) { $script:Metrics.LatencyBuckets[0]++ }
        elseif ($latencyMs -lt 20) { $script:Metrics.LatencyBuckets[1]++ }
        elseif ($latencyMs -lt 50) { $script:Metrics.LatencyBuckets[2]++ }
        elseif ($latencyMs -lt 100) { $script:Metrics.LatencyBuckets[3]++ }
        else { $script:Metrics.LatencyBuckets[4]++ }
    }
    
    # Update cache stats
    if ($cacheHit) { $script:Metrics.CacheHits++ }
    else { $script:Metrics.CacheMisses++ }
    
    # Update quantization stats
    switch ($quantType) {
        0 { $script:Metrics.INT8Count++ }
        1 { $script:Metrics.BF16Count++ }
        2 { $script:Metrics.FP32Count++ }
    }
}

# =============================================================================
# Prometheus Metrics Endpoint
# =============================================================================
function Start-PrometheusEndpoint {
    param($Buffer)
    
    $listener = New-Object System.Net.HttpListener
    $listener.Prefixes.Add("http://localhost:$($Config.Port)/")
    $listener.Start()
    
    Write-Host "[Server] Prometheus endpoint started on port $($Config.Port)" -ForegroundColor Green
    Write-Host "  Metrics: http://localhost:$($Config.Port)/metrics" -ForegroundColor Gray
    Write-Host "  Health:  http://localhost:$($Config.Port)/health" -ForegroundColor Gray
    Write-Host ""
    
    while ($listener.IsListening) {
        $context = $listener.GetContext()
        $request = $context.Request
        $response = $context.Response
        
        switch ($request.Url.LocalPath) {
            "/metrics" {
                $metricsText = Get-PrometheusMetrics
                $buffer = [System.Text.Encoding]::UTF8.GetBytes($metricsText)
                $response.ContentType = "text/plain; version=0.0.4"
                $response.OutputStream.Write($buffer, 0, $buffer.Length)
            }
            
            "/health" {
                $healthText = "OK`n"
                $buffer = [System.Text.Encoding]::UTF8.GetBytes($healthText)
                $response.OutputStream.Write($buffer, 0, $buffer.Length)
            }
            default {
                $response.StatusCode = 404
            }
        }
        
        $response.Close()
    }
}

function Get-PrometheusMetrics {
    $output = @()
    
    # Inference metrics
    $output += "# HELP rawrxd_inference_total Total inference requests"
    $output += "# TYPE rawrxd_inference_total counter"
    $output += "rawrxd_inference_total $($Metrics.InferenceCount)"
    
    $output += "# HELP rawrxd_tokens_generated_total Total tokens generated"
    $output += "# TYPE rawrxd_tokens_generated_total counter"
    $output += "rawrxd_tokens_generated_total $($Metrics.TokenCount)"
    
    # Latency metrics
    $avgLatency = if ($Metrics.InferenceCount -gt 0) { 
        [math]::Round($Metrics.LatencyTotal / $Metrics.InferenceCount / 1000.0, 2) 
    } else { 0 }
    
    $output += "# HELP rawrxd_latency_average_ms Average inference latency"
    $output += "# TYPE rawrxd_latency_average_ms gauge"
    $output += "rawrxd_latency_average_ms $avgLatency"
    
    $output += "# HELP rawrxd_latency_histogram Latency distribution"
    $output += "# TYPE rawrxd_latency_histogram histogram"
    $output += 'rawrxd_latency_histogram_bucket{le="10"} ' + $Metrics.LatencyBuckets[0]
    $output += 'rawrxd_latency_histogram_bucket{le="20"} ' + ($Metrics.LatencyBuckets[0] + $Metrics.LatencyBuckets[1])
    $output += 'rawrxd_latency_histogram_bucket{le="50"} ' + ($Metrics.LatencyBuckets[0] + $Metrics.LatencyBuckets[1] + $Metrics.LatencyBuckets[2])
    $output += 'rawrxd_latency_histogram_bucket{le="100"} ' + ($Metrics.LatencyBuckets[0] + $Metrics.LatencyBuckets[1] + $Metrics.LatencyBuckets[2] + $Metrics.LatencyBuckets[3])
    $output += 'rawrxd_latency_histogram_bucket{le="+Inf"} ' + ($Metrics.LatencyBuckets[0] + $Metrics.LatencyBuckets[1] + $Metrics.LatencyBuckets[2] + $Metrics.LatencyBuckets[3] + $Metrics.LatencyBuckets[4])
    
    # Cache metrics
    $cacheTotal = $Metrics.CacheHits + $Metrics.CacheMisses
    $cacheHitRate = if ($cacheTotal -gt 0) { 
        [math]::Round($Metrics.CacheHits / $cacheTotal * 100, 2) 
    } else { 0 }
    
    $output += "# HELP rawrxd_cache_hits_total Total cache hits"
    $output += "# TYPE rawrxd_cache_hits_total counter"
    $output += "rawrxd_cache_hits_total $($Metrics.CacheHits)"
    
    $output += "# HELP rawrxd_cache_misses_total Total cache misses"
    $output += "# TYPE rawrxd_cache_misses_total counter"
    $output += "rawrxd_cache_misses_total $($Metrics.CacheMisses)"
    
    $output += "# HELP rawrxd_cache_hit_rate_percent Cache hit rate"
    $output += "# TYPE rawrxd_cache_hit_rate_percent gauge"
    $output += "rawrxd_cache_hit_rate_percent $cacheHitRate"
    
    # Quantization metrics
    $output += "# HELP rawrxd_quantization_usage Quantization type usage"
    $output += "# TYPE rawrxd_quantization_usage counter"
    $output += 'rawrxd_quantization_usage{type="INT8"} ' + $Metrics.INT8Count
    $output += 'rawrxd_quantization_usage{type="BF16"} ' + $Metrics.BF16Count
    $output += 'rawrxd_quantization_usage{type="FP32"} ' + $Metrics.FP32Count
    
    # Security metrics
    $output += "# HELP rawrxd_security_events_total Total security events"
    $output += "# TYPE rawrxd_security_events_total counter"
    $output += "rawrxd_security_events_total $($Metrics.SecurityEvents)"
    
    return ($output -join "`n") + "`n"
}

# =============================================================================
# Console Dashboard
# =============================================================================
function Show-Dashboard {
    while ($true) {
        Clear-Host
        
        Write-Host "================================================" -ForegroundColor Cyan
        Write-Host "RawrXD Telemetry Dashboard (Real-time)" -ForegroundColor Cyan
        Write-Host "================================================" -ForegroundColor Cyan
        Write-Host ""
        
        # Inference stats
        Write-Host "Inference Metrics:" -ForegroundColor Yellow
        Write-Host "  Total Inferences: $($Metrics.InferenceCount)" -ForegroundColor White
        Write-Host "  Total Tokens: $($Metrics.TokenCount)" -ForegroundColor White
        
        $avgLatency = if ($Metrics.InferenceCount -gt 0) { 
            [math]::Round($Metrics.LatencyTotal / $Metrics.InferenceCount / 1000.0, 2) 
        } else { 0 }
        Write-Host "  Avg Latency: $avgLatency ms" -ForegroundColor $(if($avgLatency -lt 25){"Green"}else{"Yellow"})
        
        Write-Host ""
        
        # Cache stats
        Write-Host "Cache Metrics:" -ForegroundColor Yellow
        $cacheTotal = $Metrics.CacheHits + $Metrics.CacheMisses
        $cacheHitRate = if ($cacheTotal -gt 0) { 
            [math]::Round($Metrics.CacheHits / $cacheTotal * 100, 1) 
        } else { 0 }
        Write-Host "  Hit Rate: $cacheHitRate%" -ForegroundColor $(if($cacheHitRate -gt 90){"Green"}else{"Yellow"})
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
        Write-Host "  Events: $($Metrics.SecurityEvents)" -ForegroundColor $(if($Metrics.SecurityEvents -eq 0){"Green"}else{"Red"})
        
        Write-Host ""
        Write-Host "================================================" -ForegroundColor Cyan
        Write-Host "Prometheus: http://localhost:$($Config.Port)/metrics" -ForegroundColor Gray
        Write-Host "Press Ctrl+C to exit" -ForegroundColor DarkGray
        
        Start-Sleep -Seconds $Config.FlushInterval
    }
}

# =============================================================================
# Simulation Mode (for testing without actual buffer)
# =============================================================================
function Start-Simulation {
    Write-Host "[Simulation] Generating synthetic metrics..." -ForegroundColor Yellow
    
    while ($true) {
        # Simulate inference events
        $script:Metrics.InferenceCount += (Get-Random -Minimum 1 -Maximum 5)
        $script:Metrics.TokenCount += (Get-Random -Minimum 10 -Maximum 100)
        $script:Metrics.LatencyTotal += (Get-Random -Minimum 15000 -Maximum 25000)  # 15-25ms
        
        # Simulate cache behavior
        if ((Get-Random) -gt 0.1) { $script:Metrics.CacheHits++ }
        else { $script:Metrics.CacheMisses++ }
        
        # Simulate quantization distribution (mostly INT8)
        $r = Get-Random
        if ($r -lt 0.85) { $script:Metrics.INT8Count++ }
        elseif ($r -lt 0.95) { $script:Metrics.BF16Count++ }
        else { $script:Metrics.FP32Count++ }
        
        Start-Sleep -Milliseconds 500
    }
}

# =============================================================================
# Main Execution
# =============================================================================

# Connect to telemetry buffer
$Buffer = Connect-TelemetryBuffer

# Start simulation in background if no buffer
if (-not $Buffer) {
    Start-Job -ScriptBlock ${function:Start-Simulation} | Out-Null
}

# Start Prometheus endpoint in background
Start-Job -ScriptBlock {
    param($Port)
    Start-PrometheusEndpoint -Port $Port
} -ArgumentList $Config.Port | Out-Null

# Show console dashboard
Show-Dashboard
