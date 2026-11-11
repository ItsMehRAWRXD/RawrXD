# metrics_collector.ps1
# Phase H.5 Batch 1/5: Telemetry Ingestion Pipeline

param(
    [string]$Endpoint = "http://localhost:9090/api/v1/write",
    [int]$IntervalSeconds = 15,
    [string]$InstanceId = $env:COMPUTERNAME,
    [switch]$EnableRemoteWrite
)

$ErrorActionPreference = "Continue"

$MetricsConfig = @{
    Version = "1.0.0"
    InstanceId = $InstanceId
    Endpoint = $Endpoint
    Interval = $IntervalSeconds
    MetricsBuffer = @()
    MaxBufferSize = 1000
}

function Write-Log($Message, $Level = "INFO") {
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$timestamp] [$Level] $Message"
}

function Get-SystemMetrics {
    $metrics = @{}
    
    # CPU Usage
    $cpu = Get-Counter '\Processor(_Total)\% Processor Time' -SampleInterval 1 -MaxSamples 1 -ErrorAction SilentlyContinue
    if ($cpu) {
        $metrics['cpu_usage_percent'] = [math]::Round($cpu.CounterSamples[0].CookedValue, 2)
    }
    
    # Memory
    $memory = Get-CimInstance -ClassName Win32_OperatingSystem
    $metrics['memory_used_percent'] = [math]::Round((($memory.TotalVisibleMemorySize - $memory.FreePhysicalMemory) / $memory.TotalVisibleMemorySize) * 100, 2)
    $metrics['memory_free_mb'] = [math]::Round($memory.FreePhysicalMemory / 1024, 2)
    
    # Disk
    $disk = Get-PSDrive -Name C
    $metrics['disk_free_gb'] = [math]::Round($disk.Free / 1GB, 2)
    $metrics['disk_used_percent'] = [math]::Round((($disk.Used) / ($disk.Used + $disk.Free)) * 100, 2)
    
    # Network (if available)
    $network = Get-Counter '\Network Interface(*)\Bytes Total/sec' -ErrorAction SilentlyContinue
    if ($network) {
        $metrics['network_bytes_per_sec'] = [math]::Round(($network.CounterSamples | Measure-Object CookedValue -Sum).Sum, 2)
    }
    
    return $metrics
}

function Get-ServiceMetrics {
    $metrics = @{}
    
    $service = Get-Service -Name "RawrXD" -ErrorAction SilentlyContinue
    if ($service) {
        $metrics['service_status'] = if ($service.Status -eq "Running") { 1 } else { 0 }
        
        $process = Get-Process -Name "RawrXD" -ErrorAction SilentlyContinue
        if ($process) {
            $metrics['process_memory_mb'] = [math]::Round($process.WorkingSet64 / 1MB, 2)
            $metrics['process_cpu_percent'] = [math]::Round($process.CPU, 2)
            $metrics['process_threads'] = $process.Threads.Count
            $metrics['process_handles'] = $process.HandleCount
        }
    }
    else {
        $metrics['service_status'] = 0
    }
    
    return $metrics
}

function Get-InferenceMetrics {
    $metrics = @{}
    
    # Try to get metrics from RawrXD API
    try {
        $response = Invoke-RestMethod -Uri "http://localhost:8080/metrics" -TimeoutSec 2 -ErrorAction Stop
        $metrics['inference_tps'] = $response.tps
        $metrics['inference_latency_ms'] = $response.latency_avg
        $metrics['inference_queue_depth'] = $response.queue_depth
        $metrics['inference_active_requests'] = $response.active_requests
    }
    catch {
        # Service might not be running or metrics endpoint not available
        $metrics['inference_tps'] = 0
        $metrics['inference_latency_ms'] = 0
    }
    
    return $metrics
}

function Format-PrometheusMetrics($Metrics, $Timestamp) {
    $output = @()
    
    foreach ($metric in $Metrics.GetEnumerator()) {
        $output += "rawrxd_$($metric.Key){instance=`"$($MetricsConfig.InstanceId)`"} $($metric.Value) $Timestamp"
    }
    
    return $output -join "`n"
}

function Send-Metrics($Metrics) {
    if (-not $EnableRemoteWrite) {
        return
    }
    
    try {
        $body = $Metrics | ConvertTo-Json -Depth 3
        $response = Invoke-RestMethod -Uri $MetricsConfig.Endpoint -Method Post -Body $body -ContentType "application/json" -TimeoutSec 5
        Write-Log "Metrics sent successfully"
    }
    catch {
        Write-Log "Failed to send metrics: $_" "WARNING"
    }
}

function Start-MetricsCollection {
    Write-Log "Starting RawrXD Metrics Collector v$($MetricsConfig.Version)"
    Write-Log "Instance: $($MetricsConfig.InstanceId)"
    Write-Log "Interval: $($MetricsConfig.Interval) seconds"
    Write-Log "Remote Write: $EnableRemoteWrite"
    Write-Log ""
    
    while ($true) {
        $timestamp = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
        
        # Collect all metrics
        $allMetrics = @{}
        $allMetrics += Get-SystemMetrics
        $allMetrics += Get-ServiceMetrics
        $allMetrics += Get-InferenceMetrics
        $allMetrics['collection_timestamp'] = $timestamp
        
        # Format for Prometheus
        $prometheusFormat = Format-PrometheusMetrics -Metrics $allMetrics -Timestamp $timestamp
        
        # Output to console (can be scraped by Prometheus)
        Write-Output $prometheusFormat
        
        # Send to remote endpoint if enabled
        if ($EnableRemoteWrite) {
            Send-Metrics -Metrics $allMetrics
        }
        
        # Also write to local file for persistence
        $metricsFile = Join-Path $env:ProgramData "RawrXD\metrics\current.json"
        $allMetrics | ConvertTo-Json | Out-File $metricsFile -Force
        
        Start-Sleep -Seconds $MetricsConfig.Interval
    }
}

# Main execution
Start-MetricsCollection
