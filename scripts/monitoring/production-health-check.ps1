#!/usr/bin/env pwsh
#requires -Version 7.0

<#
.SYNOPSIS
    Phase K.3/5: Production Health Check
    
.DESCRIPTION
    Comprehensive production health monitoring:
    - Service availability checks
    - Performance metrics validation
    - Resource utilization monitoring
    - Alert generation for anomalies
    - Integration with PagerDuty/OpsGenie
    
.PARAMETER Environment
    Target environment (staging, production)
    
.PARAMETER Endpoint
    Health check endpoint (default: http://localhost:8080/health)
    
.PARAMETER PrometheusUrl
    Prometheus URL for metrics (default: http://localhost:9090)
    
.PARAMETER AlertManagerUrl
    AlertManager URL (default: http://localhost:9093)
    
.PARAMETER CheckInterval
    Interval between checks in seconds (default: 60)
    
.PARAMETER RunOnce
    Run check once and exit (default: continuous monitoring)
    
.PARAMETER GenerateReport
    Generate health report file
    
.EXAMPLE
    .\production-health-check.ps1 -Environment production
    
.EXAMPLE
    .\production-health-check.ps1 -Environment production -RunOnce -GenerateReport
#
>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("staging", "production")]
    [string]$Environment,
    
    [Parameter(Mandatory=$false)]
    [string]$Endpoint = "http://localhost:8080/health",
    
    [Parameter(Mandatory=$false)]
    [string]$PrometheusUrl = "http://localhost:9090",
    
    [Parameter(Mandatory=$false)]
    [string]$AlertManagerUrl = "http://localhost:9093",
    
    [Parameter(Mandatory=$false)]
    [int]$CheckInterval = 60,
    
    [Parameter(Mandatory=$false)]
    [switch]$RunOnce,
    
    [Parameter(Mandatory=$false)]
    [switch]$GenerateReport
)

$ErrorActionPreference = "Continue"

# Banner
Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║  Phase K.3/5: Production Health Check                            ║
║  Comprehensive Monitoring with Alert Integration                  ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

Write-Host "Configuration:" -ForegroundColor Yellow
Write-Host "  Environment: $Environment"
Write-Host "  Endpoint: $Endpoint"
Write-Host "  Prometheus: $PrometheusUrl"
Write-Host "  AlertManager: $AlertManagerUrl"
Write-Host "  Check Interval: $CheckInterval seconds"
Write-Host "  Mode: $(if ($RunOnce) { 'Single check' } else { 'Continuous monitoring' })"
Write-Host ""

# Health check thresholds
$thresholds = @{
    error_rate = 1.0           # 1% error rate threshold
    p99_latency = 100           # 100ms P99 latency threshold
    cpu_utilization = 80        # 80% CPU threshold
    memory_utilization = 85     # 85% memory threshold
    gpu_utilization = 90        # 90% GPU threshold
    disk_usage = 90             # 90% disk threshold
}

# Alert state tracking
$alertState = @{}
$checkCount = 0
$healthyCount = 0

function Send-Alert {
    param(
        [string]$Severity,
        [string]$AlertName,
        [string]$Description,
        [hashtable]$Labels
    )
    
    $alertId = "$AlertName-$($Labels.instance)"
    
    # Check if alert already firing
    if ($alertState.ContainsKey($alertId) -and $alertState[$alertId] -eq $Severity) {
        return
    }
    
    $alertState[$alertId] = $Severity
    
    $alert = @{
        labels = $Labels + @{
            alertname = $AlertName
            severity = $Severity
            environment = $Environment
        }
        annotations = @{
            summary = $AlertName
            description = $Description
        }
        startsAt = (Get-Date -Format "o")
    }
    
    try {
        Invoke-RestMethod -Uri "$AlertManagerUrl/api/v1/alerts" -Method Post -Body ($alert | ConvertTo-Json -Depth 10) -ContentType "application/json" -TimeoutSec 10
        Write-Host "  🚨 ALERT SENT: $AlertName [$Severity]" -ForegroundColor Red
    } catch {
        Write-Host "  ⚠️ Failed to send alert: $_" -ForegroundColor Yellow
    }
}

function Clear-Alert {
    param(
        [string]$AlertName,
        [hashtable]$Labels
    )
    
    $alertId = "$AlertName-$($Labels.instance)"
    
    if ($alertState.ContainsKey($alertId)) {
        $alertState.Remove($alertId)
        Write-Host "  ✅ ALERT CLEARED: $AlertName" -ForegroundColor Green
    }
}

function Test-ServiceHealth {
    param([string]$Url)
    
    try {
        $response = Invoke-RestMethod -Uri $Url -TimeoutSec 10 -ErrorAction Stop
        return @{
            healthy = ($response.status -eq "healthy")
            response = $response
            error = $null
        }
    } catch {
        return @{
            healthy = $false
            response = $null
            error = $_.Exception.Message
        }
    }
}

function Get-PrometheusMetric {
    param([string]$Query)
    
    try {
        $encodedQuery = [System.Web.HttpUtility]::UrlEncode($Query)
        $response = Invoke-RestMethod -Uri "$PrometheusUrl/api/v1/query?query=$encodedQuery" -TimeoutSec 10
        
        if ($response.data.result.Count -gt 0) {
            return [double]$response.data.result[0].value[1]
        }
        return $null
    } catch {
        return $null
    }
}

function Invoke-HealthCheck {
    $timestamp = Get-Date
    $results = @{
        timestamp = $timestamp
        environment = $Environment
        checks = @{}
        overall_healthy = $true
        alerts = @()
    }
    
    Write-Host "`n[$(Get-Date -Format 'HH:mm:ss')] Health Check #$checkCount" -ForegroundColor Cyan
    
    # Check 1: Service Availability
    Write-Host "  Checking service availability..." -NoNewline
    $serviceHealth = Test-ServiceHealth -Url $Endpoint
    $results.checks.service_available = $serviceHealth.healthy
    
    if ($serviceHealth.healthy) {
        Write-Host " ✓ HEALTHY" -ForegroundColor Green
        Clear-Alert -AlertName "ServiceDown" -Labels @{ instance = $Endpoint }
    } else {
        Write-Host " ✗ UNHEALTHY" -ForegroundColor Red
        $results.overall_healthy = $false
        $results.alerts += "Service unavailable: $($serviceHealth.error)"
        Send-Alert -Severity "critical" -AlertName "ServiceDown" -Description "Service at $Endpoint is not responding: $($serviceHealth.error)" -Labels @{ instance = $Endpoint }
    }
    
    # Check 2: Error Rate
    Write-Host "  Checking error rate..." -NoNewline
    $errorRate = Get-PrometheusMetric -Query "sum(rate(rawrxd_requests_total{status=~`"5..`"}[5m])) / sum(rate(rawrxd_requests_total[5m])) * 100"
    $results.checks.error_rate = $errorRate
    
    if ($errorRate -eq $null) {
        Write-Host " ⚠️ NO DATA" -ForegroundColor Yellow
    } elseif ($errorRate -le $thresholds.error_rate) {
        Write-Host " ✓ $([math]::Round($errorRate, 2))%" -ForegroundColor Green
        Clear-Alert -AlertName "HighErrorRate" -Labels @{ instance = $Endpoint }
    } else {
        Write-Host " ✗ $([math]::Round($errorRate, 2))%" -ForegroundColor Red
        $results.overall_healthy = $false
        $results.alerts += "High error rate: $([math]::Round($errorRate, 2))%"
        Send-Alert -Severity "warning" -AlertName "HighErrorRate" -Description "Error rate is $([math]::Round($errorRate, 2))%, threshold is $($thresholds.error_rate)%" -Labels @{ instance = $Endpoint }
    }
    
    # Check 3: P99 Latency
    Write-Host "  Checking P99 latency..." -NoNewline
    $p99Latency = Get-PrometheusMetric -Query "histogram_quantile(0.99, sum(rate(rawrxd_request_duration_seconds_bucket[5m])) by (le)) * 1000"
    $results.checks.p99_latency_ms = $p99Latency
    
    if ($p99Latency -eq $null) {
        Write-Host " ⚠️ NO DATA" -ForegroundColor Yellow
    } elseif ($p99Latency -le $thresholds.p99_latency) {
        Write-Host " ✓ $([math]::Round($p99Latency, 2))ms" -ForegroundColor Green
        Clear-Alert -AlertName "HighLatency" -Labels @{ instance = $Endpoint }
    } else {
        Write-Host " ✗ $([math]::Round($p99Latency, 2))ms" -ForegroundColor Red
        $results.overall_healthy = $false
        $results.alerts += "High P99 latency: $([math]::Round($p99Latency, 2))ms"
        Send-Alert -Severity "warning" -AlertName "HighLatency" -Description "P99 latency is $([math]::Round($p99Latency, 2))ms, threshold is $($thresholds.p99_latency)ms" -Labels @{ instance = $Endpoint }
    }
    
    # Check 4: CPU Utilization
    Write-Host "  Checking CPU utilization..." -NoNewline
    $cpuUtil = Get-PrometheusMetric -Query "avg(rate(container_cpu_usage_seconds_total{container=`"rawrxd`"}[5m])) * 100"
    $results.checks.cpu_utilization = $cpuUtil
    
    if ($cpuUtil -eq $null) {
        Write-Host " ⚠️ NO DATA" -ForegroundColor Yellow
    } elseif ($cpuUtil -le $thresholds.cpu_utilization) {
        Write-Host " ✓ $([math]::Round($cpuUtil, 2))%" -ForegroundColor Green
        Clear-Alert -AlertName "HighCPU" -Labels @{ instance = $Endpoint }
    } else {
        Write-Host " ✗ $([math]::Round($cpuUtil, 2))%" -ForegroundColor Red
        $results.alerts += "High CPU: $([math]::Round($cpuUtil, 2))%"
        Send-Alert -Severity "warning" -AlertName "HighCPU" -Description "CPU utilization is $([math]::Round($cpuUtil, 2))%, threshold is $($thresholds.cpu_utilization)%" -Labels @{ instance = $Endpoint }
    }
    
    # Check 5: Memory Utilization
    Write-Host "  Checking memory utilization..." -NoNewline
    $memUtil = Get-PrometheusMetric -Query "avg(container_memory_working_set_bytes{container=`"rawrxd`"}) / avg(container_spec_memory_limit_bytes{container=`"rawrxd`"}) * 100"
    $results.checks.memory_utilization = $memUtil
    
    if ($memUtil -eq $null) {
        Write-Host " ⚠️ NO DATA" -ForegroundColor Yellow
    } elseif ($memUtil -le $thresholds.memory_utilization) {
        Write-Host " ✓ $([math]::Round($memUtil, 2))%" -ForegroundColor Green
        Clear-Alert -AlertName "HighMemory" -Labels @{ instance = $Endpoint }
    } else {
        Write-Host " ✗ $([math]::Round($memUtil, 2))%" -ForegroundColor Red
        $results.alerts += "High memory: $([math]::Round($memUtil, 2))%"
        Send-Alert -Severity "warning" -AlertName "HighMemory" -Description "Memory utilization is $([math]::Round($memUtil, 2))%, threshold is $($thresholds.memory_utilization)%" -Labels @{ instance = $Endpoint }
    }
    
    # Check 6: GPU Utilization (if available)
    Write-Host "  Checking GPU utilization..." -NoNewline
    $gpuUtil = Get-PrometheusMetric -Query "avg(rawrxd_gpu_utilization_percent)"
    $results.checks.gpu_utilization = $gpuUtil
    
    if ($gpuUtil -eq $null) {
        Write-Host " ⚠️ NO DATA" -ForegroundColor Yellow
    } elseif ($gpuUtil -le $thresholds.gpu_utilization) {
        Write-Host " ✓ $([math]::Round($gpuUtil, 2))%" -ForegroundColor Green
        Clear-Alert -AlertName "HighGPU" -Labels @{ instance = $Endpoint }
    } else {
        Write-Host " ✗ $([math]::Round($gpuUtil, 2))%" -ForegroundColor Red
        $results.alerts += "High GPU: $([math]::Round($gpuUtil, 2))%"
        Send-Alert -Severity "warning" -AlertName "HighGPU" -Description "GPU utilization is $([math]::Round($gpuUtil, 2))%, threshold is $($thresholds.gpu_utilization)%" -Labels @{ instance = $Endpoint }
    }
    
    # Summary
    if ($results.overall_healthy) {
        $healthyCount++
        Write-Host "  Overall: ✓ HEALTHY" -ForegroundColor Green
    } else {
        Write-Host "  Overall: ✗ UNHEALTHY" -ForegroundColor Red
    }
    
    return $results
}

# Main loop
if ($RunOnce) {
    $checkCount++
    $results = Invoke-HealthCheck
    
    if ($GenerateReport) {
        $reportFile = "health-reports/health-check-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
        New-Item -ItemType Directory -Force -Path "health-reports" | Out-Null
        $results | ConvertTo-Json -Depth 10 | Out-File -FilePath $reportFile
        Write-Host "`nReport saved: $reportFile" -ForegroundColor Cyan
    }
    
    exit ($results.overall_healthy ? 0 : 1)
} else {
    Write-Host "Starting continuous monitoring (Press Ctrl+C to stop)..." -ForegroundColor Yellow
    
    while ($true) {
        $checkCount++
        $results = Invoke-HealthCheck
        
        if ($GenerateReport) {
            $reportFile = "health-reports/health-check-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
            New-Item -ItemType Directory -Force -Path "health-reports" | Out-Null
            $results | ConvertTo-Json -Depth 10 | Out-File -FilePath $reportFile
        }
        
        Write-Host "  Next check in $CheckInterval seconds..." -ForegroundColor Gray
        Start-Sleep -Seconds $CheckInterval
    }
}
