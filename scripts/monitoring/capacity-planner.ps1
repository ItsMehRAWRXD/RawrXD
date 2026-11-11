#!/usr/bin/env pwsh
#requires -Version 7.0

<#
.SYNOPSIS
    Phase K.4/5: Capacity Planning
    
.DESCRIPTION
    Automated capacity planning and scaling recommendations:
    - Historical usage analysis
    - Trend forecasting
    - Cost optimization recommendations
    - Scaling threshold recommendations
    - Resource utilization projections
    
.PARAMETER Environment
    Target environment (staging, production)
    
.PARAMETER PrometheusUrl
    Prometheus URL for metrics (default: http://localhost:9090)
    
.PARAMETER DaysOfHistory
    Days of historical data to analyze (default: 30)
    
.PARAMETER ForecastDays
    Days to forecast (default: 30)
    
.PARAMETER GenerateReport
    Generate capacity report
    
.PARAMETER OutputFormat
    Output format (json, csv, table)
    
.EXAMPLE
    .\capacity-planner.ps1 -Environment production
    
.EXAMPLE
    .\capacity-planner.ps1 -Environment production -DaysOfHistory 60 -ForecastDays 90 -GenerateReport
#
>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("staging", "production")]
    [string]$Environment,
    
    [Parameter(Mandatory=$false)]
    [string]$PrometheusUrl = "http://localhost:9090",
    
    [Parameter(Mandatory=$false)]
    [int]$DaysOfHistory = 30,
    
    [Parameter(Mandatory=$false)]
    [int]$ForecastDays = 30,
    
    [Parameter(Mandatory=$false)]
    [switch]$GenerateReport,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("json", "csv", "table")]
    [string]$OutputFormat = "table"
)

$ErrorActionPreference = "Stop"

# Banner
Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║  Phase K.4/5: Capacity Planning                                    ║
║  Resource Forecasting and Scaling Recommendations               ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

Write-Host "Configuration:" -ForegroundColor Yellow
Write-Host "  Environment: $Environment"
Write-Host "  Prometheus: $PrometheusUrl"
    Write-Host "  History: $DaysOfHistory days"
    Write-Host "  Forecast: $ForecastDays days"
    Write-Host ""

# Helper function to query Prometheus
function Get-PrometheusRange {
    param([string]$Query, [datetime]$Start, [datetime]$End, [string]$Step = "1h")
    
    $startUnix = [DateTimeOffset]::new($Start).ToUnixTimeSeconds()
    $endUnix = [DateTimeOffset]::new($End).ToUnixTimeSeconds()
    
    $encodedQuery = [System.Web.HttpUtility]::UrlEncode($Query)
    $url = "$PrometheusUrl/api/v1/query_range?query=$encodedQuery&start=$startUnix&end=$endUnix&step=$Step"
    
    try {
        $response = Invoke-RestMethod -Uri $url -TimeoutSec 30
        return $response.data.result
    } catch {
        Write-Warning "Failed to query Prometheus: $_"
        return $null
    }
}

function Get-PrometheusInstant {
    param([string]$Query)
    
    $encodedQuery = [System.Web.HttpUtility]::UrlEncode($Query)
    try {
        $response = Invoke-RestMethod -Uri "$PrometheusUrl/api/v1/query?query=$encodedQuery" -TimeoutSec 10
        if ($response.data.result.Count -gt 0) {
            return [double]$response.data.result[0].value[1]
        }
        return $null
    } catch {
        return $null
    }
}

# Phase 1: Historical Analysis
Write-Host "[Phase 1/5] Analyzing historical usage..." -ForegroundColor Green

$endTime = Get-Date
$startTime = $endTime.AddDays(-$DaysOfHistory)

# Query metrics
$metrics = @{
    requests_per_second = "sum(rate(rawrxd_requests_total[$DaysOfHistory]))"
    cpu_utilization = "avg(rate(container_cpu_usage_seconds_total{container=`"rawrxd`"}[$DaysOfHistory])) * 100"
    memory_utilization = "avg(container_memory_working_set_bytes{container=`"rawrxd`"}) / avg(container_spec_memory_limit_bytes{container=`"rawrxd`"}) * 100"
    gpu_utilization = "avg(rawrxd_gpu_utilization_percent)"
    active_connections = "avg(rawrxd_active_connections)"
    inference_latency = "histogram_quantile(0.99, sum(rate(rawrxd_inference_duration_seconds_bucket[$DaysOfHistory])) by (le)) * 1000"
    tokens_per_second = "avg(rawrxd_tokens_per_second)"
}

$currentMetrics = @{}
foreach ($metric in $metrics.GetEnumerator()) {
    $value = Get-PrometheusInstant -Query $metric.Value
    $currentMetrics[$metric.Key] = $value
    Write-Host "  $($metric.Key): $(if ($value) { [math]::Round($value, 2) } else { 'N/A' })"
}

# Get historical data for trend analysis
$historicalData = @{}
$historicalQueries = @{
    request_rate = "sum(rate(rawrxd_requests_total[1h]))"
    cpu_usage = "avg(rate(container_cpu_usage_seconds_total{container=`"rawrxd`"}[1h])) * 100"
    memory_usage = "avg(container_memory_working_set_bytes{container=`"rawrxd`"} / container_spec_memory_limit_bytes{container=`"rawrxd`"} * 100)"
}

foreach ($query in $historicalQueries.GetEnumerator()) {
    Write-Host "  Fetching $($query.Key) history..." -NoNewline
    $data = Get-PrometheusRange -Query $query.Value -Start $startTime -End $endTime -Step "1h"
    $historicalData[$query.Key] = $data
    Write-Host " ✓"
}

Write-Host ""

# Phase 2: Trend Analysis
Write-Host "[Phase 2/5] Calculating trends..." -ForegroundColor Green

function Calculate-Trend {
    param([array]$Values)
    
    if ($Values.Count -lt 2) { return @{ slope = 0; r_squared = 0 } }
    
    $n = $Values.Count
    $sumX = 0
    $sumY = 0
    $sumXY = 0
    $sumX2 = 0
    $sumY2 = 0
    
    for ($i = 0; $i -lt $n; $i++) {
        $x = $i
        $y = $Values[$i]
        $sumX += $x
        $sumY += $y
        $sumXY += $x * $y
        $sumX2 += $x * $x
        $sumY2 += $y * $y
    }
    
    $slope = ($n * $sumXY - $sumX * $sumY) / ($n * $sumX2 - $sumX * $sumX)
    $intercept = ($sumY - $slope * $sumX) / $n
    
    # R-squared calculation
    $meanY = $sumY / $n
    $ssTotal = 0
    $ssResidual = 0
    
    for ($i = 0; $i -lt $n; $i++) {
        $predicted = $slope * $i + $intercept
        $ssTotal += [math]::Pow($Values[$i] - $meanY, 2)
        $ssResidual += [math]::Pow($Values[$i] - $predicted, 2)
    }
    
    $rSquared = if ($ssTotal -gt 0) { 1 - ($ssResidual / $ssTotal) } else { 0 }
    
    return @{
        slope = $slope
        intercept = $intercept
        r_squared = $rSquared
    }
}

$trends = @{}
foreach ($data in $historicalData.GetEnumerator()) {
    if ($data.Value -and $data.Value.Count -gt 0) {
        $values = $data.Value[0].values | ForEach-Object { [double]$_[1] }
        $trend = Calculate-Trend -Values $values
        $trends[$data.Key] = $trend
        
        $growthRate = if ($values[-1] -gt 0) { ($trend.slope * $values.Count / $values[-1]) * 100 } else { 0 }
        Write-Host "  $($data.Key): Growth rate $([math]::Round($growthRate, 2))%/period (R²=$([math]::Round($trend.r_squared, 2)))"
    }
}

Write-Host ""

# Phase 3: Capacity Forecasting
Write-Host "[Phase 3/5] Forecasting capacity needs..." -ForegroundColor Green

$forecasts = @{}
$capacityLimits = @{
    cpu = 80
    memory = 85
    gpu = 90
    requests = 10000  # requests per second
}

foreach ($trend in $trends.GetEnumerator()) {
    $currentValue = $currentMetrics[$trend.Key.Replace('_usage', '_utilization').Replace('_rate', '_per_second')]
    if ($currentValue -and $trend.Value.slope -ne 0) {
        $forecastValue = $currentValue + ($trend.Value.slope * $ForecastDays * 24)  # Convert to hourly slope
        $forecasts[$trend.Key] = $forecastValue
        
        $limit = $capacityLimits[($trend.Key -replace '_.*', '')]
        $daysToLimit = if ($trend.Value.slope -gt 0) { 
            [math]::Floor(($limit - $currentValue) / ($trend.Value.slope * 24)) 
        } else { 
            "N/A" 
        }
        
        Write-Host "  $($trend.Key): Current=$([math]::Round($currentValue, 2)), Forecast=$([math]::Round($forecastValue, 2)), Days to limit=$daysToLimit"
    }
}

Write-Host ""

# Phase 4: Scaling Recommendations
Write-Host "[Phase 4/5] Generating scaling recommendations..." -ForegroundColor Green

$recommendations = @()

# CPU scaling recommendation
$cpuForecast = $forecasts['cpu_usage']
if ($cpuForecast -gt $capacityLimits.cpu) {
    $recommendations += @{
        resource = "CPU"
        current_utilization = $currentMetrics['cpu_utilization']
        forecasted_utilization = $cpuForecast
        recommendation = "SCALE_UP"
        urgency = if ($cpuForecast -gt 95) { "CRITICAL" } else { "HIGH" }
        action = "Increase CPU allocation by $([math]::Ceiling(($cpuForecast - $capacityLimits.cpu) / $capacityLimits.cpu * 100))% or add $([math]::Ceiling(($cpuForecast - $capacityLimits.cpu) / 10)) nodes"
        timeframe = if ($cpuForecast -gt 95) { "Immediate" } else { "Within 7 days" }
    }
} elseif ($currentMetrics['cpu_utilization'] -lt 30) {
    $recommendations += @{
        resource = "CPU"
        current_utilization = $currentMetrics['cpu_utilization']
        forecasted_utilization = $cpuForecast
        recommendation = "SCALE_DOWN"
        urgency = "LOW"
        action = "Consider reducing CPU allocation to optimize costs"
        timeframe = "Next maintenance window"
    }
}

# Memory scaling recommendation
$memForecast = $forecasts['memory_usage']
if ($memForecast -gt $capacityLimits.memory) {
    $recommendations += @{
        resource = "Memory"
        current_utilization = $currentMetrics['memory_utilization']
        forecasted_utilization = $memForecast
        recommendation = "SCALE_UP"
        urgency = if ($memForecast -gt 95) { "CRITICAL" } else { "HIGH" }
        action = "Increase memory allocation by $([math]::Ceiling(($memForecast - $capacityLimits.memory) / $capacityLimits.memory * 100))%"
        timeframe = if ($memForecast -gt 95) { "Immediate" } else { "Within 7 days" }
    }
}

# Request rate recommendation
$reqForecast = $forecasts['request_rate']
if ($reqForecast -gt $capacityLimits.requests) {
    $recommendations += @{
        resource = "Request Rate"
        current_utilization = $currentMetrics['requests_per_second']
        forecasted_utilization = $reqForecast
        recommendation = "SCALE_UP"
        urgency = "HIGH"
        action = "Add $([math]::Ceiling($reqForecast / $capacityLimits.requests)) load balancer instances"
        timeframe = "Within 14 days"
    }
}

# GPU recommendation (if applicable)
if ($currentMetrics['gpu_utilization'] -and $currentMetrics['gpu_utilization'] -gt 95) {
    $recommendations += @{
        resource = "GPU"
        current_utilization = $currentMetrics['gpu_utilization']
        forecasted_utilization = $currentMetrics['gpu_utilization']
        recommendation = "OPTIMIZE"
        urgency = "MEDIUM"
        action = "GPU at capacity - consider model quantization or batch size optimization"
        timeframe = "Within 30 days"
    }
}

foreach ($rec in $recommendations) {
    $color = switch ($rec.urgency) {
        "CRITICAL" { "Red" }
        "HIGH" { "Yellow" }
        "MEDIUM" { "Cyan" }
        default { "Green" }
    }
    Write-Host "  [$($rec.urgency)] $($rec.resource): $($rec.recommendation)" -ForegroundColor $color
    Write-Host "    Current: $([math]::Round($rec.current_utilization, 2))%, Forecast: $([math]::Round($rec.forecasted_utilization, 2))%"
    Write-Host "    Action: $($rec.action)"
    Write-Host "    Timeframe: $($rec.timeframe)"
    Write-Host ""
}

# Phase 5: Cost Optimization
Write-Host "[Phase 5/5] Cost optimization analysis..." -ForegroundColor Green

$costOptimizations = @()

# Check for over-provisioning
if ($currentMetrics['cpu_utilization'] -lt 20 -and $currentMetrics['memory_utilization'] -lt 30) {
    $costOptimizations += @{
        type = "OVER_PROVISIONED"
        description = "Resources significantly underutilized"
        potential_savings = "30-40%"
        action = "Right-size instances or consolidate workloads"
    }
}

# Check for off-peak scaling opportunities
$costOptimizations += @{
    type = "AUTO_SCALING"
    description = "Implement time-based auto-scaling for off-peak hours"
    potential_savings = "20-30%"
    action = "Configure HPA with custom metrics for inference load"
}

# Spot instance recommendation
$costOptimizations += @{
    type = "SPOT_INSTANCES"
    description = "Use spot/preemptible instances for non-critical inference"
    potential_savings = "60-90%"
    action = "Configure spot instance pools with fallback to on-demand"
}

foreach ($opt in $costOptimizations) {
    Write-Host "  [$($opt.type)] Potential savings: $($opt.potential_savings)" -ForegroundColor Green
    Write-Host "    $($opt.description)"
    Write-Host "    Action: $($opt.action)"
    Write-Host ""
}

# Generate Report
if ($GenerateReport) {
    $report = @{
        timestamp = Get-Date -Format "o"
        environment = $Environment
        analysis_period_days = $DaysOfHistory
        forecast_period_days = $ForecastDays
        current_metrics = $currentMetrics
        trends = $trends
        forecasts = $forecasts
        recommendations = $recommendations
        cost_optimizations = $costOptimizations
    }
    
    $reportFile = "capacity-reports/capacity-plan-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
    New-Item -ItemType Directory -Force -Path "capacity-reports" | Out-Null
    $report | ConvertTo-Json -Depth 10 | Out-File -FilePath $reportFile
    Write-Host "Report saved: $reportFile" -ForegroundColor Cyan
}

# Output based on format
if ($OutputFormat -eq "json") {
    $output = @{
        current_metrics = $currentMetrics
        recommendations = $recommendations
        cost_optimizations = $costOptimizations
    }
    $output | ConvertTo-Json -Depth 10
} elseif ($OutputFormat -eq "csv") {
    $recommendations | ForEach-Object {
        "$($_.resource),$($_.recommendation),$($_.urgency),`"$($_.action)`",$($_.timeframe)"
    }
}

# Final Summary
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "CAPACITY PLANNING COMPLETE" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "Recommendations: $($recommendations.Count)"
Write-Host "Cost optimizations: $($costOptimizations.Count)"
Write-Host ""
Write-Host "✅ Capacity analysis complete!" -ForegroundColor Green
