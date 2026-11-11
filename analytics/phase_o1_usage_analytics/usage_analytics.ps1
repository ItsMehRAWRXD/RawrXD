#!/usr/bin/env pwsh
#requires -Version 7.0

<#
.SYNOPSIS
    Phase O.1: Usage Analytics Engine
    
.DESCRIPTION
    Comprehensive usage analytics for RawrXD SaaS platform.
    Tracks token consumption, API usage patterns, and performance metrics.
    
.PARAMETER Action
    Action to perform: analyze, trends, forecast, export
    
.PARAMETER Period
    Analysis period: daily, weekly, monthly
    
.PARAMETER TenantId
    Specific tenant to analyze (optional)
    
.EXAMPLE
    .\usage_analytics.ps1 -Action analyze -Period monthly
    .\usage_analytics.ps1 -Action trends -TenantId "acme-corp"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("analyze", "trends", "forecast", "export", "dashboard")]
    [string]$Action,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("daily", "weekly", "monthly")]
    [string]$Period = "daily",
    
    [Parameter(Mandatory=$false)]
    [string]$TenantId,
    
    [Parameter(Mandatory=$false)]
    [string]$DataPath = ".\analytics_data",
    
    [Parameter(Mandatory=$false)]
    [int]$ForecastDays = 30
)

$ErrorActionPreference = "Stop"

# Analytics cache
$AnalyticsCache = @{
    LastUpdate = $null
    Metrics = @{}
    Trends = @{}
}

function Write-AnalyticsHeader {
    Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║  Phase O.1: Usage Analytics Engine                                 ║
║  Data-driven insights for RawrXD SaaS platform                     ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan
}

function Initialize-Analytics {
    if (-not (Test-Path $DataPath)) {
        New-Item -ItemType Directory -Path $DataPath -Force | Out-Null
    }
    
    $cacheFile = Join-Path $DataPath "analytics_cache.json"
    if (Test-Path $cacheFile) {
        $script:AnalyticsCache = Get-Content -Path $cacheFile -Raw | ConvertFrom-Json -AsHashtable
    }
}

function Save-Analytics {
    $cacheFile = Join-Path $DataPath "analytics_cache.json"
    $script:AnalyticsCache.LastUpdate = Get-Date -Format "o"
    $script:AnalyticsCache | ConvertTo-Json -Depth 10 | Set-Content -Path $cacheFile
}

function Get-UsageData {
    param($TenantFilter)
    
    # Load from Phase M metering data
    $meteringPath = "..\saas\phase_m2_usage_metering\metering_data\usage_db.json"
    if (Test-Path $meteringPath) {
        $data = Get-Content -Path $meteringPath -Raw | ConvertFrom-Json -AsHashtable
        
        if ($TenantFilter) {
            return $data.Tenants[$TenantFilter]
        }
        return $data.Tenants
    }
    return @{}
}

function Measure-UsageMetrics {
    param($Period)
    
    Write-Host "`nAnalyzing usage metrics ($Period)..." -ForegroundColor Yellow
    
    $tenants = Get-UsageData
    $metrics = @{
        Period = $Period
        GeneratedAt = Get-Date -Format "o"
        Summary = @{
            TotalTenants = $tenants.Count
            TotalTokens = 0
            TotalRequests = 0
            TotalRevenue = 0.0
            AvgTokensPerTenant = 0
            AvgLatencyMs = 0
        }
        ByTier = @{
            free = @{ Count = 0; Tokens = 0; Revenue = 0 }
            standard = @{ Count = 0; Tokens = 0; Revenue = 0 }
            enterprise = @{ Count = 0; Tokens = 0; Revenue = 0 }
        }
        TopConsumers = @()
        DailyPatterns = @{}
    }
    
    foreach ($tenant in $tenants.GetEnumerator()) {
        $tier = $tenant.Value.Tier
        $metrics.ByTier[$tier].Count++
        $metrics.ByTier[$tier].Tokens += $tenant.Value.TotalTokens
        $metrics.ByTier[$tier].Revenue += $tenant.Value.TotalCost
        
        $metrics.Summary.TotalTokens += $tenant.Value.TotalTokens
        $metrics.Summary.TotalRequests += $tenant.Value.TotalRequests
        $metrics.Summary.TotalRevenue += $tenant.Value.TotalCost
        
        # Track top consumers
        $metrics.TopConsumers += [PSCustomObject]@{
            TenantId = $tenant.Key
            Tokens = $tenant.Value.TotalTokens
            Tier = $tier
        }
        
        # Analyze daily patterns
        foreach ($day in $tenant.Value.DailyUsage.GetEnumerator()) {
            if (-not $metrics.DailyPatterns.ContainsKey($day.Key)) {
                $metrics.DailyPatterns[$day.Key] = @{ Tokens = 0; Requests = 0 }
            }
            $metrics.DailyPatterns[$day.Key].Tokens += $day.Value.Tokens
            $metrics.DailyPatterns[$day.Key].Requests += $day.Value.Requests
        }
    }
    
    # Calculate averages
    if ($metrics.Summary.TotalTenants -gt 0) {
        $metrics.Summary.AvgTokensPerTenant = [math]::Round($metrics.Summary.TotalTokens / $metrics.Summary.TotalTenants, 2)
    }
    
    # Sort top consumers
    $metrics.TopConsumers = $metrics.TopConsumers | Sort-Object Tokens -Descending | Select-Object -First 10
    
    $script:AnalyticsCache.Metrics[$Period] = $metrics
    Save-Analytics
    
    return $metrics
}

function Show-UsageAnalysis {
    param($Metrics)
    
    Write-Host "`nUsage Analysis Report" -ForegroundColor White
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    
    Write-Host "`nSummary:" -ForegroundColor Yellow
    Write-Host "  Total Tenants:    $($Metrics.Summary.TotalTenants)" -ForegroundColor Gray
    Write-Host "  Total Tokens:     $($Metrics.Summary.TotalTokens.ToString('N0'))" -ForegroundColor Gray
    Write-Host "  Total Requests:   $($Metrics.Summary.TotalRequests.ToString('N0'))" -ForegroundColor Gray
    Write-Host "  Total Revenue:    `$$("{0:N2}" -f $Metrics.Summary.TotalRevenue)" -ForegroundColor Green
    Write-Host "  Avg Tokens/Tenant: $($Metrics.Summary.AvgTokensPerTenant.ToString('N0'))" -ForegroundColor Gray
    
    Write-Host "`nBy Tier:" -ForegroundColor Yellow
    foreach ($tier in $Metrics.ByTier.GetEnumerator()) {
        $percent = if ($Metrics.Summary.TotalTokens -gt 0) { 
            [math]::Round(($tier.Value.Tokens / $Metrics.Summary.TotalTokens) * 100, 1) 
        } else { 0 }
        Write-Host "  $($tier.Key.PadEnd(12)): $($tier.Value.Count.ToString().PadStart(3)) tenants, $($tier.Value.Tokens.ToString('N0').PadStart(12)) tokens ($percent%)" -ForegroundColor Gray
    }
    
    Write-Host "`nTop 10 Consumers:" -ForegroundColor Yellow
    $rank = 1
    foreach ($consumer in $Metrics.TopConsumers) {
        Write-Host "  $rank. $($consumer.TenantId.PadEnd(20)) $($consumer.Tokens.ToString('N0').PadStart(12)) [$($consumer.Tier)]" -ForegroundColor Gray
        $rank++
    }
    
    Write-Host "`nDaily Pattern (last 7 days):" -ForegroundColor Yellow
    $recentDays = $Metrics.DailyPatterns.GetEnumerator() | Sort-Object Key | Select-Object -Last 7
    foreach ($day in $recentDays) {
        Write-Host "  $($day.Key): $($day.Value.Tokens.ToString('N0').PadStart(10)) tokens, $($day.Value.Requests.ToString('N0').PadStart(6)) requests" -ForegroundColor Gray
    }
}

function Measure-UsageTrends {
    param($TenantId)
    
    Write-Host "`nAnalyzing usage trends..." -ForegroundColor Yellow
    
    $tenants = Get-UsageData
    $trends = @{
        GeneratedAt = Get-Date -Format "o"
        TenantTrends = @()
        GlobalTrend = @{
            GrowthRate = 0
            TrendDirection = "stable"
        }
    }
    
    $tenantList = if ($TenantId) { @($TenantId) } else { $tenants.Keys }
    
    foreach ($id in $tenantList) {
        if (-not $tenants.ContainsKey($id)) { continue }
        
        $tenant = $tenants[$id]
        $dailyTokens = @()
        
        foreach ($day in ($tenant.DailyUsage.GetEnumerator() | Sort-Object Key)) {
            $dailyTokens += $day.Value.Tokens
        }
        
        if ($dailyTokens.Count -ge 3) {
            # Calculate growth rate
            $firstWeek = ($dailyTokens | Select-Object -First 7 | Measure-Object -Average).Average
            $lastWeek = ($dailyTokens | Select-Object -Last 7 | Measure-Object -Average).Average
            
            $growthRate = if ($firstWeek -gt 0) {
                [math]::Round((($lastWeek - $firstWeek) / $firstWeek) * 100, 2)
            } else { 0 }
            
            $trends.TenantTrends += @{
                TenantId = $id
                GrowthRate = $growthRate
                TrendDirection = if ($growthRate -gt 10) { "growing" } elseif ($growthRate -lt -10) { "declining" } else { "stable" }
                DailyAverage = [math]::Round(($dailyTokens | Measure-Object -Average).Average, 2)
                PeakDay = ($tenant.DailyUsage.GetEnumerator() | Sort-Object { $_.Value.Tokens } -Descending | Select-Object -First 1).Key
            }
        }
    }
    
    # Calculate global trend
    $growing = ($trends.TenantTrends | Where-Object { $_.TrendDirection -eq "growing" }).Count
    $declining = ($trends.TenantTrends | Where-Object { $_.TrendDirection -eq "declining" }).Count
    $stable = ($trends.TenantTrends | Where-Object { $_.TrendDirection -eq "stable" }).Count
    
    $trends.GlobalTrend.TrendDirection = if ($growing -gt $declining) { "growing" } elseif ($declining -gt $growing) { "declining" } else { "stable" }
    
    $script:AnalyticsCache.Trends = $trends
    Save-Analytics
    
    return $trends
}

function Show-Trends {
    param($Trends)
    
    Write-Host "`nUsage Trends Analysis" -ForegroundColor White
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    
    Write-Host "`nGlobal Trend: $($Trends.GlobalTrend.TrendDirection.ToUpper())" -ForegroundColor $(
        if ($Trends.GlobalTrend.TrendDirection -eq "growing") { "Green" } 
        elseif ($Trends.GlobalTrend.TrendDirection -eq "declining") { "Red" } 
        else { "Yellow" }
    )
    
    Write-Host "`nTenant Breakdown:" -ForegroundColor Yellow
    $growing = ($Trends.TenantTrends | Where-Object { $_.TrendDirection -eq "growing" }).Count
    $declining = ($Trends.TenantTrends | Where-Object { $_.TrendDirection -eq "declining" }).Count
    $stable = ($Trends.TenantTrends | Where-Object { $_.TrendDirection -eq "stable" }).Count
    
    Write-Host "  Growing:   $growing" -ForegroundColor Green
    Write-Host "  Stable:    $stable" -ForegroundColor Yellow
    Write-Host "  Declining: $declining" -ForegroundColor Red
    
    Write-Host "`nTop Growing Tenants:" -ForegroundColor Yellow
    $topGrowing = $Trends.TenantTrends | Where-Object { $_.TrendDirection -eq "growing" } | Sort-Object GrowthRate -Descending | Select-Object -First 5
    foreach ($t in $topGrowing) {
        Write-Host "  $($t.TenantId.PadEnd(20)): +$($t.GrowthRate)% growth" -ForegroundColor Green
    }
    
    Write-Host "`nTop Declining Tenants:" -ForegroundColor Yellow
    $topDeclining = $Trends.TenantTrends | Where-Object { $_.TrendDirection -eq "declining" } | Sort-Object GrowthRate | Select-Object -First 5
    foreach ($t in $topDeclining) {
        Write-Host "  $($t.TenantId.PadEnd(20)): $($t.GrowthRate)% decline" -ForegroundColor Red
    }
}

function Get-UsageForecast {
    param($Days)
    
    Write-Host "`nGenerating $Days-day usage forecast..." -ForegroundColor Yellow
    
    $tenants = Get-UsageData
    $forecast = @{
        GeneratedAt = Get-Date -Format "o"
        ForecastDays = $Days
        Predictions = @()
    }
    
    foreach ($tenant in $tenants.GetEnumerator()) {
        $dailyTokens = @()
        foreach ($day in ($tenant.Value.DailyUsage.GetEnumerator() | Sort-Object Key)) {
            $dailyTokens += $day.Value.Tokens
        }
        
        if ($dailyTokens.Count -ge 7) {
            # Simple moving average forecast
            $lastWeek = $dailyTokens | Select-Object -Last 7
            $avg = ($lastWeek | Measure-Object -Average).Average
            $trend = ($lastWeek[-1] - $lastWeek[0]) / 7
            
            $predicted = @()
            for ($i = 1; $i -le $Days; $i++) {
                $predicted += [math]::Max(0, [int]($avg + ($trend * $i)))
            }
            
            $forecast.Predictions += @{
                TenantId = $tenant.Key
                CurrentAvgDaily = [math]::Round($avg, 2)
                Trend = [math]::Round($trend, 2)
                PredictedTotal = ($predicted | Measure-Object -Sum).Sum
                DailyPredictions = $predicted
            }
        }
    }
    
    return $forecast
}

function Show-Forecast {
    param($Forecast)
    
    Write-Host "`nUsage Forecast ($($Forecast.ForecastDays) days)" -ForegroundColor White
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    
    $totalPredicted = ($Forecast.Predictions | Measure-Object -Property PredictedTotal -Sum).Sum
    Write-Host "`nTotal Predicted Usage: $($totalPredicted.ToString('N0')) tokens" -ForegroundColor Green
    
    Write-Host "`nTop Predicted Consumers:" -ForegroundColor Yellow
    $topPredicted = $Forecast.Predictions | Sort-Object PredictedTotal -Descending | Select-Object -First 10
    foreach ($p in $topPredicted) {
        $trendSymbol = if ($p.Trend -gt 0) { "↑" } elseif ($p.Trend -lt 0) { "↓" } else { "→" }
        Write-Host "  $($p.TenantId.PadEnd(20)): $($p.PredictedTotal.ToString('N0').PadStart(12)) tokens $trendSymbol" -ForegroundColor Gray
    }
}

function Export-Analytics {
    $export = @{
        GeneratedAt = Get-Date -Format "o"
        Metrics = $script:AnalyticsCache.Metrics
        Trends = $script:AnalyticsCache.Trends
    }
    
    $exportFile = Join-Path $DataPath "analytics_export_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
    $export | ConvertTo-Json -Depth 10 | Set-Content -Path $exportFile
    
    # CSV export for metrics
    $csvFile = Join-Path $DataPath "analytics_metrics_$(Get-Date -Format 'yyyyMMdd').csv"
    $csvData = @()
    foreach ($period in $export.Metrics.GetEnumerator()) {
        $csvData += [PSCustomObject]@{
            Period = $period.Key
            TotalTenants = $period.Value.Summary.TotalTenants
            TotalTokens = $period.Value.Summary.TotalTokens
            TotalRevenue = $period.Value.Summary.TotalRevenue
            GeneratedAt = $period.Value.GeneratedAt
        }
    }
    $csvData | Export-Csv -Path $csvFile -NoTypeInformation
    
    Write-Host "`nAnalytics exported:" -ForegroundColor Green
    Write-Host "  JSON: $exportFile" -ForegroundColor Gray
    Write-Host "  CSV:  $csvFile" -ForegroundColor Gray
}

function Show-Dashboard {
    Write-Host "`nUsage Analytics Dashboard" -ForegroundColor White
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    
    $tenants = Get-UsageData
    $totalTokens = ($tenants.Values | Measure-Object -Property TotalTokens -Sum).Sum
    $totalRevenue = ($tenants.Values | Measure-Object -Property TotalCost -Sum).Sum
    
    Write-Host "`nReal-time Metrics:" -ForegroundColor Yellow
    Write-Host "  Active Tenants:     $($tenants.Count)" -ForegroundColor Gray
    Write-Host "  Total Tokens:       $($totalTokens.ToString('N0'))" -ForegroundColor Gray
    Write-Host "  Total Revenue:      `$$("{0:N2}" -f $totalRevenue)" -ForegroundColor Green
    
    if ($script:AnalyticsCache.Trends.TenantTrends) {
        $growing = ($script:AnalyticsCache.Trends.TenantTrends | Where-Object { $_.TrendDirection -eq "growing" }).Count
        Write-Host "  Growing Tenants:    $growing" -ForegroundColor Green
    }
    
    Write-Host "`nLast Updated: $($script:AnalyticsCache.LastUpdate)" -ForegroundColor Gray
}

# Main execution
Write-AnalyticsHeader
Initialize-Analytics

switch ($Action) {
    "analyze" {
        $metrics = Measure-UsageMetrics -Period $Period
        Show-UsageAnalysis -Metrics $metrics
    }
    "trends" {
        $trends = Measure-UsageTrends -TenantId $TenantId
        Show-Trends -Trends $trends
    }
    "forecast" {
        $forecast = Get-UsageForecast -Days $ForecastDays
        Show-Forecast -Forecast $forecast
    }
    "export" {
        Export-Analytics
    }
    "dashboard" {
        Show-Dashboard
    }
}

Write-Host "`n✅ Analytics operation complete" -ForegroundColor Green
