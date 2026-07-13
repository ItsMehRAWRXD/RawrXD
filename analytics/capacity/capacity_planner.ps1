#!/usr/bin/env pwsh
#==============================================================================
# RawrXD Sovereign Inferencer - Capacity Planner
# Phase G.2 Batch 5/5: Predictive Scaling
#==============================================================================
# Predicts resource needs and recommends scaling actions
#==============================================================================

[CmdletBinding()]
param(
    [Parameter()]
    [string]$TelemetryPath = "..\..\governance\telemetry\telemetry_data",

    [Parameter()]
    [string]$PlanPath = ".\capacity_plans",

    [Parameter()]
    [int]$ForecastDays = 7,

    [Parameter()]
    [switch]$GeneratePlan,

    [Parameter()]
    [switch]$SimulateScaling
)

#==============================================================================
# Capacity Planner Configuration
#==============================================================================

$script:PlannerConfig = @{
    Version = "1.0.0"
    
    # Resource types
    Resources = @{
        CPU = @{ Unit = "cores"; Min = 4; Max = 64; Step = 4 }
        Memory = @{ Unit = "GB"; Min = 16; Max = 512; Step = 16 }
        GPU = @{ Unit = "devices"; Min = 1; Max = 8; Step = 1 }
        Storage = @{ Unit = "GB"; Min = 100; Max = 2000; Step = 100 }
    }
    
    # Scaling thresholds
    Scaling = @{
        ScaleUpThreshold = 80    # Percent
        ScaleDownThreshold = 30  # Percent
        ForecastHorizon = 7      # Days
        SafetyBuffer = 1.2      # 20% headroom
    }
    
    # Cost parameters
    Costs = @{
        CPU_PerCore_Hour = 0.05
        Memory_PerGB_Hour = 0.01
        GPU_PerDevice_Hour = 0.50
        Storage_PerGB_Month = 0.10
    }
}

#==============================================================================
# Capacity Planning Classes
#==============================================================================

class ResourceForecast {
    [string]$ResourceType
    [array]$DailyForecasts
    [hashtable]$PeakUsage
    [hashtable]$RecommendedCapacity
    [double]$EstimatedCost

    ResourceForecast([string]$type) {
        $this.ResourceType = $type
        $this.DailyForecasts = @()
        $this.PeakUsage = @{}
        $this.RecommendedCapacity = @{}
    }
}

class CapacityPlanner {
    [string]$TelemetryPath
    [string]$PlanPath
    [hashtable]$HistoricalData
    [hashtable]$Forecasts

    CapacityPlanner([string]$telemetry, [string]$planPath) {
        $this.TelemetryPath = $telemetry
        $this.PlanPath = $planPath
        $this.HistoricalData = @{}
        $this.Forecasts = @{}
        
        New-Item -ItemType Directory -Force -Path $planPath | Out-Null
    }

    [void] LoadHistoricalData([int]$daysBack = 30) {
        Write-Host "Loading historical data ($daysBack days)..." -ForegroundColor Yellow
        
        $metricsPath = Join-Path $this.TelemetryPath "metrics"
        if (-not (Test-Path $metricsPath)) {
            Write-Warning "No telemetry data found"
            return
        }
        
        $cutoff = (Get-Date).AddDays(-$daysBack)
        $files = Get-ChildItem -Path $metricsPath -Filter "*.jsonl" | 
            Where-Object { $_.LastWriteTime -gt $cutoff } | 
            Sort-Object LastWriteTime
        
        foreach ($metric in @("CPU", "Memory", "GPU", "TPS")) {
            $this.HistoricalData[$metric] = @()
        }
        
        foreach ($file in $files) {
            $lines = Get-Content $file.FullName
            foreach ($line in $lines) {
                if (-not $line.Trim()) { continue }
                try {
                    $data = $line | ConvertFrom-Json -AsHashtable
                    
                    # Map telemetry metrics to resource types
                    $resourceType = switch ($data.Name) {
                        "CPUUsage" { "CPU" }
                        "MemoryUsage" { "Memory" }
                        "GPUUtilization" { "GPU" }
                        "TPS" { "TPS" }
                        default { $null }
                    }
                    
                    if ($resourceType) {
                        $this.HistoricalData[$resourceType] += @{
                            Timestamp = [datetime]::Parse($data.Timestamp)
                            Value = $data.Value
                        }
                    }
                }
                catch {}
            }
        }
        
        foreach ($metric in $this.HistoricalData.Keys) {
            Write-Host "  $metric`: $($this.HistoricalData[$metric].Count) samples" -ForegroundColor Gray
        }
    }

    [ResourceForecast] GenerateForecast([string]$resourceType, [int]$days) {
        Write-Host "`nGenerating forecast for $resourceType ($days days)..." -ForegroundColor Cyan
        
        $forecast = [ResourceForecast]::new($resourceType)
        $data = $this.HistoricalData[$resourceType]
        
        if ($data.Count -eq 0) {
            Write-Warning "No historical data for $resourceType"
            return $forecast
        }
        
        # Calculate daily patterns
        $dailyStats = @{}
        for ($i = 0; $i -lt 7; $i++) {
            $dayOfWeek = $i
            $dayData = $data | Where-Object { $_.Timestamp.DayOfWeek -eq $dayOfWeek }
            
            if ($dayData.Count -gt 0) {
                $values = $dayData | Select-Object -ExpandProperty Value
                $dailyStats[$dayOfWeek] = @{
                    Mean = ($values | Measure-Object -Average).Average
                    Max = ($values | Measure-Object -Maximum).Maximum
                    P95 = $this.CalculatePercentile($values, 95)
                }
            }
        }
        
        # Generate daily forecasts
        $today = Get-Date
        for ($i = 0; $i -lt $days; $i++) {
            $forecastDate = $today.AddDays($i)
            $dayOfWeek = [int]$forecastDate.DayOfWeek
            
            if ($dailyStats.ContainsKey($dayOfWeek)) {
                $basePrediction = $dailyStats[$dayOfWeek].Mean
                $trend = $this.CalculateTrend($data)
                
                # Apply trend
                $predictedValue = $basePrediction + ($trend * $i)
                
                # Add safety buffer
                $recommendedValue = $predictedValue * $script:PlannerConfig.Scaling.SafetyBuffer
                
                $forecast.DailyForecasts += @{
                    Date = $forecastDate.ToString("yyyy-MM-dd")
                    DayOfWeek = $forecastDate.DayOfWeek.ToString()
                    PredictedUsage = [Math]::Round($predictedValue, 2)
                    RecommendedCapacity = [Math]::Round($recommendedValue, 2)
                    Confidence = "Medium"
                }
            }
        }
        
        # Calculate peak usage
        if ($forecast.DailyForecasts.Count -gt 0) {
            $allPredictions = $forecast.DailyForecasts | Select-Object -ExpandProperty PredictedUsage
            $forecast.PeakUsage = @{
                Average = ($allPredictions | Measure-Object -Average).Average
                Maximum = ($allPredictions | Measure-Object -Maximum).Maximum
                Minimum = ($allPredictions | Measure-Object -Minimum).Minimum
            }
            
            # Calculate recommended capacity
            $peakRecommended = $forecast.DailyForecasts | 
                Sort-Object -Property RecommendedCapacity -Descending | 
                Select-Object -First 1
            
            $forecast.RecommendedCapacity = @{
                Peak = $peakRecommended.RecommendedCapacity
                Average = ($forecast.DailyForecasts | Select-Object -ExpandProperty RecommendedCapacity | Measure-Object -Average).Average
            }
        }
        
        # Calculate cost
        $forecast.EstimatedCost = $this.CalculateCost($resourceType, $forecast.RecommendedCapacity.Peak)
        
        $this.Forecasts[$resourceType] = $forecast
        return $forecast
    }

    [double] CalculateTrend([array]$data) {
        if ($data.Count -lt 2) { return 0 }
        
        # Simple linear trend calculation
        $sorted = $data | Sort-Object -Property Timestamp
        $firstWeek = $sorted | Select-Object -First ([Math]::Min(7, $sorted.Count))
        $lastWeek = $sorted | Select-Object -Last ([Math]::Min(7, $sorted.Count))
        
        $firstAvg = ($firstWeek | Select-Object -ExpandProperty Value | Measure-Object -Average).Average
        $lastAvg = ($lastWeek | Select-Object -ExpandProperty Value | Measure-Object -Average).Average
        
        $daysDiff = ($lastWeek[-1].Timestamp - $firstWeek[0].Timestamp).TotalDays
        if ($daysDiff -eq 0) { return 0 }
        
        return ($lastAvg - $firstAvg) / $daysDiff
    }

    [double] CalculatePercentile([array]$values, [int]$percentile) {
        $sorted = $values | Sort-Object
        $index = [Math]::Ceiling($sorted.Count * $percentile / 100) - 1
        return $sorted[[Math]::Max(0, [Math]::Min($index, $sorted.Count - 1))]
    }

    [double] CalculateCost([string]$resourceType, [double]$capacity) {
        $hoursInMonth = 730  # Average hours per month
        
        switch ($resourceType) {
            "CPU" {
                return $capacity * $script:PlannerConfig.Costs.CPU_PerCore_Hour * $hoursInMonth
            }
            "Memory" {
                return $capacity * $script:PlannerConfig.Costs.Memory_PerGB_Hour * $hoursInMonth
            }
            "GPU" {
                return $capacity * $script:PlannerConfig.Costs.GPU_PerDevice_Hour * $hoursInMonth
            }
            default {
                return 0
            }
        }
    }

    [hashtable] GenerateScalingRecommendations() {
        Write-Host "`n=== Generating Scaling Recommendations ===" -ForegroundColor Cyan
        
        $recommendations = @{
            ScaleUp = @()
            ScaleDown = @()
            Maintain = @()
        }
        
        foreach ($resourceType in $this.Forecasts.Keys) {
            $forecast = $this.Forecasts[$resourceType]
            
            if ($forecast.DailyForecasts.Count -eq 0) { continue }
            
            $avgUsage = $forecast.PeakUsage.Average
            $peakUsage = $forecast.PeakUsage.Maximum
            $currentCapacity = $this.GetCurrentCapacity($resourceType)
            
            $utilization = ($avgUsage / $currentCapacity) * 100
            
            if ($utilization -gt $script:PlannerConfig.Scaling.ScaleUpThreshold) {
                $recommendedCapacity = $peakUsage * $script:PlannerConfig.Scaling.SafetyBuffer
                $recommendations.ScaleUp += @{
                    Resource = $resourceType
                    CurrentCapacity = $currentCapacity
                    RecommendedCapacity = [Math]::Round($recommendedCapacity, 0)
                    Reason = "Utilization at $([Math]::Round($utilization, 1))% (threshold: $($script:PlannerConfig.Scaling.ScaleUpThreshold)%)"
                    Urgency = if ($utilization -gt 90) { "High" } else { "Medium" }
                }
            }
            elseif ($utilization -lt $script:PlannerConfig.Scaling.ScaleDownThreshold) {
                $recommendedCapacity = $avgUsage * 1.5  # Keep some headroom
                $recommendations.ScaleDown += @{
                    Resource = $resourceType
                    CurrentCapacity = $currentCapacity
                    RecommendedCapacity = [Math]::Round($recommendedCapacity, 0)
                    Reason = "Utilization at $([Math]::Round($utilization, 1))% (threshold: $($script:PlannerConfig.Scaling.ScaleDownThreshold)%)"
                    Urgency = "Low"
                }
            }
            else {
                $recommendations.Maintain += @{
                    Resource = $resourceType
                    CurrentCapacity = $currentCapacity
                    Utilization = [Math]::Round($utilization, 1)
                }
            }
        }
        
        return $recommendations
    }

    [double] GetCurrentCapacity([string]$resourceType) {
        # In production, would query actual resource capacity
        # For now, return simulated values
        switch ($resourceType) {
            "CPU" { return 16 }
            "Memory" { return 64 }
            "GPU" { return 1 }
            default { return 100 }
        }
    }

    [void] SavePlan([string]$planName) {
        $plan = @{
            Name = $planName
            Generated = Get-Date -Format "o"
            ForecastDays = $script:PlannerConfig.Scaling.ForecastHorizon
            Resources = @{}
            TotalEstimatedCost = 0
        }
        
        foreach ($resourceType in $this.Forecasts.Keys) {
            $forecast = $this.Forecasts[$resourceType]
            if ($forecast.DailyForecasts.Count -gt 0) {
                $plan.Resources[$resourceType] = @{
                    Forecasts = $forecast.DailyForecasts
                    PeakUsage = $forecast.PeakUsage
                    RecommendedCapacity = $forecast.RecommendedCapacity
                    EstimatedCost = $forecast.EstimatedCost
                }
                $plan.TotalEstimatedCost += $forecast.EstimatedCost
            }
        }
        
        $path = Join-Path $this.PlanPath "$planName.json"
        $plan | ConvertTo-Json -Depth 10 | Out-File $path
        
        Write-Host "`n✓ Capacity plan saved to: $path" -ForegroundColor Green
        Write-Host "  Total estimated monthly cost: `$([Math]::Round($plan.TotalEstimatedCost, 2))" -ForegroundColor Yellow
    }

    [void] DisplayForecast([ResourceForecast]$forecast) {
        Write-Host "`n=== $([string]$forecast.ResourceType) Forecast ===" -ForegroundColor Cyan
        
        if ($forecast.DailyForecasts.Count -eq 0) {
            Write-Host "No forecast data available." -ForegroundColor Yellow
            return
        }
        
        Write-Host "`nDaily Predictions:" -ForegroundColor Yellow
        Write-Host "Date       | Day       | Predicted | Recommended" -ForegroundColor White
        Write-Host "───────────┼───────────┼───────────┼────────────" -ForegroundColor Gray
        
        foreach ($day in $forecast.DailyForecasts | Select-Object -First 10) {
            $date = $day.Date.PadRight(10)
            $dow = $day.DayOfWeek.PadRight(9)
            $pred = $day.PredictedUsage.ToString().PadRight(9)
            $rec = $day.RecommendedCapacity
            Write-Host "$date | $dow | $pred | $rec" -ForegroundColor White
        }
        
        if ($forecast.DailyForecasts.Count -gt 10) {
            Write-Host "... and $($forecast.DailyForecasts.Count - 10) more days" -ForegroundColor Gray
        }
        
        Write-Host "`nPeak Usage Statistics:" -ForegroundColor Yellow
        Write-Host "  Average: $([Math]::Round($forecast.PeakUsage.Average, 2))" -ForegroundColor White
        Write-Host "  Maximum: $([Math]::Round($forecast.PeakUsage.Maximum, 2))" -ForegroundColor White
        Write-Host "  Minimum: $([Math]::Round($forecast.PeakUsage.Minimum, 2))" -ForegroundColor White
        
        Write-Host "`nRecommended Capacity:" -ForegroundColor Yellow
        Write-Host "  Peak: $([Math]::Round($forecast.RecommendedCapacity.Peak, 2))" -ForegroundColor Green
        Write-Host "  Average: $([Math]::Round($forecast.RecommendedCapacity.Average, 2))" -ForegroundColor White
        
        Write-Host "`nEstimated Monthly Cost: `$([Math]::Round($forecast.EstimatedCost, 2))" -ForegroundColor Yellow
    }

    [void] DisplayRecommendations([hashtable]$recommendations) {
        Write-Host "`n=== Scaling Recommendations ===" -ForegroundColor Cyan
        
        if ($recommendations.ScaleUp.Count -gt 0) {
            Write-Host "`n⚠️ Scale Up Required:" -ForegroundColor Red
            foreach ($rec in $recommendations.ScaleUp) {
                Write-Host "  $($rec.Resource): $($rec.CurrentCapacity) → $($rec.RecommendedCapacity) ($($rec.Urgency) urgency)" -ForegroundColor Yellow
                Write-Host "    Reason: $($rec.Reason)" -ForegroundColor Gray
            }
        }
        
        if ($recommendations.ScaleDown.Count -gt 0) {
            Write-Host "`n✓ Scale Down Recommended:" -ForegroundColor Green
            foreach ($rec in $recommendations.ScaleDown) {
                Write-Host "  $($rec.Resource): $($rec.CurrentCapacity) → $($rec.RecommendedCapacity)" -ForegroundColor White
                Write-Host "    Reason: $($rec.Reason)" -ForegroundColor Gray
            }
        }
        
        if ($recommendations.Maintain.Count -gt 0) {
            Write-Host "`n✓ Maintain Current Capacity:" -ForegroundColor Green
            foreach ($rec in $recommendations.Maintain) {
                Write-Host "  $($rec.Resource): $($rec.CurrentCapacity) (utilization: $($rec.Utilization)%)" -ForegroundColor White
            }
        }
    }
}

#==============================================================================
# Main Execution
#==============================================================================

Write-Host @"
╔══════════════════════════════════════════════════════════════════════════════╗
║           RawrXD Sovereign - Capacity Planner                                  ║
║           Phase G.2 Batch 5/5: Predictive Scaling                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

$planner = [CapacityPlanner]::new($TelemetryPath, $PlanPath)

if ($GeneratePlan) {
    $planner.LoadHistoricalData(30)
    
    # Generate forecasts for each resource
    foreach ($resource in @("CPU", "Memory", "GPU")) {
        $forecast = $planner.GenerateForecast($resource, $ForecastDays)
        $planner.DisplayForecast($forecast)
    }
    
    # Generate recommendations
    $recommendations = $planner.GenerateScalingRecommendations()
    $planner.DisplayRecommendations($recommendations)
    
    # Save plan
    $planName = "capacity_plan_$(Get-Date -Format 'yyyyMMdd')"
    $planner.SavePlan($planName)
}
elseif ($SimulateScaling) {
    Write-Host "`n=== Simulating Scaling Actions ===" -ForegroundColor Cyan
    Write-Host "This would execute scaling recommendations in production." -ForegroundColor Yellow
    Write-Host "[DRY RUN] No actual changes made." -ForegroundColor Cyan
}
else {
    # Interactive mode
    Write-Host "`nCommands:" -ForegroundColor Yellow
    Write-Host "  1. Generate capacity plan"
    Write-Host "  2. View existing plans"
    Write-Host "  3. Simulate scaling"
    
    $choice = Read-Host "`nSelect option (1-3)"
    
    switch ($choice) {
        "1" {
            $days = Read-Host "Enter forecast days (default: 7)"
            if (-not $days) { $days = 7 }
            
            $planner.LoadHistoricalData(30)
            
            foreach ($resource in @("CPU", "Memory", "GPU")) {
                $forecast = $planner.GenerateForecast($resource, [int]$days)
                $planner.DisplayForecast($forecast)
            }
            
            $recommendations = $planner.GenerateScalingRecommendations()
            $planner.DisplayRecommendations($recommendations)
            
            $save = Read-Host "`nSave plan? (y/n)"
            if ($save -eq "y") {
                $name = Read-Host "Enter plan name"
                $planner.SavePlan($name)
            }
        }
        "2" {
            $plans = Get-ChildItem -Path $PlanPath -Filter "*.json" | Select-Object -ExpandProperty Name
            if ($plans.Count -eq 0) {
                Write-Host "No plans found." -ForegroundColor Yellow
            }
            else {
                Write-Host "`nExisting plans:" -ForegroundColor Cyan
                $plans | ForEach-Object { Write-Host "  $_" -ForegroundColor White }
            }
        }
        "3" {
            Write-Host "`n[DRY RUN] Scaling simulation mode" -ForegroundColor Cyan
            $planner.LoadHistoricalData(30)
            $recommendations = $planner.GenerateScalingRecommendations()
            $planner.DisplayRecommendations($recommendations)
        }
    }
}
