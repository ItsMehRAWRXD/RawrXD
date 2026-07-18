#!/usr/bin/env pwsh
#==============================================================================
# RawrXD Sovereign Inferencer - Performance Predictor
# Phase G.2 Batch 1/5: ML-Based Performance Forecasting
#==============================================================================
# Uses time-series analysis and statistical ML for performance prediction
#==============================================================================

[CmdletBinding()]
param(
    [Parameter()]
    [string]$TelemetryPath = "..\..\governance\telemetry\telemetry_data",

    [Parameter()]
    [string]$ModelPath = ".\models",

    [Parameter()]
    [int]$ForecastHorizon = 30,  # minutes

    [Parameter()]
    [string]$Metric = "TPS",

    [Parameter()]
    [switch]$Train,

    [Parameter()]
    [switch]$Predict
)

#==============================================================================
# Predictor Configuration
#==============================================================================

$script:PredictorConfig = @{
    Version = "1.0.0"
    
    # Statistical models used (no external ML libraries)
    Models = @{
        LinearRegression = $true
        MovingAverage = $true
        ExponentialSmoothing = $true
        TrendAnalysis = $true
    }
    
    # Forecasting parameters
    WindowSize = 10
    MinSamples = 20
    ConfidenceLevel = 0.95
    
    # Performance thresholds
    Thresholds = @{
        TPS = @{ Min = 30; Target = 45 }
        Latency = @{ Max = 100; Target = 50 }
        Memory = @{ Max = 8192; Target = 6144 }
    }
}

#==============================================================================
# Statistical ML Classes
#==============================================================================

class TimeSeriesData {
    [array]$Timestamps
    [array]$Values
    [hashtable]$Metadata

    TimeSeriesData() {
        $this.Timestamps = @()
        $this.Values = @()
        $this.Metadata = @{}
    }

    [void] AddPoint([datetime]$timestamp, [double]$value) {
        $this.Timestamps += $timestamp
        $this.Values += $value
    }

    [hashtable] GetStatistics() {
        if ($this.Values.Count -eq 0) { return @{} }
        
        $sorted = $this.Values | Sort-Object
        $n = $sorted.Count
        
        # Mean
        $sum = 0
        foreach ($v in $sorted) { $sum += $v }
        $mean = $sum / $n
        
        # Variance and StdDev
        $variance = 0
        foreach ($v in $sorted) {
            $variance += [Math]::Pow($v - $mean, 2)
        }
        $variance /= $n
        $stdDev = [Math]::Sqrt($variance)
        
        # Median
        if ($n % 2 -eq 0) {
            $median = ($sorted[$n/2 - 1] + $sorted[$n/2]) / 2
        } else {
            $median = $sorted[($n - 1) / 2]
        }
        
        # Percentiles
        $p95Index = [Math]::Floor($n * 0.95)
        $p99Index = [Math]::Floor($n * 0.99)
        
        return @{
            Count = $n
            Mean = [Math]::Round($mean, 2)
            Median = [Math]::Round($median, 2)
            StdDev = [Math]::Round($stdDev, 2)
            Min = [Math]::Round($sorted[0], 2)
            Max = [Math]::Round($sorted[-1], 2)
            P95 = [Math]::Round($sorted[$p95Index], 2)
            P99 = [Math]::Round($sorted[$p99Index], 2)
            Trend = $this.CalculateTrend()
        }
    }

    [string] CalculateTrend() {
        if ($this.Values.Count -lt 10) { return "insufficient_data" }
        
        $firstHalf = $this.Values[0..([Math]::Floor($this.Values.Count / 2) - 1)]
        $secondHalf = $this.Values[[Math]::Floor($this.Values.Count / 2)..($this.Values.Count - 1)]
        
        $firstAvg = ($firstHalf | Measure-Object -Average).Average
        $secondAvg = ($secondHalf | Measure-Object -Average).Average
        
        $change = (($secondAvg - $firstAvg) / $firstAvg) * 100
        
        if ($change -gt 10) { return "strong_increasing" }
        if ($change -gt 5) { return "increasing" }
        if ($change -lt -10) { return "strong_decreasing" }
        if ($change -lt -5) { return "decreasing" }
        return "stable"
    }
}

class LinearRegressionModel {
    [double]$Slope
    [double]$Intercept
    [double]$RSquared

    [void] Train([array]$x, [array]$y) {
        $n = $x.Count
        if ($n -ne $y.Count -or $n -eq 0) { return }
        
        $sumX = 0
        $sumY = 0
        $sumXY = 0
        $sumX2 = 0
        $sumY2 = 0
        
        for ($i = 0; $i -lt $n; $i++) {
            $sumX += $x[$i]
            $sumY += $y[$i]
            $sumXY += $x[$i] * $y[$i]
            $sumX2 += $x[$i] * $x[$i]
            $sumY2 += $y[$i] * $y[$i]
        }
        
        $this.Slope = ($n * $sumXY - $sumX * $sumY) / ($n * $sumX2 - $sumX * $sumX)
        $this.Intercept = ($sumY - $this.Slope * $sumX) / $n
        
        # Calculate R-squared
        $ssRes = 0
        $ssTot = 0
        $meanY = $sumY / $n
        
        for ($i = 0; $i -lt $n; $i++) {
            $predicted = $this.Slope * $x[$i] + $this.Intercept
            $ssRes += [Math]::Pow($y[$i] - $predicted, 2)
            $ssTot += [Math]::Pow($y[$i] - $meanY, 2)
        }
        
        $this.RSquared = if ($ssTot -ne 0) { 1 - ($ssRes / $ssTot) } else { 0 }
    }

    [double] Predict([double]$x) {
        return $this.Slope * $x + $this.Intercept
    }
}

class MovingAverageModel {
    [int]$WindowSize
    [array]$Weights

    MovingAverageModel([int]$windowSize) {
        $this.WindowSize = $windowSize
        $this.Weights = @()
        
        # Exponential weights
        $alpha = 2.0 / ($windowSize + 1)
        for ($i = 0; $i -lt $windowSize; $i++) {
            $this.Weights += $alpha * [Math]::Pow(1 - $alpha, $i)
        }
        
        # Normalize weights
        $sum = ($this.Weights | Measure-Object -Sum).Sum
        for ($i = 0; $i -lt $this.Weights.Count; $i++) {
            $this.Weights[$i] /= $sum
        }
    }

    [double] Predict([array]$values) {
        if ($values.Count -lt $this.WindowSize) { 
            return ($values | Measure-Object -Average).Average 
        }
        
        $prediction = 0
        $recent = $values[-$this.WindowSize..-1]
        
        for ($i = 0; $i -lt $this.WindowSize; $i++) {
            $prediction += $recent[$i] * $this.Weights[$i]
        }
        
        return $prediction
    }
}

class PerformancePredictor {
    [string]$TelemetryPath
    [string]$ModelPath
    [hashtable]$Models
    [TimeSeriesData]$Data

    PerformancePredictor([string]$telemetry, [string]$modelPath) {
        $this.TelemetryPath = $telemetry
        $this.ModelPath = $modelPath
        $this.Models = @{}
        $this.Data = [TimeSeriesData]::new()
        
        New-Item -ItemType Directory -Force -Path $modelPath | Out-Null
    }

    [void] LoadHistoricalData([string]$metric, [int]$hoursBack = 24) {
        Write-Host "Loading historical data for $metric..." -ForegroundColor Yellow
        
        $metricsPath = Join-Path $this.TelemetryPath "metrics"
        if (-not (Test-Path $metricsPath)) {
            Write-Warning "No telemetry data found"
            return
        }
        
        $cutoff = (Get-Date).AddHours(-$hoursBack)
        $files = Get-ChildItem -Path $metricsPath -Filter "*.jsonl" | 
            Where-Object { $_.LastWriteTime -gt $cutoff } | 
            Sort-Object LastWriteTime
        
        $count = 0
        foreach ($file in $files) {
            $lines = Get-Content $file.FullName
            foreach ($line in $lines) {
                if (-not $line.Trim()) { continue }
                try {
                    $data = $line | ConvertFrom-Json -AsHashtable
                    if ($data.Name -eq $metric) {
                        $timestamp = [datetime]::Parse($data.Timestamp)
                        $this.Data.AddPoint($timestamp, $data.Value)
                        $count++
                    }
                }
                catch {}
            }
        }
        
        Write-Host "  Loaded $count data points" -ForegroundColor Green
    }

    [void] TrainModels() {
        Write-Host "`nTraining prediction models..." -ForegroundColor Cyan
        
        if ($this.Data.Values.Count -lt $script:PredictorConfig.MinSamples) {
            Write-Warning "Insufficient data for training (need $($script:PredictorConfig.MinSamples), have $($this.Data.Values.Count))"
            return
        }
        
        # Prepare training data
        $x = @(0..($this.Data.Values.Count - 1))
        $y = $this.Data.Values
        
        # Linear Regression
        $lr = [LinearRegressionModel]::new()
        $lr.Train($x, $y)
        $this.Models["LinearRegression"] = $lr
        Write-Host "  ✓ Linear Regression (R² = $([Math]::Round($lr.RSquared, 3)))" -ForegroundColor Green
        
        # Moving Average
        $ma = [MovingAverageModel]::new($script:PredictorConfig.WindowSize)
        $this.Models["MovingAverage"] = $ma
        Write-Host "  ✓ Moving Average (window = $($script:PredictorConfig.WindowSize))" -ForegroundColor Green
        
        # Save models
        $this.SaveModels()
    }

    [hashtable] Forecast([int]$horizon) {
        Write-Host "`nGenerating forecast for next $horizon minutes..." -ForegroundColor Cyan
        
        if ($this.Models.Count -eq 0) {
            $this.LoadModels()
        }
        
        $forecasts = @{
            Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
            Horizon = $horizon
            Predictions = @()
            Confidence = @{}
        }
        
        $currentTime = $this.Data.Values.Count
        $currentValue = if ($this.Data.Values.Count -gt 0) { 
            $this.Data.Values[-1] 
        } else { 0 }
        
        for ($i = 1; $i -le $horizon; $i++) {
            $futureTime = $currentTime + $i
            $predictions = @{}
            
            # Linear Regression prediction
            if ($this.Models.ContainsKey("LinearRegression")) {
                $lr = $this.Models["LinearRegression"]
                $predictions["LinearRegression"] = [Math]::Round($lr.Predict($futureTime), 2)
            }
            
            # Moving Average prediction
            if ($this.Models.ContainsKey("MovingAverage")) {
                $ma = $this.Models["MovingAverage"]
                $predictions["MovingAverage"] = [Math]::Round($ma.Predict($this.Data.Values), 2)
            }
            
            # Ensemble prediction (average of models)
            $ensemble = ($predictions.Values | Measure-Object -Average).Average
            $predictions["Ensemble"] = [Math]::Round($ensemble, 2)
            
            $forecastTime = (Get-Date).AddMinutes($i)
            $forecasts.Predictions += @{
                Time = $forecastTime.ToString("HH:mm")
                MinutesAhead = $i
                Values = $predictions
            }
        }
        
        # Calculate confidence intervals based on historical variance
        $stats = $this.Data.GetStatistics()
        if ($stats.StdDev) {
            $zScore = 1.96  # 95% confidence
            $margin = $zScore * $stats.StdDev
            
            $forecasts.Confidence = @{
                Level = 0.95
                Margin = [Math]::Round($margin, 2)
            }
        }
        
        return $forecasts
    }

    [void] SaveModels() {
        $modelData = @{
            Version = $script:PredictorConfig.Version
            Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
            Models = @{}
        }
        
        foreach ($name in $this.Models.Keys) {
            $model = $this.Models[$name]
            $modelData.Models[$name] = @{
                Type = $model.GetType().Name
                Parameters = @{
                    Slope = if ($model.Slope) { $model.Slope } else { $null }
                    Intercept = if ($model.Intercept) { $model.Intercept } else { $null }
                    RSquared = if ($model.RSquared) { $model.RSquared } else { $null }
                    WindowSize = if ($model.WindowSize) { $model.WindowSize } else { $null }
                }
            }
        }
        
        $path = Join-Path $this.ModelPath "performance_models.json"
        $modelData | ConvertTo-Json -Depth 10 | Out-File $path
        Write-Host "  Models saved to: $path" -ForegroundColor Gray
    }

    [void] LoadModels() {
        $path = Join-Path $this.ModelPath "performance_models.json"
        if (-not (Test-Path $path)) { return }
        
        $data = Get-Content $path | ConvertFrom-Json -AsHashtable
        
        foreach ($name in $data.Models.Keys) {
            $modelData = $data.Models[$name]
            
            switch ($modelData.Type) {
                "LinearRegressionModel" {
                    $model = [LinearRegressionModel]::new()
                    $model.Slope = $modelData.Parameters.Slope
                    $model.Intercept = $modelData.Parameters.Intercept
                    $model.RSquared = $modelData.Parameters.RSquared
                    $this.Models[$name] = $model
                }
                "MovingAverageModel" {
                    $model = [MovingAverageModel]::new($modelData.Parameters.WindowSize)
                    $this.Models[$name] = $model
                }
            }
        }
        
        Write-Host "Loaded $($this.Models.Count) models from disk" -ForegroundColor Green
    }

    [void] DisplayForecast([hashtable]$forecast) {
        Write-Host "`n=== Performance Forecast ===" -ForegroundColor Cyan
        Write-Host "Generated: $($forecast.Timestamp)" -ForegroundColor Gray
        Write-Host "Horizon: $($forecast.Horizon) minutes" -ForegroundColor Gray
        
        if ($forecast.Confidence.Margin) {
            Write-Host "Confidence: 95% (±$($forecast.Confidence.Margin))" -ForegroundColor Gray
        }
        
        Write-Host "`nPredictions:" -ForegroundColor Yellow
        Write-Host "Time    | LinearReg | MovingAvg | Ensemble" -ForegroundColor White
        Write-Host "--------|-----------|-----------|----------" -ForegroundColor Gray
        
        foreach ($pred in $forecast.Predictions | Select-Object -First 10) {
            $lr = $pred.Values.LinearRegression.ToString().PadLeft(9)
            $ma = $pred.Values.MovingAverage.ToString().PadLeft(9)
            $en = $pred.Values.Ensemble.ToString().PadLeft(9)
            Write-Host "$($pred.Time) | $lr | $ma | $en" -ForegroundColor White
        }
        
        if ($forecast.Predictions.Count -gt 10) {
            Write-Host "... and $($forecast.Predictions.Count - 10) more" -ForegroundColor Gray
        }
        
        # Trend analysis
        $stats = $this.Data.GetStatistics()
        Write-Host "`nHistorical Statistics:" -ForegroundColor Yellow
        Write-Host "  Mean: $($stats.Mean)" -ForegroundColor White
        Write-Host "  Trend: $($stats.Trend)" -ForegroundColor White
        Write-Host "  Samples: $($stats.Count)" -ForegroundColor White
    }
}

#==============================================================================
# Main Execution
#==============================================================================

Write-Host @"
╔══════════════════════════════════════════════════════════════════════════════╗
║           RawrXD Sovereign - Performance Predictor                           ║
║           Phase G.2 Batch 1/5: ML-Based Performance Forecasting              ║
╚══════════════════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

$predictor = [PerformancePredictor]::new($TelemetryPath, $ModelPath)

if ($Train) {
    $predictor.LoadHistoricalData($Metric)
    $predictor.TrainModels()
    
    Write-Host "`n✓ Training complete" -ForegroundColor Green
}
elseif ($Predict) {
    $predictor.LoadHistoricalData($Metric, 24)
    $forecast = $predictor.Forecast($ForecastHorizon)
    $predictor.DisplayForecast($forecast)
    
    # Save forecast
    $forecastPath = Join-Path $ModelPath "latest_forecast.json"
    $forecast | ConvertTo-Json -Depth 10 | Out-File $forecastPath
    Write-Host "`n✓ Forecast saved to: $forecastPath" -ForegroundColor Green
}
else {
    # Interactive mode
    Write-Host "`nCommands:" -ForegroundColor Yellow
    Write-Host "  1. Train models"
    Write-Host "  2. Generate forecast"
    Write-Host "  3. View statistics"
    
    $choice = Read-Host "`nSelect option (1-3)"
    
    switch ($choice) {
        "1" {
            $metric = Read-Host "Enter metric name (TPS/Latency/Memory)"
            $predictor.LoadHistoricalData($metric)
            $predictor.TrainModels()
        }
        "2" {
            $metric = Read-Host "Enter metric name (TPS/Latency/Memory)"
            $horizon = Read-Host "Enter forecast horizon (minutes)"
            $predictor.LoadHistoricalData($metric)
            $forecast = $predictor.Forecast([int]$horizon)
            $predictor.DisplayForecast($forecast)
        }
        "3" {
            $metric = Read-Host "Enter metric name"
            $predictor.LoadHistoricalData($metric)
            $stats = $predictor.Data.GetStatistics()
            Write-Host "`nStatistics for $metric`:" -ForegroundColor Cyan
            $stats | Format-List
        }
    }
}
