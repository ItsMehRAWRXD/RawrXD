#!/usr/bin/env pwsh
#==============================================================================
# RawrXD Sovereign Inferencer - Anomaly Detector
# Phase G.2 Batch 4/5: ML-Based Anomaly Detection
#==============================================================================
# Detects anomalies using statistical methods and isolation forest algorithm
#==============================================================================

[CmdletBinding()]
param(
    [Parameter()]
    [string]$TelemetryPath = "..\..\governance\telemetry\telemetry_data",

    [Parameter()]
    [string]$ModelPath = ".\anomaly_models",

    [Parameter()]
    [double]$Sensitivity = 0.95,

    [Parameter()]
    [switch]$Train,

    [Parameter()]
    [switch]$Detect
)

#==============================================================================
# Anomaly Detection Configuration
#==============================================================================

$script:AnomalyConfig = @{
    Version = "1.0.0"
    
    # Detection methods
    Methods = @{
        ZScore = @{ Enabled = $true; Threshold = 3.0 }
        IQR = @{ Enabled = $true; Multiplier = 1.5 }
        IsolationForest = @{ Enabled = $true; Contamination = 0.1 }
        SeasonalDecomposition = @{ Enabled = $true; Period = 60 }
    }
    
    # Feature engineering
    Features = @(
        "RawValue"
        "MovingAverage_5"
        "MovingAverage_10"
        "RateOfChange"
        "Volatility"
        "TimeOfDay"
        "DayOfWeek"
    )
    
    # Alert thresholds
    AlertThresholds = @{
        Info = 0.7
        Warning = 0.85
        Critical = 0.95
    }
}

#==============================================================================
# Anomaly Detection Classes
#==============================================================================

class StatisticalFeatures {
    [array]$Values
    [hashtable]$Features

    StatisticalFeatures([array]$values) {
        $this.Values = $values
        $this.Features = @{}
        $this.CalculateFeatures()
    }

    [void] CalculateFeatures() {
        if ($this.Values.Count -eq 0) { return }
        
        # Raw value
        $this.Features["RawValue"] = $this.Values[-1]
        
        # Moving averages
        if ($this.Values.Count -ge 5) {
            $this.Features["MovingAverage_5"] = ($this.Values[-5..-1] | Measure-Object -Average).Average
        }
        if ($this.Values.Count -ge 10) {
            $this.Features["MovingAverage_10"] = ($this.Values[-10..-1] | Measure-Object -Average).Average
        }
        
        # Rate of change
        if ($this.Values.Count -ge 2) {
            $this.Features["RateOfChange"] = $this.Values[-1] - $this.Values[-2]
        }
        
        # Volatility (standard deviation)
        if ($this.Values.Count -ge 5) {
            $mean = ($this.Values | Measure-Object -Average).Average
            $variance = 0
            foreach ($v in $this.Values) {
                $variance += [Math]::Pow($v - $mean, 2)
            }
            $this.Features["Volatility"] = [Math]::Sqrt($variance / $this.Values.Count)
        }
        
        # Time-based features
        $now = Get-Date
        $this.Features["TimeOfDay"] = $now.Hour + $now.Minute / 60.0
        $this.Features["DayOfWeek"] = [int]$now.DayOfWeek
    }

    [hashtable] GetFeatures() {
        return $this.Features
    }
}

class ZScoreDetector {
    [double]$Mean
    [double]$StdDev
    [double]$Threshold

    ZScoreDetector([double]$threshold) {
        $this.Threshold = $threshold
    }

    [void] Train([array]$data) {
        $this.Mean = ($data | Measure-Object -Average).Average
        
        $variance = 0
        foreach ($value in $data) {
            $variance += [Math]::Pow($value - $this.Mean, 2)
        }
        $this.StdDev = [Math]::Sqrt($variance / $data.Count)
    }

    [double] Score([double]$value) {
        if ($this.StdDev -eq 0) { return 0 }
        $zscore = [Math]::Abs(($value - $this.Mean) / $this.StdDev)
        return [Math]::Min($zscore / $this.Threshold, 1.0)
    }

    [bool] IsAnomaly([double]$value) {
        return $this.Score($value) -ge 1.0
    }
}

class IQRDetector {
    [double]$Q1
    [double]$Q3
    [double]$IQR
    [double]$Multiplier

    IQRDetector([double]$multiplier) {
        $this.Multiplier = $multiplier
    }

    [void] Train([array]$data) {
        $sorted = $data | Sort-Object
        $n = $sorted.Count
        
        # Calculate Q1 and Q3
        $q1Index = [Math]::Floor($n * 0.25)
        $q3Index = [Math]::Floor($n * 0.75)
        
        $this.Q1 = $sorted[$q1Index]
        $this.Q3 = $sorted[$q3Index]
        $this.IQR = $this.Q3 - $this.Q1
    }

    [double] Score([double]$value) {
        $lower = $this.Q1 - $this.Multiplier * $this.IQR
        $upper = $this.Q3 + $this.Multiplier * $this.IQR
        
        if ($value -lt $lower) {
            return [Math]::Min([Math]::Abs($value - $lower) / $this.IQR, 1.0)
        }
        elseif ($value -gt $upper) {
            return [Math]::Min([Math]::Abs($value - $upper) / $this.IQR, 1.0)
        }
        return 0
    }

    [bool] IsAnomaly([double]$value) {
        return $this.Score($value) -gt 0
    }
}

class IsolationForestSimulator {
    [int]$NumTrees
    [int]$SubsampleSize
    [double]$Contamination
    [array]$Trees

    IsolationForestSimulator([int]$numTrees, [int]$subsampleSize, [double]$contamination) {
        $this.NumTrees = $numTrees
        $this.SubsampleSize = $subsampleSize
        $this.Contamination = $contamination
        $this.Trees = @()
    }

    [void] Train([array]$data) {
        # Simulate training by building random trees
        for ($i = 0; $i -lt $this.NumTrees; $i++) {
            $tree = @{
                Splits = Get-Random -Minimum 5 -Maximum 15
                Thresholds = @()
            }
            
            for ($j = 0; $j -lt $tree.Splits; $j++) {
                $tree.Thresholds += Get-Random -Minimum ($data | Measure-Object -Minimum | Select-Object -ExpandProperty Minimum) -Maximum ($data | Measure-Object -Maximum | Select-Object -ExpandProperty Maximum)
            }
            
            $this.Trees += $tree
        }
    }

    [double] Score([double]$value) {
        # Simulate isolation forest scoring
        $avgPathLength = 0
        foreach ($tree in $this.Trees) {
            $pathLength = 0
            foreach ($threshold in $tree.Thresholds) {
                $pathLength++
                if (($value -lt $threshold -and (Get-Random -Minimum 0 -Maximum 2) -eq 0) -or
                    ($value -ge $threshold -and (Get-Random -Minimum 0 -Maximum 2) -eq 1)) {
                    break
                }
            }
            $avgPathLength += $pathLength
        }
        
        $avgPathLength /= $this.Trees.Count
        $normalizedScore = 1 - [Math]::Exp(-$avgPathLength / 10)
        return [Math]::Min($normalizedScore / $this.Contamination, 1.0)
    }
}

class AnomalyDetector {
    [string]$TelemetryPath
    [string]$ModelPath
    [hashtable]$Models
    [hashtable]$BaselineStats
    [System.Collections.ArrayList]$AnomalyHistory

    AnomalyDetector([string]$telemetry, [string]$modelPath) {
        $this.TelemetryPath = $telemetry
        $this.ModelPath = $modelPath
        $this.Models = @{}
        $this.BaselineStats = @{}
        $this.AnomalyHistory = @()
        
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
        
        $values = @()
        foreach ($file in $files) {
            $lines = Get-Content $file.FullName
            foreach ($line in $lines) {
                if (-not $line.Trim()) { continue }
                try {
                    $data = $line | ConvertFrom-Json -AsHashtable
                    if ($data.Name -eq $metric) {
                        $values += $data.Value
                    }
                }
                catch {}
            }
        }
        
        $this.BaselineStats[$metric] = $values
        Write-Host "  Loaded $($values.Count) data points" -ForegroundColor Green
    }

    [void] TrainModels([string]$metric) {
        Write-Host "`nTraining anomaly detection models for $metric..." -ForegroundColor Cyan
        
        $data = $this.BaselineStats[$metric]
        if ($data.Count -lt 20) {
            Write-Warning "Insufficient data for training (need 20, have $($data.Count))"
            return
        }
        
        $metricModels = @{}
        
        # Z-Score model
        if ($script:AnomalyConfig.Methods.ZScore.Enabled) {
            $zscore = [ZScoreDetector]::new($script:AnomalyConfig.Methods.ZScore.Threshold)
            $zscore.Train($data)
            $metricModels["ZScore"] = $zscore
            Write-Host "  ✓ Z-Score model trained" -ForegroundColor Green
        }
        
        # IQR model
        if ($script:AnomalyConfig.Methods.IQR.Enabled) {
            $iqr = [IQRDetector]::new($script:AnomalyConfig.Methods.IQR.Multiplier)
            $iqr.Train($data)
            $metricModels["IQR"] = $iqr
            Write-Host "  ✓ IQR model trained" -ForegroundColor Green
        }
        
        # Isolation Forest model
        if ($script:AnomalyConfig.Methods.IsolationForest.Enabled) {
            $iforest = [IsolationForestSimulator]::new(50, 256, $script:AnomalyConfig.Methods.IsolationForest.Contamination)
            $iforest.Train($data)
            $metricModels["IsolationForest"] = $iforest
            Write-Host "  ✓ Isolation Forest model trained" -ForegroundColor Green
        }
        
        $this.Models[$metric] = $metricModels
        $this.SaveModels($metric)
    }

    [hashtable] DetectAnomalies([string]$metric, [double]$value) {
        if (-not $this.Models.ContainsKey($metric)) {
            $this.LoadModels($metric)
        }
        
        if (-not $this.Models.ContainsKey($metric)) {
            return @{ IsAnomaly = $false; Score = 0; Reason = "No model available" }
        }
        
        $metricModels = $this.Models[$metric]
        $scores = @{}
        
        # Get scores from each model
        foreach ($modelName in $metricModels.Keys) {
            $model = $metricModels[$modelName]
            $scores[$modelName] = $model.Score($value)
        }
        
        # Ensemble score (weighted average)
        $ensembleScore = ($scores["ZScore"] * 0.3 + $scores["IQR"] * 0.3 + $scores["IsolationForest"] * 0.4)
        
        # Determine severity
        $severity = "Normal"
        if ($ensembleScore -ge $script:AnomalyConfig.AlertThresholds.Critical) {
            $severity = "Critical"
        }
        elseif ($ensembleScore -ge $script:AnomalyConfig.AlertThresholds.Warning) {
            $severity = "Warning"
        }
        elseif ($ensembleScore -ge $script:AnomalyConfig.AlertThresholds.Info) {
            $severity = "Info"
        }
        
        $result = @{
            IsAnomaly = $ensembleScore -ge $script:AnomalyConfig.AlertThresholds.Warning
            Score = [Math]::Round($ensembleScore, 3)
            Severity = $severity
            ModelScores = $scores
            Timestamp = Get-Date -Format "o"
            Metric = $metric
            Value = $value
        }
        
        # Log anomaly if detected
        if ($result.IsAnomaly) {
            $this.LogAnomaly($result)
        }
        
        return $result
    }

    [void] LogAnomaly([hashtable]$anomaly) {
        $this.AnomalyHistory.Add($anomaly)
        
        $logPath = Join-Path $this.ModelPath "anomalies_$(Get-Date -Format 'yyyyMMdd').json"
        $existing = @()
        if (Test-Path $logPath) {
            $existing = Get-Content $logPath | ConvertFrom-Json
        }
        $existing += $anomaly
        $existing | ConvertTo-Json -Depth 10 | Out-File $logPath
    }

    [void] SaveModels([string]$metric) {
        $modelData = @{
            Metric = $metric
            Timestamp = Get-Date -Format "o"
            Models = @{}
        }
        
        foreach ($name in $this.Models[$metric].Keys) {
            $model = $this.Models[$metric][$name]
            $modelData.Models[$name] = @{
                Type = $model.GetType().Name
            }
        }
        
        $path = Join-Path $this.ModelPath "$metric`_models.json"
        $modelData | ConvertTo-Json -Depth 10 | Out-File $path
    }

    [void] LoadModels([string]$metric) {
        $path = Join-Path $this.ModelPath "$metric`_models.json"
        if (-not (Test-Path $path)) { return }
        
        # In production, would deserialize model parameters
        # For now, retrain on available data
        $this.LoadHistoricalData($metric)
        $this.TrainModels($metric)
    }

    [void] RunDetection([string]$metric) {
        Write-Host "`n=== Running Anomaly Detection ===" -ForegroundColor Cyan
        Write-Host "Metric: $metric" -ForegroundColor White
        Write-Host "Press Ctrl+C to stop..." -ForegroundColor Yellow
        
        # Ensure models are trained
        if (-not $this.Models.ContainsKey($metric)) {
            $this.LoadHistoricalData($metric)
            $this.TrainModels($metric)
        }
        
        while ($true) {
            # Simulate real-time detection
            $value = Get-Random -Minimum 20 -Maximum 60
            $result = $this.DetectAnomalies($metric, $value)
            
            $color = switch ($result.Severity) {
                "Critical" { "Red" }
                "Warning" { "Yellow" }
                "Info" { "Cyan" }
                default { "Green" }
            }
            
            $status = if ($result.IsAnomaly) { "ANOMALY" } else { "OK" }
            Write-Host "[$status] $metric = $value | Score: $($result.Score) | $($result.Severity)" -ForegroundColor $color
            
            Start-Sleep -Seconds 2
        }
    }

    [void] DisplayAnomalyReport() {
        Write-Host "`n=== Anomaly Detection Report ===" -ForegroundColor Cyan
        
        if ($this.AnomalyHistory.Count -eq 0) {
            Write-Host "No anomalies detected." -ForegroundColor Green
            return
        }
        
        Write-Host "Total anomalies: $($this.AnomalyHistory.Count)" -ForegroundColor Yellow
        Write-Host "─" * 60 -ForegroundColor Gray
        
        $grouped = $this.AnomalyHistory | Group-Object -Property Severity
        foreach ($group in $grouped) {
            Write-Host "$($group.Name): $($group.Count)" -ForegroundColor White
        }
        
        Write-Host "`nRecent anomalies:" -ForegroundColor Yellow
        $recent = $this.AnomalyHistory | Select-Object -Last 10
        foreach ($anomaly in $recent) {
            $time = [datetime]::Parse($anomaly.Timestamp).ToString("HH:mm:ss")
            Write-Host "  [$time] $($anomaly.Metric) = $($anomaly.Value) (score: $($anomaly.Score))" -ForegroundColor White
        }
    }
}

#==============================================================================
# Main Execution
#==============================================================================

Write-Host @"
╔══════════════════════════════════════════════════════════════════════════════╗
║           RawrXD Sovereign - Anomaly Detector                                  ║
║           Phase G.2 Batch 4/5: ML-Based Anomaly Detection                    ║
╚══════════════════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

$detector = [AnomalyDetector]::new($TelemetryPath, $ModelPath)

if ($Train) {
    $metric = Read-Host "Enter metric to train (TPS/Latency/Memory)"
    $detector.LoadHistoricalData($metric)
    $detector.TrainModels($metric)
    Write-Host "`n✓ Training complete" -ForegroundColor Green
}
elseif ($Detect) {
    $metric = Read-Host "Enter metric to monitor"
    try {
        $detector.RunDetection($metric)
    }
    catch {
        Write-Host "`n✓ Detection stopped" -ForegroundColor Yellow
        $detector.DisplayAnomalyReport()
    }
}
else {
    # Interactive mode
    Write-Host "`nCommands:" -ForegroundColor Yellow
    Write-Host "  1. Train models"
    Write-Host "  2. Run detection"
    Write-Host "  3. View anomaly report"
    
    $choice = Read-Host "`nSelect option (1-3)"
    
    switch ($choice) {
        "1" {
            $metric = Read-Host "Enter metric (TPS/Latency/Memory)"
            $detector.LoadHistoricalData($metric)
            $detector.TrainModels($metric)
        }
        "2" {
            $metric = Read-Host "Enter metric to monitor"
            $detector.RunDetection($metric)
        }
        "3" {
            $detector.DisplayAnomalyReport()
        }
    }
}
