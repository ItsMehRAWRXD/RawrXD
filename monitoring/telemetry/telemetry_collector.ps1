#!/usr/bin/env pwsh
#==============================================================================
# RawrXD Sovereign Inferencer - Telemetry Collection Pipeline
# Phase G.1 Batch 1/5: Real-time Metrics Ingestion
#==============================================================================
# Collects real-time metrics from RawrXD runtime with hotpatch tracking
#==============================================================================

[CmdletBinding()]
param(
    [Parameter()]
    [string]$Endpoint = "http://localhost:8080/metrics",

    [Parameter()]
    [int]$CollectionIntervalSeconds = 5,

    [Parameter()]
    [string]$OutputPath = ".\telemetry_data",

    [Parameter()]
    [ValidateSet("File", "InfluxDB", "Prometheus", "Console")]
    [string]$OutputMode = "File",

    [Parameter()]
    [switch]$EnableHotpatchTracking,

    [Parameter()]
    [switch]$DetectDegradation,

    [Parameter()]
    [double]$DegradationThreshold = 10.0  # Percentage drop to flag
)

#==============================================================================
# Telemetry Configuration
#==============================================================================

$script:TelemetryConfig = @{
    Version = "1.0.0"
    Metrics = @(
        @{ Name = "TPS"; Unit = "tokens/sec"; Type = "gauge"; Threshold = 30 }
        @{ Name = "TTFT"; Unit = "ms"; Type = "gauge"; Threshold = 50 }
        @{ Name = "Latency"; Unit = "ms"; Type = "gauge"; Threshold = 100 }
        @{ Name = "MemoryUsage"; Unit = "MB"; Type = "gauge"; Threshold = 8192 }
        @{ Name = "GPUUtilization"; Unit = "percent"; Type = "gauge"; Threshold = 95 }
        @{ Name = "ActiveRequests"; Unit = "count"; Type = "counter"; Threshold = 100 }
        @{ Name = "HotpatchStatus"; Unit = "status"; Type = "enum"; Threshold = 0 }
    )
    RetentionHours = 168  # 7 days
    BatchSize = 100
}

#==============================================================================
# Telemetry Collector Classes
#==============================================================================

class TelemetryCollector {
    [string]$Endpoint
    [int]$IntervalSeconds
    [string]$OutputPath
    [string]$OutputMode
    [bool]$TrackHotpatches
    [bool]$DetectDegradation
    [double]$DegradationThreshold
    [hashtable]$CurrentMetrics
    [hashtable]$BaselineMetrics
    [System.Collections.ArrayList]$HotpatchHistory
    [System.Collections.ArrayList]$DegradationEvents
    [bool]$IsRunning
    [datetime]$StartTime

    TelemetryCollector([string]$endpoint, [int]$interval, [string]$output, 
                       [string]$mode, [bool]$trackHotpatches, [bool]$detectDegradation,
                       [double]$threshold) {
        $this.Endpoint = $endpoint
        $this.IntervalSeconds = $interval
        $this.OutputPath = $output
        $this.OutputMode = $mode
        $this.TrackHotpatches = $trackHotpatches
        $this.DetectDegradation = $detectDegradation
        $this.DegradationThreshold = $threshold
        $this.CurrentMetrics = @{}
        $this.BaselineMetrics = @{}
        $this.HotpatchHistory = @()
        $this.DegradationEvents = @()
        $this.IsRunning = $false
        $this.StartTime = Get-Date
    }

    [void] Initialize() {
        Write-Host "`n=== Initializing Telemetry Collector ===" -ForegroundColor Cyan
        
        New-Item -ItemType Directory -Force -Path $this.OutputPath | Out-Null
        
        # Initialize baseline from historical data if available
        $baselinePath = Join-Path $this.OutputPath "baseline_metrics.json"
        if (Test-Path $baselinePath) {
            $this.BaselineMetrics = Get-Content $baselinePath | ConvertFrom-Json -AsHashtable
            Write-Host "✓ Baseline metrics loaded" -ForegroundColor Green
        }
        else {
            Write-Host "⚠ No baseline found. Will establish after first collection." -ForegroundColor Yellow
        }

        Write-Host "Endpoint: $($this.Endpoint)" -ForegroundColor White
        Write-Host "Interval: $($this.IntervalSeconds)s" -ForegroundColor White
        Write-Host "Output Mode: $($this.OutputMode)" -ForegroundColor White
        Write-Host "Hotpatch Tracking: $($this.TrackHotpatches)" -ForegroundColor White
        Write-Host "Degradation Detection: $($this.DetectDegradation)" -ForegroundColor White
    }

    [hashtable] CollectMetrics() {
        $metrics = @{
            Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
            Collection = @{}
            Hotpatches = @()
        }

        try {
            # Simulate metrics collection from endpoint
            # In production, this would call the actual RawrXD metrics endpoint
            $metrics.Collection = @{
                TPS = [math]::Round((Get-Random -Minimum 35 -Maximum 55) + (Get-Random -Minimum -2 -Maximum 2), 2)
                TTFT_ms = [math]::Round((Get-Random -Minimum 12 -Maximum 22), 2)
                Latency_ms = [math]::Round((Get-Random -Minimum 18 -Maximum 32), 2)
                MemoryUsage_MB = [math]::Round((Get-Random -Minimum 4000 -Maximum 7000), 2)
                GPUUtilization_Percent = [math]::Round((Get-Random -Minimum 60 -Maximum 95), 2)
                ActiveRequests = Get-Random -Minimum 1 -Maximum 20
                RequestsPerSecond = [math]::Round((Get-Random -Minimum 0.5 -Maximum 3.0), 2)
            }

            # Collect hotpatch status if enabled
            if ($this.TrackHotpatches) {
                $metrics.Hotpatches = $this.CollectHotpatchStatus()
            }
        }
        catch {
            Write-Warning "Failed to collect metrics: $_"
            $metrics.Collection.Error = $_.Exception.Message
        }

        return $metrics
    }

    [array] CollectHotpatchStatus() {
        $hotpatches = @()
        
        # Simulate hotpatch status collection
        $patchTypes = @("scheduler", "gemm", "attention", "memory", "simd")
        
        foreach ($patch in $patchTypes) {
            $status = if ((Get-Random -Maximum 100) -gt 95) { "FAILED" } 
                     elseif ((Get-Random -Maximum 100) -gt 90) { "APPLYING" }
                     else { "ACTIVE" }
            
            $hotpatches += @{
                Name = $patch
                Status = $status
                AppliedAt = if ($status -ne "FAILED") { (Get-Date).AddHours(-(Get-Random -Maximum 24)).ToString("yyyy-MM-ddTHH:mm:ssZ") } else { $null }
                DeployTime_ms = if ($status -ne "FAILED") { Get-Random -Minimum 2 -Maximum 6 } else { $null }
                TPS_Impact_Percent = if ($status -eq "ACTIVE") { Get-Random -Minimum 5 -Maximum 25 } else { 0 }
            }
        }

        return $hotpatches
    }

    [void] DetectDegradation([hashtable]$metrics) {
        if (-not $this.BaselineMetrics -or $this.BaselineMetrics.Count -eq 0) {
            # First collection establishes baseline
            $this.BaselineMetrics = $metrics.Collection.Clone()
            return
        }

        $degradations = @()

        # Check TPS degradation
        if ($metrics.Collection.TPS -and $this.BaselineMetrics.TPS) {
            $tpsDrop = (($this.BaselineMetrics.TPS - $metrics.Collection.TPS) / $this.BaselineMetrics.TPS) * 100
            if ($tpsDrop -gt $this.DegradationThreshold) {
                $degradations += @{
                    Metric = "TPS"
                    Baseline = $this.BaselineMetrics.TPS
                    Current = $metrics.Collection.TPS
                    Drop_Percent = [math]::Round($tpsDrop, 2)
                    Severity = if ($tpsDrop -gt 20) { "CRITICAL" } elseif ($tpsDrop -gt 10) { "WARNING" } else { "INFO" }
                    Timestamp = $metrics.Timestamp
                }
            }
        }

        # Check TTFT degradation (higher is worse)
        if ($metrics.Collection.TTFT_ms -and $this.BaselineMetrics.TTFT_ms) {
            $ttftIncrease = (($metrics.Collection.TTFT_ms - $this.BaselineMetrics.TTFT_ms) / $this.BaselineMetrics.TTFT_ms) * 100
            if ($ttftIncrease -gt $this.DegradationThreshold) {
                $degradations += @{
                    Metric = "TTFT"
                    Baseline = $this.BaselineMetrics.TTFT_ms
                    Current = $metrics.Collection.TTFT_ms
                    Increase_Percent = [math]::Round($ttftIncrease, 2)
                    Severity = if ($ttftIncrease -gt 50) { "CRITICAL" } elseif ($ttftIncrease -gt 20) { "WARNING" } else { "INFO" }
                    Timestamp = $metrics.Timestamp
                }
            }
        }

        # Check memory growth
        if ($metrics.Collection.MemoryUsage_MB -and $this.BaselineMetrics.MemoryUsage_MB) {
            $memGrowth = (($metrics.Collection.MemoryUsage_MB - $this.BaselineMetrics.MemoryUsage_MB) / $this.BaselineMetrics.MemoryUsage_MB) * 100
            if ($memGrowth -gt 50) {
                $degradations += @{
                    Metric = "Memory"
                    Baseline = $this.BaselineMetrics.MemoryUsage_MB
                    Current = $metrics.Collection.MemoryUsage_MB
                    Growth_Percent = [math]::Round($memGrowth, 2)
                    Severity = "WARNING"
                    Timestamp = $metrics.Timestamp
                }
            }
        }

        if ($degradations.Count -gt 0) {
            $this.DegradationEvents.AddRange($degradations)
            foreach ($deg in $degradations) {
                $color = switch ($deg.Severity) {
                    "CRITICAL" { "Red" }
                    "WARNING" { "Yellow" }
                    default { "Gray" }
                }
                Write-Host "  ⚠ $($deg.Severity): $($deg.Metric) degradation detected" -ForegroundColor $color
            }
        }
    }

    [void] ProcessHotpatchEvents([hashtable]$metrics) {
        if (-not $metrics.Hotpatches -or $metrics.Hotpatches.Count -eq 0) { return }

        foreach ($patch in $metrics.Hotpatches) {
            # Check for state changes
            $existing = $this.HotpatchHistory | Where-Object { $_.Name -eq $patch.Name } | Select-Object -Last 1
            
            if (-not $existing -or $existing.Status -ne $patch.Status) {
                # State change detected
                $event = @{
                    Name = $patch.Name
                    Status = $patch.Status
                    PreviousStatus = if ($existing) { $existing.Status } else { "NONE" }
                    Timestamp = $metrics.Timestamp
                    DeployTime_ms = $patch.DeployTime_ms
                    TPS_Impact = $patch.TPS_Impact_Percent
                }
                
                $this.HotpatchHistory.Add($event)
                
                $color = switch ($patch.Status) {
                    "ACTIVE" { "Green" }
                    "FAILED" { "Red" }
                    "APPLYING" { "Yellow" }
                    default { "Gray" }
                }
                Write-Host "  🔧 Hotpatch $($patch.Name): $($event.PreviousStatus) → $($patch.Status)" -ForegroundColor $color
            }
        }
    }

    [void] OutputMetrics([hashtable]$metrics) {
        switch ($this.OutputMode) {
            "File" { $this.OutputToFile($metrics) }
            "Console" { $this.OutputToConsole($metrics) }
            "InfluxDB" { $this.OutputToInfluxDB($metrics) }
            "Prometheus" { $this.OutputToPrometheus($metrics) }
        }
    }

    [void] OutputToFile([hashtable]$metrics) {
        $date = Get-Date -Format "yyyy-MM-dd"
        $filePath = Join-Path $this.OutputPath "telemetry_$date.jsonl"
        
        ($metrics | ConvertTo-Json -Compress) | Out-File -FilePath $filePath -Append
    }

    [void] OutputToConsole([hashtable]$metrics) {
        $time = [DateTime]::Parse($metrics.Timestamp).ToString("HH:mm:ss")
        Write-Host "[$time] " -NoNewline -ForegroundColor Gray
        Write-Host "TPS: $($metrics.Collection.TPS)" -NoNewline -ForegroundColor Green
        Write-Host " | TTFT: $($metrics.Collection.TTFT_ms)ms" -NoNewline -ForegroundColor Cyan
        Write-Host " | Latency: $($metrics.Collection.Latency_ms)ms" -NoNewline -ForegroundColor White
        Write-Host " | GPU: $($metrics.Collection.GPUUtilization_Percent)%" -ForegroundColor Yellow
    }

    [void] OutputToInfluxDB([hashtable]$metrics) {
        # Placeholder for InfluxDB integration
        # In production, this would use InfluxDB client
        Write-Verbose "InfluxDB output not implemented in this version"
    }

    [void] OutputToPrometheus([hashtable]$metrics) {
        # Placeholder for Prometheus integration
        # In production, this would expose metrics endpoint
        Write-Verbose "Prometheus output not implemented in this version"
    }

    [void] RunCollection() {
        Write-Host "`n=== Starting Telemetry Collection ===" -ForegroundColor Cyan
        Write-Host "Press Ctrl+C to stop...`n" -ForegroundColor Gray

        $this.IsRunning = $true
        $collectionCount = 0

        while ($this.IsRunning) {
            $metrics = $this.CollectMetrics()
            
            # Process metrics
            if ($this.DetectDegradation) {
                $this.DetectDegradation($metrics)
            }
            
            if ($this.TrackHotpatches) {
                $this.ProcessHotpatchEvents($metrics)
            }
            
            # Output metrics
            $this.OutputMetrics($metrics)
            
            $collectionCount++
            $this.CurrentMetrics = $metrics
            
            Start-Sleep -Seconds $this.IntervalSeconds
        }
    }

    [void] GenerateSummary() {
        $duration = (Get-Date) - $this.StartTime
        
        Write-Host "`n=== Telemetry Collection Summary ===" -ForegroundColor Cyan
        Write-Host "Duration: $([math]::Round($duration.TotalMinutes, 2)) minutes" -ForegroundColor White
        Write-Host "Collections: $($this.DegradationEvents.Count + 1)" -ForegroundColor White
        Write-Host "Degradation Events: $($this.DegradationEvents.Count)" -ForegroundColor $(
            if ($this.DegradationEvents.Count -eq 0) { "Green" } else { "Yellow" }
        )
        Write-Host "Hotpatch Events: $($this.HotpatchHistory.Count)" -ForegroundColor White

        if ($this.DegradationEvents.Count -gt 0) {
            Write-Host "`nDegradation Events:" -ForegroundColor Yellow
            $this.DegradationEvents | Group-Object Metric | ForEach-Object {
                Write-Host "  $($_.Name): $($_.Count) events" -ForegroundColor Gray
            }
        }

        # Save summary
        $summary = @{
            StartTime = $this.StartTime.ToString("yyyy-MM-ddTHH:mm:ssZ")
            EndTime = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
            Duration_Minutes = [math]::Round($duration.TotalMinutes, 2)
            DegradationEvents = $this.DegradationEvents
            HotpatchEvents = $this.HotpatchHistory
            FinalMetrics = $this.CurrentMetrics
        }

        $summaryPath = Join-Path $this.OutputPath "telemetry_summary.json"
        $summary | ConvertTo-Json -Depth 10 | Out-File $summaryPath
        Write-Host "`n✓ Summary saved: $summaryPath" -ForegroundColor Green
    }

    [void] Stop() {
        $this.IsRunning = $false
        $this.GenerateSummary()
    }
}

#==============================================================================
# Main Execution
#==============================================================================

Write-Host @"
╔══════════════════════════════════════════════════════════════════════════════╗
║           RawrXD Sovereign - Telemetry Collection Pipeline                   ║
║           Phase G.1 Batch 1/5: Real-time Metrics Ingestion                   ║
╚══════════════════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

$collector = [TelemetryCollector]::new(
    $Endpoint,
    $CollectionIntervalSeconds,
    $OutputPath,
    $OutputMode,
    $EnableHotpatchTracking,
    $DetectDegradation,
    $DegradationThreshold
)

$collector.Initialize()

# Handle Ctrl+C gracefully
$null = Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action {
    Write-Host "`n⚠ Stopping telemetry collection..." -ForegroundColor Yellow
    $collector.Stop()
}

# Run collection
try {
    $collector.RunCollection()
}
finally {
    $collector.GenerateSummary()
}
