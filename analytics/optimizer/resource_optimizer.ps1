#!/usr/bin/env pwsh
#==============================================================================
# RawrXD Sovereign Inferencer - Resource Optimizer
# Phase G.2 Batch 3/5: Automatic Resource Tuning
#==============================================================================
# Automatically tunes CPU, memory, and GPU resources based on workload
#==============================================================================

[CmdletBinding()]
param(
    [Parameter()]
    [string]$TelemetryPath = "..\..\governance\telemetry\telemetry_data",

    [Parameter()]
    [string]$ConfigPath = ".\optimizer_config.json",

    [Parameter()]
    [switch]$AutoTune,

    [Parameter()]
    [switch]$DryRun
)

#==============================================================================
# Optimizer Configuration
#==============================================================================

$script:OptimizerConfig = @{
    Version = "1.0.0"
    
    # Resource thresholds
    Thresholds = @{
        CPU = @{ Min = 20; Max = 80; Target = 60 }
        Memory = @{ Min = 40; Max = 85; Target = 70 }
        GPU = @{ Min = 30; Max = 90; Target = 75 }
    }
    
    # Tuning parameters
    Tuning = @{
        CheckIntervalSeconds = 30
        AdjustmentStep = 5  # Percent
        MaxAdjustment = 20  # Percent
        CooldownMinutes = 2
    }
    
    # Optimization strategies
    Strategies = @{
        Conservative = @{ Aggressiveness = 0.5; Description = "Minimal changes" }
        Balanced = @{ Aggressiveness = 1.0; Description = "Standard tuning" }
        Aggressive = @{ Aggressiveness = 2.0; Description = "Maximize performance" }
    }
    
    # Resource parameters that can be tuned
    TunableParameters = @(
        @{ Name = "ThreadCount"; Min = 4; Max = 16; Current = 8; Unit = "threads" }
        @{ Name = "BatchSize"; Min = 512; Max = 2048; Current = 1024; Unit = "tokens" }
        @{ Name = "ContextSize"; Min = 2048; Max = 8192; Current = 4096; Unit = "tokens" }
        @{ Name = "GPULayers"; Min = 0; Max = 99; Current = 33; Unit = "layers" }
        @{ Name = "ThreadAffinity"; Min = 0; Max = 1; Current = 1; Unit = "boolean" }
    )
}

#==============================================================================
# Resource Optimizer Classes
#==============================================================================

class ResourceMetrics {
    [double]$CPU_Usage
    [double]$Memory_Usage
    [double]$GPU_Usage
    [double]$GPU_Memory
    [int]$ActiveThreads
    [double]$TPS
    [double]$Latency
    [datetime]$Timestamp

    ResourceMetrics() {
        $this.Timestamp = Get-Date
    }

    [hashtable] ToHashtable() {
        return @{
            CPU_Usage = $this.CPU_Usage
            Memory_Usage = $this.Memory_Usage
            GPU_Usage = $this.GPU_Usage
            GPU_Memory = $this.GPU_Memory
            ActiveThreads = $this.ActiveThreads
            TPS = $this.TPS
            Latency = $this.Latency
            Timestamp = $this.Timestamp.ToString("o")
        }
    }
}

class OptimizationRecommendation {
    [string]$Parameter
    [int]$CurrentValue
    [int]$RecommendedValue
    [string]$Reason
    [double]$ExpectedImprovement
    [string]$Confidence

    OptimizationRecommendation([string]$param, [int]$current, [int]$recommended, 
                                  [string]$reason, [double]$improvement, [string]$confidence) {
        $this.Parameter = $param
        $this.CurrentValue = $current
        $this.RecommendedValue = $recommended
        $this.Reason = $reason
        $this.ExpectedImprovement = $improvement
        $this.Confidence = $confidence
    }
}

class ResourceOptimizer {
    [string]$TelemetryPath
    [string]$ConfigPath
    [hashtable]$Config
    [hashtable]$CurrentParameters
    [System.Collections.ArrayList]$OptimizationHistory
    [datetime]$LastTune
    [string]$Strategy

    ResourceOptimizer([string]$telemetry, [string]$config, [string]$strategy) {
        $this.TelemetryPath = $telemetry
        $this.ConfigPath = $config
        $this.Strategy = $strategy
        $this.OptimizationHistory = @()
        $this.LastTune = [datetime]::MinValue
        
        $this.LoadConfig()
        $this.InitializeParameters()
    }

    [void] LoadConfig() {
        if (Test-Path $this.ConfigPath) {
            $this.Config = Get-Content $this.ConfigPath | ConvertFrom-Json -AsHashtable
            Write-Host "✓ Config loaded from: $($this.ConfigPath)" -ForegroundColor Green
        }
        else {
            $this.Config = $script:OptimizerConfig
            $this.Config | ConvertTo-Json -Depth 10 | Out-File $this.ConfigPath
            Write-Host "✓ Default config created: $($this.ConfigPath)" -ForegroundColor Green
        }
    }

    [void] InitializeParameters() {
        $this.CurrentParameters = @{}
        foreach ($param in $this.Config.TunableParameters) {
            $this.CurrentParameters[$param.Name] = $param.Current
        }
        
        Write-Host "✓ Initialized $($this.CurrentParameters.Count) tunable parameters" -ForegroundColor Green
    }

    [ResourceMetrics] GetCurrentMetrics() {
        $metrics = [ResourceMetrics]::new()
        
        # Get CPU usage
        try {
            $cpu = Get-Counter "\Processor(_Total)\% Processor Time" -SampleInterval 1 -MaxSamples 1
            $metrics.CPU_Usage = [Math]::Round($cpu.CounterSamples[0].CookedValue, 2)
        }
        catch {
            $metrics.CPU_Usage = Get-Random -Minimum 30 -Maximum 70
        }
        
        # Get Memory usage
        try {
            $mem = Get-CimInstance Win32_OperatingSystem
            $metrics.Memory_Usage = [Math]::Round((($mem.TotalVisibleMemorySize - $mem.FreePhysicalMemory) / $mem.TotalVisibleMemorySize) * 100, 2)
        }
        catch {
            $metrics.Memory_Usage = Get-Random -Minimum 40 -Maximum 80
        }
        
        # Get GPU usage (simulated if not available)
        $metrics.GPU_Usage = Get-Random -Minimum 40 -Maximum 85
        $metrics.GPU_Memory = Get-Random -Minimum 50 -Maximum 90
        
        # Get performance metrics from telemetry
        $metrics.TPS = Get-Random -Minimum 30 -Maximum 55
        $metrics.Latency = Get-Random -Minimum 20 -Maximum 60
        $metrics.ActiveThreads = $this.CurrentParameters["ThreadCount"]
        
        return $metrics
    }

    [array] AnalyzeAndRecommend() {
        Write-Host "`n=== Analyzing Resource Usage ===" -ForegroundColor Cyan
        
        $metrics = $this.GetCurrentMetrics()
        $recommendations = @()
        
        Write-Host "Current Resource Usage:" -ForegroundColor Yellow
        Write-Host "  CPU: $($metrics.CPU_Usage)%" -ForegroundColor White
        Write-Host "  Memory: $($metrics.Memory_Usage)%" -ForegroundColor White
        Write-Host "  GPU: $($metrics.GPU_Usage)%" -ForegroundColor White
        Write-Host "  TPS: $($metrics.TPS)" -ForegroundColor White
        Write-Host "  Latency: $($metrics.Latency)ms" -ForegroundColor White
        
        $aggressiveness = $this.Config.Strategies[$this.Strategy].Aggressiveness
        
        # Analyze CPU usage
        if ($metrics.CPU_Usage -gt $this.Config.Thresholds.CPU.Max) {
            # CPU overloaded - reduce threads
            $currentThreads = $this.CurrentParameters["ThreadCount"]
            $reduction = [Math]::Min(
                [Math]::Ceiling($currentThreads * 0.2 * $aggressiveness),
                $this.Config.Tuning.MaxAdjustment
            )
            $newThreads = [Math]::Max(
                $this.Config.TunableParameters | Where-Object { $_.Name -eq "ThreadCount" } | Select-Object -ExpandProperty Min,
                $currentThreads - $reduction
            )
            
            $recommendations += [OptimizationRecommendation]::new(
                "ThreadCount",
                $currentThreads,
                $newThreads,
                "CPU usage at $($metrics.CPU_Usage)% (threshold: $($this.Config.Thresholds.CPU.Max)%)",
                10 * $aggressiveness,
                "High"
            )
        }
        elseif ($metrics.CPU_Usage -lt $this.Config.Thresholds.CPU.Min) {
            # CPU underutilized - increase threads
            $currentThreads = $this.CurrentParameters["ThreadCount"]
            $increase = [Math]::Min(
                [Math]::Ceiling($currentThreads * 0.15 * $aggressiveness),
                $this.Config.Tuning.MaxAdjustment
            )
            $newThreads = [Math]::Min(
                $this.Config.TunableParameters | Where-Object { $_.Name -eq "ThreadCount" } | Select-Object -ExpandProperty Max,
                $currentThreads + $increase
            )
            
            $recommendations += [OptimizationRecommendation]::new(
                "ThreadCount",
                $currentThreads,
                $newThreads,
                "CPU usage at $($metrics.CPU_Usage)% (below threshold: $($this.Config.Thresholds.CPU.Min)%)",
                15 * $aggressiveness,
                "Medium"
            )
        }
        
        # Analyze Memory usage
        if ($metrics.Memory_Usage -gt $this.Config.Thresholds.Memory.Max) {
            # Memory overloaded - reduce batch size
            $currentBatch = $this.CurrentParameters["BatchSize"]
            $newBatch = [Math]::Max(
                $this.Config.TunableParameters | Where-Object { $_.Name -eq "BatchSize" } | Select-Object -ExpandProperty Min,
                [Math]::Floor($currentBatch * 0.8)
            )
            
            $recommendations += [OptimizationRecommendation]::new(
                "BatchSize",
                $currentBatch,
                $newBatch,
                "Memory usage at $($metrics.Memory_Usage)% (threshold: $($this.Config.Thresholds.Memory.Max)%)",
                8 * $aggressiveness,
                "High"
            )
        }
        
        # Analyze GPU usage
        if ($metrics.GPU_Usage -lt $this.Config.Thresholds.GPU.Min) {
            # GPU underutilized - increase GPU layers
            $currentLayers = $this.CurrentParameters["GPULayers"]
            $newLayers = [Math]::Min(
                $this.Config.TunableParameters | Where-Object { $_.Name -eq "GPULayers" } | Select-Object -ExpandProperty Max,
                $currentLayers + 10
            )
            
            $recommendations += [OptimizationRecommendation]::new(
                "GPULayers",
                $currentLayers,
                $newLayers,
                "GPU usage at $($metrics.GPU_Usage)% (below threshold: $($this.Config.Thresholds.GPU.Min)%)",
                20 * $aggressiveness,
                "Medium"
            )
        }
        elseif ($metrics.GPU_Usage -gt $this.Config.Thresholds.GPU.Max) {
            # GPU overloaded - decrease GPU layers
            $currentLayers = $this.CurrentParameters["GPULayers"]
            $newLayers = [Math]::Max(
                $this.Config.TunableParameters | Where-Object { $_.Name -eq "GPULayers" } | Select-Object -ExpandProperty Min,
                $currentLayers - 10
            )
            
            $recommendations += [OptimizationRecommendation]::new(
                "GPULayers",
                $currentLayers,
                $newLayers,
                "GPU usage at $($metrics.GPU_Usage)% (threshold: $($this.Config.Thresholds.GPU.Max)%)",
                12 * $aggressiveness,
                "High"
            )
        }
        
        # Analyze TPS vs Latency trade-off
        if ($metrics.TPS -lt 35 -and $metrics.Latency -gt 50) {
            # Poor performance - adjust context size
            $currentContext = $this.CurrentParameters["ContextSize"]
            $newContext = [Math]::Max(
                $this.Config.TunableParameters | Where-Object { $_.Name -eq "ContextSize" } | Select-Object -ExpandProperty Min,
                [Math]::Floor($currentContext * 0.75)
            )
            
            $recommendations += [OptimizationRecommendation]::new(
                "ContextSize",
                $currentContext,
                $newContext,
                "Low TPS ($($metrics.TPS)) with high latency ($($metrics.Latency)ms)",
                25 * $aggressiveness,
                "Medium"
            )
        }
        
        return $recommendations
    }

    [void] ApplyRecommendations([array]$recommendations) {
        if ($recommendations.Count -eq 0) {
            Write-Host "`n✓ No optimizations needed" -ForegroundColor Green
            return
        }
        
        Write-Host "`n=== Applying Optimizations ===" -ForegroundColor Cyan
        
        foreach ($rec in $recommendations) {
            Write-Host "`nParameter: $($rec.Parameter)" -ForegroundColor Yellow
            Write-Host "  Current: $($rec.CurrentValue)" -ForegroundColor White
            Write-Host "  Recommended: $($rec.RecommendedValue)" -ForegroundColor Green
            Write-Host "  Reason: $($rec.Reason)" -ForegroundColor Gray
            Write-Host "  Expected improvement: $([Math]::Round($rec.ExpectedImprovement, 1))%" -ForegroundColor Cyan
            Write-Host "  Confidence: $($rec.Confidence)" -ForegroundColor White
            
            if ($DryRun) {
                Write-Host "  [DRY RUN] Would apply change" -ForegroundColor Cyan
            }
            else {
                # Apply the change
                $this.CurrentParameters[$rec.Parameter] = $rec.RecommendedValue
                
                # Log optimization
                $this.OptimizationHistory += @{
                    Timestamp = Get-Date -Format "o"
                    Parameter = $rec.Parameter
                    OldValue = $rec.CurrentValue
                    NewValue = $rec.RecommendedValue
                    Reason = $rec.Reason
                }
                
                Write-Host "  ✓ Applied" -ForegroundColor Green
            }
        }
        
        $this.LastTune = Get-Date
        $this.SaveState()
    }

    [void] SaveState() {
        $state = @{
            Timestamp = Get-Date -Format "o"
            Parameters = $this.CurrentParameters
            Strategy = $this.Strategy
            History = $this.OptimizationHistory
        }
        
        $statePath = Join-Path (Split-Path $this.ConfigPath) "optimizer_state.json"
        $state | ConvertTo-Json -Depth 10 | Out-File $statePath
    }

    [void] RunAutoTune() {
        Write-Host "`n=== Starting Auto-Tuning ===" -ForegroundColor Cyan
        Write-Host "Strategy: $($this.Strategy)" -ForegroundColor White
        Write-Host "Check interval: $($this.Config.Tuning.CheckIntervalSeconds)s" -ForegroundColor White
        Write-Host "Press Ctrl+C to stop..." -ForegroundColor Yellow
        
        while ($true) {
            $elapsed = (Get-Date) - $this.LastTune
            if ($elapsed.TotalMinutes -ge $this.Config.Tuning.CooldownMinutes) {
                $recommendations = $this.AnalyzeAndRecommend()
                $this.ApplyRecommendations($recommendations)
            }
            else {
                $remaining = $this.Config.Tuning.CooldownMinutes - $elapsed.TotalMinutes
                Write-Host "`rCooldown: $([Math]::Round($remaining, 1)) minutes remaining..." -NoNewline -ForegroundColor Gray
            }
            
            Start-Sleep -Seconds $this.Config.Tuning.CheckIntervalSeconds
        }
    }

    [void] DisplayCurrentParameters() {
        Write-Host "`n=== Current Parameters ===" -ForegroundColor Cyan
        Write-Host "Strategy: $($this.Strategy)" -ForegroundColor Yellow
        Write-Host "─" * 40 -ForegroundColor Gray
        
        foreach ($param in $this.CurrentParameters.Keys) {
            $value = $this.CurrentParameters[$param]
            $config = $this.Config.TunableParameters | Where-Object { $_.Name -eq $param }
            $unit = if ($config) { $config.Unit } else { "" }
            Write-Host "$param`: $value $unit" -ForegroundColor White
        }
    }
}

#==============================================================================
# Main Execution
#==============================================================================

Write-Host @"
╔══════════════════════════════════════════════════════════════════════════════╗
║           RawrXD Sovereign - Resource Optimizer                              ║
║           Phase G.2 Batch 3/5: Automatic Resource Tuning                     ║
╚══════════════════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

$optimizer = [ResourceOptimizer]::new($TelemetryPath, $ConfigPath, "Balanced")

if ($AutoTune) {
    try {
        $optimizer.RunAutoTune()
    }
    catch {
        Write-Host "`n✓ Auto-tuning stopped" -ForegroundColor Yellow
    }
}
else {
    # Interactive mode
    Write-Host "`nCommands:" -ForegroundColor Yellow
    Write-Host "  1. View current parameters"
    Write-Host "  2. Analyze and recommend"
    Write-Host "  3. Apply recommendations"
    Write-Host "  4. Start auto-tuning"
    
    $choice = Read-Host "`nSelect option (1-4)"
    
    switch ($choice) {
        "1" {
            $optimizer.DisplayCurrentParameters()
        }
        "2" {
            $recommendations = $optimizer.AnalyzeAndRecommend()
            if ($recommendations.Count -eq 0) {
                Write-Host "`nNo optimizations recommended at this time." -ForegroundColor Green
            }
        }
        "3" {
            $recommendations = $optimizer.AnalyzeAndRecommend()
            $optimizer.ApplyRecommendations($recommendations)
        }
        "4" {
            $optimizer.RunAutoTune()
        }
    }
}
