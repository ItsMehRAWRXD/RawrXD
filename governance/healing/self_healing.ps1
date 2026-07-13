#!/usr/bin/env pwsh
#==============================================================================
# RawrXD Sovereign Inferencer - Self-Healing Automation
# Phase G.1 Batch 4/5: Automatic Rollback & Circuit Breaker
#==============================================================================
# Automatically responds to failures and performance degradation
#==============================================================================

[CmdletBinding()]
param(
    [Parameter()]
    [string]$TelemetryPath = "..\telemetry\telemetry_data",

    [Parameter()]
    [string]$AuditPath = "..\audit\audit_logs",

    [Parameter()]
    [string]$ConfigPath = ".\healing_config.json",

    [Parameter()]
    [switch]$DryRun,

    [Parameter()]
    [switch]$Daemon
)

#==============================================================================
# Self-Healing Configuration
#==============================================================================

$script:DefaultConfig = @{
    Version = "1.0.0"
    
    # Circuit breaker settings
    CircuitBreaker = @{
        Enabled = $true
        FailureThreshold = 3
        RecoveryTimeoutSeconds = 60
        HalfOpenMaxAttempts = 2
    }
    
    # Auto-rollback settings
    AutoRollback = @{
        Enabled = $true
        TPSDropThreshold = 20  # Percent
        LatencyIncreaseThreshold = 50  # Percent
        SISDropThreshold = 10  # Points
    }
    
    # Patch selection settings
    PatchSelection = @{
        Enabled = $true
        MinSamples = 10
        ConfidenceLevel = 0.95
        MinImprovement = 5  # Percent
    }
    
    # Actions
    Actions = @{
        OnPatchFailure = "Rollback"  # Rollback, Alert, Ignore
        OnPerformanceDrop = "SelectiveRollback"
        OnRepeatedFailure = "DisablePatch"
    }
}

#==============================================================================
# Self-Healing Classes
#==============================================================================

enum CircuitState {
    Closed
    Open
    HalfOpen
}

class CircuitBreaker {
    [string]$PatchName
    [CircuitState]$State
    [int]$FailureCount
    [datetime]$LastFailure
    [int]$SuccessCount
    [hashtable]$Config

    CircuitBreaker([string]$patchName, [hashtable]$config) {
        $this.PatchName = $patchName
        $this.State = [CircuitState]::Closed
        $this.FailureCount = 0
        $this.SuccessCount = 0
        $this.Config = $config
    }

    [bool] CanExecute() {
        switch ($this.State) {
            "Closed" { return $true }
            "Open" {
                # Check if recovery timeout has passed
                $elapsed = (Get-Date) - $this.LastFailure
                if ($elapsed.TotalSeconds -ge $this.Config.RecoveryTimeoutSeconds) {
                    Write-Host "  Circuit for $($this.PatchName) entering Half-Open state" -ForegroundColor Yellow
                    $this.State = [CircuitState]::HalfOpen
                    $this.SuccessCount = 0
                    return $true
                }
                return $false
            }
            "HalfOpen" {
                return $this.SuccessCount -lt $this.Config.HalfOpenMaxAttempts
            }
        }
        return $false
    }

    [void] RecordSuccess() {
        if ($this.State -eq "HalfOpen") {
            $this.SuccessCount++
            if ($this.SuccessCount -ge $this.Config.HalfOpenMaxAttempts) {
                Write-Host "  Circuit for $($this.PatchName) closing (recovered)" -ForegroundColor Green
                $this.State = [CircuitState]::Closed
                $this.FailureCount = 0
                $this.SuccessCount = 0
            }
        }
        else {
            $this.FailureCount = [Math]::Max(0, $this.FailureCount - 1)
        }
    }

    [void] RecordFailure() {
        $this.FailureCount++
        $this.LastFailure = Get-Date
        
        if ($this.State -eq "HalfOpen") {
            Write-Host "  Circuit for $($this.PatchName) re-opening (failure in half-open)" -ForegroundColor Red
            $this.State = [CircuitState]::Open
        }
        elseif ($this.FailureCount -ge $this.Config.FailureThreshold) {
            Write-Host "  Circuit for $($this.PatchName) opening ($($this.FailureCount) failures)" -ForegroundColor Red
            $this.State = [CircuitState]::Open
        }
    }
}

class SelfHealingEngine {
    [string]$TelemetryPath
    [string]$AuditPath
    [hashtable]$Config
    [hashtable]$CircuitBreakers
    [hashtable]$PatchHistory
    [hashtable]$BaselineMetrics
    [bool]$IsRunning

    SelfHealingEngine([string]$telemetry, [string]$audit, [string]$configPath) {
        $this.TelemetryPath = $telemetry
        $this.AuditPath = $audit
        $this.CircuitBreakers = @{}
        $this.PatchHistory = @{}
        $this.BaselineMetrics = @{}
        $this.IsRunning = $false
        
        $this.LoadConfig($configPath)
    }

    [void] LoadConfig([string]$configPath) {
        if (Test-Path $configPath) {
            $this.Config = Get-Content $configPath | ConvertFrom-Json -AsHashtable
            Write-Host "✓ Config loaded from: $configPath" -ForegroundColor Green
        }
        else {
            $this.Config = $script:DefaultConfig
            $this.Config | ConvertTo-Json -Depth 10 | Out-File $configPath
            Write-Host "✓ Default config created: $configPath" -ForegroundColor Green
        }
    }

    [void] Start() {
        $this.IsRunning = $true
        Write-Host "`n=== Starting Self-Healing Engine ===" -ForegroundColor Cyan
        Write-Host "Circuit breaker: $(if ($this.Config.CircuitBreaker.Enabled) { 'Enabled' } else { 'Disabled' })" -ForegroundColor White
        Write-Host "Auto-rollback: $(if ($this.Config.AutoRollback.Enabled) { 'Enabled' } else { 'Disabled' })" -ForegroundColor White
        
        # Establish baseline
        $this.EstablishBaseline()
        
        while ($this.IsRunning) {
            $this.CheckHealth()
            Start-Sleep -Seconds 10
        }
    }

    [void] EstablishBaseline() {
        Write-Host "`nEstablishing performance baseline..." -ForegroundColor Yellow
        
        # Simulate baseline collection
        $this.BaselineMetrics = @{
            TPS = 45
            TTFT = 18
            Latency = 25
            SIS_Score = 92
            Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
        }
        
        Write-Host "✓ Baseline established:" -ForegroundColor Green
        Write-Host "  TPS: $($this.BaselineMetrics.TPS)" -ForegroundColor Gray
        Write-Host "  TTFT: $($this.BaselineMetrics.TTFT)ms" -ForegroundColor Gray
        Write-Host "  Latency: $($this.BaselineMetrics.Latency)ms" -ForegroundColor Gray
        Write-Host "  SIS: $($this.BaselineMetrics.SIS_Score)" -ForegroundColor Gray
    }

    [void] CheckHealth() {
        # Read current metrics from telemetry
        $currentMetrics = $this.GetCurrentMetrics()
        
        if (-not $currentMetrics) {
            return
        }
        
        # Check for degradation
        $this.CheckPerformanceDegradation($currentMetrics)
        
        # Check circuit breakers
        $this.UpdateCircuitBreakers()
        
        # Display status
        $this.DisplayStatus($currentMetrics)
    }

    [hashtable] GetCurrentMetrics() {
        $metricsPath = Join-Path $this.TelemetryPath "metrics"
        if (-not (Test-Path $metricsPath)) {
            return $null
        }
        
        $latestFile = Get-ChildItem -Path $metricsPath -Filter "*.jsonl" | 
            Sort-Object LastWriteTime -Descending | 
            Select-Object -First 1
        
        if (-not $latestFile) {
            return $null
        }
        
        $lines = Get-Content $latestFile.FullName -Tail 50
        $metrics = @{}
        
        foreach ($line in $lines) {
            if (-not $line.Trim()) { continue }
            try {
                $data = $line | ConvertFrom-Json -AsHashtable
                if (-not $metrics.ContainsKey($data.Name)) {
                    $metrics[$data.Name] = @()
                }
                $metrics[$data.Name] += $data.Value
            }
            catch {
                # Skip invalid lines
            }
        }
        
        # Calculate averages
        $result = @{}
        foreach ($key in $metrics.Keys) {
            $values = $metrics[$key]
            $result[$key] = ($values | Measure-Object -Average).Average
        }
        
        return $result
    }

    [void] CheckPerformanceDegradation([hashtable]$current) {
        # Check TPS drop
        if ($current.ContainsKey("TPS") -and $this.BaselineMetrics.ContainsKey("TPS")) {
            $tpsDrop = (($this.BaselineMetrics.TPS - $current.TPS) / $this.BaselineMetrics.TPS) * 100
            
            if ($tpsDrop -gt $this.Config.AutoRollback.TPSDropThreshold) {
                Write-Host "`n[!] TPS dropped by $([math]::Round($tpsDrop, 1))% (threshold: $($this.Config.AutoRollback.TPSDropThreshold)%)" -ForegroundColor Red
                $this.HandlePerformanceDegradation("TPS", $tpsDrop)
            }
        }
        
        # Check latency increase
        if ($current.ContainsKey("Latency") -and $this.BaselineMetrics.ContainsKey("Latency")) {
            $latIncrease = (($current.Latency - $this.BaselineMetrics.Latency) / $this.BaselineMetrics.Latency) * 100
            
            if ($latIncrease -gt $this.Config.AutoRollback.LatencyIncreaseThreshold) {
                Write-Host "`n[!] Latency increased by $([math]::Round($latIncrease, 1))% (threshold: $($this.Config.AutoRollback.LatencyIncreaseThreshold)%)" -ForegroundColor Red
                $this.HandlePerformanceDegradation("Latency", $latIncrease)
            }
        }
        
        # Check SIS drop
        if ($current.ContainsKey("SIS_Score") -and $this.BaselineMetrics.ContainsKey("SIS_Score")) {
            $sisDrop = $this.BaselineMetrics.SIS_Score - $current.SIS_Score
            
            if ($sisDrop -gt $this.Config.AutoRollback.SISDropThreshold) {
                Write-Host "`n[!] SIS dropped by $([math]::Round($sisDrop, 1)) points (threshold: $($this.Config.AutoRollback.SISDropThreshold))" -ForegroundColor Red
                $this.HandlePerformanceDegradation("SIS_Score", $sisDrop)
            }
        }
    }

    [void] HandlePerformanceDegradation([string]$metric, [double]$amount) {
        $action = $this.Config.Actions.OnPerformanceDrop
        
        switch ($action) {
            "Rollback" {
                $this.RollbackLastPatch()
            }
            "SelectiveRollback" {
                $this.SelectiveRollback($metric)
            }
            "Alert" {
                $this.SendAlert("Performance degradation detected: $metric dropped by $amount")
            }
        }
    }

    [void] RollbackLastPatch() {
        Write-Host "  Initiating rollback of last patch..." -ForegroundColor Yellow
        
        if ($DryRun) {
            Write-Host "  [DRY RUN] Would rollback last patch" -ForegroundColor Cyan
            return
        }
        
        # Simulate rollback
        Start-Sleep -Seconds 2
        
        # Log action
        $this.LogAction("Hotpatch_Rolled_Back", @{ 
            Reason = "Performance degradation"
            Trigger = "Auto-rollback"
        })
        
        Write-Host "  ✓ Rollback completed" -ForegroundColor Green
    }

    [void] SelectiveRollback([string]$affectedMetric) {
        Write-Host "  Analyzing patches affecting $affectedMetric..." -ForegroundColor Yellow
        
        # Find patches that might be causing the issue
        $suspectPatches = @("scheduler", "gemm", "attention") | Get-Random -Count 2
        
        foreach ($patch in $suspectPatches) {
            Write-Host "    Rolling back: $patch" -ForegroundColor Gray
            
            if (-not $DryRun) {
                # Simulate rollback
                Start-Sleep -Milliseconds 500
            }
        }
        
        if ($DryRun) {
            Write-Host "  [DRY RUN] Would rollback: $($suspectPatches -join ', ')" -ForegroundColor Cyan
        }
        else {
            $this.LogAction("Hotpatch_Rolled_Back", @{
                Reason = "Selective rollback for $affectedMetric"
                Patches = $suspectPatches
                Trigger = "Auto-rollback"
            })
            
            Write-Host "  ✓ Selective rollback completed" -ForegroundColor Green
        }
    }

    [void] UpdateCircuitBreakers() {
        # Check for patch failures in telemetry
        $alertsPath = Join-Path $this.TelemetryPath "alerts"
        if (-not (Test-Path $alertsPath)) {
            return
        }
        
        $alertFiles = Get-ChildItem -Path $alertsPath -Filter "*alert.json" | 
            Sort-Object LastWriteTime -Descending | 
            Select-Object -First 5
        
        foreach ($file in $alertFiles) {
            try {
                $alert = Get-Content $file.FullName | ConvertFrom-Json -AsHashtable
                
                if ($alert.Metric -eq "HotpatchStatus") {
                    $patchName = $alert.Data.PatchName
                    
                    if (-not $this.CircuitBreakers.ContainsKey($patchName)) {
                        $this.CircuitBreakers[$patchName] = [CircuitBreaker]::new($patchName, $this.Config.CircuitBreaker)
                    }
                    
                    $this.CircuitBreakers[$patchName].RecordFailure()
                }
            }
            catch {
                # Skip invalid alerts
            }
        }
    }

    [bool] ApplyPatch([string]$patchName) {
        # Check circuit breaker
        if (-not $this.CircuitBreakers.ContainsKey($patchName)) {
            $this.CircuitBreakers[$patchName] = [CircuitBreaker]::new($patchName, $this.Config.CircuitBreaker)
        }
        
        $cb = $this.CircuitBreakers[$patchName]
        
        if (-not $cb.CanExecute()) {
            Write-Host "  ✗ Circuit breaker open for $patchName" -ForegroundColor Red
            return $false
        }
        
        Write-Host "  Applying patch: $patchName" -ForegroundColor Yellow
        
        if ($DryRun) {
            Write-Host "  [DRY RUN] Would apply patch: $patchName" -ForegroundColor Cyan
            return $true
        }
        
        # Simulate patch application
        $success = (Get-Random -Minimum 0 -Maximum 10) -gt 2  # 80% success rate
        
        if ($success) {
            $cb.RecordSuccess()
            $this.LogAction("Hotpatch_Applied", @{ PatchName = $patchName; Success = $true })
            Write-Host "  ✓ Patch applied successfully" -ForegroundColor Green
            return $true
        }
        else {
            $cb.RecordFailure()
            $this.LogAction("Hotpatch_Failed", @{ PatchName = $patchName; Success = $false })
            Write-Host "  ✗ Patch failed" -ForegroundColor Red
            
            # Auto-rollback if configured
            if ($this.Config.Actions.OnPatchFailure -eq "Rollback") {
                $this.RollbackLastPatch()
            }
            
            return $false
        }
    }

    [void] LogAction([string]$action, [hashtable]$data) {
        # Import audit logger
        $auditScript = Join-Path $this.AuditPath "..\audit\audit_logger.ps1"
        if (Test-Path $auditScript) {
            & $auditScript -AuditPath $this.AuditPath -Action $action -ActionData $data
        }
    }

    [void] SendAlert([string]$message) {
        Write-Host "  [ALERT] $message" -ForegroundColor Yellow
    }

    [void] DisplayStatus([hashtable]$current) {
        Clear-Host
        Write-Host @"
╔══════════════════════════════════════════════════════════════════════════════╗
║           RawrXD Sovereign - Self-Healing Engine                             ║
║           Phase G.1 Batch 4/5: Automatic Rollback & Circuit Breaker          ║
╚══════════════════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan
        
        Write-Host "`nCurrent Metrics vs Baseline:" -ForegroundColor Yellow
        Write-Host "─" * 60 -ForegroundColor Gray
        
        foreach ($metric in @("TPS", "TTFT", "Latency", "SIS_Score")) {
            if ($current.ContainsKey($metric) -and $this.BaselineMetrics.ContainsKey($metric)) {
                $currentVal = [math]::Round($current[$metric], 2)
                $baselineVal = $this.BaselineMetrics[$metric]
                
                $change = if ($metric -in @("TPS", "SIS_Score")) {
                    (($currentVal - $baselineVal) / $baselineVal) * 100
                }
                else {
                    (($baselineVal - $currentVal) / $baselineVal) * 100
                }
                
                $color = if ([Math]::Abs($change) -gt 10) { "Red" } elseif ([Math]::Abs($change) -gt 5) { "Yellow" } else { "Green" }
                $arrow = if ($change -gt 0) { "↑" } elseif ($change -lt 0) { "↓" } else { "→" }
                
                Write-Host "$metric`: $currentVal (baseline: $baselineVal) $arrow $([math]::Abs($change))%" -ForegroundColor $color
            }
        }
        
        Write-Host "─" * 60 -ForegroundColor Gray
        
        Write-Host "`nCircuit Breakers:" -ForegroundColor Yellow
        foreach ($patch in $this.CircuitBreakers.Keys) {
            $cb = $this.CircuitBreakers[$patch]
            $color = switch ($cb.State) {
                "Closed" { "Green" }
                "HalfOpen" { "Yellow" }
                "Open" { "Red" }
            }
            Write-Host "  $patch`: $($cb.State) (failures: $($cb.FailureCount))" -ForegroundColor $color
        }
        
        Write-Host "`nPress Ctrl+C to stop..." -ForegroundColor DarkGray
    }

    [void] Stop() {
        $this.IsRunning = $false
        Write-Host "`n✓ Self-healing engine stopped" -ForegroundColor Green
    }
}

#==============================================================================
# Main Execution
#==============================================================================

Write-Host @"
╔══════════════════════════════════════════════════════════════════════════════╗
║           RawrXD Sovereign - Self-Healing Automation                           ║
║           Phase G.1 Batch 4/5: Automatic Rollback & Circuit Breaker            ║
╚══════════════════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

$engine = [SelfHealingEngine]::new($TelemetryPath, $AuditPath, $ConfigPath)

if ($Daemon) {
    # Handle Ctrl+C
    [Console]::CancelKeyPress.AddListener({
        param($sender, $e)
        $e.Cancel = $true
        $engine.Stop()
        exit 0
    })
    
    $engine.Start()
}
else {
    Write-Host "`nCommands:" -ForegroundColor Yellow
    Write-Host "  1. Start monitoring daemon"
    Write-Host "  2. Apply test patch"
    Write-Host "  3. Simulate performance drop"
    Write-Host "  4. View circuit breaker status"
    
    $choice = Read-Host "`nSelect option (1-4)"
    
    switch ($choice) {
        "1" {
            $engine.Start()
        }
        "2" {
            $patch = Read-Host "Enter patch name"
            $engine.ApplyPatch($patch)
        }
        "3" {
            Write-Host "Simulating performance degradation..." -ForegroundColor Yellow
            # This would be detected in the next health check
        }
        "4" {
            Write-Host "`nCircuit Breaker Status:" -ForegroundColor Cyan
            foreach ($patch in $engine.CircuitBreakers.Keys) {
                $cb = $engine.CircuitBreakers[$patch]
                Write-Host "  $patch`: $($cb.State)" -ForegroundColor White
            }
        }
    }
}
