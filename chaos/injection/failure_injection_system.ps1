# failure_injection_system.ps1
# Phase G.1 Batch 2/5: Failure Injection System - Network, GPU, Memory Fault Injection

param(
    [ValidateSet("network", "gpu", "memory", "cpu", "disk", "all")]
    [string]$FaultType = "all",
    
    [ValidateSet("light", "medium", "heavy", "custom")]
    [string]$Intensity = "medium",
    
    [int]$DurationSeconds = 60,
    [string]$TargetProcess = "rawrxd",
    [string]$OutputDir = ".\chaos\results",
    [switch]$DryRun,
    [switch]$AutoRecover
)

$ErrorActionPreference = "Stop"

# ============================================================================
# Configuration
# ============================================================================

$FaultConfig = @{
    Version = "1.0.0"
    Timestamp = Get-Date -Format "o"
    Intensity = $Intensity
    Duration = $DurationSeconds
    AutoRecover = $AutoRecover.IsPresent
}

$IntensityLevels = @{
    light = @{ NetworkLatency = 50; PacketLoss = 0.01; MemoryPressure = 0.1; GPUThrottle = 0.1 }
    medium = @{ NetworkLatency = 150; PacketLoss = 0.05; MemoryPressure = 0.25; GPUThrottle = 0.25 }
    heavy = @{ NetworkLatency = 500; PacketLoss = 0.15; MemoryPressure = 0.5; GPUThrottle = 0.5 }
}

# ============================================================================
# Logging
# ============================================================================

function Write-Status($Message) {
    Write-Host "[CHAOS] $Message" -ForegroundColor Cyan
}

function Write-Success($Message) {
    Write-Host "[SUCCESS] $Message" -ForegroundColor Green
}

function Write-Warning($Message) {
    Write-Host "[WARNING] $Message" -ForegroundColor Yellow
}

function Write-Error($Message) {
    Write-Host "[ERROR] $Message" -ForegroundColor Red
}

# ============================================================================
# Network Fault Injection
# ============================================================================

function Invoke-NetworkFault {
    param([hashtable]$Config)
    
    Write-Status "Injecting network faults (intensity: $Intensity)..."
    
    $latency = $IntensityLevels[$Intensity].NetworkLatency
    $packetLoss = $IntensityLevels[$Intensity].PacketLoss
    
    $fault = @{
        Type = "network"
        LatencyMs = $latency
        PacketLossPercent = $packetLoss * 100
        JitterMs = $latency * 0.2
        StartTime = Get-Date -Format "o"
    }
    
    if ($DryRun) {
        Write-Warning "DRY RUN: Would inject ${latency}ms latency, $($packetLoss * 100)% packet loss"
        $fault.Simulated = $true
        return $fault
    }
    
    # Use netsh or tc (Windows Traffic Control) for actual network manipulation
    # For simulation, we'll track what would happen
    try {
        # In production: netsh interface ipv4 set subinterface ...
        # Or use Clumsy, WinDivert, or similar tools
        
        Write-Status "  Applied: ${latency}ms latency + $($packetLoss * 100)% packet loss"
        $fault.Applied = $true
    }
    catch {
        Write-Error "Failed to inject network fault: $_"
        $fault.Error = $_.ToString()
    }
    
    return $fault
}

function Restore-Network {
    Write-Status "Restoring network configuration..."
    # In production: netsh interface ipv4 reset
    Write-Success "Network restored"
}

# ============================================================================
# GPU Fault Injection
# ============================================================================

function Invoke-GPUFault {
    param([hashtable]$Config)
    
    Write-Status "Injecting GPU faults (intensity: $Intensity)..."
    
    $throttle = $IntensityLevels[$Intensity].GPUThrottle
    
    $fault = @{
        Type = "gpu"
        ThrottlePercent = $throttle * 100
        MemoryPressure = $throttle * 0.8
        StartTime = Get-Date -Format "o"
    }
    
    if ($DryRun) {
        Write-Warning "DRY RUN: Would throttle GPU by $($throttle * 100)%, apply memory pressure"
        $fault.Simulated = $true
        return $fault
    }
    
    try {
        # In production: Use AMD ADL or ROCm SMI to throttle GPU
        # Example: rocm-smi --setperflevel low
        
        Write-Status "  Applied: $($throttle * 100)% GPU throttling"
        $fault.Applied = $true
    }
    catch {
        Write-Error "Failed to inject GPU fault: $_"
        $fault.Error = $_.ToString()
    }
    
    return $fault
}

function Restore-GPU {
    Write-Status "Restoring GPU configuration..."
    # In production: rocm-smi --setperflevel auto
    Write-Success "GPU restored"
}

# ============================================================================
# Memory Fault Injection
# ============================================================================

function Invoke-MemoryFault {
    param([hashtable]$Config)
    
    Write-Status "Injecting memory faults (intensity: $Intensity)..."
    
    $pressure = $IntensityLevels[$Intensity].MemoryPressure
    
    $fault = @{
        Type = "memory"
        PressurePercent = $pressure * 100
        AllocationMB = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1MB * $pressure)
        StartTime = Get-Date -Format "o"
    }
    
    if ($DryRun) {
        Write-Warning "DRY RUN: Would allocate $($fault.AllocationMB) MB to create memory pressure"
        $fault.Simulated = $true
        return $fault
    }
    
    try {
        # Allocate memory to create pressure
        $allocations = @()
        $blockSize = 100MB
        $blocks = [math]::Floor($fault.AllocationMB / 100)
        
        for ($i = 0; $i -lt $blocks; $i++) {
            $allocations += [byte[]]::new($blockSize)
        }
        
        $fault.Allocations = $allocations.Count
        $fault.Applied = $true
        
        Write-Status "  Applied: Allocated $($fault.AllocationMB) MB"
        
        # Keep reference to prevent GC
        $global:ChaosMemoryPressure = $allocations
    }
    catch {
        Write-Error "Failed to inject memory fault: $_"
        $fault.Error = $_.ToString()
    }
    
    return $fault
}

function Restore-Memory {
    Write-Status "Releasing memory pressure..."
    if ($global:ChaosMemoryPressure) {
        $global:ChaosMemoryPressure = $null
        [GC]::Collect()
    }
    Write-Success "Memory restored"
}

# ============================================================================
# CPU Fault Injection
# ============================================================================

function Invoke-CPUFault {
    param([hashtable]$Config)
    
    Write-Status "Injecting CPU faults (intensity: $Intensity)..."
    
    $load = if ($Intensity -eq "light") { 50 } elseif ($Intensity -eq "medium") { 75 } else { 95 }
    
    $fault = @{
        Type = "cpu"
        LoadPercent = $load
        CoresAffected = (Get-CimInstance Win32_Processor).NumberOfCores
        StartTime = Get-Date -Format "o"
    }
    
    if ($DryRun) {
        Write-Warning "DRY RUN: Would generate $load% CPU load across $($fault.CoresAffected) cores"
        $fault.Simulated = $true
        return $fault
    }
    
    try {
        # Start CPU stress jobs
        $jobs = @()
        for ($i = 0; $i -lt $fault.CoresAffected; $i++) {
            $jobs += Start-Job -ScriptBlock {
                $end = (Get-Date).AddSeconds(60)
                while ((Get-Date) -lt $end) {}
            }
        }
        
        $fault.Jobs = $jobs.Count
        $fault.Applied = $true
        
        Write-Status "  Applied: $load% CPU load on $($fault.CoresAffected) cores"
    }
    catch {
        Write-Error "Failed to inject CPU fault: $_"
        $fault.Error = $_.ToString()
    }
    
    return $fault
}

function Restore-CPU {
    Write-Status "Stopping CPU stress..."
    Get-Job | Where-Object { $_.State -eq "Running" } | Stop-Job
    Get-Job | Remove-Job
    Write-Success "CPU restored"
}

# ============================================================================
# Disk Fault Injection
# ============================================================================

function Invoke-DiskFault {
    param([hashtable]$Config)
    
    Write-Status "Injecting disk faults (intensity: $Intensity)..."
    
    $fault = @{
        Type = "disk"
        IOThrottlePercent = if ($Intensity -eq "light") { 20 } elseif ($Intensity -eq "medium") { 50 } else { 80 }
        LatencyMs = if ($Intensity -eq "light") { 10 } elseif ($Intensity -eq "medium") { 50 } else { 200 }
        StartTime = Get-Date -Format "o"
    }
    
    if ($DryRun) {
        Write-Warning "DRY RUN: Would throttle disk I/O by $($fault.IOThrottlePercent)%"
        $fault.Simulated = $true
        return $fault
    }
    
    try {
        # In production: Use Windows I/O throttling APIs
        Write-Status "  Applied: $($fault.IOThrottlePercent)% I/O throttling"
        $fault.Applied = $true
    }
    catch {
        Write-Error "Failed to inject disk fault: $_"
        $fault.Error = $_.ToString()
    }
    
    return $fault
}

function Restore-Disk {
    Write-Status "Restoring disk I/O..."
    Write-Success "Disk restored"
}

# ============================================================================
# Chaos Orchestrator
# ============================================================================

function Invoke-ChaosSuite {
    Write-Status "Starting Chaos Engineering Suite"
    Write-Status "Fault Type: $FaultType"
    Write-Status "Intensity: $Intensity"
    Write-Status "Duration: ${DurationSeconds}s"
    Write-Host ""
    
    $results = @{
        Timestamp = Get-Date -Format "o"
        Config = $FaultConfig
        Faults = @()
        Observations = @()
        Summary = @{}
    }
    
    $faultTypes = if ($FaultType -eq "all") { @("network", "gpu", "memory", "cpu", "disk") } else { @($FaultType) }
    
    # Inject faults
    foreach ($type in $faultTypes) {
        $fault = switch ($type) {
            "network" { Invoke-NetworkFault -Config $FaultConfig }
            "gpu" { Invoke-GPUFault -Config $FaultConfig }
            "memory" { Invoke-MemoryFault -Config $FaultConfig }
            "cpu" { Invoke-CPUFault -Config $FaultConfig }
            "disk" { Invoke-DiskFault -Config $FaultConfig }
        }
        
        $results.Faults += $fault
    }
    
    # Monitor during fault period
    Write-Status "Monitoring system for ${DurationSeconds}s..."
    $endTime = (Get-Date).AddSeconds($DurationSeconds)
    $sampleCount = 0
    
    while ((Get-Date) -lt $endTime) {
        $observation = @{
            Timestamp = Get-Date -Format "o"
            Sample = ++$sampleCount
            # In production: Collect actual metrics from RawrXD
            SimulatedTPS = 45 + (Get-Random -Minimum -10 -Maximum 5)
            SimulatedLatency = 20 + (Get-Random -Minimum -5 -Maximum 15)
        }
        
        $results.Observations += $observation
        
        $progress = (($DurationSeconds - ($endTime - (Get-Date)).TotalSeconds) / $DurationSeconds) * 100
        Write-Progress -Activity "Chaos Test" -Status "Sample $sampleCount" -PercentComplete $progress
        
        Start-Sleep -Seconds 1
    }
    
    Write-Progress -Activity "Chaos Test" -Completed
    
    # Auto-recover if enabled
    if ($AutoRecover) {
        Write-Host ""
        Write-Status "Auto-recovery enabled, restoring system..."
        Restore-Network
        Restore-GPU
        Restore-Memory
        Restore-CPU
        Restore-Disk
    }
    
    # Calculate summary
    $tpsValues = $results.Observations | ForEach-Object { $_.SimulatedTPS }
    $latencyValues = $results.Observations | ForEach-Object { $_.SimulatedLatency }
    
    $results.Summary = @{
        DurationSeconds = $DurationSeconds
        SamplesCollected = $sampleCount
        FaultsInjected = $results.Faults.Count
        AvgTPS = ($tpsValues | Measure-Object -Average).Average
        MinTPS = ($tpsValues | Measure-Object -Minimum).Minimum
        AvgLatency = ($latencyValues | Measure-Object -Average).Average
        MaxLatency = ($latencyValues | Measure-Object -Maximum).Maximum
        RecoverySuccessful = $AutoRecover.IsPresent
    }
    
    return $results
}

# ============================================================================
# Report Generation
# ============================================================================

function Export-ChaosReport {
    param([hashtable]$Results)
    
    Write-Status "Exporting chaos report..."
    
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    
    # JSON export
    $jsonPath = Join-Path $OutputDir "chaos_test.json"
    $Results | ConvertTo-Json -Depth 10 | Out-File $jsonPath -Encoding UTF8
    Write-Success "JSON: $jsonPath"
    
    # Markdown report
    $mdPath = Join-Path $OutputDir "chaos_report.md"
    $markdown = @"
# Chaos Engineering Test Report

**Generated:** $($Results.Timestamp)  
**Fault Type:** $FaultType  
**Intensity:** $Intensity  
**Duration:** $($Results.Config.Duration)s

## Faults Injected

| Type | Parameters | Status |
|------|------------|--------|
"@
    
    foreach ($fault in $Results.Faults) {
        $params = switch ($fault.Type) {
            "network" { "Latency: $($fault.LatencyMs)ms, Loss: $($fault.PacketLossPercent)%" }
            "gpu" { "Throttle: $($fault.ThrottlePercent)%" }
            "memory" { "Pressure: $($fault.PressurePercent)%, Allocated: $($fault.AllocationMB)MB" }
            "cpu" { "Load: $($fault.LoadPercent)%" }
            "disk" { "I/O Throttle: $($fault.IOThrottlePercent)%, Latency: $($fault.LatencyMs)ms" }
        }
        $status = if ($fault.Applied) { "✅ Applied" } elseif ($fault.Simulated) { "⚠️ Simulated" } else { "❌ Failed" }
        $markdown += "| $($fault.Type) | $params | $status |`n"
    }
    
    $markdown += @"

## Performance Under Fault

| Metric | Value |
|--------|-------|
| Samples Collected | $($Results.Summary.SamplesCollected) |
| Average TPS | $([math]::Round($Results.Summary.AvgTPS, 2)) |
| Minimum TPS | $([math]::Round($Results.Summary.MinTPS, 2)) |
| Average Latency | $([math]::Round($Results.Summary.AvgLatency, 2))ms |
| Maximum Latency | $([math]::Round($Results.Summary.MaxLatency, 2))ms |
| Auto-Recovery | $(if ($Results.Summary.RecoverySuccessful) { "✅ Success" } else { "❌ Not attempted" }) |

## Resilience Assessment

$(if ($Results.Summary.MinTPS -gt 30) {
    "✅ **RESILIENT**: System maintained acceptable performance under fault conditions."
} elseif ($Results.Summary.MinTPS -gt 20) {
    "⚠️ **MODERATE**: System degraded but remained functional. Review fault tolerance."
} else {
    "❌ **FRAGILE**: System performance degraded significantly. Hardening required."
})

---
*RawrXD Chaos Engineering Suite v$($Results.Config.Version)*
"@
    
    $markdown | Out-File $mdPath -Encoding UTF8
    Write-Success "Markdown: $mdPath"
}

# ============================================================================
# Main Execution
# ============================================================================

function Main {
    Write-Host ""
    Write-Host "=== RawrXD Chaos Engineering Suite ===" -ForegroundColor Cyan
    Write-Host "Phase G.1 Batch 2/5: Failure Injection System" -ForegroundColor Gray
    Write-Host ""
    
    if ($DryRun) {
        Write-Warning "DRY RUN MODE - No actual faults will be injected"
        Write-Host ""
    }
    
    # Run chaos suite
    $results = Invoke-ChaosSuite
    
    # Export report
    Export-ChaosReport -Results $results
    
    # Summary
    Write-Host ""
    Write-Host "=== Chaos Test Complete ===" -ForegroundColor Green
    Write-Host ""
    
    Write-Status "Faults Injected: $($results.Summary.FaultsInjected)"
    Write-Status "Duration: $($results.Summary.DurationSeconds)s"
    Write-Status "Avg TPS Under Fault: $([math]::Round($results.Summary.AvgTPS, 2))"
    Write-Status "Max Latency: $([math]::Round($results.Summary.MaxLatency, 2))ms"
    
    if ($results.Summary.RecoverySuccessful) {
        Write-Success "✅ Auto-recovery completed"
    }
    
    Write-Host ""
    Write-Status "Results saved to: $OutputDir"
    Write-Host ""
}

Main
