# auto_optimizer.ps1
# Phase K Batch 2/5: Automated Performance Optimization

param(
    [string]$Endpoint = "http://localhost:8080",
    [switch]$DryRun,
    [switch]$Continuous
)

$ErrorActionPreference = "Continue"

$OptimizationRules = @(
    @{
        Name = "High Latency Reduction"
        Condition = { param($m) $m.latency_p95_ms -gt 150 }
        Action = { 
            param($e)
            # Reduce batch size to improve latency
            $config = @{ batch_size = 256 }
            Invoke-RestMethod -Uri "$e/api/v1/admin/config" -Method POST -Body ($config | ConvertTo-Json) -ContentType "application/json"
            return "Reduced batch_size to 256"
        }
        Priority = 1
    },
    @{
        Name = "Low TPS Improvement"
        Condition = { param($m) $m.tps -lt 35 }
        Action = {
            param($e)
            # Increase batch size for throughput
            $config = @{ batch_size = 1024 }
            Invoke-RestMethod -Uri "$e/api/v1/admin/config" -Method POST -Body ($config | ConvertTo-Json) -ContentType "application/json"
            return "Increased batch_size to 1024"
        }
        Priority = 2
    },
    @{
        Name = "Memory Pressure Relief"
        Condition = { param($m) $m.memory_used_percent -gt 85 }
        Action = {
            param($e)
            # Clear cache
            Invoke-RestMethod -Uri "$e/api/v1/admin/cache/clear" -Method POST
            return "Cleared model cache"
        }
        Priority = 1
    },
    @{
        Name = "GPU Optimization"
        Condition = { param($m) $m.gpu_utilization_percent -lt 60 -and $m.tps -lt 40 }
        Action = {
            param($e)
            # Increase GPU layers
            $config = @{ gpu_layers = 41 }
            Invoke-RestMethod -Uri "$e/api/v1/admin/config" -Method POST -Body ($config | ConvertTo-Json) -ContentType "application/json"
            return "Increased GPU layers to 41"
        }
        Priority = 3
    }
)

function Write-OptLog($Message, $Level = "INFO") {
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch ($Level) {
        "ERROR" { "Red" }
        "WARNING" { "Yellow" }
        "SUCCESS" { "Green" }
        "OPTIMIZE" { "Cyan" }
        default { "White" }
    }
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $color
}

function Get-CurrentMetrics {
    try {
        $metrics = Invoke-RestMethod -Uri "$Endpoint/api/v1/metrics" -TimeoutSec 5
        
        # Add system metrics
        $memory = Get-CimInstance -ClassName Win32_OperatingSystem
        $metrics.memory_used_percent = (($memory.TotalVisibleMemorySize - $memory.FreePhysicalMemory) / $memory.TotalVisibleMemorySize) * 100
        
        return $metrics
    }
    catch {
        Write-OptLog "Failed to get metrics: $_" "ERROR"
        return $null
    }
}

function Test-OptimizationNeeded($Metrics) {
    $optimizations = @()
    
    foreach ($rule in $OptimizationRules | Sort-Object Priority) {
        try {
            $needsOptimization = & $rule.Condition $Metrics
            if ($needsOptimization) {
                $optimizations += $rule
            }
        }
        catch {
            Write-OptLog "Error evaluating rule $($rule.Name): $_" "WARNING"
        }
    }
    
    return $optimizations
}

function Invoke-Optimization($Rule) {
    Write-OptLog "Applying optimization: $($Rule.Name)" "OPTIMIZE"
    
    if ($DryRun) {
        Write-OptLog "DRY RUN: Would apply $($Rule.Name)" "WARNING"
        return @{ Success = $true; Action = "DRY RUN"; Changes = @() }
    }
    
    try {
        $result = & $Rule.Action $Endpoint
        Write-OptLog "✅ Optimization applied: $result" "SUCCESS"
        return @{ Success = $true; Action = $result; Changes = @($result) }
    }
    catch {
        Write-OptLog "❌ Optimization failed: $_" "ERROR"
        return @{ Success = $false; Error = $_.Exception.Message; Changes = @() }
    }
}

function Start-OptimizationCycle {
    Write-OptLog "Starting Auto-Optimizer for RawrXD"
    Write-OptLog "Endpoint: $Endpoint"
    Write-OptLog "Mode: $(if ($Continuous) { "Continuous" } else { "Single-run" })"
    Write-OptLog "Dry Run: $DryRun"
    Write-OptLog ""
    
    do {
        Write-OptLog "Checking metrics..."
        $metrics = Get-CurrentMetrics
        
        if ($metrics) {
            Write-OptLog "Current TPS: $([math]::Round($metrics.tps, 2)), Latency P95: $([math]::Round($metrics.latency_p95_ms, 2))ms"
            
            $optimizations = Test-OptimizationNeeded -Metrics $metrics
            
            if ($optimizations.Count -gt 0) {
                Write-OptLog "Found $($optimizations.Count) optimization opportunities" "WARNING"
                
                foreach ($opt in $optimizations) {
                    $result = Invoke-Optimization -Rule $opt
                    
                    if ($result.Success) {
                        # Wait and verify
                        Start-Sleep -Seconds 10
                        $newMetrics = Get-CurrentMetrics
                        if ($newMetrics) {
                            Write-OptLog "New TPS: $([math]::Round($newMetrics.tps, 2)), Latency P95: $([math]::Round($newMetrics.latency_p95_ms, 2))ms"
                        }
                    }
                }
            } else {
                Write-OptLog "No optimizations needed - system performing well" "SUCCESS"
            }
        }
        
        if ($Continuous) {
            Write-OptLog "Sleeping for 60 seconds..."
            Start-Sleep -Seconds 60
        }
    } while ($Continuous)
}

# Main execution
Start-OptimizationCycle
