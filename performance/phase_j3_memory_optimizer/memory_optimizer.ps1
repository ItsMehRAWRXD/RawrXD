#!/usr/bin/env pwsh
#requires -Version 7.0

<#
.SYNOPSIS
    Phase J.3: Memory Optimizer
    
.DESCRIPTION
    Analyzes memory usage patterns and optimizes RawrXD memory configuration.
    Tunes KV cache, buffer sizes, and memory allocation strategies for
    maximum throughput and stability.
    
.PARAMETER ProfilePath
    Path to hardware profile JSON from Phase J.1
    
.PARAMETER TuningPath
    Path to kernel tuning results from Phase J.2
    
.PARAMETER ModelSize
    Model size to optimize for (3B, 7B, 13B, 30B, 70B)
    
.PARAMETER OutputPath
    Output directory for optimization results
    
.EXAMPLE
    .\memory_optimizer.ps1 -ModelSize 7B
#
>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$ProfilePath = ".\hardware_profiles\*.json",
    
    [Parameter(Mandatory=$false)]
    [string]$TuningPath = ".\kernel_tuning\kernel_optimization.json",
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("3B", "7B", "13B", "30B", "70B")]
    [string]$ModelSize = "7B",
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = ".\memory_optimization"
)

$ErrorActionPreference = "Stop"

# Memory optimization configuration
$OptimizerConfig = @{
    Timestamp = Get-Date -Format "o"
    Profile = $null
    KernelConfig = $null
    ModelSize = $ModelSize
    Analysis = @{}
    Recommendations = @{}
}

# Model memory requirements (approximate)
$ModelRequirements = @{
    "3B" = @{ Parameters = 3e9; FP16GB = 6; Q4_0GB = 1.8; Q8_0GB = 3.5; ContextOverheadGB = 0.5 }
    "7B" = @{ Parameters = 7e9; FP16GB = 14; Q4_0GB = 4; Q8_0GB = 7.5; ContextOverheadGB = 1 }
    "13B" = @{ Parameters = 13e9; FP16GB = 26; Q4_0GB = 7.5; Q8_0GB = 14; ContextOverheadGB = 1.5 }
    "30B" = @{ Parameters = 30e9; FP16GB = 60; Q4_0GB = 17; Q8_0GB = 32; ContextOverheadGB = 2.5 }
    "70B" = @{ Parameters = 70e9; FP16GB = 140; Q4_0GB = 40; Q8_0GB = 75; ContextOverheadGB = 5 }
}

function Write-OptimizerHeader {
    Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║  Phase J.3: Memory Optimizer                                     ║
║  Optimize memory configuration for maximum throughput             ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan
}

function Import-Configuration {
    <#
    .SYNOPSIS
        Load hardware profile and kernel tuning results
    #>
    Write-Host "`n[1/4] Loading configuration..." -ForegroundColor Yellow
    
    # Load hardware profile
    try {
        if ($ProfilePath -like "*\*") {
            $profiles = Get-ChildItem -Path $ProfilePath | Sort-Object LastWriteTime -Descending
            if ($profiles.Count -gt 0) {
                $ProfilePath = $profiles[0].FullName
            }
        }
        
        $OptimizerConfig.Profile = Get-Content -Path $ProfilePath -Raw | ConvertFrom-Json
        Write-Host "  Hardware profile: $([System.IO.Path]::GetFileName($ProfilePath))" -ForegroundColor Gray
    }
    catch {
        Write-Warning "Could not load hardware profile: $_"
    }
    
    # Load kernel tuning results
    try {
        if (Test-Path $TuningPath) {
            $OptimizerConfig.KernelConfig = Get-Content -Path $TuningPath -Raw | ConvertFrom-Json
            Write-Host "  Kernel tuning: $([System.IO.Path]::GetFileName($TuningPath))" -ForegroundColor Gray
        } else {
            Write-Warning "Kernel tuning results not found at $TuningPath"
        }
    }
    catch {
        Write-Warning "Could not load kernel tuning: $_"
    }
    
    Write-Host "  Model size: $ModelSize" -ForegroundColor Gray
}

function Get-MemoryAnalysis {
    <#
    .SYNOPSIS
        Analyze memory requirements and available resources
    #>
    Write-Host "`n[2/4] Analyzing memory requirements..." -ForegroundColor Yellow
    
    $analysis = @{
        SystemMemoryGB = $OptimizerConfig.Profile.Memory.TotalPhysicalGB
        AvailableMemoryGB = $OptimizerConfig.Profile.Memory.AvailableGB
        ModelRequirements = $ModelRequirements[$ModelSize]
        QuantizationOptions = @()
        ContextLengthOptions = @()
        BatchSizeOptions = @()
    }
    
    # Determine available quantization options
    $modelReq = $ModelRequirements[$ModelSize]
    $availableMemory = $analysis.AvailableMemoryGB * 0.8  # Use 80% of available
    
    Write-Host "  System memory: $($analysis.SystemMemoryGB) GB" -ForegroundColor Gray
    Write-Host "  Available for models: $([Math]::Round($availableMemory, 1)) GB" -ForegroundColor Gray
    Write-Host "  Model requirements:" -ForegroundColor Gray
    Write-Host "    FP16: $($modelReq.FP16GB) GB" -ForegroundColor Gray
    Write-Host "    Q8_0: $($modelReq.Q8_0GB) GB" -ForegroundColor Gray
    Write-Host "    Q4_0: $($modelReq.Q4_0GB) GB" -ForegroundColor Gray
    
    # Determine feasible quantization levels
    if ($availableMemory -ge $modelReq.FP16GB + $modelReq.ContextOverheadGB) {
        $analysis.QuantizationOptions += "FP16"
    }
    if ($availableMemory -ge $modelReq.Q8_0GB + $modelReq.ContextOverheadGB) {
        $analysis.QuantizationOptions += "Q8_0"
    }
    if ($availableMemory -ge $modelReq.Q4_0GB + $modelReq.ContextOverheadGB) {
        $analysis.QuantizationOptions += "Q4_0"
    }
    
    if ($analysis.QuantizationOptions.Count -eq 0) {
        Write-Warning "Insufficient memory for $ModelSize model. Consider using a smaller model."
        $analysis.Feasible = $false
    } else {
        $analysis.Feasible = $true
        $analysis.RecommendedQuantization = $analysis.QuantizationOptions[0]
        
        Write-Host "  Feasible quantization: $($analysis.QuantizationOptions -join ', ')" -ForegroundColor Green
        Write-Host "  Recommended: $($analysis.RecommendedQuantization)" -ForegroundColor Cyan
    }
    
    # Calculate context length options
    $contextOptions = @(512, 1024, 2048, 4096, 8192, 16384, 32768)
    $selectedQuant = $analysis.RecommendedQuantization
    $modelMemory = switch ($selectedQuant) {
        "FP16" { $modelReq.FP16GB }
        "Q8_0" { $modelReq.Q8_0GB }
        "Q4_0" { $modelReq.Q4_0GB }
        default { $modelReq.Q4_0GB }
    }
    
    foreach ($ctx in $contextOptions) {
        # Estimate KV cache memory: 2 * num_layers * num_heads * head_dim * seq_len * sizeof(float) * batch_size
        # Simplified: ~0.5MB per 1K tokens for 7B model, scales with model size
        $kvCachePer1K = ($ModelSize -replace "B", "") * 0.07  # Approximate
        $kvCacheGB = ($ctx / 1024) * $kvCachePer1K / 1024
        $totalMemory = $modelMemory + $kvCacheGB + $modelReq.ContextOverheadGB
        
        if ($totalMemory -le $availableMemory) {
            $analysis.ContextLengthOptions += $ctx
        }
    }
    
    if ($analysis.ContextLengthOptions.Count -gt 0) {
        $analysis.RecommendedContext = $analysis.ContextLengthOptions[-1]  # Largest feasible
        Write-Host "  Feasible context lengths: $($analysis.ContextLengthOptions -join ', ')" -ForegroundColor Green
        Write-Host "  Recommended context: $($analysis.RecommendedContext)" -ForegroundColor Cyan
    } else {
        $analysis.RecommendedContext = 512
        Write-Warning "Limited memory - using minimum context length"
    }
    
    # Calculate batch size options
    $batchOptions = @(1, 2, 4, 8, 16, 32)
    $analysis.BatchSizeOptions = @()
    
    foreach ($batch in $batchOptions) {
        # Check if batch size is feasible given memory constraints
        $batchMemory = $modelMemory + ($kvCachePer1K * $batch / 1024) + $modelReq.ContextOverheadGB
        if ($batchMemory -le $availableMemory * 0.9) {
            $analysis.BatchSizeOptions += $batch
        }
    }
    
    if ($analysis.BatchSizeOptions.Count -gt 0) {
        # Recommend batch size based on CPU threads if available
        if ($OptimizerConfig.KernelConfig -and $OptimizerConfig.KernelConfig.kernel) {
            $analysis.RecommendedBatchSize = [Math]::Min($analysis.BatchSizeOptions[-1], $OptimizerConfig.KernelConfig.kernel.threads)
        } else {
            $analysis.RecommendedBatchSize = $analysis.BatchSizeOptions[-1]
        }
        Write-Host "  Feasible batch sizes: $($analysis.BatchSizeOptions -join ', ')" -ForegroundColor Green
        Write-Host "  Recommended batch: $($analysis.RecommendedBatchSize)" -ForegroundColor Cyan
    } else {
        $analysis.RecommendedBatchSize = 1
    }
    
    return $analysis
}

function Get-MemoryRecommendations {
    <#
    .SYNOPSIS
        Generate memory optimization recommendations
    #>
    param($Analysis)
    
    Write-Host "`n[3/4] Generating memory recommendations..." -ForegroundColor Yellow
    
    $recommendations = @{
        Quantization = $Analysis.RecommendedQuantization
        ContextLength = $Analysis.RecommendedContext
        BatchSize = $Analysis.RecommendedBatchSize
        KVCacheStrategy = ""
        MemoryPoolSizeGB = 0
        BufferStrategy = ""
        NUMAAware = $false
        MemoryMapping = $true
        PrefetchStrategy = ""
    }
    
    # KV cache strategy
    if ($Analysis.SystemMemoryGB -ge 64) {
        $recommendations.KVCacheStrategy = "full_precision"
        $recommendations.KVCacheQuantization = "none"
    } elseif ($Analysis.SystemMemoryGB -ge 32) {
        $recommendations.KVCacheStrategy = "quantized"
        $recommendations.KVCacheQuantization = "Q8_0"
    } else {
        $recommendations.KVCacheStrategy = "quantized"
        $recommendations.KVCacheQuantization = "Q4_0"
    }
    
    Write-Host "  KV cache strategy: $($recommendations.KVCacheStrategy)" -ForegroundColor Gray
    Write-Host "  KV cache quantization: $($recommendations.KVCacheQuantization)" -ForegroundColor Gray
    
    # Memory pool sizing
    $recommendations.MemoryPoolSizeGB = [Math]::Min(
        [Math]::Floor($Analysis.AvailableMemoryGB * 0.7),
        [int]($Analysis.ModelRequirements.($recommendations.Quantization + "GB") * 1.5)
    )
    
    Write-Host "  Memory pool: $($recommendations.MemoryPoolSizeGB) GB" -ForegroundColor Gray
    
    # Buffer strategy
    if ($Analysis.SystemMemoryGB -ge 128) {
        $recommendations.BufferStrategy = "aggressive_prefetch"
        $recommendations.PrefetchStrategy = "lookahead_4"
    } elseif ($Analysis.SystemMemoryGB -ge 64) {
        $recommendations.BufferStrategy = "moderate_prefetch"
        $recommendations.PrefetchStrategy = "lookahead_2"
    } else {
        $recommendations.BufferStrategy = "minimal"
        $recommendations.PrefetchStrategy = "on_demand"
    }
    
    Write-Host "  Buffer strategy: $($recommendations.BufferStrategy)" -ForegroundColor Gray
    Write-Host "  Prefetch: $($recommendations.PrefetchStrategy)" -ForegroundColor Gray
    
    # NUMA awareness
    if ($OptimizerConfig.Profile.CPU.LogicalProcessors -ge 16) {
        $recommendations.NUMAAware = $true
        Write-Host "  NUMA awareness: enabled" -ForegroundColor Gray
    }
    
    # Memory mapping
    $recommendations.MemoryMapping = $true
    Write-Host "  Memory mapping: enabled" -ForegroundColor Gray
    
    return $recommendations
}

function Export-OptimizationResults {
    <#
    .SYNOPSIS
        Export memory optimization results
    #>
    param($Analysis, $Recommendations)
    
    Write-Host "`n[4/4] Exporting optimization results..." -ForegroundColor Yellow
    
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    
    # JSON configuration
    $config = @{
        version = "1.0.0"
        timestamp = $OptimizerConfig.Timestamp
        model = @{
            size = $ModelSize
            parameters = $Analysis.ModelRequirements.Parameters
            quantization = $Recommendations.Quantization
        }
        memory = @{
            system_gb = $Analysis.SystemMemoryGB
            available_gb = $Analysis.AvailableMemoryGB
            pool_gb = $Recommendations.MemoryPoolSizeGB
            utilization_target = 0.75
        }
        inference = @{
            context_length = $Recommendations.ContextLength
            batch_size = $Recommendations.BatchSize
        }
        kv_cache = @{
            strategy = $Recommendations.KVCacheStrategy
            quantization = $Recommendations.KVCacheQuantization
            max_memory_gb = [Math]::Floor($Analysis.AvailableMemoryGB * 0.3)
        }
        optimization = @{
            buffer_strategy = $Recommendations.BufferStrategy
            prefetch_strategy = $Recommendations.PrefetchStrategy
            numa_aware = $Recommendations.NUMAAware
            memory_mapping = $Recommendations.MemoryMapping
            flash_attention = $true
            continuous_batching = $true
        }
    }
    
    $configFile = Join-Path $OutputPath "memory_optimization.json"
    $config | ConvertTo-Json -Depth 10 | Set-Content -Path $configFile
    
    # Markdown report
    $report = @"
# RawrXD Memory Optimization Report

**Generated:** $($OptimizerConfig.Timestamp)  
**Model:** $ModelSize ($($Analysis.ModelRequirements.Parameters) parameters)

## Memory Analysis

| Property | Value |
|----------|-------|
| System Memory | $($Analysis.SystemMemoryGB) GB |
| Available Memory | $($Analysis.AvailableMemoryGB) GB |
| Memory Pool | $($Recommendations.MemoryPoolSizeGB) GB |

## Model Configuration

| Property | Value |
|----------|-------|
| Quantization | $($Recommendations.Quantization) |
| Model Size | $($Analysis.ModelRequirements.($Recommendations.Quantization + "GB")) GB |
| Context Length | $($Recommendations.ContextLength) tokens |
| Batch Size | $($Recommendations.BatchSize) |

## Memory Optimization Settings

| Property | Value |
|----------|-------|
| KV Cache Strategy | $($Recommendations.KVCacheStrategy) |
| KV Cache Quantization | $($Recommendations.KVCacheQuantization) |
| Buffer Strategy | $($Recommendations.BufferStrategy) |
| Prefetch Strategy | $($Recommendations.PrefetchStrategy) |
| NUMA Aware | $($Recommendations.NUMAAware) |
| Memory Mapping | $($Recommendations.MemoryMapping) |

## Feasibility Analysis

$(if ($Analysis.Feasible) { "✅ **Model can run with recommended configuration**" } else { "❌ **Insufficient memory for this model**" })

### Feasible Quantization Levels
$(foreach ($q in $Analysis.QuantizationOptions) { "- $q`n" })

### Feasible Context Lengths
$(foreach ($c in $Analysis.ContextLengthOptions) { "- $c tokens`n" })

### Feasible Batch Sizes
$(foreach ($b in $Analysis.BatchSizeOptions) { "- $b`n" })

## Configuration File

The optimized configuration has been saved to: `memory_optimization.json`

Apply these settings by copying the configuration file to your RawrXD config directory.

---
*Generated by RawrXD Memory Optimizer*
"@
    
    $reportFile = Join-Path $OutputPath "memory_optimization_report.md"
    $report | Set-Content -Path $reportFile
    
    Write-Host "`nResults saved:" -ForegroundColor Cyan
    Write-Host "  Config JSON: $configFile" -ForegroundColor Gray
    Write-Host "  Report: $reportFile" -ForegroundColor Gray
    
    return @{
        Config = $configFile
        Report = $reportFile
    }
}

# Main execution
Write-OptimizerHeader

# Load configuration
Import-Configuration

# Analyze memory
$analysis = Get-MemoryAnalysis

if (-not $analysis.Feasible) {
    Write-Error "Cannot optimize for $ModelSize model - insufficient memory"
    exit 1
}

# Generate recommendations
$recommendations = Get-MemoryRecommendations -Analysis $analysis

# Export results
$exported = Export-OptimizationResults -Analysis $analysis -Recommendations $recommendations

# Summary
Write-Host "`n══════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "MEMORY OPTIMIZATION COMPLETE" -ForegroundColor Cyan
Write-Host "══════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "Model: $ModelSize ($($analysis.ModelRequirements.Parameters) parameters)" -ForegroundColor White
Write-Host "Quantization: $($recommendations.Quantization)" -ForegroundColor White
Write-Host "Context Length: $($recommendations.ContextLength) tokens" -ForegroundColor White
Write-Host "Batch Size: $($recommendations.BatchSize)" -ForegroundColor White
Write-Host "Memory Pool: $($recommendations.MemoryPoolSizeGB) GB" -ForegroundColor White
Write-Host "KV Cache: $($recommendations.KVCacheStrategy) ($($recommendations.KVCacheQuantization))" -ForegroundColor White

Write-Host "`nTo apply these settings, copy memory_optimization.json to your RawrXD config directory." -ForegroundColor Green
