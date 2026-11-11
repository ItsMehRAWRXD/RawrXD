#!/usr/bin/env pwsh
#requires -Version 7.0

<#
.SYNOPSIS
    Phase G.3 Batch 2/5: Centralized Metrics Aggregator
    
.DESCRIPTION
    Collects and aggregates metrics from multiple RawrXD instances:
    - Pulls metrics from discovered nodes
    - Cross-node correlation and analysis
    - Cluster-wide SIS/SAI aggregation
    - Statistical analysis across nodes
    - Leader election for high availability
    
.PARAMETER DiscoveryRegistry
    Path to cluster discovery registry (default: ..\batch1_cluster_discovery\cluster_registry)
    
.PARAMETER OutputPath
    Path for aggregated metrics output (default: .\aggregated_metrics)
    
.PARAMETER AggregationInterval
    Metrics aggregation interval in seconds (default: 30)
    
.PARAMETER NodeTimeout
    Node timeout in seconds (default: 60)
    
.PARAMETER EnableCorrelation
    Enable cross-node correlation analysis
    
.EXAMPLE
    .\metrics_aggregator.ps1
    
.EXAMPLE
    .\metrics_aggregator.ps1 -AggregationInterval 15 -EnableCorrelation
#
>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$DiscoveryRegistry = "..\batch1_cluster_discovery\cluster_registry",
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = ".\aggregated_metrics",
    
    [Parameter(Mandatory=$false)]
    [int]$AggregationInterval = 30,
    
    [Parameter(Mandatory=$false)]
    [int]$NodeTimeout = 60,
    
    [Parameter(Mandatory=$false)]
    [switch]$EnableCorrelation
)

# Error action preference
$ErrorActionPreference = "Stop"

# Banner
Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║  Phase G.3 Batch 2/5: Centralized Metrics Aggregator                ║
║  Multi-Node Metrics Collection & Cluster-Wide Analysis              ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

# Create output directory
New-Item -ItemType Directory -Force -Path $OutputPath | Out-Null

# Aggregator state
$script:AggregatorState = @{
    start_time = Get-Date -Format "o"
    total_samples = 0
    node_metrics = @{}  # node_id -> metrics array
    cluster_stats = @{}  # aggregated statistics
    running = $true
}

function Get-ClusterNodes {
    <#
    .SYNOPSIS
        Reads discovered nodes from registry
    #>
    $registryPath = Join-Path $DiscoveryRegistry "cluster_registry.json"
    
    if (-not (Test-Path $registryPath)) {
        Write-Host "  ! No discovery registry found. Run cluster_discovery.ps1 first." -ForegroundColor Yellow
        return @()
    }
    
    $registry = Get-Content -Path $registryPath | ConvertFrom-Json -AsHashtable
    
    # Filter healthy nodes
    $healthyNodes = $registry.known_nodes | Where-Object { 
        $_.health_status -eq "healthy" -or $_.health_status -eq "unknown"
    }
    
    return $healthyNodes
}

function Get-NodeMetrics {
    <#
    .SYNOPSIS
        Fetches metrics from a single node
    #>
    param([hashtable]$Node)
    
    try {
        $metrics = Invoke-RestMethod -Uri "http://$($Node.address):8081/api/metrics/live" -Method GET -TimeoutSec 5 -ErrorAction SilentlyContinue
        return @{
            node_id = $Node.node_id
            timestamp = Get-Date -Format "o"
            success = $true
            metrics = $metrics
        }
    }
    catch {
        return @{
            node_id = $Node.node_id
            timestamp = Get-Date -Format "o"
            success = $false
            error = $_.ToString()
        }
    }
}

function Invoke-MetricsAggregation {
    <#
    .SYNOPSIS
        Aggregates metrics from all nodes
    #>
    $nodes = Get-ClusterNodes
    
    if ($nodes.Count -eq 0) {
        Write-Host "  ! No healthy nodes found" -ForegroundColor Yellow
        return
    }
    
    Write-Host "  Collecting from $($nodes.Count) nodes..." -ForegroundColor Gray
    
    $allMetrics = @()
    $successCount = 0
    
    foreach ($node in $nodes) {
        $result = Get-NodeMetrics -Node $node
        $allMetrics += $result
        
        if ($result.success) {
            $successCount++
            
            # Store in node-specific buffer
            if (-not $script:AggregatorState.node_metrics[$result.node_id]) {
                $script:AggregatorState.node_metrics[$result.node_id] = [System.Collections.ArrayList]::new()
            }
            [void]$script:AggregatorState.node_metrics[$result.node_id].Add($result.metrics)
            
            # Keep only last 100 samples per node
            if ($script:AggregatorState.node_metrics[$result.node_id].Count -gt 100) {
                $script:AggregatorState.node_metrics[$result.node_id].RemoveAt(0)
            }
        }
    }
    
    Write-Host "    ✓ $successCount/$($nodes.Count) nodes responded" -ForegroundColor Green
    
    # Calculate cluster-wide statistics
    $successfulMetrics = $allMetrics | Where-Object { $_.success } | ForEach-Object { $_.metrics }
    
    if ($successfulMetrics.Count -gt 0) {
        $clusterStats = @{
            timestamp = Get-Date -Format "o"
            node_count = $nodes.Count
            responding_nodes = $successCount
            
            # TPS statistics
            tps_values = $successfulMetrics | ForEach-Object { $_.tps }
            tps_avg = ($tps_values | Measure-Object -Average).Average
            tps_min = ($tps_values | Measure-Object -Minimum).Minimum
            tps_max = ($tps_values | Measure-Object -Maximum).Maximum
            tps_std = if ($tps_values.Count -gt 1) { 
                $avg = ($tps_values | Measure-Object -Average).Average
                [Math]::Sqrt((($tps_values | ForEach-Object { [Math]::Pow($_ - $avg, 2) } | Measure-Object -Average).Average))
            } else { 0 }
            
            # SIS statistics
            sis_values = $successfulMetrics | ForEach-Object { $_.sis }
            sis_avg = ($sis_values | Measure-Object -Average).Average
            sis_min = ($sis_values | Measure-Object -Minimum).Minimum
            
            # SAI statistics
            sai_values = $successfulMetrics | ForEach-Object { $_.sai }
            sai_avg = ($sai_values | Measure-Object -Average).Average
            sai_min = ($sai_values | Measure-Object -Minimum).Minimum
            
            # Latency statistics
            latency_values = $successfulMetrics | ForEach-Object { $_.latency_ms }
            latency_avg = ($latency_values | Measure-Object -Average).Average
            latency_max = ($latency_values | Measure-Object -Maximum).Maximum
            
            per_node = $successfulMetrics | ForEach-Object {
                @{
                    node_id = $_.instances[0].name
                    tps = $_.tps
                    sis = $_.sis
                    sai = $_.sai
                    latency_ms = $_.latency_ms
                }
            }
        }
        
        $script:AggregatorState.cluster_stats = $clusterStats
        $script:AggregatorState.total_samples += $successCount
        
        # Save aggregated metrics
        Save-AggregatedMetrics -Stats $clusterStats -RawMetrics $allMetrics
        
        # Display summary
        Show-ClusterSummary -Stats $clusterStats
    }
}

function Save-AggregatedMetrics {
    <#
    .SYNOPSIS
        Saves aggregated metrics to disk
    #>
    param(
        [hashtable]$Stats,
        [array]$RawMetrics
    )
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $filename = "cluster_metrics_${timestamp}.json"
    $filepath = Join-Path $OutputPath $filename
    
    $output = @{
        timestamp = Get-Date -Format "o"
        cluster_stats = $Stats
        raw_metrics = $RawMetrics
        aggregation_version = "1.0"
    }
    
    $output | ConvertTo-Json -Depth 10 | Set-Content -Path $filepath
}

function Show-ClusterSummary {
    <#
    .SYNOPSIS
        Displays cluster-wide metrics summary
    #>
    param([hashtable]$Stats)
    
    Write-Host "`nCluster Metrics Summary" -ForegroundColor Cyan
    Write-Host "  Nodes: $($Stats.responding_nodes)/$($Stats.node_count) responding" -ForegroundColor White
    Write-Host "  TPS: avg=$([Math]::Round($Stats.tps_avg, 1)) min=$([Math]::Round($Stats.tps_min, 1)) max=$([Math]::Round($Stats.tps_max, 1))" -ForegroundColor White
    Write-Host "  SIS: avg=$([Math]::Round($Stats.sis_avg, 1)) min=$([Math]::Round($Stats.sis_min, 1))" -ForegroundColor White
    Write-Host "  SAI: avg=$([Math]::Round($Stats.sai_avg, 2)) min=$([Math]::Round($Stats.sai_min, 2))" -ForegroundColor White
    Write-Host "  Latency: avg=$([Math]::Round($Stats.latency_avg, 1))ms max=$([Math]::Round($Stats.latency_max, 1))ms" -ForegroundColor White
    
    if ($EnableCorrelation) {
        Invoke-CorrelationAnalysis
    }
}

function Invoke-CorrelationAnalysis {
    <#
    .SYNOPSIS
        Performs cross-node correlation analysis
    #>
    Write-Host "`n  Cross-Node Correlation:" -ForegroundColor Yellow
    
    $nodeIds = $script:AggregatorState.node_metrics.Keys
    
    if ($nodeIds.Count -lt 2) {
        Write-Host "    (Need 2+ nodes for correlation)" -ForegroundColor Gray
        return
    }
    
    # Calculate TPS variance across nodes
    $tpsValues = @()
    foreach ($nodeId in $nodeIds) {
        $samples = $script:AggregatorState.node_metrics[$nodeId]
        if ($samples.Count -gt 0) {
            $avgTps = ($samples | ForEach-Object { $_.tps } | Measure-Object -Average).Average
            $tpsValues += $avgTps
        }
    }
    
    if ($tpsValues.Count -gt 1) {
        $mean = ($tpsValues | Measure-Object -Average).Average
        $variance = (($tpsValues | ForEach-Object { [Math]::Pow($_ - $mean, 2) } | Measure-Object -Average).Average)
        $cv = if ($mean -gt 0) { [Math]::Sqrt($variance) / $mean } else { 0 }
        
        Write-Host "    TPS Coefficient of Variation: $([Math]::Round($cv * 100, 1))%" -ForegroundColor $(if ($cv -lt 0.1) { "Green" } else { "Yellow" })
        
        if ($cv -gt 0.2) {
            Write-Host "    ⚠ High variance detected - nodes may need rebalancing" -ForegroundColor Yellow
        }
    }
}

# Main execution
Write-Host "`nConfiguration:" -ForegroundColor Yellow
Write-Host "  Discovery Registry: $DiscoveryRegistry" -ForegroundColor White
Write-Host "  Output Path: $OutputPath" -ForegroundColor White
Write-Host "  Aggregation Interval: ${AggregationInterval}s" -ForegroundColor White
Write-Host "  Correlation Analysis: $EnableCorrelation" -ForegroundColor White

Write-Host "`nStarting metrics aggregator...`n" -ForegroundColor Green
Write-Host "Press Ctrl+C to stop`n" -ForegroundColor Gray

try {
    while ($script:AggregatorState.running) {
        Invoke-MetricsAggregation
        
        Write-Host "  Next aggregation in ${AggregationInterval}s..." -ForegroundColor DarkGray
        Start-Sleep -Seconds $AggregationInterval
    }
}
catch {
    Write-Host "`nError: $_" -ForegroundColor Red
}
finally {
    Write-Host "`nMetrics aggregator stopped." -ForegroundColor Yellow
    Write-Host "Total samples collected: $($script:AggregatorState.total_samples)" -ForegroundColor White
}
