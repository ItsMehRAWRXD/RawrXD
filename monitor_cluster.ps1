# Sovereign Engine Cluster Monitor
# Aggregates metrics from all 8 Prometheus endpoints
# Usage: .\monitor_cluster.ps1 [-Continuous] [-Interval 5]

param(
    [switch]$Continuous = $false,
    [int]$Interval = 5,
    [switch]$StressTest = $false
)

$ErrorActionPreference = "SilentlyContinue"

# Node configuration
$Nodes = @(
    @{ Id = 0; Role = "HEAD";   Port = 8080; IP = "127.0.0.1" },
    @{ Id = 1; Role = "WORKER"; Port = 8081; IP = "127.0.0.1" },
    @{ Id = 2; Role = "WORKER"; Port = 8082; IP = "127.0.0.1" },
    @{ Id = 3; Role = "WORKER"; Port = 8083; IP = "127.0.0.1" },
    @{ Id = 4; Role = "WORKER"; Port = 8084; IP = "127.0.0.1" },
    @{ Id = 5; Role = "WORKER"; Port = 8085; IP = "127.0.0.1" },
    @{ Id = 6; Role = "WORKER"; Port = 8086; IP = "127.0.0.1" },
    @{ Id = 7; Role = "WORKER"; Port = 8087; IP = "127.0.0.1" }
)

function Get-NodeMetrics {
    param($Node)
    
    $metrics = @{
        NodeId = $Node.Id
        Role = $Node.Role
        Port = $Node.Port
        Status = "OFFLINE"
        ResponseTime = 0
        TokensProcessed = 0
        KVCacheSize = 0
        RingLatency = 0
        MemoryUsage = 0
        CPUUsage = 0
    }
    
    $startTime = Get-Date
    try {
        $response = Invoke-WebRequest -Uri "http://$($Node.IP):$($Node.Port)/metrics" -TimeoutSec 2 -UseBasicParsing
        $metrics.ResponseTime = ((Get-Date) - $startTime).TotalMilliseconds
        $metrics.Status = "ONLINE"
        
        # Parse Prometheus metrics
        $content = $response.Content
        
        # Extract sovereign_tokens_processed
        if ($content -match 'sovereign_tokens_processed\s+(\d+)') {
            $metrics.TokensProcessed = [int]$matches[1]
        }
        
        # Extract sovereign_kv_cache_bytes
        if ($content -match 'sovereign_kv_cache_bytes\s+(\d+)') {
            $metrics.KVCacheSize = [int64]$matches[1]
        }
        
        # Extract sovereign_ring_latency_ms
        if ($content -match 'sovereign_ring_latency_ms\s+([\d.]+)') {
            $metrics.RingLatency = [float]$matches[1]
        }
        
        # Extract process_memory_usage_bytes
        if ($content -match 'process_memory_usage_bytes\s+(\d+)') {
            $metrics.MemoryUsage = [int64]$matches[1]
        }
        
        # Extract process_cpu_seconds_total (convert to percentage)
        if ($content -match 'process_cpu_seconds_total\s+([\d.]+)') {
            $metrics.CPUUsage = [float]$matches[1]
        }
    } catch {
        $metrics.Status = "ERROR"
    }
    
    return $metrics
}

function Show-ClusterDashboard {
    param($Metrics)
    
    Clear-Host
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    
    Write-Host "╔══════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║                    SOVEREIGN ENGINE CLUSTER DASHBOARD                          ║" -ForegroundColor Cyan
    Write-Host "║                    $timestamp                          ║" -ForegroundColor Cyan
    Write-Host "╚══════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    
    # Summary statistics
    $onlineNodes = ($Metrics | Where-Object { $_.Status -eq "ONLINE" }).Count
    $totalTokens = ($Metrics | Measure-Object -Property TokensProcessed -Sum).Sum
    $avgLatency = ($Metrics | Where-Object { $_.RingLatency -gt 0 } | Measure-Object -Property RingLatency -Average).Average
    $totalMemory = ($Metrics | Measure-Object -Property MemoryUsage -Sum).Sum
    
    Write-Host "CLUSTER SUMMARY:" -ForegroundColor Yellow
    Write-Host "  Nodes Online:    $onlineNodes/8" -ForegroundColor $(if ($onlineNodes -eq 8) { "Green" } else { "Yellow" })
    Write-Host "  Total Tokens:    $totalTokens" -ForegroundColor White
    Write-Host "  Avg Ring Latency: $(if ($avgLatency) { "{0:N2} ms" -f $avgLatency } else { "N/A" })" -ForegroundColor $(if ($avgLatency -lt 10) { "Green" } elseif ($avgLatency -lt 50) { "Yellow" } else { "Red" })
    Write-Host "  Total Memory:    $([math]::Round($totalMemory / 1MB, 2)) MB" -ForegroundColor White
    Write-Host ""
    
    # Individual node status
    Write-Host "NODE STATUS:" -ForegroundColor Yellow
    Write-Host "  ID │ Role   │ Status  │ Response │ Tokens    │ Ring Lat │ Memory" -ForegroundColor Gray
    Write-Host "  ───┼────────┼─────────┼──────────┼───────────┼──────────┼──────────" -ForegroundColor Gray
    
    foreach ($metric in $Metrics | Sort-Object NodeId) {
        $statusColor = switch ($metric.Status) {
            "ONLINE"  { "Green" }
            "OFFLINE" { "Red" }
            default   { "Yellow" }
        }
        
        $latencyColor = if ($metric.RingLatency -eq 0) { "Gray" }
                       elseif ($metric.RingLatency -lt 10) { "Green" }
                       elseif ($metric.RingLatency -lt 50) { "Yellow" }
                       else { "Red" }
        
        $memoryMB = [math]::Round($metric.MemoryUsage / 1MB, 1)
        
        Write-Host "  $($metric.NodeId.ToString().PadRight(2)) │ " -NoNewline
        Write-Host "$($metric.Role.PadRight(6))" -NoNewline
        Write-Host " │ " -NoNewline
        Write-Host "$($metric.Status.PadRight(7))" -ForegroundColor $statusColor -NoNewline
        Write-Host " │ " -NoNewline
        Write-Host "$($metric.ResponseTime.ToString("N0").PadRight(7)) ms" -NoNewline
        Write-Host " │ " -NoNewline
        Write-Host "$($metric.TokensProcessed.ToString().PadRight(9))" -NoNewline
        Write-Host " │ " -NoNewline
        Write-Host "$($metric.RingLatency.ToString("N2").PadRight(7)) ms" -ForegroundColor $latencyColor -NoNewline
        Write-Host " │ " -NoNewline
        Write-Host "$($memoryMB.ToString().PadRight(7)) MB" -NoNewline
        Write-Host ""
    }
    
    Write-Host ""
    Write-Host "Press Ctrl+C to exit monitoring" -ForegroundColor DarkGray
}

function Export-MetricsToFile {
    param($Metrics)
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $csvLine = "$timestamp," + ($Metrics | ForEach-Object { 
        "$($_.NodeId),$($_.Status),$($_.TokensProcessed),$($_.RingLatency),$($_.MemoryUsage)" 
    }) -join ","
    
    Add-Content -Path "D:\RawrXD\simulation\metrics_history.csv" -Value $csvLine
}

# Main execution
Write-Host "Sovereign Engine Cluster Monitor" -ForegroundColor Cyan
Write-Host "Polling 8 Prometheus endpoints (ports 8080-8087)...`n" -ForegroundColor Gray

if ($StressTest) {
    Write-Host "STRESS TEST MODE: Will run 100 sequential inferences" -ForegroundColor Yellow
    Write-Host ""
}

# Initialize CSV header if not exists
$csvPath = "D:\RawrXD\simulation\metrics_history.csv"
if (-not (Test-Path $csvPath)) {
    $header = "Timestamp," + (0..7 | ForEach-Object { "Node$($_)_Status,Node$($_)_Tokens,Node$($_)_Latency,Node$($_)_Memory" }) -join ","
    Set-Content -Path $csvPath -Value $header
}

$iteration = 0
$maxIterations = if ($StressTest) { 100 } else { [int]::MaxValue }

do {
    $iteration++
    $metrics = @()
    
    # Poll all nodes in parallel
    $jobs = $Nodes | ForEach-Object {
        Start-Job -ScriptBlock ${function:Get-NodeMetrics} -ArgumentList $_
    }
    
    $jobs | Wait-Job -Timeout 5 | Out-Null
    
    foreach ($job in $jobs) {
        $result = Receive-Job -Job $job -ErrorAction SilentlyContinue
        if ($result) {
            $metrics += $result
        }
        Remove-Job -Job $job -Force
    }
    
    # Add missing nodes
    foreach ($node in $Nodes) {
        if (-not ($metrics | Where-Object { $_.NodeId -eq $node.Id })) {
            $metrics += @{
                NodeId = $node.Id
                Role = $node.Role
                Port = $node.Port
                Status = "TIMEOUT"
                ResponseTime = 0
                TokensProcessed = 0
                KVCacheSize = 0
                RingLatency = 0
                MemoryUsage = 0
                CPUUsage = 0
            }
        }
    }
    
    Show-ClusterDashboard -Metrics $metrics
    Export-MetricsToFile -Metrics $metrics
    
    if ($Continuous -or $StressTest) {
        if ($StressTest) {
            Write-Host "`nStress Test Progress: $iteration/$maxIterations iterations" -ForegroundColor Yellow
        }
        Start-Sleep -Seconds $Interval
    }
    
} while ($Continuous -or ($StressTest -and $iteration -lt $maxIterations))

Write-Host "`nMonitoring complete. Metrics saved to: $csvPath" -ForegroundColor Green