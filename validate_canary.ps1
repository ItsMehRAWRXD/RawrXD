# Sovereign Engine Canary Validation
# Validates health and performance of canary deployment stages
# Usage: .\validate_canary.ps1 -Stage {1|2|3|4} [-Duration 60]

param(
    [Parameter(Mandatory=$true)]
    [ValidateRange(1,4)]
    [int]$Stage,
    
    [int]$Duration = 60,
    [switch]$LoadTest = $false
)

$ErrorActionPreference = "Stop"

# Stage node mapping
$StageNodes = @{
    1 = @(0)
    2 = @(0,1)
    3 = @(0,1,2,3)
    4 = @(0,1,2,3,4,5,6,7)
}

$AllNodes = @(
    @{ Id = 0; Role = "HEAD";   IP = "192.168.1.10"; Port = 8080 },
    @{ Id = 1; Role = "WORKER"; IP = "192.168.1.11"; Port = 8081 },
    @{ Id = 2; Role = "WORKER"; IP = "192.168.1.12"; Port = 8082 },
    @{ Id = 3; Role = "WORKER"; IP = "192.168.1.13"; Port = 8083 },
    @{ Id = 4; Role = "WORKER"; IP = "192.168.1.14"; Port = 8084 },
    @{ Id = 5; Role = "WORKER"; IP = "192.168.1.15"; Port = 8085 },
    @{ Id = 6; Role = "WORKER"; IP = "192.168.1.16"; Port = 8086 },
    @{ Id = 7; Role = "WORKER"; IP = "192.168.1.17"; Port = 8087 }
)

$targetNodes = $AllNodes | Where-Object { $StageNodes[$Stage] -contains $_.Id }

Write-Host "╔══════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║                    CANARY VALIDATION - Stage $Stage                              ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Phase 1: Connectivity Check
Write-Host "PHASE 1: Connectivity Validation" -ForegroundColor Yellow

$connectivityResults = @()
foreach ($node in $targetNodes) {
    Write-Host "  Node $($node.Id) ($($node.IP))..." -NoNewline
    
    $ping = Test-Connection -ComputerName $node.IP -Count 2 -Quiet -ErrorAction SilentlyContinue
    $port = Test-NetConnection -ComputerName $node.IP -Port $($node.Port) -WarningAction SilentlyContinue
    
    $result = [PSCustomObject]@{
        NodeId = $node.Id
        Ping = $ping
        Prometheus = $port.TcpTestSucceeded
    }
    $connectivityResults += $result
    
    $status = $(if ($ping -and $port.TcpTestSucceeded) { "✅" } elseif ($ping) { "⚠️" } else { "❌" }
    Write-Host " $status" -ForegroundColor $(if ($ping -and $port.TcpTestSucceeded) { "Green" } elseif ($ping) { "Yellow" } else { "Red" })
}

$connectedNodes = ($connectivityResults | Where-Object { $_.Ping -and $_.Prometheus }).Count
Write-Host "  Connected: $connectedNodes/$($targetNodes.Count)" -ForegroundColor $(if ($connectedNodes -eq $targetNodes.Count) { "Green" } else { "Yellow" })
Write-Host ""

# Phase 2: Metrics Collection
Write-Host "PHASE 2: Metrics Collection ($Duration seconds)" -ForegroundColor Yellow

$metricsHistory = @()
$startTime = Get-Date

while (((Get-Date) - $startTime).TotalSeconds -lt $Duration) {
    $elapsed = [math]::Round(((Get-Date) - $startTime).TotalSeconds)
    $percent = [math]::Min(100, ($elapsed / $Duration) * 100)
    
    Write-Progress -Activity "Collecting Metrics" -Status "$elapsed/$Duration seconds" -PercentComplete $percent
    
    $snapshot = @{
        Timestamp = Get-Date -Format "HH:mm:ss"
        Nodes = @()
    }
    
    foreach ($node in $targetNodes) {
        try {
            $response = Invoke-WebRequest -Uri "http://$($node.IP):$($node.Port)/metrics" -TimeoutSec 2 -UseBasicParsing -ErrorAction SilentlyContinue
            $content = $response.Content
            
            # Parse metrics
            $tokens = $(if ($content -match 'sovereign_tokens_processed\s+(\d+)') { [int]$matches[1] } else { 0 }
            $latency = $(if ($content -match 'sovereign_ring_latency_ms\s+([\d.]+)') { [float]$matches[1] } else { 0 }
            $memory = $(if ($content -match 'process_memory_usage_bytes\s+(\d+)') { [int64]$matches[1] } else { 0 }
            
            $snapshot.Nodes += @{
                NodeId = $node.Id
                Online = $true
                Tokens = $tokens
                Latency = $latency
                Memory = $memory
            }
        } catch {
            $snapshot.Nodes += @{
                NodeId = $node.Id
                Online = $false
                Tokens = 0
                Latency = 0
                Memory = 0
            }
        }
    }
    
    $metricsHistory += $snapshot
    Start-Sleep -Seconds 1
}

Write-Progress -Activity "Collecting Metrics" -Completed

# Phase 3: Analysis
Write-Host "`nPHASE 3: Performance Analysis" -ForegroundColor Yellow

# Calculate trends
$onlineSnapshots = $metricsHistory | Where-Object { $_.Nodes | Where-Object { $_.Online } }
$totalSnapshots = $metricsHistory.Count

if ($onlineSnapshots.Count -eq 0) {
    Write-Host "  ❌ No nodes reporting metrics!" -ForegroundColor Red
    exit 1
}

# Per-node analysis
$nodeStats = @()
foreach ($node in $targetNodes) {
    $nodeMetrics = $onlineSnapshots | ForEach-Object { 
        $_.Nodes | Where-Object { $_.NodeId -eq $node.Id }
    }
    
    if ($nodeMetrics.Count -gt 0) {
        $latencies = $nodeMetrics | Where-Object { $_.Latency -gt 0 } | ForEach-Object { $_.Latency }
        $memories = $nodeMetrics | ForEach-Object { $_.Memory }
        
        $stat = [PSCustomObject]@{
            NodeId = $node.Id
            Uptime = ($nodeMetrics.Count / $totalSnapshots) * 100
            AvgLatency = $(if ($latencies.Count -gt 0) { ($latencies | Measure-Object -Average).Average } else { 0 }
            MaxLatency = $(if ($latencies.Count -gt 0) { ($latencies | Measure-Object -Maximum).Maximum } else { 0 }
            AvgMemory = $(if ($memories.Count -gt 0) { ($memories | Measure-Object -Average).Average } else { 0 }
            TokenDelta = $(if ($nodeMetrics.Count -gt 0) { $nodeMetrics[-1].Tokens - $nodeMetrics[0].Tokens } else { 0 }
        }
        $nodeStats += $stat
    }
}

Write-Host "  Node Performance:" -ForegroundColor Gray
Write-Host "  ID │ Uptime │ Avg Lat │ Max Lat │ Memory  │ Tokens" -ForegroundColor Gray
Write-Host "  ───┼────────┼─────────┼─────────┼─────────┼────────" -ForegroundColor Gray

foreach ($stat in $nodeStats | Sort-Object NodeId) {
    $uptimeColor = $(if ($stat.Uptime -gt 95) { "Green" } elseif ($stat.Uptime -gt 80) { "Yellow" } else { "Red" }
    $latencyColor = $(if ($stat.AvgLatency -lt 50) { "Green" } elseif ($stat.AvgLatency -lt 200) { "Yellow" } else { "Red" }
    
    Write-Host "  $($stat.NodeId.ToString().PadRight(2)) │ " -NoNewline
    Write-Host "$($stat.Uptime.ToString("N1").PadRight(6))%" -ForegroundColor $uptimeColor -NoNewline
    Write-Host " │ " -NoNewline
    Write-Host "$($stat.AvgLatency.ToString("N1").PadRight(7))" -ForegroundColor $latencyColor -NoNewline
    Write-Host " │ " -NoNewline
    Write-Host "$($stat.MaxLatency.ToString("N1").PadRight(7))" -NoNewline
    Write-Host " │ " -NoNewline
    Write-Host "$([math]::Round($stat.AvgMemory/1MB,1).ToString().PadRight(6))MB" -NoNewline
    Write-Host " │ " -NoNewline
    Write-Host "$($stat.TokenDelta)" -NoNewline
    Write-Host ""
}

# Phase 4: Load Test (optional)
if ($LoadTest) {
    Write-Host "`nPHASE 4: Load Test" -ForegroundColor Yellow
    Write-Host "  Sending synthetic load..." -ForegroundColor Gray
    
    $loadTestTokens = 100
    $loadTestStart = Get-Date
    
    for ($i = 0; $i -lt $loadTestTokens; $i++) {
        # Simulate token generation
        $headNode = $targetNodes | Where-Object { $_.Role -eq "HEAD" }
        if ($headNode) {
            try {
                Invoke-WebRequest -Uri "http://$($headNode.IP):$($headNode.Port)/generate" -Method POST -Body "token=$i" -TimeoutSec 1 -ErrorAction SilentlyContinue | Out-Null
            } catch {}
        }
        
        if ($i % 10 -eq 0) {
            Write-Progress -Activity "Load Test" -Status "$i/$loadTestTokens tokens" -PercentComplete (($i / $loadTestTokens) * 100)
        }
    }
    
    Write-Progress -Activity "Load Test" -Completed
    
    $loadTestEnd = Get-Date
    $loadTestDuration = ($loadTestEnd - $loadTestStart).TotalSeconds
    $tps = $loadTestTokens / $loadTestDuration
    
    Write-Host "  Load test complete: $loadTestTokens tokens in ${loadTestDuration:N2}s ($([math]::Round($tps,1)) TPS)" -ForegroundColor Green
}

# Final Assessment
Write-Host "`n╔══════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║                    VALIDATION RESULTS                                          ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan

$avgUptime = ($nodeStats | Measure-Object -Property Uptime -Average).Average
$avgLatency = ($nodeStats | Measure-Object -Property AvgLatency -Average).Average
$maxLatency = ($nodeStats | Measure-Object -Property MaxLatency -Maximum).Maximum

Write-Host "`nAggregate Metrics:" -ForegroundColor White
Write-Host "  Average Uptime:    $([math]::Round($avgUptime, 1))%" -ForegroundColor $(if ($avgUptime -gt 95) { "Green" } else { "Yellow" })
Write-Host "  Average Latency:   $([math]::Round($avgLatency, 2)) ms" -ForegroundColor $(if ($avgLatency -lt 50) { "Green" } elseif ($avgLatency -lt 200) { "Yellow" } else { "Red" })
Write-Host "  Maximum Latency:   $([math]::Round($maxLatency, 2)) ms" -ForegroundColor $(if ($maxLatency -lt 100) { "Green" } elseif ($maxLatency -lt 500) { "Yellow" } else { "Red" })
Write-Host "  Total Tokens:      $(($nodeStats | Measure-Object -Property TokenDelta -Sum).Sum)" -ForegroundColor White

# Pass/Fail criteria
$passed = ($avgUptime -gt 95) -and ($avgLatency -lt 200) -and ($maxLatency -lt 500)

Write-Host "`n========================================" -ForegroundColor $(if ($passed) { "Green" } else { "Yellow" })
Write-Host "VALIDATION $(if ($passed) { 'PASSED ✅' } else { 'FAILED ❌' })" -ForegroundColor $(if ($passed) { "Green" } else { "Yellow" })
Write-Host "========================================" -ForegroundColor $(if ($passed) { "Green" } else { "Yellow" })

if ($passed) {
    Write-Host "`n✅ Stage $Stage is healthy and ready for next stage!" -ForegroundColor Green
    if ($Stage -lt 4) {
        Write-Host "  Proceed: .\deploy_canary.ps1 -Stage $($Stage+1)" -ForegroundColor Cyan
    }
} else {
    Write-Host "`n⚠️  Stage $Stage showing issues. Consider:" -ForegroundColor Yellow
    Write-Host "  1. Review logs: Get-Content \\$($targetNodes[0].IP)\C`$\Sovereign\logs\sovereign.log" -ForegroundColor Gray
    Write-Host "  2. Rollback: .\rollback_canary.ps1 -Stage $Stage" -ForegroundColor Red
    Write-Host "  3. Investigate before proceeding" -ForegroundColor Gray
}