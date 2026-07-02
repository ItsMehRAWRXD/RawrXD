# RawrXD Local Cluster Quick Start
# Launches 3-node SuperNode cluster on localhost for testing

param(
    [int]$NodeCount = 3,
    [int]$BasePort = 9001,
    [switch]$WithHAProxy = $true,
    [switch]$WithChaos = $false
)

$ErrorActionPreference = "Stop"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "RawrXD Local Cluster Quick Start" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Check if binaries exist
$SuperNodeExe = ".\build-supernode\bin\sovereign_super_node.exe"
if (-not (Test-Path $SuperNodeExe)) {
    $SuperNodeExe = ".\bin\sovereign_super_node.exe"
}

if (-not (Test-Path $SuperNodeExe)) {
    Write-Error "SuperNode executable not found. Build the project first."
    exit 1
}

Write-Host "Using SuperNode: $SuperNodeExe" -ForegroundColor Gray

# Kill any existing cluster nodes
Write-Host "`nCleaning up existing processes..." -ForegroundColor Yellow
Get-Process | Where-Object { $_.ProcessName -like "*super_node*" -or $_.ProcessName -like "*haproxy*" } | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

# Start cluster nodes
$Nodes = @()
for ($i = 0; $i -lt $NodeCount; $i++) {
    $port = $BasePort + $i
    $nodeId = $i
    
    Write-Host "Starting Node $nodeId on port $port..." -NoNewline
    
    $proc = Start-Process -FilePath $SuperNodeExe -ArgumentList @(
        "--node-id", $nodeId,
        "--port", $port,
        "--workers", "4",
        "--arena-size", "2147483648"
    ) -PassThru -WindowStyle Hidden
    
    $Nodes += @{
        Id = $nodeId
        Port = $port
        Process = $proc
        PID = $proc.Id
    }
    
    Write-Host " ✅ PID $($proc.Id)" -ForegroundColor Green
    Start-Sleep -Milliseconds 500
}

# Wait for nodes to be ready
Write-Host "`nWaiting for nodes to be ready..." -ForegroundColor Yellow
$readyCount = 0
$maxWait = 30
$waited = 0

while ($readyCount -lt $NodeCount -and $waited -lt $maxWait) {
    $readyCount = 0
    foreach ($node in $Nodes) {
        try {
            $response = Invoke-WebRequest -Uri "http://127.0.0.1:$($node.Port)/health" -TimeoutSec 1 -UseBasicParsing -ErrorAction SilentlyContinue
            if ($response.StatusCode -eq 200) {
                $readyCount++
            }
        } catch {}
    }
    
    if ($readyCount -lt $NodeCount) {
        Write-Host "  $readyCount/$NodeCount nodes ready..." -ForegroundColor Gray
        Start-Sleep -Seconds 1
        $waited++
    }
}

if ($readyCount -eq $NodeCount) {
    Write-Host "`n✅ All $NodeCount nodes are ready!" -ForegroundColor Green
} else {
    Write-Warning "Only $readyCount/$NodeCount nodes ready after ${maxWait}s"
}

# Display cluster info
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Cluster Status" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

foreach ($node in $Nodes) {
    $status = if ($node.Process.HasExited) { "EXITED" } else { "RUNNING" }
    Write-Host "Node $($node.Id): http://127.0.0.1:$($node.Port) (PID: $($node.PID), $status)"
}

Write-Host "`nHealth Check URLs:" -ForegroundColor Yellow
foreach ($node in $Nodes) {
    Write-Host "  http://127.0.0.1:$($node.Port)/health"
}

Write-Host "`nMetrics URLs:" -ForegroundColor Yellow
foreach ($node in $Nodes) {
    Write-Host "  http://127.0.0.1:$($node.Port)/metrics"
}

# Save node info for chaos tests
$clusterInfo = @{
    nodes = $Nodes | ForEach-Object { @{ id = $_.Id; port = $_.Port; pid = $_.PID } }
    basePort = $BasePort
    nodeCount = $NodeCount
    startedAt = Get-Date -Format "o"
}

$clusterInfo | ConvertTo-Json | Set-Content ".cluster_info.json"
Write-Host "`nCluster info saved to .cluster_info.json" -ForegroundColor Gray

# Launch HAProxy if requested
if ($WithHAProxy) {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Starting HAProxy Load Balancer" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    
    $haproxyConfig = @"
global
    daemon
    maxconn 4096

defaults
    mode http
    timeout connect 5s
    timeout client 30s
    timeout server 30s

frontend rawrxd_frontend
    bind *:8080
    default_backend rawrxd_backend

backend rawrxd_backend
    balance roundrobin
    option httpchk GET /health
"@

    for ($i = 0; $i -lt $NodeCount; $i++) {
        $port = $BasePort + $i
        $haproxyConfig += "    server node$i 127.0.0.1:$port check`n"
    }
    
    $haproxyConfig | Set-Content "haproxy.cfg"
    
    # Check for haproxy
    $haproxyPath = "C:\Program Files\haproxy\haproxy.exe"
    if (Test-Path $haproxyPath) {
        Start-Process -FilePath $haproxyPath -ArgumentList "-f", "haproxy.cfg" -WindowStyle Hidden
        Write-Host "HAProxy started on http://localhost:8080" -ForegroundColor Green
        Write-Host "  Stats: http://localhost:8080/stats" -ForegroundColor Gray
    } else {
        Write-Warning "HAProxy not found at $haproxyPath"
        Write-Host "Install HAProxy or use direct node URLs" -ForegroundColor Yellow
    }
}

# Launch chaos tests if requested
if ($WithChaos) {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Starting Chaos Engineering Tests" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    
    Start-Sleep -Seconds 3
    
    $chaosArgs = @{
        ClusterEndpoint = "http://localhost:8080"
        Scenario = "all"
        DurationSeconds = 30
        Intensity = 25
        Report = $true
    }
    
    & "..\chaos-tests\chaos-test-suite.ps1" @chaosArgs
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Cluster is running! Press Ctrl+C to stop" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# Keep script running until interrupted
try {
    while ($true) {
        Start-Sleep -Seconds 5
        
        # Check if any node died
        $aliveCount = 0
        foreach ($node in $Nodes) {
            if (-not $node.Process.HasExited) {
                $aliveCount++
            }
        }
        
        if ($aliveCount -eq 0) {
            Write-Host "`n⚠️  All nodes have exited" -ForegroundColor Yellow
            break
        }
        
        Write-Host "$(Get-Date -Format 'HH:mm:ss') | Nodes: $aliveCount/$NodeCount | Running..." -NoNewline
        Write-Host "`r" -NoNewline
    }
} finally {
    Write-Host "`n`nShutting down cluster..." -ForegroundColor Yellow
    
    foreach ($node in $Nodes) {
        if (-not $node.Process.HasExited) {
            Stop-Process -Id $node.PID -Force -ErrorAction SilentlyContinue
            Write-Host "Stopped Node $($node.Id) (PID: $($node.PID))" -ForegroundColor Gray
        }
    }
    
    Get-Process haproxy -ErrorAction SilentlyContinue | Stop-Process -Force
    
    Remove-Item ".cluster_info.json" -ErrorAction SilentlyContinue
    Remove-Item "haproxy.cfg" -ErrorAction SilentlyContinue
    
    Write-Host "`n✅ Cluster stopped" -ForegroundColor Green
}
