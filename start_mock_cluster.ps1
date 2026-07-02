# RawrXD Mock Cluster for Testing
# Simulates SuperNode cluster HTTP endpoints for integration testing

param(
    [int]$NodeCount = 3,
    [int]$BasePort = 9001,
    [int]$DurationMinutes = 10
)

$ErrorActionPreference = "Stop"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "RawrXD Mock Cluster (Testing Mode)" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Node simulation using PowerShell HTTP listeners
$script:Nodes = @()
$script:Running = $true
$script:Metrics = @{}

function Start-MockNode {
    param($NodeId, $Port)
    
    $listener = [System.Net.HttpListener]::new()
    $listener.Prefixes.Add("http://127.0.0.1:$Port/")
    
    try {
        $listener.Start()
        Write-Host "Node $NodeId listening on http://127.0.0.1:$Port" -ForegroundColor Green
        
        # Initialize metrics
        $script:Metrics[$NodeId] = @{
            tokens_processed = 0
            requests_served = 0
            start_time = Get-Date
            tps = 0
        }
        
        # Process requests asynchronously
        $runspace = [runspacefactory]::CreateRunspace()
        $runspace.Open()
        
        $powershell = [powershell]::Create()
        $powershell.Runspace = $runspace
        
        $powershell.AddScript({
            param($listener, $nodeId, $metrics)
            
            while ($listener.IsListening) {
                try {
                    $context = $listener.GetContext()
                    $request = $context.Request
                    $response = $context.Response
                    
                    $path = $request.Url.AbsolutePath
                    $method = $request.HttpMethod
                    
                    switch ($path) {
                        "/health" {
                            $health = @{
                                status = "healthy"
                                node_id = $nodeId
                                uptime_seconds = ((Get-Date) - $metrics[$nodeId].start_time).TotalSeconds
                                timestamp = Get-Date -Format "o"
                            } | ConvertTo-Json
                            
                            $buffer = [System.Text.Encoding]::UTF8.GetBytes($health)
                            $response.ContentType = "application/json"
                            $response.ContentLength64 = $buffer.Length
                            $response.OutputStream.Write($buffer, 0, $buffer.Length)
                            $metrics[$nodeId].requests_served++
                        }
                        
                        "/metrics" {
                            # Simulate TPS
                            $elapsed = ((Get-Date) - $metrics[$nodeId].start_time).TotalSeconds
                            if ($elapsed -gt 0) {
                                $metrics[$nodeId].tps = [math]::Round($metrics[$nodeId].tokens_processed / $elapsed, 2)
                            }
                            
                            $prometheus = @"
# HELP sovereign_tokens_processed Total tokens processed
# TYPE sovereign_tokens_processed counter
sovereign_tokens_processed{node="$nodeId"} $($metrics[$nodeId].tokens_processed)

# HELP sovereign_requests_total Total requests served
# TYPE sovereign_requests_total counter
sovereign_requests_total{node="$nodeId"} $($metrics[$nodeId].requests_served)

# HELP sovereign_tps_current Current tokens per second
# TYPE sovereign_tps_current gauge
sovereign_tps_current{node="$nodeId"} $($metrics[$nodeId].tps)
"@
                            
                            $buffer = [System.Text.Encoding]::UTF8.GetBytes($prometheus)
                            $response.ContentType = "text/plain"
                            $response.ContentLength64 = $buffer.Length
                            $response.OutputStream.Write($buffer, 0, $buffer.Length)
                        }
                        
                        "/v1/completions" {
                            if ($method -eq "POST") {
                                # Simulate completion processing
                                Start-Sleep -Milliseconds (Get-Random -Minimum 10 -Maximum 50)
                                
                                $completion = @{
                                    jsonrpc = "2.0"
                                    id = 1
                                    result = @{
                                        items = @(
                                            @{ label = "function"; insertText = "function"; score = 0.95; kind = "function" },
                                            @{ label = "for"; insertText = "for"; score = 0.87; kind = "keyword" },
                                            @{ label = "if"; insertText = "if"; score = 0.82; kind = "keyword" }
                                        )
                                    }
                                } | ConvertTo-Json -Depth 10
                                
                                $buffer = [System.Text.Encoding]::UTF8.GetBytes($completion)
                                $response.ContentType = "application/json"
                                $response.ContentLength64 = $buffer.Length
                                $response.OutputStream.Write($buffer, 0, $buffer.Length)
                                
                                $metrics[$nodeId].tokens_processed += 3
                                $metrics[$nodeId].requests_served++
                            }
                        }
                        
                        default {
                            $response.StatusCode = 404
                            $message = "Not Found"
                            $buffer = [System.Text.Encoding]::UTF8.GetBytes($message)
                            $response.ContentLength64 = $buffer.Length
                            $response.OutputStream.Write($buffer, 0, $buffer.Length)
                        }
                    }
                    
                    $response.OutputStream.Close()
                } catch {
                    # Listener stopped
                    break
                }
            }
        }).AddArgument($listener).AddArgument($NodeId).AddArgument($script:Metrics)
        
        $handle = $powershell.BeginInvoke()
        
        return @{
            Id = $NodeId
            Port = $Port
            Listener = $listener
            PowerShell = $powershell
            Handle = $handle
            Runspace = $runspace
        }
    } catch {
        Write-Error "Failed to start Node $NodeId on port $Port`: $_"
        return $null
    }
}

# Start nodes
Write-Host "Starting $NodeCount mock nodes..." -ForegroundColor Yellow
for ($i = 0; $i -lt $NodeCount; $i++) {
    $port = $BasePort + $i
    $node = Start-MockNode -NodeId $i -Port $port
    if ($node) {
        $script:Nodes += $node
    }
    Start-Sleep -Milliseconds 100
}

if ($script:Nodes.Count -eq 0) {
    Write-Error "Failed to start any nodes"
    exit 1
}

Write-Host "`n✅ All $($script:Nodes.Count) nodes started!" -ForegroundColor Green

# Display cluster info
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Cluster Status" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

foreach ($node in $script:Nodes) {
    Write-Host "Node $($node.Id): http://127.0.0.1:$($node.Port)"
    Write-Host "  Health: http://127.0.0.1:$($node.Port)/health"
    Write-Host "  Metrics: http://127.0.0.1:$($node.Port)/metrics"
    Write-Host "  Completions: http://127.0.0.1:$($node.Port)/v1/completions"
}

# Save cluster info
$clusterInfo = @{
    nodes = $script:Nodes | ForEach-Object { @{ id = $_.Id; port = $_.Port } }
    basePort = $BasePort
    nodeCount = $script:Nodes.Count
    startedAt = Get-Date -Format "o"
    mode = "mock"
}

$clusterInfo | ConvertTo-Json | Set-Content ".cluster_info.json"
Write-Host "`nCluster info saved to .cluster_info.json" -ForegroundColor Gray

# Keep running until interrupted
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Mock cluster is running!" -ForegroundColor Cyan
Write-Host "Press Ctrl+C to stop" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# Simulate TPS updates
$endTime = (Get-Date).AddMinutes($DurationMinutes)

try {
    while ((Get-Date) -lt $endTime -and $script:Running) {
        Start-Sleep -Seconds 5
        
        $totalTps = 0
        $totalRequests = 0
        
        foreach ($node in $script:Nodes) {
            if ($script:Metrics[$node.Id]) {
                $totalTps += $script:Metrics[$node.Id].tps
                $totalRequests += $script:Metrics[$node.Id].requests_served
            }
        }
        
        Write-Host "$(Get-Date -Format 'HH:mm:ss') | Nodes: $($script:Nodes.Count) | TPS: $([math]::Round($totalTps, 0)) | Requests: $totalRequests | Running..." -NoNewline
        Write-Host "`r" -NoNewline
    }
} finally {
    Write-Host "`n`nShutting down mock cluster..." -ForegroundColor Yellow
    
    $script:Running = $false
    
    foreach ($node in $script:Nodes) {
        try {
            $node.Listener.Stop()
            $node.Listener.Close()
            
            if ($node.PowerShell) {
                $node.PowerShell.Stop()
                $node.PowerShell.Dispose()
            }
            
            if ($node.Runspace) {
                $node.Runspace.Close()
                $node.Runspace.Dispose()
            }
            
            Write-Host "Stopped Node $($node.Id)" -ForegroundColor Gray
        } catch {
            Write-Host "Error stopping Node $($node.Id): $_" -ForegroundColor Red
        }
    }
    
    Remove-Item ".cluster_info.json" -ErrorAction SilentlyContinue
    
    Write-Host "`n✅ Mock cluster stopped" -ForegroundColor Green
}
