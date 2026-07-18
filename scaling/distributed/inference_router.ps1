# RawrXD Distributed Inference Router
# Phase L.3 - Distributed Model Serving
# Routes inference requests to appropriate shards across cluster

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [int]$ListenPort = 8080,

    [Parameter(Mandatory=$false)]
    [string[]]$BackendNodes = @("192.168.1.10:8080", "192.168.1.11:8080"),

    [Parameter(Mandatory=$false)]
    [ValidateSet("roundrobin", "leastloaded", "latency", "affinity")]
    [string]$RoutingStrategy = "leastloaded",

    [Parameter(Mandatory=$false)]
    [switch]$StartServer
)

$ErrorActionPreference = "Stop"

# Router state
$script:RouterState = @{
    Nodes = @{}
    RequestCount = 0
    Strategy = $RoutingStrategy
    LastRotation = 0
    ShardCache = @{}
}

# Logging
function Write-RouterLog {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $colors = @{ "INFO" = "White"; "SUCCESS" = "Green"; "WARNING" = "Yellow"; "ERROR" = "Red"; "DEBUG" = "Gray" }
    Write-Host "[$timestamp] [ROUTER] [$Level] $Message" -ForegroundColor $colors[$Level]
}

# Node health and metrics tracking
class RouterNode {
    [string]$Address
    [string]$Status
    [hashtable]$Metrics
    [int]$CurrentLoad
    [double]$AvgLatency
    [DateTime]$LastUpdate
    [int]$RequestCount
    [hashtable]$ShardInfo

    RouterNode([string]$address) {
        $this.Address = $address
        $this.Status = "unknown"
        $this.Metrics = @{}
        $this.CurrentLoad = 0
        $this.AvgLatency = 0
        $this.LastUpdate = [DateTime]::MinValue
        $this.RequestCount = 0
        $this.ShardInfo = @{}
    }

    [void] UpdateMetrics([hashtable]$newMetrics) {
        $this.Metrics = $newMetrics
        $this.CurrentLoad = $newMetrics.active_requests
        $this.AvgLatency = $newMetrics.avg_latency_ms
        $this.LastUpdate = Get-Date
    }

    [bool] IsHealthy() {
        return $this.Status -eq "healthy" -and (Get-Date) - $this.LastUpdate -lt [TimeSpan]::FromSeconds(30)
    }

    [double] GetScore() {
        # Lower score = better candidate
        $loadScore = $this.CurrentLoad * 10
        $latencyScore = $this.AvgLatency
        $healthPenalty = if ($this.IsHealthy()) { 0 } else { 10000 }
        return $loadScore + $latencyScore + $healthPenalty
    }
}

# Health check all nodes
function Update-NodeHealth {
    param([string[]]$Nodes)

    foreach ($nodeAddr in $Nodes) {
        if (!$script:RouterState.Nodes[$nodeAddr]) {
            $script:RouterState.Nodes[$nodeAddr] = [RouterNode]::new($nodeAddr)
        }

        $node = $script:RouterState.Nodes[$nodeAddr]

        try {
            $startTime = Get-Date
            $response = Invoke-WebRequest -Uri "http://$nodeAddr/health" -TimeoutSec 5
            $latency = ((Get-Date) - $startTime).TotalMilliseconds

            if ($response.StatusCode -eq 200) {
                $healthData = $response.Content | ConvertFrom-Json

                $node.UpdateMetrics(@{
                    tps = $healthData.tps
                    active_requests = $healthData.active_requests
                    avg_latency_ms = $latency
                    memory_percent = $healthData.memory_percent
                    gpu_percent = $healthData.gpu_percent
                })

                $node.Status = "healthy"
            } else {
                $node.Status = "degraded"
            }
        } catch {
            $node.Status = "unhealthy"
        }
    }
}

# Select best node based on routing strategy
function Select-TargetNode {
    param(
        [string]$ModelName = "",
        [int]$TokenCount = 0
    )

    $healthyNodes = $script:RouterState.Nodes.Values | Where-Object { $_.IsHealthy() }

    if ($healthyNodes.Count -eq 0) {
        Write-RouterLog "No healthy nodes available!" "ERROR"
        return $null
    }

    switch ($script:RouterState.Strategy) {
        "roundrobin" {
            $nodes = $healthyNodes | Sort-Object Address
            $index = $script:RouterState.LastRotation % $nodes.Count
            $script:RouterState.LastRotation++
            return $nodes[$index]
        }
        "leastloaded" {
            return $healthyNodes | Sort-Object CurrentLoad | Select-Object -First 1
        }
        "latency" {
            return $healthyNodes | Sort-Object AvgLatency | Select-Object -First 1
        }
        "affinity" {
            # Route to node that has the model shards loaded
            if ($ModelName -and $script:RouterState.ShardCache[$ModelName]) {
                $preferredNodes = $script:RouterState.ShardCache[$ModelName]
                $available = $healthyNodes | Where-Object { $preferredNodes -contains $_.Address }
                if ($available) {
                    return $available | Sort-Object CurrentLoad | Select-Object -First 1
                }
            }
            return $healthyNodes | Sort-Object CurrentLoad | Select-Object -First 1
        }
        default {
            return $healthyNodes | Get-Random
        }
    }
}

# Route inference request
function Route-InferenceRequest {
    param(
        [hashtable]$Request,
        [string]$ModelName = ""
    )

    $script:RouterState.RequestCount++
    $requestId = [Guid]::NewGuid().ToString()

    Write-RouterLog "Request $requestId - Routing inference request" "DEBUG"

    # Select target node
    $targetNode = Select-TargetNode -ModelName $ModelName -TokenCount $Request.max_tokens

    if (!$targetNode) {
        return @{
            error = "No healthy nodes available"
            request_id = $requestId
            timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
        }
    }

    Write-RouterLog "Request $requestId - Routed to $($targetNode.Address)" "INFO"

    try {
        $startTime = Get-Date

        # Forward request
        $response = Invoke-WebRequest -Uri "http://$($targetNode.Address)/v1/completions" -Method POST -Body ($Request | ConvertTo-Json -Depth 10) -ContentType "application/json" -TimeoutSec 300

        $latency = ((Get-Date) - $startTime).TotalMilliseconds
        $targetNode.RequestCount++

        Write-RouterLog "Request $requestId - Completed in $([math]::Round($latency, 2))ms" "SUCCESS"

        return @{
            request_id = $requestId
            node = $targetNode.Address
            latency_ms = $latency
            response = $response.Content | ConvertFrom-Json
        }
    } catch {
        Write-RouterLog "Request $requestId - Failed: $($_.Exception.Message)" "ERROR"

        # Try failover to another node
        $failoverNode = $script:RouterState.Nodes.Values | Where-Object { $_.IsHealthy() -and $_.Address -ne $targetNode.Address } | Select-Object -First 1

        if ($failoverNode) {
            Write-RouterLog "Request $requestId - Failover to $($failoverNode.Address)" "WARNING"

            try {
                $response = Invoke-WebRequest -Uri "http://$($failoverNode.Address)/v1/completions" -Method POST -Body ($Request | ConvertTo-Json -Depth 10) -ContentType "application/json" -TimeoutSec 300

                return @{
                    request_id = $requestId
                    node = $failoverNode.Address
                    failover = $true
                    original_node = $targetNode.Address
                    response = $response.Content | ConvertFrom-Json
                }
            } catch {
                return @{
                    error = "Request failed on primary and failover nodes"
                    request_id = $requestId
                    primary_error = $_.Exception.Message
                    timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
                }
            }
        }

        return @{
            error = "Request failed: $($_.Exception.Message)"
            request_id = $requestId
            timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
        }
    }
}

# Start HTTP listener for router
function Start-RouterServer {
    param([int]$Port)

    $listener = [System.Net.HttpListener]::new()
    $listener.Prefixes.Add("http://+:$Port/")
    $listener.Start()

    Write-RouterLog "Router server started on port $Port" "SUCCESS"
    Write-RouterLog "Routing strategy: $($script:RouterState.Strategy)" "INFO"
    Write-RouterLog "Backend nodes: $($BackendNodes -join ', ')" "INFO"

    # Start health check loop in background
    $healthCheckJob = Start-Job -ScriptBlock {
        param($Nodes)
        while ($true) {
            Update-NodeHealth -Nodes $Nodes
            Start-Sleep -Seconds 5
        }
    } -ArgumentList $BackendNodes

    try {
        while ($listener.IsListening) {
            $context = $listener.GetContext()
            $request = $context.Request
            $response = $context.Response

            $path = $request.Url.LocalPath
            $method = $request.Method

            Write-RouterLog "$method $path from $($request.RemoteEndPoint)" "DEBUG"

            $responseData = $null
            $statusCode = 200

            switch ($path) {
                "/health" {
                    $healthyCount = ($script:RouterState.Nodes.Values | Where-Object { $_.IsHealthy() }).Count
                    $responseData = @{
                        status = if ($healthyCount -gt 0) { "healthy" } else { "degraded" }
                        nodes_total = $script:RouterState.Nodes.Count
                        nodes_healthy = $healthyCount
                        strategy = $script:RouterState.Strategy
                        requests_served = $script:RouterState.RequestCount
                    } | ConvertTo-Json
                }
                "/v1/completions" {
                    if ($method -eq "POST") {
                        $reader = [System.IO.StreamReader]::new($request.InputStream)
                        $body = $reader.ReadToEnd()
                        $reader.Close()

                        $requestData = $body | ConvertFrom-Json
                        $modelName = $requestData.model

                        $result = Route-InferenceRequest -Request $requestData -ModelName $modelName
                        $responseData = $result | ConvertTo-Json -Depth 10

                        if ($result.error) {
                            $statusCode = 503
                        }
                    } else {
                        $statusCode = 405
                        $responseData = '{"error": "Method not allowed"}'
                    }
                }
                "/admin/nodes" {
                    $nodes = $script:RouterState.Nodes.Values | ForEach-Object {
                        @{
                            address = $_.Address
                            status = $_.Status
                            load = $_.CurrentLoad
                            latency = $_.AvgLatency
                            requests = $_.RequestCount
                            last_update = $_.LastUpdate
                        }
                    }
                    $responseData = $nodes | ConvertTo-Json -Depth 10
                }
                "/admin/stats" {
                    $stats = @{
                        total_requests = $script:RouterState.RequestCount
                        strategy = $script:RouterState.Strategy
                        nodes = $script:RouterState.Nodes.Values | ForEach-Object {
                            @{
                                address = $_.Address
                                status = $_.Status
                                load = $_.CurrentLoad
                                latency = [math]::Round($_.AvgLatency, 2)
                                requests = $_.RequestCount
                            }
                        }
                    }
                    $responseData = $stats | ConvertTo-Json -Depth 10
                }
                default {
                    $statusCode = 404
                    $responseData = '{"error": "Not found"}'
                }
            }

            $buffer = [System.Text.Encoding]::UTF8.GetBytes($responseData)
            $response.ContentType = "application/json"
            $response.StatusCode = $statusCode
            $response.ContentLength64 = $buffer.Length
            $response.OutputStream.Write($buffer, 0, $buffer.Length)
            $response.OutputStream.Close()
        }
    } finally {
        $listener.Stop()
        Stop-Job $healthCheckJob
        Remove-Job $healthCheckJob
    }
}

# Main execution
if ($StartServer) {
    # Initial health check
    Write-RouterLog "Performing initial health check..." "INFO"
    Update-NodeHealth -Nodes $BackendNodes

    # Start server
    Start-RouterServer -Port $ListenPort
} else {
    Write-Host @"
RawrXD Distributed Inference Router
Usage:
  .\inference_router.ps1 -StartServer -ListenPort 8080 -BackendNodes @("node1:8080", "node2:8080") -RoutingStrategy leastloaded

Routing Strategies:
  roundrobin   - Distribute requests evenly across nodes
  leastloaded  - Route to node with lowest active request count
  latency      - Route to node with lowest average latency
  affinity     - Prefer nodes with model shards cached

Endpoints:
  POST /v1/completions    - Route inference request
  GET  /health            - Router health status
  GET  /admin/nodes       - Node status information
  GET  /admin/stats       - Routing statistics
"@ -ForegroundColor Cyan
}
