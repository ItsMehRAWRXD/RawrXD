# RawrXD Mock Cluster Server
# Simple HTTP server for testing chaos engineering and extension integration

param(
    [int]$Port = 8080,
    [int]$NodeCount = 3,
    [switch]$ChaosMode = $false
)

$ErrorActionPreference = "Stop"

Add-Type -AssemblyName System.Net.Http
Add-Type -AssemblyName System.Web

Write-Host "RawrXD Mock Cluster Server" -ForegroundColor Cyan
Write-Host "=========================" -ForegroundColor Cyan
Write-Host "Port: $Port"
Write-Host "Simulated Nodes: $NodeCount"
Write-Host "Chaos Mode: $ChaosMode`n"

# State
$script:RequestCount = 0
$script:StartTime = Get-Date
$script:Healthy = $true
$script:LatencyMs = 50
$script:Tps = 7234
$script:Nodes = @()

for ($i = 0; $i -lt $NodeCount; $i++) {
    $script:Nodes += @{
        Id = $i
        Status = "UP"
        Port = 9001 + $i
        TPS = [math]::Floor(7234 / $NodeCount)
    }
}

# HTTP Listener
$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add("http://localhost:$Port/")
$listener.Start()

Write-Host "Server started on http://localhost:$Port" -ForegroundColor Green
Write-Host "Press Ctrl+C to stop`n" -ForegroundColor Yellow

# Request handler
function Handle-Request($context) {
    $request = $context.Request
    $response = $context.Response
    $url = $request.Url.LocalPath
    $method = $request.HttpMethod
    
    $script:RequestCount++
    
    # Simulate latency
    if ($script:LatencyMs -gt 0) {
        Start-Sleep -Milliseconds $script:LatencyMs
    }
    
    # Chaos mode: randomly fail requests
    if ($ChaosMode -and (Get-Random -Maximum 100) -lt 10) {
        $response.StatusCode = 503
        $response.Close()
        return
    }
    
    switch ($url) {
        "/health" {
            $status = if ($script:Healthy) { "healthy" } else { "unhealthy" }
            $body = @{
                status = $status
                nodes = $script:Nodes.Count
                uptime = ((Get-Date) - $script:StartTime).TotalSeconds
                requests = $script:RequestCount
            } | ConvertTo-Json
            
            $buffer = [System.Text.Encoding]::UTF8.GetBytes($body)
            $response.ContentType = "application/json"
            $response.ContentLength64 = $buffer.Length
            $response.OutputStream.Write($buffer, 0, $buffer.Length)
        }
        
        "/metrics" {
            $body = @"
# RawrXD Mock Metrics
rawrxd_nodes_total $($script:Nodes.Count)
rawrxd_tps_current $script:Tps
rawrxd_latency_ms $script:LatencyMs
rawrxd_requests_total $script:RequestCount
"@
            $buffer = [System.Text.Encoding]::UTF8.GetBytes($body)
            $response.ContentType = "text/plain"
            $response.ContentLength64 = $buffer.Length
            $response.OutputStream.Write($buffer, 0, $buffer.Length)
        }
        
        "/v1/completions" {
            if ($method -eq "POST") {
                # Parse request
                $reader = New-Object System.IO.StreamReader($request.InputStream)
                $json = $reader.ReadToEnd()
                $reader.Close()
                
                # Generate mock completion
                $completion = @{
                    jsonrpc = "2.0"
                    id = 1
                    result = @{
                        items = @(
                            @{
                                label = "def process_data"
                                insertText = "def process_data(data):`n    return data"
                                kind = "function"
                                score = 0.95
                            },
                            @{
                                label = "def validate_input"
                                insertText = "def validate_input(input):`n    return True"
                                kind = "function"
                                score = 0.87
                            },
                            @{
                                label = "class DataProcessor"
                                insertText = "class DataProcessor:`n    def __init__(self):`n        pass"
                                kind = "class"
                                score = 0.82
                            }
                        )
                    }
                } | ConvertTo-Json -Depth 10
                
                $buffer = [System.Text.Encoding]::UTF8.GetBytes($completion)
                $response.ContentType = "application/json"
                $response.ContentLength64 = $buffer.Length
                $response.OutputStream.Write($buffer, 0, $buffer.Length)
            } else {
                $response.StatusCode = 405
            }
        }
        
        "/stats" {
            $body = @{
                nodes = $script:Nodes
                total_tps = $script:Tps
                avg_latency = $script:LatencyMs
            } | ConvertTo-Json
            
            $buffer = [System.Text.Encoding]::UTF8.GetBytes($body)
            $response.ContentType = "application/json"
            $response.ContentLength64 = $buffer.Length
            $response.OutputStream.Write($buffer, 0, $buffer.Length)
        }
        
        default {
            $response.StatusCode = 404
            $body = '{"error": "Not found"}'
            $buffer = [System.Text.Encoding]::UTF8.GetBytes($body)
            $response.ContentType = "application/json"
            $response.ContentLength64 = $buffer.Length
            $response.OutputStream.Write($buffer, 0, $buffer.Length)
        }
    }
    
    $response.Close()
}

# Control endpoint
function Show-Status {
    Write-Host "`n$(Get-Date -Format 'HH:mm:ss') | Requests: $script:RequestCount | TPS: $script:Tps | Latency: $script:LatencyMs`ms | Nodes: $($script:Nodes.Count)" -NoNewline
    Write-Host "`r" -NoNewline
}

# Main loop
try {
    while ($listener.IsListening) {
        $task = $listener.GetContextAsync()
        while (-not $task.IsCompleted) {
            Start-Sleep -Milliseconds 100
            if ($script:RequestCount % 10 -eq 0) {
                Show-Status
            }
        }
        
        Handle-Request $task.Result
    }
} finally {
    $listener.Stop()
    Write-Host "`n`nServer stopped" -ForegroundColor Yellow
}
