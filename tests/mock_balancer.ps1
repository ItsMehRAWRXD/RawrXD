#Requires -PSEdition Core
#Requires -Version 7.0
<#
.SYNOPSIS
    Mock RawrXD Balancer for Shadow Mode Testing
.DESCRIPTION
    Lightweight HTTP listener that simulates the RawrZ-MAX-Cluster balancer
    on port 12639. Returns synthetic headers for shadow mode validation.
    Does NOT require admin privileges (uses localhost only).
.NOTES
    Run this in a separate terminal before executing the smoke test.
    Press Ctrl+C to stop.
#>

param(
    [int]$Port = 12639,
    [int]$NodeCount = 3
)

$ErrorActionPreference = 'Stop'

# Simple TCP listener (no admin required for localhost)
$listener = [System.Net.HttpListener]::new()
$listener.Prefixes.Add("http://localhost:$Port/")

try {
    $listener.Start()
    Write-Host "Mock Balancer listening on http://localhost:$Port/" -ForegroundColor Green
    Write-Host "Press Ctrl+C to stop." -ForegroundColor Gray

    $requestCount = 0
    while ($listener.IsListening) {
        $context = $listener.GetContext()
        $request = $context.Request
        $response = $context.Response

        $requestCount++
        $timestamp = Get-Date -Format "HH:mm:ss.fff"

        if ($request.HttpMethod -eq 'POST' -and $request.RawUrl -eq '/v1/chat/completions') {
            # Read request body
            $reader = [System.IO.StreamReader]::new($request.InputStream)
            $body = $reader.ReadToEnd()
            $reader.Close()

            # Extract prompt for logging
            $json = $body | ConvertFrom-Json -ErrorAction SilentlyContinue
            $prompt = $json.messages[0].content
            Write-Host "[$timestamp] Req#$requestCount`: $prompt" -ForegroundColor Cyan

            # Simulate balancer response with synthetic headers
            $nodeId = "mock-node-$($requestCount % $NodeCount + 1)"
            $latency = Get-Random -Minimum 45 -Maximum 120

            $response.StatusCode = 200
            $response.ContentType = "application/json"

            # Add custom headers
            $response.Headers.Add("X-Rawr-Node-ID", $nodeId)
            $response.Headers.Add("X-Rawr-Balancer-Latency", "$latency")
            $response.Headers.Add("X-Rawr-Shadow-Id", $json.id ?? "shadow-$requestCount")

            # Synthetic response (balancer would return this)
            $respBody = @{
                id = "chatcmpl-mock-$requestCount"
                object = "chat.completion"
                created = [int][DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
                model = "mock-balancer"
                choices = @(@{
                    index = 0
                    message = @{
                        role = "assistant"
                        content = "[BALANCER] Response from $nodeId (latency: ${latency}ms)"
                    }
                    finish_reason = "stop"
                })
            } | ConvertTo-Json -Depth 5

            $buffer = [System.Text.Encoding]::UTF8.GetBytes($respBody)
            $response.ContentLength64 = $buffer.Length
            $response.OutputStream.Write($buffer, 0, $buffer.Length)
            $response.OutputStream.Close()

            Write-Host "  → $nodeId, ${latency}ms" -ForegroundColor Green
        } else {
            # Health check or unknown endpoint
            $response.StatusCode = 200
            $respBody = '{"status":"ok","mode":"mock-balancer"}'
            $buffer = [System.Text.Encoding]::UTF8.GetBytes($respBody)
            $response.ContentLength64 = $buffer.Length
            $response.OutputStream.Write($buffer, 0, $buffer.Length)
            $response.OutputStream.Close()
        }
    }
} catch {
    Write-Host "Error: $_" -ForegroundColor Red
} finally {
    $listener.Stop()
    $listener.Close()
    Write-Host "Mock Balancer stopped." -ForegroundColor Yellow
}
