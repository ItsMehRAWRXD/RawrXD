# Gate 077: Systematic proxy stress test
# Start sustained streaming generation on candidate port 11437
Write-Host "Starting streaming generation on 11437..."
$body = @"
{"model":"reap16-glm-4_7-flash:latest","messages":[{"role":"user","content":"Sustained stress test with 20 polls"}],"stream":true}
"@
curl.exe --noproxy "*" -s -d $body -o /tmp/stream_stress_full.txt http://127.0.0.1:11437/v1/chat/completions &
Write-Host "Streaming generation started in background"

Write-Host "Beginning 20-poll interval over 20 seconds (1 poll per second)`n"

# Initialize results array
$results = @()
$i = 0
while ($i -lt 20) {
    $i++
    # Poll /v1/models
    $curlResp = curl.exe --noproxy "*" -s -w "%{http_code} %{time_total}s" http://127.0.0.1:11437/v1/models
    # Parse HTTP code and latency from curl output
    # Format: "HTTP_CODE TIME_IN_SECONDS"
    $parts = $curlResp -split " "
    $httpCode = $parts[0]
    $latencySec = $parts[1]
    # Convert to milliseconds
    $latencyMs = [math]::Round($latencySec * 1000)
    # Get timestamp
    $timestamp = (Get-Date).ToString("o")
    # Record result
    $results += [pscustomobject]@{
        poll = $i
        http_code = $httpCode
        latency_ms = $latencyMs
        timestamp = $timestamp
    }
    Write-Host "Poll $i: HTTP=$httpCode Latency=${latencyMs}ms @ $timestamp"
    # Sleep 1 second before next poll
    Start-Sleep -Seconds 1
}

# Compute statistics
$validResults = $results | Where-Object { $_.latency_ms -gt 0 }
$count = $validResults.Count
if ($count -gt 0) {
    $sorted = $validResults.latency_ms | Sort-Object
    $p50Idx = [math]::Floor($count * 0.5)
    $p95Idx = [math]::Floor($count * 0.95)
    $p50 = $sorted[$p50Idx]
    $p95 = $sorted[$p95Idx]
    $max = ($sorted | Measure-Object -Maximum).Maximum
    $failures = ($results | Where-Object { $_.http_code -ne 200 }).Count
    $successes = $count - $failures
    Write-Host "`n=== Systematic Stress Statistics ===="
    Write-Host "Polls attempted: 20"
    Write-Host "Polls with valid latency: $count"
    Write-Host "P50 latency: $p50 ms"
    Write-Host "P95 latency: $p95 ms"
    Write-Host "Max latency: $max ms"
    Write-Host "HTTP failures (non-200): $failures"
    Write-Host "Successful (HTTP 200): $successes"
    Write-Host "`n=== Per-Poll Detail ===="
    $results | Format-Table poll http_code latency_ms timestamp -AutoSize
} else {
    Write-Host "`nNo valid latency measurements recorded across 20 polls."
    $results | Format-Table poll http_code latency_ms timestamp -AutoSize
}
Write-Host "`n=== Process State ===="
tasklist | findstr rawrxd_ollama_proxy