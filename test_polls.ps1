# Run 20 polls during sustained streaming on candidate port 11437
# This tests Gate 077: Systematic proxy stress
Write-Host "Ensuring streaming generation active on 11437..."
# Quick streaming start to keep model loaded
$body = @"
{"model":"reap16-glm-4_7-flash:latest","messages":[{"role":"user","content":"keep warm"}],"stream":true}
"@
curl.exe --noproxy "*" -s -d $body http://127.0.0.1:11437/v1/chat/completions -o /dev/null 2>&1 &
Write-Host "Streaming started in background, running 20 polls..."
Start-Sleep -Seconds 1

# Run 20 polls with 1-second intervals
$i = 1
$validLatencies = @()
$totalFailures = 0
while ($i -le 20) {
    $curlResp = curl.exe --noproxy "*" -s -w "%{http_code} %{time_total}s" http://127.0.0.1:11437/v1/models 2>&1
    $parts = $curlResp -split " "
    $httpCode = $parts[0]
    $latencySec = $parts[1]
    $latencyMs = [math]::Round($latencySec * 1000)
    
    if ($httpCode -eq 200) {
        $validLatencies += $latencyMs
            Write-Host "Poll $i: HTTP $httpCode Latency $latencyMs ms VALID"
    } else {
            Write-Host "Poll $i: HTTP $httpCode Latency $latencyMs ms FAILURE"
        $totalFailures++
    }
    
    $i++
    Start-Sleep -Seconds 1
}

# Compute statistics
$count = $validLatencies.Count
if ($count -gt 0) {
    $sorted = $validLatencies | Sort-Object
    $p50Idx = [math]::Floor($count * 0.5)
    $p95Idx = [math]::Floor($count * 0.95)
    $p50 = $sorted[$p50Idx]
    $p95 = $sorted[$p95Idx]
    $max = ($sorted | Measure-Object -Maximum).Maximum
    Write-Host ""
    Write-Host "=== Gate 077: Systematic Proxy Stress Statistics ==="
    Write-Host "Polls attempted: 20"
    Write-Host "Valid (HTTP 200) polls: $count"
    Write-Host "HTTP failures (non-200): $totalFailures"
    Write-Host "P50 latency: $p50 ms"
    Write-Host "P95 latency: $p95 ms"
    Write-Host "Max latency: $max ms"
    Write-Host ""
    Write-Host "=== Per-Poll Latency Detail ==="
    $sorted | ForEach-Object { Write-Host "  Latency: $_ ms" }
} else {
    Write-Host ""
    Write-Host "No valid latency measurements across 20 polls"
    Write-Host "All 20 polls resulted in HTTP failures"
}

# Verify original proxy on 11436 still works
Write-Host ""
Write-Host "=== Verifying original proxy on 11436 ==="
$origResp = curl.exe --noproxy "*" -s http://127.0.0.1:11436/v1/models 2>&1
$origHttp = ($origResp -replace "^.*HTTP/\d+\s+(\d+).*", "$1")
Write-Host "Original proxy 11436 HTTP status: $origHttp"
if ($origHttp -eq 200) {
    Write-Host "Original proxy on 11436: OPERATIONAL"
}
