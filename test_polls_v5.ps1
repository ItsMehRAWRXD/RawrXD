# Run 20 polls during sustained streaming on candidate port 11437
# This tests Gate 077: Systematic proxy stress
Write-Host "Ensuring streaming generation active on 11437..."
# Quick streaming start to keep model loaded
$body = "{`"model`":`"reap16-glm-4_7-flash:latest`",`"messages`":[`"role`":`"user`",`"content`":`"keep warm`"`],`"stream`":true}"
curl.exe --noproxy "*" -s -d $body http://127.0.0.1:11437/v1/chat/completions -o /dev/null 2>&1 &
Write-Host "Streaming started in background, running 20 polls..."
Start-Sleep -Seconds 1

# Run 20 polls with 1-second intervals, results to file
$i = 1
$resultsFile = "F:\rawrxd\poll_results5.txt"
"poll,http_code,latency_ms" > $resultsFile
$totalFailures = 0
while ($i -le 20) {
    $curlResp = curl.exe --noproxy "*" -s -w "%{http_code} %{time_total}" http://127.0.0.1:11437/v1/models 2>&1
    # Parse: first space-separated token is HTTP code, second is time in seconds
    $tokens = $curlResp -split " "
    $httpCode = $tokens[0]
    $latencySec = $tokens[1]
    $latencyMs = [math]::Round($latencySec * 1000)
    
    # Write CSV row using + concatenation to avoid variable interpolation issues
    "$i,$httpCode,$latencyMs" >> $resultsFile
    
    if ($httpCode -eq 200) {
        # Use string format to avoid variable interpolation issues
        $msg = [string]::Format("Poll {0}: HTTP {1} Latency {2} ms VALID", $i, $httpCode, $latencyMs)
        Write-Host $msg
    } else {
        $totalFailures++
        $msg = [string]::Format("Poll {0}: HTTP {1} Latency {2} ms FAILURE", $i, $httpCode, $latencyMs)
        Write-Host $msg
    }
    
    $i++
    Start-Sleep -Seconds 1
}

# Compute statistics from results file
$validLines = Get-Content $resultsFile | Where-Object { $_ -match "^,200," }
$latencies = @()
foreach ($line in $validLines) {
    $parts = $line -split ","
    if ($parts.Count -ge 3) {
        $latencies += [int]$parts[2]
    }
}

$count = $latencies.Count
if ($count -gt 0) {
    $sorted = $latencies | Sort-Object
    $p50Idx = [math]::Floor($count * 0.5)
    $p95Idx = [math]::Floor($count * 0.95)
    $p50 = $sorted[$p50Idx]
    $p95 = $sorted[$p95Idx]
    $max = $sorted[$sorted.Count - 1]
    $failures = 20 - $count
    Write-Host ""
    Write-Host "=== Gate 077: Systematic Proxy Stress Statistics ==="
    Write-Host "Polls attempted: 20"
    Write-Host "Valid (HTTP 200) polls: $count"
    Write-Host "HTTP failures (non-200): $failures"
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
if ($origResp -match "HTTP\/[^\s]+\s+(\d+)") {
    $origHttp = $matches[1]
    Write-Host "Original proxy 11436 HTTP status: $origHttp"
} elseif ($origResp.Contains("object")) {
    Write-Host "Original proxy 11436: OPERATIONAL (returned model list)"
} else {
    Write-Host "Original proxy 11436 response: $origResp.Substring(0, 100)"
}
if ($origHttp -eq 200) {
    Write-Host "Original proxy on 11436: OPERATIONAL"
}

Write-Host ""
Write-Host "=== Gate 077 Test Complete ==="
