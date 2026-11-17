# Gate 077: Systematic proxy stress test - poll during active candidate
# Using -f format operator to avoid PowerShell variable interpolation issues
# 20 polls at 1-second intervals during sustained streaming on candidate port 11437

Write-Host "Running 20 polls on candidate port 11437 (using -f format operator)..."
$i = 1
$resultsFile = "F:\rawrxd\poll_results7.csv"
"poll,http_code,latency_ms" > $resultsFile
$totalFailures = 0

while ($i -le 20) {
    # Use two separate curl -w calls to get HTTP code and time_total
    $httpCode = curl.exe --noproxy "*" -s -w "%{http_code}" http://127.0.0.1:11437/v1/models 2>&1
    # Get time_total from the same request by redirecting to a temp file
    $timeFile = "F:\rawrxd\temp_curl_time.txt"
    $null = curl.exe --noproxy "*" -s -o /dev/null -w "%{time_total}" http://127.0.0.1:11437/v1/models -o $timeFile 2>&1
    $timeSec = Get-Content $timeFile -TotalCount 1
    # Remove any trailing whitespace/newline
    $timeSec = $timeSec.Trim()
    $l = [math]::Round($timeSec * 1000)
    # Clean up temp file
    Remove-Item $timeFile -Force -ErrorAction SilentlyContinue
    
    "$i,$httpCode,$l" >> $resultsFile
    
    $status = if ($httpCode -eq 200) { "VALID" } else { "FAILURE" }
    if ($httpCode -ne 200) { $totalFailures++ }
    $msg = "Poll {0}: HTTP {1} ms {2}" -f $i, $l, $status
    Write-Host $msg
    
    $i++
    Start-Sleep -Seconds 1
}

# Compute statistics from CSV
$validLines = Get-Content $resultsFile | Where-Object { $_ -match "^\d+,200," }
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
    foreach ($lat in $sorted) {
        Write-Host "  Latency: $lat ms"
    }
} else {
    Write-Host ""
    Write-Host "No valid latency measurements across 20 polls"
    Write-Host "All 20 polls resulted in HTTP failures"
}

# Verify original proxy on 11436 still works
Write-Host ""
Write-Host "=== Verifying original proxy on 11436 ==="
$or = curl.exe --noproxy "*" -s http://127.0.0.1:11436/v1/models 2>&1
$hasList = $or.Contains("object")
if ($or -match "HTTP/[^\s]+\s+(\d+)") {
    $oh = $matches[1]
} else {
    $oh = "unknown"
}
if ($oh -eq 200) {
    $origStatus = "OPERATIONAL"
} elseif ($hasList) {
    $origStatus = "returned model list"
} else {
    $origStatus = "status unknown"
}
$origMsg = "Original proxy 11436: " + $origStatus
Write-Host $origMsg

Write-Host ""
Write-Host "=== Gate 077 Test Complete ==="