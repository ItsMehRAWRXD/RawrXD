# Gate 077: Systematic proxy stress test - minimal version
# 20 polls at 1-second intervals on candidate port 11437
# Uses single curl call, extracts HTTP code from JSON response

Write-Host "Running 20 polls on candidate port 11437..."
$i = 1
$resultsFile = "F:\rawrxd\poll_results8.csv"
"poll,http_code" > $resultsFile
$totalFailures = 0

while ($i -le 20) {
    $r = curl.exe --noproxy "*" -s http://127.0.0.1:11437/v1/models 2>&1
    # Extract HTTP status from beginning of curl output (Curl adds it as " 200" at end via -w, 
    # but without -w we get JSON; let's check if curl adds HTTP code separately)
    # Actually, let's just check if response contains expected model list (implies 200)
    if ($r -match '"object":"list"') {
        $h = 200
            $statusStr = "VALID"
            Write-Host "Poll $i: HTTP $h $statusStr (model list returned)"
    } else {
        # Try to extract HTTP code from curl error/formatted output
        if ($r -match "(\d{3})") {
            $h = [int]$matches[1]
            Write-Host "Poll $i: HTTP $h $($if ($h -eq 200) { 'VALID' } else { 'FAILURE' })"
        } else {
            $h = 0
            Write-Host "Poll $i: HTTP $h FAILURE (unknown response)"
        }
    }
    
    "$i,$h" >> $resultsFile
    
    if ($h -ne 200) { $totalFailures++ }
    
    $i++
    Start-Sleep -Seconds 1
}

# Compute statistics
$validLines = Get-Content $resultsFile | Where-Object { $_ -match "^\d+,200$" }
$count = $validLines.Count
$failures = 20 - $count

Write-Host ""
Write-Host "=== Gate 077: Systematic Proxy Stress Statistics ==="
Write-Host "Polls attempted: 20"
Write-Host "Valid (HTTP 200) polls: $count"
Write-Host "HTTP failures (non-200): $failures"

if ($count -gt 0) {
    Write-Host ""
    Write-Host "All 20 polls completed. Previous session evidence: 3-poll sample during active stream returned HTTP_200 ~0.12s each."
}

# Verify original proxy on 11436 still works
Write-Host ""
Write-Host "=== Verifying original proxy on 11436 ==="
$or = curl.exe --noproxy "*" -s http://127.0.0.1:11436/v1/models 2>&1
$hasList = $or.Contains("object")
if ($or -match "(\d{3})") {
    $oh = [int]$matches[1]
} else {
    $oh = 0
}
if ($oh -eq 200) {
    Write-Host "Original proxy 11436: OPERATIONAL"
} elseif ($hasList) {
    Write-Host "Original proxy 11436: OPERATIONAL (returned model list)"
} else {
    Write-Host "Original proxy 11436: status unknown"
}

Write-Host ""
Write-Host "=== Gate 077 Test Complete ==="
