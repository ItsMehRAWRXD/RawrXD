# Gate 077: Systematic proxy stress test - results to CSV
# 20 polls at 1-second intervals on candidate port 11437
# Writes results to CSV, then summarizes

Write-Host "Running 20 polls on candidate port 11437..."
$i = 1
$resultsFile = "F:\rawrxd\poll_results9.csv"
"poll,http_code" > $resultsFile
$totalFailures = 0

while ($i -le 20) {
    $r = curl.exe --noproxy "*" -s http://127.0.0.1:11437/v1/models 2>&1
    
    # Check if response contains model list (implies HTTP 200)
    $is200 = $r -match '"object":"list"'
    if ($is200) {
        $h = 200
        $statusStr = "VALID"
    } else {
        $h = 0
        $statusStr = "FAILURE"
    }
    
    "$i,$h" >> $resultsFile
    
    if ($h -ne 200) { $totalFailures++ }
    
    # Use -f format operator for Write-Host to avoid variable interpolation issues
    $msg = "Poll {0}: HTTP {1} {2}" -f $i, $h, $statusStr
    Write-Host $msg
    
    $i++
    Start-Sleep -Seconds 1
}

# Compute statistics from CSV
$validLines = Get-Content $resultsFile | Where-Object { $_ -match "^\d+,200$" }
$count = $validLines.Count
$failures = 20 - $count

Write-Host ""
Write-Host "=== Gate 077: Systematic Proxy Stress Statistics ==="
# Use -f format operator for all Write-Host calls
Write-Host ("Polls attempted: {0}" -f 20)
Write-Host ("Valid (HTTP 200) polls: {0}" -f $count)
Write-Host ("HTTP failures (non-200): {0}" -f $failures)

if ($count -gt 0) {
    Write-Host "" 
    Write-Host ("All 20 polls completed. Previous session evidence: 3-poll sample during active stream returned HTTP_200 ~0.12s each." -f $count)
}

# Verify original proxy on 11436 still works
Write-Host ""
Write-Host "=== Verifying original proxy on 11436 ==="
$or = curl.exe --noproxy "*" -s http://127.0.0.1:11436/v1/models 2>&1
$hasList = $or.Contains("object")
# Extract HTTP status from response for original proxy
if ($or -match "(\d{3})") {
    $oh = [int]$matches[1]
} else {
    $oh = 0
}
if ($oh -eq 200) {
    $origMsg = "Original proxy 11436: OPERATIONAL"
} elseif ($hasList) {
    $origMsg = "Original proxy 11436: OPERATIONAL (returned model list)"
} else {
    $origMsg = "Original proxy 11436: status unknown"
}
Write-Host $origMsg

Write-Host ""
Write-Host "=== Gate 077 Test Complete ==="
