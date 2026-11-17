# Regression test: concurrent /v1/models during streaming generation
$body = @{
    model = "reap16-glm-4_7-flash:latest"
    messages = @(
        @{role = "user"; content = "Write a detailed 500-word essay about the history of artificial intelligence from its origins to the present day, covering major milestones, key researchers, and technological breakthroughs in each era."}
    )
    stream = $true
    temperature = 0.7
    max_tokens = 1024
}
$bodyJson = $body | ConvertTo-Json -Depth 10
$bodyJson | Set-Content "F:\rawrxd\evidence\stream_test_request.json" -Encoding utf8

# Start streaming request in background (no WindowStyle to avoid conflict)
$streamProc = Start-Process -FilePath "curl.exe" -ArgumentList @("--noproxy", "*", "-N", "-s", "-H", "Content-Type: application/json", "--data-binary", "@F:\rawrxd\evidence\stream_test_request.json", "http://127.0.0.1:11436/v1/chat/completions") -WindowStyle Hidden
Write-Host "Started streaming request with PID: $streamProc.Id"

# Poll /v1/models every second for 30 seconds
$results = @()
for ($i = 0; $i -lt 30; $i++) {
    $start = Get-Date
    try {
        $response = curl.exe --noproxy "*" --max-time 5 -s -w "HTTP=%{http_code} TIME=%{time_total}s" "http://127.0.0.1:11436/v1/models"
        $status = "PASS"
        if ($response -notmatch "HTTP=200") { $status = "FAIL" }
        $results += "$(Get-Date -Format "HH:mm:ss.fff") HTTP=$(($response -split "HTTP=")[1].Split(" ")[0]) $status"
    } catch {
        $results += "$(Get-Date -Format "HH:mm:ss.fff") ERROR: $_"
    }
    Start-Sleep -Seconds 1
}

# Wait for stream to complete
try { Wait-Process $streamProc -Timeout 60 } catch {}

Write-Host "=== RESULTS ==="
$results | ForEach-Object { Write-Host $_ }
$passCount = ($results | Where-Object { $_ -match "200" }).Count
$failCount = ($results | Where-Object { $_ -notmatch "200" }).Count
Write-Host "Total polls: $($results.Count)"
Write-Host "PASS (200): $passCount"
Write-Host "FAIL: $failCount"