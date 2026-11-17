# Test nonstreaming generation on candidate port 11437
$body = @"
{"model":"reap16-glm-4_7-flash:latest","messages":[{"role":"user","content":"Hello, world!"}],"stream":false}
"@
Write-Host "Sending nonstreaming request to 11437..."
$start = Get-Date
$curlResp = curl.exe --noproxy "*" -s -d $body http://127.0.0.1:11437/v1/chat/completions 2>&1
$end = Get-Date
$elapsed = $end - $start
Write-Host "Response received in $($elapsed.TotalMilliseconds)ms"
Write-Host "Response body (first 500 chars):"
Write-Host $curlResp.Substring(0, [math]::Min(500, $curlResp.Length))
