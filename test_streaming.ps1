# Test SSE streaming on candidate port 11437
$body = @"
{"model":"reap16-glm-4_7-flash:latest","messages":[{"role":"user","content":"Sustained streaming test for stress gate"}],"stream":true}
"@
Write-Host "Sending streaming request to 11437..."
$start = Get-Date
$curlResp = curl.exe --noproxy "*" -s -N -d $body http://127.0.0.1:11437/v1/chat/completions 2>&1
$end = Get-Date
$elapsed = $end - $start
Write-Host "Streaming completed in $($elapsed.TotalMilliseconds)ms"
# Count [DONE] markers and chunks
$doneCount = ($curlResp -split "[DONE]" | Measure-Object).Lines
$chunkCount = ($curlResp -split "`n" | Measure-Object).Lines
Write-Host "Total chunks (newlines): $chunkCount"
Write-Host "[DONE] markers found: $doneCount"
Write-Host "Response body (first 1000 chars):"
Write-Host $curlResp.Substring(0, [math]::Min(1000, $curlResp.Length))
