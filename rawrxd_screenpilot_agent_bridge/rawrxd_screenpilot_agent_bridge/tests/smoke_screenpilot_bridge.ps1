param(
    [string]$Base = "http://127.0.0.1:11437",
    [string]$Model = "qwen2.5-coder:32b",
    [string]$Workspace = "F:\~dev"
)

$ErrorActionPreference = "Stop"

Write-Host "== HEALTH =="
$health = Invoke-RestMethod "$Base/api/health"
$health | ConvertTo-Json -Depth 5

Write-Host "== SESSION =="
$session = Invoke-RestMethod "$Base/api/session" -Method Post
if (-not $session.token) { throw "No session token returned" }

$headers = @{ "X-RawrXD-Session" = $session.token }

Write-Host "== AGENT RUN =="
$body = @{
    requestId = "screenpilot-smoke-$([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())"
    mode       = "ask"
    model      = $Model
    workspace  = $Workspace
    prompt     = "Respond with exactly: SCREENPILOT_AGENT_BRIDGE_PASS"
} | ConvertTo-Json -Compress

$response = Invoke-WebRequest `
    -Uri "$Base/api/agent/run" `
    -Method Post `
    -Headers $headers `
    -ContentType "application/json" `
    -Body $body

$response.Content

if ($response.Content -notmatch "SCREENPILOT_AGENT_BRIDGE_PASS") {
    throw "FAIL: expected model marker not observed"
}

Write-Host "SCREENPILOT_AGENT_BRIDGE_SMOKE=PASS" -ForegroundColor Green
