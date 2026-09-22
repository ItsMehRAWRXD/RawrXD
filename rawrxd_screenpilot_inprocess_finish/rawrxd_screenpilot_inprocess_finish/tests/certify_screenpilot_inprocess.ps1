param(
    [string]$Base = "http://127.0.0.1:11435",
    [string]$Model = "qwen2.5-coder:32b",
    [string]$Workspace = "F:\~dev"
)

$ErrorActionPreference = "Stop"

function Pass($Name) {
    Write-Host "$Name=PASS" -ForegroundColor Green
}

function Fail($Name, $Why) {
    Write-Host "$Name=FAIL :: $Why" -ForegroundColor Red
    throw "$Name failed: $Why"
}

# 1. Health proves in-process canonical route.
$h = Invoke-RestMethod "$Base/api/v1/screenpilot/health"
if ($h.ok -and $h.transport -eq "in-process" -and $h.authority -eq "canonical") {
    Pass "SCREENPILOT_INPROCESS_ROUTE"
} else {
    Fail "SCREENPILOT_INPROCESS_ROUTE" ($h | ConvertTo-Json -Compress)
}

# 2. Get session.
$s = Invoke-RestMethod "$Base/api/v1/screenpilot/session" -Method Post
if (-not $s.token) { Fail "SCREENPILOT_SESSION_GUARD" "token missing" }
Pass "SCREENPILOT_SESSION_GUARD"

$headers = @{ "X-RawrXD-Session" = $s.token }

# 3. Bad token must fail.
try {
    Invoke-WebRequest "$Base/api/v1/screenpilot/capabilities" `
        -Headers @{ "X-RawrXD-Session" = "bad" } | Out-Null
    Fail "SCREENPILOT_BAD_TOKEN_REJECT" "bad token accepted"
} catch {
    if ($_.Exception.Response.StatusCode.value__ -ne 401) { throw }
    Pass "SCREENPILOT_BAD_TOKEN_REJECT"
}

# 4. Workspace escape must fail.
$escapeBody = @{
    requestId = "escape-$([guid]::NewGuid())"
    mode = "ask"
    model = $Model
    workspace = "C:\"
    prompt = "do nothing"
} | ConvertTo-Json -Compress

try {
    Invoke-WebRequest "$Base/api/v1/screenpilot/agent/run" `
        -Method Post -Headers $headers -ContentType "application/json" -Body $escapeBody | Out-Null
    Fail "SCREENPILOT_WORKSPACE_BOUNDARY" "workspace escape accepted"
} catch {
    if ($_.Exception.Response.StatusCode.value__ -ne 403) { throw }
    Pass "SCREENPILOT_WORKSPACE_BOUNDARY"
}

# 5. Exercise all four modes through the SAME authority route.
foreach ($mode in @("ask","plan","build","agent")) {
    $marker = "SCREENPILOT_$($mode.ToUpper())_PASS"
    $body = @{
        requestId = "$mode-$([guid]::NewGuid())"
        mode = $mode
        model = $Model
        workspace = $Workspace
        prompt = "Respond with the exact marker $marker. Do not perform destructive actions."
    } | ConvertTo-Json -Compress

    $r = Invoke-WebRequest "$Base/api/v1/screenpilot/agent/run" `
        -Method Post -Headers $headers -ContentType "application/json" -Body $body

    if ($r.Content -match [regex]::Escape($marker)) {
        Pass "SCREENPILOT_$($mode.ToUpper())_MODE"
    } else {
        Fail "SCREENPILOT_$($mode.ToUpper())_MODE" "marker not observed"
    }
}

Write-Host ""
Write-Host "SCREENPILOT_LOCAL_AGENT_E2E=PASS" -ForegroundColor Green
