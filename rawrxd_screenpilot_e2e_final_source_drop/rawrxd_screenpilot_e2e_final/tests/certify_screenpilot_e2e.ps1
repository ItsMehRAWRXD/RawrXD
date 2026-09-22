param(
    [string]$Base = "http://127.0.0.1:11435",
    [string]$Model = "rawrxd",
    [string]$Workspace = "F:\~dev"
)

$ErrorActionPreference = "Stop"

function Pass([string]$Name) {
    Write-Host "$Name=PASS" -ForegroundColor Green
}
function Fail([string]$Name, [string]$Why) {
    Write-Host "$Name=FAIL :: $Why" -ForegroundColor Red
    throw "$Name failed: $Why"
}

$api = "$Base/api/v1/screenpilot"

# Health must prove the production path rather than the old subprocess bridge.
$h = Invoke-RestMethod "$api/health"
if ($h.ok -and $h.transport -eq "in-process" -and
    $h.authority -eq "canonical" -and $h.abi -eq 2) {
    Pass "SCREENPILOT_INPROCESS_AUTHORITY"
} else {
    Fail "SCREENPILOT_INPROCESS_AUTHORITY" ($h | ConvertTo-Json -Compress)
}

# Session issuance.
$s = Invoke-RestMethod "$api/session" -Method Post
if (-not $s.token) { Fail "SCREENPILOT_SESSION_ISSUE" "token missing" }
Pass "SCREENPILOT_SESSION_ISSUE"

$headers = @{ "X-RawrXD-Session" = $s.token }

# Invalid session denied.
try {
    Invoke-WebRequest "$api/capabilities" `
        -Headers @{ "X-RawrXD-Session" = "invalid-token" } | Out-Null
    Fail "SCREENPILOT_SESSION_REJECT" "invalid token accepted"
} catch {
    if ($_.Exception.Response.StatusCode.value__ -ne 401) { throw }
    Pass "SCREENPILOT_SESSION_REJECT"
}

# Capabilities.
$c = Invoke-RestMethod "$api/capabilities" -Headers $headers
if ($c.streaming -and $c.cancel -and $c.approval -and
    $c.workspaceOnly -and $c.toolAuthority) {
    Pass "SCREENPILOT_CAPABILITIES"
} else {
    Fail "SCREENPILOT_CAPABILITIES" ($c | ConvertTo-Json -Compress)
}

# Workspace escape must fail before the agent ever runs.
$escapeBody = @{
    requestId = "escape-$([guid]::NewGuid().ToString('N'))"
    mode = "ask"
    model = $Model
    workspace = "C:\"
    prompt = "Return OK"
} | ConvertTo-Json -Compress

try {
    Invoke-WebRequest "$api/agent/run" `
        -Method Post -Headers $headers -ContentType "application/json" -Body $escapeBody | Out-Null
    Fail "SCREENPILOT_WORKSPACE_ESCAPE_REJECT" "C:\ accepted"
} catch {
    if ($_.Exception.Response.StatusCode.value__ -ne 403) { throw }
    Pass "SCREENPILOT_WORKSPACE_ESCAPE_REJECT"
}

# Unknown mode denied.
$badMode = @{
    requestId = "mode-$([guid]::NewGuid().ToString('N'))"
    mode = "root"
    model = $Model
    workspace = $Workspace
    prompt = "Return OK"
} | ConvertTo-Json -Compress

try {
    Invoke-WebRequest "$api/agent/run" `
        -Method Post -Headers $headers -ContentType "application/json" -Body $badMode | Out-Null
    Fail "SCREENPILOT_UNKNOWN_MODE_REJECT" "unknown mode accepted"
} catch {
    if ($_.Exception.Response.StatusCode.value__ -ne 400) { throw }
    Pass "SCREENPILOT_UNKNOWN_MODE_REJECT"
}

# Exercise all four modes against a real local model/coordinator.
foreach ($mode in @("ask", "plan", "build", "agent")) {
    $marker = "SCREENPILOT_$($mode.ToUpper())_MODE_PASS"
    $body = @{
        requestId = "$mode-$([guid]::NewGuid().ToString('N'))"
        mode = $mode
        model = $Model
        workspace = $Workspace
        prompt = "Return exactly this marker and do not invoke a tool: $marker"
    } | ConvertTo-Json -Compress

    $r = Invoke-WebRequest "$api/agent/run" `
        -Method Post -Headers $headers -ContentType "application/json" -Body $body

    if ($r.Content -match [regex]::Escape($marker)) {
        Pass "SCREENPILOT_$($mode.ToUpper())_MODE"
    } else {
        Fail "SCREENPILOT_$($mode.ToUpper())_MODE" "marker not observed"
    }
}

Write-Host ""
Write-Host "SCREENPILOT_PROTOCOL_E2E=PASS" -ForegroundColor Green
