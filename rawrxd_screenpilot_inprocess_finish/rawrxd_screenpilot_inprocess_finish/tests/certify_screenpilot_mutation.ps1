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

$session = Invoke-RestMethod "$Base/api/v1/screenpilot/session" -Method Post
if (-not $session.token) { Fail "SCREENPILOT_MUTATION_SESSION" "token missing" }

$headers = @{ "X-RawrXD-Session" = $session.token }

$prompt = Get-Content (Join-Path $PSScriptRoot "agent_mutation_gate_prompt.txt") -Raw
$body = @{
    requestId = "mutation-$([guid]::NewGuid())"
    mode = "agent"
    model = $Model
    workspace = $Workspace
    prompt = $prompt
} | ConvertTo-Json -Compress

$r = Invoke-WebRequest "$Base/api/v1/screenpilot/agent/run" `
    -Method Post `
    -Headers $headers `
    -ContentType "application/json" `
    -Body $body

$required = @(
    "SCREENPILOT_TOOL_AUTHORITY=PASS",
    "SCREENPILOT_WRITE=PASS",
    "SCREENPILOT_READ=PASS",
    "SCREENPILOT_SEARCH=PASS",
    "SCREENPILOT_DELETE=PASS",
    "SCREENPILOT_MUTATION_E2E=PASS"
)

foreach ($marker in $required) {
    if ($r.Content -notmatch [regex]::Escape($marker)) {
        Fail $marker "receipt marker not observed"
    }
    Pass $marker
}

$gateFile = Join-Path $Workspace ".rawrxd_screenpilot_gate.txt"
if (Test-Path $gateFile) {
    Fail "SCREENPILOT_GATE_CLEANUP" "disposable gate file still exists"
}
Pass "SCREENPILOT_GATE_CLEANUP"

Write-Host ""
Write-Host "SCREENPILOT_AGENT_MUTATION_CERT=PASS" -ForegroundColor Green
