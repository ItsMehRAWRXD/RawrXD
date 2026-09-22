param(
    [string]$Base = "http://127.0.0.1:11435",
    [string]$Model = "rawrxd",
    [string]$Workspace = "F:\~dev"
)

$ErrorActionPreference = "Stop"
$api = "$Base/api/v1/screenpilot"

function Pass([string]$Name) { Write-Host "$Name=PASS" -ForegroundColor Green }
function Fail([string]$Name, [string]$Why) {
    Write-Host "$Name=FAIL :: $Why" -ForegroundColor Red
    throw "$Name failed: $Why"
}

$s = Invoke-RestMethod "$api/session" -Method Post
$headers = @{ "X-RawrXD-Session" = $s.token }

$prompt = Get-Content (Join-Path $PSScriptRoot "mutation_gate_prompt.txt") -Raw
$body = @{
    requestId = "mutation-$([guid]::NewGuid().ToString('N'))"
    mode = "agent"
    model = $Model
    workspace = $Workspace
    prompt = $prompt
} | ConvertTo-Json -Compress

$r = Invoke-WebRequest "$api/agent/run" `
    -Method Post -Headers $headers -ContentType "application/json" -Body $body

$required = @(
    "SCREENPILOT_TOOL_AUTHORITY=PASS",
    "SCREENPILOT_WORKSPACE_WRITE=PASS",
    "SCREENPILOT_WORKSPACE_READ=PASS",
    "SCREENPILOT_WORKSPACE_SEARCH=PASS",
    "SCREENPILOT_WORKSPACE_DELETE=PASS",
    "SCREENPILOT_MUTATION_CLEANUP=PASS",
    "SCREENPILOT_MUTATION_E2E=PASS"
)

foreach ($marker in $required) {
    if ($r.Content -notmatch [regex]::Escape($marker)) {
        Fail $marker "receipt missing from stream"
    }
    Pass $marker
}

$gate = Join-Path $Workspace ".rawrxd_screenpilot_gate.txt"
if (Test-Path $gate) {
    Fail "SCREENPILOT_GATE_FILE_REMOVED" "gate file still exists"
}
Pass "SCREENPILOT_GATE_FILE_REMOVED"
Pass "SCREENPILOT_MUTATION_CERT"
