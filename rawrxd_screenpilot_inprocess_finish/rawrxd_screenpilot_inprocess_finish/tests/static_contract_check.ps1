param(
    [string]$Root = (Split-Path -Parent $PSScriptRoot)
)

$ErrorActionPreference = "Stop"

function Pass($Name) {
    Write-Host "$Name=PASS" -ForegroundColor Green
}

function Fail($Name, $Why) {
    Write-Host "$Name=FAIL :: $Why" -ForegroundColor Red
    throw "$Name failed: $Why"
}

$cpp = Get-Content (Join-Path $Root "src\rawrxd_screenpilot_agent.cpp") -Raw
$js  = Get-Content (Join-Path $Root "web\screenpilot_client.js") -Raw

# The production adapter must not grow a second execution authority.
$forbidden = @(
    'CreateProcess',
    'ShellExecute',
    'WinExec',
    '_popen',
    'popen(',
    'system(',
    'cmd.exe',
    'powershell.exe'
)

foreach ($term in $forbidden) {
    if ($cpp -match [regex]::Escape($term)) {
        Fail "SCREENPILOT_NO_DIRECT_EXECUTION" "found forbidden term: $term"
    }
}
Pass "SCREENPILOT_NO_DIRECT_EXECUTION"

if ($cpp -match '127\.0\.0\.1' -or $cpp -match 'localhost') {
    Pass "SCREENPILOT_LOCALHOST_POLICY_PRESENT"
} else {
    Fail "SCREENPILOT_LOCALHOST_POLICY_PRESENT" "localhost checks missing"
}

if ($cpp -match 'workspace_root' -and $cpp -match 'path_is_under') {
    Pass "SCREENPILOT_WORKSPACE_POLICY_PRESENT"
} else {
    Fail "SCREENPILOT_WORKSPACE_POLICY_PRESENT" "workspace confinement missing"
}

if ($js -match 'const API = "/api/v1/screenpilot"') {
    Pass "SCREENPILOT_SAME_ORIGIN_CLIENT"
} else {
    Fail "SCREENPILOT_SAME_ORIGIN_CLIENT" "client is not using same-origin API path"
}

if ($js -match '11437') {
    Fail "SCREENPILOT_NO_TEMP_BRIDGE_REFERENCE" "temporary bridge port remains in production JS"
}
Pass "SCREENPILOT_NO_TEMP_BRIDGE_REFERENCE"

Write-Host ""
Write-Host "SCREENPILOT_STATIC_CONTRACT=PASS" -ForegroundColor Green
