param(
    [Parameter(Mandatory=$true)][string]$Deep2TokenIds,
    [Parameter(Mandatory=$true)][string]$ReferenceTokenIds,
    [Parameter(Mandatory=$true)][string]$AgentSmokeScript,
    [string[]]$AgentSmokeArgs = @(),
    [string]$ExpectedAgentEvidence = "",
    [string]$DropRoot = (Split-Path -Parent $PSScriptRoot),
    [string]$BuildDir = ""
)

$ErrorActionPreference = "Stop"
if (-not $BuildDir) { $BuildDir = Join-Path $DropRoot "build-cert-tools" }

& cmake -S $DropRoot -B $BuildDir
if ($LASTEXITCODE -ne 0) { throw "BLOCK5_TOOL_CONFIGURE_FAIL" }

& cmake --build $BuildDir --target rawrxd_token_sequence_parity --config Release --parallel
if ($LASTEXITCODE -ne 0) { throw "BLOCK5_TOOL_BUILD_FAIL" }

$candidates = @(
    (Join-Path $BuildDir "rawrxd_token_sequence_parity.exe"),
    (Join-Path $BuildDir "Release\rawrxd_token_sequence_parity.exe"),
    (Join-Path $BuildDir "bin\rawrxd_token_sequence_parity.exe"),
    (Join-Path $BuildDir "bin\Release\rawrxd_token_sequence_parity.exe")
)
$exe = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $exe) { throw "BLOCK5_TOOL_NOT_FOUND" }

& $exe $Deep2TokenIds $ReferenceTokenIds
if ($LASTEXITCODE -ne 0) { throw "BLOCK5_MULTITOKEN_FAIL" }

if (-not (Test-Path $AgentSmokeScript)) {
    throw "BLOCK5_AGENT_SMOKE_NOT_FOUND: $AgentSmokeScript"
}

& powershell -NoProfile -ExecutionPolicy Bypass -File $AgentSmokeScript @AgentSmokeArgs
if ($LASTEXITCODE -ne 0) {
    throw "BLOCK5_AGENTIC_SMOKE_FAIL exit=$LASTEXITCODE"
}

if ($ExpectedAgentEvidence) {
    if (-not (Test-Path $ExpectedAgentEvidence)) {
        throw "BLOCK5_EXPECTED_AGENT_EVIDENCE_MISSING"
    }
    $ev = Get-Content $ExpectedAgentEvidence -Raw
    if ($ev -notmatch "PASS") {
        throw "BLOCK5_AGENT_EVIDENCE_NOT_PASS"
    }
}

"BLOCK5_MULTITOKEN_PARITY=PASS"
"BLOCK5_AGENTIC_PRODUCT=PASS"
"PARITY_CLOSURE=PASS"
