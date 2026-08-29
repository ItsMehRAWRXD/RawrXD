<#
.SYNOPSIS
  AGENT_SCHEMA_RETRY_001 - MODEL_RETRY lane (STRICT; no bare-key repair).
#>
param(
    [string]$Model = "F:\~dev\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf",
    [string]$BuildBin = "F:\~dev\rawrxd\build-win32ide-fresh\bin",
    [string]$Fixture = "F:\~dev\rawrxd\fixtures\agent_e2e_002b\01_compile",
    [string]$OutRoot = "F:\~dev\rawrxd\evidence\AGENT_SCHEMA_RETRY_001",
    [int]$MaxTokens = 256
)

$ErrorActionPreference = "Stop"
$exe = Join-Path $BuildBin "RawrXD-Agentic.exe"
if (-not (Test-Path -LiteralPath $exe)) { throw "missing $exe - rebuild RawrXD-Agentic" }
if (-not (Test-Path -LiteralPath $Model)) { throw "missing $Model" }
if (-not (Test-Path -LiteralPath $Fixture)) { throw "missing $Fixture" }

New-Item -ItemType Directory -Force -Path $OutRoot | Out-Null
$work = Join-Path $OutRoot "workspace"
if (Test-Path -LiteralPath $work) { Remove-Item -LiteralPath $work -Recurse -Force }
New-Item -ItemType Directory -Force -Path $work | Out-Null
Copy-Item -Path (Join-Path $Fixture '*') -Destination $work -Recurse -Force

$console = Join-Path $OutRoot "agent.console.txt"
$argList = @(
    "--model", $Model,
    "--workspace", $work,
    "--schema-retry-cert",
    "--schema-cert-out", $OutRoot,
    "--max-tokens", "$MaxTokens",
    "--no-stream"
)

Write-Host "AGENT_SCHEMA_RETRY_001 starting STRICT MODEL_RETRY bare-key-repair=OFF"
# Deep2 writes lifetime diagnostics to stderr; do not treat that as a PowerShell error.
$prevEap = $ErrorActionPreference
$ErrorActionPreference = "Continue"
& $exe @argList > $console 2>&1
$code = $LASTEXITCODE
$ErrorActionPreference = $prevEap
Get-Content -LiteralPath $console -ErrorAction SilentlyContinue | Select-Object -Last 40

$reportPath = Join-Path $OutRoot "AGENT_SCHEMA_RETRY_001.txt"
$status = "FAIL"
if (Test-Path $reportPath) {
    $txt = Get-Content -LiteralPath $reportPath -Raw
    if ($txt -match 'AGENT_SCHEMA_RETRY_001=PASS') { $status = "PASS" }
}

$ts = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$md = @"
# AGENT_SCHEMA_RETRY_001 - LOCK

**Status:** ``$status``
**Frozen:** $ts
**Lane:** MODEL_RETRY (RAWRXD_TOOL_ARGS_STRICT=1; bare-key repair OFF)

Distinct from SCHEMA-002 lane R (deterministic parser repair before dispatch).

## Required

``````text
FIRST_CALL_SCHEMA_VALID=0
FIRST_CALL_DISPATCHED=0
SECOND_CALL_SCHEMA_VALID=1
SECOND_CALL_DISPATCHED=1
FIRST_CALL_SIDE_EFFECTS=0
TOTAL_HANDLER_EXECUTIONS=1
CORRECTION_REQUIRED_NEW_INFERENCE=1
``````

## Artifacts

- AGENT_SCHEMA_RETRY_001.txt
- AGENT_SCHEMA_RETRY_001.lock.json
- agent.console.txt
- Regenerator: scripts/RUN_AGENT_SCHEMA_RETRY_001.ps1
"@
Set-Content -LiteralPath (Join-Path $OutRoot "LOCK.md") -Value $md -Encoding UTF8
Write-Host "AGENT_SCHEMA_RETRY_001=$status exit=$code"
exit $code
