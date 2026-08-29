<#
.SYNOPSIS
  AGENT_SCHEMA_RETRY_001 - MODEL_RETRY lane (STRICT; no bare-key repair).

.NOTES
  Native stderr (e.g. [LIFE] ~Deep2Engine) must NOT be merged through PowerShell's
  2>&1 | Tee-Object path — that converts diagnostics into NativeCommandError and
  contaminates the cert gate. Capture via Start-Process RedirectStandard* and
  gate only on native ExitCode + evidence assertions.
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

$stdout = Join-Path $OutRoot "stdout.txt"
$stderr = Join-Path $OutRoot "stderr.txt"
$console = Join-Path $OutRoot "agent.console.txt"
foreach ($f in @($stdout, $stderr, $console)) {
    if (Test-Path -LiteralPath $f) { Remove-Item -LiteralPath $f -Force }
}

# Start-Process ArgumentList is one command-line string on Windows.
$argLine = @(
    "--model", "`"$Model`"",
    "--workspace", "`"$work`"",
    "--schema-retry-cert",
    "--schema-cert-out", "`"$OutRoot`"",
    "--max-tokens", "$MaxTokens",
    "--no-stream"
) -join " "

Write-Host "AGENT_SCHEMA_RETRY_001 starting STRICT MODEL_RETRY bare-key-repair=OFF"
Write-Host "capture: Start-Process RedirectStandardOutput/Error (no 2>&1 Tee)"

$p = Start-Process `
    -FilePath $exe `
    -ArgumentList $argLine `
    -NoNewWindow `
    -Wait `
    -PassThru `
    -RedirectStandardOutput $stdout `
    -RedirectStandardError $stderr

$nativeExit = $p.ExitCode
Write-Host "AGENT_NATIVE_EXIT=$nativeExit"

# Combined console for humans; keep stdout/stderr separate as evidence.
$combined = @()
if (Test-Path -LiteralPath $stdout) {
    $combined += "===== STDOUT ====="
    $combined += Get-Content -LiteralPath $stdout
}
if (Test-Path -LiteralPath $stderr) {
    $combined += "===== STDERR ====="
    $combined += Get-Content -LiteralPath $stderr
}
$combined | Set-Content -LiteralPath $console -Encoding UTF8

$stdoutText = if (Test-Path $stdout) { Get-Content -LiteralPath $stdout -Raw } else { "" }
$stderrText = if (Test-Path $stderr) { Get-Content -LiteralPath $stderr -Raw } else { "" }
$reportPath = Join-Path $OutRoot "AGENT_SCHEMA_RETRY_001.txt"
$reportText = if (Test-Path $reportPath) { Get-Content -LiteralPath $reportPath -Raw } else { "" }

function Test-Flag([string]$hay, [string]$pattern) {
    return [bool]($hay -match $pattern)
}

# Schema assertions from native report (functional gate already written by EXE).
$firstInvalid = Test-Flag $reportText 'FIRST_CALL_SCHEMA_VALID=0'
$firstDispZero = Test-Flag $reportText 'FIRST_CALL_DISPATCHED=0'
$firstSideZero = Test-Flag $reportText 'FIRST_CALL_SIDE_EFFECTS=0'
$secondValid = Test-Flag $reportText 'SECOND_CALL_SCHEMA_VALID=1'
$secondDisp = Test-Flag $reportText 'SECOND_CALL_DISPATCHED=1'
$correctedDiff = Test-Flag $reportText 'corrected_call_different=PASS'
$handlerOne = Test-Flag $reportText 'handler_execution_count=1'
$modelRetry = Test-Flag $reportText 'CORRECTION_REQUIRED_NEW_INFERENCE=1'
$reportPassLine = Test-Flag $reportText 'AGENT_SCHEMA_RETRY_001=PASS'

# Teardown: destructor diagnostics go to stderr (not a failure).
$dtorBegin = Test-Flag $stderrText '\[LIFE\] ~Deep2Engine BEGIN'
$dtorEnd = Test-Flag $stderrText '\[LIFE\] ~Deep2Engine END'

$nativeExitZero = ($nativeExit -eq 0)

$gates = [ordered]@{
    FIRST_INVALID_REJECTED     = $firstInvalid
    FIRST_DISPATCHED_ZERO      = $firstDispZero
    FIRST_SIDE_EFFECTS_ZERO    = $firstSideZero
    MODEL_RETRY_OCCURRED       = $modelRetry
    CORRECTED_CALL_DIFFERENT   = $correctedDiff
    SECOND_SCHEMA_VALID        = $secondValid
    SECOND_DISPATCHED_ONCE     = $secondDisp
    HANDLER_EXECUTIONS_ONE     = $handlerOne
    NATIVE_EXIT_ZERO           = $nativeExitZero
    TEARDOWN_COMPLETE          = ($dtorBegin -and $dtorEnd)
    REPORT_PASS_LINE           = $reportPassLine
}

$allPass = $true
foreach ($k in $gates.Keys) {
    if (-not $gates[$k]) { $allPass = $false }
}

$status = if ($allPass) { "PASS" } else { "FAIL" }
$ts = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

$summary = New-Object System.Text.StringBuilder
[void]$summary.AppendLine("AGENT_SCHEMA_RETRY_001")
[void]$summary.AppendLine("frozen_at_utc=$ts")
[void]$summary.AppendLine("AGENT_NATIVE_EXIT=$nativeExit")
[void]$summary.AppendLine("powershell_stderr_record=irrelevant")
[void]$summary.AppendLine("")
foreach ($k in $gates.Keys) {
    $v = if ($gates[$k]) { "PASS" } else { "FAIL" }
    [void]$summary.AppendLine(("$k=$v"))
}
[void]$summary.AppendLine("")
[void]$summary.AppendLine("DEEP2_DESTRUCTOR_BEGIN=$([int]$dtorBegin)")
[void]$summary.AppendLine("DEEP2_DESTRUCTOR_END=$([int]$dtorEnd)")
[void]$summary.AppendLine("AGENT_SCHEMA_RETRY_001=$status")
$summaryPath = Join-Path $OutRoot "HARNESS_GATE.txt"
Set-Content -LiteralPath $summaryPath -Value $summary.ToString() -Encoding UTF8
Write-Host ($summary.ToString())

$lock = [ordered]@{
    gate = "AGENT_SCHEMA_RETRY_001"
    status = $status
    frozen_at_utc = $ts
    lane = "MODEL_RETRY"
    strict = $true
    bare_key_repair = $false
    AGENT_NATIVE_EXIT = $nativeExit
    note = "Gate on native ExitCode + assertions. PowerShell NativeCommandError from stderr is irrelevant."
    gates = $gates
    DEEP2_DESTRUCTOR_BEGIN = $dtorBegin
    DEEP2_DESTRUCTOR_END = $dtorEnd
}
($lock | ConvertTo-Json -Depth 6) | Set-Content -LiteralPath (Join-Path $OutRoot "AGENT_SCHEMA_RETRY_001.lock.json") -Encoding UTF8

$md = @"
# AGENT_SCHEMA_RETRY_001 - LOCK

**Status:** ``$status``
**Frozen:** $ts
**Lane:** MODEL_RETRY (RAWRXD_TOOL_ARGS_STRICT=1; bare-key repair OFF)

## Certification rule

``````text
native_exe_exit_0         = required
powershell_stderr_record  = irrelevant to native success
schema_retry_assertions   = required
DEEP2_DESTRUCTOR BEGIN+END = required (real teardown)
``````

## Harness gates

$(($gates.GetEnumerator() | ForEach-Object { "- ``$($_.Key)`` = $(if ($_.Value) {'PASS'} else {'FAIL'})" }) -join "`n")

``AGENT_NATIVE_EXIT=$nativeExit``
``DEEP2_DESTRUCTOR_BEGIN=$([int]$dtorBegin)``
``DEEP2_DESTRUCTOR_END=$([int]$dtorEnd)``

## Artifacts

- stdout.txt / stderr.txt (separate; no 2>&1 Tee contamination)
- agent.console.txt (combined)
- AGENT_SCHEMA_RETRY_001.txt (native report)
- HARNESS_GATE.txt
- Regenerator: scripts/RUN_AGENT_SCHEMA_RETRY_001.ps1
"@
Set-Content -LiteralPath (Join-Path $OutRoot "LOCK.md") -Value $md -Encoding UTF8

Write-Host "AGENT_SCHEMA_RETRY_001=$status AGENT_NATIVE_EXIT=$nativeExit"
if ($allPass) { exit 0 } else { exit 1 }
