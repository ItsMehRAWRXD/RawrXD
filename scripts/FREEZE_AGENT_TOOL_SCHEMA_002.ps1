<#
.SYNOPSIS
  AGENT-TOOL-SCHEMA-002 — certify schema-gated dispatch + model retry from an E2E case transcript.
#>
param(
    [string]$CaseDir = "F:\~dev\rawrxd\evidence\AGENT_E2E_002b\01_compile",
    [string]$OutRoot = "F:\~dev\rawrxd\evidence\AGENT_TOOL_SCHEMA_002",
    [string]$SourceName = "main.c"
)

$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path $OutRoot | Out-Null

$transcriptPath = Join-Path $CaseDir "RAWRXD_AGENT_TRANSCRIPT.json"
$summaryPath = Join-Path $CaseDir "RUN_SUMMARY.txt"
$beforePath = Join-Path $CaseDir "workspace_before\$SourceName"
$afterPath = Join-Path $CaseDir "workspace_after\$SourceName"
$consolePath = Join-Path $CaseDir "agent.console.txt"

foreach ($p in @($transcriptPath, $summaryPath, $beforePath, $afterPath)) {
    if (-not (Test-Path -LiteralPath $p)) { throw "missing $p" }
}

$raw = Get-Content -LiteralPath $transcriptPath -Raw -Encoding UTF8
$console = if (Test-Path $consolePath) { Get-Content -LiteralPath $consolePath -Raw } else { "" }

$beforeSha = (Get-FileHash -Algorithm SHA256 -LiteralPath $beforePath).Hash.ToLowerInvariant()
$afterSha = (Get-FileHash -Algorithm SHA256 -LiteralPath $afterPath).Hash.ToLowerInvariant()
$sourceMutated = ($beforeSha -ne $afterSha)

$summary = Get-Content -LiteralPath $summaryPath -Raw
$goal = $summary -match 'goal\.satisfied=True|goal\.satisfied=true'

# Parse steps loosely from transcript
$stepBlocks = [regex]::Matches($raw, '"step"\s*:\s*(?<n>\d+)')
$rejectLines = [regex]::Matches($console, '\[TOOL_SCHEMA\] REJECT[^\r\n]*')
$acceptLines = [regex]::Matches($console, '\[TOOL_SCHEMA\] ACCEPT[^\r\n]*')
$schemaErrors = [regex]::Matches($raw, '"error"\s*:\s*"schema_validation"')
$dispatchedTrue = [regex]::Matches($raw, '"dispatched"\s*:\s*true')
$dispatchedFalse = [regex]::Matches($raw, '"dispatched"\s*:\s*false')

# Detect invalid args that were rejected (schema_validation + dispatched false)
$invalidRejected = $schemaErrors.Count -gt 0 -or $rejectLines.Count -gt 0
# Fail-closed: any schema_validation result must not have dispatched:true on same object
$badDispatch = $false
$resultObjs = [regex]::Matches($raw, '\{"ok":(?<body>.*?)\}\{|"ok":(?<body>.*?)\}(?=,|])')
# Simpler: if REJECT console lines exist, ACCEPT should not precede same-step for same malformed args.
# Hard invariant from transcript: count schema_validation blocks containing "dispatched":true
$schemaWithDispatch = [regex]::Matches($raw, '"error"\s*:\s*"schema_validation"[^\}]*"dispatched"\s*:\s*true|"dispatched"\s*:\s*true[^\}]*"error"\s*:\s*"schema_validation"')
if ($schemaWithDispatch.Count -gt 0) { $badDispatch = $true }
# Also: REJECT implies we never want handler-side missing string argument without schema_validation
$legacyMissing = [regex]::Matches($raw, 'missing string argument')
$invalidDispatched = $badDispatch -or ($legacyMissing.Count -gt 0 -and $schemaErrors.Count -eq 0)

$validationToModel = $schemaErrors.Count -gt 0 -or ($raw -match 'schema_validation')

# Retry: more than one step with tool_calls, or ACCEPT after REJECT
$modelRetry = $stepBlocks.Count -ge 2
$retrySchemaValid = $acceptLines.Count -gt 0
$retryDispatched = $dispatchedTrue.Count -gt 0 -or $acceptLines.Count -gt 0

$gate = [ordered]@{
    INVALID_ARGS_REJECTED     = [bool]$invalidRejected
    INVALID_ARGS_DISPATCHED   = [bool]$invalidDispatched
    VALIDATION_ERROR_TO_MODEL = [bool]$validationToModel
    MODEL_RETRY_OCCURRED      = [bool]$modelRetry
    RETRY_SCHEMA_VALID        = [bool]$retrySchemaValid
    RETRY_TOOL_DISPATCHED     = [bool]$retryDispatched
    FILE_BYTES_CHANGED        = [bool]$sourceMutated
    GOAL_SATISFIED            = [bool]$goal
}

# Gate pass criteria (schema hardening): reject invalid, never dispatch invalid, error to model.
# Retry success is observed separately (may still FAIL if TinyLlama can't repair JSON).
$schemaGateHardPass =
    $gate.INVALID_ARGS_REJECTED -eq $true -and
    $gate.INVALID_ARGS_DISPATCHED -eq $false -and
    $gate.VALIDATION_ERROR_TO_MODEL -eq $true

$status = if ($schemaGateHardPass) {
    if ($gate.RETRY_SCHEMA_VALID -and $gate.RETRY_TOOL_DISPATCHED) { "PASS_WITH_RETRY" }
    elseif ($gate.MODEL_RETRY_OCCURRED) { "PASS_GATE_RETRY_INCOMPLETE" }
    else { "PASS_GATE_NO_RETRY" }
} else { "FAIL" }

$ts = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

$txt = New-Object System.Text.StringBuilder
[void]$txt.AppendLine("AGENT-TOOL-SCHEMA-002")
[void]$txt.AppendLine("frozen_from=$CaseDir")
[void]$txt.AppendLine("frozen_at_utc=$ts")
[void]$txt.AppendLine("status=$status")
[void]$txt.AppendLine("")
foreach ($k in $gate.Keys) {
    [void]$txt.AppendLine(("{0,-28} {1}" -f $k, $gate[$k]))
}
[void]$txt.AppendLine("")
[void]$txt.AppendLine("schema_reject_console=$($rejectLines.Count)")
[void]$txt.AppendLine("schema_accept_console=$($acceptLines.Count)")
[void]$txt.AppendLine("schema_validation_results=$($schemaErrors.Count)")
[void]$txt.AppendLine("dispatched_true=$($dispatchedTrue.Count)")
[void]$txt.AppendLine("dispatched_false=$($dispatchedFalse.Count)")
[void]$txt.AppendLine("before_sha=$beforeSha")
[void]$txt.AppendLine("after_sha=$afterSha")
[void]$txt.AppendLine("legacy_missing_string_arg=$($legacyMissing.Count)")

$ladderPath = Join-Path $OutRoot "AGENT_TOOL_SCHEMA_002.txt"
Set-Content -LiteralPath $ladderPath -Value $txt.ToString() -Encoding UTF8

$lock = [ordered]@{
    gate = "AGENT-TOOL-SCHEMA-002"
    status = $status
    frozen_at_utc = $ts
    source_case = $CaseDir
    hard_invariants = [ordered]@{
        SCHEMA_VALID_false_implies_TOOL_DISPATCHED_false = -not $invalidDispatched
        INVALID_ARGS_REJECTED = $gate.INVALID_ARGS_REJECTED
        VALIDATION_ERROR_TO_MODEL = $gate.VALIDATION_ERROR_TO_MODEL
    }
    metrics = $gate
    note = "No silent bare-key repair. Schema reject must not dispatch. Retry quality judged separately."
    template_hypothesis = "CLOSED"
    tool_effect_001 = "FROZEN (malformed args authority)"
}
($lock | ConvertTo-Json -Depth 6) | Set-Content -LiteralPath (Join-Path $OutRoot "AGENT-TOOL-SCHEMA-002.lock.json") -Encoding UTF8

$md = @"
# AGENT-TOOL-SCHEMA-002 — LOCK

**Status:** ``$status``
**Frozen:** $ts
**Source:** ``$CaseDir``

## Hard invariants

| Metric | Value |
| --- | --- |
$(($gate.GetEnumerator() | ForEach-Object { "| ``$($_.Key)`` | $($_.Value) |" }) -join "`n")

## Required

``````text
SCHEMA_VALID == false  =>  TOOL_DISPATCHED == false
INVALID_ARGS_REJECTED == true
VALIDATION_ERROR_TO_MODEL == true
``````

Hard gate pass: **$schemaGateHardPass**

## Artifacts

- ``AGENT_TOOL_SCHEMA_002.txt``
- Regenerator: ``scripts/FREEZE_AGENT_TOOL_SCHEMA_002.ps1``
"@
Set-Content -LiteralPath (Join-Path $OutRoot "AGENT-TOOL-SCHEMA-002.lock.md") -Value $md -Encoding UTF8

Write-Host "AGENT-TOOL-SCHEMA-002 -> $OutRoot status=$status"
Get-Content $ladderPath
if (-not $schemaGateHardPass) { exit 2 } else { exit 0 }
