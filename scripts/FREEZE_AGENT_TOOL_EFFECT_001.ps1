<#
.SYNOPSIS
  AGENT-TOOL-EFFECT-001 — localize first failed agent-tool transition.

.DESCRIPTION
  Analyzes an existing AGENT-E2E-002b case transcript (default: 01_compile).
  Does not re-run the model. Freezes AGENT_TOOL_LADDER_001 + lock verdict.

  CRITICAL (re-freeze 2026-08-29):
    - TOOL_RESULT_OK requires EVERY executed tool to be execution_ok
      (not "any succeeded").
    - BUILD_AGENT_* and BUILD_HARNESS_* are separate dimensions.
    - Harness build/run SUCCESS must NEVER promote agent BUILD_* to PASS.
    - Unsupported success claims after tool failure are flagged separately.
#>
param(
    [string]$CaseDir = "F:\~dev\rawrxd\evidence\AGENT_E2E_002b\01_compile",
    [string]$OutRoot = "F:\~dev\rawrxd\evidence\AGENT_TOOL_EFFECT_001",
    [string]$SourceName = "main.c",
    [string]$ExpectedStdoutPattern = "hello from b01"
)

$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path $OutRoot | Out-Null

$transcriptPath = Join-Path $CaseDir "RAWRXD_AGENT_TRANSCRIPT.json"
$summaryPath = Join-Path $CaseDir "RUN_SUMMARY.txt"
$beforePath = Join-Path $CaseDir "workspace_before\$SourceName"
$afterPath = Join-Path $CaseDir "workspace_after\$SourceName"

foreach ($p in @($transcriptPath, $summaryPath, $beforePath, $afterPath)) {
    if (-not (Test-Path -LiteralPath $p)) { throw "missing $p" }
}

function Test-LooksLikeJsonObject([string]$s) {
    if ([string]::IsNullOrWhiteSpace($s)) { return $false }
    $t = $s.Trim()
    if (-not ($t.StartsWith('{') -and $t.EndsWith('}'))) { return $false }
    return [regex]::IsMatch($t, '^\{\s*"[^"]+"\s*:')
}

function Get-RequiredKeys([string]$tool) {
    switch ($tool) {
        "replace_in_file" { return @("path") }
        "write_file" { return @("path", "content") }
        "run_command" { return @("command") }
        "read_file" { return @("path") }
        default { return @() }
    }
}

function Test-QuotedStringPresent([string]$argsRaw, [string]$key) {
    return [regex]::IsMatch($argsRaw, '"' + [regex]::Escape($key) + '"\s*:\s*"')
}

function Test-IsBuildCommand([string]$argsRaw) {
    # Match cmake --build / ninja / msbuild in command=... whether quoted or bare.
    return [regex]::IsMatch($argsRaw,
        '(?i)(cmake\s+--build|[/\\]ninja(\.exe)?(\s|$)|[/\\]msbuild(\.exe)?(\s|$)|(^|[\s:"''])ninja(\.exe)?(\s|$)|(^|[\s:"''])msbuild(\.exe)?(\s|$))')
}

function Get-Mark($value, [string]$actor = "agent") {
    if ($null -eq $value) { return "N/A" }
    if ($value -is [string]) { return $value }
    if ($value) {
        if ($actor -eq "harness") { return "HARNESS_PASS" }
        return "PASS"
    }
    if ($actor -eq "harness") { return "HARNESS_FAIL" }
    return "FAIL"
}

$raw = Get-Content -LiteralPath $transcriptPath -Raw -Encoding UTF8

$calls = New-Object System.Collections.Generic.List[object]
$results = New-Object System.Collections.Generic.List[object]

$toolCallsBlock = [regex]::Match($raw, '"tool_calls"\s*:\s*\[(?<body>.*?)\]\s*,\s*"tool_results"', [System.Text.RegularExpressions.RegexOptions]::Singleline)
if ($toolCallsBlock.Success) {
    $body = $toolCallsBlock.Groups['body'].Value
    $each = [regex]::Matches($body, '\{"id":"(?<id>[^"]+)","name":"(?<name>[^"]+)","arguments":(?<args>\{.*?\}|"(?:\\.|[^"\\])*")\}')
    foreach ($m in $each) {
        $argsText = $m.Groups['args'].Value
        if ($argsText.StartsWith('"')) {
            $argsText = $argsText.Substring(1, $argsText.Length - 2) -replace '\\"', '"' -replace '\\n', "`n"
        }
        $calls.Add([pscustomobject]@{
            id = $m.Groups['id'].Value
            name = $m.Groups['name'].Value
            arguments = $argsText
        })
    }
}

$toolResultsBlock = [regex]::Match($raw, '"tool_results"\s*:\s*\[(?<body>.*?)\]\s*\}', [System.Text.RegularExpressions.RegexOptions]::Singleline)
if ($toolResultsBlock.Success) {
    $body = $toolResultsBlock.Groups['body'].Value
    $each = [regex]::Matches($body, '\{"ok":(?<ok>true|false),"tool":"(?<tool>[^"]+)","exit_code":(?<ex>-?\d+),"dispatched":(?<disp>true|false),"output":"(?<out>(?:\\.|[^"\\])*)"(?<rest>.*?)\}')
    if ($each.Count -eq 0) {
        $each = [regex]::Matches($body, '\{"ok":(?<ok>true|false),"tool":"(?<tool>[^"]+)","exit_code":(?<ex>-?\d+),"output":"(?<out>(?:\\.|[^"\\])*)"\}')
    }
    foreach ($m in $each) {
        $out = $m.Groups['out'].Value -replace '\\n', "`n" -replace '\\"', '"'
        $disp = $true
        if ($m.Groups['disp'].Success -and $m.Groups['disp'].Value -ne '') {
            $disp = ($m.Groups['disp'].Value -eq 'true')
        }
        $err = ''
        if ($m.Groups['rest'].Success) {
            $em = [regex]::Match($m.Groups['rest'].Value, '"error":"(?<e>[^"]+)"')
            if ($em.Success) { $err = $em.Groups['e'].Value }
        }
        $results.Add([pscustomobject]@{
            ok = ($m.Groups['ok'].Value -eq 'true')
            tool = $m.Groups['tool'].Value
            exit_code = [int]$m.Groups['ex'].Value
            output = $out
            dispatched = $disp
            error = $err
        })
    }
}

# Collect ALL model_response blobs (success claims may appear after tools).
$modelChunks = New-Object System.Collections.Generic.List[string]
foreach ($m in [regex]::Matches($raw, '"model_response"\s*:\s*"(?<m>(?:\\.|[^"\\])*)"')) {
    $chunk = $m.Groups['m'].Value -replace '\\n', "`n" -replace '\\"', '"'
    $modelChunks.Add($chunk)
}
$modelOut0 = if ($modelChunks.Count -gt 0) { $modelChunks[0] } else { "" }
$modelAll = ($modelChunks -join "`n")

$beforeSha = (Get-FileHash -Algorithm SHA256 -LiteralPath $beforePath).Hash.ToLowerInvariant()
$afterSha = (Get-FileHash -Algorithm SHA256 -LiteralPath $afterPath).Hash.ToLowerInvariant()
$sourceMutated = ($beforeSha -ne $afterSha)

$summary = Get-Content -LiteralPath $summaryPath -Raw
$buildExit = if ($summary -match 'build_exit=(-?\d+)') { [int]$Matches[1] } else { -999 }
$runExit = if ($summary -match 'run_exit=(-?\d+)') { [int]$Matches[1] } else { -999 }
$stdout = if ($summary -match 'stdout=(.+)') { $Matches[1].Trim() } else { "" }
$goal = $summary -match 'goal\.satisfied=True|goal\.satisfied=true'
$harnessBuildInvoked = $true  # AGENT-E2E-002b harness always attempts proof build after agent

# --- Per-call rows ---
$callRows = @()
$anySchemaValid = $false

for ($i = 0; $i -lt $calls.Count; $i++) {
    $c = $calls[$i]
    $r = if ($i -lt $results.Count) { $results[$i] } else { $null }
    $argsRaw = [string]$c.arguments
    $looksJson = Test-LooksLikeJsonObject $argsRaw
    $parserAccept = $true
    $keysOk = $true
    foreach ($k in (Get-RequiredKeys $c.name)) {
        if (-not (Test-QuotedStringPresent $argsRaw $k)) { $keysOk = $false }
    }
    if ($c.name -eq 'replace_in_file') {
        $hasSearch = (Test-QuotedStringPresent $argsRaw 'search') -or (Test-QuotedStringPresent $argsRaw 'old_string')
        $hasReplace = (Test-QuotedStringPresent $argsRaw 'replace') -or (Test-QuotedStringPresent $argsRaw 'new_string')
        if (-not $hasSearch -or -not $hasReplace) { $keysOk = $false }
    }
    $schemaValid = $looksJson -and $keysOk
    $runtimeSchemaOk = $false
    if ($null -ne $r) {
        if ($r.PSObject.Properties.Name -contains 'dispatched' -and $r.dispatched -and
            (-not ($r.PSObject.Properties.Name -contains 'error' -and $r.error -eq 'schema_validation'))) {
            $runtimeSchemaOk = $true
            $schemaValid = $true
        }
        if ($r.PSObject.Properties.Name -contains 'error' -and $r.error -eq 'schema_validation') {
            $schemaValid = $false
            $runtimeSchemaOk = $false
        }
    }
    if ($schemaValid) { $anySchemaValid = $true }

    $executed = $false
    $execOk = $false
    $resultText = ""
    if ($null -ne $r) {
        $executed = if ($r.PSObject.Properties.Name -contains 'dispatched') { [bool]$r.dispatched } else { $true }
        $execOk = [bool]$r.ok
        $resultText = [string]$r.output
        if ($resultText -match 'missing string argument' -and -not $runtimeSchemaOk) { $schemaValid = $false }
    }

    $callRows += [pscustomobject]@{
        index = $i
        name = $c.name
        arguments = $argsRaw
        parser_accept = $parserAccept
        looks_like_json = $looksJson
        schema_valid = $schemaValid
        executed = $executed
        execution_ok = $execOk
        result = $resultText
        is_build_command = (($c.name -eq 'run_command') -and (Test-IsBuildCommand $argsRaw))
    }
}

# --- Actor-separated build dimensions ---
$buildAgentCalls = @($callRows | Where-Object { $_.is_build_command })
$buildAgentCall = if ($buildAgentCalls.Count -gt 0) { $buildAgentCalls[-1] } else { $null }
$buildInvokedAgentTool = $null -ne $buildAgentCall
$buildAgentExit0 = $buildInvokedAgentTool -and $buildAgentCall.execution_ok

$buildHarnessInvoked = $harnessBuildInvoked
$buildHarnessExit0 = ($buildExit -eq 0)

# TOOL_RESULT_OK: EVERY executed tool must succeed (not "any succeeded").
$executedCalls = @($callRows | Where-Object { $_.executed })
$failedExecuted = @($executedCalls | Where-Object { -not $_.execution_ok })
$toolResultOk = ($executedCalls.Count -gt 0) -and ($failedExecuted.Count -eq 0)

# Unsupported success claim: model claims compile/build success while agent build failed
# or any executed tool failed.
$successClaimRx = '(?i)(successfully\s+compiled|compiled\s+and\s+built|build(ing)?\s+succeed|executable\s+\w+\s+(was\s+)?built)'
$unsupportedSuccessClaim = $false
if (($failedExecuted.Count -gt 0 -or -not $buildAgentExit0) -and
    ($modelAll -match $successClaimRx)) {
    $unsupportedSuccessClaim = $true
}
# Stronger: if agent build explicitly failed and claim present → always flag.
if ($buildInvokedAgentTool -and -not $buildAgentExit0 -and ($modelAll -match $successClaimRx)) {
    $unsupportedSuccessClaim = $true
}

$modelOutput = -not [string]::IsNullOrWhiteSpace($modelOut0)
$toolCallDetected = $modelOut0 -match 'TOOL_CALL:' -or $calls.Count -gt 0
$toolCallParsed = $calls.Count -gt 0

# Agent-authority ladder (first-false authority). Harness facts are separate.
$ladder = [ordered]@{
    MODEL_OUTPUT           = $modelOutput
    TOOL_CALL_DETECTED     = $toolCallDetected
    TOOL_CALL_PARSED       = $toolCallParsed
    SCHEMA_VALID           = ($toolCallParsed -and $anySchemaValid)
    TOOL_DISPATCHED        = ($executedCalls.Count -gt 0)
    TOOL_RESULT_OK         = $toolResultOk
    FILE_BYTES_CHANGED     = $sourceMutated
    BUILD_AGENT_INVOKED    = $buildInvokedAgentTool
    BUILD_AGENT_EXIT_0     = $buildAgentExit0
}

# Harness-only dimensions (never promote agent ladder).
$harness = [ordered]@{
    BUILD_HARNESS_INVOKED  = $buildHarnessInvoked
    BUILD_HARNESS_EXIT_0   = $buildHarnessExit0
    PROGRAM_RUN            = ($runExit -ne -1 -and $runExit -ne -999)
    EXPECTED_STDOUT        = ($stdout -match $ExpectedStdoutPattern)
    GOAL_SATISFIED         = [bool]$goal
}

$firstFalse = $null
$firstFalseDomain = $null
foreach ($k in $ladder.Keys) {
    if (-not $ladder[$k]) {
        $firstFalse = $k
        break
    }
}

switch ($firstFalse) {
    "MODEL_OUTPUT"           { $firstFalseDomain = "generation/runtime" }
    "TOOL_CALL_DETECTED"     { $firstFalseDomain = "model decision" }
    "TOOL_CALL_PARSED"       { $firstFalseDomain = "parser" }
    "SCHEMA_VALID" {
        $malformed = ($callRows | Where-Object { -not $_.looks_like_json }).Count -gt 0
        if ($malformed) { $firstFalseDomain = "model/tool-call generation (malformed arguments)" }
        else { $firstFalseDomain = "tool contract" }
    }
    "TOOL_DISPATCHED"        { $firstFalseDomain = "dispatcher/tool runtime" }
    "TOOL_RESULT_OK"         { $firstFalseDomain = "AGENT_TOOL_EXECUTION" }
    "FILE_BYTES_CHANGED"     { $firstFalseDomain = "edit semantics/no-op" }
    "BUILD_AGENT_INVOKED"    { $firstFalseDomain = "AGENT_TOOL_EXECUTION" }
    "BUILD_AGENT_EXIT_0"     { $firstFalseDomain = "AGENT_TOOL_EXECUTION" }
    default                  { $firstFalseDomain = "unknown" }
}

$editInvariant = [ordered]@{}
foreach ($row in $callRows) {
    if ($row.name -in @('replace_in_file', 'write_file')) {
        $editInvariant["call_$($row.index)"] = [ordered]@{
            tool = $row.name
            parser_accept = $row.parser_accept
            schema_valid = $row.schema_valid
            execution_ok = $row.execution_ok
            before_sha256_ne_after = $sourceMutated
            invariant_pass = ($row.parser_accept -and $row.schema_valid -and $row.execution_ok -and $sourceMutated)
        }
    }
}

$agentRepairEffect = $sourceMutated -and (
    (@($callRows | Where-Object {
        $_.name -in @('replace_in_file', 'write_file') -and $_.execution_ok
    })).Count -gt 0
)
$agentBuildEffect = $buildAgentExit0
$gateStatus = if ($null -eq $firstFalse) { "PASS" } else { "FAIL" }

$ts = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

# --- Ladder text ---
$ladderTxt = New-Object System.Text.StringBuilder
[void]$ladderTxt.AppendLine("AGENT_TOOL_LADDER_001")
[void]$ladderTxt.AppendLine("frozen_from=$CaseDir")
[void]$ladderTxt.AppendLine("frozen_at_utc=$ts")
[void]$ladderTxt.AppendLine("authority_rule=agent_transitions_only; harness_never_promotes_agent_PASS")
[void]$ladderTxt.AppendLine("")
[void]$ladderTxt.AppendLine("=== agent transition ladder (first false is authority) ===")
foreach ($k in $ladder.Keys) {
    $mark = Get-Mark $ladder[$k] "agent"
    $auth = if ($k -eq $firstFalse) { "  << FIRST_FALSE" } else { "" }
    [void]$ladderTxt.AppendLine(("{0,-24} {1}{2}" -f $k, $mark, $auth))
}
[void]$ladderTxt.AppendLine("")
[void]$ladderTxt.AppendLine("=== harness-only dimensions (NOT agent authority) ===")
foreach ($k in $harness.Keys) {
    $mark = Get-Mark $harness[$k] "harness"
    [void]$ladderTxt.AppendLine(("{0,-24} {1}" -f $k, $mark))
}
[void]$ladderTxt.AppendLine("")
[void]$ladderTxt.AppendLine("first_false_transition=$firstFalse")
[void]$ladderTxt.AppendLine("root_domain=$firstFalseDomain")
[void]$ladderTxt.AppendLine("UNSUPPORTED_SUCCESS_CLAIM=$unsupportedSuccessClaim")
[void]$ladderTxt.AppendLine("")
[void]$ladderTxt.AppendLine("=== separated effects ===")
[void]$ladderTxt.AppendLine("AGENT_REPAIR_EFFECT.source_mutated=$sourceMutated")
[void]$ladderTxt.AppendLine("AGENT_REPAIR_EFFECT.pass=$agentRepairEffect")
[void]$ladderTxt.AppendLine("AGENT_BUILD_EFFECT.invoked=$buildInvokedAgentTool")
[void]$ladderTxt.AppendLine("AGENT_BUILD_EFFECT.exit_0=$buildAgentExit0")
[void]$ladderTxt.AppendLine("AGENT_BUILD_EFFECT.pass=$agentBuildEffect")
[void]$ladderTxt.AppendLine("HARNESS_BUILD_VERIFICATION.invoked=$buildHarnessInvoked")
[void]$ladderTxt.AppendLine("HARNESS_BUILD_VERIFICATION.exit_0=$buildHarnessExit0")
[void]$ladderTxt.AppendLine("RESULTING_PROGRAM_CORRECT=$($harness.EXPECTED_STDOUT -and $harness.PROGRAM_RUN)")
[void]$ladderTxt.AppendLine("")
[void]$ladderTxt.AppendLine("=== calls ===")
foreach ($row in $callRows) {
    [void]$ladderTxt.AppendLine("call_$($row.index).name=$($row.name)")
    [void]$ladderTxt.AppendLine("call_$($row.index).arguments=$($row.arguments)")
    [void]$ladderTxt.AppendLine("call_$($row.index).parser_accept=$($row.parser_accept)")
    [void]$ladderTxt.AppendLine("call_$($row.index).looks_like_json=$($row.looks_like_json)")
    [void]$ladderTxt.AppendLine("call_$($row.index).schema_valid=$($row.schema_valid)")
    [void]$ladderTxt.AppendLine("call_$($row.index).executed=$($row.executed)")
    [void]$ladderTxt.AppendLine("call_$($row.index).execution_ok=$($row.execution_ok)")
    [void]$ladderTxt.AppendLine("call_$($row.index).is_build_command=$($row.is_build_command)")
    [void]$ladderTxt.AppendLine("call_$($row.index).result=$($row.result)")
    [void]$ladderTxt.AppendLine("")
}
[void]$ladderTxt.AppendLine("=== filesystem / proof ===")
[void]$ladderTxt.AppendLine("before_main_sha256=$beforeSha")
[void]$ladderTxt.AppendLine("after_main_sha256=$afterSha")
[void]$ladderTxt.AppendLine("source_mutated=$sourceMutated")
[void]$ladderTxt.AppendLine("build_invoked_agent_tool=$buildInvokedAgentTool")
[void]$ladderTxt.AppendLine("build_agent_exit_0=$buildAgentExit0")
[void]$ladderTxt.AppendLine("build_invoked_harness=$buildHarnessInvoked")
[void]$ladderTxt.AppendLine("build_harness_exit=$buildExit")
[void]$ladderTxt.AppendLine("run_invoked=$($runExit -ne -1 -and $runExit -ne -999)")
[void]$ladderTxt.AppendLine("run_exit=$runExit")
[void]$ladderTxt.AppendLine("stdout=$stdout")
[void]$ladderTxt.AppendLine("goal_satisfied_harness=$goal")
[void]$ladderTxt.AppendLine("")
[void]$ladderTxt.AppendLine("=== model_output (truncated; all chunks scanned for claims) ===")
$trunc = if ($modelAll.Length -gt 800) { $modelAll.Substring(0, 800) + "..." } else { $modelAll }
[void]$ladderTxt.AppendLine($trunc)

$ladderPath = Join-Path $OutRoot "AGENT_TOOL_LADDER_001.txt"
Set-Content -LiteralPath $ladderPath -Value $ladderTxt.ToString() -Encoding UTF8

$lockObj = [ordered]@{
    gate = "AGENT-TOOL-EFFECT-001"
    status = $gateStatus
    frozen_at_utc = $ts
    source_case = $CaseDir
    first_false_transition = $firstFalse
    root_domain = $firstFalseDomain
    note = "Agent BUILD_* must never inherit harness BUILD_* PASS. TOOL_RESULT_OK requires all executed tools ok."
    authority_rule = "agent_transitions_only; harness_never_promotes_agent_PASS"
    ladder_agent = $ladder
    ladder_harness = $harness
    effects = [ordered]@{
        AGENT_REPAIR_EFFECT = $agentRepairEffect
        AGENT_BUILD_EFFECT = $agentBuildEffect
        HARNESS_BUILD_VERIFICATION = $buildHarnessExit0
        RESULTING_PROGRAM_CORRECT = ($harness.EXPECTED_STDOUT -and $harness.PROGRAM_RUN)
        UNSUPPORTED_SUCCESS_CLAIM = $unsupportedSuccessClaim
    }
    calls = $callRows
    edit_invariant = $editInvariant
    before_main_sha256 = $beforeSha
    after_main_sha256 = $afterSha
    source_mutated = $sourceMutated
    build_invoked_agent_tool = $buildInvokedAgentTool
    build_agent_exit_0 = $buildAgentExit0
    build_invoked_harness = $buildHarnessInvoked
    build_harness_exit = $buildExit
    run_exit = $runExit
    stdout = $stdout
    goal_satisfied_harness = [bool]$goal
    template_hypothesis = "CLOSED (not reopened)"
    numerical_tracks = "SEPARATE (Q_PRE_ROPE / O_PROJ not implicated by this transcript)"
    case_04_disposition = "NOT_ESTABLISHED_BY_THIS_FREEZE"
}

$lockJsonPath = Join-Path $OutRoot "AGENT-TOOL-EFFECT-001.lock.json"
($lockObj | ConvertTo-Json -Depth 8) | Set-Content -LiteralPath $lockJsonPath -Encoding UTF8

$agentLadderLines = ($ladder.GetEnumerator() | ForEach-Object {
    "{0,-24} {1}" -f $_.Key, (Get-Mark $_.Value "agent")
}) -join "`n"
$harnessLadderLines = ($harness.GetEnumerator() | ForEach-Object {
    "{0,-24} {1}" -f $_.Key, (Get-Mark $_.Value "harness")
}) -join "`n"

$md = @"
# AGENT-TOOL-EFFECT-001 — LOCK

**Status:** ``$gateStatus``
**Frozen:** $ts
**Source run:** ``$CaseDir``

## Authority

First false transition: **``$firstFalse``**
Root domain: **$firstFalseDomain**

```text
SOURCE_MUTATION                = $(if ($sourceMutated) {'PASS'} else {'FAIL'})
AGENT_BUILD_EXECUTION          = $(if ($agentBuildEffect) {'PASS'} else {'FAIL'})
HARNESS_BUILD_VERIFICATION     = $(if ($buildHarnessExit0) {'PASS'} else {'FAIL'})
RESULTING_PROGRAM_CORRECT      = $(if ($harness.EXPECTED_STDOUT -and $harness.PROGRAM_RUN) {'PASS'} else {'FAIL'})
UNSUPPORTED_SUCCESS_CLAIM      = $(if ($unsupportedSuccessClaim) {'DETECTED'} else {'ABSENT'})
```

Template/EOS/tokenizer hypothesis: **CLOSED** (not reopened).
Deep2 numerical tracks (Q_PRE_ROPE / O_PROJ): **SEPARATE**.
Case ``04_logic_bug`` disposition: **NOT established by this freeze** (evidence is ``01_compile`` only).

## Agent ladder (authority)

``````text
$agentLadderLines
``````

## Harness-only ladder (verification; must not promote agent PASS)

``````text
$harnessLadderLines
``````

## Classification

| Fact | Value |
| --- | --- |
| First failure | $firstFalse |
| Root domain | $firstFalseDomain |
| Agent repaired source | $agentRepairEffect |
| Agent build exit 0 | $buildAgentExit0 |
| Harness build exit 0 | $buildHarnessExit0 |
| Unsupported success claim | $unsupportedSuccessClaim |

## Invariant

``````text
tool failure
    → success claim forbidden

external harness later verifies success
    → harness may establish verified result
    → does NOT retroactively make the earlier agent claim valid
    → does NOT set BUILD_AGENT_EXIT_0 = PASS
``````

## Artifacts

- ``AGENT_TOOL_LADDER_001.txt``
- ``AGENT-TOOL-EFFECT-001.lock.json``
- Regenerator: ``scripts/FREEZE_AGENT_TOOL_EFFECT_001.ps1``
"@
$lockMdPath = Join-Path $OutRoot "AGENT-TOOL-EFFECT-001.lock.md"
Set-Content -LiteralPath $lockMdPath -Value $md -Encoding UTF8

Write-Host "AGENT-TOOL-EFFECT-001 re-frozen -> $OutRoot"
Write-Host "status=$gateStatus"
Write-Host "first_false=$firstFalse"
Write-Host "root_domain=$firstFalseDomain"
Write-Host "TOOL_RESULT_OK=$toolResultOk"
Write-Host "build_invoked_agent_tool=$buildInvokedAgentTool build_agent_exit_0=$buildAgentExit0"
Write-Host "build_harness_exit_0=$buildHarnessExit0"
Write-Host "UNSUPPORTED_SUCCESS_CLAIM=$unsupportedSuccessClaim"
Write-Host "source_mutated=$sourceMutated"
Get-Content -LiteralPath $ladderPath
exit $(if ($gateStatus -eq 'PASS') { 0 } else { 1 })
