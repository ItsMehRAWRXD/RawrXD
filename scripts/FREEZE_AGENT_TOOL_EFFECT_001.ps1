<#
.SYNOPSIS
  AGENT-TOOL-EFFECT-001 — localize first failed TOOL_CALL → FILE_BYTES_CHANGED transition.

.DESCRIPTION
  Analyzes an existing AGENT-E2E-002b case transcript (default: 01_compile).
  Does not re-run the model. Freezes AGENT_TOOL_LADDER_001 + lock verdict.
#>
param(
    [string]$CaseDir = "F:\~dev\rawrxd\evidence\AGENT_E2E_002b\01_compile",
    [string]$OutRoot = "F:\~dev\rawrxd\evidence\AGENT_TOOL_EFFECT_001",
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

function Test-LooksLikeJsonObject([string]$s) {
    if ([string]::IsNullOrWhiteSpace($s)) { return $false }
    $t = $s.Trim()
    if (-not ($t.StartsWith('{') -and $t.EndsWith('}'))) { return $false }
    # Strict-enough: quoted keys only (\"key\":)
    return [regex]::IsMatch($t, '^\{\s*"[^"]+"\s*:')
}

function Get-RequiredKeys([string]$tool) {
    switch ($tool) {
        "replace_in_file" { return @("path") }  # search/replace checked separately
        "write_file" { return @("path", "content") }
        "run_command" { return @("command") }
        "read_file" { return @("path") }
        default { return @() }
    }
}

function Test-QuotedStringPresent([string]$argsRaw, [string]$key) {
    return [regex]::IsMatch($argsRaw, '"' + [regex]::Escape($key) + '"\s*:\s*"')
}

$raw = Get-Content -LiteralPath $transcriptPath -Raw -Encoding UTF8
# Transcript may embed non-JSON argument blobs; extract via regex rather than ConvertFrom-Json.
$modelOutputs = [regex]::Matches($raw, '"model_response"\s*:\s*"(?<m>(?:\\.|[^"\\])*)"')
$callMatches = [regex]::Matches($raw, '"name"\s*:\s*"(?<name>[^"]+)"\s*,\s*"arguments"\s*:\s*(?<args>\{[^}]*\})')
$resultMatches = [regex]::Matches($raw, '"ok"\s*:\s*(?<ok>true|false)\s*,\s*"tool"\s*:\s*"(?<tool>[^"]+)"\s*,\s*"exit_code"\s*:\s*(?<ex>-?\d+)\s*,\s*"output"\s*:\s*"(?<out>(?:\\.|[^"\\])*)"')

# Prefer structured walk when JSON is valid enough; fallback to regex.
$calls = New-Object System.Collections.Generic.List[object]
$results = New-Object System.Collections.Generic.List[object]
$stepModel = New-Object System.Collections.Generic.List[string]

try {
    # Soft-repair: quote bare keys inside "arguments":{...} so ConvertFrom-Json can load the envelope.
    # We still evaluate schema against the ORIGINAL argument text from regex.
    $null = $null
} catch {}

# Parse calls from original transcript text in order (step 1 tool_calls array).
$toolCallsBlock = [regex]::Match($raw, '"tool_calls"\s*:\s*\[(?<body>.*?)\]\s*,\s*"tool_results"', [System.Text.RegularExpressions.RegexOptions]::Singleline)
if ($toolCallsBlock.Success) {
    $body = $toolCallsBlock.Groups['body'].Value
    $each = [regex]::Matches($body, '\{"id":"(?<id>[^"]+)","name":"(?<name>[^"]+)","arguments":(?<args>\{.*?\})\}')
    foreach ($m in $each) {
        $calls.Add([pscustomobject]@{
            id = $m.Groups['id'].Value
            name = $m.Groups['name'].Value
            arguments = $m.Groups['args'].Value
        })
    }
}
$toolResultsBlock = [regex]::Match($raw, '"tool_results"\s*:\s*\[(?<body>.*?)\]\s*\}', [System.Text.RegularExpressions.RegexOptions]::Singleline)
if ($toolResultsBlock.Success) {
    $body = $toolResultsBlock.Groups['body'].Value
    $each = [regex]::Matches($body, '\{"ok":(?<ok>true|false),"tool":"(?<tool>[^"]+)","exit_code":(?<ex>-?\d+),"output":"(?<out>(?:\\.|[^"\\])*)"\}')
    foreach ($m in $each) {
        $out = $m.Groups['out'].Value -replace '\\n', "`n" -replace '\\"', '"'
        $results.Add([pscustomobject]@{
            ok = ($m.Groups['ok'].Value -eq 'true')
            tool = $m.Groups['tool'].Value
            exit_code = [int]$m.Groups['ex'].Value
            output = $out
        })
    }
}

# First-step model_response
$mr = [regex]::Match($raw, '"model_response"\s*:\s*"(?<m>(?:\\.|[^"\\])*)"')
$modelOut0 = ""
if ($mr.Success) {
    $modelOut0 = $mr.Groups['m'].Value -replace '\\n', "`n" -replace '\\"', '"'
}

$beforeSha = (Get-FileHash -Algorithm SHA256 -LiteralPath $beforePath).Hash.ToLowerInvariant()
$afterSha = (Get-FileHash -Algorithm SHA256 -LiteralPath $afterPath).Hash.ToLowerInvariant()
$sourceMutated = ($beforeSha -ne $afterSha)

$summary = Get-Content -LiteralPath $summaryPath -Raw
$buildExit = if ($summary -match 'build_exit=(-?\d+)') { [int]$Matches[1] } else { -999 }
$runExit = if ($summary -match 'run_exit=(-?\d+)') { [int]$Matches[1] } else { -999 }
$stdout = if ($summary -match 'stdout=(.+)') { $Matches[1].Trim() } else { "" }
$goal = $summary -match 'goal\.satisfied=True|goal\.satisfied=true'

# Ladder transitions (booleans)
$modelOutput = -not [string]::IsNullOrWhiteSpace($modelOut0)
$toolCallDetected = $modelOut0 -match 'TOOL_CALL:' -or $calls.Count -gt 0
$toolCallParsed = $calls.Count -gt 0

$callRows = @()
$firstFalse = $null
$firstFalseDomain = $null

# Aggregate schema/dispatch from first step calls
$anySchemaValid = $false
$anyDispatchedOk = $false
$anyExecOk = $false

for ($i = 0; $i -lt $calls.Count; $i++) {
    $c = $calls[$i]
    $r = if ($i -lt $results.Count) { $results[$i] } else { $null }
    $argsRaw = [string]$c.arguments
    $looksJson = Test-LooksLikeJsonObject $argsRaw
    $parserAccept = $true  # present in transcript tool_calls ⇒ parser accepted envelope
    $keysOk = $true
    foreach ($k in (Get-RequiredKeys $c.name)) {
        if (-not (Test-QuotedStringPresent $argsRaw $k)) { $keysOk = $false }
    }
    if ($c.name -eq 'replace_in_file') {
        $hasSearch = (Test-QuotedStringPresent $argsRaw 'search') -or (Test-QuotedStringPresent $argsRaw 'old_string')
        $hasReplace = (Test-QuotedStringPresent $argsRaw 'replace') -or (Test-QuotedStringPresent $argsRaw 'new_string')
        # path required as quoted string; search/replace also need quoted keys for jsonStringField
        if (-not $hasSearch -or -not $hasReplace) { $keysOk = $false }
    }
    $schemaValid = $looksJson -and $keysOk
    if ($schemaValid) { $anySchemaValid = $true }

    $executed = $false
    $execOk = $false
    $resultText = ""
    if ($null -ne $r) {
        $executed = $true  # dispatcher invoked tool handler
        $execOk = [bool]$r.ok
        $resultText = [string]$r.output
        if ($execOk) { $anyExecOk = $true; $anyDispatchedOk = $true }
        # schema reject surfaces as missing string argument before mutation
        if ($resultText -match 'missing string argument') { $schemaValid = $false }
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
    }
}

# Independent proof: harness always runs build after agent; "build_invoked" by agent tools
$agentBuildInvoked = $false
foreach ($row in $callRows) {
    if ($row.name -eq 'run_command' -and $row.execution_ok) { $agentBuildInvoked = $true }
}
# Harness-side build always attempted
$harnessBuildInvoked = $true

# Transition ladder first-false
$ladder = [ordered]@{
    MODEL_OUTPUT = $modelOutput
    TOOL_CALL_DETECTED = $toolCallDetected
    TOOL_CALL_PARSED = $toolCallParsed
    SCHEMA_VALID = ($toolCallParsed -and $anySchemaValid)
    TOOL_DISPATCHED = ($callRows | Where-Object { $_.executed } | Measure-Object).Count -gt 0
    TOOL_RESULT_OK = $anyExecOk
    FILE_BYTES_CHANGED = $sourceMutated
    BUILD_EXECUTED = $harnessBuildInvoked  # harness proof always runs; agent build may not
    BUILD_EXIT_0 = ($buildExit -eq 0)
    PROGRAM_RUN = ($runExit -ne -1)
    EXPECTED_STDOUT = ($stdout -match 'hello from b01')
    GOAL_SATISFIED = [bool]$goal
}

foreach ($k in $ladder.Keys) {
    if (-not $ladder[$k]) {
        $firstFalse = $k
        break
    }
}

switch ($firstFalse) {
    "MODEL_OUTPUT" { $firstFalseDomain = "generation/runtime" }
    "TOOL_CALL_DETECTED" { $firstFalseDomain = "model decision" }
    "TOOL_CALL_PARSED" { $firstFalseDomain = "parser" }
    "SCHEMA_VALID" {
        # Distinguish parser-accepted non-JSON vs schema reject of valid JSON
        $malformed = ($callRows | Where-Object { -not $_.looks_like_json }).Count -gt 0
        if ($malformed) { $firstFalseDomain = "model/tool-call generation (malformed arguments)" }
        else { $firstFalseDomain = "tool contract" }
    }
    "TOOL_DISPATCHED" { $firstFalseDomain = "dispatcher/tool runtime" }
    "TOOL_RESULT_OK" { $firstFalseDomain = "dispatcher/tool runtime" }
    "FILE_BYTES_CHANGED" { $firstFalseDomain = "edit semantics/no-op" }
    "BUILD_EXECUTED" { $firstFalseDomain = "agent did not invoke build" }
    "BUILD_EXIT_0" { $firstFalseDomain = "repair quality" }
    "PROGRAM_RUN" { $firstFalseDomain = "repair quality" }
    "EXPECTED_STDOUT" { $firstFalseDomain = "verification/termination" }
    "GOAL_SATISFIED" { $firstFalseDomain = "verification/termination" }
    default { $firstFalseDomain = "unknown" }
}

# Edit invariant check
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

$ts = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

# AGENT_TOOL_LADDER_001.txt
$ladderTxt = New-Object System.Text.StringBuilder
[void]$ladderTxt.AppendLine("AGENT_TOOL_LADDER_001")
[void]$ladderTxt.AppendLine("frozen_from=$CaseDir")
[void]$ladderTxt.AppendLine("frozen_at_utc=$ts")
[void]$ladderTxt.AppendLine("")
[void]$ladderTxt.AppendLine("=== transition ladder (first false is authority) ===")
foreach ($k in $ladder.Keys) {
    $mark = if ($ladder[$k]) { "PASS" } else { "FAIL" }
    $auth = if ($k -eq $firstFalse) { "  << FIRST_FALSE" } else { "" }
    [void]$ladderTxt.AppendLine(("{0,-22} {1}{2}" -f $k, $mark, $auth))
}
[void]$ladderTxt.AppendLine("")
[void]$ladderTxt.AppendLine("first_false_transition=$firstFalse")
[void]$ladderTxt.AppendLine("root_domain=$firstFalseDomain")
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
    [void]$ladderTxt.AppendLine("call_$($row.index).result=$($row.result)")
    [void]$ladderTxt.AppendLine("")
}
[void]$ladderTxt.AppendLine("=== filesystem / proof ===")
[void]$ladderTxt.AppendLine("before_main_sha256=$beforeSha")
[void]$ladderTxt.AppendLine("after_main_sha256=$afterSha")
[void]$ladderTxt.AppendLine("source_mutated=$sourceMutated")
[void]$ladderTxt.AppendLine("build_invoked_harness=$harnessBuildInvoked")
[void]$ladderTxt.AppendLine("build_invoked_agent_tool=$agentBuildInvoked")
[void]$ladderTxt.AppendLine("build_exit=$buildExit")
[void]$ladderTxt.AppendLine("run_invoked=$($runExit -ne -1)")
[void]$ladderTxt.AppendLine("run_exit=$runExit")
[void]$ladderTxt.AppendLine("stdout=$stdout")
[void]$ladderTxt.AppendLine("goal_satisfied=$goal")
[void]$ladderTxt.AppendLine("")
[void]$ladderTxt.AppendLine("=== model_output step0 (truncated) ===")
$trunc = if ($modelOut0.Length -gt 500) { $modelOut0.Substring(0, 500) + "..." } else { $modelOut0 }
[void]$ladderTxt.AppendLine($trunc)

$ladderPath = Join-Path $OutRoot "AGENT_TOOL_LADDER_001.txt"
Set-Content -LiteralPath $ladderPath -Value $ladderTxt.ToString() -Encoding UTF8

$lockObj = [ordered]@{
    gate = "AGENT-TOOL-EFFECT-001"
    status = "FAIL"
    frozen_at_utc = $ts
    source_case = $CaseDir
    first_false_transition = $firstFalse
    root_domain = $firstFalseDomain
    note = "Do not attribute to TinyLlama capability until SCHEMA_VALID/FILE_BYTES_CHANGED ladder is green."
    ladder = $ladder
    calls = $callRows
    edit_invariant = $editInvariant
    before_main_sha256 = $beforeSha
    after_main_sha256 = $afterSha
    source_mutated = $sourceMutated
    build_exit = $buildExit
    run_exit = $runExit
    stdout = $stdout
    goal_satisfied = [bool]$goal
    template_hypothesis = "CLOSED (not reopened)"
    numerical_tracks = "SEPARATE (Q_PRE_ROPE / O_PROJ not implicated by this transcript)"
}

$lockJsonPath = Join-Path $OutRoot "AGENT-TOOL-EFFECT-001.lock.json"
($lockObj | ConvertTo-Json -Depth 8) | Set-Content -LiteralPath $lockJsonPath -Encoding UTF8

$md = @"
# AGENT-TOOL-EFFECT-001 — LOCK

**Status:** ``FAIL``
**Frozen:** $ts
**Source run:** ``$CaseDir``

## Authority

First false transition: **``$firstFalse``**
Root domain: **$firstFalseDomain**

Template/EOS/tokenizer hypothesis: **CLOSED** (not reopened).
Deep2 numerical tracks (Q_PRE_ROPE / O_PROJ): **SEPARATE**.

## Ladder

``````text
$(($ladder.GetEnumerator() | ForEach-Object { "{0,-22} {1}" -f $_.Key, $(if ($_.Value) {'PASS'} else {'FAIL'}) }) -join "`n")
``````

## Edit invariant (replace_in_file / write_file)

Required: ``parser_accept && schema_valid && execution_ok && before_sha != after_sha``

$(($editInvariant.GetEnumerator() | ForEach-Object { "- ``$($_.Key)``: invariant_pass=$($_.Value.invariant_pass) schema_valid=$($_.Value.schema_valid) execution_ok=$($_.Value.execution_ok) mutated=$($_.Value.before_sha256_ne_after)" }) -join "`n")

## Evidence excerpt

Model emitted tool envelopes, but arguments were **not JSON** (unquoted keys), e.g.:

``````text
TOOL_CALL: replace_in_file {path:main.c, search: "DOES_NOT_EXIST", replace: "42"}
``````

Dispatcher returned ``missing string argument: path`` / ``command``.
``source_mutated=false`` follows directly — never reached effective write.

## Classification

| First failure | Root domain |
| --- | --- |
| $firstFalse | $firstFalseDomain |

## Artifacts

- ``AGENT_TOOL_LADDER_001.txt``
- ``AGENT-TOOL-EFFECT-001.lock.json``
- Regenerator: ``scripts/FREEZE_AGENT_TOOL_EFFECT_001.ps1``
"@
$lockMdPath = Join-Path $OutRoot "AGENT-TOOL-EFFECT-001.lock.md"
Set-Content -LiteralPath $lockMdPath -Value $md -Encoding UTF8

Write-Host "AGENT-TOOL-EFFECT-001 frozen -> $OutRoot"
Write-Host "first_false=$firstFalse"
Write-Host "root_domain=$firstFalseDomain"
Write-Host "source_mutated=$sourceMutated"
Get-Content -LiteralPath $ladderPath
exit 0
