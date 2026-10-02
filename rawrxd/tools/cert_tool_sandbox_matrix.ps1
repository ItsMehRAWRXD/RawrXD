# cert_tool_sandbox_matrix.ps1
# RAWRXD_IDE_WRITE_TRANSACTIONAL_PROFILE_001 -- sandbox decision matrix
#
# Builds tools/tool_sandbox_matrix_cert.cpp against the in-tree tool authority
# and runs it over every built-in tool x every path class, then records the
# decision table.
#
# The workspace, including the junction escape_link, is built here rather than
# in the driver so that the junction is created by the same mklink /J a real
# operator would use, and removed afterwards with rmdir (which unlinks the
# junction and never touches the target).
#
# No InferenceEngine, no CMake, no shared build tree: four translation units
# compiled straight to a temp exe. The sandbox is one library; deciding whether
# a decision table needs a 1.5 GB server to be credible is a different question.
#
# RUN HISTORY IS APPEND-ONLY. Every run writes MATRIX_RUN_<stamp>.txt and one
# line into MATRIX_HISTORY.txt, and the output directory is never wiped. An
# earlier version of this script deleted the directory on entry, which destroyed
# the record of a run that had reported 5 mismatches -- three of them bugs in
# the table itself. A cert that erases its own failing runs cannot show that it
# learned anything, so the erasure is gone rather than the evidence.
#
# -Mode probe rebuilds the authority with the reparse-point check removed and
# requires the junction rows to FAIL. That is the proof this table is
# load-bearing rather than a table that always says yes.
#
# Usage
#   pwsh -File tools/cert_tool_sandbox_matrix.ps1 [-OutDir <dir>] [-Mode full|probe]

[CmdletBinding()]
param(
    [string]$OutDir = "F:\~dev\rawrxd\audit\RAWRXD_IDE_SANDBOX_MATRIX_001",
    [ValidateSet("full", "probe")]
    [string]$Mode = "full"
)

# 'Continue', not 'Stop': cl and vcvars write to stderr during a normal build
# and PowerShell turns that into a NativeCommandError under 'Stop', abandoning
# the script after the build already succeeded. Decisions here are made by the
# produced exe's exit code and by grepping its measured table, never by the
# absence of console noise.
$ErrorActionPreference = "Continue"
$repo = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
$utf8 = New-Object System.Text.UTF8Encoding($false)
$log = New-Object System.Collections.Generic.List[string]
function Say([string]$l) { Write-Host $l; $log.Add($l) | Out-Null }

# Append-only: previous runs are evidence, not litter.
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
$stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
$runDir = Join-Path $OutDir ("run_" + $stamp)
New-Item -ItemType Directory -Path $runDir -Force | Out-Null

# The verdict vocabulary, written next to the data it describes so that a reader
# (or a parser) never has to infer it from context.
#
#   CONTRACT_SATISFIED = the build under test met every stated expectation
#   CONTRACT_VIOLATED  = it did not
#   DEFECT_DETECTED    = a deliberately defective CONTROL build failed as required
#   NO_VERDICT         = the control could not be constructed; nothing was measured
#
# Bare PASS/FAIL tokens are not used anywhere in these records, for one reason:
# a probe's success IS a failure of the code it probed, so three runs reporting
# "PASS" would let an aggregate parser count two deliberately defective builds
# as successes -- or, read the other way, report a required control failure as
# an alarming gate failure.
$semantics = @(
    "# RAWRXD_IDE_SANDBOX_MATRIX_001 -- verdict semantics (see also the receipt)",
    "CONTRACT_SATISFIED = the build under test met every stated expectation",
    "CONTRACT_VIOLATED  = the build under test did not",
    "DEFECT_DETECTED    = a deliberately defective CONTROL build failed as required",
    "NO_VERDICT         = the control could not be constructed; nothing was measured",
    "mode=full  -> expect run_verdict=CONTRACT_SATISFIED",
    "mode=probe -> expect run_verdict=DEFECT_DETECTED and junction_violations>0",
    "This file is rewritten on every run; MATRIX_HISTORY.txt is append-only."
)
[System.IO.File]::WriteAllLines((Join-Path $OutDir "VERDICT_SEMANTICS.txt"), $semantics, $utf8)

# MATRIX_HISTORY.txt keeps EVERY run verbatim, including the three written before
# the vocabulary change, which still carry a bare verdict field. They are not
# rewritten -- the annotation maps them -- but a parser must not have to know
# that. So each run also REBUILDS a normalised index from the raw history,
# keeping only lines that carry an explicit run_verdict. An aggregator reads the
# index; a human reads the history. Rebuilding rather than appending means the
# two can never drift apart.
$indexPath = Join-Path $OutDir "MATRIX_HISTORY.index.txt"

$ws = Join-Path $runDir "work"
$outside = Join-Path $runDir "outside"
New-Item -ItemType Directory -Path $ws -Force | Out-Null
New-Item -ItemType Directory -Path $outside -Force | Out-Null
[System.IO.File]::WriteAllText((Join-Path $outside "secret.txt"), "RAWRXD_SHOULD_NEVER_BE_READ", $utf8)
$junction = Join-Path $ws "escape_link"
cmd /c "mklink /J `"$junction`" `"$outside`"" > $null 2>&1
if (-not (Test-Path -LiteralPath $junction)) {
    Say "SETUP=FAILED (mklink /J produced no junction) -- the junction rows would be vacuous"
    exit 1
}
Say "junction_created=$junction -> $outside"

$vcvars = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
$incs = @("$repo\include", "$repo\src", "$repo\src\agentic") | ForEach-Object { '/I' + $_ }

# Which authority source gets compiled. In probe mode it is a copy of the
# in-tree tool authority with the reparse-point check deleted, so the junction
# rows have to fail. Nothing is substituted silently: if the guard is not found
# exactly once, the probe refuses to run rather than reporting a pass.
$registrySource = "$repo\src\agentic\AgentToolRegistry.cpp"
if ($Mode -eq "probe") {
    $body = [System.IO.File]::ReadAllText($registrySource)
    $guard = [regex]::new('    if \(CrossesReparsePoint\(canonical, rootWide\.size\(\)\)\) \{\r?\n        outError = "path crosses a reparse point \(junction or link\) inside the root";\r?\n        return false;\r?\n    \}\r?\n')
    $hits = $guard.Matches($body).Count
    if ($hits -ne 1) {
        Say "PROBE_SETUP=FAILED: found $hits copies of the reparse-point guard, expected exactly 1"
        Say "NO_VERDICT_ISSUED=1"
        [System.IO.File]::AppendAllText((Join-Path $OutDir "MATRIX_HISTORY.txt"),
            "$stamp mode=probe build_role=none run_verdict=NO_VERDICT note=guard_hits_$hits`n", $utf8)
        exit 1
    }
    $registrySource = Join-Path $runDir "AgentToolRegistry.noreparse.cpp"
    [System.IO.File]::WriteAllText($registrySource, $guard.Replace($body, "", 1), $utf8)
    Say "PROBE_MODE=reparse-point guard removed from the compiled authority"
}

$exe = Join-Path $runDir "tool_sandbox_matrix_cert.exe"
$bat = @"
call "$vcvars" >nul 2>&1 && cl /nologo /EHsc /std:c++20 /O2 /MT /D_CRT_SECURE_NO_WARNINGS /DNOMINMAX /DWIN32_LEAN_AND_MEAN $($incs -join ' ') /Fe"$exe" /Fo"$runDir\\" "$repo\tools\tool_sandbox_matrix_cert.cpp" "$registrySource" "$repo\src\agentic\CommandExecutor.cpp" "$repo\src\agentic\CheckpointRollbackAuthority.cpp"
"@
$batPath = Join-Path $runDir "build.bat"
[System.IO.File]::WriteAllText($batPath, $bat, $utf8)
$buildLog = Join-Path $runDir "build.log"
cmd /c "`"$batPath`"" > $buildLog 2>&1
if (-not (Test-Path -LiteralPath $exe)) {
    Say "BUILD=FAILED"
    Get-Content -LiteralPath $buildLog | Select-Object -Last 20 | ForEach-Object { Say "  $_" }
    [System.IO.File]::AppendAllText((Join-Path $OutDir "MATRIX_HISTORY.txt"),
        "$stamp mode=$Mode build_role=none run_verdict=NO_VERDICT note=BUILD_FAILED`n", $utf8)
    exit 1
}
Say "BUILD=OK"
Say ("mode=" + $Mode)
Say ("registry_sha256=" + (Get-FileHash -LiteralPath $registrySource -Algorithm SHA256).Hash)
Say ("ckpt_sha256=" + (Get-FileHash -LiteralPath "$repo\src\agentic\CheckpointRollbackAuthority.cpp" -Algorithm SHA256).Hash)
Say ("matrix_cpp_sha256=" + (Get-FileHash -LiteralPath "$repo\tools\tool_sandbox_matrix_cert.cpp" -Algorithm SHA256).Hash)
$junctionRows = (Select-String -LiteralPath "$repo\tools\tool_sandbox_matrix_cert.cpp" -Pattern '"junction",').Count
Say ("junction_rows_in_table=" + $junctionRows)

$verdict = "CONTRACT_VIOLATED"
$buildRole = if ($Mode -eq "probe") { "control" } else { "candidate" }
try {
    $table = Join-Path $runDir "MATRIX.txt"
    & $exe $ws $buildRole > $table 2>&1
    $code = $LASTEXITCODE
    Get-Content -LiteralPath $table | ForEach-Object { Say ("  " + $_) }
    Say "cert_exit=$code"
    $text = Get-Content -LiteralPath $table -Raw
    $rows = if ($text -match 'rows=(\d+)') { $Matches[1] } else { "?" }
    $mismatches = if ($text -match 'mismatches=(\d+)') { $Matches[1] } else { "?" }
    $junctionFails = (Select-String -LiteralPath $table -Pattern '^junction' | Measure-Object).Count
    $junctionViolations = (Select-String -LiteralPath $table -Pattern 'junction .*MISMATCH' | Measure-Object).Count
    $driverVerdict = if ($text -match '_SANDBOX_MATRIX_VERDICT=(\w+)') { $Matches[1] } else { "?" }
    Say "driver_verdict=$driverVerdict"
    Say "matrix_rows=$rows"
    Say "matrix_mismatches=$mismatches"
    Say "junction_rows=$junctionRows junction_violations=$junctionViolations"

    if ($Mode -eq "probe") {
        # The probe succeeds only when the guard's absence is DETECTED: the
        # junction rows must be violated. A probe where the vulnerable build
        # still satisfied the contract would mean the table cannot see the
        # defect at all, and "no violations" must never be reported as a pass.
        $detected = ($junctionViolations -ge 1) -and ($mismatches -ge 1) -and ($code -ne 0)
        $verdict = if ($detected) { "DEFECT_DETECTED" } else { "CONTRACT_VIOLATED" }
        Say ("PROBE_DETECTED_THE_DEFECT=" + $detected)
        Say ("JUNCTION_ROWS_WENT_FROM_REFUSE_TO_" + $(if ($detected) { "ACCEPT_WITHOUT_THE_GUARD" } else { "STILL_REFUSED" }))
    }
    else {
        $verdict = if ($code -eq 0 -and $mismatches -eq "0" -and $driverVerdict -eq "CONTRACT_SATISFIED") {
            "CONTRACT_SATISFIED"
        } else { "CONTRACT_VIOLATED" }
    }
    # The label carries the role so the two kinds of run are never conflated,
    # even by eye.
    $label = if ($Mode -eq "probe") {
        "RAWRXD_IDE_WRITE_TRANSACTIONAL_PROFILE_001_SANDBOX_MATRIX_PROBE"
    } else {
        "RAWRXD_IDE_WRITE_TRANSACTIONAL_PROFILE_001_SANDBOX_MATRIX"
    }
    Say "$label=$verdict"
}
finally {
    cmd /c "rmdir `"$junction`"" > $null 2>&1
    Say "junction_removed=$(-not (Test-Path -LiteralPath $junction))"
    # rmdir on a junction unlinks the link. If the target's contents are gone,
    # rmdir followed the link and deleted a real directory: that would make the
    # junction escape test destructive, so the check is that the target SURVIVES.
    if (Test-Path -LiteralPath (Join-Path $outside "secret.txt")) {
        Say "JUNCTION_RMDIR_CHECK=PASS (target directory and its contents left intact)"
    }
    else {
        Say "JUNCTION_RMDIR_CHECK=FAIL (rmdir followed the junction and deleted the target)"
        $verdict = "CONTRACT_VIOLATED"
    }
}

[System.IO.File]::WriteAllText((Join-Path $runDir "MATRIX_LOG.txt"), ($log -join [Environment]::NewLine), $utf8)
$historyLine = "$stamp mode=$Mode build_role=$buildRole rows=$rows mismatches=$mismatches junction_violations=$junctionViolations run_verdict=$verdict"
$historyPath = Join-Path $OutDir "MATRIX_HISTORY.txt"
[System.IO.File]::AppendAllText($historyPath, ($historyLine + "`n"), $utf8)

# Rebuild the parser surface from the raw history. Lines without run_verdict=
# are pre-vocabulary runs; they are counted here rather than silently dropped,
# so the gap between the two files is always visible.
#
# legacy_lines_excluded is MANDATORY. It is not decoration: a future harness
# regression that starts emitting old-format records again would raise this
# number, and a raised number is the only signal a consumer of the index would
# otherwise never get. The count is compared against a stored baseline, and a
# run that cannot compute it at all is a CONTRACT_VIOLATED run rather than a run
# that quietly produced an index nobody can trust.
$allHistory = @(Get-Content -LiteralPath $historyPath)
$normalised = @($allHistory | Where-Object { $_ -match 'run_verdict=' })
$legacyCount = $allHistory.Count - $normalised.Count
$baselinePath = Join-Path $OutDir "LEGACY_BASELINE.txt"
$previousLegacy = $null
if (Test-Path -LiteralPath $baselinePath) {
    $raw = (Get-Content -LiteralPath $baselinePath -Raw).Trim()
    if ($raw -match '^\d+$') { $previousLegacy = [int]$raw }
}
$indexFieldOk = ($legacyCount -ge 0) -and ($null -ne $legacyCount)
if (-not $indexFieldOk) {
    Say "INDEX_FIELD_MISSING=1 (legacy_lines_excluded could not be computed)"
    $verdict = "CONTRACT_VIOLATED"
}
# A missing baseline means there is nothing to compare against yet, which is a
# different thing from a count that grew. The first run establishes the baseline
# and says so; only a genuinely larger count is a regression signal. Reporting an
# increase against an absent baseline would make the alarm fire on every fresh
# checkout, and an alarm that always fires is an alarm nobody reads.
if ($null -eq $previousLegacy) {
    Say "legacy_lines_excluded=$legacyCount baseline_established=1 (no prior baseline to compare)"
}
else {
    Say "legacy_lines_excluded=$legacyCount previous_baseline=$previousLegacy"
    if ($legacyCount -gt $previousLegacy) {
        Say "LEGACY_COUNT_INCREASED=1 (records appeared in the old format -- harness regression)"
    }
}
[System.IO.File]::WriteAllText($baselinePath, "$legacyCount`n", $utf8)
$indexLines = @(
    "# Normalised run index. Parser surface: every line carries run_verdict=.",
    "# Rebuilt from MATRIX_HISTORY.txt on each run; not independently appended.",
    "# Verdict vocabulary: CONTRACT_SATISFIED | CONTRACT_VIOLATED | DEFECT_DETECTED | NO_VERDICT",
    "# A probe's success is a FAILURE of the code it probed, so DEFECT_DETECTED is",
    "# the correct outcome for a control build and must never be read as a success.",
    "# legacy_lines_excluded=$legacyCount (pre-vocabulary; see MATRIX_HISTORY_ANNOTATION.txt)"
) + $normalised
[System.IO.File]::WriteAllLines($indexPath, $indexLines, $utf8)
Say "history_appended=MATRIX_HISTORY.txt"
Say "index_rebuilt=MATRIX_HISTORY.index.txt runs=$($normalised.Count) legacy_excluded=$legacyCount"
if ($verdict -ne "CONTRACT_SATISFIED" -and $verdict -ne "DEFECT_DETECTED") { exit 1 }
exit 0
