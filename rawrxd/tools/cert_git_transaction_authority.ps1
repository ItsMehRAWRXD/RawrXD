# cert_git_transaction_authority.ps1
#   RAWRXD_GIT_TRANSACTION_AUTHORITY_001
#
# Builds tools/git_transaction_gate_driver.cpp against the in-tree tool
# authority and the real git-safety authority, then runs it against a REAL git
# repository created inside the scratch directory. Nothing is asserted from
# source reading: every gate condition is decided by observing repository state
# (HEAD, porcelain status, branch, index tree) and the checkpoint counters.
#
# G0..G13 are measured by the driver. G14/G15 are this script's job:
#   -Mode control  rebuilds the SAME driver against a copy of
#   AgentToolRegistry.cpp with the transaction gate removed, and requires G4 to
#   be DETECTED. The control's verdict is reported as
#   CONTRACT_VIOLATED + DEFECT_DETECTED, never as a bare failure, because a
#   probe's success is a failure of the code it probed.
#
# Append-only: every run writes run_<UTC stamp>/ and one line into
# GIT_GATE_HISTORY.txt, and the index is rebuilt from it. A later passing run
# cannot erase an earlier failing one.
#
# Usage
#   pwsh -File tools/cert_git_transaction_authority.ps1 [-Mode candidate|control] [-OutDir <dir>]

[CmdletBinding()]
param(
    [string]$OutDir = "F:\~dev\rawrxd\audit\RAWRXD_GIT_TRANSACTION_AUTHORITY_001",
    [ValidateSet("candidate", "control")]
    [string]$Mode = "candidate"
)

# 'Continue', not 'Stop': cl writes to stderr during a normal build and
# PowerShell turns that into a NativeCommandError under 'Stop', abandoning the
# script after the build already succeeded.
$ErrorActionPreference = "Continue"
$repo = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
$utf8 = New-Object System.Text.UTF8Encoding($false)
$log = New-Object System.Collections.Generic.List[string]
function Say([string]$l) { Write-Host $l; $log.Add($l) | Out-Null }

$semantics = @(
    "# RAWRXD_GIT_TRANSACTION_AUTHORITY_001 -- verdict semantics",
    "CONTRACT_SATISFIED = the build under test met every stated gate condition",
    "CONTRACT_VIOLATED  = it did not",
    "DEFECT_DETECTED    = a deliberately defective CONTROL build failed as required",
    "NO_VERDICT         = the control could not be constructed; nothing was measured",
    "mode=candidate -> expect run_verdict=CONTRACT_SATISFIED",
    "mode=control   -> expect run_verdict=DEFECT_DETECTED and G4 not met"
)
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
[System.IO.File]::WriteAllLines((Join-Path $OutDir "VERDICT_SEMANTICS.txt"), $semantics, $utf8)

$stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
$runDir = Join-Path $OutDir ("run_" + $stamp)
New-Item -ItemType Directory -Path $runDir -Force | Out-Null
$ws = Join-Path $runDir "ws"
New-Item -ItemType Directory -Path $ws -Force | Out-Null

# ---- which registry source gets compiled ----------------------------------
#
# The control removes exactly the transaction gate and nothing else. Extraction
# is by INDEX rather than by regex: a regex that fails to match would silently
# produce a control identical to the candidate, and the probe would then "pass"
# while proving nothing. Index arithmetic makes a miss an explicit failure.
$registrySource = Join-Path $repo "src\agentic\AgentToolRegistry.cpp"
$gateStartMarker = "    if (policy.writeRequiresTransaction && IsTransactionRequired"
if ($Mode -eq "control") {
    $body = [System.IO.File]::ReadAllText($registrySource)
    $start = $body.IndexOf($gateStartMarker)
    $startCount = ([regex]::Matches($body, [regex]::Escape($gateStartMarker))).Count
    if ($start -lt 0 -or $startCount -ne 1) {
        Say "PROBE_SETUP=FAILED: gate marker found $startCount times, expected exactly 1"
        Say "run_verdict=NO_VERDICT (a control that cannot remove the guard proves nothing)"
        [System.IO.File]::AppendAllText((Join-Path $OutDir "GIT_GATE_HISTORY.txt"),
            "$stamp mode=control build_role=control run_verdict=NO_VERDICT note=gate_marker_hits_$startCount`n", $utf8)
        exit 1
    }
    $endSearch = $start
    $end = -1
    while (($endSearch = $body.IndexOf("        return r;", $endSearch)) -ge 0) {
        $close = $body.IndexOf("`n    }", $endSearch)
        if ($close -lt 0) { break }
        $candidateEnd = $close + "`n    }".Length
        # The gate block ends at the first `return r;` followed by a brace at
        # four-space indent. Verify the text in between is only this gate.
        $segment = $body.Substring($start, $candidateEnd - $start)
        if ($segment -notmatch 'ckpt::Transaction::Active\(\)' -or
            $segment -notmatch 'r\.error = name') {
            $endSearch = $close + 1
            continue
        }
        $end = $candidateEnd
        break
    }
    if ($end -lt 0) {
        Say "PROBE_SETUP=FAILED: the gate body was not delimited; refusing to guess its extent"
        [System.IO.File]::AppendAllText((Join-Path $OutDir "GIT_GATE_HISTORY.txt"),
            "$stamp mode=control build_role=control run_verdict=NO_VERDICT note=gate_body_not_delimited`n", $utf8)
        exit 1
    }
    $removed = $body.Substring($start, $end - $start)
    Say ("PROBE_MODE=removed the transaction gate (" + ($removed -split "`n").Count + " lines)")
    $stripped = $body.Substring(0, $start) +
        "    // CONTROL BUILD (RAWRXD_GIT_TRANSACTION_AUTHORITY_001 G14): the" + "`n" +
        "    // transaction gate on mutating tools has been deliberately removed." + "`n" +
        $body.Substring($end)
    $registrySource = Join-Path $runDir "AgentToolRegistry.no_tx_gate.cpp"
    [System.IO.File]::WriteAllText($registrySource, $stripped, $utf8)
    [System.IO.File]::WriteAllText((Join-Path $runDir "REMOVED_GATE.txt"), $removed, $utf8)
}

# ---- build -----------------------------------------------------------------
$vcvars = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
$incs = @("$repo\include", "$repo\src", "$repo\src\agentic") | ForEach-Object { '/I' + $_ }
$srcs = @(
    "$repo\tools\git_transaction_gate_driver.cpp",
    $registrySource,
    "$repo\src\agentic\CommandExecutor.cpp",
    "$repo\src\agentic\CheckpointRollbackAuthority.cpp",
    "$repo\src\agentic\GitSafetyAuthority.cpp",
    "$repo\src\agentic\GitSafetyAuthorityTools.cpp"
) | ForEach-Object { '"' + $_ + '"' }
$exe = Join-Path $runDir "git_gate.exe"
$bat = @"
call "$vcvars" >nul 2>&1 && cl /nologo /EHsc /std:c++20 /O2 /MT /D_CRT_SECURE_NO_WARNINGS /DNOMINMAX /DWIN32_LEAN_AND_MEAN $($incs -join ' ') /Fe"$exe" /Fo"$runDir\\" $($srcs -join ' ') /link bcrypt.lib
"@
$batPath = Join-Path $runDir "build.bat"
[System.IO.File]::WriteAllText($batPath, $bat, $utf8)
$buildLog = Join-Path $runDir "build.log"
cmd /c "`"$batPath`"" > $buildLog 2>&1
if (-not (Test-Path -LiteralPath $exe)) {
    Say "BUILD=FAILED"
    Get-Content -LiteralPath $buildLog | Select-Object -Last 20 | ForEach-Object { Say "  $_" }
    [System.IO.File]::AppendAllText((Join-Path $OutDir "GIT_GATE_HISTORY.txt"),
        "$stamp mode=$Mode build_role=none run_verdict=NO_VERDICT note=BUILD_FAILED`n", $utf8)
    exit 1
}
Say "BUILD=OK"
Say ("mode=" + $Mode)
Say ("registry_sha256=" + (Get-FileHash -LiteralPath $registrySource -Algorithm SHA256).Hash)
Say ("driver_sha256=" + (Get-FileHash -LiteralPath "$repo\tools\git_transaction_gate_driver.cpp" -Algorithm SHA256).Hash)
Say ("git_authority_sha256=" + (Get-FileHash -LiteralPath "$repo\src\agentic\GitSafetyAuthority.cpp" -Algorithm SHA256).Hash)

# ---- run -------------------------------------------------------------------
$buildRole = if ($Mode -eq "control") { "control" } else { "candidate" }
$runVerdict = "CONTRACT_VIOLATED"
$conditionsNotMet = "?"
try {
    $out = Join-Path $runDir "GATE.txt"
    & $exe $ws > $out 2>&1
    $code = $LASTEXITCODE
    Get-Content -LiteralPath $out | ForEach-Object { Say ("  " + $_) }
    Say "gate_exit=$code"
    $text = Get-Content -LiteralPath $out -Raw
    $conditionsNotMet = if ($text -match 'gate_conditions_not_met=(\d+)') { $Matches[1] } else { "?" }
    $g4NotMet = @(Select-String -LiteralPath $out -Pattern "G4_mutating_git_refused_without_a_transaction\s+UNEXPECTED").Count
    $g4Reached = @(Select-String -LiteralPath $out -Pattern "G4_call_reached_the_transaction_question\s+AS_EXPECTED").Count
    $checkCount = if ($text -match 'checks=(\d+)') { $Matches[1] } else { "?" }
    Say ("checks=" + $checkCount)
    Say ("gate_conditions_not_met=" + $conditionsNotMet)
    Say ("G4_reached_the_transaction_question=" + [bool]$g4Reached)
    Say ("G4_contract_violated=" + [bool]$g4NotMet)

    if ($Mode -eq "control") {
        # The control passes only when removing the guard is DETECTED: G4 must
        # be violated. A control where the vulnerable build still satisfies the
        # contract would mean the gate measures nothing.
        $detected = ($g4NotMet -ge 1) -and ($conditionsNotMet -ge 1) -and ($code -ne 0)
        $runVerdict = if ($detected) { "DEFECT_DETECTED" } else { "CONTRACT_VIOLATED" }
        Say ("PROBE_DETECTED_THE_DEFECT=" + $detected)
    }
    else {
        $runVerdict = if ($code -eq 0 -and $conditionsNotMet -eq "0") { "CONTRACT_SATISFIED" } else { "CONTRACT_VIOLATED" }
    }
    $label = if ($Mode -eq "control") { "RAWRXD_GIT_TRANSACTION_AUTHORITY_001_CONTROL" } else { "RAWRXD_GIT_TRANSACTION_AUTHORITY_001" }
    Say "$label=$runVerdict"
}
finally {
    [System.IO.File]::WriteAllText((Join-Path $runDir "GATE_LOG.txt"), ($log -join [Environment]::NewLine), $utf8)
    $historyPath = Join-Path $OutDir "GIT_GATE_HISTORY.txt"
    $historyLine = "$stamp mode=$Mode build_role=$buildRole gate_conditions_not_met=$conditionsNotMet run_verdict=$runVerdict"
    [System.IO.File]::AppendAllText($historyPath, ($historyLine + "`n"), $utf8)
    $all = @(Get-Content -LiteralPath $historyPath)
    $normalised = @($all | Where-Object { $_ -match 'run_verdict=' })
    $legacy = $all.Count - $normalised.Count
    $baselinePath = Join-Path $OutDir "LEGACY_BASELINE.txt"
    $prev = $null
    if (Test-Path -LiteralPath $baselinePath) {
        $raw = (Get-Content -LiteralPath $baselinePath -Raw).Trim()
        if ($raw -match '^\d+$') { $prev = [int]$raw }
    }
    if ($null -eq $prev) { Say "legacy_lines_excluded=$legacy baseline_established=1" }
    else {
        Say "legacy_lines_excluded=$legacy previous_baseline=$prev"
        if ($legacy -gt $prev) { Say "LEGACY_COUNT_INCREASED=1 (harness regression)" }
    }
    [System.IO.File]::WriteAllText($baselinePath, "$legacy`n", $utf8)
    $indexLines = @(
        "# Normalised run index. Parser surface: every line carries run_verdict=.",
        "# Rebuilt from GIT_GATE_HISTORY.txt on each run.",
        "# CONTRACT_SATISFIED | CONTRACT_VIOLATED | DEFECT_DETECTED | NO_VERDICT",
        "legacy_lines_excluded=$legacy"
    ) + $normalised
    [System.IO.File]::WriteAllLines((Join-Path $OutDir "GIT_GATE_HISTORY.index.txt"), $indexLines, $utf8)
    Say "history_appended=GIT_GATE_HISTORY.txt index_rebuilt=GIT_GATE_HISTORY.index.txt"
}

if ($runVerdict -ne "CONTRACT_SATISFIED" -and $runVerdict -ne "DEFECT_DETECTED") { exit 1 }
exit 0
