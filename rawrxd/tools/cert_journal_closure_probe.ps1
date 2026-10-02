# cert_journal_closure_probe.ps1
#   RAWRXD_IDE_WRITE_TRANSACTIONAL_PROFILE_001 -- falsification probe driver
#
# Compiles tools/ckpt_journal_closure_probe.cpp twice:
#
#   1. against the in-tree CheckpointRollbackAuthority.cpp  -> must report
#      COMMITTED_EDIT_SURVIVED_LATER_RECOVERY=1
#   2. against a copy whose Transaction::Rollback() has the PRE-FIX ordering
#      restored -> must report COMMITTED_EDIT_SURVIVED_LATER_RECOVERY=0
#
# PASS requires both. A cert that cannot be made to fail is not evidence, and
# the second build is the only way to show this particular measurement is
# load-bearing rather than vacuous.
#
# The pre-fix copy is produced by an exact-text substitution of the fixed
# Rollback() body. If the fixed text is not found the driver fails loudly and
# writes NO probe verdict -- it never falls back to "assume the fix is there",
# because that is precisely the self-certifying shape this project keeps
# retracting.
#
# No InferenceEngine, no CMake reconfigure, no shared build tree: three
# translation units compiled straight to an exe in a temp directory, so this
# cannot collide with another session's in-flight build.
#
# Usage
#   pwsh -File tools/cert_journal_closure_probe.ps1 [-OutDir <dir>]

[CmdletBinding()]
param(
    [string]$OutDir = "F:\~dev\rawrxd\audit\RAWRXD_IDE_WRITE_TRANSACTIONAL_PROFILE_001\probe"
)

# NOT 'Stop'. cl.exe and vcvars64 write to stderr during a normal build, and
# under $ErrorActionPreference='Stop' PowerShell converts that into a
# NativeCommandError and abandons the script AFTER the build has already
# succeeded. Failures here are decided by an explicit Test-Path on the produced
# exe, never by the absence of stderr noise.
$ErrorActionPreference = "Continue"
$repo = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
$utf8 = New-Object System.Text.UTF8Encoding($false)
$log = New-Object System.Collections.Generic.List[string]
function Say([string]$l) { Write-Host $l; $log.Add($l) | Out-Null }

if (Test-Path -LiteralPath $OutDir) { Remove-Item -LiteralPath $OutDir -Recurse -Force }
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

$vcvars = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
$incs = @("$repo\include", "$repo\src", "$repo\src\agentic") |
    ForEach-Object { '/I' + $_ }

# The pre-fix ordering. The substitution is anchored on the function's own
# signature and on the first statement after the recovery pass, so the long
# explanatory comment inside the fixed version cannot make it drift. If the
# anchors do not match exactly once, the driver issues NO verdict.
$prefixRollback = @'
bool Transaction::Rollback(std::string* outError) {
    std::string root;
    {
        std::lock_guard<std::mutex> lk(activeMutex());
        root = active().workspaceRoot;
    }
    if (root.empty()) {
        if (outError) *outError = "no active transaction";
        return false;
    }
    // PRE-FIX ORDERING, RESTORED DELIBERATELY FOR THE FALSIFICATION PROBE.
    // The recovery pass runs while this process still holds the journal handle
    // that Begin() opened with FILE_SHARE_READ, so the reopen it performs to
    // append ROLLBACK fails with ERROR_SHARING_VIOLATION and the transaction
    // stays permanently incomplete.
    const RecoveryReport rep = RecoverWorkspace(root, /*writeReceipt=*/true);
    {
        std::lock_guard<std::mutex> lk(activeMutex());
        lastRecovery() = rep;
        if (active().journal != INVALID_HANDLE_VALUE) ::CloseHandle(active().journal);
        active() = ActiveTx();
    }
    if (!rep.AllRestored()) {
'@

function Build-Probe([string]$label, [string]$ckptSource) {
    $dir = Join-Path $OutDir $label
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    $exe = Join-Path $dir "probe_$label.exe"
    $bat = @"
call "$vcvars" >nul 2>&1 && cl /nologo /EHsc /std:c++20 /O2 /MT /D_CRT_SECURE_NO_WARNINGS /DNOMINMAX /DWIN32_LEAN_AND_MEAN $($incs -join ' ') /Fe"$exe" /Fo"$dir\\" "$repo\tools\ckpt_journal_closure_probe.cpp" "$repo\src\agentic\AgentToolRegistry.cpp" "$repo\src\agentic\CommandExecutor.cpp" "$ckptSource"
"@
    $batPath = Join-Path $dir "build.bat"
    [System.IO.File]::WriteAllText($batPath, $bat, $utf8)
    $buildLog = Join-Path $dir "build.log"
    cmd /c "`"$batPath`"" > $buildLog 2>&1
    if (-not (Test-Path -LiteralPath $exe)) {
        Say "BUILD_$label=FAILED"
        Get-Content -LiteralPath $buildLog | Select-Object -Last 15 | ForEach-Object { Say "  $_" }
        return $null
    }
    Say "BUILD_$label=OK"
    return $exe
}

function Run-Probe([string]$label, [string]$exe, [string]$role) {
    $ws = Join-Path $OutDir ("ws_" + $label)
    if (Test-Path -LiteralPath $ws) { Remove-Item -LiteralPath $ws -Recurse -Force }
    $out = Join-Path $OutDir ("run_$label.txt")
    & $exe $ws $role > $out 2>&1
    $code = $LASTEXITCODE
    Get-Content -LiteralPath $out | ForEach-Object { Say ("  " + $_) }
    Say "EXIT_$label=$code"
    $text = Get-Content -LiteralPath $out -Raw
    $survived = if ($text -match 'COMMITTED_EDIT_SURVIVED_LATER_RECOVERY=(\d)') { $Matches[1] } else { "?" }
    $stale = if ($text -match 'STALE_JOURNAL_REPLAYED=(\d)') { $Matches[1] } else { "?" }
    return [pscustomobject]@{ Exit = $code; Survived = $survived; StaleReplayed = $stale }
}

# ---------------------------------------------------------------------------
# 1. in-tree (fixed) authority
# ---------------------------------------------------------------------------
$inTree = "$repo\src\agentic\CheckpointRollbackAuthority.cpp"
$inTreeSha = (Get-FileHash -LiteralPath $inTree -Algorithm SHA256).Hash
Say "in_tree_ckpt_sha256=$inTreeSha"

$body = [System.IO.File]::ReadAllText($inTree)
$anchor = [regex]::new('bool Transaction::Rollback\(std::string\* outError\) \{.*?if \(!rep\.AllRestored\(\)\) \{',
    [System.Text.RegularExpressions.RegexOptions]::Singleline)
$matches = $anchor.Matches($body)
if ($matches.Count -ne 1) {
    Say "PROBE_SETUP=FAILED: expected exactly one Rollback() region, found $($matches.Count)"
    Say "run_verdict=NO_VERDICT (a probe that cannot rebuild the pre-fix state proves nothing)"
    [System.IO.File]::WriteAllText((Join-Path $OutDir "PROBE_LOG.txt"), ($log -join [Environment]::NewLine), $utf8)
    exit 1
}

$fixedExe = Build-Probe "fixed" $inTree
if ($null -eq $fixedExe) { exit 1 }
$fixedRun = Run-Probe "fixed" $fixedExe "candidate"

# ---------------------------------------------------------------------------
# 2. the same authority with the pre-fix ordering restored
# ---------------------------------------------------------------------------
$prefixed = $anchor.Replace($body, $prefixRollback, 1)
if ($prefixed -eq $body) {
    Say "PROBE_SETUP=FAILED: the pre-fix substitution changed nothing"
    exit 1
}
$prefixSrc = Join-Path $OutDir "CheckpointRollbackAuthority.prefix.cpp"
[System.IO.File]::WriteAllText($prefixSrc, $prefixed, $utf8)
$prefixExe = Build-Probe "prefix" $prefixSrc
if ($null -eq $prefixExe) { exit 1 }
$prefixRun = Run-Probe "prefix" $prefixExe "control"

# ---------------------------------------------------------------------------
# 3. the probe is only worth anything if the two builds disagree
# ---------------------------------------------------------------------------
$fixedOk = ($fixedRun.Survived -eq "1")
$prefixDetected = ($prefixRun.Survived -eq "0")
$inTreeIntact = ((Get-FileHash -LiteralPath $inTree -Algorithm SHA256).Hash -eq $inTreeSha)

Say ""
Say "fixed_build_committed_edit_survived=$($fixedRun.Survived)"
Say "prefix_build_committed_edit_survived=$($prefixRun.Survived)"
Say "prefix_build_stale_journal_replayed=$($prefixRun.StaleReplayed)"
Say "in_tree_source_unchanged_by_probe=$($inTreeIntact -and $inTreeSha.Length -gt 0)"
Say "FALSIFICATION_PROBE_DETECTED_THE_DEFECT=$($prefixDetected -and $fixedOk)"

# Two builds, two opposite expectations, one vocabulary. Bare PASS/FAIL would
# put a token next to each that means the same thing to a parser and opposite
# things to a reader: the candidate must SURVIVE, the control must NOT survive.
#   CONTRACT_SATISFIED = the candidate kept the committed edit
#   DEFECT_DETECTED   = the control lost it, which is what the control is for
#   CONTRACT_VIOLATED = the candidate lost it -> the gate is failing
$candidateVerdict = if ($fixedOk) { "CONTRACT_SATISFIED" } else { "CONTRACT_VIOLATED" }
$controlVerdict = if ($prefixDetected) { "DEFECT_DETECTED" } else { "CONTRACT_SATISFIED" }
Say "build_role=candidate build=fixed run_verdict=$candidateVerdict"
Say "build_role=control   build=prefix run_verdict=$controlVerdict"
Say "in_tree_source_unchanged_by_probe=$inTreeIntact"
$overall = if ($fixedOk -and $prefixDetected -and $inTreeIntact) { "CONTRACT_SATISFIED" } else { "CONTRACT_VIOLATED" }
Say "RAWRXD_IDE_WRITE_TRANSACTIONAL_PROFILE_001_JOURNAL_CLOSURE=$overall"
Say "legend: CONTRACT_SATISFIED=expected behaviour observed, DEFECT_DETECTED=injected defect observed, CONTRACT_VIOLATED=gate failing, NO_VERDICT=control not constructible"

[System.IO.File]::WriteAllText((Join-Path $OutDir "PROBE_LOG.txt"), ($log -join [Environment]::NewLine), $utf8)
if ($fixedOk -and $prefixDetected -and $inTreeIntact) { exit 0 }
exit 1
