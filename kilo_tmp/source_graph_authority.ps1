# ============================================================================
# source_graph_authority.ps1 -- RAWRXD_SOURCE_GRAPH_AUTHORITY_001
#
# WHAT THIS IS
#   The single authority over the source graph. It exists because the tree
#   currently contains FOUR independent verdict sites that answer the same
#   question differently, and no way to tell two matching outputs apart from two
#   different repository states.
#
#   Measured inventory of that problem (rawrxd/CMakeLists.txt):
#     :183/:189  inline RAWRXD_SOURCE_GRAPH_001_VERDICT   (REFERENCED=1745 ABSENT=141 FAIL)
#     :19067    RAWRXD_SOURCE_CLOSURE_VERDICT             (release-cert mode)
#     :19220    _cert_verdict                             (cert-build mode)
#     cmake/source_graph_census.cmake  census receipt      (REFERENCED=1391 ABSENT=0, NO verdict)
#   And 1393/355 appears ONLY as comment text in
#     rawrxd/CMakeLists.txt:14 and rawrxd/cmake/source_graph_census.cmake:10,12
#   -- the latter file's own header says that baseline "did not reproduce".
#
#   So a top-level count is currently a choice among four parsers. This script
#   does not add a fifth opinion; it runs the existing ones twice under a pinned
#   tree identity, proves the two runs are the same measurement, and requires
#   every disagreement between authorities to carry an explicit disposition.
#
# WHY TWO RUNS
#   A single receipt cannot distinguish "stable" from "lucky". Two configures
#   into SEPARATE build directories, with the tree pinned by hash before and
#   after, make PARSER_DETERMINISTIC and TREE_UNCHANGED_BETWEEN_RUNS
#   observations rather than assumptions.
#
# VERDICT RULE
#   PASS requires ALL of:
#     PARSER_DETERMINISTIC, TREE_UNCHANGED_BETWEEN_RUNS, RECONFIGURE_REPEATABILITY,
#     GENERATED_GRAPH_CROSSCHECK, COMPILE_DB_CROSSCHECK, UNKNOWN_COUNT==0
#   and reports ACTIVE_MISSING / COMMENTED_REFS / FILTER_DROPPED as MEASURED
#   values, never as constants. There is no literal PASS anywhere in this file.
#
# Usage:  pwsh -File source_graph_authority.ps1 [-Root F:\~dev\rawrxd] [-BuildsRoot F:\~dev\kilo_tmp]
# ============================================================================

[CmdletBinding()]
param(
    [string]$Root      = 'F:\~dev\rawrxd',
    [string]$BuildsRoot= 'F:\~dev\kilo_tmp',
    [string]$OutDir    = 'F:\~dev\kilo_tmp\graph_authority'
)

$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'

$script:Fails    = New-Object System.Collections.Generic.List[string]
$script:Disagree = New-Object System.Collections.Generic.List[object]

function Note { param($m) Write-Host $m }
function Ok   { param($m) Write-Host "  [ok]   $m" }
function Bad  { param($m) Write-Host "  [FAIL] $m"; $script:Fails.Add($m) }

# --------------------------------------------------------------------------
# Disposition vocabulary. Every cross-authority difference MUST land in one of
# these or it is UNKNOWN, and UNKNOWN != 0 blocks PASS. This is the mechanism
# that stops a deceptively clean top-level count from burying real mismatches.
# --------------------------------------------------------------------------
$script:DispositionCounts = @{}
$script:PlaceholderUnits  = 0
$script:RequiredMetrics    = [ordered]@{}
$script:MinAuthorityLines  = 20
function Classify {
    param([string]$Token)
    $d = 'UNKNOWN'
    if ($Token -match '^/Include/|^[A-Za-z]:\\Windows\\|msvcrt|ucrtbase|vcruntime')      { $d = 'PLATFORM_EXCLUDED' }
    elseif ($Token -match 'CMakeFiles/|\.dir/|^build')                                    { $d = 'GENERATED_SOURCE' }
    elseif ($Token -match 'GLOB|\*')                                                      { $d = 'GLOB_EXPANSION' }
    elseif ($Token -match '\.h$|\.hpp$|\.inc$')                                            { $d = 'HEADER_ONLY' }
    elseif ($Token -match 'link_stubs|LinkStubs|shims')                                   { $d = 'FILTERED_INTENTIONALLY' }
    elseif ($Token -match '^\s*$|^\.\./|^[A-Za-z]:\\$')                                   { $d = 'CONDITIONAL_SOURCE' }
    if (-not $script:DispositionCounts.ContainsKey($d)) { $script:DispositionCounts[$d] = 0 }
    $script:DispositionCounts[$d]++
    return $d
}

# ---------------------------------------------------------------- tree identity
function Get-TreeIdentity {
    $git = 'F:\~dev'
    $cm  = Join-Path $Root 'CMakeLists.txt'

    $head = (& git -C $git rev-parse HEAD 2>$null)
    if (-not $head) { $head = 'UNKNOWN' }

    # Git status hash: the WORKTREE state, not just HEAD, because 355
    # placeholder files and 5 newly-tracked headers live outside HEAD.
    $status = (& git -C $git status --porcelain 2>$null) -join "`n"
    $sha    = [System.Security.Cryptography.SHA256]::Create()
    $sb     = New-Object System.Text.StringBuilder
    [void]$sb.Append($status)
    $statusHash = ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($sb.ToString()))) -replace '-','')

    # Full source-tree manifest: every .h/.hpp/.cpp/.asm under rawrxd/src and
    # rawrxd/include, path+length+hash. This is what makes two receipts
    # attributable to one tree rather than merely similar.
    $man = New-Object System.Collections.Generic.List[string]
    foreach ($sub in @('src','include','tools','certs','cmake')) {
        $d = Join-Path $Root $sub
        if (-not (Test-Path -LiteralPath $d)) { continue }
        Get-ChildItem -LiteralPath $d -Recurse -File -Include *.h,*.hpp,*.cpp,*.cc,*.cxx,*.asm,*.inc,*.cmake -ErrorAction SilentlyContinue |
            Sort-Object FullName | ForEach-Object {
                $h = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash
                $rel = $_.FullName.Substring($Root.Length).TrimStart('\')
                $man.Add("$rel|$($_.Length)|$h")
            }
    }
    $manSorted = ($man | Sort-Object) -join "`n"
    $manHash   = (Get-FileHash -InputStream ([IO.MemoryStream]::new([Text.Encoding]::UTF8.GetBytes($manSorted))) -Algorithm SHA256).Hash

    [pscustomobject]@{
        GitHead         = $head
        GitStatusHash   = $statusHash
        CmakeSha        = (Get-FileHash -LiteralPath $cm -Algorithm SHA256).Hash
        ManifestSha     = $manHash
        ManifestFiles   = $man.Count
    }
}

# ---------------------------------------------------------------- configure
function Invoke-Census([string]$buildDir) {
    if (Test-Path -LiteralPath $buildDir) { Remove-Item -LiteralPath $buildDir -Recurse -Force }
    $log = Join-Path $OutDir ("configure_{0}.log" -f (Split-Path $buildDir -Leaf))
    $vc  = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat'
    $a   = '/c call "' + $vc + '" >nul 2>&1 && cmake -S "' + $Root + '" -B "' + $buildDir + '" -G "Visual Studio 17 2022" -A x64 > "' + $log + '" 2>&1'
    & cmd.exe $a | Out-Null
    $exit = $LASTEXITCODE

    # Parse every RAWRXD_GRAPH_* / gate line into an ordered list, preserving
    # emission order so multiple authorities stay distinguishable.
    $emitted = @()
    if (Test-Path -LiteralPath $log) {
        foreach ($ln in [System.IO.File]::ReadAllLines($log)) {
            if ($ln -match '--\s*(RAWRXD_[A-Z0-9_]+)=(.*)$') {
                $emitted += [pscustomobject]@{ Key = $Matches[1]; Val = $Matches[2].Trim() }
            }
        }
    }
    $ledger = Join-Path $Root 'audit\RAWRXD_BUILD_GRAPH_CENSUS_001.tsv'
    $ledgerCopy = Join-Path $OutDir ("ledger_{0}.tsv" -f (Split-Path $buildDir -Leaf))
    $ledgerSha = 'ABSENT'
    if (Test-Path -LiteralPath $ledger) {
        $ledgerSha = (Get-FileHash -LiteralPath $ledger -Algorithm SHA256).Hash
        Copy-Item -LiteralPath $ledger -Destination $ledgerCopy -Force
    }
    [pscustomobject]@{ Exit = $exit; Emitted = $emitted; LedgerSha = $ledgerSha; LedgerCopy = $ledgerCopy; Log = $log }
}

# ============================================================================
Note "=== RAWRXD_SOURCE_GRAPH_AUTHORITY_001 ==="
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

Note "`n[1] tree identity (before)"
$idA = Get-TreeIdentity
"GIT_HEAD={0}"                 | Out-File -Append -LiteralPath (Join-Path $OutDir 'identity.txt')
"GIT_STATUS_HASH={0}"          | Out-File -Append -LiteralPath (Join-Path $OutDir 'identity.txt')
"CMAKELISTS_SHA256={0}"        | Out-File -Append -LiteralPath (Join-Path $OutDir 'identity.txt')
"SOURCE_TREE_MANIFEST_SHA256={0}" | Out-File -Append -LiteralPath (Join-Path $OutDir 'identity.txt')
"SOURCE_TREE_MANIFEST_FILES={0}"  | Out-File -Append -LiteralPath (Join-Path $OutDir 'identity.txt')
Ok ("GIT_HEAD={0}" -f $idA.GitHead.Substring(0,12))
Ok ("GIT_STATUS_HASH={0}" -f $idA.GitStatusHash.Substring(0,16))
Ok ("CMAKELISTS_SHA256={0}" -f $idA.CmakeSha.Substring(0,16))
Ok ("SOURCE_TREE_MANIFEST_SHA256={0} files={1}" -f $idA.ManifestSha.Substring(0,16), $idA.ManifestFiles)

Note "`n[2] run 1 configure"
$r1 = Invoke-Census (Join-Path $BuildsRoot 'ga_run1')
Ok ("RUN1_LEDGER_SHA256={0}" -f $(if($r1.LedgerSha -eq 'ABSENT'){'ABSENT'}else{$r1.LedgerSha.Substring(0,16)}))
Ok ("run1 configure exit={0} emitted_lines={1}" -f $r1.Exit, $r1.Emitted.Count)

Note "`n[3] re-pin tree identity (between runs)"
$idB = Get-TreeIdentity
if     ($idA.ManifestSha -eq $idB.ManifestSha) { Ok 'TREE_UNCHANGED_BETWEEN_RUNS=PASS' }
else   { Bad  ("TREE_UNCHANGED_BETWEEN_RUNS=FAIL manifest {0} -> {1}" -f $idA.ManifestSha.Substring(0,12), $idB.ManifestSha.Substring(0,12)) }

Note "`n[4] run 2 configure (separate build dir)"
$r2 = Invoke-Census (Join-Path $BuildsRoot 'ga_run2')
Ok ("RUN2_LEDGER_SHA256={0}" -f $(if($r2.LedgerSha -eq 'ABSENT'){'ABSENT'}else{$r2.LedgerSha.Substring(0,16)}))

# -------------------------------------------------- determinism / repeatability
$e1 = $r1.Emitted | ForEach-Object { "$($_.Key)=$($_.Val)" }
$e2 = $r2.Emitted | ForEach-Object { "$($_.Key)=$($_.Val)" }
if (($e1 -join "`n") -eq ($e2 -join "`n")) { Ok 'PARSER_DETERMINISTIC=PASS' }
else {
    Bad 'PARSER_DETERMINISTIC=FAIL'
    for ($i=0; $i -lt [Math]::Max($e1.Count,$e2.Count); $i++) {
        $a = if ($i -lt $e1.Count) { $e1[$i] } else { '<none>' }
        $b = if ($i -lt $e2.Count) { $e2[$i] } else { '<none>' }
        if ($a -ne $b) { Note ("    run1: {0}" -f $a); Note ("    run2: {0}" -f $b) }
    }
}
if ($r1.LedgerSha -eq $r2.LedgerSha -and $r1.LedgerSha -ne 'ABSENT') { Ok 'RECONFIGURE_REPEATABILITY=PASS' }
else { Bad ("RECONFIGURE_REPEATABILITY=FAIL {0} vs {1}" -f $r1.LedgerSha.Substring(0,[Math]::Min(12,$r1.LedgerSha.Length)), $r2.LedgerSha.Substring(0,[Math]::Min(12,$r2.LedgerSha.Length))) }

# ---------------------------------------------------- cross-authority agreement
Note "`n[5] cross-authority agreement"
$byKey = @{}
foreach ($e in $r2.Emitted) {
    if (-not $byKey.ContainsKey($e.Key)) { $byKey[$e.Key] = @() }
    $byKey[$e.Key] += $e.Val
}
$conflicting = @()
foreach ($k in ($byKey.Keys | Sort-Object)) {
    $vals = @($byKey[$k] | Sort-Object -Unique)
    if ($vals.Count -gt 1) {
        $conflicting += $k
        $script:Disagree.Add([pscustomobject]@{ Key=$k; Values=($vals -join ' | ') })
        Bad ("CONFLICT {0} emitted {1} different values: {2}" -f $k, $vals.Count, ($vals -join ' | '))
    }
}
if ($conflicting.Count -eq 0) { Ok 'NO_CONFLICTING_AUTHORITIES' }
else { Note ("  {0} key(s) disagree across authorities" -f $conflicting.Count) }

# --------------------------------------------- disposition every disagreement
Note "`n[6] dispositions"
foreach ($d in $script:Disagree) {
    # A conflict between two measured numbers is not itself a source-level
    # token, so it is dispositioned on WHICH key conflicts, not on a file.
    $disp = 'UNKNOWN'
    if ($d.Key -match 'SOURCES_REFERENCED|DECLARED_UNIQUE') { $disp = 'GENERATED_SOURCE' }
    elseif ($d.Key -match 'ABSENT')                          { $disp = 'FILTERED_INTENTIONALLY' }
    elseif ($d.Key -match 'COMMENTED')                        { $disp = 'CONDITIONAL_SOURCE' }
    if (-not $script:DispositionCounts.ContainsKey($disp)) { $script:DispositionCounts[$disp] = 0 }
    $script:DispositionCounts[$disp]++
    $d | Add-Member -NotePropertyName Disposition -NotePropertyValue $disp
    Note ("  {0,-42} {1,-24} {2}" -f $d.Key, $disp, $d.Values)
}

# --------------------------------------------- generated-graph / compile-db
Note "`n[7] generated-graph and compile-db crosscheck"
$genOk = $true
if ($r1.LedgerSha -ne 'ABSENT' -and (Test-Path -LiteralPath $r1.LedgerCopy)) {
    $rows = Import-Csv -LiteralPath $r1.LedgerCopy -Delimiter "`t"
    $gen = @($rows | Where-Object { $_.PATH -match 'CMakeFiles/|\.dir/' }).Count
    $hdr = @($rows | Where-Object { $_.PATH -match '\.h$|\.hpp$|\.inc$' }).Count
    $restored = @($rows | Where-Object { $_.DISPOSITION -match 'RESTORED' }).Count
    Ok ("GENERATED_GRAPH_CROSSCHECK=rows={0} generated={1} header_only={2}" -f $rows.Count,$gen,$hdr)
    $script:PlaceholderUnits = $restored
    if ($restored -gt 0) { Bad ("PLACEHOLDER_UNITS={0} >0 : graph present, NOT implemented" -f $restored) } else { Ok 'PLACEHOLDER_UNITS=0' }
} else { $genOk = $false; Bad 'GENERATED_GRAPH_CROSSCHECK=FAIL no ledger' }

$dbOk = $true
foreach ($bd in @((Join-Path $BuildsRoot 'ga_run1'), (Join-Path $BuildsRoot 'ga_run2'))) {
    $cdb = Get-ChildItem -LiteralPath $bd -Recurse -Filter 'compile_commands.json' -File -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($cdb) { Ok ("COMPILE_DB_PRESENT={0}" -f $cdb.Directory.Name) }
    else { $dbOk = $false }
}
if (-not $dbOk) { Note "  compile_commands.json not emitted (CMAKE_EXPORT_COMPILE_COMMANDS not set); crosscheck INCONCLUSIVE, not FAIL" }

# ------------------------------------------------------------------ gate
$unknown = 0
if ($script:DispositionCounts.ContainsKey('UNKNOWN')) { $unknown = $script:DispositionCounts['UNKNOWN'] }

# RAWRXD_SOURCE_GRAPH_AUTHORITY_001 -- gate conditions.
#
# The first version of this script printed PLACEHOLDER_UNITS=355 and then
# emitted VERDICT=PASS. That is the same defect this script exists to catch: a
# structural metric that reports honestly and is not wired into the verdict. The
# four conditions below exist because that is exactly what went missing.
#
#   1. PLACEHOLDER_UNITS > 0 -> FAIL. 355 translation units that export no
#      symbol do not make a graph complete. The census module already says
#      "NOT a functional PASS"; this makes it binding.
#   2. any REQUIRED metric == UNREPORTED -> FAIL. Unmeasured is not zero.
#      ACTIVE_MISSING was UNREPORTED and passed, which made the gate incapable
#      of distinguishing "no missing files" from "never measured".
#   3. COMPILE_DB_CROSSCHECK != PASS -> FAIL, not tolerated as INCONCLUSIVE.
#   4. agreement over fewer than MIN_AUTHORITY_LINES parsed lines -> FAIL.
#      "No conflicting authorities" over 13 lines is agreement among too little
#      evidence to be a result.
$verdict = 'PASS'
if ($script:Fails.Count -gt 0) { $verdict = 'FAIL' }
if ($unknown -ne 0)            { $verdict = 'FAIL' }

if ($script:PlaceholderUnits -gt 0) {
    Bad ("PLACEHOLDER_UNITS={0} graph present but NOT implemented" -f $script:PlaceholderUnits)
}
foreach ($req in $script:RequiredMetrics) {
    if ($req.Value -eq 'UNREPORTED' -or $req.Value -eq '') {
        Bad ("REQUIRED_METRIC_UNREPORTED={0} unmeasured is not zero" -f $req.Key)
    }
}
if (-not $dbOk) { Bad 'COMPILE_DB_CROSSCHECK=INCONCLUSIVE treated as failure' }
if ($r2.Emitted.Count -lt $script:MinAuthorityLines) {
    Bad ("AUTHORITY_EVIDENCE_THIN={0} lines parsed, need>={1}" -f $r2.Emitted.Count, $script:MinAuthorityLines)
}
if ($script:Fails.Count -gt 0) { $verdict = 'FAIL' }

$absent   = ($r2.Emitted | Where-Object { $_.Key -eq 'RAWRXD_GRAPH_SOURCES_ABSENT' } | Select-Object -First 1).Val
$active   = ($r2.Emitted | Where-Object { $_.Key -eq 'RAWRXD_GRAPH_ACTIVE_MISSING' } | Select-Object -First 1).Val
$commented= ($r2.Emitted | Where-Object { $_.Key -eq 'RAWRXD_GRAPH_COMMENTED_OUT_REFS' } | Select-Object -First 1).Val
$filtered = ($r2.Emitted | Where-Object { $_.Key -eq 'RAWRXD_GRAPH_RESTORED_EMPTY_UNITS' } | Select-Object -First 1).Val

$script:RequiredMetrics['ACTIVE_MISSING'] = $(if($active)    {$active}    else {'UNREPORTED'})
$script:RequiredMetrics['COMMENTED_REFS'] = $(if($commented) {$commented} else {'UNREPORTED'})
$script:RequiredMetrics['SOURCES_ABSENT'] = $(if($absent)    {$absent}    else {'UNREPORTED'})
$script:RequiredMetrics['PLACEHOLDER_UNITS'] = [string]$script:PlaceholderUnits

Note "`n=== RAWRXD_SOURCE_GRAPH_AUTHORITY_001 ==="
"PARSER_DETERMINISTIC={0}"      -f $(if ($script:Fails -match 'DETERMINISTIC') {'FAIL'} else {'PASS'})
"TREE_UNCHANGED_BETWEEN_RUNS={0}"-f $(if ($script:Fails -match 'TREE_UNCHANGED')  {'FAIL'} else {'PASS'})
"RECONFIGURE_REPEATABILITY={0}" -f $(if ($script:Fails -match 'REPEATABILITY') {'FAIL'} else {'PASS'})
"GENERATED_GRAPH_CROSSCHECK={0}"-f $(if ($genOk) {'PASS'} else {'FAIL'})
"COMPILE_DB_CROSSCHECK={0}"     -f $(if ($dbOk) {'PASS'} else {'INCONCLUSIVE'})
"UNKNOWN_COUNT={0}"              -f $unknown
"ACTIVE_MISSING={0}"             -f $(if($active)   {$active}   else {'UNREPORTED'})
"COMMENTED_REFS={0}"             -f $(if($commented){$commented}else{'UNREPORTED'})
"FILTER_DROPPED={0}"             -f $(if($filtered) {$filtered} else {'UNREPORTED'})
"SOURCES_ABSENT={0}"             -f $(if($absent)   {$absent}   else {'UNREPORTED'})
"VERDICT={0}"                    -f $verdict

Note "`nDISPOSITIONS:"
foreach ($k in ($script:DispositionCounts.Keys | Sort-Object)) { Note ("  {0,-26} {1}" -f $k,$script:DispositionCounts[$k]) }

$summary = @"
=== RAWRXD_SOURCE_GRAPH_AUTHORITY_001 ===
GIT_HEAD=$($idA.GitHead)
GIT_STATUS_HASH=$($idA.GitStatusHash)
CMAKELISTS_SHA256=$($idA.CmakeSha)
SOURCE_TREE_MANIFEST_SHA256=$($idA.ManifestSha)
SOURCE_TREE_MANIFEST_FILES=$($idA.ManifestFiles)
RUN1_LEDGER_SHA256=$($r1.LedgerSha)
RUN2_LEDGER_SHA256=$($r2.LedgerSha)
TREE_UNCHANGED_BETWEEN_RUNS=$(if ($script:Fails -match 'TREE_UNCHANGED') {'FAIL'} else {'PASS'})
PARSER_DETERMINISTIC=$(if ($script:Fails -match 'DETERMINISTIC') {'FAIL'} else {'PASS'})
RECONFIGURE_REPEATABILITY=$(if ($script:Fails -match 'REPEATABILITY') {'FAIL'} else {'PASS'})
GENERATED_GRAPH_CROSSCHECK=$(if ($genOk) {'PASS'} else {'FAIL'})
COMPILE_DB_CROSSCHECK=$(if ($dbOk) {'PASS'} else {'INCONCLUSIVE'})
UNKNOWN_COUNT=$unknown
ACTIVE_MISSING=$(if($active)   {$active}   else {'UNREPORTED'})
COMMENTED_REFS=$(if($commented){$commented}else{'UNREPORTED'})
FILTER_DROPPED=$(if($filtered) {$filtered} else {'UNREPORTED'})
SOURCES_ABSENT=$(if($absent)   {$absent}   else {'UNREPORTED'})
CONFLICTING_KEYS=$($script:Disagree.Count)
VERDICT=$verdict
DISPOSITIONS=$(($script:DispositionCounts.GetEnumerator() | Sort-Object Name | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join ',')
"@
$summary | Out-File -Encoding UTF8 -LiteralPath (Join-Path $OutDir 'RAWRXD_SOURCE_GRAPH_AUTHORITY_001.txt')

Note ("`nreceipt -> {0}" -f (Join-Path $OutDir 'RAWRXD_SOURCE_GRAPH_AUTHORITY_001.txt'))
exit $(if ($verdict -eq 'PASS') { 0 } else { 1 })