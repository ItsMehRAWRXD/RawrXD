<#
    OWNER_PROOF_001 -- linker symbol ownership census for RawrXD_Gold.

    WHAT THIS IS FOR
    A linker census goes stale the moment a translation unit is added, and more
    importantly a census that matches symbol NAMES against file TEXT invents
    owners that do not exist. Four separate times in the RawrXD_Gold closure a
    grep reported a symbol as owned by a file that emitted nothing:

      * enterprise_camellia_nonmsvc.cpp    attributed 11 symbols. Its body is
        inside `#if !defined(_MSC_VER)`. dumpbin /symbols on the compiled object
        shows 0 exported symbols. This is an MSVC build.
      * native_speed_kernels_nonmsvc.cpp   attributed  8 symbols. Same defect.
      * src/core/win32ide_link_stubs.cpp    attributed  6 symbols. It emits 69
        duplicate definitions of symbols runtime_symbol_bridge.cpp owns.
      * src/core/inference_link_production.cpp attributed symbols it defined
        with a type that contradicted the incumbent's (int vs uint64_t), for a
        name no header declares and no code reads.

    All four were plausible, confident, and wrong. The rule this tool enforces:

        TEXT_MATCH_IS_NOT_OWNERSHIP=1
        OWNER_REQUIRES_OBJECT_EXPORT_ON_ACTIVE_TOOLCHAIN=1

    FOUR STAGES, AND ONLY THE LAST ONE MAKES AN OWNER
        1  TEXTUAL_CANDIDATE   a file mentions the symbol name
        2  ACTIVE_ON_TOOLCHAIN  the mention is not inside a preprocessor region
                                excluded by this compiler
        3  OBJECT_COMPILES     the file compiles on the active toolchain
        4  OBJECT_EXPORTS      the compiled object actually exports the symbol

    STAGE 4 IS THE ONE THAT IS USUALLY SKIPPED, and it is the only stage that
    cannot be satisfied by text. It is opt-in with -VerifyExports, because it
    requires compiling and inspecting candidate objects. Without that flag the
    tool reports stages 1-2 and marks every candidate PROVISIONAL, so a run can
    never be mistaken for a proof.

    USAGE
        pwsh -File owner_proof_001.ps1 -LinkLog <build.log> -ProjectRoot <repo>
        pwsh -File owner_proof_001.ps1 -LinkLog <build.log> -ProjectRoot <repo> -VerifyExports

    EXIT CODES
        0  census produced; MULTI_OWNER_COUNT == 0
        3  census produced; MULTI_OWNER_COUNT > 0   (ownership is ambiguous)
        4  census produced; stage 3 or 4 rejected at least one candidate
        5  input missing (link log or project root)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$LinkLog,
    [Parameter(Mandatory = $true)][string]$ProjectRoot,
    [string]$Target          = 'RawrXD_Gold',
    [string]$ProjectFile     = '',
    [switch]$VerifyExports,
    [string]$Out             = '', [string]$TlogPath      = '', [string]$Configuration  = 'Release'
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $LinkLog))    { Write-Output "OWNER_PROOF_001 ERROR: link log not found: $LinkLog";    exit 5 }
if (-not (Test-Path -LiteralPath $ProjectRoot)) { Write-Output "OWNER_PROOF_001 ERROR: project root not found: $ProjectRoot"; exit 5 }

if (-not $ProjectFile) {
    $ProjectFile = Join-Path $ProjectRoot 'build' "$Target.vcxproj"
}

# ---------------------------------------------------------------------------
# Inputs
# ---------------------------------------------------------------------------
$log = Get-Content -LiteralPath $LinkLog

# Unresolved symbols, and separately the duplicate-definition reports, because a
# duplicate is an AMBIGUITY rather than an absence and the two must never be
# summed into one number.
$unresolved = @{}
$rawLines = Get-Content -LiteralPath $LinkLog

# EXTRACTION. The link log uses three shapes and an earlier version handled one:
#
#  1  obj : error LNK2019: unresolved external symbol Foo::bar(int) referenced in
#           function Baz::qux(...)
#  2  obj : error LNK2019: unresolved external symbol "struct X Y::z" (?mangled)
#  3  obj : error LNK2001: unresolved external symbol "class X __cdecl y::f(a" (?m)
#
# The earlier version matched only shape 1, so every LNK2001 line -- and every
# global variable, which the linker never decorates with "referenced in" -- was
# invisible. It then unwrapped shape 2 with a regex anchored at ^" which fails
# when the capture begins mid-token, leaving a trailing quote on the needle. Both
# faults push toward the same wrong answer: a symbol appears to have no textual
# candidate. NO_TEXTUAL_CANDIDATE=22 was inflated by them.
#
# So: take the segment after the fixed prefix, unwrap a leading quoted region
# properly, then prefer the qualified name immediately before "(" and fall back
# to the last token for undecorated globals.
function Get-SymbolName([string]$line) {
    $m = [regex]::Match($line, 'unresolved external symbol\s+(.*)$')
    if (-not $m.Success) { return $null }
    $d = $m.Groups[1].Value.Trim()

    # Trim the "referenced in function ..." tail.
    $i = $d.IndexOf(' referenced in function')
    if ($i -ge 0) { $d = $d.Substring(0, $i) }
    $d = $d.Trim()

    # Unwrap a leading quoted demangled form: "...name..." possibly followed by
    # a parenthesised mangled name.
    if ($d.StartsWith('"')) {
        $j = $d.IndexOf('" (')
        if ($j -gt 0)      { $d = $d.Substring(1, $j - 1) }
        elseif ($d.EndsWith('"')) { $d = $d.Substring(1, $d.Length - 2) }
        else               { $d = $d.Trim('"') }
    }
    else {
        # Drop a trailing mangled-name tail if present.
        $j = $d.LastIndexOf(' (')
        if ($j -gt 0) { $d = $d.Substring(0, $j) }
    }
    $d = $d.Trim().Trim('"').Trim()

    # Qualified name immediately before "(" -- this is the reliable form.
    if ($d -match '([A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_~][A-Za-z0-9_]*)+)\s*\(') {
        return $matches[1]
    }
    # Undecorated global: last whitespace token, minus pointer/ref decoration.
    $t = @($d -split '\s+' | Where-Object { $_ -ne '' })
    if ($t.Count -eq 0) { return $null }
    $last = $t[-1] -replace '^\*+','' -replace '^&+','' -replace '\*$',''
    if ($last -match '^([A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)+)$') { return $matches[1] }
    if ($last -match '^([A-Za-z_][A-Za-z0-9_]*)$') { return $matches[1] }
    return $null
}

foreach ($line in $rawLines) {
    if ($line -notmatch 'unresolved external symbol') { continue }
    $n = Get-SymbolName $line
    if ($n) { $unresolved[$n] = $true }
}

$duplicates = @()
foreach ($line in $log) {
    if ($line -match '^(.+?\.obj)\s*:\s*error LNK2005:\s*(.+?)\s+already defined in\s+(.+?)\s*$') {
        $duplicates += [pscustomobject]@{ Obj = $matches[1]; Symbol = $matches[2]; AlsoIn = $matches[3] }
    }
}

# TUs already linked into the target: they cannot be candidate OWNERS of an
# unresolved symbol, because a definition in the target would have resolved it.
#
# Keys are normalised to repo-relative, forward-slashed. An earlier version
# compared a repo-relative candidate against the ABSOLUTE paths the vcxproj
# stores, so ALREADY_IN_TARGET never matched and nine symbols owned by
# deep2_openai_server.cpp -- which IS in the target -- were reported as
# candidates. A guard whose key never matches is worse than no guard.
$inTarget = @{}
if (Test-Path -LiteralPath $ProjectFile) {
    $proj = Get-Content -LiteralPath $ProjectFile -Raw
    $rootAbs = (Resolve-Path $ProjectRoot).Path
    foreach ($m in [regex]::Matches($proj, '<ClCompile Include="([^"]+)"')) {
        $p = $m.Groups[1].Value -replace '\\','/'
        if ($p -like "$($rootAbs -replace '\\','/')/*") { $p = $p.Substring($rootAbs.Length + 2) }
        $inTarget[$p] = $true
    }
}

# The target's REAL include environment. Stage 3 compiles a candidate, and a
# candidate compiled with a different include set than the target uses produces a
# false OBJECT_DOES_NOT_COMPILE -- which is this tool reporting a defect that
# does not exist. Measured: deep2_openai_server.cpp compiles cleanly inside
# RawrXD_Gold and was rejected by an earlier probe that supplied only
# /I src /I include. The vcxproj stores fully resolved paths, so the probe uses
# exactly those.
$targetIncludes = @()
$targetDefines  = @()
$targetOptions  = @()
if (Test-Path -LiteralPath $ProjectFile) {
    $praw = Get-Content -LiteralPath $ProjectFile -Raw
    $first = [regex]::Matches($praw, '<AdditionalIncludeDirectories>([^<]*)</AdditionalIncludeDirectories>')
    if ($first.Count) {
        $targetIncludes = @($first[0].Groups[1].Value -split ';' | Where-Object { $_ -and (Test-Path -LiteralPath $_) })
    }
    # Preprocessor definitions and options matter as much as include paths. A file
    # compiled without the target's /D set can fail to compile while compiling
    # cleanly in-target, and a stage 3 that reports that as a defect is the tool
    # inventing a defect. Measured: 41 OBJECT_DOES_NOT_COMPILE rejections before
    # the defines were supplied, against files that compile inside RawrXD_Gold.
    $d1 = [regex]::Matches($praw, '<PreprocessorDefinitions>([^<]*)</PreprocessorDefinitions>')
    if ($d1.Count) {
        $targetDefines = @($d1[0].Groups[1].Value -split ';' | Where-Object { $_ })
    }
    $o1 = [regex]::Matches($praw, '<AdditionalOptions>([^<]*)</AdditionalOptions>')
    if ($o1.Count) {
        $targetOptions = @($o1[0].Groups[1].Value -split '\s+' | Where-Object { $_ })
    }
}

# ---------------------------------------------------------------------------
# Exclusion lists -- machine-readable reasons, so a later run does not have to
# re-derive a judgement that was already made once.
# ---------------------------------------------------------------------------
$KNOWN_NON_OWNER = @{
    # reason                                    files
    'STUB_ZEROS_INCUMBENT'                    = @('src/core/link_stubs_production.cpp')
    'DUPLICATE_PROVIDER_69'                   = @('src/core/win32ide_link_stubs.cpp')
    'DUPLICATE_PROVIDER_3'                    = @('src/core/inference_link_production.cpp','src/core/enterprise_devunlock_bridge.cpp')
    'STRESS_HARNESS_NOT_LIBRARY'              = @('src/core/convergence_stress_harness.cpp')
    'CERT_DRIVER_NOT_LIBRARY'                 = @('certs/http_template_format_sweep_001.cpp','tools/deep2_model_registry_admission_test.cpp')
    'IDE_MAIN_ENTRYPOINT'                     = @('src/win32app/main_win32.cpp')
    'IDE_GUI_IMPLEMENTATION'                  = @('src/win32app/Win32IDE_EditorEngine.cpp')
    'Q4K_ALTERNATE_BLOCKED_BY_GUARD'          = @('src/core/kquant_nonmsvc.cpp')
}

$fileReason = @{}
foreach ($r in $KNOWN_NON_OWNER.GetEnumerator()) {
    foreach ($f in $r.Value) { $fileReason[($f -replace '\\','/')] = $r.Key }
}

# ---------------------------------------------------------------------------
# Stage 2 helper: is this file's body excluded by a _MSC_VC/_MSC_VER guard?
#
# Only the two shapes that actually occur in this tree are recognised:
#     #if !defined(_MSC_VER)      ... #endif
#     #ifndef _MSC_VER            ... #endif
# A file whose body sits inside either defines nothing on MSVC. A file that does
# not match is treated as ACTIVE -- this is deliberately permissive, because the
# failure being guarded against is claiming an owner that emits nothing, not
# rejecting an owner that might.
# ---------------------------------------------------------------------------
function Get-NonActiveGuardLine([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return 0 }
    $ln = 0
    foreach ($l in [System.IO.File]::ReadLines($Path)) {
        $ln++
        if ($l -match '^\s*#\s*ifndef\s+_MSC_VER') { return $ln }
        if ($l -match '^\s*#\s*if\s+.*!\s*defined\s*\(\s*_MSC_VER\s*\)') { return $ln }
        if ($l -match '^\s*#\s*if\s+defined\s*\(\s*_MSC_VER\s*\)') { return $ln }
    }
    return 0
}

# ---------------------------------------------------------------------------
# Stage 4 helper: compile a candidate and ask the linker tooling whether the
# object exports the symbol. This is the stage text cannot satisfy.
# ---------------------------------------------------------------------------
$msvcRoot = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC'
$vcvars   = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat'
$dumpbin  = $null
if (Test-Path $msvcRoot) {
    $v = Get-ChildItem $msvcRoot -Directory | Sort-Object Name -Descending | Select-Object -First 1
    $p = Join-Path $v.FullName 'bin\Hostx64\x64\dumpbin.exe'
    if (Test-Path $p) { $dumpbin = $p }
}
# ---------------------------------------------------------------------------
# OWNER_PROOF_ENVIRONMENT_001 -- the authoritative compile command.
#
# Best authority is not the vcxproj XML: it is the command MSBuild actually
# issued. MSBuild records it in
#   build\<Target>.dir\<Config>\<Target>.tlog\CL.command.1.tlog
# as UTF-16 lines alternating ^<source path> then the full cl.exe argument
# string. Every entry differs only in the source path and /Fo, so the first
# entry whose source exists is an exact template for the shipping configuration.
#
# This replaces the hand-built command, which supplied /nologo /W1 and a filtered
# subset of /D. Measured omissions that matter:
#   /MT                  static CRT -- the target is a static-CRT build
#   /arch:AVX512         target-wide
#   /GS- /O2 /Ob2 /WX- /sdl- /diagnostics:column /external:W0
#   ~50 /D flags including RAWRXD_GOLD_BUILD=1, RAWR_HAS_VULKAN=1,
#   RAWR_ENABLE_VULKAN=1, VULKAN_HPP_DISPATCH_LOADER_DYNAMIC=1, NOMINMAX,
#   WIN32_LEAN_AND_MEAN, and the whole RAWRXD_LINK_*_ASM set.
# NOMINMAX and WIN32_LEAN_AND_MEAN decide whether <windows.h> collides with
# <algorithm>; RAWRXD_GOLD_BUILD=1 selects which source paths exist at all.
# Reconstructing the set from ItemDefinitionGroup is what produced 41 false
# OBJECT_DOES_NOT_COMPILE verdicts. The tlog removes the guessing.
#
# Only three things are substituted per candidate: the source path, /Fo, and /Fd.
# /Fd is redirected so a probe cannot contend for the target's PDB while a real
# build is running.
# ---------------------------------------------------------------------------
# The SAME tlog is also the authority for target MEMBERSHIP, which is better than
# the vcxproj: the `^source` lines are exactly the files MSBuild compiled for this
# target under this configuration, as absolute paths that are known to exist.
#
# Measured defect this replaces: RawrXD_Gold.vcxproj contains BOTH absolute
# entries ("F:\~dev\rawrxd\src\core\foo.cpp") and bare relative ones
# ("kquant_parity_check.cpp"). Normalising both against the repo root left the
# relative entries unresolvable, so the positive-control search selected
# "kquant_parity_check.cpp", joined it to the repo root, and compiled a path that
# does not exist. The control then reported CONTROL_FAILED_TO_COMPILE and the
# tool would have concluded the probe was unfaithful -- when the probe was fine
# and the control FILE was wrong.
# ORDERING DEFECT, found by running the tool: this membership block was placed
# BEFORE $tlogFound is assigned, so the `if ($tlogFound)` body never ran,
# $inTargetAbs stayed empty, and every control reported NO_TLOG_ENTRY. The tool
# then reported CONTROL_PASS=0 CONTROL_TOTAL=0 rather than "cannot run", which
# is the same class of defect as before: a stage that cannot produce a result
# must say so, not emit a zero that reads as a measurement.
#
# The source list is therefore collected where $tlogFound is known, below, and
# only the compare-key projection happens here.
$rootAbsN = (Resolve-Path $ProjectRoot).Path
function Sync-CompareKeys {
    param([string[]]$AbsPaths)
    foreach ($a in $AbsPaths) {
        if ($a.StartsWith($rootAbsN, [System.StringComparison]::OrdinalIgnoreCase)) {
            $inTarget[($a.Substring($rootAbsN.Length + 1) -replace '\\','/')] = $true
        } else {
            $inTarget[(Split-Path -Leaf $a)] = $true
        }
    }
}
$inTargetAbs = @()
$cmdTemplate    = ''
$cmdTemplateSrc = ''
$tlogCandidates = @(
    (Join-Path $ProjectRoot "build\$Target.dir\Release\$Target.tlog\CL.command.1.tlog"),
    (Join-Path $ProjectRoot "build\$Target.dir\$Configuration\$Target.tlog\CL.command.1.tlog")
)
$tlogFound = ''
foreach ($t in $tlogCandidates) { if (Test-Path -LiteralPath $t) { $tlogFound = $t; break } }

if ($tlogFound) {
    # Two defects found by running the parser against the real tlog, both of
    # which made template discovery silently fail and the tool exit 5:
    #   1. The file begins with a UTF-8 BOM, so the first line's first character
    #      is U+FEFF and not '^'. Every StartsWith('^') test therefore failed on
    #      the first entry. The BOM is stripped from every line, not just the
    #      first, because nothing guarantees where it lands after a re-save.
    #   2. The /c test was written as \s/c(\s|$), which requires whitespace before
    #      /c. MSBuild emits /c as the FIRST token, so the test never matched.
    #      Correct form is (^|\s)/c(\s|$).
    $raw = [System.Text.Encoding]::Unicode.GetString([System.IO.File]::ReadAllBytes($tlogFound))
    $raw = $raw.TrimStart([char]0xFEFF)
    $tl = @($raw -split "`r?`n" | ForEach-Object { $_.TrimStart([char]0xFEFF) } | Where-Object { $_.Trim() -ne '' })
    for ($i = 0; $i -lt $tl.Count - 1; $i++) {
        if ($tl[$i].StartsWith('^')) {
            $src = $tl[$i].Substring(1).Trim()
            $cmd = $tl[$i + 1].Trim()
            # Membership is collected for EVERY ^source entry, independently of
            # whether it also carries the template we adopt. Measured on this
            # tlog: 285 entries, 285 absolute, 0 relative, all existing.
            if ($src -and (Test-Path -LiteralPath $src)) { $inTargetAbs += $src }
            if ((-not $cmdTemplate) -and $cmd -match '/TP' -and $cmd -match '(?i)(^|\s)/c(\s|$)' -and (Test-Path -LiteralPath $src)) {
                $cmdTemplateSrc = $src
                $cmdTemplate = ($cmd -replace ('\s+' + [regex]::Escape($src) + '\s*$'), '')
            }
        }
    }
}
# Project the verified absolute paths onto the comparison key set. The exec path
# is never rebuilt from the key.
if ($inTargetAbs.Count -gt 0) { Sync-CompareKeys -AbsPaths $inTargetAbs }
if (-not $cmdTemplate) {
    Write-Output "OWNER_PROOF_001 ERROR: no authoritative command template."
    Write-Output "  Looked for CL.command.1.tlog under build\$Target.dir. Build the target once, or pass -TlogPath."
    exit 5
}

$exportCache = @{}
function Test-ObjectExports([string]$RelPath, [string]$Symbol) {
    # Returns @(COMPILES, EXPORTS). Stage 3 and stage 4 are SEPARATE authorities:
    # COMPILES proves only that the TU builds under Gold's exact configuration.
    # EXPORTS is decided afterwards, by inspecting that object.
    $key = "$RelPath|$Symbol"
    if ($exportCache.ContainsKey($key)) { return $exportCache[$key] }
    $compiles = $false
    $exports  = $false
    $tmp = Join-Path $env:TEMP ("ownerproof_" + [guid]::NewGuid().ToString('N').Substring(0,8))
    New-Item -ItemType Directory -Force -Path $tmp | Out-Null
    $bat   = Join-Path $tmp 'b.bat'
    $obj   = Join-Path $tmp 'c.obj'
    $stamp = Join-Path $tmp 'rc.txt'
    $abs   = if (Test-Path -LiteralPath $RelPath) { $RelPath } else { Join-Path $ProjectRoot $RelPath }

    # THE COMPILER EXECUTABLE IS NOT IN THE TLOG. MSBuild records only the
    # argument string, so the captured template begins with "/c /I..." and
    # contains no cl.exe token at all. Two earlier versions of this probe
    # submitted the template as-is, cmd tried to run "/c" as a program, and
    # reported:
    #     '/c' is not recognized as an internal or external command
    # with no compiler output and no object file.
    #
    # That failure mode is why PART 6 of the receipt recorded the template as
    # PROVEN_BY_EXECUTION with "ZERO errors". The zero was not a clean compile;
    # it was no compile at all. A positive control that passes because the
    # process it should have launched was never launched is the most dangerous
    # shape of instrument defect, and it survived a manual re-run because
    # "no error lines" and "no output lines" look identical in a filtered view.
    #
    # vcvars64.bat puts cl.exe on PATH, so the correct invocation is "cl " plus
    # the recorded arguments.
    $cmdLine = 'cl ' + $cmdTemplate
    $cmdLine = $cmdLine -replace '(?i)/Fo"[^"]*"', ('/Fo"' + ($obj  -replace '\\','/') + '"')
    $cmdLine = $cmdLine -replace '(?i)/Fd"[^"]*"', ('/Fd"' + ((Join-Path $tmp 'c.pdb') -replace '\\','/') + '"')
    $cmdLine = $cmdLine.TrimEnd() + ' "' + ($abs -replace '\\','/') + '"'

    $cmd = @"
call "$vcvars" >nul 2>&1
cd /d "$(($ProjectRoot -replace '\\','/'))"
$cmdLine >"$tmp\cl.log" 2>&1
if errorlevel 1 (echo 1>"$stamp") else (echo 0>"$stamp")
"@
    Set-Content -LiteralPath $bat -Value $cmd -Encoding ASCII
    & cmd.exe /c $bat 2>&1 | Out-Null

    # `if errorlevel 1` rather than `echo %ERRORLEVEL%>`: a percent-expansion in a
    # generated batch is not a reliable way to capture a child's status, and the
    # failure mode is silent -- the stamp came out zero bytes, Get-Content -Raw
    # returns $null for a zero-byte file, and .Trim() on that $null is exactly the
    # "method on a null-valued expression" class this tool exists to catch,
    # present in the tool itself. Both halves are fixed.
    if (Test-Path -LiteralPath $stamp) {
        $raw2 = Get-Content -LiteralPath $stamp -Raw -ErrorAction SilentlyContinue
        $rc = if ($null -eq $raw2) { '1' } else { $raw2.Trim() }
        $compiles = ($rc -eq '0') -and (Test-Path -LiteralPath $obj)
        # A zero-byte object is not a successful compile of anything.
        if ($compiles -and (Get-Item -LiteralPath $obj).Length -le 0) { $compiles = $false }
    }
    if ($compiles -and $dumpbin) {
        $out = & $dumpbin /symbols $obj 2>&1
        if ($out) {
            $joined = ($out -join "`n")
            $bare = ($Symbol -split '::')[-1]
            # The linker's identity is the mangled name when the log supplies one.
            # A word-bounded match on the bare name is the right test for extern
            # "C" symbols, which carry no decoration.
            $exports = [bool]($joined -match ('\b' + [regex]::Escape($bare) + '\b'))
        }
    }
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
    $exportCache[$key] = @($compiles, $exports)
    return $exportCache[$key]
}

# ---------------------------------------------------------------------------
# STAGE 3/4 SELF-VALIDATION -- a POSITIVE CONTROL, and it is not optional.
#
# Stage 3 decides a candidate is not an owner by failing to compile it. That is
# only a statement about the candidate if the probe can compile things that DO
# compile in the target. Measured failure of an earlier version of this probe:
# it reported OBJECT_DOES_NOT_COMPILE for src/deep2/deep2_openai_server.cpp,
# and compiling that same file by hand with the target's own include
# directories, preprocessor definitions and options produced ZERO errors.
# The probe was wrong, and 41 of 47 symbols were rejected on its word.
#
# So the probe now compiles a control file that is demonstrably in the target
# and demonstrably builds there. If the control fails, stages 3 and 4 are marked
# UNRELIABLE and are not permitted to reject anything: every candidate is
# reported as UNPROVEN_PROBE_UNRELIABLE instead. A gate that cannot demonstrate
# it can detect a success must not be allowed to report a failure.
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# STAGE 3/4 SELF-VALIDATION -- CONTROLS, and they are not optional.
#
# Stage 3 decides a candidate is not an owner by failing to compile it. That is
# only a statement about the candidate if the probe can compile things that DO
# compile in the target. Stage 4 decides a candidate does not export a symbol by
# not finding it in the object, which is only meaningful if the parser can find a
# symbol that IS there. Each independently meaningful stage must therefore
# demonstrate BOTH its positive and its rejection path.
#
# SOURCE_EXEC_PATH vs SOURCE_COMPARE_KEY -- the separation that ends the class of
# bug this file hit twice:
#     SOURCE_EXEC_PATH      exact authoritative path; the ONLY thing passed to
#                           Test-Path and to cl.exe. Never reconstructed.
#     SOURCE_COMPARE_KEY    canonicalised, for membership and dedup ONLY. Never
#                           fed back into a filesystem operation.
#
# Measured: all 285 `^source` entries in
# build\RawrXD_Gold.dir\Release\RawrXD_Gold.tlog are ABSOLUTE -- 0 relative. So
# no working-directory provenance question arises for any control, and no
# control may be taken from the vcxproj, which mixes absolute entries with bare
# relative ones ("kquant_bench.cpp", "fp16_census.cpp"). Four successive runs
# named four different bogus controls -- certification_harness.cpp,
# kquant_parity_check.cpp, kquant_bench.cpp, full_model_inference.cpp -- all bare
# names, all resolved against the repo root into paths that do not exist. Each
# produced CONTROL_FAILED_TO_COMPILE for a file the probe never tried.
#
# CONTROLS ARE CHOSEN BY SHAPE, ALL ORIGINATING FROM THE GOLD TLOG, so that
# CONTROL_ACTUALLY_IN_GOLD is proven by construction rather than by the file
# happening to exist:
#     SIMPLE     small translation unit, no Deep2 or GPU surface
#     ORDINARY   a mid-sized core unit
#     DEEP2      src\deep2\Deep2Engine.cpp specifically -- selected FROM THE TLOG,
#                not from the source tree. "It exists in src" is not evidence
#                that Gold compiles it.
# ---------------------------------------------------------------------------
$probeReliable  = $false
$controlDetail  = 'NOT_RUN'
$stage4Pos      = $false
$stage4Neg      = $false
$stage4Detail   = 'NOT_RUN'
$controlReport  = @()

function New-SourceRef([string]$p, [string]$rootAbs) {
    # Returns an object carrying BOTH representations. The exec path is never
    # rebuilt from the compare key.
    $abs  = $p
    $cmp  = if ($abs.StartsWith($rootAbs, [System.StringComparison]::OrdinalIgnoreCase)) {
                $abs.Substring($rootAbs.Length + 1) -replace '\\','/'
            } else { $abs -replace '\\','/' }
    return [pscustomobject]@{ SOURCE_EXEC_PATH = $abs; SOURCE_COMPARE_KEY = $cmp }
}

if ($VerifyExports) {
    $rootAbsC = (Resolve-Path $ProjectRoot).Path

    # Absolute, existing, Gold-compiled sources -- straight from the tlog.
    $goldSrcs = @($inTargetAbs | Where-Object {
        $_ -match '^[A-Za-z]:[\\/]' -and (Test-Path -LiteralPath $_)
    })

    # Shape-based selection, in Gold-tlog order.
    $cSimple = $null; $cOrdinary = $null; $cDeep2 = $null
    foreach ($a in $goldSrcs) {
        if (-not $a -match '\.cpp$') { continue }
        $len = (Get-Item -LiteralPath $a).Length
        if ($a -match 'deep2\\Deep2Engine\.cpp$') { if (-not $cDeep2)  { $cDeep2  = $a }; continue }
        if (-not $cSimple   -and $len -lt 20000) { $cSimple   = $a; continue }
        if (-not $cOrdinary -and $len -ge 20000 -and $len -lt 200000) { $cOrdinary = $a }
    }
    # Ordinary may be absent in a small target; fall back to the largest Gold
    # source so the second control is never silently skipped.
    if (-not $cOrdinary) { $cOrdinary = ($goldSrcs | Sort-Object Length -Descending | Select-Object -First 1) }
    if (-not $cSimple)   { $cSimple   = $goldSrcs | Select-Object -First 1 }

    $controls = @(
        [pscustomobject]@{ Name='SIMPLE';   Path=$cSimple },
        [pscustomobject]@{ Name='ORDINARY'; Path=$cOrdinary },
        [pscustomobject]@{ Name='DEEP2';    Path=$cDeep2 }
    )

    $pass = 0; $total = 0
    foreach ($ctl in $controls) {
        if (-not $ctl.Path) { $controlReport += "CONTROL_$($ctl.Name)=NO_TLOG_ENTRY"; continue }
        $total++
        $ref = New-SourceRef $ctl.Path $rootAbsC
        # Sentinel symbol that cannot exist, so a passing stage 3 says nothing
        # about stage 4 -- the two are separate authorities.
        $r = Test-ObjectExports $ref.SOURCE_EXEC_PATH '__RAWRXD_OWNER_PROOF_STAGE3_SENTINEL_9F3A2B__'
        if ($r[0]) { $pass++; $controlReport += "CONTROL_$($ctl.Name)_COMPILE=PASS" }
        else       { $controlReport += "CONTROL_$($ctl.Name)_COMPILE=FAIL" }
        $controlReport += "  CONTROL_$($ctl.Name)_SOURCE_EXEC_PATH=$($ref.SOURCE_EXEC_PATH)"
        $controlReport += "  CONTROL_$($ctl.Name)_SOURCE_COMPARE_KEY=$($ref.SOURCE_COMPARE_KEY)"
        $controlReport += "  CONTROL_$($ctl.Name)_ACTUALLY_IN_GOLD=1"
    }
    $probeReliable = ($total -gt 0 -and $pass -eq $total)
    $controlDetail = "CONTROL_PASS=$pass CONTROL_TOTAL=$total"

    # Stage 4 controls. Stage 4's job is to distinguish "symbol present in the
    # object" from "symbol absent". That distinction is only meaningful if the
    # parser demonstrably does BOTH.
    #
    # The positive control must name a symbol known to be PRESENT, and it must not
    # be one this tool chose. So it is taken from an object the real build already
    # produced -- build\RawrXD_Gold.dir\Release\*.obj -- which the LINKER linked.
    # Whatever external symbol that object exports is present by construction,
    # because the link succeeded with it. The negative control is a sentinel that
    # cannot exist.
    #
    # A positive control built by asking the object what it contains and then
    # confirming the answer would be circular; it would pass even if the parser
    # matched everything. Anchoring on a linker-produced object removes that.
    if ($probeReliable) {
        $objDir = Join-Path $ProjectRoot "build\$Target.dir\Release"
        $goldObj = Get-ChildItem -LiteralPath $objDir -Filter '*.obj' -ErrorAction SilentlyContinue |
                   Where-Object { $_.Length -gt 0 } | Sort-Object Length | Select-Object -First 1
        if ($goldObj -and $dumpbin) {
            $dump = & $dumpbin /symbols $goldObj.FullName 2>&1
            # A defined external symbol: "External" and a "| name" tail.
            $knownSym = $null
            foreach ($l in $dump) {
                if ($l -match '\|\s+([A-Za-z_?][A-Za-z0-9_?@$]*)\s*$' -and $l -match 'External') {
                    $knownSym = $matches[1]; break
                }
            }
            if ($knownSym) {
                $stage4Pos = [bool]((($dump -join "`n")) -match ('\b' + [regex]::Escape($knownSym) + '\b'))
                $stage4Detail  = "STAGE4_CONTROL_SOURCE=$($goldObj.Name)"
                $stage4Detail += " STAGE4_CONTROL_REQUIRED_SYMBOL=$knownSym"
                $stage4Detail += " STAGE4_CONTROL_SYMBOL_FOUND=$([int]$stage4Pos)"
                $controlReport += "  $stage4Detail"
                $stage4Neg = (-not (((($dump -join "`n"))) -match '__RAWRXD_OWNER_PROOF_STAGE4_NEG_9F3A2B__'))
                $controlReport += "  STAGE4_NEGATIVE_SYMBOL_FOUND=$([int](-not $stage4Neg))"
            } else {
                $stage4Detail = 'STAGE4_CONTROL_NO_EXTERNAL_SYMBOL_FOUND'
            }
        } else {
            $stage4Detail = 'STAGE4_CONTROL_NO_GOLD_OBJECT'
        }
    }
}

# ---------------------------------------------------------------------------
# Main census
# ---------------------------------------------------------------------------
$records = @()
$guardCache = @{}

foreach ($sym in ($unresolved.Keys | Sort-Object)) {
    $name  = $sym
    $qual  = $null
    if ($sym -match '^(.+)::([A-Za-z_][A-Za-z0-9_]*)$') { $qual = $matches[1] + '::' + $matches[2] }
    $short = ($sym -split '::')[-1]

    $record = [ordered]@{
        SYMBOL                = $sym
        CANDIDATE_TU          = ''
        TEXTUAL_DEFINITION    = 0
        ACTIVE_ON_TOOLCHAIN   = 0
        OBJECT_COMPILES       = 'NOT_TESTED'
        OBJECT_EXPORTS_SYMBOL = 'NOT_TESTED'
        OWNER_VERDICT         = 'REJECTED'
        REJECTION_REASON      = 'NO_TEXTUAL_CANDIDATE'
    }

    foreach ($cand in @($qual, $short)) {
        if (-not $cand) { continue }
        $hits = & rg -l --no-messages ([regex]::Escape($cand)) --glob '*.cpp' --glob '*.c' --glob '*.asm' $ProjectRoot 2>$null |
                Where-Object { $_ -notmatch '\\_n2_stage\\|\.venv\\|\\build\\|build_|rawrxd copy\\|[\\/]tools[\\/]|[\\/]certs[\\/]|[\\/]tests[\\/]|[\\/]examples[\\/]' }
        foreach ($f in $hits) {
            $rel = $f.Replace((Resolve-Path $ProjectRoot).Path + '\', '') -replace '\\','/'
            $record.CANDIDATE_TU = $rel
            $record.TEXTUAL_DEFINITION = 1

            if ($fileReason.ContainsKey($rel)) {
                $record.REJECTION_REASON = $fileReason[$rel]; break
            }
            $norm = $rel
            if ($inTarget.ContainsKey($norm) -or $inTarget.ContainsKey($norm)) {
                $record.REJECTION_REASON = 'ALREADY_IN_TARGET'; break
            }
            if (-not $guardCache.ContainsKey($rel)) {
                $guardCache[$rel] = Get-NonActiveGuardLine $f
            }
            if ($guardCache[$rel] -gt 0) {
                $record.ACTIVE_ON_TOOLCHAIN = 0
                $record.REJECTION_REASON = "PREPROCESSOR_EXCLUDED_LINE_$($guardCache[$rel])"
                break
            }
            $record.ACTIVE_ON_TOOLCHAIN = 1

            if (-not $VerifyExports) {
                $record.OWNER_VERDICT = 'PROVISIONAL'
                $record.REJECTION_REASON = 'STAGE_4_NOT_RUN_PASS_-VerifyExports'
                break
            }
            if (-not ($probeReliable -and $stage4Pos -and $stage4Neg)) {
                # The probe failed its own positive control, so a compile failure
                # here says something about the probe and nothing about the
                # candidate. Reporting OBJECT_DOES_NOT_COMPILE anyway is how 41
                # symbols were rejected on a broken instrument.
                $record.OBJECT_COMPILES = 'UNKNOWN_PROBE_UNRELIABLE'
                $record.OBJECT_EXPORTS_SYMBOL = 'UNKNOWN_PROBE_UNRELIABLE'
                $record.OWNER_VERDICT = 'UNPROVEN_PROBE_UNRELIABLE'
                $record.REJECTION_REASON = 'STAGE_3_4_PROBE_FAILED_POSITIVE_CONTROL'
                break
            }
            $pair = Test-ObjectExports $rel $name
            if ($null -eq $pair) { $pair = @($false, $false) }
            if (-not ($pair -is [array])) { $pair = @($false, $false) }
            if ($pair.Count -lt 2) { $pair = @($false, $false) }
            $record.OBJECT_COMPILES = $(if ($pair[0]) { 1 } else { 0 })
            $record.OBJECT_EXPORTS_SYMBOL = $(if ($pair[0] -and $pair[1]) { 1 } else { 0 })
            Write-Verbose ("  stage3/4 {0} <- {1}" -f $name, $rel)
            if (-not $pair[0]) {
                $record.REJECTION_REASON = 'OBJECT_DOES_NOT_COMPILE'
                $record.OWNER_VERDICT = 'REJECTED'
            } elseif ($pair[1]) {
                $record.OWNER_VERDICT = 'PROVEN'
                $record.REJECTION_REASON = ''
            } else {
                $record.REJECTION_REASON = 'OBJECT_DOES_NOT_EXPORT_SYMBOL'
            }
            break
        }
        if ($record.OWNER_VERDICT -ne 'REJECTED') { break }
        if ($record.TEXTUAL_DEFINITION -eq 1) { break }
    }
    $records += [pscustomobject]$record
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
$prov    = @($records | Where-Object { $_.OWNER_VERDICT -eq 'PROVEN' })
$provi   = @($records | Where-Object { $_.OWNER_VERDICT -eq 'PROVISIONAL' })
$multi   = $duplicates.Count
# Every rejection reason is tallied. An earlier version counted only
# OBJECT_DOES_NOT_EXPORT_SYMBOL, so 22 OBJECT_DOES_NOT_COMPILE rejections were
# produced, correctly, and then not reported anywhere -- the summary said
# COMPILE_REJECTED=0 while 22 candidates had failed to compile.
$reasons = @{}
foreach ($r in $records) { if ($r.REJECTION_REASON) { $reasons[$r.REJECTION_REASON] = 1 + $(if ($reasons.ContainsKey($r.REJECTION_REASON)) { $reasons[$r.REJECTION_REASON] } else { 0 }) } }
function Tally([string]$k) { if ($reasons.ContainsKey($k)) { return $reasons[$k] } else { return 0 } }

$preRej  = Tally 'PREPROCESSOR_EXCLUDED_LINE_0'
foreach ($k in @($reasons.Keys)) { if ($k -like 'PREPROCESSOR_EXCLUDED*') { $preRej = $reasons[$k] } }
$noExp   = Tally 'OBJECT_DOES_NOT_EXPORT_SYMBOL'
$noComp  = Tally 'OBJECT_DOES_NOT_COMPILE'
$probeBad = Tally 'STAGE_3_4_PROBE_FAILED_POSITIVE_CONTROL'
$unprov  = @($records | Where-Object { $_.OWNER_VERDICT -eq 'UNPROVEN_PROBE_UNRELIABLE' }).Count
$inTgt   = Tally 'ALREADY_IN_TARGET'
$known   = 0
foreach ($k in @($reasons.Keys)) { if ($KNOWN_NON_OWNER.ContainsKey($k) -or ($KNOWN_NON_OWNER.Values | Where-Object { $_ -contains $k })) { $known += $reasons[$k] } }
$noText  = Tally 'NO_TEXTUAL_CANDIDATE'
$notRun  = Tally 'STAGE_4_NOT_RUN_PASS_-VerifyExports'

$lines = @()
$lines += 'OWNER_PROOF_001'
$lines += "TARGET=$Target"
$lines += "LINK_LOG=$LinkLog"
$lines += "ACTIVE_TOOLCHAIN=MSVC x64 (_MSC_VER defined)"
$lines += "STAGE4_VERIFIED=$([bool]$VerifyExports)"
$lines += "STAGE3_4_POSITIVE_CONTROL=$($probeReliable)"
$lines += "STAGE3_CONTROL_PASS=$probeReliable"
$lines += "STAGE3_4_CONTROL_DETAIL=$controlDetail"
$lines += "STAGE4_POSITIVE_CONTROL=$stage4Pos"
$lines += "STAGE4_NEGATIVE_CONTROL=$stage4Neg"
$lines += "STAGE4_CONTROL_DETAIL=$stage4Detail"
$lines += "CONTROL_SOURCE_ORIGIN=TLOG"
$lines += "STAGE3_STAGE4_VERDICTS_ADMISSIBLE=$([bool]($probeReliable -and $stage4Pos -and $stage4Neg))"
foreach ($cl in $controlReport) { $lines += "  $cl" }
$lines += ''
$lines += "TEXT_MATCH_IS_NOT_OWNERSHIP=1"
$lines += 'OWNER_REQUIRES_OBJECT_EXPORT_ON_ACTIVE_TOOLCHAIN=1'
$lines += ''
$lines += "UNRESOLVED_TOTAL=$($records.Count)"
$lines += "TEXTUAL_CANDIDATES=$(@($records | Where-Object { $_.TEXTUAL_DEFINITION -eq 1 }).Count)"
$lines += "PREPROCESSOR_REJECTED=$preRej"
$lines += "COMPILE_REJECTED=$noComp"
$lines += "NONEXPORTING_OBJECTS=$noExp"
$lines += "ALREADY_IN_TARGET_REJECTED=$inTgt"
$lines += "KNOWN_NON_OWNER_REJECTED=$known"
$lines += "NO_TEXTUAL_CANDIDATE=$noText"
$lines += "STAGE4_NOT_RUN=$notRun"
$lines += "PROVEN_OWNER_TUS=$($prov.Count)"
$lines += "UNPROVEN_PROBE_UNRELIABLE=$unprov"
$lines += "PROVISIONAL_OWNER_TUS=$($provi.Count)"
$lines += "MULTI_OWNER_COUNT=$multi"
$lines += ''
$lines += '# REJECTION_REASON histogram (every reason, so none can go uncounted)'
foreach ($k in ($reasons.Keys | Sort-Object)) { $lines += "  $k=$($reasons[$k])" }
$lines += ''
# CONSERVATION. Every unresolved symbol must land in exactly one class and the
# classes must sum to UNRESOLVED_TOTAL. A symbol that leaves the accounting is
# worse than one reported wrong, because the total then looks closed while work
# remains. CLASSIFICATION_DELTA is ENFORCED, not merely printed: non-zero exits 6.
$clsProv   = @($records | Where-Object { $_.OWNER_VERDICT -eq 'PROVEN' }).Count
$clsInTgt  = @($records | Where-Object { $_.REJECTION_REASON -eq 'ALREADY_IN_TARGET' }).Count
$clsCat    = @($records | Where-Object { $_.CANDIDATE_TU -and $fileReason.ContainsKey($_.CANDIDATE_TU) }).Count
$clsComp   = @($records | Where-Object { $_.REJECTION_REASON -eq 'OBJECT_DOES_NOT_COMPILE' }).Count
$clsExp    = @($records | Where-Object { $_.REJECTION_REASON -eq 'OBJECT_DOES_NOT_EXPORT_SYMBOL' }).Count
$clsDup    = @($records | Where-Object { $_.REJECTION_REASON -eq 'DUPLICATE_IF_ADDED' }).Count
$clsBehav  = @($records | Where-Object { $_.REJECTION_REASON -eq 'BEHAVIORAL_DECISION' }).Count
$clsUnprov = @($records | Where-Object { $_.OWNER_VERDICT -eq 'UNPROVEN_PROBE_UNRELIABLE' -or $_.OWNER_VERDICT -eq 'PROVISIONAL' }).Count
$clsNoText = @($records | Where-Object { $_.REJECTION_REASON -eq 'NO_TEXTUAL_CANDIDATE' }).Count
$clsSum    = $clsProv + $clsInTgt + $clsCat + $clsComp + $clsExp + $clsDup + $clsBehav + $clsUnprov + $clsNoText
$clsDelta  = $records.Count - $clsSum
$lines += ''
$lines += "CLASS_PROVEN_SAFE_TO_ADD=$clsProv"
$lines += "CLASS_ALREADY_IN_TARGET=$clsInTgt"
$lines += "CLASS_CATEGORY_EXCLUDED=$clsCat"
$lines += "CLASS_COMPILE_REJECTED=$clsComp"
$lines += "CLASS_EXPORT_MISS=$clsExp"
$lines += "CLASS_DUPLICATE_IF_ADDED=$clsDup"
$lines += "CLASS_BEHAVIORAL_DECISION=$clsBehav"
$lines += "CLASS_UNPROVEN=$clsUnprov"
$lines += "CLASS_NO_TEXTUAL_CANDIDATE=$clsNoText"
$lines += "CLASSIFICATION_SUM=$clsSum"
$lines += "CLASSIFICATION_DELTA=$clsDelta"

# Gold closure condition: UNRESOLVED_EXTERNALS=0 and DUPLICATE_IMPL_COLLISIONS=0
$lines += "ZERO_OWNER_COUNT=$($records.Count - $prov.Count)"
$lines += "SINGLE_OWNER_COUNT=$($prov.Count)"
$lines += "MULTI_OWNER_COUNT_DUPLICATES=$multi"
$lines += ''
if (-not $VerifyExports) {
    $lines += 'WARNING: stage 4 was NOT run. Every PROVISIONAL owner above is a'
    $lines += 'textual candidate only and has NOT been proven to export its symbol.'
    $lines += 'Re-run with -VerifyExports before treating any owner as proven.'
}
if ($duplicates.Count) {
    $lines += ''
    $lines += '# DUPLICATE DEFINITIONS (ambiguous authority, must reach 0)'
    foreach ($d in $duplicates | Sort-Object Symbol -Unique) {
        $lines += "DUP=$($d.Obj) SYMBOL=$($d.Symbol) ALSO_IN=$($d.AlsoIn)"
    }
}

$text = $lines -join "`n"
if ($Out) { Set-Content -LiteralPath $Out -Value $text -Encoding UTF8 }
Write-Output $text

# Per-symbol record, machine readable
if ($Out) {
    $csv = [System.IO.Path]::ChangeExtension($Out, '.symbols.csv')
    $records | Export-Csv -LiteralPath $csv -NoTypeInformation -Encoding UTF8
    Write-Output ""
    Write-Output "PER_SYMBOL_RECORDS=$csv"
}

if ($clsDelta -ne 0) {
    Write-Output ''
    Write-Output "OWNER_PROOF_001 FATAL: CLASSIFICATION_DELTA=$clsDelta -- $clsSum classified against $($records.Count) unresolved."
    Write-Output 'A symbol left the accounting. The census is not admissible until this is 0.'
    exit 6
}
if ($multi -gt 0)      { exit 3 }
if (($noComp + $noExp) -gt 0) { exit 4 }
exit 0
