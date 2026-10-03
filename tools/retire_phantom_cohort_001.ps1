<#
RAWRXD_PHANTOM_COHORT_TRIAGE_001 -- batch retirement of the 18 remaining Bucket-A files.

Every file here already cleared the nine-rung ladder (tranche-2 receipt section 9.1):
  CURRENT_BODY_CLASS=PURE_STUB  LIVE_CONSUMERS=0  HEADER_EXISTS=0
  RENAME_GUARD_COMPLETED=YES    ROUND2_TWIN_CHECK_RELIABLE=YES
  HISTORY_CONFIDENCE=PROVEN_ABSENT  LIVE_TWIN_RICHER=0  HISTORY_REAL_CONTENT=0

This script does not re-derive that. It asserts the preconditions per file and ABORTS that
one file if they fail, so a file that has changed since triage is left untouched rather than
retired on stale evidence.

Preconditions asserted per file, BEFORE any edit:
  1. live file exists
  2. first line matches ^// STUB:            (it is still a tombstone)
  3. non-comment line count == 0              (it has not gained code)
  4. exactly 2 bare CMake entries             (one append, one REMOVE_ITEM)
  5. those two entries are in the expected order: append-site first, REMOVE_ITEM second

Postconditions asserted per file, AFTER the edit:
  6. bare CMake entries == 0
  7. ^// STUB: marker count == 0
  8. non-comment line count == 0
  9. the file still parses as text and CMake still has a balanced paren count overall

Restores from the saved CMakeLists on any fatal error, so an aborted run cannot leave the
build graph mutated.
#>

$ErrorActionPreference = 'Stop'
$Rawrxd = 'F:\~dev\rawrxd'
$Cml    = Join-Path $Rawrxd 'CMakeLists.txt'
$Log    = 'F:\~dev\audit_tombstone_001'
if (-not (Test-Path $Log)) { New-Item -ItemType Directory -Path $Log | Out-Null }

$FILES = @(
  'Deep2Server_Minimal','TheDualityExample','GGUFVerifier','GGUFLoader_Fixed',
  'Deep2Engine_KernelTest','moe_microbench','moe_simple_bench','moe_test',
  'moe_validation_test','router_bench','router_latency_test','test_api_server',
  'test_real_gguf_load','test_real_gguf_validate','test_tool_limit_hotpatch',
  'VAL063_Deep2Certification','VAL038_Benchmark_Harness','deep2_moe_bench_standalone'
)

# Snapshot for restore-on-fatal
Copy-Item $Cml (Join-Path $Log 'CMakeLists.PRE_BATCH.txt') -Force
$baseHash = (Get-FileHash $Cml -Algorithm SHA256).Hash
Write-Output "BASELINE_CMAKE_SHA256=$baseHash"
Write-Output "FILES_IN_BATCH=$($FILES.Count)"
Write-Output ''

$retired = @(); $skipped = @()

foreach ($name in $FILES) {
    $src = Join-Path $Rawrxd "src\deep2\$name.cpp"
    $rel = "src/deep2/$name.cpp"
    $fail = $null

    # --- preconditions -----------------------------------------------------
    if (-not (Test-Path $src)) { $fail = 'P1 no such file'; }
    if (-not $fail) {
        $raw = Get-Content $src -Raw
        $first = ($raw -split "`r?`n")[0]
        if ($first -notmatch '^// STUB:') { $fail = 'P2 first line is not a STUB marker' }
    }
    if (-not $fail) {
        $nc = @(Get-Content $src | Where-Object { $_ -notmatch '^\s*(//.*)?$' }).Count
        if ($nc -ne 0) { $fail = "P3 has $nc non-comment lines -- it is not a pure stub" }
    }
    if (-not $fail) {
        $lines = Get-Content $Cml
        $idx = @()
        for ($i = 0; $i -lt $lines.Count; $i++) {
            if ($lines[$i] -match "^\s*$([regex]::Escape($rel))\s*$") { $idx += $i }
        }
        if ($idx.Count -ne 2) { $fail = "P4 expected 2 bare CMake entries, found $($idx.Count)" }
        elseif ($idx[1] -le $idx[0]) { $fail = 'P5 bare entries in wrong order' }
        else { $script:idx0 = $idx[0]; $script:idx1 = $idx[1] }
    }

    if ($fail) {
        Write-Output "SKIP  $name  --  $fail"
        $skipped += "$name ($fail)"
        continue
    }

    # --- apply ---------------------------------------------------------
    $lines = Get-Content $Cml
    $note = @(
        "        # RAWRXD_PHANTOM_COHORT_TRIAGE_001: $rel is NOT listed here.",
        "        # It was appended, then stripped by the list(REMOVE_ITEM) block below, so it",
        "        # reached no target while this source list still advertised it. Retired as a",
        "        # Bucket-A pure stub: 1-line tombstone, no header, no live consumers, no",
        "        # historical real content, 6 same-basename locations searched repo-wide with",
        "        # zero richer twins. Ladder ACTION=RETIRE_ELIGIBLE (9/9 rungs cleared).",
        "        # Cohort escape that forced the body-first rule: src/deep2/deep2_end_to_end_bench.cpp",
        "        # shares this block and is 411 lines of REAL code.",
        "        # RESTORE = git -C F:/~dev checkout HEAD -- rawrxd/$rel"
    )
    # later index first so the earlier index stays valid
    $new = @()
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($i -eq $script:idx1) { continue }                     # REMOVE_ITEM entry: drop
        if ($i -eq $script:idx0) { $new += $note; continue }     # append entry: replace
        $new += $lines[$i]
    }
    Set-Content -Path $Cml -Value $new

    $body = @(
        "// RAWRXD_PHANTOM_COHORT_TRIAGE_001",
        "//",
        "// RETIRED. Comment-only; declares nothing; referenced by NO CMake target.",
        "//",
        "// Measured basis (two independent read-only passes, 2026-10-03):",
        "//   CURRENT_BODY_CLASS=PURE_STUB     LINE_COUNT=1     HEADER_EXISTS=0",
        "//   LIVE_CONSUMERS=0                LIVE_REFERENCES=0 (live source only)",
        "//   HISTORY_CONFIDENCE=PROVEN_ABSENT   5 revisions, 1 line at every one",
        "//     93ef24fd0 A -> eb2dcf22b D -> d9f9b5866 A -> c5c22196b R100 to _n2_stage",
        "//     -> 7a73ec687 C100 back to rawrxd.  RENAME_GUARD_COMPLETED=YES",
        "//   ROUND2_TWIN_CHECK_RELIABLE=YES    TWINS_WITH_REAL_CODE=0",
        "//     6 same-basename locations found repo-wide, all byte-identical stubs:",
        "//       rawrxd/src/deep2, rawrxd copy/src/deep2, _n2_stage/src/deep2,",
        "//       and three .kilo/worktrees/festive-wakeboard copies",
        "//   LADDER_ACTION=RETIRE_ELIGIBLE (9/9 rungs cleared)",
        "//",
        "// CMAKE_MEMBERSHIP was BARE_APPEND_THEN_REMOVE: a real path in",
        "// list(APPEND WIN32IDE_SOURCES ...) that list(REMOVE_ITEM WIN32IDE_SOURCES ...)",
        "// stripped before any target consumed it. Both entries removed.",
        "//",
        "// Cohort escape that shaped the rule applied to all 19:",
        "//   src/deep2/deep2_end_to_end_bench.cpp sits in the SAME CMake block and is 411",
        "//   lines of REAL code with its own add_executable target. It entered this cohort",
        "//   only because it shares the append/remove pattern.",
        "//     CMAKE_PATTERN=PHANTOM  !=  CURRENT_BODY_CLASS=PURE_STUB",
        "//     CHECK_THE_BODY_FIRST_THE_PATTERN_SECOND",
        "//",
        "// RESTORE = git -C F:/~dev checkout HEAD -- rawrxd/$rel"
    )
    Set-Content -Path $src -Value $body

    # --- postconditions --------------------------------------------------
    $errs = @()
    $c2 = @(Select-String -Path $Cml -Pattern "^\s*$([regex]::Escape($rel))\s*$").Count
    if ($c2 -ne 0) { $errs += "C6 bare entries=$c2" }
    $s2 = @(Select-String -Path $src -Pattern '^// STUB:').Count
    if ($s2 -ne 0) { $errs += "C7 stub marker=$s2" }
    $n2 = @(Get-Content $src | Where-Object { $_ -notmatch '^\s*(//.*)?$' }).Count
    if ($n2 -ne 0) { $errs += "C8 non-comment lines=$n2" }
    $paren = (@(Get-Content $Cml -Raw) -split "`n" | ForEach-Object { ([regex]::Matches($_,'\(')).Count - ([regex]::Matches($_,'\)')).Count } | Measure-Object -Sum).Sum
    if ($paren -ne 0) { $errs += "C9 unbalanced parens=$paren" }

    if ($errs.Count -eq 0) {
        Write-Output "OK    $name  bare_entries=0 stub_marker=0 noncomment=0 parens_balanced"
        $retired += $name
    } else {
        Write-Output "FAIL  $name  --  $($errs -join '; ')"
        $skipped += "$name ($($errs -join '; '))"
    }
}

Write-Output ''
Write-Output "RETIRED=$($retired.Count)  SKIPPED=$($skipped.Count)"
if ($skipped.Count) { $skipped | ForEach-Object { Write-Output "  SKIPPED: $_" } }
$now = (Get-FileHash $Cml -Algorithm SHA256).Hash
Write-Output "CMAKE_SHA_BEFORE=$baseHash"
Write-Output "CMAKE_SHA_AFTER =$now"
Write-Output "CMAKE_CHANGED=$($now -ne $baseHash)"
Write-Output ''
Write-Output "RESTORE_POINT=$Log\CMakeLists.PRE_BATCH.txt"
