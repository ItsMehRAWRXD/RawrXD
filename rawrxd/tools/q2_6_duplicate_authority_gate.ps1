# Q2.6 — Tree-wide duplicate-authority classification gate
# Authority: RAWRXD_DUPLICATE_AUTHORITY_001
#
# The dangerous condition is NOT "a class name appears twice". It is:
#
#     same fully-qualified authority
#   + two definitions
#   + BOTH reachable by one build configuration
#
# That is what EventLedger was. Fifteen other FQNs share a name; most are
# harmless variants where only one header is ever included. This gate derives
# reachability from the include graph and target membership, so it can tell the
# two apart BEFORE a compile is spent.
#
# It also folds in entry-point collisions (two `main()` reaching one
# executable), which is the same failure at link scope.
#
# Classification per FQN:
#   LIVE_DUPLICATE_DEFECT   both definitions reach the same target
#   MUTUALLY_EXCLUSIVE      both defined, but no single TU includes both headers
#   BUILD_VARIANT           only one definition is included by anything built
#   DEAD_QUARANTINE         no definition is included by anything built
#   CANONICAL               single definition (reported for completeness)

$ErrorActionPreference = "Stop"
$root = "F:\~dev"
$fail = 0
function Say($k, $v) { "{0,-52} = {1}" -f $k, $v }
function Bump($n, $v) { if ($v -ne 0) { $script:fail++; "  *** $n = $v ***" } }

# ---------------------------------------------------------------- targets
# Parse target -> source list from the build files that matter.
$targetSrc = @{}          # target -> list of source paths (repo-relative, /)
$targetName = @{}
function Add-Target([string]$tname, [string[]]$srcs, [string]$file) {
    $targetSrc[$tname] = $srcs
    $targetName[$tname] = $file
}

# CORRECTION: the first version parsed only these two files. It therefore never
# saw rawrxd/CMakeLists.txt (16842 lines, dozens of targets), and reported
# agentic/ToolRegistry.cpp and agent/AgentCore.cpp as unreachable when they are
# in fact listed there 4x and 1x respectively. Every DEAD_QUARANTINE verdict
# from that version was scoped to too small a target set.
foreach ($cm in @("$root\CMakeLists.txt",
                  "$root\rawrxd\CMakeLists.txt",
                  "$root\rawrxd\win32ide_strict\CMakeLists.txt")) {
    if (-not (Test-Path $cm)) { continue }
    $lines = Get-Content $cm
    $cur = $null
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $l = $lines[$i]
        if ($l -match '^\s*(add_executable|add_library)\s*\(?\s*([A-Za-z0-9_\-]+)') {
            $cur = $matches[2]
            if (-not $targetSrc.ContainsKey($cur)) { $targetSrc[$cur] = @(); $targetName[$cur] = $cm }
            continue
        }
        # a line that is just ")" closes the current source list
        if ($l -match '^\s*\)\s*$') { $cur = $null; continue }
        if ($null -ne $cur -and $l -match '^\s+([A-Za-z0-9_\-/\.]+\.(cpp|c|asm))\s*$') {
            $p = $matches[1]
            # normalise to repo-relative with forward slashes
            $p = $p -replace '^\$\{CMAKE_CURRENT_SOURCE_DIR\}/', ''
            $p = $p -replace '^\.\./', ''
            $targetSrc[$cur] += $p
        }
    }
}
# resolve each target source to an absolute path for existence checks
$targetAbs = @{}
foreach ($k in $targetSrc.Keys) {
    $abs = @()
    foreach ($s in $targetSrc[$k]) {
        $cands = @("$root\$($s -replace '/','\')", "$root\rawrxd\$($s -replace '/','\')",
                   "$root\rawrxd\win32ide_strict\$($s -replace '/','\')")
        foreach ($c in $cands) { if (Test-Path $c) { $abs += $c; break } }
    }
    $targetAbs[$k] = $abs
}
Say "TARGETS_PARSED" $targetAbs.Count
foreach ($k in ($targetAbs.Keys | Sort-Object)) { "    {0,-26} {1} sources" -f $k, $targetAbs[$k].Count }

# ---------------------------------------------------------------- includers
# Map: header ID -> set of absolute files that #include it.
#
# The key MUST be a path-qualified ID, not a bare basename. There are two
# distinct headers named Deep2StackGuard.h (rawrxd/src/deep2/ and
# rawrxd/src/deep2/expert_cache/). Keying by basename conflated them and
# reported two unrelated FQNs as duplicates of each other.
$allCode = Get-ChildItem "$root\rawrxd\src","$root\src" -Recurse -Include *.cpp,*.hpp,*.h,*.c -ErrorAction SilentlyContinue
$includers = @{}
$ambiguous = @{}
function Get-HeaderId([string]$path) {
    $p = $path -replace [regex]::Escape("$root\"), ""
    $p = $p -replace [regex]::Escape("$root\rawrxd\src\"), "rawrxd/src/"
    $p = $p -replace [regex]::Escape("$root\src\"), "src/"
    return $p
}
# Index EVERY header by basename so a bare #include can be resolved against
# real files. Guessing a fixed list of candidate directories silently drops
# most includes and under-reports reachability, which would turn this gate into
# another false-zero. (First draft did exactly that: 1540 -> 679 resolved.)
$headerIndex = @{}
foreach ($h in ($allCode | Where-Object { $_.Extension -in @('.hpp', '.h') })) {
    $b = $h.Name
    if (-not $headerIndex.ContainsKey($b)) { $headerIndex[$b] = @() }
    $headerIndex[$b] += (Get-HeaderId $h.FullName)
}

function Resolve-Include([string]$inc, [string]$selfDirRel) {
    if ($inc -match '/') {
        $c = $inc -replace '^\./', ''
        if ($c -match '\.\.') { return @() }
        return @($c | Where-Object { $headerIndex.Values -contains $_ })
    }
    $b = $inc
    if (-not $headerIndex.ContainsKey($b)) { return @() }
    $all = $headerIndex[$b]
    # Prefer the including file's own directory (that is what the compiler does
    # first for quoted includes), then any other single match.
    # NOTE: compare with normalised separators. IDs are built from absolute
    # paths and therefore contain backslashes; a forward-slash pattern here
    # never matches and would misreport every same-directory include as
    # ambiguous.
    $selfNorm = ($selfDirRel -replace '\\','/')
    $sameDir = $all | Where-Object {
        $n = ($_ -replace '\\','/')
        ($n -eq "$selfNorm/$b") -or ($n -like "*/$selfNorm/$b")
    }
    if ($sameDir) { return @($sameDir) }
    if ($all.Count -eq 1) { return @($all) }
    $script:ambiguous[$b] = $all
    return @($all)
}

foreach ($f in $allCode) {
    $lines = Get-Content $f.FullName -ErrorAction SilentlyContinue
    if (-not $lines) { continue }
    $selfDirRel = ((Get-HeaderId $f.DirectoryName) -replace '\\','/')
    foreach ($l in $lines) {
        if ($l -match '^\s*#\s*include\s*[<"]([^>"]+)[>"]') {
            $inc = $matches[1]
            foreach ($rid in (Resolve-Include $inc $selfDirRel)) {
                if (-not $includers.ContainsKey($rid)) { $includers[$rid] = @() }
                if ($includers[$rid] -notcontains $f.FullName) { $includers[$rid] += $f.FullName }
            }
        }
    }
}
if ($ambiguous.Count -gt 0) {
    Say "AMBIGUOUS_BARE_INCLUDES" $ambiguous.Count
    foreach ($k in ($ambiguous.Keys | Sort-Object)) {
        "    {0} -> {1}" -f $k, ($ambiguous[$k] -join " | ")
    }
}
Say "CODE_FILES_SCANNED" $allCode.Count
Say "DISTINCT_HEADERS_INCLUDED" $includers.Count

# ---------------------------------------------------------------- duplicate FQNs
# Definitions only (a definition has a body or inherits; a forward decl ends ';').
$defs = @{}
foreach ($f in $allCode) {
    if ($f.Extension -notin @('.hpp', '.h')) { continue }
    $ns = ""
    $lines = Get-Content $f.FullName -ErrorAction SilentlyContinue
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $l = $lines[$i]
        if ($l -match '^\s*namespace\s+([A-Za-z0-9_]+)\s*\{') { $ns = $matches[1] }
        if ($l -match '^\s*class\s+([A-Za-z0-9_]+)\s*(final\s*)?(:|\{)' -and
            $l -notmatch '^\s*class\s+[A-Za-z0-9_]+\s*;') {
            $fqn = $(if ($ns) { "$ns::$($matches[1])" } else { $matches[1] })
            if (-not $defs.ContainsKey($fqn)) { $defs[$fqn] = @() }
            $defs[$fqn] += $f.FullName
        }
    }
}
$dups = @($defs.GetEnumerator() | Where-Object { ($_.Value | Sort-Object -Unique).Count -gt 1 } |
         Sort-Object Name)
Say "DUPLICATE_FQN_TOTAL" $dups.Count

# Which targets own each includer, and which own each defining header's TU.
function Get-TargetsOfFiles([string[]]$files) {
    $out = @()
    foreach ($t in $targetAbs.Keys) {
        foreach ($tf in $targetAbs[$t]) {
            foreach ($f in $files) {
                if ($f -and ((Resolve-Path $f -ErrorAction SilentlyContinue).Path -eq
                             (Resolve-Path $tf -ErrorAction SilentlyContinue).Path)) {
                    if ($out -notcontains $t) { $out += $t }
                }
            }
        }
    }
    return $out
}

$liveDefects = @()
$unclassified = @()
$rows = @()

foreach ($d in $dups) {
    $headers = @($d.Value | Sort-Object -Unique)
    # per-header reachability
    $perHeader = @()
    foreach ($h in $headers) {
        $hid = Get-HeaderId $h
        $inc  = @()
        if ($includers.ContainsKey($hid)) { $inc = $includers[$hid] }
        # a header is also "reached" if it is itself compiled as a source
        $incTargets = Get-TargetsOfFiles $inc
        $ownTargets = @()
        foreach ($t in $targetAbs.Keys) { if ($targetAbs[$t] -contains $h) { $ownTargets += $t } }
        $perHeader += [pscustomobject]@{
            Header = $h; ID = $hid; Includers = $inc; Targets = @($incTargets + $ownTargets | Sort-Object -Unique)
        }
    }
    # LIVE = some single target appears in BOTH sides' target sets
    $shared = $null
    for ($i = 0; $i -lt $perHeader.Count; $i++) {
        for ($j = $i + 1; $j -lt $perHeader.Count; $j++) {
            $inter = @($perHeader[$i].Targets | Where-Object { $perHeader[$j].Targets -contains $_ })
            if ($inter.Count -gt 0) { $shared = $inter; break }
        }
        if ($shared) { break }
    }
    # MUTUALLY_EXCLUSIVE = both defined and both reached, but never by one target
    $bothReached = @($perHeader | Where-Object { $_.Targets.Count -gt 0 }).Count
    if ($shared) {
        $cls = "LIVE_DUPLICATE_DEFECT"
        $liveDefects += $d.Name
    } elseif ($bothReached -ge 2) {
        $cls = "MUTUALLY_EXCLUSIVE"
    } elseif ($bothReached -eq 1) {
        $cls = "BUILD_VARIANT"
    } else {
        $cls = "DEAD_QUARANTINE"
    }
    $rows += [pscustomobject]@{
        FQN = $d.Name; Class = $cls
        Headers = ($headers | ForEach-Object { Get-HeaderId $_ }) -join " | "
        Targets = (($perHeader | ForEach-Object { $_.Targets }) | Sort-Object -Unique) -join ","
        Shared = $(if ($shared) { $shared -join "," } else { "-" })
    }
}

Write-Host ""
Write-Host "FQN CLASSIFICATION"
Write-Host "-----------------------------------------------------------------"
foreach ($r in $rows) {
    "{0,-42} {1,-24}" -f $r.FQN, $r.Class
    "    headers: {0}" -f $r.Headers
    "    targets: {0}   shared: {1}" -f $r.Targets, $r.Shared
}
Write-Host ""

$byClass = $rows | Group-Object Class | Sort-Object Name
foreach ($g in $byClass) { Say "CLASS_$($g.Name.ToUpper())" $g.Count }

# ------------------------------------------------------- entry-point collisions
Write-Host ""
Write-Host "ENTRY-POINT COLLISIONS"
Write-Host "-----------------------------------------------------------------"
$mainDef = @{}
foreach ($f in $allCode) {
    if ($f.Extension -ne '.cpp') { continue }
    $m = Select-String -Path $f.FullName -Pattern '^\s*int\s+main\s*\(' -ErrorAction SilentlyContinue
    if ($m) { $mainDef[$f.FullName] = $true }
}
$epCollisions = @()
$dupListings = @()
foreach ($t in $targetAbs.Keys) {
    # A source listed twice in one target is a manifest defect, NOT two entry
    # points. CMake de-duplicates sources, so it does not produce a link error.
    # Counting it as a collision produced a false positive on target `rawrxd`,
    # where src/win32app/cli_main_headless.cpp appears at lines 268 and 13849.
    $all2 = @($targetAbs[$t])
    $distinct = @($all2 | Sort-Object -Unique)
    if ($all2.Count -ne $distinct.Count) {
        $d = @($all2 | Group-Object | Where-Object { $_.Count -gt 1 })
        $dupListings += $t
        "  {0}: {1} source(s) listed more than once" -f $t, (($d | ForEach-Object { "$($_.Name)x$($_.Count)" }) -join ", ")
    }
    $mains = @($distinct | Where-Object { $mainDef.ContainsKey($_) })
    if ($mains.Count -gt 1) {
        $epCollisions += $t
        "  {0}: {1} DISTINCT entry points" -f $t, $mains.Count
        foreach ($mm in $mains) { "      {0}" -f $mm.Replace("$root\", "") }
    }
}
Say "TARGETS_WITH_DUPLICATE_SOURCE_LISTING" $dupListings.Count
Say "CANONICAL_TARGET_ENTRYPOINT_COLLISIONS" $epCollisions.Count
Bump "ENTRYPOINT_COLLISIONS" $epCollisions.Count

# ---------------------------------------------------------------- verdict
$unclassified = @($rows | Where-Object { $_.Class -notmatch '^(LIVE_DUPLICATE_DEFECT|MUTUALLY_EXCLUSIVE|BUILD_VARIANT|DEAD_QUARANTINE|CANONICAL)$' })
Say "UNCLASSIFIED" $unclassified.Count
Say "LIVE_DUPLICATE_DEFECTS" $liveDefects.Count
Bump "LIVE_DUPLICATE_DEFECTS" $liveDefects.Count
Bump "UNCLASSIFIED" $unclassified.Count
if ($liveDefects.Count -gt 0) {
    Write-Host ""
    Write-Host "LIVE DUPLICATE DETECTS (must be remediated before Q3):"
    foreach ($l in $liveDefects) { "    $l" }
}

Write-Host "-----------------------------------------------------------------"
Write-Host "Q2_6_FAIL=$fail"
Write-Host "VERDICT=$(if ($fail -eq 0) { 'PASS' } else { 'FAIL' })"
exit $(if ($fail -eq 0) { 0 } else { 1 })
