# ============================================================================
# authority_census.ps1 — RAWRXD_AUTHORITY_SURFACE_CENSUS_001
#
# The grep this replaces answers "does the name appear in a text file", which
# proves 30 MATCHES and nothing else. A name in a ledger is a claim. This tool
# walks the evidence chain for every name and reports the strongest state that is
# actually supported:
#
#   RETRACTED            the project's own record withdraws it
#   STALE_CLAIM          documented as stale / not complete / false-pass
#   PLAN_ONLY            appears only under .kilo/plans
#   DOCUMENTATION_ONLY    named in AGENTS.md/agent.md, no source anywhere
#   UNIMPLEMENTED_STUB    source exists and is a stub
#   SOURCE_DECLARED      header only, or no implementation body
#   SOURCE_IMPLEMENTED   header + non-stub implementation
#   CMAKE_WIRED          named in a CMake source list
#   BINARY_REACHABLE     the literal is present in a built artifact
#   RUNTIME_PROVEN       a receipt exists for it
#
# The promotion rule is the user's, verbatim in intent: an authority may only be
# called proven when source exists AND the body is real AND a target compiles it
# AND production reaches it AND a receipt came from that path. This tool reports
# how far up that chain each name has climbed and refuses to collapse the gaps.
# ============================================================================
param(
    [string]$Root = "F:\~dev",
    [string]$Project = "rawrxd",
    [string]$OutDir = "F:\~dev\rawrxd\receipts\RAWRXD_AUTHORITY_SURFACE_CENSUS_001",
    [string[]]$BinaryGlobs = @(
        "F:\~dev\rawrxd\build\*.exe",
        "G:\~dev\rawrxd\build\bin\*.exe",
        "C:\Users\Garrett\AppData\Local\Temp\kilo\cmtp\Release\*.exe"
    )
)
$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

# --- stub markers: an authority whose body is only these is not implemented --
$stubMarkers = @(
    '// STUB', '/* STUB', 'UNIMPLEMENTED', 'IMPLEMENTED_BUILT_UNADOPTED',
    'ORPHAN_AUTHORITY', 'CAN_REPORT_PASS=0', 'THIS AUTHORITY CANNOT PASS'
)
$retractionMarkers = @('RETRACT', 'FALSE_PASS', 'FALSE PASS', 'NOT_COMPLETE', 'STALE')

function Normalize-Name([string]$s) {
    ($s -replace '[^A-Za-z0-9]', '').ToUpperInvariant()
}

# RAWRXD_COMPUTE_ROUTE_AUTHORITY_001 -> RAWRXDCOMPUTEROUTEAUTHORITY001
# The distinctive middle is what maps to a filename, so keep a version that has
# the wrapper words removed: COMPUTEROUTE.
function Core-Tokens([string]$name) {
    $core = $name -replace '^RAWRXD_', '' -replace '_AUTHORITY_\d+$', ''
    return Normalize-Name $core
}

# ---------------------------------------------------------------------------
# 1. Enumerate names from every text surface.
# ---------------------------------------------------------------------------
$sources = @{}
$textFiles = @()
foreach ($pattern in @("$Root\AGENTS.md", "$Root\agent.md", "$Root\AGENT.md")) {
    if (Test-Path -LiteralPath $pattern) { $textFiles += $pattern }
}
foreach ($d in @("$Root\.kilo\plans", "$Root\.kilo\command", "$Root\.kilo\agent")) {
    if (Test-Path -LiteralPath $d) {
        $textFiles += (Get-ChildItem -LiteralPath $d -Recurse -File -Include *.md,*.json -ErrorAction SilentlyContinue).FullName
    }
}
if (Test-Path -LiteralPath "$Root\$Project\audit") {
    $textFiles += (Get-ChildItem -LiteralPath "$Root\$Project\audit" -Recurse -File -Filter *.md -ErrorAction SilentlyContinue).FullName
}

$namePattern = 'RAWRXD_[A-Z0-9_]*AUTHORITY_[0-9]+'
foreach ($tf in $textFiles) {
    $t = Get-Content -LiteralPath $tf -ErrorAction SilentlyContinue
    if (-not $t) { continue }
    foreach ($line in $t) {
        foreach ($m in [regex]::Matches($line, $namePattern)) {
            $n = $m.Value
            if (-not $sources.ContainsKey($n)) {
                $sources[$n] = [ordered]@{ docs = @(); planOnly = $true; retracted = $false; stale = $false }
            }
            $sources[$n].docs += $tf
            if ($tf -like '*\.kilo\plans\*') { $sources[$n].planOnly = $false }
            $u = $line.ToUpperInvariant()
            foreach ($rm in $retractionMarkers) {
                if ($u -like "*$rm*") {
                    if ($rm -eq 'RETRACT' -or $rm -like '*FALSE*') { $sources[$n].retracted = $true }
                    else { $sources[$n].stale = $true }
                }
            }
        }
    }
}

Write-Output "NAMES_IN_TEXT=$($sources.Count)"

# ---------------------------------------------------------------------------
# 2. Source surface: map each name to candidate files by normalised core token.
# ---------------------------------------------------------------------------
$srcRoots = @("$Root\$Project\src", "$Root\$Project\include")
$allFiles = @()
foreach ($sr in $srcRoots) {
    if (Test-Path -LiteralPath $sr) {
        $allFiles += (Get-ChildItem -LiteralPath $sr -Recurse -File -Include *.h,*.hpp,*.cpp,*.c -ErrorAction SilentlyContinue)
    }
}
Write-Output "SOURCE_FILES_SCANNED=$($allFiles.Count)"

# Group by normalised basename so a header is never classified without its .cpp
# sibling. Matching a single file and judging the authority by that file alone
# reported ComputeBenchmarkAuthority.h (398 bytes) as SOURCE_DECLARED while its
# 1782-byte implementation sat next to it, and it reported GIT_SAFETY against a
# tools\*.ps1 seal script because the match was the first entry an unordered
# dictionary happened to yield.
$groups = @{}
foreach ($f in $allFiles) {
    $key = Normalize-Name $f.BaseName
    if (-not $groups.ContainsKey($key)) { $groups[$key] = New-Object System.Collections.ArrayList }
    [void]$groups[$key].Add($f)
}
$groupKeys = @($groups.Keys) | Sort-Object

# ---------------------------------------------------------------------------
# 3. CMake wiring and receipt evidence.
# ---------------------------------------------------------------------------
$cmakePath = "$Root\$Project\CMakeLists.txt"
$cmakeText = if (Test-Path -LiteralPath $cmakePath) { Get-Content -Raw -LiteralPath $cmakePath } else { '' }
$receiptRoot = "$Root\$Project\receipts"
$receiptNames = @{}
if (Test-Path -LiteralPath $receiptRoot) {
    foreach ($d in (Get-ChildItem -LiteralPath $receiptRoot -Directory -ErrorAction SilentlyContinue)) {
        $receiptNames[$d.Name] = $true
    }
}

# Binary literals: which authority names are physically inside a built artifact.
$binaries = @()
foreach ($g in $BinaryGlobs) {
    if (Test-Path -LiteralPath $g) {
        $binaries += (Get-ChildItem -Path $g -File -ErrorAction SilentlyContinue)
    }
}
# Zero binaries is NOT a finding of "nothing is reachable". It is an unmeasured
# axis, and reporting it as 0 would make RUNTIME_PROVEN=0 and
# BINARY_REACHABLE=0 look like results when they are gaps in the instrument.
if ($binaries.Count -eq 0) {
    Write-Output "BINARY_SCAN=NOT_MEASURED (no artifacts matched; BINARY_REACHABLE and RUNTIME_PROVEN cannot be concluded)"
} else {
    Write-Output "BINARY_SCAN=PERFORMED"
}
Write-Output "BINARIES_SCANNED=$($binaries.Count)"
$binText = @{}
foreach ($b in $binaries) {
    try {
        $bytes = [System.IO.File]::ReadAllBytes($b.FullName)
        $s = [System.Text.Encoding]::ASCII.GetString($bytes)
        $binText[$b.FullName] = $s
    } catch { }
}

# ---------------------------------------------------------------------------
# 4. Classify. Highest proven state wins; retraction dominates everything.
# ---------------------------------------------------------------------------
$results = @()
foreach ($name in ($sources.Keys | Sort-Object)) {
    $info = $sources[$name]
    $core = Core-Tokens $name
    $stem = $core -replace 'AUTHORITY$', ''

    # Deterministic, and an exact match on the full authority basename wins over
    # a substring hit. Iteration order must not decide which file answers for an
    # authority.
    $file = $null
    $group = $null
    $exactKey = Normalize-Name ("$stem" + 'Authority')
    if ($groups.ContainsKey($exactKey)) { $group = $groups[$exactKey] }
    else {
        foreach ($k in $groupKeys) {
            if ($stem.Length -ge 6 -and $k.Contains($stem)) { $group = $groups[$k]; break }
        }
    }
    if ($group) {
        $sorted = @($group | Sort-Object { $_.Extension } -Descending)
        $file = $sorted[0].FullName
    }

    $exists = $false; $isStub = $false; $hasBody = $false; $bytes = 0
    $hasHeader = $false; $hasImpl = $false; $implBytes = 0
    if ($group) {
        $exists = $true
        foreach ($g in $group) {
            $bytes += $g.Length
            if ($g.Extension -match '^\.(cpp|c)$') {
                $hasImpl = $true
                $implBytes += $g.Length
                $body = Get-Content -Raw -LiteralPath $g.FullName -ErrorAction SilentlyContinue
                if ($body) {
                    # Strip comments so a marker named in prose does not count as
                    # a stub, which is the mistake that hides a real migration.
                    $codeOnly = [regex]::Replace($body, '(?s)/\*.*?\*/', ' ')
                    $codeOnly = [regex]::Replace($codeOnly, '(?m)//.*$', ' ')
                    $codeOnly = [regex]::Replace($codeOnly, '\s+', ' ')
                    if ($codeOnly.Trim().Length -gt 400) { $hasBody = $true }
                    foreach ($sm in $stubMarkers) { if ($body -like "*$sm*") { $isStub = $true } }
                }
            } else { $hasHeader = $true }
        }
    }

    # CMake membership is checked across the WHOLE group: CMake lists the .cpp,
    # the match may have landed on the .h, and testing only the matched leaf is
    # how a genuinely wired authority was reported as merely implemented.
    $cmakeWired = $false
    if ($group -and $cmakeText) {
        foreach ($g in $group) {
            if ($cmakeText -like "*$($g.Name)*") { $cmakeWired = $true }
        }
    }

    $binHit = $false
    foreach ($k in $binText.Keys) { if ($binText[$k].Contains($name)) { $binHit = $true; break } }

    $hasReceipt = $receiptNames.ContainsKey($name)

    $state = 'DOCUMENTATION_ONLY'
    if ($group) {
        if ($isStub) { $state = 'UNIMPLEMENTED_STUB' }
        elseif ($hasImpl -and $hasBody) { $state = 'SOURCE_IMPLEMENTED' }
        else { $state = 'SOURCE_DECLARED' }
        if ($cmakeWired -and $state -eq 'SOURCE_IMPLEMENTED') { $state = 'CMAKE_WIRED' }
        if ($binHit -and $state -eq 'CMAKE_WIRED') { $state = 'BINARY_REACHABLE' }
        if ($hasReceipt -and $state -eq 'BINARY_REACHABLE') { $state = 'RUNTIME_PROVEN' }
    } elseif ($info.planOnly) { $state = 'PLAN_ONLY' }

    # A retraction outranks every positive signal. An authority the project has
    # withdrawn must never be reported as proven because a stale file still builds.
    if ($info.retracted) { $state = 'RETRACTED' }
    elseif ($info.stale -and $state -in @('DOCUMENTATION_ONLY', 'PLAN_ONLY')) { $state = 'STALE_CLAIM' }

    $results += [pscustomobject]@{
        name = $name
        state = $state
        file = if ($group) { ($group | ForEach-Object { $_.Name }) -join '+' } else { '' }
        bytes = $bytes
        implBytes = $implBytes
        hasHeader = $hasHeader
        hasImpl = $hasImpl
        stub = $isStub
        cmake = $cmakeWired
        binary = if ($binaries.Count) { $binHit } else { 'NOT_MEASURED' }
        receipt = $hasReceipt
        docs = $info.docs.Count
    }
}

# ---------------------------------------------------------------------------
# 5. Report.
# ---------------------------------------------------------------------------
$order = @('RUNTIME_PROVEN','BINARY_REACHABLE','CMAKE_WIRED','SOURCE_IMPLEMENTED',
           'SOURCE_DECLARED','UNIMPLEMENTED_STUB','PLAN_ONLY','DOCUMENTATION_ONLY',
           'STALE_CLAIM','RETRACTED')
$results = $results | Sort-Object @{Expression = { $order.IndexOf($_.state) }}, name

"--- AUTHORITY SURFACE ---"
foreach ($r in $results) {
    "{0,-24} {1,-46} {2}" -f $r.state, $r.name, $r.file
}
""
"--- SUMMARY ---"
"NAME_TOTAL=$($results.Count)"
foreach ($s in $order) {
    $n = ($results | Where-Object { $_.state -eq $s } | Measure-Object).Count
    "STATE_{0}={1}" -f $s, $n
}
$proven = ($results | Where-Object { $_.state -in @('RUNTIME_PROVEN','BINARY_REACHABLE','CMAKE_WIRED') } | Measure-Object).Count
"PROMOTABLE_TO_IMPLEMENTED_BUILT_UNADOPTED_OR_PROVEN=$proven"
"DOCUMENTED_NOT_EVIDENCED=$($results.Count - $proven)"

($results | Select-Object name,state,file,bytes,stub,cmake,binary,receipt,docs |
    ConvertTo-Json -Depth 4) | Set-Content -LiteralPath "$OutDir\census.json" -Encoding utf8

$sb = New-Object System.Text.StringBuilder
[void]$sb.AppendLine("=== RAWRXD_AUTHORITY_SURFACE_CENSUS_001 ===")
[void]$sb.AppendLine("PROMOTION_RULE=source_exists+non_stub+target_compiles+production_reaches+receipt")
[void]$sb.AppendLine("NAME_TOTAL=$($results.Count)")
foreach ($s in $order) {
    $n = ($results | Where-Object { $_.state -eq $s } | Measure-Object).Count
    [void]$sb.AppendLine("STATE_$s=$n")
}
[void]$sb.AppendLine("NOTE=Name presence in a ledger proves a CLAIM. This census reports the")
[void]$sb.AppendLine("     strongest state backed by source, build, binary or receipt evidence.")
[void]$sb.AppendLine("=== RECEIPT_END ===")
$sb.ToString() | Set-Content -LiteralPath "$OutDir\authority_census.txt" -Encoding utf8
Write-Output "OUT_JSON=$OutDir\census.json"
Write-Output "OUT_RECEIPT=$OutDir\authority_census.txt"