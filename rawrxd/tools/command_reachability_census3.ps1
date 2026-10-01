# ============================================================================
# tools/command_reachability_census3.ps1
# RAWRXD_COMMAND_REACHABILITY_CENSUS_003
#
# Reclassification of prior work:
#   CENSUS_001 duplicate-definition gate  = VALID  (673/927 collide)
#   CENSUS_001 reachability gate          = INVALID_DETECTOR_GAP
#   CENSUS_002                            = SUPERSEDED, over-counts
#
# CENSUS_002 attributed binding PER FILE: if a file mentioned CommandPalette
# anywhere, every handler name mentioned anywhere in that file was marked
# palette-bound. A single palette file therefore promoted hundreds of handlers
# to "product reachable". That is why it reported 550 reachable collisions,
# which is an over-count, not a measurement.
#
# This census attributes PER REFERENCE SITE. A handler is product-reachable
# only if a reference to it occurs on a line, or within a small context window,
# that also carries a binding construct -- and the file is not test/demo/audit.
#
# Patterns accepted:
#   &handler            &Class::handler       Class::handler
#   handler(            {"name", &handler}    {"name", &Class::handler}
#   Register...(handler   registerTool(handler   AddCommand(handler
#   Bind*(handler       CommandDescriptor(   CommandSpec(
#   WM_COMMAND / IDM_ / CMD_ numeric ids paired with the name in the same file
#
# Emits: CSV rows + a gate summary that refuses to auto-pass on an implausible
# zero. Edits nothing.
# ============================================================================
param(
    [string]$Root = "F:\~dev\rawrxd",
    [string]$OutCsv = ""
)

$ErrorActionPreference = "Stop"

$srcRoot = Join-Path $Root "src"
$incRoot = Join-Path $Root "include"
$toolRoot = Join-Path $Root "tools"
if (-not (Test-Path $srcRoot)) { throw "no src under $Root" }
if ([string]::IsNullOrEmpty($OutCsv)) { $OutCsv = Join-Path $Root "audit\command_reachability_census3.csv" }
New-Item -ItemType Directory -Force -Path (Split-Path $OutCsv) | Out-Null

# ---------------------------------------------------------------------------
# Root set and path classification. Only PRODUCT promotes to reachable.
# ---------------------------------------------------------------------------
$scanRoots = @($srcRoot)
foreach ($r in @($incRoot, $toolRoot)) { if (Test-Path $r) { $scanRoots += $r } }

function Get-PathClass([string]$rel) {
    if ($rel -match '(^|/)(test|tests)(/|$)|_test\.|Test\.|smoke|harness|gate_verifier') { return 'TEST' }
    if ($rel -match '(^|/)audit(/|$)')                    { return 'AUDIT' }
    if ($rel -match 'demo|Demo')                          { return 'DEMO' }
    if ($rel -match 'generated|autogen')                  { return 'GENERATED' }
    if ($rel -match '(^|/)tools(/|$)')                   { return 'UNKNOWN' }
    return 'PRODUCT'
}

# Binding constructs, evaluated on the reference line and a +/-4 line window.
$bindRe = @(
    '&',                                   # function pointer / member pointer
    '\bRegister\w*\s*\(',                  # Register / RegisterCommand / RegisterTool
    '\bregister\w+\s*\{',                  # ToolDef{ ... }
    '\bAdd(Command|Handler|Tool)\w*\s*\(',
    '\bBind\w*\s*\(',
    '\bCommand(Spec|Descriptor|Handler)\s*\{',
    'WM_COMMAND', 'IDM_', 'CMD_',
    'AppendMenu', 'CreatePopupMenu', 'SetMenuItemInfo',
    'TranslateAccelerator', 'ACCEL',
    'CommandPalette', 'command_palette', 'QuickOpen',
    'RegisterHotkey', 'RegisterHotKey', 'WM_HOTKEY',
    'commandBus', 'CommandBus', 'DispatchCommand',
    '\{',                                   # brace-initialised table entry
    '=>'                                    # lambda body capturing the handler
)

# Reference forms for a bare handler name.
$refRes = @(
    "&\s*(?:[\w:]+::)?\Q{name}\E\b",         # &handler  /  &Class::handler
    "\b[\w:]+::\Q{name}\E\s*\(",             # Class::handler(
    "\b\Q{name}\E\s*\(",                    # handler(
    '["'']\Q{name}\E["'']',               # "handler" or 'handler'
    "\b\Q{name}\E\b\s*,",                   # name,   in a table entry
    "=>[^}]*\b\Q{name}\E\b"                 # lambda body
)

$defRe = '^\s*((?:static|extern|inline|virtual)\s+)*CommandResult\s+(\w+)\s*\('

$names = @{}
$defCount = @{}
$defLocs = @{}

# ---------------------------------------------------------------------------
# Pass 1 -- definitions across the root set.
# ---------------------------------------------------------------------------
foreach ($rootDir in $scanRoots) {
    foreach ($f in (Get-ChildItem -Path $rootDir -Recurse -Include *.cpp,*.h,*.hpp -ErrorAction SilentlyContinue |
                    Where-Object { $_.FullName -notmatch '\\build\\' })) {
        $rel = $f.FullName.Substring($Root.Length + 1).Replace('\', '/')
        $lines = [System.IO.File]::ReadAllLines($f.FullName)
        for ($i = 0; $i -lt $lines.Length; $i++) {
            if ($lines[$i] -notmatch $defRe) { continue }
            $n = $Matches[2]
            if (-not $names.ContainsKey($n)) { $names[$n] = $true; $defCount[$n] = 0; $defLocs[$n] = @() }
            $defCount[$n] = $defCount[$n] + 1
            $defLocs[$n] += "$rel`:$($i + 1)"
        }
    }
}

# ---------------------------------------------------------------------------
# Pass 2 -- per-reference-site reachability.
# ---------------------------------------------------------------------------
$ev = @{}     # name -> list of evidence strings
foreach ($n in $names.Keys) { $ev[$n] = New-Object System.Collections.Generic.List[string] }

# ONE precompiled alternation of every known handler name. Matching this per
# line is O(line) instead of O(line x names x patterns); the previous form was
# 917 names x 6 patterns for every line in the tree and did not terminate in
# any usable time.
$nameAlternation = '(?:' + (($names.Keys | ForEach-Object { [regex]::Escape($_) }) -join '|') + ')'
$nameRx = [regex]::new('\b(' + $nameAlternation + ')\b')

foreach ($rootDir in $scanRoots) {
    foreach ($f in (Get-ChildItem -Path $rootDir -Recurse -Include *.cpp,*.h,*.hpp -ErrorAction SilentlyContinue |
                    Where-Object { $_.FullName -notmatch '\\build\\' })) {
        $rel = $f.FullName.Substring($Root.Length + 1).Replace('\', '/')
        $pc = Get-PathClass $rel
        $lines = [System.IO.File]::ReadAllLines($f.FullName)

        for ($i = 0; $i -lt $lines.Length; $i++) {
            $line = $lines[$i]
            if ($line -notmatch '\w\s*[(&,]|:{2}') { continue }   # cheap prefilter

            $lo = [Math]::Max(0, $i - 4)
            $hi = [Math]::Min($lines.Length - 1, $i + 4)
            $ctx = ($lines[$lo..$hi] -join "`n")

            # Which of our names appear on this line or in its window?
            $seenHere = @{}
            foreach ($m in $nameRx.Matches($line)) { $seenHere[$m.Groups[1].Value] = $true }
            if ($seenHere.Count -eq 0) { continue }

            $isBind = $false
            $form = ''
            foreach ($b in $bindRe) {
                if ($ctx -match $b) { $isBind = $true; $form = $b; break }
            }
            if (-not $isBind) { continue }

            foreach ($n in $seenHere.Keys) {
                $ev[$n].Add("$pc|$rel`:$($i + 1)|$form")
            }
        }
    }
}

# ---------------------------------------------------------------------------
# Pass 3 -- adjudication.
# ---------------------------------------------------------------------------
$rows = New-Object System.Collections.Generic.List[object]
foreach ($n in ($names.Keys | Sort-Object)) {
    $all = $ev[$n]
    $prod  = @($all | Where-Object { $_ -like 'PRODUCT|*' })
    $test  = @($all | Where-Object { $_ -like 'TEST|*' })
    $other = @($all | Where-Object { $_ -notlike 'PRODUCT|*' -and $_ -notlike 'TEST|*' })
    $defs  = $defCount[$n]

    if ($prod.Count -ge 1 -and $defs -ge 2) { $d = 'REACHABLE_COLLISION' }
    elseif ($prod.Count -ge 1)               { $d = 'REAL_REACHABLE_SINGLE' }
    elseif ($test.Count -ge 1 -and $defs -ge 2) { $d = 'TEST_ONLY_DUPLICATE' }
    elseif ($defs -ge 2)                     { $d = 'UNREACHABLE_DUPLICATE_CANDIDATE' }
    else                                     { $d = 'UNREACHABLE_SINGLE' }

    $rows.Add([pscustomobject]@{
        NAME                 = $n
        DEFINITIONS         = $defs
        DIRECT_CALL_REFS    = @($prod | Where-Object { $_ -match '\|.*\(|\|.*::' }).Count
        FUNCTION_PTR_REFS   = @($prod | Where-Object { $_ -match '\|&' }).Count
        REGISTRY_TABLE_REFS = @($prod | Where-Object { $_ -match 'Register|register|Command|\{|\[' }).Count
        PRODUCT_REFS        = $prod.Count
        TEST_REFS           = $test.Count
        UNKNOWN_REFS        = $other.Count
        PRODUCT_REACHABLE   = [int]($prod.Count -gt 0)
        DISPOSITION         = $d
        LOCATIONS           = (($defLocs[$n] | Select-Object -First 6) -join ';')
        EVIDENCE_LINES      = (($prod | Select-Object -First 3) -join ' | ')
    })
}

$rows | Export-Csv -Path $OutCsv -NoTypeInformation -Encoding UTF8

$coll   = ($rows | Where-Object { $_.DISPOSITION -eq 'REACHABLE_COLLISION' }).Count
$single = ($rows | Where-Object { $_.DISPOSITION -eq 'REAL_REACHABLE_SINGLE' }).Count
$dupCan = ($rows | Where-Object { $_.DISPOSITION -eq 'UNREACHABLE_DUPLICATE_CANDIDATE' }).Count
$testD  = ($rows | Where-Object { $_.DISPOSITION -eq 'TEST_ONLY_DUPLICATE' }).Count
$unk    = ($rows | Where-Object { $_.DISPOSITION -eq 'UNREACHABLE_SINGLE' }).Count
$prodRefs = ($rows | Measure-Object -Property PRODUCT_REFS -Sum).Sum

Write-Output "RAWRXD_COMMAND_REACHABILITY_CENSUS_003"
Write-Output "SEARCH_ROOTS=src,include,tools"
Write-Output "NAMES_TOTAL=$($rows.Count)"
Write-Output "PRODUCT_REFS_TOTAL=$prodRefs"
Write-Output ""
Write-Output "DISPOSITION_REAL_REACHABLE_SINGLE=$single"
Write-Output "DISPOSITION_REACHABLE_COLLISION=$coll"
Write-Output "DISPOSITION_UNREACHABLE_DUPLICATE_CANDIDATE=$dupCan"
Write-Output "DISPOSITION_TEST_ONLY_DUPLICATE=$testD"
Write-Output "DISPOSITION_UNREACHABLE_SINGLE=$unk"
Write-Output ""
Write-Output "CSV=$OutCsv"
Write-Output ""

# Refuse to auto-pass on an implausible zero.
if ($prodRefs -eq 0) {
    Write-Output "VERDICT=FAIL_IMPLAUSIBLE_ZERO_REACHABILITY"
} elseif ($coll -eq 0) {
    Write-Output "VERDICT=PASS"
} else {
    Write-Output "VERDICT=FAIL"
}
Write-Output "GATE_REACHABLE_COLLISION=$coll"
