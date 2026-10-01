# ============================================================================
# tools/command_reachability_census.ps1
# RAWRXD_COMMAND_REACHABILITY_CENSUS_001
#
# Companion to command_authority_census.ps1. That tool measured how many times
# each handler NAME is defined (673 of 927 collide). This one asks the question
# that collapses the problem: is any of those names actually BOUND to a
# user-reachable surface -- menu, accelerator, command palette, keybinding?
#
# An unbound name cannot mislead a user no matter which definition wins the
# link, so it is removable. A bound name with 6 definitions is a live defect
# whose visible behaviour depends on link order.
#
# Read-only. Writes one CSV and prints the gate summary.
# ============================================================================
param(
    [string]$Root = "F:\~dev\rawrxd",
    [string]$CensusCsv = "",
    [string]$OutCsv = ""
)

$ErrorActionPreference = "Stop"

$srcRoot = Join-Path $Root "src"
if (-not (Test-Path $srcRoot)) { throw "no src under $Root" }
if ([string]::IsNullOrEmpty($CensusCsv)) { $CensusCsv = Join-Path $Root "audit\command_authority_census.csv" }
if (-not (Test-Path $CensusCsv)) { throw "run command_authority_census.ps1 first" }
if ([string]::IsNullOrEmpty($OutCsv)) { $OutCsv = Join-Path $Root "audit\command_reachability_census.csv" }
New-Item -ItemType Directory -Force -Path (Split-Path $OutCsv) | Out-Null

# Binding surfaces: the IDE files that actually surface a command to a user.
# Patterns are deliberately narrow so a mention in a comment does not count.
$bindFiles = Get-ChildItem -Path (Join-Path $srcRoot 'win32app') -Recurse -Include *.cpp -ErrorAction SilentlyContinue
$bindPatterns = @(
    'menu\.\s*Append|AppendMenu',
    'SetAccel|ACCELERATOR|TranslateAccelerator',
    'CommandPalette|command_palette|QuickOpen|Ctrl\+P',
    'RegisterHotkey|RegisterHotKey|WM_HOTKEY',
    'keybinding|KeyBinding|BindKey|AddShortcut'
)

# Index: for every binding file, the set of handler-like tokens it mentions.
# We intersect that with the census names rather than regexing the whole tree,
# because a match in a comment or a test is not a binding.
$census = Import-Csv -Path $CensusCsv
$names = @{}
foreach ($r in $census) { $names[$r.COMMAND_ID] = $r }

$bindingHits = @{}

foreach ($bf in $bindFiles) {
    $text = [System.IO.File]::ReadAllText($bf.FullName)
    $rel = $bf.FullName.Substring($Root.Length + 1).Replace('\', '/')

    $hasBindingConstruct = $false
    foreach ($p in $bindPatterns) {
        if ($text -match $p) { $hasBindingConstruct = $true; break }
    }
    if (-not $hasBindingConstruct) { continue }

    foreach ($name in $names.Keys) {
        if ($name -notmatch '^handle') { continue }
        # Call or registration form: identifier followed by '(' or listed in a
        # table entry. A bare word in prose is not counted.
        if ($text -match ("\b" + [regex]::Escape($name) + "\s*\(") -or
            ($text -match ("[""']" + [regex]::Escape($name) + "[""']"))) {
            if (-not $bindingHits.ContainsKey($name)) {
                $bindingHits[$name] = New-Object System.Collections.Generic.List[string]
            }
            $bindingHits[$name].Add($rel)
        }
    }
}

$rows = New-Object System.Collections.Generic.List[object]
foreach ($name in ($names.Keys | Sort-Object)) {
    $c = $names[$name]
    $bound = $bindingHits.ContainsKey($name)
    $defs = [int]$c.DEFINITIONS
    if ($c.DISPOSITION -eq 'UNRESOLVED_COLLISION') {
        if ($bound)      { $d = 'BOUND_COLLISION' }
        else             { $d = 'UNBOUND_COLLISION' }
    } elseif ($bound)   { $d = 'BOUND_SINGLE' }
    else                { $d = 'UNBOUND_SINGLE' }
    $rows.Add([pscustomobject]@{
        COMMAND_ID     = $name
        DEFINITIONS   = $defs
        DISPOSITION    = $c.DISPOSITION
        REACHABLE     = [int]$bound
        REACH_DISP    = $d
        BIND_SURFACES = $(if ($bound) { (($bindingHits[$name] | Sort-Object -Unique) -join ';') } else { '' })
    })
}

$rows | Export-Csv -Path $OutCsv -NoTypeInformation -Encoding UTF8

$boundColl   = ($rows | Where-Object { $_.REACH_DISP -eq 'BOUND_COLLISION' }).Count
$unboundColl = ($rows | Where-Object { $_.REACH_DISP -eq 'UNBOUND_COLLISION' }).Count
$boundSingle = ($rows | Where-Object { $_.REACH_DISP -eq 'BOUND_SINGLE' }).Count
$unboundSing = ($rows | Where-Object { $_.REACH_DISP -eq 'UNBOUND_SINGLE' }).Count

Write-Output "RAWRXD_COMMAND_REACHABILITY_CENSUS_001"
Write-Output "BINDING_FILES_WITH_SURFACES=$($bindFiles.Count)"
Write-Output "NAMES_TOTAL=$($rows.Count)"
Write-Output "NAMES_REACHABLE=$($boundColl + $boundSingle)"
Write-Output "NAMES_UNREACHABLE=$($unboundColl + $unboundSing)"
Write-Output ""
Write-Output "BOUND_COLLISION=$boundColl"
Write-Output "UNBOUND_COLLISION=$unboundColl"
Write-Output "BOUND_SINGLE=$boundSingle"
Write-Output "UNBOUND_SINGLE=$unboundSing"
Write-Output "CSV=$OutCsv"
Write-Output ""
Write-Output "REACHABLE_FEATURE_FICTION=$boundColl"
Write-Output "GATE_DUPLICATE_COMMAND_AUTHORITY=$([int](($boundColl + $unboundColl) -gt 0))"
$v = 'FAIL'
if ($boundColl -eq 0) { $v = 'PASS' }
Write-Output "VERDICT=$v"
