# ============================================================================
# tools/command_authority_census.ps1
# RAWRXD_COMMAND_AUTHORITY_CENSUS_001
#
# Emits one row per handler NAME, not per handler file, with the number and
# locations of every definition of that name. The per-file fiction count was
# measuring the wrong layer: the decisive fact is that a single name
# (handleModelList) is defined six times, in translation units that do not even
# agree on what CommandResult is. Two of those six are unmarked fiction:
# win32ide_handler_impls.cpp returns CommandResult::ok() unconditionally, which
# is worse than FEATURE_FICTION=1 because nothing downstream can tell it from a
# real implementation.
#
# Dispositions (only these four):
#   REAL_AUTHORITY        exactly one definition and it is not fiction
#   UNRESOLVED_COLLISION  2+ definitions of the same name
#   DEAD_FICTION          every definition is fiction
#
# Read-only. Writes one CSV and prints the gate summary.
# ============================================================================
param(
    [string]$Root = "F:\~dev\rawrxd",
    [string]$OutCsv = ""
)

$ErrorActionPreference = "Stop"

$srcRoot = Join-Path $Root "src"
if (-not (Test-Path $srcRoot)) { throw "no src under $Root" }
if ([string]::IsNullOrEmpty($OutCsv)) { $OutCsv = Join-Path $Root "audit\command_authority_census.csv" }
New-Item -ItemType Directory -Force -Path (Split-Path $OutCsv) | Out-Null

# 1. Every source file that can define a handler.
$files = Get-ChildItem -Path $srcRoot -Recurse -Include *.cpp -ErrorAction SilentlyContinue |
         Where-Object { $_.FullName -notmatch '\\build\\' }

# 2. Definition extraction. A definition is a line that looks like
#    "CommandResult <name>(" at the start of a line, optionally preceded by
#    storage specifiers. Definitions are per-name, not per-file, because the
#    collision is the finding.
$defRe = '^\s*(?:static\s+|extern\s+|inline\s+)*CommandResult\s+(\w+)\s*\('
$fictionRe = 'FEATURE_FICTION=1'
$fakeOkRe  = 'CommandResult::ok\s*\(\s*\)'

$defs = @{}

foreach ($f in $files) {
    $lines = [System.IO.File]::ReadAllLines($f.FullName)
    $i = 0
    while ($i -lt $lines.Length) {
        if ($lines[$i] -match $defRe) {
            $name = $Matches[1]
            # Capture the body by brace balance so fiction is judged per
            # function rather than per file.
            $start = $i
            $depth = 0
            $seenOpen = $false
            $body = New-Object System.Collections.Generic.List[string]
            while ($i -lt $lines.Length) {
                $line = $lines[$i]
                $body.Add($line)
                foreach ($ch in $line.ToCharArray()) {
                    if ($ch -eq '{') { $depth++; $seenOpen = $true }
                    elseif ($ch -eq '}') { $depth-- }
                }
                $i++
                if ($seenOpen -and $depth -le 0) { break }
            }
            $bodyText = $body -join "`n"
            $isFiction = $bodyText -match $fictionRe
            $isFakeOk  = (-not $isFiction) -and ($bodyText -match $fakeOkRe)
            $rel = $f.FullName.Substring($Root.Length + 1).Replace('\', '/')
            if (-not $defs.ContainsKey($name)) {
                $defs[$name] = New-Object System.Collections.Generic.List[object]
            }
            $defs[$name].Add([pscustomobject]@{
                Name      = $name
                File      = $rel
                Line      = $start + 1
                IsFiction = $isFiction
                IsFakeOk  = $isFakeOk
            })
            continue
        }
        $i++
    }
}

# 3. Disposition per name.
$rows = New-Object System.Collections.Generic.List[object]
foreach ($name in ($defs.Keys | Sort-Object)) {
    $d = $defs[$name]
    $n = $d.Count
    $fiction = ($d | Where-Object { $_.IsFiction }).Count
    $fakeOk  = ($d | Where-Object { $_.IsFakeOk }).Count
    $real    = $n - $fiction - $fakeOk

    if ($n -ge 2)            { $disp = 'UNRESOLVED_COLLISION' }
    elseif ($fiction -eq $n)  { $disp = 'DEAD_FICTION' }
    elseif ($real -ge 1)      { $disp = 'REAL_AUTHORITY' }
    else                      { $disp = 'UNRESOLVED_COLLISION' }

    $rows.Add([pscustomobject]@{
        COMMAND_ID           = $name
        DEFINITIONS         = $n
        REAL_DEFINITIONS    = $real
        FICTION_DEFINITIONS = $fiction
        FAKE_OK_DEFINITIONS = $fakeOk
        DISPOSITION         = $disp
        LOCATIONS           = (($d | ForEach-Object { "$($_.File):$($_.Line)" }) -join ';')
    })
}

$rows | Export-Csv -Path $OutCsv -NoTypeInformation -Encoding UTF8

# 4. Gate summary. Every number here is counted, not asserted.
$collisions  = ($rows | Where-Object { $_.DISPOSITION -eq 'UNRESOLVED_COLLISION' }).Count
$dead        = ($rows | Where-Object { $_.DISPOSITION -eq 'DEAD_FICTION' }).Count
$real        = ($rows | Where-Object { $_.DISPOSITION -eq 'REAL_AUTHORITY' }).Count
$fakeOkDefs  = ($rows | Measure-Object -Property FAKE_OK_DEFINITIONS -Sum).Sum
$fictionDefs = ($rows | Measure-Object -Property FICTION_DEFINITIONS -Sum).Sum
$totalDefs   = ($rows | Measure-Object -Property DEFINITIONS -Sum).Sum

Write-Output "RAWRXD_COMMAND_AUTHORITY_CENSUS_001"
Write-Output "SOURCE_FILES_SCANNED=$($files.Count)"
Write-Output "UNIQUE_HANDLER_NAMES=$($rows.Count)"
Write-Output "TOTAL_DEFINITIONS=$totalDefs"
Write-Output "DISPOSITION_REAL_AUTHORITY=$real"
Write-Output "DISPOSITION_UNRESOLVED_COLLISION=$collisions"
Write-Output "DISPOSITION_DEAD_FICTION=$dead"
Write-Output "FICTION_DEFINITIONS=$fictionDefs"
Write-Output "FAKE_OK_DEFINITIONS=$fakeOkDefs"
Write-Output "CSV=$OutCsv"
Write-Output ""
Write-Output "GATE_DUPLICATE_COMMAND_AUTHORITY=$([int]($collisions -gt 0))"
Write-Output "GATE_FALSE_PRESENT_FEATURES=$([int]($fakeOkDefs -gt 0))"
$verdict = 'FAIL'
if ($collisions -eq 0 -and $fakeOkDefs -eq 0) { $verdict = 'PASS' }
Write-Output "VERDICT=$verdict"
