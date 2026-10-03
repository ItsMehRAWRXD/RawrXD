<#
RAWRXD_SOURCE_GRAPH_001 -- build-graph census.

Measures the declared source graph: what CMake references, what exists, what does not, and
which references have been commented out. Produces the numbers the completion gate needs,
grouped by area so the missing graph can be materialised in tranches.

Classification, and why each is distinct:
  PRESENT              path exists on disk
  ACTIVE_MISSING       a bare path on a source line, file absent -> DEFECT (CMake's
                       rawrxd_filter_missing_sources silently drops these, so the target
                       builds with less code than its source list implies)
  COMMENTED_MISSING    a path that exists only inside a `#` comment -> DEFECT (the source
                       was referenced and then hidden rather than resolved)
  COMMENTED_PRESENT    a path in a `#` comment whose file does exist -> the reference was
                       retired but the file was left behind

Comment detection is per line: a `#` outside a quoted string starts a comment for the rest of
that line. That is deliberately conservative -- a path appearing after `#` is treated as
commented, because that is how every comment in this file is actually written.
#>

$ErrorActionPreference = 'Continue'
$Repo   = 'F:\~dev'
$Root   = 'F:\~dev\rawrxd'
$Cml    = Join-Path $Root 'CMakeLists.txt'
$Log    = 'F:\~dev\audit_tombstone_001'
$OutCsv = Join-Path $Log 'source_graph_001.csv'
if (-not (Test-Path $Log)) { New-Item -ItemType Directory -Path $Log | Out-Null }

$lines = Get-Content $Cml

# strip a trailing comment from a line, respecting quoted strings
function Strip-Comment([string]$line) {
    $inQ = $false; $out = ''
    foreach ($ch in $line.ToCharArray()) {
        if ($ch -eq '"') { $inQ = -not $inQ; $out += $ch; continue }
        if (-not $inQ -and $ch -eq '#') { break }
        $out += $ch
    }
    return $out
}

$rx = [regex]'([A-Za-z0-9_./\\ -]+\.(?:cpp|cc|cxx|hpp|h|asm|inc|m|mm))'
$rows = New-Object System.Collections.Generic.List[object]
$seenActive  = @{}
$seenComment = @{}

for ($i = 0; $i -lt $lines.Count; $i++) {
    $raw = $lines[$i]
    $code = Strip-Comment $raw
    $isComment = ($code.TrimEnd() -ne $raw.TrimEnd())

    foreach ($m in $rx.Matches($raw)) {
        $p = $m.Groups[1].Value.Trim()
        if (-not $p) { continue }
        # skip obvious non-paths
        if ($p -match '^\s*$') { continue }
        $norm = $p -replace '\\','/'
        $inCode = -not $isComment
        $full = if ([IO.Path]::IsPathRooted($p)) { $p } else { Join-Path $Root $p }
        $exists = Test-Path -LiteralPath $full

        if ($inCode) {
            $key = $norm.ToLower()
            if ($seenActive.ContainsKey($key)) { continue }
            $seenActive[$key] = $true
            $rows.Add([pscustomobject]@{ Line=$i+1; Path=$norm; Kind=($(if($exists){'PRESENT'}else{'ACTIVE_MISSING'})); Area=(($norm -split '/')[1]) })
        } else {
            # only count a commented ref once
            $key = $norm.ToLower()
            if ($seenComment.ContainsKey($key)) { continue }
            $seenComment[$key] = $true
            if (-not $seenActive.ContainsKey($key)) {
                $rows.Add([pscustomobject]@{ Line=$i+1; Path=$norm; Kind=($(if($exists){'COMMENTED_PRESENT'}else{'COMMENTED_MISSING'})); Area=(($norm -split '/')[1]) })
            }
        }
    }
}

$present   = @($rows | Where-Object Kind -eq 'PRESENT')
$actMiss   = @($rows | Where-Object Kind -eq 'ACTIVE_MISSING')
$cmtMiss   = @($rows | Where-Object Kind -eq 'COMMENTED_MISSING')
$cmtPres   = @($rows | Where-Object Kind -eq 'COMMENTED_PRESENT')
$referenced = $present.Count + $actMiss.Count

Write-Output "=== RAWRXD_SOURCE_GRAPH_001 ==="
Write-Output "RAWRXD_GRAPH_SOURCES_REFERENCED=$referenced"
Write-Output "RAWRXD_GRAPH_SOURCES_PRESENT=$($present.Count)"
Write-Output "RAWRXD_GRAPH_SOURCES_ABSENT=$($actMiss.Count + $cmtMiss.Count)"
Write-Output "RAWRXD_GRAPH_ACTIVE_MISSING=$($actMiss.Count)"
Write-Output "RAWRXD_GRAPH_COMMENTED_MISSING=$($cmtMiss.Count)"
Write-Output "RAWRXD_GRAPH_COMMENTED_PRESENT=$($cmtPres.Count)"

Write-Output ''
Write-Output '=== absent, by area (ACTIVE first, then COMMENTED) ==='
Write-Output ('{0,-26} {1,7} {2,9} {3,9}' -f 'AREA','ACTIVE','CMT_MISS','CMT_PRES')
$areas = ($actMiss + $cmtMiss + $cmtPres | ForEach-Object { $_.Area }) | Sort-Object -Unique
$rowsOut = foreach ($a in $areas) {
    [pscustomobject]@{
        Area   = $a
        Active = @($actMiss  | Where-Object Area -eq $a).Count
        CmtMis = @($cmtMiss  | Where-Object Area -eq $a).Count
        CmtPre = @($cmtPres  | Where-Object Area -eq $a).Count
    }
}
$rowsOut | Sort-Object Active -Descending | Select-Object -First 22 | ForEach-Object {
    Write-Output ('{0,-26} {1,7} {2,9} {3,9}' -f $_.Area,$_.Active,$_.CmtMis,$_.CmtPre)
}

$rows | Export-Csv -Path $OutCsv -NoTypeInformation -Encoding UTF8
Write-Output ''
Write-Output "CSV=$OutCsv"