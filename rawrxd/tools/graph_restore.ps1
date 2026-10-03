<#
.SYNOPSIS
    RAWRXD_GRAPH_RESTORE_001
    Materialise every declared-but-absent source path so the build graph is
    structurally complete.

.DESCRIPTION
    355 of 1393 declared source paths do not exist; 325 more are commented out
    of the graph. Every build has therefore been silently smaller than the
    architecture it claims to implement, and no counter reported it.

    This creates the missing paths. What it deliberately does NOT do:

      * export a symbol
      * define a function, class, or behaviour
      * return a plausible value
      * satisfy a linker reference

    Each file is a GRAPH-RESTORATION UNIT: a real path at the declared location
    carrying a marker that identifies it as such and names the census. It
    compiles to an empty translation unit. Anything that needs it for a symbol
    will fail at link, and that failure IS the implementation queue.

    The marker is greppable on purpose. Every downstream tool, census and
    receipt can therefore distinguish a restored path from an implemented one,
    so structural completeness can never be mistaken for functional
    completeness. `RAWRXD_GRAPH_RESTORED_001` is the token to count.

    IDEMPOTENT. Existing files are never touched.

.PARAMETER Area
    Restrict to one area, e.g. win32app, sovereign, deep2. Default: all.
#>
[CmdletBinding()]
param(
    [string]$RepoRoot = 'F:\~dev\rawrxd',
    [string]$Area = ''
)
$ErrorActionPreference = 'Stop'
$cmPath = Join-Path $RepoRoot 'CMakeLists.txt'
if (-not (Test-Path $cmPath)) { throw "CMakeLists.txt not found: $cmPath" }

$text = [System.IO.File]::ReadAllText($cmPath)

# Every source path the graph declares, active or commented. Both forms are
# captured because the goal is that the declared architecture EXISTS, not that a
# particular commenting style is preserved.
$pat = '(?<![A-Za-z0-9_/\\])((?:src|tools|certs|tests|include|examples|3rdparty)/[A-Za-z0-9_./\\-]+\.(?:cpp|c|hpp|h|cc|cxx|asm|rc))'
$refs = [regex]::Matches($text, $pat) |
         ForEach-Object { $_.Groups[1].Value.Replace('\','/') } |
         Sort-Object -Unique

$absent = New-Object System.Collections.Generic.List[string]
foreach ($r in $refs) {
    $fs = Join-Path $RepoRoot ($r.Replace('/','\'))
    if (-not (Test-Path $fs)) { $absent.Add($r) }
}

if ($Area) { $absent = $absent | Where-Object { $_ -match "/$([regex]::Escape($Area))/" } }

$MARK = @(
  '// RAWRXD_GRAPH_RESTORED_001'
  '//'
  '// GRAPH-RESTORATION UNIT. This path is materialised to make the declared'
  '// build graph structurally complete. It contains NO implementation and'
  '// exports NO symbol. It is not a functional PASS.'
  '//'
  '// If something links against a symbol from this translation unit, that'
  '// link error is the implementation queue for this file.'
  '//'
  '// Declared by: rawrxd/CMakeLists.txt'
  '// Census:       audit/RAWRXD_BUILD_GRAPH_CENSUS_001.tsv'
) -join "`n"

$created = 0; $skipped = 0; $failed = @()
foreach ($r in $absent) {
    $fs = Join-Path $RepoRoot ($r.Replace('/','\'))
    $dir = Split-Path $fs -Parent
    try {
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
        if (Test-Path $fs) { $skipped++; continue }
        [System.IO.File]::WriteAllText($fs, $MARK + "`n")
        $created++
    } catch { $failed += "$r :: $($_.Exception.Message)" }
}

Write-Host ''
Write-Host '=== RAWRXD_GRAPH_RESTORE_001 ==='
Write-Host ("AREA_FILTER        = " + $(if ($Area) { $Area } else { '<all>' }))
Write-Host ("DECLARED_UNIQUE    = " + $refs.Count)
Write-Host ("ABSENT_TO_RESTORE  = " + $absent.Count)
Write-Host ("FILES_CREATED      = " + $created)
Write-Host ("FILES_SKIPPED      = " + $skipped + "  (already present)")
Write-Host ("FILES_FAILED       = " + $failed.Count)
Write-Host ''
Write-Host 'CREATED BY AREA:'
$absent | ForEach-Object { $p = $_ -split '/'; if ($p.Count -ge 2) { "$($p[0])/$($p[1])" } else { $p[0] } } |
    Group-Object | Sort-Object Count -Descending | Select-Object -First 16 |
    ForEach-Object { "{0,5}  {1}" -f $_.Count, $_.Name }
if ($failed.Count) {
    Write-Host ''
    Write-Host 'FAILURES:'
    $failed | Select-Object -First 10 | ForEach-Object { "  $_" }
}
Write-Host ''
Write-Host 'MARKER_TOKEN = RAWRXD_GRAPH_RESTORED_001'
Write-Host 'Count with:  Select-String -Path <tree> -Pattern RAWRXD_GRAPH_RESTORED_001 -List'
