<#
.SYNOPSIS
    RAWRXD_COMMENTED_REF_RESTORE_001
    Re-enable commented-out source declarations in CMakeLists.txt.

.DESCRIPTION
    After materialising the absent graph, 145 commented-out declarations point at
    files that DO exist on disk. That is the most misleading state a build graph
    can be in: the source is present, a reader assumes it is compiled, and every
    tool that parses the build graph sees nothing wrong. These files have been
    silently excluded from every build.

    This uncomments them.

    PRECISION IS THE WHOLE RISK. Only a line whose entire content after the '#'
    is whitespace plus ONE source path is touched:

        #   src/win32app/Foo.cpp        <- restored
        # see also src/foo.cpp           <- NOT touched (prose)
        # 1234 references were dropped  <- NOT touched (prose)

    A looser rule that uncommented any path mentioned on a comment line would
    corrupt explanatory comments throughout a 1.25 MB file, and the earlier
    325-count that inflated this number is exactly the consequence of that loose
    definition being used for analysis.

    A path is only restored when it EXISTS on disk. Restoring a declaration for a
    file that is still absent would move the problem, not fix it.
#>
[CmdletBinding()]
param(
    [string]$RepoRoot = 'F:\~dev\rawrxd',
    [switch]$DryRun
)
$ErrorActionPreference = 'Stop'
$cmPath = Join-Path $RepoRoot 'CMakeLists.txt'
if (-not (Test-Path $cmPath)) { throw "CMakeLists.txt not found: $cmPath" }

$lines = [System.IO.File]::ReadAllLines($cmPath)
$out = New-Object System.Collections.Generic.List[string]
$restored = 0; $skippedAbsent = 0; $skippedProse = 0
$restoredPaths = New-Object System.Collections.Generic.List[string]

# A pure declaration line: '#', whitespace, one source path, optional whitespace.
$decl = '^\s*#\s*((?:src|tools|certs|tests|include|examples|3rdparty)/[A-Za-z0-9_./-]+\.(?:cpp|hpp|h|cc|cxx|asm|rc))\s*$'

foreach ($ln in $lines) {
    if ($ln -match $decl) {
        $p = $Matches[1]
        $fs = Join-Path $RepoRoot ($p.Replace('/','\'))
        if (Test-Path $fs) {
            $restoredPaths.Add($p)
            if (-not $DryRun) {
                # Uncomment, preserving the original indentation of the code
                # column so the list stays visually aligned.
                $stripped = $ln -replace '^\s*#\s*', ''
                $out.Add(($stripped -replace '[ \t]+$',''))
                $restored++
                continue
            }
        } else {
            $skippedAbsent++
        }
    } elseif ($ln -match '^\s*#' -and $ln -match '(?:src|tools|certs|tests|include|examples|3rdparty)/[A-Za-z0-9_./-]+\.(?:cpp|hpp|h|cc|cxx|asm|rc)') {
        $skippedProse++
    }
    $out.Add($ln)
}

Write-Host ''
Write-Host '=== RAWRXD_COMMENTED_REF_RESTORE_001 ==='
Write-Host ("MODE            = " + $(if ($DryRun) { 'DRY-RUN (no writes)' } else { 'APPLY' }))
Write-Host ("DECLARATIONS_RESTORED  = " + $restored)
Write-Host ("SKIPPED_PATH_ABSENT    = " + $skippedAbsent + "  (file does not exist)")
Write-Host ("SKIPPED_PROSE_LINES    = " + $skippedProse + "  (comment mentioning a path, not a declaration)")
Write-Host ''
Write-Host 'RESTORED BY AREA:'
$restoredPaths | ForEach-Object { $p = $_ -split '/'; "$($p[0])/$($p[1])" } |
    Group-Object | Sort-Object Count -Descending | Select-Object -First 12 |
    ForEach-Object { "{0,5}  {1}" -f $_.Count, $_.Name }

if (-not $DryRun) {
    [System.IO.File]::WriteAllLines($cmPath, $out)
    Write-Host ''
    Write-Host "CMakeLists.txt rewritten: $($out.Count) lines"
}
