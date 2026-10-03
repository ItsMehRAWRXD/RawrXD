# =============================================================================
# RAWRXD_BUILD_GRAPH_CENSUS_001.ps1
#
# INSTRUMENTATION ONLY. This script measures and reports. It refuses nothing,
# gates nothing, and modifies nothing.
#
# It answers one question precisely: of every source path the build graph
# declares, how many actually exist?
#
# The distinction it is careful about:
#   rawrxd_filter_missing_sources() removes absent paths at configure time and
#   prints [rawrxd_stub_gate] warnings. That is a filter WITH a counter.
#   A '#'-commented source reference is a manual exclusion that no tool reports
#   and that no build graph can see. That is the larger and unmeasured surface,
#   so it is counted separately here rather than being folded into "absent".
#
# Usage:
#   powershell -File tools/RAWRXD_BUILD_GRAPH_CENSUS_001.ps1 `
#              -RepoRoot F:\~dev\rawrxd `
#              -TsVPath audit/RAWRXD_BUILD_GRAPH_CENSUS_001/manifest.tsv
# =============================================================================
[CmdletBinding()]
param(
    [string] $RepoRoot   = (Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)),
    [string] $TsVPath    = "",
    [string[]] $CmakeFiles = @()
)

if ($CmakeFiles.Count -eq 0) {
    $CmakeFiles = @(
        (Join-Path $RepoRoot 'CMakeLists.txt'),
        (Join-Path (Split-Path -Parent $RepoRoot) 'CMakeLists.txt')
    )
}
$CmakeFiles = $CmakeFiles | Where-Object { Test-Path -LiteralPath $_ }

if (-not $TsVPath) {
    $TsVPath = Join-Path $RepoRoot 'audit\RAWRXD_BUILD_GRAPH_CENSUS_001\manifest.tsv'
}

# Source-bearing extensions only. .ps1/.json/.txt/.cmake are tool or metadata
# references (custom-target scripts, json payloads) and are NOT source paths;
# counting them would inflate "absent" with things that were never source.
$SourceExt = @('.cpp','.cc','.cxx','.c','.hpp','.hxx','.h','.inl','.ipp','.asm','.s','.rc')

# A source path as written in CMake: relative, forward slashes, at least one
# directory component, no spaces (CMake source lists are unquoted here).
$PathRegex = [regex]'(?<![\w./\\-])([\w./\\-]*[\\/])?[\w.-]+\.(cpp|cc|cxx|c|hpp|hxx|h|inl|ipp|asm|s|rc)\b'

# Area key. Grouping on the first segment alone collapses the entire src/ tree
# into one bucket ("src:325"), which hides the surface that actually matters --
# src/win32app is the priority inventory. So for paths under src/, the area is
# the SECOND segment. External/SDK trees (Windows Kits, Program Files) are
# bucketed as EXTERNAL rather than being mixed into project areas.
function Get-Area([string] $p) {
    if ($p -match '^src/([^/]+)/') { return $Matches[1] }
    if ($p -match '^src/')            { return 'src' }
    if ($p -match '^(rawrxd/)?(src)/([^/]+)/') { return $Matches[3] }
    if ($p -match '^(rawrxd/)?(src)/')        { return 'src' }
    if ($p -match '(?i)Kits|Program Files|VulkanSDK|node_modules') { return 'EXTERNAL' }
    if ($p -match '^/') { return 'ABSOLUTE' }
    return ($p -split '/')[0]
}

$records = New-Object System.Collections.Generic.List[object]

foreach ($cm in $CmakeFiles) {
    $lines = Get-Content -LiteralPath $cm
    $cmRel = $cm.Substring($RepoRoot.Length).TrimStart('\','/')
    if ($cmRel.StartsWith('..')) { $cmRel = Split-Path -Leaf $cm }

    $inBlock = $false
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $line = $lines[$i]
        $lineNo = $i + 1

        # Track /* ... */ regions so a path inside a block comment is not
        # reported as an active declaration.
        $opens  = ([regex]::Matches($line, '/\*')).Count
        $closes = ([regex]::Matches($line, '\*/')).Count

        $activeLine = $line
        $wasInBlock = $inBlock
        if ($inBlock) {
            $endIdx = $line.IndexOf('*/')
            if ($endIdx -ge 0) { $activeLine = $line.Substring($endIdx + 2); $inBlock = $false }
            else { $activeLine = '' }
        }
        if (-not $wasInBlock -and $opens -gt 0) {
            $startIdx = $activeLine.IndexOf('/*')
            $endIdx2 = $activeLine.IndexOf('*/', $startIdx + 2)
            if ($endIdx2 -ge 0) { $activeLine = $activeLine.Substring(0,$startIdx) + ' ' + $activeLine.Substring($endIdx2 + 2) }
            else { $activeLine = $activeLine.Substring(0,$startIdx); $inBlock = $true }
        }

        $trimmed = $activeLine.Trim()
        $isComment = $trimmed.StartsWith('#')

        foreach ($m in $PathRegex.Matches($activeLine)) {
            # Groups[0] already spans the optional directory prefix AND the
            # filename, so it IS the path. Concatenating Groups[1] with
            # Groups[0] would duplicate the directory.
            $p = $m.Value
            # Normalise: forward slashes, strip ./ prefix
            $p = ($p -replace '\\','/') -replace '^\./',''
            if ($p -match '^\.\./') { continue }          # escapes the repo root
            if (-not ($SourceExt -contains [System.IO.Path]::GetExtension($p).ToLower())) { continue }
            if ($p -notmatch '/') { continue }             # bare filename: not a source path

            # Existence is resolved against the repo root ONLY, except for
            # paths explicitly prefixed "rawrxd/" which are written relative to
            # the parent's own root (that is how the root CMakeLists.txt spells
            # them). A blanket parent-directory fallback is wrong: it resolves
            # "src/..." against a *different*, unrelated top-level src/ tree
            # and reports hundreds of absent files as present.
            $rel  = $p -replace '/','\'
            $base = $RepoRoot
            if ($p -match '^rawrxd/') { $base = Split-Path -Parent $RepoRoot; $rel = $p.Substring(7) -replace '/','\' }

            $records.Add([pscustomobject]@{
                Path    = $p
                Area    = (Get-Area $p)
                Exists  = (Test-Path -LiteralPath (Join-Path $base $rel))
                Active  = (-not $isComment)
                Origin  = "$cmRel`:$lineNo"
            })
        }
    }
}

# Deduplicate on Path, keeping Active=1 if ANY reference to it is active.
$byPath = @{}
foreach ($r in $records) {
    $k = $r.Path
    if (-not $byPath.ContainsKey($k)) { $byPath[$k] = $r }
    elseif ($r.Active -and -not $byPath[$k].Active) { $byPath[$k].Active = $true; $byPath[$k].Origin = $r.Origin }
}

$all      = @($byPath.Values)
$present  = @($all | Where-Object { $_.Exists })
$absent   = @($all | Where-Object { -not $_.Exists })
$cActive  = @($all | Where-Object { -not $_.Active })
$cAbsent  = @($cActive | Where-Object { -not $_.Exists })
$cPresent = @($cActive | Where-Object { $_.Exists })

$pct = if ($all.Count) { [math]::Round(100.0 * $present.Count / $all.Count, 1) } else { 0 }
$apct = if ($all.Count) { [math]::Round(100.0 * $absent.Count / $all.Count, 1) } else { 0 }

$absentCpp = @($absent | Where-Object { [System.IO.Path]::GetExtension($_.Path) -eq '.cpp' })
$absentNonCpp = $absent.Count - $absentCpp.Count

Write-Output "RAWRXD_BUILD_GRAPH_CENSUS_001"
Write-Output "REPO_ROOT=$RepoRoot"
Write-Output "CMAKE_FILES_SCANNED=$($CmakeFiles.Count)"
Write-Output ""
Write-Output "RAWRXD_GRAPH_SOURCES_REFERENCED=$($all.Count)"
Write-Output "RAWRXD_GRAPH_SOURCES_PRESENT=$($present.Count)"
Write-Output "RAWRXD_GRAPH_SOURCES_ABSENT=$($absent.Count)"
Write-Output "RAWRXD_GRAPH_PRESENT_PCT=$pct"
Write-Output "RAWRXD_GRAPH_ABSENT_PCT=$apct"
Write-Output "RAWRXD_GRAPH_ABSENT_CPP=$($absentCpp.Count)"
Write-Output "RAWRXD_GRAPH_ABSENT_NONCPP=$absentNonCpp"
Write-Output ""
Write-Output "RAWRXD_GRAPH_ABSENT_ACTIVE_REFS=$($absent.Count - $cAbsent.Count)"
Write-Output "RAWRXD_GRAPH_ABSENT_COMMENTED_REFS=$($cAbsent.Count)"
Write-Output "RAWRXD_GRAPH_COMMENTED_PRESENT=$($cPresent.Count)"
Write-Output "RAWRXD_GRAPH_COMMENTED_ABSENT=$($cAbsent.Count)"
Write-Output ""
Write-Output "RAWRXD_GRAPH_ABSENT_BY_AREA="
foreach ($g in ($absent | Group-Object Area | Sort-Object Count -Descending)) {
    Write-Output ("  {0}:{1}" -f $g.Name, $g.Count)
}

# Machine-readable manifest: one record per declared path.
$dir = Split-Path -Parent $TsVPath
if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
$hdr = "PATH`tAREA`tEXISTS`tACTIVE`tTARGET_REF`tDISPOSITION"
$lines = New-Object System.Collections.Generic.List[string]
$lines.Add($hdr)
foreach ($r in ($all | Sort-Object Path)) {
    $disp = if (-not $r.Active -and -not $r.Exists) { 'COMMENTED_ABSENT' }
            elseif (-not $r.Active)              { 'COMMENTED_PRESENT' }
            elseif (-not $r.Exists)              { 'ACTIVE_ABSENT' }
            else                                 { 'ACTIVE_PRESENT' }
    $lines.Add(("{0}`t{1}`t{2}`t{3}`t{4}`t{5}" -f $r.Path, $r.Area, [int]$r.Exists, [int]$r.Active, $r.Origin, $disp))
}
Set-Content -LiteralPath $TsVPath -Value $lines -Encoding UTF8
Write-Output ""
Write-Output "MANIFEST=$TsVPath"
Write-Output "MANIFEST_RECORDS=$($all.Count)"