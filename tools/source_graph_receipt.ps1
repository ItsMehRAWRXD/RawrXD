# RAWRXD_BUILD_GRAPH_DIAGNOSTIC_RECEIPT (PowerShell)

# Computes the declared source-graph metrics from the filesystem, at the moment it is
# asked, so the receipt cannot contradict itself.
#
# Why anchored detection: a first attempt used a space-permitting regex and counted prose
# in comments as declarations, inventing areas such as "Windows Kits" and "RawrXD_Gold.m".
# A candidate must now contain a forward slash AND match a known source root, or be a bare
# token with no spaces. That excludes prose and absolute SDK paths.
#
# Two prior readings of this graph disagree (per-list "DROPPED 225 nonexistent" against a
# global "RAWRXD_DROPPED_SOURCE_TOTAL=0 / VERDICT=PASS" in the same configuration), which is
# the reason this computes rather than asserts.

param([string]$Root = 'F:\~dev\rawrxd')

$ErrorActionPreference = 'Stop'
$Cml = Join-Path $Root 'CMakeLists.txt'
if (-not (Test-Path $Cml)) { Write-Output 'RAWRXD_GRAPH_CML_MISSING=1'; exit 1 }

$exts    = @('.cpp','.cc','.cxx','.hpp','.h','.asm','.inc','.m','.mm')
$srcRoot = '(src|Ship|tests|B014|certs|3rdparty|rguf_source|cmake|include|assets|masm|asm|validation|production)'

function Split-Code([string]$line) {
    # returns @{ Code=...; Comment=...; IsComment=$bool }, honouring double-quoted strings
    $inQ = $false; $code = ''; $i = 0
    while ($i -lt $line.Length) {
        $ch = $line[$i]
        if ($ch -eq '"') { $inQ = -not $inQ; $code += $ch }
        elseif ($ch -eq '#' -and -not $inQ) {
            return @{ Code = $code; Comment = $line.Substring($i); IsComment = $true }
        }
        else { $code += $ch }
        $i++
    }
    return @{ Code = $code; Comment = ''; IsComment = $false }
}

function Test-PathCandidate([string]$p) {
    if (-not $p) { return $false }
    # Absolute host paths (SDK/toolchain references quoted in this file) are not source
    # declarations. They produced a bogus "Program Files (x86)" area in a prior run.
    if ($p -match '^[A-Za-z]:' -or $p -match '^[\\/]') { return $false }
    if ($p -match 'Program Files|Windows Kits|node_modules|\.git') { return $false }
    $lp = $p.ToLowerInvariant()
    $okExt = $false
    foreach ($e in $exts) { if ($lp.EndsWith($e)) { $okExt = $true; break } }
    if (-not $okExt) { return $false }
    if ($p -match "(^|/)$srcRoot/") { return $true }
    if ($p.Contains('/') -and -not $p.Contains(' ')) { return $true }
    return $false
}

# a quoted token, which is how CMake paths are written here
$qre = [regex]'^\s*"([^"]+)"'
# Source paths in this CMakeLists are predominantly BARE and unquoted
# (e.g. "    src/deep2/Deep2Engine.cpp"), so a quoted-only scan misses most of the graph --
# a prior run reported 106 referenced against a true count in the high hundreds. Both forms
# are scanned: quoted tokens, and bare space-free tokens.
$tre = [regex]'[A-Za-z0-9_./\\@$(){}-]+\.(?:cpp|cc|cxx|hpp|h|asm|inc|m|mm)'
$present = @{}; $actMiss = @{}; $cmtMiss = @{}; $cmtPres = @{}

$lines = Get-Content $Cml
for ($i = 0; $i -lt $lines.Count; $i++) {
    $parts = Split-Code $lines[$i]
    $segs = @(@{ Text = $parts.Code;    Cmt = $false }, @{ Text = $parts.Comment; Cmt = $true })
    foreach ($seg in $segs) {
        if (-not $seg.Text) { continue }
        $cands = New-Object System.Collections.Generic.List[string]
        foreach ($m in [regex]::Matches($seg.Text, '"([^"]+)"')) { $cands.Add($m.Groups[1].Value) }
        foreach ($m in $tre.Matches($seg.Text))                    { $cands.Add($m.Value) }
        foreach ($raw in $cands) {
            $p = $raw.Trim() -replace '\\','/'
            if (-not (Test-PathCandidate $p)) { continue }
            $full = Join-Path $Root $p
            $exists = Test-Path -LiteralPath $full
            if ($seg.Cmt) {
                if ($exists) { if (-not $present.ContainsKey($p) -and -not $cmtMiss.ContainsKey($p)) { $cmtPres[$p] = $i+1 } }
                else { if (-not $cmtMiss.ContainsKey($p) -and -not $actMiss.ContainsKey($p)) { $cmtMiss[$p] = $i+1 } }
            } else {
                if ($exists) { $present[$p] = $i+1 }
                elseif (-not $actMiss.ContainsKey($p)) { $actMiss[$p] = $i+1 }
                else { $present[$p] = $i+1 }
            }
        }
    }
}

$referenced = $present.Count + $actMiss.Count
$absent     = $actMiss.Count + $cmtMiss.Count
$absentCpp  = @($actMiss.Keys + $cmtMiss.Keys | Where-Object { $_.ToLowerInvariant().EndsWith('.cpp') }).Count

function Get-Area([string]$p) {
    # Bare filenames have no directory to split on; grouping them by their own name
    # produced areas like "json.hpp" and "RawrXD_Gold.m". Bucket those explicitly.
    if (-not $p.Contains('/')) { return '<bare>' }
    $s = $p.Split('/')
    if ($s.Count -gt 1) { return $s[1] }
    return $s[0]
}

$byArea = @{}
foreach ($k in $actMiss.Keys) { $a = Get-Area $k; if (-not $byArea.ContainsKey($a)) { $byArea[$a] = @(0,0,0) }; $byArea[$a][0]++ }
foreach ($k in $cmtMiss.Keys) { $a = Get-Area $k; if (-not $byArea.ContainsKey($a)) { $byArea[$a] = @(0,0,0) }; $byArea[$a][1]++ }
foreach ($k in $cmtPres.Keys) { $a = Get-Area $k; if (-not $byArea.ContainsKey($a)) { $byArea[$a] = @(0,0,0) }; $byArea[$a][2]++ }

Write-Output '=== RAWRXD BUILD GRAPH DIAGNOSTIC RECEIPT ==='
Write-Output "RAWRXD_GRAPH_SOURCES_REFERENCED=$referenced"
Write-Output "RAWRXD_GRAPH_SOURCES_PRESENT=$($present.Count)"
Write-Output "RAWRXD_GRAPH_SOURCES_ABSENT=$absent"
Write-Output "RAWRXD_GRAPH_ABSENT_CPP=$absentCpp"
Write-Output "RAWRXD_GRAPH_COMMENTED_OUT_REFS=$($cmtMiss.Count + $cmtPres.Count)"
Write-Output "RAWRXD_GRAPH_ACTIVE_MISSING=$($actMiss.Count)"
Write-Output "RAWRXD_GRAPH_COMMENTED_MISSING=$($cmtMiss.Count)"
Write-Output "RAWRXD_GRAPH_COMMENTED_PRESENT=$($cmtPres.Count)"

$areaStr = ($byArea.GetEnumerator() | Sort-Object { -($_.Value[0] + $_.Value[1]) } |
            ForEach-Object { "$($_.Key):$($_.Value[0] + $_.Value[1])" }) -join ','
Write-Output "RAWRXD_GRAPH_ABSENT_BY_AREA=$areaStr"

Write-Output '--- absent by area (active / commented-missing / commented-present) ---'
foreach ($e in ($byArea.GetEnumerator() | Sort-Object { -($_.Value[0] + $_.Value[1]) } | Select-Object -First 25)) {
    Write-Output ("  {0,-26} {1,5} {2,5} {3,5}" -f $e.Key, $e.Value[0], $e.Value[1], $e.Value[2])
}

$ok = ($absent -eq 0 -and $cmtMiss.Count -eq 0 -and $cmtPres.Count -eq 0)
Write-Output "RAWRXD_SOURCE_GRAPH_001=$(if ($ok) { 'PASS' } else { 'FAIL' })"
Write-Output 'RAWRXD_SOURCE_GRAPH_001_SCOPE=graph existence and reference visibility only'
Write-Output 'RAWRXD_SOURCE_GRAPH_001_NOT_A_FUNCTIONAL_PASS=1'

# machine-readable path dump for the materialisation step
$dump = @()
foreach ($k in $actMiss.Keys)  { $dump += "ACTIVE_MISSING,$k" }
foreach ($k in $cmtMiss.Keys)  { $dump += "COMMENTED_MISSING,$k" }
foreach ($k in $cmtPres.Keys)  { $dump += "COMMENTED_PRESENT,$k" }
$dump | Sort-Object | Set-Content -Path 'F:\~dev\audit_tombstone_001\graph_absent_paths.txt' -Encoding UTF8
Write-Output 'PATHS_DUMP=F:\~dev\audit_tombstone_001\graph_absent_paths.txt'
exit 0