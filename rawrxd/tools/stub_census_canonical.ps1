<#
.SYNOPSIS
    RAWRXD_STUB_CENSUS_CANONICAL_001
    One canonical definition of "stub", applied to every axis the historical
    censuses varied, so that each conflicting count is DERIVED rather than
    argued about.

.DESCRIPTION
    Four historical numbers are in circulation for the same repository and the
    same question (how many stub translation units are there?):

        338   pure_stub_paths.txt        (RAWRXD_IDE_AUDIT_20261002)
        339   STUB_HEADER_REPORT.md  src, excluding .bak
        424   STUB_HEADER_REPORT.md  src(339) + tests(85)
        417   (unattributed)
        426   (unattributed)

    The purpose here is NOT to decide which number wins. It is to make each one
    REPRODUCIBLE from a named set of axes, so the disagreement becomes
    informative instead of a credibility problem.

    THE ROOT CAUSE OF THE DISAGREEMENT, found by reading the historical script:

        $first = FirstNonBlank $f.FullName
        if ($first -match '^//\s*STUB\b') { ... }

    That rule inspects ONLY the first non-blank line and requires the literal
    token STUB there. It therefore cannot see:

      * files whose banner is `// Auto-generated stub`   (the regex needs STUB
        immediately after `//` and optional whitespace; "Auto-generated" is in
        the way), and
      * files that are empty-bodied with no banner at all, and
      * files whose first line is a comment that merely mentions a stub.

    So the 338/339/417/424/426 spread is not measurement noise. It is five
    different QUESTIONS, and at least one of them was answered with a rule that
    is blind to the largest stub population in this tree.

    RULES (each named, so a count can always cite the rule that produced it):

      R1_FIRSTLINE_STUB   first non-blank line matches ^//\s*STUB
                          -- THE HISTORICAL RULE. Reported for reproduction only.

      R2_ANY_STUB         any line matches ^\s*//\s*(STUB|Auto-generated stub)
                          -- banner anywhere, both wordings.

      R3_AUTO_STUB        any line matches Auto-generated stub

      R4_ZERO_NONCOMMENT  after stripping block comments, line comments and
                          preprocessor lines, no code punctuation remains
                          (; { } ( ) =). This is the rule the CMake gate
                          rawrxd_filter_missing_sources() applies, and it is the
                          only one that catches a body-less file with no banner.

      R5_TRIVIAL_MAIN     body reduces to `intmainreturn0` -- an `int main(){...}`
                          that links and certifies nothing.

.PARAMETER RepoRoot
    Repository root. Defaults to the parent of this script's directory.

.PARAMETER EmitMatrix
    Print the full rules x roots x extensions reconciliation matrix.

.OUTPUT
    Text census to stdout. Nothing is written to the repository.
#>
[CmdletBinding()]
param(
    [string]$RepoRoot = '',
    [switch]$EmitMatrix
)

$ErrorActionPreference = 'Stop'
if (-not $RepoRoot) { $RepoRoot = Split-Path -Parent $PSScriptRoot }
if (-not (Test-Path $RepoRoot)) { throw "RepoRoot not found: $RepoRoot" }

# ---------------------------------------------------------------------------
# AXES, DECLARED. A count that does not name these is not a count.
# ---------------------------------------------------------------------------
$AXES = [ordered]@{
    ROOTS = @(
        @{ Name = 'rawrxd_all';   Paths = @('.') }
        @{ Name = 'src_only';     Paths = @('src') }
        @{ Name = 'src_and_tests';Paths = @('src', 'tests') }
    )
    # Historical censuses disagreed on whether HEADERS are part of the population.
    # A header is not a translation unit, so the default excludes them and the
    # matrix shows what including them costs.
    EXT_NO_HEADER  = @('.cpp', '.c', '.cc', '.cxx')
    EXT_WITH_HEADER= @('.cpp', '.c', '.cc', '.cxx', '.h', '.hpp')
    # Directories that are build output or vendored code. Counting them inflates
    # the population with COPIES, which is the classic way a census doubles.
    EXCLUDE_DIRS   = @('build', 'build_*', '.git', '3rdparty', 'out', 'bin',
                        'obj', 'node_modules', '.vs')
}

function Get-Excluded([string]$rel) {
    $norm = $rel.Replace('\', '/')
    foreach ($pat in $AXES.EXCLUDE_DIRS) {
        if ($norm -match "(^|/)$([regex]::Escape($pat) -replace '\\\*','[^/]*')(/|$)") {
            return $true
        }
    }
    return $false
}

# Comment and preprocessor stripping for R4. Order matters: block comments first
# (so a `//` inside a block comment does not start a line comment), then line
# comments, then preprocessor. PowerShell regex has no dot-matches-newline, so
# block comments are removed with a bounded loop rather than one pattern --
# the same constraint the CMake gate documents.
function Remove-Comments([string]$s) {
    $out = $s
    for ($i = 0; $i -lt 64; $i++) {
        $a = $out.IndexOf('/*')
        if ($a -lt 0) { break }
        $b = $out.IndexOf('*/', $a + 2)
        if ($b -lt 0) { break }
        $out = $out.Substring(0, $a) + ' ' + $out.Substring($b + 2)
    }
    $out = [regex]::Replace($out, '//[^\n]*', ' ')
    $out = [regex]::Replace($out, '#[^\n]*', ' ')
    return $out
}

function Get-FirstNonBlank([string]$path) {
    foreach ($line in [System.IO.File]::ReadLines($path)) {
        if (-not [string]::IsNullOrWhiteSpace($line)) { return $line.Trim() }
    }
    return ''
}

function Invoke-Census {
    param([string[]]$Paths, [string[]]$Extensions, [string]$Label)

    $files = New-Object System.Collections.Generic.List[System.IO.FileInfo]
    foreach ($p in $Paths) {
        $full = Join-Path $RepoRoot $p
        if (-not (Test-Path $full)) { continue }
        foreach ($f in [System.IO.Directory]::EnumerateFiles(
                    $full, '*', [System.IO.SearchOption]::AllDirectories)) {
            $rel = $f.Substring($RepoRoot.Length).TrimStart('\', '/')
            if (Get-Excluded $rel) { continue }
            $ext = [System.IO.Path]::GetExtension($f).ToLowerInvariant()
            if ($Extensions -notcontains $ext) { continue }
            $files.Add((New-Object System.IO.FileInfo($f)))
        }
    }
    # Duplicate-path policy: the SAME file reachable through two roots must be
    # counted once. EnumerateFiles per-root with a set keyed on full path.
    $seen = New-Object 'System.Collections.Generic.HashSet[string]'
    $uniq = New-Object System.Collections.Generic.List[System.IO.FileInfo]
    foreach ($f in $files) {
        if ($seen.Add($f.FullName)) { $uniq.Add($f) }
    }

    $r1 = 0; $r2 = 0; $r3 = 0; $r4 = 0; $r5 = 0
    $r2list = New-Object System.Collections.Generic.List[string]
    $r4list = New-Object System.Collections.Generic.List[string]
    $r1list = New-Object System.Collections.Generic.List[string]

    foreach ($f in $uniq) {
        $rel = $f.FullName.Substring($RepoRoot.Length).TrimStart('\', '/').Replace('\', '/')
        $first = Get-FirstNonBlank $f.FullName
        if ($first -match '^//\s*STUB\b') { $r1++; $r1list.Add($rel) }

        $text = [System.IO.File]::ReadAllText($f.FullName)
        $hasAnyStub = $text -match '(?m)^\s*//\s*(STUB\b|Auto-generated stub)'
        if ($hasAnyStub) { $r2++; $r2list.Add($rel) }
        if ($text -match '(?m)Auto-generated stub') { $r3++ }

        $code = Remove-Comments $text
        $hasCode = $code -match '[;{}()=]'
        if (-not $hasCode) { $r4++; $r4list.Add($rel) }
        $ident = [regex]::Replace($code, '[^A-Za-z0-9_]', '')
        if ($ident -eq 'intmainreturn0') { $r5++ }
    }

    return [pscustomobject]@{
        Label            = $Label
        FilesScanned     = $uniq.Count
        R1_FirstLineStub = $r1
        R2_AnyStub       = $r2
        R3_AutoStub      = $r3
        R4_ZeroNonComment= $r4
        R5_TrivialMain   = $r5
        R2Paths          = $r2list
        R4Paths          = $r4list
        R1Paths          = $r1list
    }
}

$combos = @()
foreach ($root in $AXES.ROOTS) {
    foreach ($extName in @('EXT_NO_HEADER', 'EXT_WITH_HEADER')) {
        $combos += ,@($root, $extName)
    }
}

$results = New-Object System.Collections.Generic.List[object]
foreach ($c in $combos) {
    $root = $c[0]; $extName = $c[1]
    $label = '{0}|{1}' -f $root.Name, $extName
    $results.Add((Invoke-Census -Paths $root.Paths -Extensions $AXES[$extName] -Label $label))
}

Write-Host ''
Write-Host '=== RAWRXD_STUB_CENSUS_CANONICAL_001 ==='
Write-Host ('REPO_ROOT=' + $RepoRoot)
Write-Host ''
Write-Host ('{0,-34} {1,7} {2,7} {3,7} {4,7} {5,7}' -f `
    'ROOT|EXT', 'FILES', 'R1', 'R2', 'R3', 'R4')
Write-Host ('-' * 72)
foreach ($r in $results) {
    Write-Host ('{0,-34} {1,7} {2,7} {3,7} {4,7} {5,7}' -f `
        $r.Label, $r.FilesScanned, $r.R1_FirstLineStub, $r.R2_AnyStub,
        $r.R3_AutoStub, $r.R4_ZeroNonComment)
}
Write-Host ''
Write-Host 'R1 = first-non-blank-line matches ^//\s*STUB   (THE HISTORICAL RULE)'
Write-Host 'R2 = any line matches ^\s*//\s*(STUB|Auto-generated stub)'
Write-Host 'R3 = any line matches Auto-generated stub'
Write-Host 'R4 = no code punctuation survives comment+preprocessor stripping'
Write-Host 'R5 = body reduces to int main(){return 0;}'

# The reconciliation that matters: how many files does the historical rule miss?
$primary = $results | Where-Object { $_.Label -eq 'src_only|EXT_WITH_HEADER' } | Select-Object -First 1
if (-not $primary) { $primary = $results | Select-Object -First 1 }
Write-Host ''
Write-Host '--- RECONCILIATION against the historical R1 rule ---'
Write-Host ('R1 sees            : ' + $primary.R1_FirstLineStub)
Write-Host ('R2 sees            : ' + $primary.R2_AnyStub)
Write-Host ('R4 sees            : ' + $primary.R4_ZeroNonComment)
$missed = @($primary.R4Paths | Where-Object { $primary.R1Paths -notcontains $_ })
Write-Host ('MISSED BY R1       : ' + $missed.Count + '  (visible to R4, invisible to R1)')
foreach ($m in ($missed | Select-Object -First 10)) { Write-Host ('    ' + $m) }

if ($EmitMatrix) {
    Write-Host ''
    Write-Host '--- FULL R4 LIST for the primary axis (canonical population) ---'
    foreach ($p in $primary.R4Paths) { Write-Host ('    ' + $p) }
}

Write-Host ''
Write-Host 'NOTE: a count is admissible only alongside its RULE, ROOT and EXT.'
Write-Host '      338 / 339 / 417 / 424 / 426 are five different questions.'
