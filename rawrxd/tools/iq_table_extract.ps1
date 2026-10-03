<#
.SYNOPSIS
    RAWRXD_IQ_TABLE_EXTRACT_001
    Extract the i-quant codebook tables from a vendored ggml reference and emit
    them as a compilable C++ include.

.DESCRIPTION
    WHY THIS EXISTS, AND WHY IT IS A SCRIPT AND NOT A TRANSCRIPTION.

    Types 17 (IQ2_XS, 50 tensors) and 18 (IQ3_XXS, 77 tensors) of the deepseek4
    MoE model account for 127 of 129 routed-expert tensors. Both decode through
    fixed codebook tables. Those tables are the difference between measuring the
    MoE residual delta and declaring it unmeasurable.

    The tables were previously declared unobtainable, on the grounds that
    reproducing 256-4096 magic bytes from recall cannot be verified afterwards: a
    single wrong entry yields a decode that is perfectly self-consistent, passes
    every stationarity test, and produces a rank curve indistinguishable from a
    real one.

    That reasoning was correct about RECALL and wrong about AVAILABILITY. A
    vendored ggml exists in-tree at
        .kilo\worktrees\equal-viscountess\3rdparty\ggml\src\ggml-common.h
    and defines every table as
        GGML_TABLE_BEGIN(type, name, size) ... GGML_TABLE_END()
    with comma-separated decimal or hex literals. So the tables are READ, not
    remembered. This script parses them and emits an include.

    The generated file carries the source path, the line range and a content
    hash, so a reader can tell at a glance that the bytes came from the
    reference and not from an author.

    NOTHING HERE IS HAND-COPIED. A transcription of 4096 bytes is exactly the
    operation that cannot be checked.

.PARAMETER Reference
    Path to ggml-common.h.

.PARAMETER Out
    Output .inc path.

.PARAMETER Tables
    Table names to extract.
#>
[CmdletBinding()]
param(
    [string]$Reference = 'F:\~dev\.kilo\worktrees\equal-viscountess\3rdparty\ggml\src\ggml-common.h',
    [string]$OutFile = 'F:\~dev\rawrxd\certs\iq_tables.inc',
    [string[]]$Tables = @('kmask_iq2xs','ksigns_iq2xs','iq2xs_grid','iq3xxs_grid')
)
$ErrorActionPreference = 'Stop'
if (-not (Test-Path $Reference)) { throw "reference not found: $Reference" }

$lines = [System.IO.File]::ReadAllLines($Reference)
$sha = (Get-FileHash $Reference -Algorithm SHA256).Hash

# Named $outLines, not $out: the -Out/-OutFile parameters bind into the same
# scope and a same-named local silently wins, which turns every .Add() into a
# method call on a string.
$outLines = New-Object System.Collections.Generic.List[string]
$outLines.Add('// GENERATED FILE -- DO NOT EDIT BY HAND.')
$outLines.Add('// RAWRXD_IQ_TABLE_EXTRACT_001')
$outLines.Add("// SOURCE  : $Reference")
$outLines.Add("// SHA256  : $sha")
$outLines.Add('// These bytes are PARSED from the reference above. They are not transcribed,')
$outLines.Add('// and they are not recalled. Re-run tools/iq_table_extract.ps1 to regenerate.')
$outLines.Add('')

$emitted = @()
foreach ($name in $Tables) {
    # Locate the opening macro for this exact table name.
    $beginIdx = -1
    $ctype = $null
    $csize = $null
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match 'GGML_TABLE_BEGIN\(\s*([A-Za-z0-9_]+)\s*,\s*' +
                           [regex]::Escape($name) + '\s*,\s*([^)]+)\)') {
            $beginIdx = $i; $ctype = $Matches[1]; $csize = $Matches[2].Trim(); break
        }
    }
    if ($beginIdx -lt 0) {
        $outLines.Add("// MISSING: $name  (not found in reference -- this is a hard stop)")
        continue
    }
    # Collect until GGML_TABLE_END.
    $body = New-Object System.Collections.Generic.List[string]
    $endIdx = -1
    for ($i = $beginIdx + 1; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match 'GGML_TABLE_END') { $endIdx = $i; break }
        # strip line comments and block-comment fragments
        $t = [regex]::Replace($lines[$i], '//.*$', '')
        $t = [regex]::Replace($t, '/\*.*?\*/', '')
        $body.Add($t)
    }
    if ($endIdx -lt 0) {
        $outLines.Add("// UNTERMINATED: $name")
        continue
    }

    $joined = ($body -join ' ')
    $joined = [regex]::Replace($joined, '\s+', ' ')
    $parts = $joined.Split(',') | ForEach-Object { $_.Trim() } |
             Where-Object { $_ -ne '' -and $_ -match '^[0-9A-Fa-fx]+$' }

    $outLines.Add("// $name : $ctype[$csize]   source lines $($beginIdx+1)..$($endIdx+1)")
    $outLines.Add("static const $ctype $name[] = {")
    $perLine = 8
    for ($i = 0; $i -lt $parts.Count; $i += $perLine) {
        $chunk = $parts[$i..([Math]::Min($i + $perLine - 1, $parts.Count - 1))]
        $outLines.Add('    ' + ($chunk -join ', ') + ',')
    }
    $outLines.Add('};')
    $outLines.Add('')
    $emitted += [pscustomobject]@{
        Name = $name; Declared = $csize; Emitted = $parts.Count
        FirstLine = $beginIdx + 1; LastLine = $endIdx + 1
    }
}

[System.IO.File]::WriteAllLines($OutFile, $outLines)

Write-Host ''
Write-Host '=== RAWRXD_IQ_TABLE_EXTRACT_001 ==='
Write-Host ("REFERENCE      = $Reference")
Write-Host ("REFERENCE_SHA  = $sha")
Write-Host ("OUT            = $OutFile")
Write-Host ''
Write-Host ('{0,-18} {1,-10} {2,-9} {3,-9} {4}' -f 'TABLE','TYPE','DECLARED','EMITTED','LINES')
Write-Host ('-' * 64)
$allOk = $true
foreach ($e in $emitted) {
    $ok = ([int]$e.Declared -eq [int]$e.Emitted)
    if (-not $ok) { $allOk = $false }
    Write-Host ('{0,-18} {1,-10} {2,-9} {3,-9} {4}-{5} {6}' -f `
        $e.Name, '', $e.Declared, $e.Emitted, $e.FirstLine, $e.LastLine,
        $(if ($ok) { 'OK' } else { 'COUNT MISMATCH' }))
}
Write-Host ''
# A count mismatch means the parser dropped or invented entries. That is the one
# failure mode that would silently corrupt every decode built on the table.
if ($allOk) {
    Write-Host 'TABLE_COUNT_VERIFICATION=PASS  (every table emitted exactly its declared size)'
} else {
    Write-Host 'TABLE_COUNT_VERIFICATION=FAIL  (a table does not match its declared size)'
}
Write-Host ("GENERATED_SHA256 = " + (Get-FileHash $OutFile -Algorithm SHA256).Hash)
if (-not $allOk) { exit 2 }
