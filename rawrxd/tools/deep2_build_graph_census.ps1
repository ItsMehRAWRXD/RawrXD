$ErrorActionPreference = 'Stop'
# RAWRXD_DEEP2_BUILD_GRAPH_CENSUS_001
#
# Classifies every src/deep2 translation unit by whether it is reachable from
# any CMake target. The defect this measures is adoption, not design: a source
# file can be complete, correct and still contribute nothing to the product.
#
# Output is a machine-readable census plus a summary. No verdict is asserted
# here; this tool measures, it does not certify.

$root = 'F:\~dev\rawrxd'
$outDir = Join-Path $root 'audit\RAWRXD_DEEP2_BUILD_GRAPH_CENSUS_001'
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

$cmakeFiles = @(
    (Join-Path $root 'CMakeLists.txt'),
    (Join-Path $root 'win32ide_strict\CMakeLists.txt')
) | Where-Object { Test-Path $_ }

$cpp = Get-ChildItem (Join-Path $root 'src\deep2') -Recurse -Filter *.cpp
$total = $cpp.Count

$rows = New-Object System.Collections.Generic.List[object]
$missing = 0
$reachable = 0

foreach ($f in $cpp) {
    $rel = $f.FullName.Substring($root.Length + 1).Replace('\','/')

    # A file is reachable when at least one CMake manifest names its basename.
    # Basename matching is the right granularity here: CMake lists sources as
    # plain relative paths, and no two files in this tree share a basename.
    $hit = $false
    foreach ($cm in $cmakeFiles) {
        if (Select-String -Path $cm -SimpleMatch -Pattern $f.Name -Quiet) { $hit = $true; break }
    }

    # Distinguish a real stub from a real implementation: the stub-removed
    # marker this project uses is a file whose entire body is a `// STUB:` line.
    $stub = $false
    $lines = @(Get-Content $f.FullName | Where-Object { $_.Trim() -ne '' })
    if ($lines.Count -le 3 -and ($lines -join "`n") -match '^\s*//\s*STUB') { $stub = $true }

    if ($hit) { $reachable++ } else { $missing++ }

    $rows.Add([pscustomobject]@{
        Path       = $rel
        Reachable  = $hit
        IsStub     = $stub
        Bytes      = $f.Length
    })
}

$rows | Sort-Object Path | Export-Csv (Join-Path $outDir 'census.csv') -NoTypeInformation

$stubMissing = @($rows | Where-Object { -not $_.Reachable -and $_.IsStub }).Count
$implMissing = @($rows | Where-Object { -not $_.Reachable -and -not $_.IsStub }).Count

$summary = @()
$summary += "TOTAL_DEEP2_CPP=$total"
$summary += "REACHABLE_FROM_BUILD=$reachable"
$summary += "UNREACHABLE_FROM_BUILD=$missing"
$summary += "UNREACHABLE_PCT=$([math]::Round(100.0 * $missing / [math]::Max($total,1),1))"
$summary += "UNREACHABLE_STUB_FILES=$stubMissing"
$summary += "UNREACHABLE_IMPLEMENTATIONS=$implMissing"
$summary += "VERDICT=MEASURED"
$summary -join "`n" | Set-Content (Join-Path $outDir 'census_summary.txt') -Encoding UTF8

$summary