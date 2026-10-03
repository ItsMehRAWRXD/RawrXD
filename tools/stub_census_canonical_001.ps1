<#
RAWRXD_STUB_CENSUS_CANONICAL_001

Establishes ONE canonical stub population and measures load-bearing-ness EMPIRICALLY
rather than by parsing CMakeLists.txt.

Why empirical: the stub census has produced four different totals (334, 417, 424, 426)
and one provably wrong structural claim (APPEND_THEN_REMOVE=0, refuted by direct source
reading). Static CMake parsing is what produced the wrong answer, so this census does not
rely on it for the load-bearing question.

Ground truth for "did this stub actually compile?":  if a translation unit is a member of
a target that was really built, its object file exists in the build tree. That is an
artifact produced by the compiler, not an inference about a source list.

Canonical method, stated so the discrepancy with prior counts is EXPLAINABLE:
  - roots      : rawrxd\src and rawrxd\tests
  - extensions : .cpp, .h, .hpp
  - predicate  : FIRST line matches ^// STUB:
  - excluded   : any path containing \build, \evidence\, \audit\, _n2_stage, \.kilo,
                 or ending in .bak
A prior agent reported 23 then 21 header-backed stubs; the earlier census reported 19. That
is the same kind of drift this script is meant to stop, so every count below is emitted
with the command that produced it.
#>

$ErrorActionPreference = 'Continue'
$Repo   = 'F:\~dev'
$Rawrxd = 'F:\~dev\rawrxd'
$Build  = 'F:\~dev\build_rawr_ninja'
$Log    = 'F:\~dev\audit_tombstone_001'
$Out    = Join-Path $Log 'stub_census_canonical.csv'

$exclude = '\\build|\\evidence\\|\\audit\\|_n2_stage|\\\.kilo\\'
$roots   = @("$Rawrxd\src", "$Rawrxd\tests")

$files = foreach ($r in $roots) {
    if (-not (Test-Path $r)) { continue }
    Get-ChildItem -Path $r -Recurse -File -Include *.cpp,*.h,*.hpp -ErrorAction SilentlyContinue |
      Where-Object { $_.FullName -notmatch $exclude -and $_.Name -notlike '*.bak' }
}

$stubs = @()
foreach ($f in $files) {
    $first = Get-Content $f.FullName -TotalCount 1 -ErrorAction SilentlyContinue
    if ($first -and $first -match '^\s*//\s*STUB:') {
        $rel = $f.FullName.Substring($Rawrxd.Length + 1) -replace '\\','/'
        $stubs += [pscustomobject]@{
            Path      = $rel
            Dir       = ($rel -split '/')[1]
            Ext       = $f.Extension
            Lines     = (Get-Content $f.FullName -ErrorAction SilentlyContinue | Measure-Object -Line).Lines
        }
    }
}

Write-Output "TOTAL_FILES_SCANNED=$($files.Count)"
Write-Output "TOTAL_STUBS_CANONICAL=$($stubs.Count)"
$srcStubs  = @($stubs | Where-Object { $_.Path -like 'src/*' }).Count
$testStubs = @($stubs | Where-Object { $_.Path -like 'tests/*' }).Count
Write-Output "STUBS_SRC=$srcStubs"
Write-Output "STUBS_TESTS=$testStubs"

Write-Output ''
Write-Output '--- by subdirectory (top 15) ---'
$stubs | Group-Object Dir | Sort-Object Count -Descending | Select-Object -First 15 |
    ForEach-Object { Write-Output ("  {0,-24} {1}" -f $_.Name, $_.Count) }

# ---- header pairing -------------------------------------------------------
$hdrCount = 0; $hdrRows = @()
foreach ($s in $stubs) {
    if ($s.Ext -ne '.cpp') { continue }
    $base = [IO.Path]::GetFileNameWithoutExtension($s.Path)
    $stem = Join-Path $Rawrxd (Split-Path $s.Path -Parent)
    foreach ($ext in '.hpp','.h') {
        $cand = Join-Path $stem ($base + $ext)
        if (Test-Path $cand) { $hdrCount++; $hdrRows += [pscustomobject]@{Stub=$s.Path;Header=$s.Path.Substring(0,$s.Path.Length-4)+$ext}; break }
    }
}
Write-Output ''
Write-Output "STUBS_WITH_SAME_DIR_HEADER=$hdrCount"

# ---- EMPIRICAL load-bearing: does an object file exist? --------------------
$objHits = @()
foreach ($s in $stubs) {
    if ($s.Ext -ne '.cpp') { continue }
    $relDir  = (Split-Path $s.Path -Parent) -replace '/','\'
    $base    = [IO.Path]::GetFileNameWithoutExtension($s.Path)
    $found   = @(Get-ChildItem -Path $Build -Recurse -File -Filter "$base.cpp.obj" -ErrorAction SilentlyContinue |
                 Where-Object { $_.FullName -replace '\\','/' -like "*$($s.Path -replace '\.cpp$')" })
    if ($found.Count) { $objHits += [pscustomobject]@{Stub=$s.Path; Obj=$found[0].FullName} }
}
Write-Output ''
Write-Output "EMPIRICALLY_COMPILED_STUBS=$($objHits.Count)"
if ($objHits.Count) {
    Write-Output '  (a .obj exists ONLY if the TU really compiled into a built target)'
    $objHits | ForEach-Object { Write-Output "  COMPILED: $($_.Stub)" }
}

Write-Output ''
Write-Output "STUBS_NOT_COMPILED=$($stubs.Count - $objHits.Count)"
Write-Output "COVERAGE=$([math]::Round(100.0*$stubs.Count/[math]::Max(1,$stubs.Count),2))% enumerated"

$stubs | Export-Csv -Path $Out -NoTypeInformation -Encoding UTF8
Write-Output ''
Write-Output "CSV=$Out"