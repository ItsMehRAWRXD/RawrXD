[CmdletBinding()]
param(
    [string]$RepoRoot = 'F:\~dev\rawrxd',
    [string]$Receipt = '',
    [switch]$ScanAllSrc,
    [switch]$NoFail
)
$ErrorActionPreference = 'Stop'
$scanRoot = if ($ScanAllSrc) { Join-Path $RepoRoot 'src' } else { Join-Path $RepoRoot 'src\win32app' }
if (-not (Test-Path $scanRoot)) { throw "Scan root not found: $scanRoot" }
if (-not $Receipt) { $Receipt = Join-Path $RepoRoot 'ide_stub_audit_receipt.txt' }
$cmake = Join-Path $RepoRoot 'CMakeLists.txt'
$cmakeText = if (Test-Path $cmake) { [System.IO.File]::ReadAllText($cmake).Replace('\','/') } else { '' }

function FirstNonBlank([string]$Path) {
    foreach ($line in [System.IO.File]::ReadLines($Path)) {
        if (-not [string]::IsNullOrWhiteSpace($line)) { return $line.Trim() }
    }
    return ''
}
$files = Get-ChildItem $scanRoot -Recurse -File | Where-Object { $_.Extension -in '.cpp','.c','.h','.hpp','.cc','.cxx' }
$pure = New-Object System.Collections.Generic.List[object]
$markers = New-Object System.Collections.Generic.List[object]
$stubNamed = New-Object System.Collections.Generic.List[object]
foreach ($f in $files) {
    $first = FirstNonBlank $f.FullName
    $rel = [IO.Path]::GetRelativePath($RepoRoot, $f.FullName).Replace('\','/')
    if ($first -match '^//\s*STUB\b') {
        $cmakeRef = $cmakeText.Contains($rel)
        $pure.Add([pscustomobject]@{Path=$rel; CMakeReferenced=$cmakeRef})
    }
    if ($f.Name -match '(?i)stub|fallback') { $stubNamed.Add($rel) }
    $hits = Select-String -LiteralPath $f.FullName -Pattern 'TODO','NOTIMPL','not implemented','placeholder' -SimpleMatch -ErrorAction SilentlyContinue
    if ($hits) { $markers.Add([pscustomobject]@{Path=$rel; Count=@($hits).Count}) }
}
$cmakePure = @($pure | Where-Object CMakeReferenced)
$lines = New-Object System.Collections.Generic.List[string]
$lines.Add('GATE=RAWRXD_IDE_STUB_AUDIT_001')
$lines.Add('TIMESTAMP_UTC=' + (Get-Date).ToUniversalTime().ToString('o'))
$lines.Add('REPO_ROOT=' + $RepoRoot)
$lines.Add('SCAN_ROOT=' + $scanRoot)
$lines.Add('SOURCE_FILES_SCANNED=' + @($files).Count)
$lines.Add('PURE_STUB_FILES=' + @($pure).Count)
$lines.Add('CMAKE_REFERENCED_PURE_STUB_FILES=' + @($cmakePure).Count)
$lines.Add('STUB_OR_FALLBACK_NAMED_FILES=' + @($stubNamed).Count)
$lines.Add('MARKER_FILES=' + @($markers).Count)
foreach ($x in $pure) { $lines.Add(('PURE_STUB={0}|CMAKE={1}' -f $x.Path,[int]$x.CMakeReferenced)) }
foreach ($x in $stubNamed) { $lines.Add('STUB_NAMED=' + $x) }
foreach ($x in $markers) { $lines.Add(('MARKER_FILE={0}|COUNT={1}' -f $x.Path,$x.Count)) }
$verdict = if (@($pure).Count -eq 0) { 'PASS' } else { 'FAIL' }
$lines.Add('VERDICT=' + $verdict)
[IO.File]::WriteAllLines($Receipt, $lines)
$lines | ForEach-Object { Write-Host $_ }
if ($verdict -ne 'PASS' -and -not $NoFail) { exit 2 }
