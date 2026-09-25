[CmdletBinding()]
param(
    [string]$RepoRoot = 'F:\~dev\rawrxd',
    [string]$OutDir = ''
)
$ErrorActionPreference = 'Stop'
if (-not $OutDir) { $OutDir = Join-Path $RepoRoot '_ide_stub_context' }
$srcRoot = Join-Path $RepoRoot 'src\win32app'
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
function FirstNonBlank([string]$Path) {
    foreach ($line in [IO.File]::ReadLines($Path)) { if (-not [string]::IsNullOrWhiteSpace($line)) { return $line.Trim() } }
    return ''
}
$stubs = Get-ChildItem $srcRoot -Recurse -File -Filter '*.cpp' | Where-Object { (FirstNonBlank $_.FullName) -match '^//\s*STUB\b' }
$manifest = New-Object System.Collections.Generic.List[string]
foreach ($f in $stubs) {
    $rel = [IO.Path]::GetRelativePath($RepoRoot, $f.FullName)
    $dst = Join-Path $OutDir $rel
    New-Item -ItemType Directory -Force -Path (Split-Path $dst -Parent) | Out-Null
    Copy-Item $f.FullName $dst -Force
    $manifest.Add($rel)
}
foreach ($support in @('src\win32app\Win32IDE.h','src\win32app\Win32IDE.hpp','CMakeLists.txt')) {
    $p=Join-Path $RepoRoot $support
    if (Test-Path $p) {
        $dst=Join-Path $OutDir $support
        New-Item -ItemType Directory -Force -Path (Split-Path $dst -Parent) | Out-Null
        Copy-Item $p $dst -Force
    }
}
[IO.File]::WriteAllLines((Join-Path $OutDir 'PURE_STUB_MANIFEST.txt'), $manifest)
Write-Host "PURE_STUB_CONTEXT_FILES=$($manifest.Count)"
Write-Host "OUT_DIR=$OutDir"
