param(
    [string]$RepoRoot = "F:\~dev\rawrxd",
    [string]$BuildDir = "build-win32ide-p1",
    [string]$Generator = "",
    [string]$Config = "Release"
)

$ErrorActionPreference = "Stop"
Set-Location $RepoRoot

$absBuild = Join-Path $RepoRoot $BuildDir
if (Test-Path $absBuild) {
    Remove-Item -Recurse -Force $absBuild
}

$args = @(
    "-S", ".",
    "-B", $BuildDir,
    "-DRAWRXD_BUILD_WIN32IDE=ON",
    "-DRAWRXD_BUILD_RAWRENGINE=OFF",
    "-DRAWRXD_BUILD_GOLD=OFF"
)
if ($Generator) {
    $args += @("-G", $Generator)
}

& cmake @args
if ($LASTEXITCODE -ne 0) {
    throw "BLOCK1_CONFIGURE_FAIL exit=$LASTEXITCODE"
}

$missing = Join-Path $absBuild "P1_WIN32IDE_MISSING_SOURCES.txt"
if (-not (Test-Path $missing)) {
    throw "BLOCK1_FILTER_MANIFEST_MISSING: $missing"
}

& cmake --build $BuildDir --target RawrXD-Win32IDE --config $Config --parallel
if ($LASTEXITCODE -ne 0) {
    throw "BLOCK1_BUILD_FAIL exit=$LASTEXITCODE"
}

$candidates = @(
    (Join-Path $absBuild "bin\RawrXD-Win32IDE.exe"),
    (Join-Path $absBuild "$Config\RawrXD-Win32IDE.exe"),
    (Join-Path $absBuild "bin\$Config\RawrXD-Win32IDE.exe")
)
$exe = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $exe) {
    throw "BLOCK1_EXE_NOT_FOUND"
}

"BLOCK1_WIN32IDE=PASS"
"EXE=$exe"
Get-Content $missing
