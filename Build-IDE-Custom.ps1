<#
.SYNOPSIS
    Build RawrXD IDE with your custom MASM C++ compiler (no MinGW).
.DESCRIPTION
    Set RAWRXD_CXX_COMPILER to your custom compiler path. Uses cmake/RawrXD_CustomCompiler.cmake.
#>
param(
    [string]$BuildDir = "build_custom",
    [string]$Config = "Release",
    [Parameter(Mandatory=$false)]
    [string]$CxxCompiler = $env:RAWRXD_CXX_COMPILER,
    [string]$CCompiler = $env:RAWRXD_C_COMPILER
)

$ErrorActionPreference = "Stop"
$ProjectRoot = $PSScriptRoot
$ToolchainFile = Join-Path $ProjectRoot "cmake\RawrXD_CustomCompiler.cmake"

if (-not $CxxCompiler -or -not (Test-Path $CxxCompiler)) {
    Write-Host "Set -CxxCompiler or env RAWRXD_CXX_COMPILER to your custom C++ compiler path." -ForegroundColor Red
    exit 1
}

$BuildPath = Join-Path $ProjectRoot $BuildDir
if (-not (Test-Path $BuildPath)) { New-Item -ItemType Directory -Path $BuildPath -Force | Out-Null }
Push-Location $BuildPath
try {
    $args = "-DCMAKE_TOOLCHAIN_FILE=$ToolchainFile", "-DRAWRXD_CXX_COMPILER=$CxxCompiler", "-DCMAKE_BUILD_TYPE=$Config", "-S", $ProjectRoot, "-B", "."
    if ($CCompiler -and (Test-Path $CCompiler)) { $args = $args + "-DRAWRXD_C_COMPILER=$CCompiler" }
    & cmake @args
    if ($LASTEXITCODE -ne 0) { throw "Configure failed" }
    & cmake --build . --config $Config
    if ($LASTEXITCODE -ne 0) { throw "Build failed" }
    Write-Host "IDE build complete. Output in $BuildPath" -ForegroundColor Green
} finally { Pop-Location }
