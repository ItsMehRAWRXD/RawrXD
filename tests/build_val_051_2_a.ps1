# Build script for VAL-051.2.A Standalone Token Proof
# Requires: Visual Studio 2022/2026 (cl.exe)

$ErrorActionPreference = "Stop"

Write-Host "=== Building VAL-051.2.A Standalone Token Proof ===" -ForegroundColor Cyan
Write-Host ""

# Find VS2022/2026
$vsWhere = "C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path $vsWhere)) {
    Write-Error "vswhere.exe not found. Please install Visual Studio."
    exit 1
}

$vsPath = & $vsWhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $vsPath) {
    Write-Error "Visual Studio with C++ tools not found."
    exit 1
}

Write-Host "Found Visual Studio at: $vsPath" -ForegroundColor Green

# Import VS environment
$vcvars = Join-Path $vsPath "VC\Auxiliary\Build\vcvars64.bat"
if (-not (Test-Path $vcvars)) {
    Write-Error "vcvars64.bat not found at: $vcvars"
    exit 1
}

# Get environment from vcvars
$envVars = cmd /c "`"$vcvars`" && set"
$envVars | ForEach-Object {
    if ($_ -match '^([^=]+)=(.*)$') {
        $name = $matches[1]
        $value = $matches[2]
        Set-Item -Path "Env:$name" -Value $value
    }
}

Write-Host "Visual Studio environment loaded" -ForegroundColor Green
Write-Host ""

# Paths
$rawrxdRoot = "D:\rawrxd"
$src = "$rawrxdRoot\tests\val_051_2_a_standalone_token_proof.cpp"
$src1 = "$rawrxdRoot\src\gguf_loader.cpp"
$src2 = "$rawrxdRoot\src\core\inference_witness.cpp"
$out = "$rawrxdRoot\tests\val_051_2_a.exe"

# Compiler flags - use INCLUDE env var from vcvars + add missing SDK paths
$winSdkVer = "10.0.22621.0"
$includes = @(
    "/I`"$rawrxdRoot\include`"",
    "/I`"$rawrxdRoot\src`"",
    "/I`"$rawrxdRoot\include\core`"",
    "/I`"C:\Program Files (x86)\Windows Kits\10\include\$winSdkVer\um`"",
    "/I`"C:\Program Files (x86)\Windows Kits\10\include\$winSdkVer\shared`""
)

$flags = @(
    "/std:c++20",
    "/O2",
    "/EHsc",
    "/W3",
    "/nologo",
    "/D_CRT_SECURE_NO_WARNINGS",
    "/DWIN32_LEAN_AND_MEAN"
)

Write-Host "Compiling..." -ForegroundColor Yellow
Write-Host "  Source: $src" -ForegroundColor Gray
Write-Host "  Output: $out" -ForegroundColor Gray
Write-Host ""

# Build command
$cl = "cl.exe"
$args = $flags + $includes + @($src, $src1, $src2, "/Fe:`"$out`"")

& $cl @args

if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Error "Build failed with exit code $LASTEXITCODE"
    exit 1
}

Write-Host ""
Write-Host "=== Build SUCCESS ===" -ForegroundColor Green
Write-Host "Executable: $out" -ForegroundColor Cyan
Write-Host ""
Write-Host "To run:" -ForegroundColor Yellow
Write-Host "  $out" -ForegroundColor White
Write-Host "  $out [path_to_model.gguf]" -ForegroundColor White
