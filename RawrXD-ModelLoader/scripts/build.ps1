param(
  [string]$Config = "Release",
  [string]$A       = "x64"
)

$BuildDir = Join-Path $PSScriptRoot "..\build"

# Clean build directory to avoid CMake cache path mismatches
if (Test-Path $BuildDir) {
    Write-Host ">>> Cleaning previous build directory ..."
    Remove-Item $BuildDir -Recurse -Force
}

New-Item -ItemType Directory -Path $BuildDir | Out-Null

Write-Host ">>> Configuring CMake ..."
cmake -S (Join-Path $PSScriptRoot "..") -B $BuildDir -A $A -DCMAKE_BUILD_TYPE=$Config
if ($LASTEXITCODE -ne 0) { throw "CMake configure failed" }

Write-Host ">>> Building ..."
cmake --build $BuildDir --config $Config
if ($LASTEXITCODE -ne 0) { throw "CMake build failed" }

Write-Host ">>> Done: binaries in $BuildDir\$Config"
