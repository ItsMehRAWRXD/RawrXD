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
# Win32 IDE targets remain gated in CMake (if(FALSE) until headers land).
# CI still compiles the always-on native library so the job is a real build.
$targets = @("brutal_gzip")
if ($env:CI -eq "true") {
    foreach ($target in $targets) {
        Write-Host ">>> Building target $target ..."
        cmake --build $BuildDir --config $Config --target $target
        if ($LASTEXITCODE -ne 0) { throw "CMake build failed for $target" }
    }
} else {
    cmake --build $BuildDir --config $Config
    if ($LASTEXITCODE -ne 0) { throw "CMake build failed" }
}

Write-Host ">>> Done: binaries in $BuildDir\$Config"
