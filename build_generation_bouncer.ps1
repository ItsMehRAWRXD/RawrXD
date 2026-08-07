# Build Generation Bouncer + CLI
# Usage: .\build_generation_bouncer.ps1

$ErrorActionPreference = "Stop"
Set-Location "D:\rawrxd"

Write-Host "[Build] Creating build directory..." -ForegroundColor Cyan
if (!(Test-Path "build")) {
    New-Item -ItemType Directory -Path "build" | Out-Null
}

Set-Location "build"

Write-Host "[Build] Running CMake configure..." -ForegroundColor Cyan
cmake -G Ninja .. `
    -DCMAKE_BUILD_TYPE=Release `
    -DRAWRXD_BUILD_CLI=ON `
    -DRAWRXD_PRODUCTION_STRIP_STUB_SOURCES=OFF

if ($LASTEXITCODE -ne 0) {
    Write-Host "[Build] CMake configure failed!" -ForegroundColor Red
    exit $LASTEXITCODE
}

Write-Host "[Build] Building RawrXD-Generate..." -ForegroundColor Cyan
cmake --build . --target RawrXD-Generate --config Release

if ($LASTEXITCODE -ne 0) {
    Write-Host "[Build] Build failed!" -ForegroundColor Red
    exit $LASTEXITCODE
}

Write-Host "[Build] Build complete!" -ForegroundColor Green
Write-Host "[Run]  .\bin\RawrXD-Generate.exe --model <path> --prompt `"Hello`"" -ForegroundColor Yellow
