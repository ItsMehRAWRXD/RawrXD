<#
.SYNOPSIS
    Build script for Deep2Engine using PowerShell
#>

Write-Host "====================================================" -ForegroundColor Cyan
Write-Host "       DEEP2ENGINE BUILD PIPELINE (PowerShell)      " -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$buildDir = Join-Path $scriptDir "build"

if (-not (Test-Path $buildDir)) {
    New-Item -ItemType Directory -Path $buildDir -Force | Out-Null
}

Set-Location $buildDir

Write-Host "[CMAKE] Configuring project..." -ForegroundColor Yellow
cmake .. -DCMAKE_BUILD_TYPE=Release
if ($LASTEXITCODE -ne 0) {
    Write-Error "[ERROR] CMake configuration failed"
    exit 1
}

Write-Host "[BUILD] Compiling..." -ForegroundColor Yellow
cmake --build . --config Release
if ($LASTEXITCODE -ne 0) {
    Write-Error "[ERROR] Build failed"
    exit 1
}

Write-Host ""
Write-Host "====================================================" -ForegroundColor Green
Write-Host "[SUCCESS] Build complete! Executable at:" -ForegroundColor Green
Write-Host "    build\bin\Deep2Engine_Benchmark.exe" -ForegroundColor Green
Write-Host "====================================================" -ForegroundColor Green