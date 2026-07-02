#!/usr/bin/env powershell
# =============================================================================
# Fix CMake Cache Loop Issue
# Clears cache and reconfigures properly
# =============================================================================

[CmdletBinding()]
param(
    [string]$BuildDir = "build-test",
    [string]$BuildType = "Release"
)

$ErrorActionPreference = "Stop"

Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║  Fixing CMake Cache Loop                                       ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan

# Step 1: Clean the build directory completely
if (Test-Path $BuildDir) {
    Write-Host "[INFO] Removing existing build directory..." -ForegroundColor Yellow
    Remove-Item -Recurse -Force $BuildDir
    Write-Host "[OK] Build directory removed" -ForegroundColor Green
}

# Step 2: Create fresh build directory
New-Item -ItemType Directory -Path $BuildDir | Out-Null
Write-Host "[OK] Fresh build directory created" -ForegroundColor Green

# Step 3: Configure with explicit settings to avoid cache invalidation
Write-Host "`n[INFO] Configuring CMake (single pass)..." -ForegroundColor Cyan

$env:CMAKE_ASM_MASM_COMPILER = "C:/Program Files/Microsoft Visual Studio/18/Enterprise/VC/Tools/MSVC/14.51.36231/bin/Hostx64/x64/ml64.exe"

$cmakeArgs = @(
    "-B", $BuildDir
    "-G", "Ninja"
    "-DCMAKE_BUILD_TYPE=$BuildType"
    "-DCMAKE_CXX_STANDARD=20"
    "-DCMAKE_ASM_MASM_COMPILER=$env:CMAKE_ASM_MASM_COMPILER"
)

& cmake @cmakeArgs 2>&1 | ForEach-Object {
    if ($_ -match "error|Error|ERROR") {
        Write-Host $_ -ForegroundColor Red
    } else {
        Write-Host $_
    }
}

if ($LASTEXITCODE -ne 0) {
    throw "CMake configuration failed"
}

Write-Host "`n[OK] CMake configuration complete (no cache loop)" -ForegroundColor Green
Write-Host "`nNext steps:" -ForegroundColor Cyan
Write-Host "  ninja -C $BuildDir <target>"
Write-Host "  Or run: .\scripts\run_all_tests.ps1 -SkipBuild"
