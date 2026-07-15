#!/usr/bin/env powershell
# =============================================================================
# Build Sovereign INT8 Binary
# Phase 18 - Build Script for INT8 Quantized Inference Engine
# =============================================================================

[CmdletBinding()]
param(
    [string]$BuildDir = "build-int8",
    [string]$BuildType = "Release",
    [switch]$Clean
)

$ErrorActionPreference = "Stop"

Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║  Sovereign Engine v1.2_INT8 - Build Script                     ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Verify we're in the RawrXD directory
if (-not (Test-Path "CMakeLists.txt")) {
    throw "CMakeLists.txt not found. Run this script from the RawrXD root directory."
}

# Clean build if requested
if ($Clean -and (Test-Path $BuildDir)) {
    Write-Host "[INFO] Cleaning previous build..." -ForegroundColor Yellow
    Remove-Item -Recurse -Force $BuildDir
}

# Create build directory
if (-not (Test-Path $BuildDir)) {
    New-Item -ItemType Directory -Path $BuildDir | Out-Null
}

# Configure with CMake
Write-Host "[INFO] Configuring with CMake..." -ForegroundColor Green
$cmakeArgs = @(
    "-B", $BuildDir
    "-G", "Ninja"
    "-DCMAKE_BUILD_TYPE=$BuildType"
    "-DCMAKE_CXX_STANDARD=20"
    "-DRAWRXD_BUILD_WIN32IDE=OFF"
    "-DRAWRXD_BUILD_CLI=ON"
)

& cmake @cmakeArgs 2>&1 | ForEach-Object {
    if ($_ -match "error|Error|ERROR") {
        Write-Host $_ -ForegroundColor Red
    } else {
        Write-Host $_
    }
}

if ($LASTEXITCODE -ne 0) {
    throw "CMake configuration failed with exit code $LASTEXITCODE"
}

# Build the INT8 components
Write-Host "`n[INFO] Building Sovereign INT8 components..." -ForegroundColor Green

$components = @(
    "Sovereign_INT8_Kernels",
    "Sovereign_INT8_Dequant",
    "sovereign_int8_calibration",
    "sovereign_inference_dispatch"
)

foreach ($component in $components) {
    Write-Host "  Building $component..." -NoNewline
    ninja -C $BuildDir $component 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Host " OK" -ForegroundColor Green
    } else {
        Write-Host " SKIPPED (may be part of larger target)" -ForegroundColor Yellow
    }
}

# Build the main executable
Write-Host "`n[INFO] Linking Sovereign_v1.2_INT8.exe..." -ForegroundColor Green
ninja -C $BuildDir Sovereign_v1.2_INT8 2>&1 | ForEach-Object {
    if ($_ -match "error|Error|ERROR|warning|Warning|WARNING") {
        Write-Host $_ -ForegroundColor Red
    } else {
        Write-Host $_
    }
}

if ($LASTEXITCODE -ne 0) {
    # Try alternative target names
    Write-Host "[WARN] Primary target failed, trying alternatives..." -ForegroundColor Yellow
    
    $altTargets = @("rawrxd", "RawrEngine", "RawrXD_Gold")
    $built = $false
    
    foreach ($target in $altTargets) {
        Write-Host "  Trying $target..." -NoNewline
        ninja -C $BuildDir $target 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-Host " OK" -ForegroundColor Green
            $built = $true
            break
        } else {
            Write-Host " Failed" -ForegroundColor Red
        }
    }
    
    if (-not $built) {
        throw "Build failed for all target attempts"
    }
}

# Find the built binary
$binaryPaths = @(
    "$BuildDir\bin\Sovereign_v1.2_INT8.exe",
    "$BuildDir\Sovereign_v1.2_INT8.exe",
    "$BuildDir\bin\rawrxd.exe",
    "$BuildDir\bin\RawrEngine.exe",
    "$BuildDir\bin\RawrXD_Gold.exe"
)

$foundBinary = $null
foreach ($path in $binaryPaths) {
    if (Test-Path $path) {
        $foundBinary = $path
        break
    }
}

if ($foundBinary) {
    $fileInfo = Get-Item $foundBinary
    $sizeKB = [math]::Round($fileInfo.Length / 1KB, 2)
    
    Write-Host "`n[SUCCESS] Binary built successfully!" -ForegroundColor Green
    Write-Host "  Path: $foundBinary" -ForegroundColor White
    Write-Host "  Size: $sizeKB KB" -ForegroundColor White
    Write-Host "  Modified: $($fileInfo.LastWriteTime)" -ForegroundColor White
    
    # Copy to root for convenience
    $rootPath = "Sovereign_v1.2_INT8.exe"
    Copy-Item $foundBinary $rootPath -Force
    Write-Host "  Copied to: .\$rootPath" -ForegroundColor Green
    
    Write-Host "`nNext steps:" -ForegroundColor Cyan
    Write-Host "  1. Run validation: .\scripts\sanity_check_sapphire_rapids.ps1 -BinaryPath '.\Sovereign_v1.2_INT8.exe'"
    Write-Host "  2. Or execute directly: .\Sovereign_v1.2_INT8.exe --help"
} else {
    Write-Host "`n[WARN] Binary may have been built but not found in expected locations" -ForegroundColor Yellow
    Write-Host "  Check $BuildDir\bin\ for executables" -ForegroundColor Yellow
}

Write-Host "`nBuild complete." -ForegroundColor Green
