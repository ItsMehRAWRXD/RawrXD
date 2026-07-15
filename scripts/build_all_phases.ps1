#!/usr/bin/env pwsh
#Requires -Version 7.0

<#
.SYNOPSIS
    Build script for all RawrXD phases

.DESCRIPTION
    Builds all C++ components for phases AW-4 through AZ

.NOTES
    File: build_all_phases.ps1
    Version: 14.7.3
    Date: 2026-07-14
#>

[CmdletBinding()]
param(
    [string]$BuildType = "Release",
    [string]$BuildDir = "..\build",
    [switch]$Clean,
    [switch]$Verbose
)

$ErrorActionPreference = "Stop"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "RawrXD v14.7.3 - Build All Phases" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# Clean build directory if requested
if ($Clean -and (Test-Path $BuildDir)) {
    Write-Host "Cleaning build directory..." -ForegroundColor Yellow
    Remove-Item -Recurse -Force $BuildDir
}

# Create build directory
if (-not (Test-Path $BuildDir)) {
    New-Item -ItemType Directory -Path $BuildDir | Out-Null
}

Set-Location $BuildDir

# Configure with CMake
Write-Host "`nConfiguring with CMake..." -ForegroundColor Green
$cmakeArgs = @(
    "..",
    "-G", "Ninja",
    "-DCMAKE_BUILD_TYPE=$BuildType",
    "-DCMAKE_CXX_STANDARD=17",
    "-DRAWRXD_BUILD_PHASE_AW4=ON",
    "-DRAWRXD_BUILD_PHASE_AX=ON",
    "-DRAWRXD_BUILD_PHASE_AY=ON",
    "-DRAWRXD_BUILD_PHASE_AZ=ON",
    "-DRAWRXD_BUILD_TESTS=ON"
)

if ($Verbose) {
    $cmakeArgs += "-DCMAKE_VERBOSE_MAKEFILE=ON"
}

& cmake @cmakeArgs
if ($LASTEXITCODE -ne 0) {
    Write-Error "CMake configuration failed"
    exit 1
}

# Build
Write-Host "`nBuilding all phases..." -ForegroundColor Green
$buildArgs = @("--build", ".", "--config", $BuildType)
if ($Verbose) {
    $buildArgs += "--verbose"
}

& ninja
if ($LASTEXITCODE -ne 0) {
    Write-Error "Build failed"
    exit 1
}

Write-Host "`n========================================" -ForegroundColor Green
Write-Host "Build completed successfully!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green

# Show build summary
Write-Host "`nBuild Summary:" -ForegroundColor Cyan
Write-Host "  Build Type: $BuildType"
Write-Host "  Build Directory: $(Resolve-Path $BuildDir)"

# List built artifacts
$artifacts = Get-ChildItem -Path "." -Recurse -Include "*.exe", "*.dll", "*.lib", "*.a", "*.so" -ErrorAction SilentlyContinue
if ($artifacts) {
    Write-Host "`nBuilt Artifacts:" -ForegroundColor Cyan
    $artifacts | ForEach-Object { Write-Host "  - $($_.Name)" }
}

Set-Location ..
