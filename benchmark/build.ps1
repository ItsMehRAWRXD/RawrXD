#!/usr/bin/env pwsh
# RawrXD Reproducible Build Script
# Usage: .\benchmark\build.ps1 [-Clean] [-Config Release|Debug]

param(
    [switch]$Clean = $false,
    [string]$Config = "Release",
    [string]$BuildDir = "build",
    [string]$VcpkgDir = "$env:VCPKG_ROOT"
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "Continue"

# Build metadata
$BuildId = [System.Guid]::NewGuid().ToString().Substring(0, 8)
$BuildTime = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
$GitCommit = (git rev-parse --short HEAD 2>$null) || "unknown"
$GitBranch = (git rev-parse --abbrev-ref HEAD 2>$null) || "unknown"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "RawrXD Reproducible Build" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Build ID:    $BuildId"
Write-Host "Config:      $Config"
Write-Host "Commit:      $GitCommit"
Write-Host "Branch:      $GitBranch"
Write-Host "Time:        $BuildTime"
Write-Host ""

# Verify environment
Write-Host "[1/5] Verifying environment..." -ForegroundColor Yellow

$requiredTools = @(
    @{ Name = "CMake"; Command = "cmake"; MinVersion = "3.20" },
    @{ Name = "Ninja"; Command = "ninja"; MinVersion = "1.10" },
    @{ Name = "Git"; Command = "git"; MinVersion = "2.30" },
    @{ Name = "Python"; Command = "python"; MinVersion = "3.9" }
)

$missingTools = @()
foreach ($tool in $requiredTools) {
    $found = Get-Command $tool.Command -ErrorAction SilentlyContinue
    if (-not $found) {
        $missingTools += $tool.Name
        Write-Host "  ✗ $($tool.Name) not found" -ForegroundColor Red
    } else {
        $version = & $tool.Command --version 2>$null | Select-Object -First 1
        Write-Host "  ✓ $($tool.Name) $version" -ForegroundColor Green
    }
}

if ($missingTools.Count -gt 0) {
    Write-Host "ERROR: Missing required tools: $($missingTools -join ', ')" -ForegroundColor Red
    exit 1
}

# Check for Visual Studio
Write-Host "  Checking Visual Studio..." -NoNewline
$vsWhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (Test-Path $vsWhere) {
    $vsPath = & $vsWhere -latest -property installationPath
    Write-Host " found at $vsPath" -ForegroundColor Green
} else {
    Write-Host " not found (may use MinGW)" -ForegroundColor Yellow
}

# Clean build directory
if ($Clean -and (Test-Path $BuildDir)) {
    Write-Host "[2/5] Cleaning build directory..." -ForegroundColor Yellow
    Remove-Item -Recurse -Force $BuildDir
}

# Configure
Write-Host "[3/5] Configuring with CMake..." -ForegroundColor Yellow
New-Item -ItemType Directory -Force -Path $BuildDir | Out-Null

$cmakeArgs = @(
    "-S", ".",
    "-B", $BuildDir,
    "-G", "Ninja",
    "-DCMAKE_BUILD_TYPE=$Config",
    "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
    "-DRAWRXD_BUILD_TESTS=ON",
    "-DRAWRXD_BUILD_BENCHMARKS=ON"
)

if ($VcpkgDir -and (Test-Path "$VcpkgDir\scripts\buildsystems\vcpkg.cmake")) {
    $cmakeArgs += "-DCMAKE_TOOLCHAIN_FILE=$VcpkgDir/scripts/buildsystems/vcpkg.cmake"
}

& cmake @cmakeArgs 2>&1 | Tee-Object -FilePath "$BuildDir\configure.log"
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: CMake configuration failed" -ForegroundColor Red
    exit 1
}

# Build
Write-Host "[4/5] Building..." -ForegroundColor Yellow
$buildStart = Get-Date

& cmake --build $BuildDir --config $Config --parallel $env:NUMBER_OF_PROCESSORS 2>&1 | Tee-Object -FilePath "$BuildDir\build.log"
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Build failed" -ForegroundColor Red
    exit 1
}

$buildDuration = (Get-Date) - $buildStart
Write-Host "  Build completed in $($buildDuration.TotalMinutes.ToString('F1')) minutes" -ForegroundColor Green

# Generate build manifest
Write-Host "[5/5] Generating build manifest..." -ForegroundColor Yellow
$manifest = @{
    build_id = $BuildId
    build_time = $BuildTime
    git_commit = $GitCommit
    git_branch = $GitBranch
    config = $Config
    duration_seconds = [math]::Round($buildDuration.TotalSeconds, 2)
    artifacts = @{
        executable = "RawrXD.exe"
        test_runner = "RawrXD_tests.exe"
        benchmark_runner = "RawrXD_benchmarks.exe"
    }
    environment = @{
        cmake_version = (cmake --version | Select-String "cmake version" | ForEach-Object { $_.Line.Split()[2] })
        ninja_version = (ninja --version)
        python_version = (python --version).Split()[1]
    }
}

$manifest | ConvertTo-Json -Depth 4 | Set-Content "$BuildDir\build_manifest.json"

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "Build Successful!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host "Artifacts in: $BuildDir"
Write-Host "Manifest:     $BuildDir\build_manifest.json"
Write-Host "Next step:    .\benchmark\validate.ps1"
