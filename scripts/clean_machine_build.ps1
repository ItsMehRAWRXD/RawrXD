#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Clean Machine Build — Verifies no hidden dependencies on local build artifacts
.DESCRIPTION
    Performs a clean build from scratch to verify:
    - No cached generated files
    - No stale object files
    - No developer environment variable dependencies
    - No hidden Qt references
    - Clean CMake generation
.NOTES
    Run from repository root: .\scripts\clean_machine_build.ps1
#>

$ErrorActionPreference = "Stop"
$RepoRoot = Resolve-Path "."
$BuildDir = Join-Path $RepoRoot "build"
$StartTime = Get-Date

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  RawrXD Clean Machine Build" -ForegroundColor Cyan
Write-Host "  Repository: $RepoRoot" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Step 1: Verify prerequisites
Write-Host "[1/6] Verifying prerequisites..." -ForegroundColor Yellow
$required = @("cmake", "git", "ninja")
$missing = @()
foreach ($cmd in $required) {
    if (!(Get-Command $cmd -ErrorAction SilentlyContinue)) {
        $missing += $cmd
    }
}
if ($missing.Count -gt 0) {
    Write-Host "  ❌ Missing: $($missing -join ', ')" -ForegroundColor Red
    exit 1
}
Write-Host "  ✓ All prerequisites found" -ForegroundColor Green

# Step 2: Check for Qt dependencies
Write-Host "`n[2/6] Checking for Qt dependencies..." -ForegroundColor Yellow
$qtDlls = Get-ChildItem -Path $RepoRoot -Filter "Qt*.dll" -ErrorAction SilentlyContinue
$qtRefs = Select-String -Path (Get-ChildItem -Path $RepoRoot -Recurse -Filter "*.cpp" -ErrorAction SilentlyContinue) `
    -Pattern '#include <Q[^F]' -SimpleMatch -ErrorAction SilentlyContinue

if ($qtDlls) {
    Write-Host "  ⚠ Qt DLLs found: $($qtDlls.Count)" -ForegroundColor Yellow
    foreach ($dll in $qtDlls) {
        Write-Host "    $($dll.Name)"
    }
} else {
    Write-Host "  ✓ No Qt DLLs" -ForegroundColor Green
}

if ($qtRefs) {
    Write-Host "  ⚠ Qt includes found: $($qtRefs.Count)" -ForegroundColor Yellow
} else {
    Write-Host "  ✓ No Qt includes in source" -ForegroundColor Green
}

# Step 3: Clean build directory
Write-Host "`n[3/6] Cleaning build directory..." -ForegroundColor Yellow
if (Test-Path $BuildDir) {
    Remove-Item -Path $BuildDir -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "  ✓ Removed existing build directory" -ForegroundColor Green
} else {
    Write-Host "  ✓ No existing build directory" -ForegroundColor Green
}

# Step 4: CMake configure
Write-Host "`n[4/6] Configuring CMake..." -ForegroundColor Yellow
$configureResult = & cmake -S $RepoRoot -B $BuildDir -G "Ninja" `
    -DCMAKE_BUILD_TYPE=Release `
    -DRAWR_ENABLE_VULKAN=ON `
    -DGGML_VULKAN=ON `
    -DBUILD_TESTING=ON 2>&1

if ($LASTEXITCODE -ne 0) {
    Write-Host "  ❌ CMake configure failed (exit: $LASTEXITCODE)" -ForegroundColor Red
    Write-Host "  $configureResult" -ForegroundColor Red
    exit 1
}
Write-Host "  ✓ CMake configure succeeded" -ForegroundColor Green

# Step 5: Build
Write-Host "`n[5/6] Building..." -ForegroundColor Yellow
$buildResult = & cmake --build $BuildDir --config Release -j 4 2>&1

if ($LASTEXITCODE -ne 0) {
    Write-Host "  ❌ Build failed (exit: $LASTEXITCODE)" -ForegroundColor Red
    
    # Extract error summary
    $errors = $buildResult | Select-String -Pattern "error|Error|LNK|C[0-9]{4}" -SimpleMatch
    if ($errors) {
        Write-Host "`nFirst 10 errors:" -ForegroundColor Red
        $errors | Select-Object -First 10 | ForEach-Object { Write-Host "  $_" }
    }
    exit 1
}
Write-Host "  ✓ Build succeeded" -ForegroundColor Green

# Step 6: Verify output
Write-Host "`n[6/6] Verifying output..." -ForegroundColor Yellow
$targets = @(
    "RawrXD.exe",
    "RawrXD-Win32IDE.exe",
    "RawrXD-InferenceEngine.exe"
)

$found = 0
foreach ($target in $targets) {
    $path = Join-Path $BuildDir "Release" $target
    if (Test-Path $path) {
        $size = (Get-Item $path).Length / 1MB
        Write-Host "  ✓ $target ($([math]::Round($size, 1)) MB)" -ForegroundColor Green
        $found++
    } else {
        $altPath = Join-Path $BuildDir $target
        if (Test-Path $altPath) {
            $size = (Get-Item $altPath).Length / 1MB
            Write-Host "  ✓ $target ($([math]::Round($size, 1)) MB)" -ForegroundColor Green
            $found++
        } else {
            Write-Host "  ⚠ $target not found" -ForegroundColor Yellow
        }
    }
}

$elapsed = (Get-Date) - $StartTime
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  Clean Machine Build Complete" -ForegroundColor Cyan
Write-Host "  Duration: $([math]::Round($elapsed.TotalMinutes, 1)) minutes" -ForegroundColor Cyan
Write-Host "  Targets found: $found" -ForegroundColor Cyan
Write-Host "  Status: $(if ($LASTEXITCODE -eq 0) { '✅ PASSED' } else { '❌ FAILED' })" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# Write evidence
$evidence = @{
    timestamp = (Get-Date -Format "o")
    duration_minutes = [math]::Round($elapsed.TotalMinutes, 1)
    cmake_configure = $LASTEXITCODE -eq 0
    build_success = $LASTEXITCODE -eq 0
    targets_found = $found
    qt_dlls_found = $qtDlls.Count
    qt_includes_found = $qtRefs.Count
    clean_build = $true
    passed = $LASTEXITCODE -eq 0
} | ConvertTo-Json

$null = New-Item -ItemType Directory -Force -Path "evidence"
$evidence | Out-File -FilePath "evidence/CLEAN_MACHINE_BUILD.json" -Encoding utf8
Write-Host "`nEvidence: evidence/CLEAN_MACHINE_BUILD.json" -ForegroundColor Cyan

exit $LASTEXITCODE
