<#
.SYNOPSIS
    RawrXD Phase 21 Build Orchestrator
    Hardens CMake MASM integration and validates kernel builds
.DESCRIPTION
    Sets up directory structure, installs CMake module, and runs
    build-time validation (Shadow Run) for all MASM kernels.
.NOTES
    Run from project root: .\scripts\Phase21_Build.ps1
#>

[CmdletBinding()]
param(
    [ValidateSet("Debug", "Release", "RelWithDebInfo")]
    [string]$Configuration = "Release",
    
    [string]$BuildDir = "build-phase21",
    
    [switch]$Clean,
    [switch]$SkipTests,
    [switch]$VerboseBuild
)

$ErrorActionPreference = "Stop"
$startTime = Get-Date

#=============================================================================
# Color Output Helpers
#=============================================================================
function Write-Success($msg) { Write-Host "[OK] $msg" -ForegroundColor Green }
function Write-Info($msg)  { Write-Host "[..] $msg" -ForegroundColor Cyan }
function Write-Warn($msg)  { Write-Host "[!] $msg" -ForegroundColor Yellow }
function Write-Error($msg) { Write-Host "[XX] $msg" -ForegroundColor Red }

#=============================================================================
# Phase Header
#=============================================================================
Write-Host ""
Write-Host "=== RawrXD Phase 21: CMake MASM Integration ===" -ForegroundColor Cyan
Write-Host ""

#=============================================================================
# Directory Structure Setup
#=============================================================================
Write-Info "Setting up directory structure..."

$dirs = @(
    "cmake/modules",
    "src/kernels",
    "src/include",
    "src/core",
    "src/ai",
    "src/infra",
    "src/ide",
    "tests",
    "scripts",
    "docs"
)

foreach ($dir in $dirs) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        Write-Info "Created: $dir"
    }
}
Write-Success "Directory structure ready"

#=============================================================================
# Install CMake Module
#=============================================================================
Write-Info "Verifying CMake module..."

$moduleSource = "cmake/modules/RawrXD_MASM.cmake"
if (-not (Test-Path $moduleSource)) {
    Write-Error "RawrXD_MASM.cmake not found at $moduleSource"
    exit 1
}
Write-Success "CMake module verified: $moduleSource"

#=============================================================================
# Clean Build (if requested)
#============================================================================= $(if ($Clean -and (Test-Path $BuildDir)) {
    Write-Info "Cleaning build directory: $BuildDir"
    Remove-Item -Recurse -Force $BuildDir
    Write-Success "Build directory cleaned"
}

#=============================================================================
# CMake Configuration
#=============================================================================
Write-Info "Configuring with CMake..."

$cmakeArgs = @(
    "-S", "."
    "-B", $BuildDir
    "-G", "Ninja"
    "-DCMAKE_BUILD_TYPE=$Configuration"
    "-DRAWRXD_BUILD_KERNELS=ON"
    "-DRAWRXD_BUILD_TESTS=ON"
    "-DRAWRXD_BUILD_IDE=ON"
)

if ($VerboseBuild) {
    $cmakeArgs += "-DCMAKE_VERBOSE_MAKEFILE=ON"
}

& cmake @cmakeArgs
if ($LASTEXITCODE -ne 0) {
    Write-Error "CMake configuration failed"
    exit 1
}
Write-Success "CMake configuration complete"

#=============================================================================
# Build
#=============================================================================
Write-Info "Building RawrXD (this may take several minutes)..."

$buildArgs = @(
    "--build", $BuildDir
    "--config", $Configuration
    "--parallel"
)

if ($VerboseBuild) {
    $buildArgs += "--verbose"
}

& cmake @buildArgs
if ($LASTEXITCODE -ne 0) {
    Write-Error "Build failed"
    exit 1
}
Write-Success "Build complete"

#=============================================================================
# Shadow Run: Build-Time Kernel Validation
#============================================================================= $(if (-not $SkipTests) {
    Write-Info "Running Shadow Run validation (build-time kernel tests)..."
    
    & ctest --test-dir $BuildDir --output-on-failure -C $Configuration
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Shadow Run validation failed"
        exit 1
    }
    Write-Success "Shadow Run validation passed"
}

#=============================================================================
# Build Summary
#=============================================================================
$endTime = Get-Date
$duration = $endTime - $startTime

Write-Host ""
Write-Host "=== BUILD SUMMARY ===" -ForegroundColor Green
Write-Host "Config:    $Configuration" -ForegroundColor Green
Write-Host "Duration:  $($duration.ToString('mm\:ss\.fff'))" -ForegroundColor Green
Write-Host "Tests:     $(if($SkipTests){'SKIPPED'}else{'PASSED'})" -ForegroundColor Green
Write-Host "=====================" -ForegroundColor Green
Write-Host ""

# Check for build artifacts
$exePath = "$BuildDir/$Configuration/RawrXD-AgenticIDE.exe"
if (-not (Test-Path $exePath)) {
    $exePath = "$BuildDir/RawrXD-AgenticIDE.exe"
}

if (Test-Path $exePath) {
    $exeSize = (Get-Item $exePath).Length / 1MB
    Write-Success "Executable: $exePath ($([math]::Round($exeSize, 2)) MB)"
} else {
    Write-Warn "Executable not found at expected path"
}

Write-Host ""
Write-Info "Phase 21 complete. Ready for Phase 22."
