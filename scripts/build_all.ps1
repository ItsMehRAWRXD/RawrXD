<#
.SYNOPSIS
    RawrXD Complete Build Script
    
.DESCRIPTION
    Builds all RawrXD targets with proper dependency ordering and error handling.
    Supports incremental builds, parallel compilation, and various configurations.
    
.PARAMETER Configuration
    Build configuration (Debug, Release, RelWithDebInfo)
    
.PARAMETER Targets
    Specific targets to build (default: all)
    
.PARAMETER Clean
    Perform a clean build
    
.PARAMETER Parallel
    Number of parallel jobs (default: auto)
    
.PARAMETER Verbose
    Enable verbose output
    
.EXAMPLE
    .\build_all.ps1 -Configuration Release
    
.EXAMPLE
    .\build_all.ps1 -Clean -Parallel 8
#>

[CmdletBinding()]
param(
    [ValidateSet("Debug", "Release", "RelWithDebInfo", "MinSizeRel")]
    [string]$Configuration = "Release",
    
    [string[]]$Targets = @("all"),
    [switch]$Clean,
    [int]$Parallel = 0,
    [switch]$Verbose,
    [switch]$SkipTests,
    [switch]$Install
)

$ErrorActionPreference = "Stop"
$startTime = Get-Date

# Script directory
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectRoot = Split-Path -Parent $scriptDir
$buildDir = Join-Path $projectRoot "build-$($Configuration.ToLower())"

Write-Host "RawrXD Build Script" -ForegroundColor Cyan
Write-Host "==================" -ForegroundColor Cyan
Write-Host ""

# Determine parallel jobs
if ($Parallel -eq 0) {
    $Parallel = (Get-CimInstance Win32_ComputerSystem).NumberOfLogicalProcessors
}

Write-Host "Configuration: $Configuration" -ForegroundColor White
Write-Host "Build Directory: $buildDir" -ForegroundColor White
Write-Host "Parallel Jobs: $Parallel" -ForegroundColor White
Write-Host ""

# Verify environment
function Test-BuildEnvironment {
    $issues = @()
    
    # Check CMake
    if (-not (Get-Command cmake -ErrorAction SilentlyContinue)) {
        $issues += "CMake not found in PATH"
    }
    
    # Check compiler
    if (-not $env:CC -and -not (Get-Command cl -ErrorAction SilentlyContinue)) {
        if (-not (Get-Command gcc -ErrorAction SilentlyContinue)) {
            $issues += "No C compiler found (run vcvars64.bat or install GCC)"
        }
    }
    
    if ($issues.Count -gt 0) {
        Write-Host "Build Environment Issues:" -ForegroundColor Red
        foreach ($issue in $issues) {
            Write-Host "  - $issue" -ForegroundColor Red
        }
        exit 1
    }
    
    Write-Host "Build environment verified" -ForegroundColor Green
}

# Clean build directory
function Clear-BuildDirectory {
    if (Test-Path $buildDir) {
        Write-Host "Cleaning build directory..." -ForegroundColor Yellow
        Remove-Item -Recurse -Force $buildDir
    }
    New-Item -ItemType Directory -Path $buildDir -Force | Out-Null
}

# Configure with CMake
function Invoke-CMakeConfigure {
    param([string[]]$Options)
    
    Write-Host "Configuring with CMake..." -ForegroundColor Cyan
    
    Push-Location $buildDir
    try {
        $cmakeArgs = @(
            "-G", "Ninja",
            "-DCMAKE_BUILD_TYPE=$Configuration",
            "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON"
        )
        
        if ($Verbose) {
            $cmakeArgs += "-DCMAKE_VERBOSE_MAKEFILE=ON"
        }
        
        $cmakeArgs += $Options
        $cmakeArgs += $projectRoot
        
        Write-Host "cmake $([string]::Join(' ', $cmakeArgs))" -ForegroundColor Gray
        
        & cmake @cmakeArgs 2>&1 | ForEach-Object {
            if ($_ -match "error|Error|ERROR") {
                Write-Host $_ -ForegroundColor Red
            }
            elseif ($_ -match "warning|Warning|WARNING") {
                Write-Host $_ -ForegroundColor Yellow
            }
            else {
                Write-Host $_
            }
        }
        
        if ($LASTEXITCODE -ne 0) {
            throw "CMake configuration failed with exit code $LASTEXITCODE"
        }
        
        Write-Host "CMake configuration successful" -ForegroundColor Green
    }
    finally {
        Pop-Location
    }
}

# Build targets
function Invoke-CMakeBuild {
    param([string[]]$BuildTargets)
    
    foreach ($target in $BuildTargets) {
        Write-Host "Building target: $target" -ForegroundColor Cyan
        
        Push-Location $buildDir
        try {
            $buildArgs = @(
                "--build", ".",
                "--target", $target,
                "--config", $Configuration,
                "--parallel", $Parallel
            )
            
            if ($Verbose) {
                $buildArgs += "--verbose"
            }
            
            & cmake @buildArgs 2>&1 | ForEach-Object {
                if ($_ -match "error LNK|error C|fatal error") {
                    Write-Host $_ -ForegroundColor Red
                }
                elseif ($_ -match "warning C") {
                    Write-Host $_ -ForegroundColor Yellow
                }
                else {
                    Write-Host $_
                }
            }
            
            if ($LASTEXITCODE -ne 0) {
                throw "Build failed for target '$target' with exit code $LASTEXITCODE"
            }
            
            Write-Host "Target '$target' built successfully" -ForegroundColor Green
        }
        finally {
            Pop-Location
        }
    }
}

# Run tests
function Invoke-TestSuite {
    Write-Host "Running test suite..." -ForegroundColor Cyan
    
    Push-Location $buildDir
    try {
        $testArgs = @("--output-on-failure")
        if ($Verbose) {
            $testArgs += "-V"
        }
        
        & ctest @testArgs
        
        if ($LASTEXITCODE -ne 0) {
            Write-Host "Some tests failed" -ForegroundColor Yellow
        }
        else {
            Write-Host "All tests passed" -ForegroundColor Green
        }
    }
    finally {
        Pop-Location
    }
}

# Install build
function Install-BuildArtifacts {
    Write-Host "Installing build artifacts..." -ForegroundColor Cyan
    
    Push-Location $buildDir
    try {
        & cmake --install . --config $Configuration
        
        if ($LASTEXITCODE -ne 0) {
            throw "Installation failed with exit code $LASTEXITCODE"
        }
        
        Write-Host "Installation successful" -ForegroundColor Green
    }
    finally {
        Pop-Location
    }
}

# Print build summary
function Write-BuildSummary {
    param([TimeSpan]$Duration)
    
    Write-Host ""
    Write-Host "Build Summary" -ForegroundColor Cyan
    Write-Host "=============" -ForegroundColor Cyan
    Write-Host "Configuration: $Configuration" -ForegroundColor White
    Write-Host "Duration: $($Duration.ToString('hh\:mm\:ss'))" -ForegroundColor White
    Write-Host ""
    
    # List built binaries
    $binDir = Join-Path $buildDir "bin"
    if (Test-Path $binDir) {
        Write-Host "Built Binaries:" -ForegroundColor White
        Get-ChildItem $binDir -File | ForEach-Object {
            $size = "{0:N2} MB" -f ($_.Length / 1MB)
            Write-Host "  $($_.Name) ($size)" -ForegroundColor Gray
        }
    }
    
    Write-Host ""
    Write-Host "Build completed successfully!" -ForegroundColor Green
}

# Main execution
Test-BuildEnvironment

if ($Clean) {
    Clear-BuildDirectory
}

if (-not (Test-Path $buildDir)) {
    New-Item -ItemType Directory -Path $buildDir -Force | Out-Null
}

# Configure if needed
if (-not (Test-Path (Join-Path $buildDir "CMakeCache.txt")) -or $Clean) {
    Invoke-CMakeConfigure
}

# Build
Invoke-CMakeBuild -BuildTargets $Targets

# Test
if (-not $SkipTests) {
    Invoke-TestSuite
}

# Install
if ($Install) {
    Install-BuildArtifacts
}

# Summary
$duration = (Get-Date) - $startTime
Write-BuildSummary -Duration $duration
